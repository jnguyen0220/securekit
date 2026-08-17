use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::app;
use crate::github::enumerate_public_repos_page;
use crate::github_auth::TokenManager;
use crate::registry::WorkerRegistry;
use crate::store::TargetStore;
use crate::util::{jittered_delay, read_list_file};

const ENUM_QUEUE_HIGH_WATER: usize = 5_000;
const WORKER_WAIT_POLL: Duration = Duration::from_secs(2);
const QUEUE_WATERMARK_POLL: Duration = Duration::from_secs(2);
const ENUM_RETRY_BASE_DELAY: Duration = Duration::from_secs(10);
const ENUM_RETRY_JITTER: Duration = Duration::from_secs(3);

type SharedStore = Arc<dyn TargetStore>;

#[derive(Debug, Serialize, Deserialize)]
struct EnumCursorCheckpoint {
    cursor: u64,
}

pub(crate) trait RepoCacheOrchestration: Send + Sync {
    fn get_sha(&self, repo: &str) -> Option<String>;
    fn set_enum_cursor(&self, cursor: u64) -> Result<()>;
}

/// Load repositories from a text list file (one per line), ignoring blanks and
/// `#` comments.
pub(crate) fn read_repo_list(path: &Path) -> Result<Vec<String>> {
    read_list_file(path)
}

pub(crate) fn load_enum_cursor_checkpoint(path: &Path) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    let parsed: EnumCursorCheckpoint = serde_json::from_str(&content).ok()?;
    Some(parsed.cursor)
}

fn save_enum_cursor_checkpoint(path: &Path, cursor: u64) -> Result<()> {
    let payload = EnumCursorCheckpoint { cursor };
    let body =
        serde_json::to_string_pretty(&payload).context("enum cursor serialization failed")?;
    fs::write(path, body)
        .with_context(|| format!("write enum cursor checkpoint {} failed", path.display()))
}

fn next_enumeration_retry_delay() -> Duration {
    jittered_delay(ENUM_RETRY_BASE_DELAY, ENUM_RETRY_JITTER)
}

/// True when `git ls-remote`/HEAD precheck indicates the repository cannot be
/// accessed by clients due to auth, permissions, or remote availability
/// problems. These should be skipped before enqueueing to avoid wasting claim
/// slots on known-unscannable targets.
fn should_skip_repo_on_head_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("terminal prompts disabled")
        || m.contains("could not read username")
        || m.contains("authentication failed")
        || m.contains("requested url returned error: 401")
        || m.contains("requested url returned error: 403")
        || m.contains("http 401")
        || m.contains("http 403")
        || m.contains("repository not found")
        || m.contains("there is a problem with this repository on disk")
        || m.contains("unavailable")
        || m.contains("timed out")
}

/// Resolve HEAD commit SHA for either a local git checkout path or a remote
/// repository URL.
///
/// Returns `Ok(None)` when the target exists but has no refs yet (for example,
/// a brand-new empty repository with no default branch).
fn repo_head_sha(repo: &str, git_head_timeout_secs: u64) -> Result<Option<String>> {
    if Path::new(repo).exists() {
        crate::git::local_head_sha(Path::new(repo))
            .with_context(|| format!("read local HEAD for {} failed", repo))
    } else {
        crate::git::remote_head_sha_timed(repo, Duration::from_secs(git_head_timeout_secs))
    }
}

/// Filter repositories so only unseen or changed-HEAD targets are enqueued.
fn filter_repos_by_cache<C>(
    candidates: Vec<String>,
    cache: &C,
    git_head_timeout_secs: u64,
) -> Vec<String>
where
    C: RepoCacheOrchestration,
{
    let mut filtered = Vec::new();
    for repo in candidates {
        let Some(cached_sha) = cache.get_sha(&repo) else {
            filtered.push(repo);
            continue;
        };

        match repo_head_sha(&repo, git_head_timeout_secs) {
            Ok(Some(head)) => {
                if cached_sha != head {
                    filtered.push(repo);
                }
            }
            Ok(None) => {
                if Path::new(&repo).exists() {
                    app::debug(
                        "server",
                        format!("local repo has no refs yet; enqueueing {}", repo),
                    );
                    filtered.push(repo);
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if should_skip_repo_on_head_error(&msg) {
                    continue;
                }
                app::warn(
                    "server",
                    format!(
                        "HEAD precheck failed for {}; enqueueing anyway: {}",
                        repo, e
                    ),
                );
                filtered.push(repo);
            }
        }
    }
    filtered
}

/// Block background work until at least one worker is active.
async fn wait_for_active_workers(registry: &WorkerRegistry) {
    if registry.active_count() == 0 {
        app::info("server", "no active workers; background processing paused");
        while registry.active_count() == 0 {
            tokio::time::sleep(WORKER_WAIT_POLL).await;
        }
        app::info("server", "worker connected; background processing resumed");
    }
}

pub(crate) struct EnumerationOrchestrator<C>
where
    C: RepoCacheOrchestration + 'static,
{
    store: SharedStore,
    tokens: Arc<TokenManager>,
    repo_cache: Arc<C>,
    registry: Arc<WorkerRegistry>,
    git_head_timeout_secs: u64,
}

impl<C> EnumerationOrchestrator<C>
where
    C: RepoCacheOrchestration + 'static,
{
    pub(crate) fn new(
        store: SharedStore,
        tokens: Arc<TokenManager>,
        repo_cache: Arc<C>,
        registry: Arc<WorkerRegistry>,
        git_head_timeout_secs: u64,
    ) -> Self {
        Self {
            store,
            tokens,
            repo_cache,
            registry,
            git_head_timeout_secs,
        }
    }

    pub(crate) fn spawn_enumeration(&self, since: u64, cursor_file: PathBuf) {
        let store = Arc::clone(&self.store);
        let tokens = Arc::clone(&self.tokens);
        let repo_cache = Arc::clone(&self.repo_cache);
        let registry = Arc::clone(&self.registry);
        let git_head_timeout_secs = self.git_head_timeout_secs;

        tokio::spawn(async move {
            let http = reqwest::Client::new();
            let mut cursor = since;
            app::info("server", format!("enumeration started at cursor {}", since));
            loop {
                wait_for_active_workers(&registry).await;
                while store.stats().pending >= ENUM_QUEUE_HIGH_WATER {
                    tokio::time::sleep(QUEUE_WATERMARK_POLL).await;
                }

                match enumerate_public_repos_page(&http, cursor, &tokens).await {
                    Ok((repos, next_cursor)) => {
                        if next_cursor == cursor {
                            app::info("server", "enumeration complete");
                            store.set_enumeration_done();
                            break;
                        }
                        cursor = next_cursor;
                        if let Err(e) = save_enum_cursor_checkpoint(&cursor_file, cursor) {
                            app::warn(
                                "server",
                                format!("failed to persist enum cursor {}: {}", cursor, e),
                            );
                        }
                        if let Err(e) = repo_cache.set_enum_cursor(cursor) {
                            app::warn(
                                "server",
                                format!("failed to persist cache cursor {}: {}", cursor, e),
                            );
                        }
                        let filtered = filter_repos_by_cache(
                            repos,
                            repo_cache.as_ref(),
                            git_head_timeout_secs,
                        );
                        store.enqueue(filtered);
                    }
                    Err(e) => {
                        let delay = next_enumeration_retry_delay();
                        app::warn(
                            "server",
                            format!("enumeration error; retrying in {:?}: {}", delay, e),
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        });
    }

    pub(crate) fn spawn_static_enqueue(&self, list_path: PathBuf) {
        let store = Arc::clone(&self.store);
        let repo_cache = Arc::clone(&self.repo_cache);
        let registry = Arc::clone(&self.registry);
        let git_head_timeout_secs = self.git_head_timeout_secs;

        tokio::spawn(async move {
            wait_for_active_workers(&registry).await;
            match read_repo_list(&list_path) {
                Ok(repos) => {
                    let filtered =
                        filter_repos_by_cache(repos, repo_cache.as_ref(), git_head_timeout_secs);
                    store.enqueue(filtered);
                }
                Err(e) => {
                    app::error(
                        "server",
                        format!("failed to read list file {}: {}", list_path.display(), e),
                    );
                }
            }
            store.set_enumeration_done();
        });
    }
}
