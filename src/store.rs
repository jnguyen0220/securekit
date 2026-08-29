//! Storage backend for the coordination server.
//!
//! The server tracks a queue of repositories to scan (the "list"), leases work
//! items to clients, and records the redacted results they report back.
//!
//! [`TargetStore`] is the abstraction; [`FileTargetStore`] is a file-backed
//! implementation that seeds its queue from a plain-text list file (one repo
//! per line) whose path comes from the environment (`.env`). A database-backed
//! implementation can be added later by implementing the same trait — see the
//! `DB-ready` note in [`crate::server`].

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::app;
use crate::lifecycle::WorkItemLifecycleState;
use crate::protocol::{StoreStats, SubmitReport, WorkItem};
use crate::util::current_unix_time;

const RESULTS_FLUSH_EVERY_LINES: usize = 50;
const RESULTS_FLUSH_MAX_INTERVAL_SECS: u64 = 2;

#[derive(Serialize)]
struct PersistedFinding {
    kind: String,
    match_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_secret: Option<String>,
    fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    validity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validity_reason: Option<String>,
}

#[derive(Serialize)]
struct PersistedReport {
    repo: String,
    has_leak: bool,
    finding_count: usize,
    findings: Vec<PersistedFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Behaviour required of any target-list backend (file, database, ...).
///
/// Implementors must be `Send + Sync` because the axum server shares a single
/// instance across all request handlers via an `Arc`.
pub trait TargetStore: Send + Sync {
    /// Lease up to `count` pending items, marking them in-flight with an
    /// expiry `lease_secs` in the future. Expired leases are recycled first so
    /// a crashed worker's items are not lost.
    fn claim(&self, count: usize, lease_secs: u64) -> Vec<WorkItem>;

    /// Append newly-discovered repositories to the pending queue. Used by the
    /// server's central enumeration task to feed work as it finds it.
    fn enqueue(&self, repos: Vec<String>);

    /// Mark that no more repositories will be enumerated. Combined with an empty
    /// queue this tells clients (via [`enumeration_drained`]) that they may exit.
    ///
    /// [`enumeration_drained`]: TargetStore::enumeration_drained
    fn set_enumeration_done(&self);

    /// True once enumeration is complete **and** no claimable/in-flight work
    /// remains — i.e. the whole run is finished and clients should stop polling.
    fn enumeration_drained(&self) -> bool;

    /// Record a completed scan result and mark its item done.
    fn complete(&self, report: SubmitReport) -> Result<()>;

    /// Return a snapshot of queue counters.
    fn stats(&self) -> StoreStats;
}

#[derive(Clone)]
struct Inflight {
    repo: String,
    lease_expiry: u64,
}

struct Inner {
    pending: VecDeque<WorkItem>,
    inflight: HashMap<u64, Inflight>,
    lease_expiry_queue: BinaryHeap<Reverse<(u64, u64)>>,
    item_states: HashMap<u64, WorkItemLifecycleState>,
    done: usize,
    repos_with_leaks: usize,
    /// Next work-item id to assign when enqueuing discovered repos.
    next_id: u64,
    /// Set once the enumeration source is exhausted (no more repos will arrive).
    enumeration_done: bool,
}

/// A file-backed [`TargetStore`].
///
/// * The target list is read once at construction from a text file (one repo
///   per line; blank lines and `#` comments ignored).
/// * Queue state lives in memory behind a [`Mutex`].
/// * Each completed report is appended as one JSON line to `results_path` so
///   results survive a restart even though the queue itself does not.
pub struct FileTargetStore {
    inner: Mutex<Inner>,
    results_writer: Mutex<ResultsWriterState>,
}

struct ResultsWriterState {
    writer: BufWriter<fs::File>,
    dirty_lines: usize,
    last_flush: u64,
}

impl FileTargetStore {
    /// Build a store, seeding the queue from `list_path` and appending results
    /// to `results_path`.
    pub fn from_files(list_path: &Path, results_path: PathBuf) -> Result<Self> {
        let content = fs::read_to_string(list_path)
            .with_context(|| format!("failed to read list file: {}", list_path.display()))?;

        let mut pending = VecDeque::new();
        let mut next_id: u64 = 1;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            pending.push_back(WorkItem {
                id: next_id,
                repo: trimmed.to_string(),
                clone_url: None,
            });
            next_id += 1;
        }
        // Open the results file once and keep the handle for the store's
        // lifetime so each completed report is a single buffered append rather
        // than an open/append/close cycle.
        let results_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&results_path)
            .with_context(|| format!("failed to open results file: {}", results_path.display()))?;

        let now = current_unix_time();
        Ok(Self {
            inner: Mutex::new(Inner {
                pending,
                inflight: HashMap::new(),
                lease_expiry_queue: BinaryHeap::new(),
                item_states: (1..next_id)
                    .map(|id| (id, WorkItemLifecycleState::on_enqueue()))
                    .collect(),
                done: 0,
                repos_with_leaks: 0,
                next_id,
                // A static list is the complete work set from the outset.
                enumeration_done: true,
            }),
            results_writer: Mutex::new(ResultsWriterState {
                writer: BufWriter::new(results_file),
                dirty_lines: 0,
                last_flush: now,
            }),
        })
    }

    /// Build a store with an empty claim queue that is fed dynamically by the
    /// server's central enumeration task, and records reported results.
    pub fn new_empty(results_path: PathBuf) -> Result<Self> {
        let results_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&results_path)
            .with_context(|| format!("failed to open results file: {}", results_path.display()))?;

        let now = current_unix_time();
        Ok(Self {
            inner: Mutex::new(Inner {
                pending: VecDeque::new(),
                inflight: HashMap::new(),
                lease_expiry_queue: BinaryHeap::new(),
                item_states: HashMap::new(),
                done: 0,
                repos_with_leaks: 0,
                next_id: 1,
                // Work arrives asynchronously; not done until the task says so.
                enumeration_done: false,
            }),
            results_writer: Mutex::new(ResultsWriterState {
                writer: BufWriter::new(results_file),
                dirty_lines: 0,
                last_flush: now,
            }),
        })
    }

    /// Move any leases whose deadline has passed back to the pending queue.
    fn requeue_expired(inner: &mut Inner) {
        let start = std::time::Instant::now();
        let now = current_unix_time();
        let mut reclaimed = 0usize;

        while let Some(Reverse((expiry, id))) = inner.lease_expiry_queue.peek().copied() {
            if expiry > now {
                break;
            }
            inner.lease_expiry_queue.pop();

            // Skip stale heap entries. We only reclaim when the currently
            // tracked inflight lease for this item still matches the heap key.
            let Some(inflight) = inner.inflight.get(&id) else {
                continue;
            };
            if inflight.lease_expiry != expiry {
                continue;
            }

            if let Some(item) = inner.inflight.remove(&id) {
                let state = inner
                    .item_states
                    .entry(id)
                    .or_insert(WorkItemLifecycleState::on_enqueue());
                *state = state.on_lease_expire();
                inner.pending.push_back(WorkItem {
                    id,
                    repo: item.repo,
                    clone_url: None,
                });
                reclaimed += 1;
            }
        }

        if reclaimed > 0 {
            app::debug(
                "store",
                format!(
                    "reclaimed {} expired lease(s) in {}ms",
                    reclaimed,
                    start.elapsed().as_millis()
                ),
            );
        }
    }
}

impl TargetStore for FileTargetStore {
    fn claim(&self, count: usize, lease_secs: u64) -> Vec<WorkItem> {
        let mut inner = self.inner.lock().unwrap();
        Self::requeue_expired(&mut inner);

        let mut leased = Vec::new();
        let expiry = current_unix_time() + lease_secs;
        for _ in 0..count {
            let Some(item) = inner.pending.pop_front() else {
                break;
            };
            let state = inner
                .item_states
                .entry(item.id)
                .or_insert(WorkItemLifecycleState::on_enqueue());
            *state = state.on_claim();
            inner.inflight.insert(
                item.id,
                Inflight {
                    repo: item.repo.clone(),
                    lease_expiry: expiry,
                },
            );
            inner.lease_expiry_queue.push(Reverse((expiry, item.id)));
            leased.push(item);
        }
        leased
    }

    fn enqueue(&self, repos: Vec<String>) {
        if repos.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        for repo in repos {
            let id = inner.next_id;
            inner.next_id += 1;
            inner
                .item_states
                .insert(id, WorkItemLifecycleState::on_enqueue());
            inner.pending.push_back(WorkItem {
                id,
                repo,
                clone_url: None,
            });
        }
    }

    fn set_enumeration_done(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.enumeration_done = true;
    }

    fn enumeration_drained(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        // Recycle expired leases first so an item held by a crashed worker
        // isn't mistaken for finished work.
        Self::requeue_expired(&mut inner);
        inner.enumeration_done && inner.pending.is_empty() && inner.inflight.is_empty()
    }

    fn complete(&self, mut report: SubmitReport) -> Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            // Count the result as done. For queue (`/claim`) reports we only
            // count it if we still owned the lease, so a late report for a
            // re-queued item is accepted but not double-counted. Shard-
            // enumeration reports carry no `item_id` and always count.
            let counted = match report.item_id {
                Some(id) => {
                    let was_inflight = inner.inflight.remove(&id).is_some();
                    if was_inflight {
                        // Terminal state: evict the lifecycle record so this map
                        // stays bounded to live work instead of growing by one
                        // entry per item for the whole run.
                        inner.item_states.remove(&id);
                    }
                    was_inflight
                }
                None => true,
            };
            if counted {
                inner.done += 1;
                if report.has_leak {
                    inner.repos_with_leaks += 1;
                }
            }
        }

        normalize_report_paths(&mut report);

        // Durably append only leak-positive results as JSON Lines. This keeps
        // `results.jsonl` focused on actionable findings.
        if report.has_leak {
            let persisted = PersistedReport {
                repo: report.repo,
                has_leak: report.has_leak,
                finding_count: report.finding_count,
                findings: report
                    .findings
                    .into_iter()
                    .map(|f| PersistedFinding {
                        kind: f.kind,
                        match_text: f.match_text,
                        raw_secret: f.raw_secret,
                        fingerprint: f.fingerprint,
                        validity: f.validity,
                        validity_reason: f.validity_reason,
                    })
                    .collect(),
                commit_sha: report.commit_sha,
                error: report.error,
            };
            let line = serde_json::to_string(&persisted).context("failed to serialize report")?;
            let mut state = self.results_writer.lock().unwrap();
            writeln!(state.writer, "{}", line).context("failed to write result line")?;
            state.dirty_lines += 1;

            let now = current_unix_time();
            let should_flush = state.dirty_lines >= RESULTS_FLUSH_EVERY_LINES
                || now.saturating_sub(state.last_flush) >= RESULTS_FLUSH_MAX_INTERVAL_SECS;
            if should_flush {
                state
                    .writer
                    .flush()
                    .context("failed to flush result lines")?;
                state.dirty_lines = 0;
                state.last_flush = now;
            }
        }
        Ok(())
    }

    fn stats(&self) -> StoreStats {
        let mut inner = self.inner.lock().unwrap();
        Self::requeue_expired(&mut inner);
        StoreStats {
            pending: inner.pending.len(),
            inflight: inner.inflight.len(),
            done: inner.done,
            repos_with_leaks: inner.repos_with_leaks,
            active_workers: 0,
            perf: None,
        }
    }
}

impl Drop for FileTargetStore {
    fn drop(&mut self) {
        let Ok(state) = self.results_writer.get_mut() else {
            return;
        };
        if state.dirty_lines > 0 {
            let _ = state.writer.flush();
            state.dirty_lines = 0;
            state.last_flush = current_unix_time();
        }
    }
}

fn normalize_report_paths(report: &mut SubmitReport) {
    let repo = report.repo.trim_end_matches('/').trim_end_matches(".git");
    let repo_path = Path::new(repo);

    for finding in &mut report.findings {
        let file = finding.file.trim();
        if file.is_empty() {
            continue;
        }
        if file.starts_with("http://") || file.starts_with("https://") {
            continue;
        }
        if Path::new(file).is_absolute() {
            continue;
        }

        if repo.starts_with("http://") || repo.starts_with("https://") {
            finding.file = format!("{}/{}", repo, file.trim_start_matches("./"));
        } else if repo_path.is_absolute() {
            finding.file = repo_path.join(file).display().to_string();
        }
    }
}
