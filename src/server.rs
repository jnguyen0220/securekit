//! Server mode: an axum HTTP service that hands out scan work to clients and
//! collects their (redacted) results.
//!
//! Configuration comes from the environment (loaded from `.env` by
//! [`crate::load_dotenv`] before this runs):
//!
//! | Variable                  | Meaning                                   | Default              |
//! |---------------------------|-------------------------------------------|----------------------|
//! | `SECUREKIT_BIND`          | Address to bind the HTTP server           | `127.0.0.1:8080`     |
//! | `SECUREKIT_LIST_FILE`     | Static repo list (one/line); disables live enumeration | optional |
//! | `SECUREKIT_RESULTS_FILE`  | Where to append redacted results (JSONL)  | `results.jsonl`      |
//! | `SECUREKIT_LEASE_SECS`    | How long a claimed item stays leased      | `300`                |
//! | `SECUREKIT_WORKER_TTL_SECS` | Heartbeat window before a worker expires | `60`                |
//! | `SECUREKIT_SCAN_WORKERS`  | Parallel scans the server tells clients to run | `4`             |
//! | `SECUREKIT_CLAIM_BATCH`   | Advisory client batch hint (server allocates a round-robin slice per bot) | `10` |
//! | `SECUREKIT_ENUM_SINCE`    | Numeric repo id to start enumeration after | `0`                 |
//! | `SECUREKIT_ENUM_CURSOR_FILE` | Where to persist enumeration cursor | `.enum-cursor.json` |
//! | `SECUREKIT_ENUM_PAGE_DELAY_MS` | Pause between GitHub enumeration page fetches (rate-limit throttle) | `500` |
//! | `SECUREKIT_IGNORE_FILE`   | Ignore-regex file shipped to clients      | optional             |
//! | `SECUREKIT_NO_DEFAULT_IGNORES` | Drop the built-in false-positive rules | `false`             |
//! | `GITHUB_APP_*` / `GITHUB_TOKEN` | GitHub credential the **server** enumerates with | anonymous |
//!
//! ## Central enumeration and client leases
//! The server is the sole orchestrator. Unless a static `SECUREKIT_LIST_FILE`
//! is provided, a background task enumerates public repositories using the
//! server's own GitHub credential and feeds their URLs into the `/claim` queue.
//! Clients need nothing but the server URL: on `/register` they get a
//! [`WorkerConfig`] (ignore rules, scan concurrency, claim batch size), then
//! lease public repo URLs via `/claim`. When the server has a GitHub credential,
//! claims may also include a short-lived authenticated clone URL so clients can
//! avoid anonymous clone throttling.
//!
//! ## Pluggable storage
//! The server only depends on the [`TargetStore`] trait, so swapping the
//! file-backed store for another backend (e.g. a database) is a matter of
//! implementing that trait and constructing it in [`build_store`].

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

use crate::app;
use crate::github_auth::TokenManager;
use crate::protocol::{
    Ack, ClaimRequest, ClaimResponse, LatencyStats, PerfStats, RegisterRequest, StoreStats,
    SubmitReport, UnregisterRequest, WorkerConfig,
};
use crate::registry::WorkerRegistry;
use crate::scan::load_ignore_pattern_strings;
use crate::server_config::ServerConfig;
use crate::server_orchestration::{
    load_enum_cursor_checkpoint, EnumerationOrchestrator, RepoCacheOrchestration,
};
use crate::server_usecase::{
    ClaimService, RepoCacheWriter, ReportService, WorkerLifecycleService, WorkerSettings,
};
use crate::store::{FileTargetStore, TargetStore};
use crate::util::{bool_from_env, current_unix_time, path_from_env, path_or_default_from_env};
use crate::{cache::load_cache, cache::save_cache, cache::CachedRepo, cache::ScanCache};

/// Hard cap on how many items a single claim can lease, to keep one greedy
/// client from draining the queue.
const MAX_CLAIM: usize = 100;
const CACHE_FLUSH_EVERY_UPDATES: usize = 25;
const CACHE_FLUSH_MAX_INTERVAL_SECS: u64 = 5;
const PERF_WINDOW_SIZE: usize = 256;

type SharedStore = Arc<dyn TargetStore>;

/// Shared state handed to every request handler.
#[derive(Clone)]
struct AppState {
    store: SharedStore,
    registry: Arc<WorkerRegistry>,
    worker_service: Arc<WorkerLifecycleService>,
    claim_service: Arc<ClaimService>,
    report_service: Arc<ReportService<RepoCache>>,
    perf: Arc<ServerPerfMonitor>,
}

#[derive(Default)]
struct PerfWindow {
    claim_ms: VecDeque<u64>,
    report_ms: VecDeque<u64>,
    stats_ms: VecDeque<u64>,
}

impl PerfWindow {
    fn push(queue: &mut VecDeque<u64>, value_ms: u64) {
        queue.push_back(value_ms);
        if queue.len() > PERF_WINDOW_SIZE {
            queue.pop_front();
        }
    }

    fn summary(queue: &VecDeque<u64>) -> LatencyStats {
        if queue.is_empty() {
            return LatencyStats::default();
        }

        let mut values: Vec<u64> = queue.iter().copied().collect();
        values.sort_unstable();
        let last = values.len() - 1;
        let p50_idx = (last * 50) / 100;
        let p95_idx = (last * 95) / 100;
        let max_ms = *values.last().unwrap_or(&0);

        LatencyStats {
            samples: values.len(),
            p50_ms: values[p50_idx],
            p95_ms: values[p95_idx],
            max_ms,
        }
    }
}

#[derive(Default)]
struct ServerPerfMonitor {
    inner: Mutex<PerfWindow>,
}

impl ServerPerfMonitor {
    fn observe_claim(&self, elapsed: Duration) {
        let mut inner = self.inner.lock().unwrap();
        PerfWindow::push(&mut inner.claim_ms, elapsed.as_millis() as u64);
    }

    fn observe_report(&self, elapsed: Duration) {
        let mut inner = self.inner.lock().unwrap();
        PerfWindow::push(&mut inner.report_ms, elapsed.as_millis() as u64);
    }

    fn observe_stats(&self, elapsed: Duration) {
        let mut inner = self.inner.lock().unwrap();
        PerfWindow::push(&mut inner.stats_ms, elapsed.as_millis() as u64);
    }

    fn snapshot(&self) -> PerfStats {
        let inner = self.inner.lock().unwrap();
        PerfStats {
            claim: PerfWindow::summary(&inner.claim_ms),
            report: PerfWindow::summary(&inner.report_ms),
            stats: PerfWindow::summary(&inner.stats_ms),
        }
    }
}

/// Server-owned repository cache keyed by repo URL -> last scanned commit SHA.
struct RepoCache {
    inner: Mutex<RepoCacheState>,
}

struct RepoCacheState {
    cache: ScanCache,
    by_url: HashMap<String, CachedRepo>,
    dirty_updates: usize,
    last_flush: u64,
}

impl RepoCache {
    fn from_disk() -> Result<Self> {
        let now = current_unix_time();
        let cache = load_cache()?;
        let by_url = cache
            .repos
            .iter()
            .cloned()
            .map(|r| (r.url.clone(), r))
            .collect();
        Ok(Self {
            inner: Mutex::new(RepoCacheState {
                cache,
                by_url,
                dirty_updates: 0,
                last_flush: now,
            }),
        })
    }

    fn get_sha(&self, repo: &str) -> Option<String> {
        let state = self.inner.lock().unwrap();
        state.by_url.get(repo).map(|entry| entry.commit_sha.clone())
    }

    fn enum_cursor(&self) -> Option<u64> {
        let state = self.inner.lock().unwrap();
        state.cache.enum_cursor
    }

    fn set_enum_cursor(&self, cursor: u64) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        state.cache.enum_cursor = Some(cursor);
        Self::sync_cache_from_map(&mut state);
        state.dirty_updates = 0;
        state.last_flush = current_unix_time();
        save_cache(&state.cache)
    }

    fn upsert_sha(&self, repo: &str, sha: &str) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        state.by_url.insert(
            repo.to_string(),
            CachedRepo {
                url: repo.to_string(),
                commit_sha: sha.to_string(),
                timestamp: current_unix_time(),
            },
        );

        state.dirty_updates += 1;
        let now = current_unix_time();
        let should_flush = state.dirty_updates >= CACHE_FLUSH_EVERY_UPDATES
            || now.saturating_sub(state.last_flush) >= CACHE_FLUSH_MAX_INTERVAL_SECS;
        if should_flush {
            Self::sync_cache_from_map(&mut state);
            save_cache(&state.cache)?;
            state.dirty_updates = 0;
            state.last_flush = now;
        }
        Ok(())
    }

    fn sync_cache_from_map(state: &mut RepoCacheState) {
        state.cache.repos = state.by_url.values().cloned().collect();
        state.cache.rebuild_index();
    }
}

impl RepoCacheWriter for RepoCache {
    fn upsert_sha(&self, repo: &str, sha: &str) -> Result<()> {
        RepoCache::upsert_sha(self, repo, sha)
    }
}

impl RepoCacheOrchestration for RepoCache {
    fn get_sha(&self, repo: &str) -> Option<String> {
        self.get_sha(repo)
    }

    fn set_enum_cursor(&self, cursor: u64) -> Result<()> {
        self.set_enum_cursor(cursor)
    }
}

impl Drop for RepoCache {
    fn drop(&mut self) {
        let Ok(state) = self.inner.get_mut() else {
            return;
        };
        if state.dirty_updates > 0 {
            RepoCache::sync_cache_from_map(state);
            let _ = save_cache(&state.cache);
            state.dirty_updates = 0;
        }
    }
}

/// Read configuration from the environment and build the shared store.
fn build_store() -> Result<SharedStore> {
    let results_path = path_or_default_from_env("SECUREKIT_RESULTS_FILE", "results.jsonl");

    // Always use dynamic enqueue path so both static-list and live-enumeration
    // flows share the same server-side cache filtering behavior.
    Ok(Arc::new(FileTargetStore::new_empty(results_path)?))
}

/// Read the ignore ruleset the server ships to every client (built-in defaults
/// plus an optional `SECUREKIT_IGNORE_FILE`), validating that each pattern
/// compiles before it is handed out.
fn build_ignore_patterns() -> Result<Vec<String>> {
    let ignore_file = path_from_env("SECUREKIT_IGNORE_FILE");
    let no_default = bool_from_env("SECUREKIT_NO_DEFAULT_IGNORES", false);

    let patterns = load_ignore_pattern_strings(no_default, &[], ignore_file.as_deref())?;
    // Fail fast on a bad pattern rather than shipping it to every client.
    for p in &patterns {
        regex::Regex::new(p).with_context(|| format!("ignore regex invalid: {p}"))?;
    }
    Ok(patterns)
}

/// Entry point for the `securekit-server` binary. Binds the HTTP server and serves until killed.
pub async fn run_server() -> Result<()> {
    let cfg = ServerConfig::from_env(MAX_CLAIM)?;
    let ignore_patterns = build_ignore_patterns()?;
    let store = build_store()?;
    let repo_cache = Arc::new(RepoCache::from_disk().context("load server cache failed")?);
    let registry = Arc::new(WorkerRegistry::new(cfg.worker_ttl_secs));
    let token_manager = Arc::new(TokenManager::from_env().await);
    let orchestrator = EnumerationOrchestrator::new(
        Arc::clone(&store),
        Arc::clone(&token_manager),
        Arc::clone(&repo_cache),
        Arc::clone(&registry),
        cfg.git_head_timeout_secs,
    );

    let ignore_rule_count = ignore_patterns.len();
    let worker_settings = WorkerSettings {
        ignore_patterns: Arc::new(ignore_patterns),
        scan_workers: cfg.scan_workers,
        claim_batch: cfg.claim_batch,
        validate_secrets: cfg.validate_secrets,
        azure_active_probe: cfg.azure_active_probe,
    };
    let worker_service = Arc::new(WorkerLifecycleService::new(
        Arc::clone(&registry),
        worker_settings,
    ));
    let claim_service = Arc::new(ClaimService::new(
        Arc::clone(&store),
        Arc::clone(&registry),
        Arc::clone(&token_manager),
        cfg.lease_secs,
    ));
    let report_service = Arc::new(ReportService::new(
        Arc::clone(&store),
        Arc::clone(&repo_cache),
    ));

    // Enumerate centrally with the server's own credential unless a static list
    // was supplied. Claims may include authenticated clone URLs when available.
    if let Some(path) = cfg.list_path.clone() {
        app::info("server", "static list mode enabled");
        orchestrator.spawn_static_enqueue(path);
    } else {
        let configured_since = cfg.enum_since;
        let cursor_file = cfg.enum_cursor_file.clone();
        let checkpoint_since = load_enum_cursor_checkpoint(&cursor_file).unwrap_or(0);
        let cache_since = repo_cache.enum_cursor().unwrap_or(0);
        let since = configured_since.max(checkpoint_since).max(cache_since);
        if since != configured_since {
            app::info(
                "server",
                format!(
                    "resuming cursor {} (config={}, checkpoint={}, cache={})",
                    since, configured_since, checkpoint_since, cache_since
                ),
            );
        }
        orchestrator.spawn_enumeration(since, cursor_file);
    }

    let state = AppState {
        store: Arc::clone(&store),
        registry: Arc::clone(&registry),
        worker_service,
        claim_service,
        report_service,
        perf: Arc::new(ServerPerfMonitor::default()),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/heartbeat", post(heartbeat))
        .route("/unregister", post(unregister))
        .route("/claim", post(claim))
        .route("/report", post(report))
        .route("/stats", get(stats))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind)
        .await
        .with_context(|| format!("bind {} failed", cfg.bind))?;

    app::info("server", format!("listening on http://{}", cfg.bind));
    app::info(
        "server",
        format!(
            "config workers={} claim_batch={} ignore_rules={} validate_secrets={} azure_active_probe={}",
            cfg.scan_workers,
            cfg.claim_batch,
            ignore_rule_count,
            cfg.validate_secrets,
            cfg.azure_active_probe
        ),
    );

    axum::serve(listener, app)
        .await
        .context("serve loop failed")?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

/// Register a worker (or refresh an existing one) and return its scan config.
async fn register(
    State(app): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Json<WorkerConfig> {
    let config = app.worker_service.register(&req.worker_id);
    app::debug("server", format!("worker {} registered", req.worker_id));
    Json(config)
}

/// Heartbeat: refresh liveness and return the current config.
async fn heartbeat(
    State(app): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Json<WorkerConfig> {
    Json(app.worker_service.heartbeat(&req.worker_id))
}

/// Explicitly remove a worker when it shuts down.
async fn unregister(State(app): State<AppState>, Json(req): Json<UnregisterRequest>) -> Json<Ack> {
    let ack = app.worker_service.unregister(&req.worker_id);
    app::debug("server", format!("worker {} unregistered", req.worker_id));
    Json(ack)
}

async fn claim(State(app): State<AppState>, Json(_req): Json<ClaimRequest>) -> Json<ClaimResponse> {
    let started = Instant::now();
    // The server drives allocation: it hands this bot an even round-robin slice
    // of the pending queue, so the client's requested batch size is advisory.
    let response = app.claim_service.claim().await;
    app.perf.observe_claim(started.elapsed());
    Json(response)
}

async fn report(State(app): State<AppState>, Json(report): Json<SubmitReport>) -> Json<Ack> {
    let started = Instant::now();
    let ack = app.report_service.submit(report);
    app.perf.observe_report(started.elapsed());
    Json(ack)
}

async fn stats(State(app): State<AppState>) -> Json<StoreStats> {
    let started = Instant::now();
    let mut s = app.store.stats();
    s.active_workers = app.registry.active_count();
    s.perf = Some(app.perf.snapshot());
    app.perf.observe_stats(started.elapsed());
    Json(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_core::round_robin_claim_count;

    #[test]
    fn round_robin_splits_pending_evenly_across_bots() {
        // 100 urls across 5 connected bots -> 20 each, mutually exclusive.
        assert_eq!(round_robin_claim_count(100, 5), 20);
        // Uneven splits round up so no item is stranded.
        assert_eq!(round_robin_claim_count(9, 2), 5);
        assert_eq!(round_robin_claim_count(3, 3), 1);
    }

    #[test]
    fn round_robin_handles_bounds_and_empty_inputs() {
        assert_eq!(round_robin_claim_count(0, 0), 1);
        // A lone bot still can't drain more than MAX_CLAIM in one claim.
        assert_eq!(round_robin_claim_count(10_000, 1), MAX_CLAIM);
    }
}
