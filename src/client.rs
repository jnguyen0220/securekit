//! Client mode: a zero-credential scanning bot.
//!
//! ## Functional core, imperative shell
//! The interesting decisions — how long to back off, when to exit, how a scan
//! result becomes a redacted wire report — live in [`crate::client_core`] as
//! pure, immutable functions. All network I/O is funneled through the single
//! choke point in [`crate::client_shell`]. This module is the imperative shell:
//! it owns the runtime (signals, the rayon pool, the heartbeat task) and wires
//! the pure core to the I/O choke point.
//!
//! ## Zero configuration
//! A client needs nothing but the server URL. On startup it `POST /register`s
//! and the server replies with a [`WorkerConfig`] — the ignore ruleset, the scan
//! concurrency, and how many repos to lease per claim. The client never reads a
//! credential or scan setting from its own environment.
//!
//! ## Work distribution
//! The server enumerates public repositories centrally and feeds their URLs into
//! a claim queue. The client repeatedly `POST /claim`s a batch of repo URLs,
//! uses a server-provided clone URL for each lease (authenticated when
//! available), scans it, and reports back. When the queue is momentarily empty
//! it backs off and polls again; when the server signals enumeration is finished
//! and drained, it exits. A background heartbeat keeps the worker counted as
//! alive.
//!
//! ## Secret handling
//! The raw secret value produced by the scanner never leaves this process. Each
//! finding is converted into a [`WireFinding`](crate::protocol::WireFinding)
//! carrying only the masked value, a SHA-256 fingerprint, and the file location
//! before being sent upstream.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rayon::prelude::*;
use regex::Regex;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::app;
use crate::client_core::{self, ClaimPlan, MIN_IDLE_BACKOFF};
use crate::client_shell::ServerLink;
use crate::protocol::{Ack, SubmitReport, WorkerConfig};
use crate::{compile_ignore_patterns, scan_repo, ScanCache};

/// Wait for a process termination signal.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Install exactly one shutdown listener for the process and expose it both as
/// a watch channel (for async waits) and an atomic flag (for rayon workers).
fn spawn_shutdown_listener() -> (watch::Receiver<bool>, Arc<AtomicBool>) {
    let (tx, rx) = watch::channel(false);
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_task = Arc::clone(&shutdown);

    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_task.store(true, Ordering::Relaxed);
        let _ = tx.send(true);
    });

    (rx, shutdown)
}

/// Mix entropy from the clock, pid, and a stack address for the GUID seed. This
/// is the impure half of worker-id generation; the expansion into an RFC 4122
/// GUID is done by the pure [`client_core::guid_from_seed`].
fn generate_guid() -> String {
    let seed = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let pid = std::process::id() as u64;
        let stack_marker = &nanos as *const _ as u64;
        nanos ^ pid.rotate_left(32) ^ stack_marker
    };
    client_core::guid_from_seed(seed)
}

/// Current wall-clock nanoseconds, used only as jitter entropy for the pure
/// backoff planner. Differs per process and per call.
fn entropy_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
}

struct ScanOptions {
    validate_secrets: bool,
    azure_active_probe: bool,
}

/// The one side effect in the scan path: clone + scan a repo, then hand the
/// result to the pure core to build the redacted wire report. Runs on a rayon
/// worker thread, so it must be free of async/`.await`.
fn scan_and_build(
    item_id: u64,
    repo: &str,
    clone_url: Option<&str>,
    worker_id: &str,
    ignore_patterns: &[Regex],
    cache: &ScanCache,
    options: &ScanOptions,
) -> SubmitReport {
    let clone_source = clone_url.unwrap_or(repo);
    match scan_repo(
        repo,
        Some(clone_source),
        ignore_patterns,
        cache,
        None,
        options.validate_secrets,
        options.azure_active_probe,
    ) {
        Ok(r) => client_core::report_from_scan(item_id, repo, worker_id, &r),
        Err(e) => client_core::report_from_error(item_id, repo, worker_id, &e.to_string()),
    }
}

/// Spawn a background task that heartbeats the server through the I/O choke
/// point so this worker stays counted as alive (and its leases keep flowing).
fn spawn_heartbeat(
    link: ServerLink,
    worker_id: String,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = link.heartbeat(&worker_id).await {
                app::debug("client", format!("heartbeat failed: {}", e));
            }
        }
    })
}

/// Entry point for the `securekit-client` binary.
///
/// Needs only a server URL: it registers for scan config, then repeatedly leases
/// public repo URLs from `/claim`, clones and scans them anonymously in
/// parallel, and reports redacted results until the server's queue is drained.
pub async fn run_client(server_url: &str, worker_id: Option<String>) -> Result<()> {
    let link = ServerLink::new(server_url);
    let worker_id = worker_id.unwrap_or_else(generate_guid);
    // Client stays stateless: server owns repo cache/filtering decisions.
    let cache = ScanCache::default();

    // Join the fleet: the server hands us our scan config (no credential).
    let config: WorkerConfig = link.register(&worker_id).await?;
    let scan_workers = config.scan_workers.max(1);
    let claim_batch = config.claim_batch.max(1);
    let ignore_patterns = compile_ignore_patterns(&config.ignore_patterns)
        .context("server ignore pattern invalid")?;
    let scan_options = ScanOptions {
        validate_secrets: config.validate_secrets,
        azure_active_probe: config.azure_active_probe,
    };

    // Dedicated pool so parallel scanning doesn't fight the async runtime.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(scan_workers)
        .build()
        .context("scan thread pool build failed")?;

    app::info(
        "client",
        format!(
            "{} ready at {} (ttl={}s, workers={}, claim_batch={}, ignore_rules={})",
            worker_id,
            link.base(),
            config.ttl_secs,
            scan_workers,
            claim_batch,
            ignore_patterns.len(),
        ),
    );

    // Keep the worker alive in the background.
    let hb_interval = Duration::from_secs((config.ttl_secs / 3).max(5));
    let heartbeat = spawn_heartbeat(link.clone(), worker_id.clone(), hb_interval);
    let (mut shutdown_rx, shutdown_flag) = spawn_shutdown_listener();

    // Lease → scan → report, until the server's queue is drained.
    let mut scanned = 0usize;
    let mut idle_backoff = MIN_IDLE_BACKOFF;
    let mut terminated_by_signal = false;
    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            terminated_by_signal = true;
            break;
        }

        let resp = tokio::select! {
            _ = shutdown_rx.changed() => {
                terminated_by_signal = true;
                break;
            }
            resp = link.claim(&worker_id, claim_batch) => resp?,
        };

        // Pure core decides the next step; the shell just carries it out.
        match client_core::plan_claim(&resp, idle_backoff, entropy_nanos()) {
            ClaimPlan::Drained => {
                app::info(
                    "client",
                    format!("queue drained; {} scanned {} repo(s)", worker_id, scanned),
                );
                break;
            }
            ClaimPlan::Idle { wait, next_backoff } => {
                // Jittered ("full jitter") backoff desynchronizes the fleet:
                // without it, whichever workers first win work keep polling on a
                // short interval and monopolize every fresh batch, starving peers
                // whose backoff has grown.
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        terminated_by_signal = true;
                        break;
                    }
                    _ = tokio::time::sleep(wait) => {}
                }
                idle_backoff = next_backoff;
                continue;
            }
            ClaimPlan::Scan => {}
        }
        idle_backoff = MIN_IDLE_BACKOFF;

        // Scan leased repos in parallel on the rayon pool.
        let scan_started = std::time::Instant::now();
        let reports: Vec<SubmitReport> = pool.install(|| {
            resp.items
                .par_iter()
                .filter_map(|item| {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        return None;
                    }
                    Some(scan_and_build(
                        item.id,
                        &item.repo,
                        item.clone_url.as_deref(),
                        &worker_id,
                        &ignore_patterns,
                        &cache,
                        &scan_options,
                    ))
                })
                .collect()
        });
        app::debug(
            "client",
            format!(
                "batch scan complete | repos={} | elapsed_ms={}",
                reports.len(),
                scan_started.elapsed().as_millis()
            ),
        );

        if shutdown_flag.load(Ordering::Relaxed) {
            terminated_by_signal = true;
            break;
        }

        // Report results with bounded concurrency (async I/O back to the server).
        let concurrency = client_core::report_concurrency(scan_workers, claim_batch);
        let limiter = Arc::new(Semaphore::new(concurrency));
        let mut report_tasks: JoinSet<Result<(SubmitReport, Ack)>> = JoinSet::new();
        let report_started = std::time::Instant::now();

        for report in reports {
            if shutdown_flag.load(Ordering::Relaxed) {
                terminated_by_signal = true;
                break;
            }

            let link = link.clone();
            let limiter = Arc::clone(&limiter);
            report_tasks.spawn(async move {
                let _permit = limiter
                    .acquire_owned()
                    .await
                    .context("report semaphore acquire failed")?;
                let ack = link
                    .report(&report)
                    .await
                    .with_context(|| format!("report submit failed for {}", report.repo))?;
                Ok((report, ack))
            });
        }

        while let Some(joined) = report_tasks.join_next().await {
            let (report, ack) = joined.context("report task join failed")??;

            scanned += 1;
            let (important, line) =
                client_core::format_report_progress(&worker_id, &report, ack.ok);
            app::progress("client", important, line);
        }
        app::debug(
            "client",
            format!(
                "batch report complete | elapsed_ms={} | concurrency={}",
                report_started.elapsed().as_millis(),
                concurrency
            ),
        );

        if terminated_by_signal {
            break;
        }
    }

    // Stop heartbeats first so we don't re-register right after unregistering.
    heartbeat.abort();
    if let Err(e) = link.unregister(&worker_id).await {
        app::warn("client", format!("unregister failed: {}", e));
    }
    if terminated_by_signal {
        app::info("client", format!("{} terminated by signal", worker_id));
    }

    Ok(())
}
