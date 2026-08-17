//! Client mode: a zero-credential scanning bot.
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
//! it backs off and polls
//! again; when the server signals enumeration is finished and drained, it exits.
//! A background heartbeat keeps the worker counted as alive.
//!
//! ## Secret handling
//! The raw secret value produced by the scanner never leaves this process. Each
//! finding is converted into a [`WireFinding`] carrying only the masked value,
//! a SHA-256 fingerprint, and the file location before being sent upstream.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rayon::prelude::*;
use regex::Regex;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::app;
use crate::protocol::{
    Ack, ClaimRequest, ClaimResponse, RegisterRequest, SubmitReport, UnregisterRequest,
    WireFinding, WorkerConfig,
};
use crate::{compile_ignore_patterns, scan_repo, ScanCache};

/// Shortest and longest backoff while waiting for the server to enumerate more
/// work into an empty claim queue. The cap is kept modest so a worker that
/// misses a few empty polls recovers quickly instead of being starved out of
/// every fresh batch by peers that are polling faster.
const MIN_IDLE_BACKOFF: Duration = Duration::from_secs(2);
const MAX_IDLE_BACKOFF: Duration = Duration::from_secs(10);
const MAX_REPORT_CONCURRENCY: usize = 16;

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

/// Generate a random RFC 4122 version-4 GUID (e.g.
/// `3f2504e0-4f89-41d3-9a0c-0305e82c3301`) used as the default worker id.
///
/// Every client gets a globally-unique id without coordination, so two bots
/// never collide in the server registry. Entropy is mixed from the clock, pid,
/// and a stack address and expanded with SplitMix64 — enough to avoid
/// collisions across a fleet without pulling in a uuid/rand dependency.
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

    let mut state = seed;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&next().to_le_bytes());
    bytes[8..].copy_from_slice(&next().to_le_bytes());
    // Stamp the version (4) and RFC 4122 variant bits.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    let mut guid = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            guid.push('-');
        }
        let _ = write!(guid, "{:02x}", byte);
    }
    guid
}

/// Scan a single (public) repository and build the redacted report to send
/// upstream. Runs on a rayon worker thread, so it must be free of async/`.await`.
/// The server may provide an authenticated clone URL per lease; the client
/// itself still manages no GitHub credential.
struct LocalReport {
    submit: SubmitReport,
}

struct ScanOptions {
    validate_secrets: bool,
    azure_active_probe: bool,
}

fn build_report(
    item_id: u64,
    repo: &str,
    clone_url: Option<&str>,
    worker_id: &str,
    ignore_patterns: &[Regex],
    cache: &ScanCache,
    options: &ScanOptions,
) -> LocalReport {
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
        Ok(r) => LocalReport {
            submit: SubmitReport {
                worker_id: worker_id.to_string(),
                item_id: Some(item_id),
                repo: repo.to_string(),
                has_leak: r.has_leak,
                finding_count: r.finding_count,
                // Submit the matched value and full finding metadata.
                findings: r
                    .findings
                    .iter()
                    .map(|f| WireFinding {
                        kind: f.kind.clone(),
                        match_text: f.match_text.clone(),
                        raw_secret: Some(format!("{}:{}", f.file, f.line)),
                        fingerprint: f.fingerprint.clone(),
                        file: f.file.clone(),
                        validity: f.validity.clone(),
                        validity_reason: f.validity_reason.clone(),
                    })
                    .collect(),
                commit_sha: r.commit_sha,
                error: None,
            },
        },
        Err(e) => LocalReport {
            submit: SubmitReport {
                worker_id: worker_id.to_string(),
                item_id: Some(item_id),
                repo: repo.to_string(),
                has_leak: false,
                finding_count: 0,
                findings: Vec::new(),
                commit_sha: None,
                error: Some(e.to_string()),
            },
        },
    }
}

/// Register with the server and return the initial worker config.
async fn register(http: &reqwest::Client, base: &str, worker_id: &str) -> Result<WorkerConfig> {
    http.post(format!("{}/register", base))
        .json(&RegisterRequest {
            worker_id: worker_id.to_string(),
        })
        .send()
        .await
        .context("register request failed")?
        .json()
        .await
        .context("register response decode failed")
}

/// Lease up to `count` repositories from the server's claim queue.
async fn claim(
    http: &reqwest::Client,
    base: &str,
    worker_id: &str,
    count: usize,
) -> Result<ClaimResponse> {
    http.post(format!("{}/claim", base))
        .json(&ClaimRequest {
            worker_id: worker_id.to_string(),
            count,
        })
        .send()
        .await
        .context("claim request failed")?
        .json()
        .await
        .context("claim response decode failed")
}

/// Spawn a background task that heartbeats the server so this worker stays
/// counted as alive (and its leases keep flowing).
fn spawn_heartbeat(
    http: reqwest::Client,
    base: String,
    worker_id: String,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = http
                .post(format!("{}/heartbeat", base))
                .json(&RegisterRequest {
                    worker_id: worker_id.clone(),
                })
                .send()
                .await
            {
                app::debug("client", format!("heartbeat failed: {}", e));
            }
        }
    })
}

fn report_concurrency(scan_workers: usize, claim_batch: usize) -> usize {
    scan_workers
        .min(claim_batch)
        .clamp(1, MAX_REPORT_CONCURRENCY)
}

/// Pick a randomized wait in `[MIN_IDLE_BACKOFF, cap]` ("full jitter").
///
/// Randomizing the idle wait stops the fleet from polling in lock-step, which
/// otherwise lets a couple of workers repeatedly win every freshly enumerated
/// batch while others starve. Entropy comes from the wall-clock nanosecond,
/// which differs per process and per call — good enough to spread polls out.
fn jittered_backoff(cap: Duration) -> Duration {
    let min_ms = MIN_IDLE_BACKOFF.as_millis() as u64;
    let cap_ms = cap.as_millis() as u64;
    if cap_ms <= min_ms {
        return cap;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let span = cap_ms - min_ms;
    Duration::from_millis(min_ms + nanos % (span + 1))
}

/// Best-effort unregister call for graceful client shutdown.
async fn unregister(http: &reqwest::Client, base: &str, worker_id: &str) -> Result<()> {
    let ack: Ack = http
        .post(format!("{}/unregister", base))
        .json(&UnregisterRequest {
            worker_id: worker_id.to_string(),
        })
        .send()
        .await
        .context("unregister request failed")?
        .json()
        .await
        .context("unregister ack decode failed")?;

    if !ack.ok {
        anyhow::bail!("unregister rejected by server");
    }
    Ok(())
}

/// Entry point for the `securekit-client` binary.
///
/// Needs only a server URL: it registers for scan config, then repeatedly leases
/// public repo URLs from `/claim`, clones and scans them anonymously in
/// parallel, and reports redacted results until the server's queue is drained.
pub async fn run_client(server_url: &str, worker_id: Option<String>) -> Result<()> {
    let base = server_url.trim_end_matches('/').to_string();
    let worker_id = worker_id.unwrap_or_else(generate_guid);
    let http = reqwest::Client::new();
    // Client stays stateless: server owns repo cache/filtering decisions.
    let cache = ScanCache::default();

    // Join the fleet: the server hands us our scan config (no credential).
    let config = register(&http, &base, &worker_id).await?;
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
            base,
            config.ttl_secs,
            scan_workers,
            claim_batch,
            ignore_patterns.len(),
        ),
    );

    // Keep the worker alive in the background.
    let hb_interval = Duration::from_secs((config.ttl_secs / 3).max(5));
    let heartbeat = spawn_heartbeat(http.clone(), base.clone(), worker_id.clone(), hb_interval);
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
            resp = claim(&http, &base, &worker_id, claim_batch) => resp?,
        };

        if resp.items.is_empty() {
            if resp.enumeration_done {
                app::info(
                    "client",
                    format!("queue drained; {} scanned {} repo(s)", worker_id, scanned),
                );
                break;
            }
            // Queue momentarily empty; wait for the server to enumerate more.
            // Use jittered ("full jitter") backoff so the fleet desynchronizes:
            // without it, whichever workers first win work keep polling on a
            // short interval and monopolize every fresh batch, starving peers
            // whose backoff has grown. Jitter gives each worker a fair chance
            // to be the one polling when new work arrives.
            let wait = jittered_backoff(idle_backoff);
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    terminated_by_signal = true;
                    break;
                }
                _ = tokio::time::sleep(wait) => {}
            }
            idle_backoff = (idle_backoff * 2).min(MAX_IDLE_BACKOFF);
            continue;
        }
        idle_backoff = MIN_IDLE_BACKOFF;

        // Scan leased repos in parallel on the rayon pool.
        let scan_started = std::time::Instant::now();
        let local_reports: Vec<LocalReport> = pool.install(|| {
            resp.items
                .par_iter()
                .filter_map(|item| {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        return None;
                    }
                    Some(build_report(
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
                local_reports.len(),
                scan_started.elapsed().as_millis()
            ),
        );

        if shutdown_flag.load(Ordering::Relaxed) {
            terminated_by_signal = true;
            break;
        }

        // Report results with bounded concurrency (async I/O back to the server).
        let concurrency = report_concurrency(scan_workers, claim_batch);
        let limiter = Arc::new(Semaphore::new(concurrency));
        let mut report_tasks: JoinSet<Result<(SubmitReport, Ack)>> = JoinSet::new();
        let report_started = std::time::Instant::now();

        for local in local_reports {
            if shutdown_flag.load(Ordering::Relaxed) {
                terminated_by_signal = true;
                break;
            }

            let report = local.submit;
            let http = http.clone();
            let base = base.clone();
            let limiter = Arc::clone(&limiter);
            report_tasks.spawn(async move {
                let _permit = limiter
                    .acquire_owned()
                    .await
                    .context("report semaphore acquire failed")?;
                let ack: Ack = http
                    .post(format!("{}/report", base))
                    .json(&report)
                    .send()
                    .await
                    .with_context(|| format!("report submit failed for {}", report.repo))?
                    .json()
                    .await
                    .context("report ack decode failed")?;
                Ok((report, ack))
            });
        }

        while let Some(joined) = report_tasks.join_next().await {
            let result = joined.context("report task join failed")??;
            let (report, ack) = result;

            scanned += 1;
            let status = app::scan_status(report.error.is_some(), report.has_leak);
            let error_suffix = report
                .error
                .as_deref()
                .map(app::concise_error)
                .map(|e| format!(" | reason: {}", e))
                .unwrap_or_default();
            let server_suffix = if ack.ok { "" } else { " | server_rejected" };
            app::info(
                "client",
                format!(
                    "{} | repo={} | status={} | findings={}{}{}",
                    worker_id,
                    report.repo,
                    status,
                    report.finding_count,
                    server_suffix,
                    error_suffix
                ),
            );
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
    if let Err(e) = unregister(&http, &base, &worker_id).await {
        app::warn("client", format!("unregister failed: {}", e));
    }
    if terminated_by_signal {
        app::info("client", format!("{} terminated by signal", worker_id));
    }

    Ok(())
}
