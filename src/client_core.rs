//! Client functional core: pure, immutable decision and transform logic.
//!
//! Nothing in this module performs I/O, spawns tasks, reads the clock, or
//! mutates shared state. Every function is a deterministic mapping from its
//! inputs to its outputs; any entropy (clock jitter, GUID seed) is supplied by
//! the imperative shell. This keeps the interesting decisions — how long to
//! back off, when to exit, how a scan result becomes a wire report — trivially
//! testable and free of side effects. All the side effects live in
//! [`crate::client`] (orchestration) and [`crate::client_shell`] (network I/O).

use std::fmt::Write as _;
use std::time::Duration;

use crate::app;
use crate::protocol::{ClaimResponse, SubmitReport, WireFinding};
use crate::report::Report;

/// Shortest and longest backoff while waiting for the server to enumerate more
/// work into an empty claim queue. The cap is kept modest so a worker that
/// misses a few empty polls recovers quickly instead of being starved out of
/// every fresh batch by peers that are polling faster.
pub(crate) const MIN_IDLE_BACKOFF: Duration = Duration::from_secs(2);
pub(crate) const MAX_IDLE_BACKOFF: Duration = Duration::from_secs(10);
const MAX_REPORT_CONCURRENCY: usize = 16;

/// What the worker should do after a `/claim` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaimPlan {
    /// The response carried work items; scan them.
    Scan,
    /// Queue is momentarily empty; sleep `wait`, then poll again with
    /// `next_backoff` as the new cap.
    Idle {
        wait: Duration,
        next_backoff: Duration,
    },
    /// Enumeration is finished and the queue is drained; the worker may exit.
    Drained,
}

/// Decide what to do with a `/claim` response. Pure: `entropy_nanos` is the only
/// source of jitter and is supplied by the shell.
pub(crate) fn plan_claim(
    resp: &ClaimResponse,
    idle_backoff: Duration,
    entropy_nanos: u64,
) -> ClaimPlan {
    if !resp.items.is_empty() {
        ClaimPlan::Scan
    } else if resp.enumeration_done {
        ClaimPlan::Drained
    } else {
        ClaimPlan::Idle {
            wait: jittered_backoff(idle_backoff, entropy_nanos),
            next_backoff: next_idle_backoff(idle_backoff),
        }
    }
}

/// Grow the idle backoff toward [`MAX_IDLE_BACKOFF`] after an empty poll.
pub(crate) fn next_idle_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_IDLE_BACKOFF)
}

/// Pick a wait in `[MIN_IDLE_BACKOFF, cap]` ("full jitter").
///
/// Randomizing the idle wait stops the fleet from polling in lock-step, which
/// otherwise lets a couple of workers repeatedly win every freshly enumerated
/// batch while others starve. Entropy is provided by the caller so this stays
/// pure and testable.
pub(crate) fn jittered_backoff(cap: Duration, entropy_nanos: u64) -> Duration {
    let min_ms = MIN_IDLE_BACKOFF.as_millis() as u64;
    let cap_ms = cap.as_millis() as u64;
    if cap_ms <= min_ms {
        return cap;
    }
    let span = cap_ms - min_ms;
    Duration::from_millis(min_ms + entropy_nanos % (span + 1))
}

/// Bounded concurrency for reporting results back to the server.
pub(crate) fn report_concurrency(scan_workers: usize, claim_batch: usize) -> usize {
    scan_workers
        .min(claim_batch)
        .clamp(1, MAX_REPORT_CONCURRENCY)
}

/// Turn a successful scan [`Report`] into the redacted [`SubmitReport`] sent
/// upstream. The raw secret value never leaves the process: only the matched
/// text, a fingerprint, and the file location travel over the wire.
pub(crate) fn report_from_scan(
    item_id: u64,
    repo: &str,
    worker_id: &str,
    r: &Report,
) -> SubmitReport {
    SubmitReport {
        worker_id: worker_id.to_string(),
        item_id: Some(item_id),
        repo: repo.to_string(),
        has_leak: r.has_leak,
        finding_count: r.finding_count,
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
        commit_sha: r.commit_sha.clone(),
        error: None,
    }
}

/// Build the report describing a scan that failed (clone error, etc.).
pub(crate) fn report_from_error(
    item_id: u64,
    repo: &str,
    worker_id: &str,
    err: &str,
) -> SubmitReport {
    SubmitReport {
        worker_id: worker_id.to_string(),
        item_id: Some(item_id),
        repo: repo.to_string(),
        has_leak: false,
        finding_count: 0,
        findings: Vec::new(),
        commit_sha: None,
        error: Some(err.to_string()),
    }
}

/// Build the per-repo progress line and whether it is "important" (a leak,
/// scan error, or server rejection) for the operator.
pub(crate) fn format_report_progress(
    worker_id: &str,
    report: &SubmitReport,
    ack_ok: bool,
) -> (bool, String) {
    let status = app::scan_status(report.error.is_some(), report.has_leak);
    let error_suffix = report
        .error
        .as_deref()
        .map(app::concise_error)
        .map(|e| format!(" | reason: {}", e))
        .unwrap_or_default();
    let server_suffix = if ack_ok { "" } else { " | server_rejected" };
    let important = report.has_leak || report.error.is_some() || !ack_ok;
    (
        important,
        format!(
            "{} | repo={} | status={} | findings={}{}{}",
            worker_id, report.repo, status, report.finding_count, server_suffix, error_suffix
        ),
    )
}

/// Expand a 64-bit seed into a random RFC 4122 version-4 GUID (e.g.
/// `3f2504e0-4f89-41d3-9a0c-0305e82c3301`) used as the default worker id.
///
/// The shell supplies the entropy seed; this expansion is pure. SplitMix64
/// stretches the seed into 128 bits — enough to avoid collisions across a fleet
/// without pulling in a uuid/rand dependency.
pub(crate) fn guid_from_seed(seed: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::WorkItem;

    fn work_item(id: u64) -> WorkItem {
        WorkItem {
            id,
            repo: format!("https://github.com/acme/repo{id}"),
            clone_url: None,
        }
    }

    #[test]
    fn plan_claim_scans_when_items_present() {
        let resp = ClaimResponse {
            items: vec![work_item(1)],
            enumeration_done: false,
        };
        assert_eq!(plan_claim(&resp, MIN_IDLE_BACKOFF, 0), ClaimPlan::Scan);
    }

    #[test]
    fn plan_claim_drains_when_done_and_empty() {
        let resp = ClaimResponse {
            items: vec![],
            enumeration_done: true,
        };
        assert_eq!(plan_claim(&resp, MIN_IDLE_BACKOFF, 0), ClaimPlan::Drained);
    }

    #[test]
    fn plan_claim_idles_and_grows_backoff_when_empty() {
        let resp = ClaimResponse {
            items: vec![],
            enumeration_done: false,
        };
        match plan_claim(&resp, MIN_IDLE_BACKOFF, 0) {
            ClaimPlan::Idle { wait, next_backoff } => {
                assert!(wait >= MIN_IDLE_BACKOFF && wait <= MAX_IDLE_BACKOFF);
                assert_eq!(next_backoff, MIN_IDLE_BACKOFF * 2);
            }
            other => panic!("expected Idle, got {other:?}"),
        }
    }

    #[test]
    fn next_idle_backoff_is_capped() {
        assert_eq!(next_idle_backoff(MAX_IDLE_BACKOFF), MAX_IDLE_BACKOFF);
        assert_eq!(next_idle_backoff(MIN_IDLE_BACKOFF), MIN_IDLE_BACKOFF * 2);
    }

    #[test]
    fn jittered_backoff_stays_within_bounds() {
        let cap = MAX_IDLE_BACKOFF;
        for entropy in [0u64, 1, 12_345, u64::MAX] {
            let wait = jittered_backoff(cap, entropy);
            assert!(wait >= MIN_IDLE_BACKOFF && wait <= cap);
        }
        // A cap at the floor collapses to the floor.
        assert_eq!(jittered_backoff(MIN_IDLE_BACKOFF, 999), MIN_IDLE_BACKOFF);
    }

    #[test]
    fn report_concurrency_is_bounded() {
        assert_eq!(report_concurrency(0, 0), 1);
        assert_eq!(report_concurrency(4, 10), 4);
        assert_eq!(report_concurrency(100, 100), MAX_REPORT_CONCURRENCY);
    }

    #[test]
    fn report_from_error_marks_failure() {
        let report = report_from_error(7, "https://github.com/acme/x", "w1", "clone failed");
        assert_eq!(report.item_id, Some(7));
        assert!(!report.has_leak);
        assert_eq!(report.finding_count, 0);
        assert_eq!(report.error.as_deref(), Some("clone failed"));
    }

    #[test]
    fn format_report_progress_flags_leaks_and_rejections() {
        let clean = report_from_error(1, "r", "w", "");
        let mut clean = clean;
        clean.error = None;
        let (important, line) = format_report_progress("w", &clean, true);
        assert!(!important);
        assert!(line.contains("status=clean"));

        let leaky = SubmitReport {
            has_leak: true,
            finding_count: 3,
            ..clean.clone()
        };
        let (important, line) = format_report_progress("w", &leaky, true);
        assert!(important);
        assert!(line.contains("status=leak"));

        let (important, line) = format_report_progress("w", &clean, false);
        assert!(important);
        assert!(line.contains("server_rejected"));
    }

    #[test]
    fn guid_from_seed_is_deterministic_and_well_formed() {
        let a = guid_from_seed(0xDEAD_BEEF);
        let b = guid_from_seed(0xDEAD_BEEF);
        assert_eq!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.as_bytes()[14], b'4'); // version nibble
        assert!(matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_ne!(guid_from_seed(1), guid_from_seed(2));
    }
}
