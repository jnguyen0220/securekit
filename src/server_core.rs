//! Server functional core: pure decision and formatting logic.
//!
//! Like [`crate::client_core`], nothing here performs I/O or mutates shared
//! state. These functions turn inputs (a claim request, a submitted report)
//! into decisions and log lines that the imperative shell
//! ([`crate::server`]) and the use-case services ([`crate::server_usecase`])
//! then act on. Keeping them pure means the queue-fairness math and the
//! operator-facing status text are unit-testable in isolation.

use crate::app;
use crate::protocol::SubmitReport;

/// Hard cap on how many items a single claim can lease, to keep one greedy
/// client from draining the queue.
pub(crate) const MAX_CLAIM: usize = 100;

/// Even round-robin share of the pending queue for a single connected worker.
///
/// With `pending` items and `active_workers` bots connected, each bot leases an
/// equal, mutually-exclusive slice — e.g. 100 pending across 5 bots -> 20 each.
/// Leased items are removed from the shared queue, so the slices never overlap
/// and every bot scans its slice in parallel. The share is clamped to
/// [`MAX_CLAIM`] so one claim can never drain the queue when the worker count is
/// momentarily low (for example a single bot at startup).
pub(crate) fn round_robin_claim_count(pending: usize, active_workers: usize) -> usize {
    let workers = active_workers.max(1);
    pending.max(1).div_ceil(workers).clamp(1, MAX_CLAIM)
}

/// Build the per-report progress line the server logs, plus whether it is
/// "important" (a leak or a skipped/failed scan) for the operator.
pub(crate) fn format_report_progress(report: &SubmitReport) -> (bool, String) {
    let status = if report.error.is_some() {
        "skip"
    } else {
        "scan"
    };
    let reason = report
        .error
        .as_deref()
        .map(app::concise_error)
        .map(|e| format!(" | reason: {}", e))
        .unwrap_or_default();
    let important = report.has_leak || report.error.is_some();
    (
        important,
        format!(
            "{} | repo={} | status={} | findings={}{}",
            report.worker_id, report.repo, status, report.finding_count, reason
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(has_leak: bool, error: Option<&str>) -> SubmitReport {
        SubmitReport {
            worker_id: "w1".to_string(),
            item_id: Some(1),
            repo: "https://github.com/acme/repo".to_string(),
            has_leak,
            finding_count: if has_leak { 2 } else { 0 },
            findings: Vec::new(),
            commit_sha: Some("abc123".to_string()),
            error: error.map(str::to_string),
        }
    }

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

    #[test]
    fn format_report_progress_marks_clean_scan_unimportant() {
        let (important, line) = format_report_progress(&report(false, None));
        assert!(!important);
        assert!(line.contains("status=scan"));
        assert!(line.contains("findings=0"));
    }

    #[test]
    fn format_report_progress_flags_leaks_and_skips() {
        let (important, line) = format_report_progress(&report(true, None));
        assert!(important);
        assert!(line.contains("status=scan"));

        let (important, line) = format_report_progress(&report(false, Some("clone failed")));
        assert!(important);
        assert!(line.contains("status=skip"));
        assert!(line.contains("reason: clone failed"));
    }
}
