//! Wire types shared between the coordination server and its scanning clients.
//!
//! Findings exchanged between clients and server include the matched secret
//! value, its SHA-256 fingerprint, and file location.

use serde::{Deserialize, Serialize};

/// A single unit of work handed to a client: a repository to scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkItem {
    /// Stable id assigned by the server (also the queue key / lease key).
    pub id: u64,
    /// Repository URL or path to scan.
    pub repo: String,
    /// Optional authenticated clone URL minted by the server for this lease.
    /// Clients should prefer this when present and still report `repo` as the
    /// canonical repository identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_url: Option<String>,
}

/// Client -> server: "give me up to `count` repositories to scan".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub worker_id: String,
    pub count: usize,
}

/// Client -> server: "I'm here, register/refresh my liveness" (used by both
/// `/register` at startup and `/heartbeat` periodically).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub worker_id: String,
}

/// Client -> server: "I'm shutting down; remove me from the active registry".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnregisterRequest {
    pub worker_id: String,
}

/// Server -> client: the leased work items (may be fewer than requested, or
/// empty when the queue is drained).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub items: Vec<WorkItem>,
    /// True when the server has finished enumerating public repositories **and**
    /// the claim queue is drained, i.e. no more work will ever arrive. An empty
    /// `items` with this set tells a client it may exit; empty with this unset
    /// means "queue momentarily empty, back off and poll again".
    #[serde(default)]
    pub enumeration_done: bool,
}

/// Server -> client: the complete operating configuration a worker needs.
///
/// This is the response to both `/register` and `/heartbeat`, so a client can
/// bootstrap from **nothing but a server URL**.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Seconds after which the server considers this worker dead if it has not
    /// sent another heartbeat. Clients should ping well within this window.
    pub ttl_secs: u64,
    /// Ignore regexes (as strings) the client compiles and applies to findings.
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    /// Number of repositories the client should scan in parallel.
    pub scan_workers: usize,
    /// How many repositories to lease from `/claim` per request.
    pub claim_batch: usize,
    /// Whether clients should verify if detected secrets are still active.
    #[serde(default)]
    pub validate_secrets: bool,
    /// Whether clients should actively probe Azure storage credentials.
    #[serde(default)]
    pub azure_active_probe: bool,
}

/// A finding as it travels over the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireFinding {
    pub kind: String,
    /// Raw matched value from the scanner.
    pub match_text: String,
    /// Explicit raw secret value for JSONL consumers that expect this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_secret: Option<String>,
    /// `sha256:...` fingerprint of the raw value (for de-dup / tracking).
    pub fingerprint: String,
    pub file: String,
    /// Optional best-effort validity status (`valid`, `invalid`, `unknown`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<String>,
}

/// Client -> server: the result of scanning one work item.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitReport {
    pub worker_id: String,
    /// Queue lease id when the repo came from `/claim`; `None` for repos a
    /// client scanned outside the claim queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<u64>,
    pub repo: String,
    pub has_leak: bool,
    pub finding_count: usize,
    pub findings: Vec<WireFinding>,
    /// HEAD commit SHA scanned by the client when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
    /// Set when the client failed to scan the repo (clone error, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Server -> client acknowledgement for a submitted report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
}

/// Snapshot of the server queue, returned by `GET /stats`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StoreStats {
    pub pending: usize,
    pub inflight: usize,
    pub done: usize,
    pub repos_with_leaks: usize,
    /// Number of workers currently registered (active shards).
    #[serde(default)]
    pub active_workers: usize,
}
