//! Configuration for a standalone scan run (`securekit` binary). The binary
//! parses its CLI flags into [`ScanConfig`] and hands it to
//! [`crate::run_scan`].

use std::path::PathBuf;

use crate::report::OutputFormat;

#[derive(Debug, Default)]
pub struct ScanConfig {
    /// Repository URLs or local paths passed positionally.
    pub repos: Vec<String>,
    /// Optional file with one repo URL/path per line.
    pub repo_file: Option<PathBuf>,
    /// Output format.
    pub output: OutputFormat,
    /// Write results here instead of stdout.
    pub output_file: Option<PathBuf>,
    /// Max repositories scanned in parallel.
    pub max_workers: usize,
    /// Extra ignore regexes.
    pub ignore_pattern: Vec<String>,
    /// File of ignore regexes (one per line).
    pub ignore_file: Option<PathBuf>,
    /// Disable the built-in false-positive ignore rules.
    pub no_default_ignores: bool,
    /// Enumeration start cursor (numeric repo id).
    pub since: u64,
    /// Enumeration upper-bound repo id.
    pub until: Option<u64>,
    /// Total workers sharing the enumeration workload.
    pub shard_count: u64,
    /// This worker's shard index.
    pub shard_index: u64,
    /// Max enumerated repositories to scan.
    pub enumerate_limit: usize,
    /// Write responsible-disclosure reports to this directory.
    pub disclosure_dir: Option<PathBuf>,
    /// Show raw (unredacted) secrets in output.
    pub show_raw_secrets: bool,
    /// Verify whether detected secrets still appear to be active.
    pub validate_secrets: bool,
    /// Perform active Azure probes (signed storage checks) to reduce `unknown`.
    pub azure_active_probe: bool,
}
