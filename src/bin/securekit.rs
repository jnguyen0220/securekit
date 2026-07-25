//! `securekit` — standalone secret scanner.
//!
//! Scans one or more repositories (local paths or GitHub URLs) for likely
//! leaked secrets. Can also discover repositories to scan via GitHub search or
//! by enumerating public repositories, and can emit responsible-disclosure
//! reports. For the distributed workflow see `securekit-server` /
//! `securekit-client`.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use securekit::app;
use securekit::{load_dotenv, load_dotenv_from, run_scan, OutputFormat, ScanConfig};

#[derive(Parser, Debug)]
#[command(
    name = "securekit",
    author,
    version,
    about = "Scan repositories for likely leaked secrets"
)]
struct Args {
    #[arg(value_name = "REPO", help = "GitHub repository URL or local path")]
    repos: Vec<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to a .env file to load (defaults to ./.env if present)"
    )]
    env_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Text file with one repository URL/path per line"
    )]
    repo_file: Option<PathBuf>,

    #[arg(long, value_name = "FORMAT", value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,

    #[arg(
        long,
        value_name = "PATH",
        help = "Write results to this file instead of stdout"
    )]
    output_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "N",
        default_value_t = 4,
        help = "Maximum number of repositories to scan in parallel"
    )]
    max_workers: usize,

    #[arg(
        long,
        value_name = "PATTERN",
        help = "Regex pattern to ignore; can be provided multiple times"
    )]
    ignore_pattern: Vec<String>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Text file with one ignore regex per line"
    )]
    ignore_file: Option<PathBuf>,

    #[arg(
        long,
        help = "Disable the built-in ignore rules for common false positives"
    )]
    no_default_ignores: bool,

    #[arg(
        long,
        value_name = "ID",
        default_value_t = 0,
        help = "Start enumerating public repositories after this numeric repo ID (cursor)"
    )]
    since: u64,

    #[arg(
        long,
        value_name = "ID",
        help = "Stop enumerating once repo IDs exceed this value (upper bound of your shard's range)"
    )]
    until: Option<u64>,

    #[arg(
        long,
        value_name = "N",
        default_value_t = 1,
        help = "Total number of workers/bots sharing the enumeration workload"
    )]
    shard_count: u64,

    #[arg(
        long,
        value_name = "I",
        default_value_t = 0,
        help = "This worker's index (0-based). Processes repos where id % shard_count == shard_index"
    )]
    shard_index: u64,

    #[arg(
        long,
        value_name = "N",
        default_value_t = 100,
        help = "Maximum number of enumerated repositories to scan in this run"
    )]
    enumerate_limit: usize,

    #[arg(
        long,
        value_name = "DIR",
        help = "Write per-repo responsible-disclosure reports to this directory"
    )]
    disclosure_dir: Option<PathBuf>,

    #[arg(
        long,
        help = "Show full unredacted secret values in output (NOT recommended; leaks live credentials into your logs/DB)"
    )]
    show_raw_secrets: bool,

    #[arg(
        long,
        help = "Verify whether detected secrets are still active (currently supports GitHub tokens)"
    )]
    validate_secrets: bool,

    #[arg(
        long,
        help = "Actively probe Azure storage credentials using signed requests (off by default)"
    )]
    azure_active_probe: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // Load .env (if present) so a GitHub token can be picked up automatically.
    match args.env_file.as_deref() {
        Some(path) => {
            if !load_dotenv_from(path) {
                app::warn(
                    "securekit",
                    format!("env file not found: {}; continuing", path.display()),
                );
            }
        }
        None => load_dotenv(),
    }

    run_scan(ScanConfig {
        repos: args.repos,
        repo_file: args.repo_file,
        output: args.output,
        output_file: args.output_file,
        max_workers: args.max_workers,
        ignore_pattern: args.ignore_pattern,
        ignore_file: args.ignore_file,
        no_default_ignores: args.no_default_ignores,
        since: args.since,
        until: args.until,
        shard_count: args.shard_count,
        shard_index: args.shard_index,
        enumerate_limit: args.enumerate_limit,
        disclosure_dir: args.disclosure_dir,
        show_raw_secrets: args.show_raw_secrets,
        validate_secrets: args.validate_secrets,
        azure_active_probe: args.azure_active_probe,
    })
    .await
}
