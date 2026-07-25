use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_SCAN_WORKERS: usize = 4;
const DEFAULT_CLAIM_BATCH: usize = 10;
const DEFAULT_WORKER_TTL_SECS: u64 = 60;
const DEFAULT_VALIDATE_SECRETS: bool = true;
const DEFAULT_AZURE_ACTIVE_PROBE: bool = false;
const DEFAULT_LEASE_SECS: u64 = 300;
const DEFAULT_ENUM_SINCE: u64 = 0;
const DEFAULT_ENUM_CURSOR_FILE: &str = ".enum-cursor.json";
const DEFAULT_GIT_HEAD_TIMEOUT_SECS: u64 = 15;

#[derive(Clone, Debug)]
pub(crate) struct ServerConfig {
    pub(crate) bind: SocketAddr,
    pub(crate) worker_ttl_secs: u64,
    pub(crate) scan_workers: usize,
    pub(crate) claim_batch: usize,
    pub(crate) validate_secrets: bool,
    pub(crate) azure_active_probe: bool,
    pub(crate) lease_secs: u64,
    pub(crate) list_path: Option<PathBuf>,
    pub(crate) enum_since: u64,
    pub(crate) enum_cursor_file: PathBuf,
    pub(crate) git_head_timeout_secs: u64,
}

impl ServerConfig {
    pub(crate) fn from_env(max_claim: usize) -> Result<Self> {
        let bind: SocketAddr = std::env::var("SECUREKIT_BIND")
            .unwrap_or_else(|_| DEFAULT_BIND.to_string())
            .parse()
            .context("SECUREKIT_BIND is invalid")?;

        Ok(Self {
            bind,
            worker_ttl_secs: u64_from_env("SECUREKIT_WORKER_TTL_SECS", DEFAULT_WORKER_TTL_SECS),
            scan_workers: usize_from_env("SECUREKIT_SCAN_WORKERS", DEFAULT_SCAN_WORKERS),
            claim_batch: usize_from_env("SECUREKIT_CLAIM_BATCH", DEFAULT_CLAIM_BATCH)
                .min(max_claim),
            validate_secrets: bool_from_env("SECUREKIT_VALIDATE_SECRETS", DEFAULT_VALIDATE_SECRETS),
            azure_active_probe: bool_from_env(
                "SECUREKIT_AZURE_ACTIVE_PROBE",
                DEFAULT_AZURE_ACTIVE_PROBE,
            ),
            lease_secs: u64_from_env("SECUREKIT_LEASE_SECS", DEFAULT_LEASE_SECS),
            list_path: std::env::var("SECUREKIT_LIST_FILE").ok().map(PathBuf::from),
            enum_since: u64_from_env("SECUREKIT_ENUM_SINCE", DEFAULT_ENUM_SINCE),
            enum_cursor_file: std::env::var("SECUREKIT_ENUM_CURSOR_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(DEFAULT_ENUM_CURSOR_FILE)),
            git_head_timeout_secs: u64_from_env(
                "SECUREKIT_GIT_HEAD_TIMEOUT_SECS",
                DEFAULT_GIT_HEAD_TIMEOUT_SECS,
            )
            .max(1),
        })
    }
}

fn usize_from_env(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(default)
}

fn u64_from_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn bool_from_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}
