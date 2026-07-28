use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::util::{
    bool_from_env, path_from_env, path_or_default_from_env, u64_from_env, usize_from_env_min,
};

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
            scan_workers: usize_from_env_min("SECUREKIT_SCAN_WORKERS", DEFAULT_SCAN_WORKERS, 1),
            claim_batch: usize_from_env_min("SECUREKIT_CLAIM_BATCH", DEFAULT_CLAIM_BATCH, 1)
                .min(max_claim),
            validate_secrets: bool_from_env("SECUREKIT_VALIDATE_SECRETS", DEFAULT_VALIDATE_SECRETS),
            azure_active_probe: bool_from_env(
                "SECUREKIT_AZURE_ACTIVE_PROBE",
                DEFAULT_AZURE_ACTIVE_PROBE,
            ),
            lease_secs: u64_from_env("SECUREKIT_LEASE_SECS", DEFAULT_LEASE_SECS),
            list_path: path_from_env("SECUREKIT_LIST_FILE"),
            enum_since: u64_from_env("SECUREKIT_ENUM_SINCE", DEFAULT_ENUM_SINCE),
            enum_cursor_file: path_or_default_from_env(
                "SECUREKIT_ENUM_CURSOR_FILE",
                DEFAULT_ENUM_CURSOR_FILE,
            ),
            git_head_timeout_secs: u64_from_env(
                "SECUREKIT_GIT_HEAD_TIMEOUT_SECS",
                DEFAULT_GIT_HEAD_TIMEOUT_SECS,
            )
            .max(1),
        })
    }
}
