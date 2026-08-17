//! Local scan cache: skip re-scanning a remote repo whose `HEAD` has not moved
//! since the last run.
//!
//! One file is maintained:
//! * [`COMMIT_CACHE_FILE`] stores the latest seen commit per repo.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const COMMIT_CACHE_FILE: &str = ".scan-cache.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CachedRepo {
    pub(crate) url: String,
    pub(crate) commit_sha: String,
    pub(crate) timestamp: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct ScanCache {
    pub(crate) repos: Vec<CachedRepo>,
    /// Last known GitHub public-repo enumeration cursor used by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) enum_cursor: Option<u64>,
    /// URL -> commit SHA lookup index, rebuilt on load. Not serialized (the
    /// on-disk format stays a plain list of repos).
    #[serde(skip)]
    index: HashMap<String, String>,
}

impl ScanCache {
    /// (Re)build the URL -> SHA index from `repos`. Call after mutating
    /// `repos` directly or after deserializing.
    pub(crate) fn rebuild_index(&mut self) {
        self.index = self
            .repos
            .iter()
            .map(|r| (r.url.clone(), r.commit_sha.clone()))
            .collect();
    }
}

pub(crate) fn load_cache() -> Result<ScanCache> {
    if Path::new(COMMIT_CACHE_FILE).exists() {
        let content = fs::read_to_string(COMMIT_CACHE_FILE)?;
        let mut cache: ScanCache = serde_json::from_str(&content).unwrap_or_default();
        cache.rebuild_index();
        Ok(cache)
    } else {
        Ok(ScanCache::default())
    }
}

pub(crate) fn save_cache(cache: &ScanCache) -> Result<()> {
    let content = serde_json::to_string_pretty(cache)?;
    fs::write(COMMIT_CACHE_FILE, content)?;
    Ok(())
}

pub(crate) fn get_repo_commit_sha(repo_dir: &Path) -> Result<String> {
    crate::git::local_head_sha(repo_dir)
        .with_context(|| format!("failed to get commit SHA from {}", repo_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("no HEAD commit in {}", repo_dir.display()))
}

pub(crate) fn find_cached_sha(repo_url: &str, cache: &ScanCache) -> Option<String> {
    cache.index.get(repo_url).cloned()
}
