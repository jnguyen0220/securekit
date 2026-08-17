//! Small shared helpers used across the crate: time, hashing, redaction, and
//! `.env` loading.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Seconds since the UNIX epoch (0 if the clock is set before it).
pub(crate) fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// SHA-256 fingerprint of a secret. Storing the fingerprint (instead of the
/// raw value) lets you prove/track a leak and de-duplicate findings without
/// hoarding live credentials.
pub(crate) fn fingerprint_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// Redact a secret for display: keep the first/last 4 characters so an owner
/// can recognise the credential, mask the middle.
pub(crate) fn redact_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let n = chars.len();
    if n <= 8 {
        return "*".repeat(n);
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[n - 4..].iter().collect();
    format!("{}{}{}", prefix, "*".repeat(n - 8), suffix)
}

/// Build an authenticated HTTPS GitHub URL when a token is available.
///
/// Returns `None` for non-GitHub URLs, non-HTTPS URLs, or when no token is
/// provided.
pub(crate) fn github_authenticated_url(repo_url: &str, token: Option<&str>) -> Option<String> {
    match token {
        Some(t) if repo_url.starts_with("https://github.com/") => {
            Some(repo_url.replacen("https://", &format!("https://x-access-token:{}@", t), 1))
        }
        _ => None,
    }
}

/// Remove URL user-info (for example embedded tokens) before logging.
pub(crate) fn redact_url_credentials(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        if let Some((_, host_and_path)) = rest.split_once('@') {
            return format!("https://{}", host_and_path);
        }
    }
    url.to_string()
}

/// Build the GitHub User-Agent header used by API requests.
///
/// Prefer setting `SECUREKIT_USER_AGENT` explicitly. If it is unset, we fall
/// back to `securekit/<version>` and append an optional contact token from
/// `SECUREKIT_USER_AGENT_CONTACT` (for example, an email or docs URL).
pub(crate) fn github_user_agent() -> String {
    if let Some(explicit) = std::env::var("SECUREKIT_USER_AGENT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return explicit;
    }

    let mut ua = format!("securekit/{}", env!("CARGO_PKG_VERSION"));
    if let Some(contact) = std::env::var("SECUREKIT_USER_AGENT_CONTACT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        ua.push_str(&format!(" ({})", contact));
    }
    ua
}

/// Add bounded jitter to a base delay to avoid synchronized retries.
pub(crate) fn jittered_delay(base: Duration, max_jitter: Duration) -> Duration {
    let jitter_ms = max_jitter.as_millis() as u64;
    if jitter_ms == 0 {
        return base;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let salt = now ^ ((std::process::id() as u64) << 16);
    let offset_ms = salt % (jitter_ms + 1);
    base + Duration::from_millis(offset_ms)
}

/// Shared retry/backoff policy used by network and git operations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryPolicy {
    /// Number of retries after the initial attempt.
    pub(crate) max_retries: u32,
    /// Base delay before the first retry.
    pub(crate) base_delay: Duration,
    /// Maximum exponent used by exponential backoff.
    pub(crate) max_exponent: u32,
    /// Maximum random jitter added to each computed delay.
    pub(crate) jitter: Duration,
}

impl RetryPolicy {
    pub(crate) fn new(
        max_retries: u32,
        base_delay: Duration,
        max_exponent: u32,
        jitter: Duration,
    ) -> Self {
        Self {
            max_retries,
            base_delay,
            max_exponent,
            jitter,
        }
    }

    /// True when another retry is allowed after `attempt` failures.
    pub(crate) fn can_retry(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }

    /// Exponential backoff delay for a retry attempt, including jitter.
    pub(crate) fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.min(self.max_exponent));
        let base = self.base_delay.saturating_mul(factor);
        jittered_delay(base, self.jitter)
    }
}

/// Parse a boolean environment variable with a default fallback.
pub(crate) fn bool_from_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

/// Parse a usize environment variable with a minimum accepted value.
pub(crate) fn usize_from_env_min(key: &str, default: usize, min: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= min)
        .unwrap_or(default)
}

/// Parse a u64 environment variable with a default fallback.
pub(crate) fn u64_from_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Parse an optional path environment variable.
pub(crate) fn path_from_env(key: &str) -> Option<PathBuf> {
    std::env::var(key).ok().map(PathBuf::from)
}

/// Parse a path environment variable, using a default path when missing.
pub(crate) fn path_or_default_from_env(key: &str, default: &str) -> PathBuf {
    std::env::var(key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}

/// Read a list file with one entry per line, ignoring blanks and `#` comments.
pub(crate) fn read_list_file(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read list file {} failed", path.display()))?;
    let mut rows = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        rows.push(trimmed.to_string());
    }
    Ok(rows)
}

/// Load simple KEY=VALUE pairs from a `.env` file in the current directory
/// into the process environment (only if not already set). Lines starting
/// with `#` and blank lines are ignored. Values may be optionally quoted.
pub fn load_dotenv() {
    load_dotenv_from(Path::new(".env"));
}

/// Load simple KEY=VALUE pairs from the `.env`-style file at `path` into the
/// process environment (only if the variable is not already set). Lines
/// starting with `#` and blank lines are ignored; values may be optionally
/// quoted. Returns `true` if the file existed and was read, `false` otherwise.
pub fn load_dotenv_from(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let mut value = value.trim();
            if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value = &value[1..value.len().saturating_sub(1)];
            }
            if std::env::var(key).is_err() {
                std::env::set_var(key, value);
            }
        }
    }
    true
}
