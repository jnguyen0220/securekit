//! Secret scanning core: the pattern catalogue, repository cloning, ignore
//! rules, and the per-repository scan entry point ([`scan_repo`]).

use crate::app;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Once, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{collections::HashMap, collections::HashSet};

use anyhow::{Context, Result};
use rayon::prelude::*;
use regex::Regex;
use walkdir::WalkDir;

use crate::cache::{find_cached_sha, get_repo_commit_sha, ScanCache};
use crate::report::{Finding, Report};
use crate::util::{fingerprint_secret, github_authenticated_url, redact_url_credentials};
use crate::validation::validate_secret;

/// Built-in ignore rule that filters common placeholder/example credentials.
const DEFAULT_IGNORE_PATTERN: &str =
    r"(?i)(example|placeholder|changeme|dummy|fake|testdata|your[_-]?token|your[_-]?api[_-]?key)";

/// Default per-batch cap for parallel outbound secret validation calls.
const DEFAULT_VALIDATE_PARALLELISM: usize = 8;
/// Hard safety ceiling to avoid runaway thread fanout from environment config.
const MAX_VALIDATE_PARALLELISM: usize = 64;
/// Temp clone directories older than this are considered stale and removable.
const DEFAULT_CLONE_TMP_MAX_AGE_SECS: u64 = 24 * 60 * 60;
/// Number of retries after an initial clone failure for retryable HTTP/network
/// errors.
const DEFAULT_CLONE_RETRIES: u32 = 2;

fn validate_parallelism() -> usize {
    std::env::var("SECUREKIT_VALIDATE_PARALLELISM")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .map(|n| n.min(MAX_VALIDATE_PARALLELISM))
        .unwrap_or(DEFAULT_VALIDATE_PARALLELISM)
}

fn clone_tmp_max_age_secs() -> u64 {
    std::env::var("SECUREKIT_CLONE_TMP_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CLONE_TMP_MAX_AGE_SECS)
}

fn clone_retries() -> u32 {
    std::env::var("SECUREKIT_CLONE_RETRIES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_CLONE_RETRIES)
}

/// Build the *uncompiled* list of ignore regexes from the built-in defaults
/// (unless disabled), inline patterns, and an optional ignore file.
///
/// Returning the raw pattern strings (rather than compiled [`Regex`]es) lets
/// the coordination server ship the ruleset to clients over the wire, where
/// each client compiles it via [`load_ignore_patterns`].
pub fn load_ignore_pattern_strings(
    no_default_ignores: bool,
    ignore_pattern: &[String],
    ignore_file: Option<&Path>,
) -> Result<Vec<String>> {
    let mut patterns = Vec::new();
    if !no_default_ignores {
        patterns.push(DEFAULT_IGNORE_PATTERN.to_string());
    }

    for pattern in ignore_pattern {
        patterns.push(pattern.clone());
    }

    if let Some(path) = ignore_file {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read ignore file: {}", path.display()))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                patterns.push(trimmed.to_string());
            }
        }
    }

    Ok(patterns)
}

/// Build the list of ignore regexes from the built-in defaults (unless
/// disabled), inline patterns, and an optional ignore file.
pub fn load_ignore_patterns(
    no_default_ignores: bool,
    ignore_pattern: &[String],
    ignore_file: Option<&Path>,
) -> Result<Vec<Regex>> {
    load_ignore_pattern_strings(no_default_ignores, ignore_pattern, ignore_file)?
        .iter()
        .map(|p| Regex::new(p).with_context(|| format!("invalid ignore regex: {p}")))
        .collect()
}

/// Compile a set of ignore regexes received over the wire (from the server),
/// reporting which pattern failed to compile.
pub fn compile_ignore_patterns(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| Regex::new(p).with_context(|| format!("invalid ignore regex: {p}")))
        .collect()
}

fn should_ignore_finding(finding: &Finding, ignore_patterns: &[Regex]) -> bool {
    if ignore_patterns.is_empty() {
        return false;
    }
    let haystack = format!("{} {} {}", finding.kind, finding.file, finding.match_text);
    ignore_patterns
        .iter()
        .any(|pattern| pattern.is_match(&haystack))
}

/// The secret-detection pattern catalogue, compiled exactly once on first use
/// and shared across every repository scan (and every rayon worker thread).
fn secret_patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            ("aws_access_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            ("github_token", Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap()),
            ("github_oauth", Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap()),
            (
                "github_pat",
                Regex::new(r"github_pat_[A-Za-z0-9_]{20,}").unwrap(),
            ),
            (
                "slack_token",
                Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
            ),
            (
                "slack_webhook",
                Regex::new(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+").unwrap(),
            ),
            (
                "google_api_key",
                Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap(),
            ),
            (
                "azure_storage_connection_string",
                Regex::new(
                    r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/=]{40,};EndpointSuffix=core\.windows\.net",
                )
                .unwrap(),
            ),
            (
                "azure_sas_token",
                Regex::new(r"sv=[^\s&]+&[^\s]*sig=[^\s&]+(?:&[^\s]*)*").unwrap(),
            ),
            (
                "stripe_secret_key",
                Regex::new(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}").unwrap(),
            ),
            (
                "stripe_restricted_key",
                Regex::new(r"rk_(?:live|test)_[0-9a-zA-Z]{24,}").unwrap(),
            ),
            (
                "openai_api_key",
                Regex::new(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}").unwrap(),
            ),
            (
                "gitlab_pat",
                Regex::new(r"glpat-[0-9a-zA-Z_\-]{20}").unwrap(),
            ),
            ("npm_token", Regex::new(r"npm_[A-Za-z0-9]{36}").unwrap()),
            (
                "sendgrid_api_key",
                Regex::new(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}").unwrap(),
            ),
            ("twilio_api_key", Regex::new(r"SK[0-9a-fA-F]{32}").unwrap()),
            (
                "private_key",
                Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----").unwrap(),
            ),
            (
                "jwt",
                Regex::new(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
                    .unwrap(),
            ),
        ]
    })
}

fn scan_repo_dir(
    path: &Path,
    validate_secrets: bool,
    azure_active_probe: bool,
) -> Result<Vec<Finding>> {
    let patterns = secret_patterns();

    let mut findings = Vec::new();
    let skip_dirs = [
        ".git",
        "node_modules",
        "venv",
        "env",
        "__pycache__",
        ".venv",
        "dist",
        "build",
        ".next",
    ];
    // Binary/asset extensions to skip (without the leading dot).
    let skip_exts = [
        "png", "jpg", "jpeg", "gif", "pdf", "zip", "gz", "tar", "woff", "woff2", "ico",
    ];

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_dir() {
            let name = entry.file_name().to_string_lossy();
            if skip_dirs.contains(&name.as_ref()) {
                continue;
            }
        }

        if entry.file_type().is_file() {
            let ext = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if skip_exts.contains(&ext) {
                continue;
            }

            if let Ok(content) = fs::read_to_string(entry.path()) {
                let rel_path = entry
                    .path()
                    .strip_prefix(path)
                    .unwrap_or(entry.path())
                    .display()
                    .to_string();
                for (kind, pattern) in patterns {
                    for m in pattern.find_iter(&content) {
                        let secret = m.as_str().to_string();
                        let line = content[..m.start()].bytes().filter(|&b| b == b'\n').count() + 1;
                        findings.push(Finding {
                            kind: (*kind).to_string(),
                            fingerprint: fingerprint_secret(&secret),
                            match_text: secret,
                            file: rel_path.clone(),
                            line,
                            validity: None,
                        });
                    }
                }
            }
        }
    }

    if validate_secrets && !findings.is_empty() {
        // Validate only first-seen unique secrets and reuse result for repeats.
        let mut seen = HashSet::new();
        let mut unique_inputs: Vec<(String, String)> = Vec::new();
        for finding in &findings {
            if seen.insert(finding.match_text.clone()) {
                unique_inputs.push((finding.kind.clone(), finding.match_text.clone()));
            }
        }

        let batch_size = validate_parallelism();
        let mut validity_cache: HashMap<String, Option<String>> = HashMap::new();

        for chunk in unique_inputs.chunks(batch_size) {
            let resolved: Vec<(String, Option<String>)> = chunk
                .par_iter()
                .map(|(kind, secret)| {
                    (
                        secret.clone(),
                        validate_secret(kind, secret, azure_active_probe),
                    )
                })
                .collect();

            for (secret, validity) in resolved {
                validity_cache.insert(secret, validity);
            }
        }

        for finding in &mut findings {
            finding.validity = validity_cache
                .get(&finding.match_text)
                .cloned()
                .unwrap_or(None);
        }
    }

    Ok(findings)
}

fn clone_error_is_retryable(stderr: &str) -> bool {
    let msg = stderr.to_ascii_lowercase();
    msg.contains("requested url returned error: 403")
        || msg.contains("requested url returned error: 429")
        || msg.contains("the remote end hung up unexpectedly")
        || msg.contains("operation timed out")
        || msg.contains("connection timed out")
        || msg.contains("connection reset")
        || msg.contains("could not resolve host")
        || msg.contains("failure when receiving data from the peer")
}

fn clone_retry_delay(attempt: u32) -> Duration {
    Duration::from_secs(2u64.saturating_pow(attempt.min(4)))
}

/// Best-effort cleanup of stale clone dirs from prior runs.
///
/// This runs once per process, only touches `secret-scan-*` directories in the
/// system temp directory, and removes only those older than the configured age.
fn cleanup_stale_clone_dirs_once() {
    static CLEANUP_ONCE: Once = Once::new();
    CLEANUP_ONCE.call_once(|| {
        let max_age = clone_tmp_max_age_secs();
        if max_age == 0 {
            return;
        }

        let now = SystemTime::now();
        let base = std::env::temp_dir();
        let Ok(entries) = fs::read_dir(&base) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with("secret-scan-") {
                continue;
            }

            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }

            let Ok(modified) = meta.modified() else {
                continue;
            };
            let age_secs = now.duration_since(modified).unwrap_or_default().as_secs();
            if age_secs < max_age {
                continue;
            }

            if let Err(e) = fs::remove_dir_all(&path) {
                app::debug(
                    "scan",
                    format!("failed to remove stale clone dir {}: {}", path.display(), e),
                );
            }
        }
    });
}

/// Create a unique temp directory for cloning without collisions across
/// concurrent workers/processes.
fn create_unique_clone_dir(repo_name: &str) -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let pid = std::process::id();

    for attempt in 0..64u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = base.join(format!(
            "secret-scan-{}-{}-{}-{}",
            repo_name, pid, nanos, attempt
        ));

        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to create temp clone dir {}", dir.display()))
            }
        }
    }

    anyhow::bail!("failed to allocate unique temp clone dir for {}", repo_name);
}

fn clone_repo(repo_url: &str, token: Option<&str>) -> Result<PathBuf> {
    cleanup_stale_clone_dirs_once();

    let repo_name = repo_url
        .trim_end_matches('/')
        .split('/')
        .next_back()
        .unwrap_or("repo");
    let clone_url =
        github_authenticated_url(repo_url, token).unwrap_or_else(|| repo_url.to_string());
    let redacted_repo = redact_url_credentials(repo_url);
    let retries = clone_retries();

    for attempt in 0..=retries {
        let temp_dir = create_unique_clone_dir(repo_name)?;
        let output = Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg(&clone_url)
            .arg(&temp_dir)
            .output()
            .with_context(|| format!("failed to run git clone for {}", redacted_repo))?;

        if output.status.success() {
            return Ok(temp_dir);
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let retryable = clone_error_is_retryable(&stderr);
        let _ = fs::remove_dir_all(&temp_dir);

        if retryable && attempt < retries {
            let delay = clone_retry_delay(attempt);
            app::warn(
                "scan",
                format!(
                    "git clone retry {}/{} for {}: {}",
                    attempt + 1,
                    retries,
                    redacted_repo,
                    stderr
                ),
            );
            std::thread::sleep(delay);
            continue;
        }

        if stderr.is_empty() {
            anyhow::bail!("git clone failed for {}", redacted_repo);
        }
        anyhow::bail!("git clone failed for {}: {}", redacted_repo, stderr);
    }

    anyhow::bail!("git clone failed for {}", redacted_repo)
}

/// Resolve the current HEAD commit SHA for a local checkout path or a remote
/// repository URL.
///
/// Returns `Ok(None)` when no refs/HEAD are available (for example, an empty
/// repository).
fn resolve_repo_head_sha(repo: &str, token: Option<&str>) -> Result<Option<String>> {
    let output = if Path::new(repo).exists() {
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .with_context(|| format!("failed to read local HEAD for {}", repo))?
    } else {
        let repo_for_lookup =
            github_authenticated_url(repo, token).unwrap_or_else(|| repo.to_string());
        Command::new("git")
            .arg("ls-remote")
            .arg(&repo_for_lookup)
            .arg("HEAD")
            .output()
            .with_context(|| format!("failed to read remote HEAD for {}", repo))?
    };

    if !output.status.success() {
        anyhow::bail!("failed to resolve HEAD for {}", repo);
    }

    let text = String::from_utf8(output.stdout).context("failed to parse git output")?;
    Ok(text.split_whitespace().next().map(|s| s.to_string()))
}

fn absolutize_finding_paths(repo: &str, findings: &mut [Finding]) {
    if Path::new(repo).exists() {
        let base = fs::canonicalize(repo).unwrap_or_else(|_| PathBuf::from(repo));
        for finding in findings.iter_mut() {
            let rel = Path::new(&finding.file);
            if rel.is_absolute() {
                continue;
            }
            finding.file = base.join(rel).display().to_string();
        }
        return;
    }

    let repo_prefix = repo.trim_end_matches('/').trim_end_matches(".git");
    for finding in findings.iter_mut() {
        let rel = finding.file.trim_start_matches("./");
        finding.file = format!("{}/{}", repo_prefix, rel);
    }
}

pub(crate) fn scan_repo(
    repo: &str,
    clone_source_override: Option<&str>,
    ignore_patterns: &[Regex],
    cache: &ScanCache,
    token: Option<&str>,
    validate_secrets: bool,
    azure_active_probe: bool,
) -> Result<Report> {
    let clone_source = clone_source_override.unwrap_or(repo);

    // Resolve HEAD once up front so cache checks can skip unchanged repos
    // without cloning. If lookup fails, proceed with a normal scan.
    let pre_scan_sha = resolve_repo_head_sha(repo, token).ok().flatten();

    if let Some(cached_sha) = find_cached_sha(repo, cache) {
        if pre_scan_sha.as_deref() == Some(cached_sha.as_str()) {
            app::debug("scan", format!("skip unchanged {}", repo));
            return Ok(Report {
                repo: repo.to_string(),
                finding_count: 0,
                findings: Vec::new(),
                has_leak: false,
                skipped: Some("no changes".to_string()),
                commit_sha: pre_scan_sha,
            });
        }
    }

    let is_local_repo = Path::new(repo).exists();
    let (findings, sha) = if is_local_repo {
        (
            scan_repo_dir(Path::new(repo), validate_secrets, azure_active_probe)?,
            pre_scan_sha.or_else(|| get_repo_commit_sha(Path::new(repo)).ok()),
        )
    } else {
        let repo_dir = clone_repo(clone_source, token)?;
        let sha = get_repo_commit_sha(&repo_dir).ok();
        let result = scan_repo_dir(&repo_dir, validate_secrets, azure_active_probe);
        let _ = fs::remove_dir_all(&repo_dir);
        (result?, sha)
    };

    let mut findings: Vec<Finding> = findings
        .into_iter()
        .filter(|finding| !should_ignore_finding(finding, ignore_patterns))
        .collect();

    absolutize_finding_paths(repo, &mut findings);

    Ok(Report {
        repo: repo.to_string(),
        finding_count: findings.len(),
        has_leak: !findings.is_empty(),
        findings,
        skipped: None,
        commit_sha: sha,
    })
}
