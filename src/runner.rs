//! Standalone scan orchestration: gather the repo list (explicit, file,
//! enumeration, and/or search), scan in parallel, then emit results and
//! optional disclosure reports.

use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::app;
use crate::cache::{load_cache, save_cache, CachedRepo};
use crate::config::ScanConfig;
use crate::disclosure::write_disclosure_report;
use crate::github::enumerate_public_repos;
use crate::github_auth::TokenManager;
use crate::report::{write_output, Report};
use crate::scan::{load_ignore_patterns, scan_repo};
use crate::util::{current_unix_time, redact_secret};

fn load_repo_list(repos: &[String], repo_file: Option<&Path>) -> Result<Vec<String>> {
    let mut repos = repos.to_vec();
    if let Some(path) = repo_file {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read repo file: {}", path.display()))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                repos.push(trimmed.to_string());
            }
        }
    }
    Ok(repos)
}

/// Run a standalone scan: resolve credentials, gather the repo list (explicit,
/// file, enumeration, and/or search), scan in parallel, then emit results and
/// optional disclosure reports.
///
/// `.env` is expected to already be loaded (call [`crate::load_dotenv`] first).
pub async fn run_scan(cfg: ScanConfig) -> Result<()> {
    // Resolve the best available credential: GitHub App installation token if
    // configured, otherwise a PAT (GITHUB_TOKEN/GH_TOKEN), otherwise anonymous.
    // App installation tokens are auto-refreshed as they near expiry so long
    // crawls keep working past the ~1 hour token lifetime.
    let token_manager = Arc::new(TokenManager::from_env().await);

    let mut repos = load_repo_list(&cfg.repos, cfg.repo_file.as_deref())?;

    // With no explicit targets, scan every open (public) repository on GitHub.
    // Enumeration walks repos in ascending id order and can be split across a
    // fleet with the shard/range settings.
    if repos.is_empty() {
        let enumerated = enumerate_public_repos(
            cfg.since,
            cfg.until,
            cfg.shard_count,
            cfg.shard_index,
            cfg.enumerate_limit,
            &token_manager,
        )
        .await?;
        repos.extend(enumerated);
    }

    let ignore_patterns = load_ignore_patterns(
        cfg.no_default_ignores,
        &cfg.ignore_pattern,
        cfg.ignore_file.as_deref(),
    )?;
    let mut cache = load_cache()?;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.max_workers.max(1))
        .build()?;

    // Scan in chunks, refreshing the token between chunks so a crawl that runs
    // longer than a GitHub App token's ~1 hour lifetime keeps authenticating.
    let mut reports: Vec<Report> = Vec::with_capacity(repos.len());
    for chunk in repos.chunks(64) {
        let token = token_manager.token().await;
        let chunk_reports: Result<Vec<Report>> = pool.install(|| {
            chunk
                .par_iter()
                .map(|repo| {
                    scan_repo(
                        repo,
                        None,
                        &ignore_patterns,
                        &cache,
                        token.as_deref(),
                        cfg.validate_secrets,
                        cfg.azure_active_probe,
                    )
                })
                .collect()
        });
        reports.extend(chunk_reports?);
    }

    // Update the cache with the new commit SHAs. Build a URL-keyed map once so
    // applying all reports is O(N + M) instead of O(N * M).
    let mut by_url: std::collections::HashMap<String, CachedRepo> =
        cache.repos.drain(..).map(|r| (r.url.clone(), r)).collect();
    for report in &reports {
        if let Some(sha) = &report.commit_sha {
            by_url.insert(
                report.repo.clone(),
                CachedRepo {
                    url: report.repo.clone(),
                    commit_sha: sha.clone(),
                    timestamp: current_unix_time(),
                },
            );
        }
    }
    cache.repos = by_url.into_values().collect();
    save_cache(&cache)?;

    // Filter out skipped repos from output.
    reports.retain(|r| r.skipped.is_none());

    // Generate responsible-disclosure reports for repos with findings.
    // These always redact the secret value regardless of --show-raw-secrets.
    if let Some(dir) = &cfg.disclosure_dir {
        let token = token_manager.token().await;
        for report in reports.iter().filter(|r| r.has_leak) {
            if let Err(e) = write_disclosure_report(dir, report, &token).await {
                app::warn(
                    "scan",
                    format!("failed to write disclosure report for {}: {}", report.repo, e),
                );
            }
        }
    }

    // By default, redact secret values in the machine/console output so runs
    // don't accumulate a store of live credentials. Use --show-raw-secrets to
    // opt out (not recommended).
    if !cfg.show_raw_secrets {
        for report in reports.iter_mut() {
            for finding in report.findings.iter_mut() {
                finding.match_text = redact_secret(&finding.match_text);
            }
        }
    }

    let mut output_writer: Box<dyn Write> = if let Some(path) = &cfg.output_file {
        Box::new(
            File::create(path)
                .with_context(|| format!("failed to create output file: {}", path.display()))?,
        )
    } else {
        Box::new(io::stdout())
    };

    write_output(&mut *output_writer, cfg.output, &reports)?;

    Ok(())
}
