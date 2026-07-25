//! GitHub REST API helpers: shared request headers, repository search, and
//! public-repo enumeration (with sharding) for research / responsible
//! disclosure.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::app;
use crate::github_auth::TokenManager;
use crate::util::current_unix_time;

#[derive(Debug, Deserialize)]
struct GitHubRepo {
    #[serde(default)]
    id: u64,
    clone_url: Option<String>,
    html_url: Option<String>,
    full_name: Option<String>,
}

impl GitHubRepo {
    /// Best available clone URL: an explicit `clone_url`/`html_url`, or one
    /// synthesised from `full_name`.
    fn best_url(&self) -> Option<String> {
        self.clone_url
            .clone()
            .or_else(|| self.html_url.clone())
            .or_else(|| {
                self.full_name
                    .clone()
                    .map(|name| format!("https://github.com/{}", name))
            })
    }
}

/// Apply the standard GitHub API headers, adding auth if a token is present.
pub(crate) fn github_headers(
    builder: reqwest::RequestBuilder,
    token: &Option<String>,
) -> reqwest::RequestBuilder {
    let mut b = builder
        .header("User-Agent", "secret-repo-scanner")
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(token) = token {
        b = b.header("Authorization", format!("Bearer {}", token));
    }
    b
}

/// Fetch a single page (up to 100) of public repos from GitHub's documented
/// "List public repositories" endpoint (`GET /repositories?since=`), starting
/// after `cursor`. Transparently refreshes an expired/revoked token and backs
/// off (sleeping) when the rate limit is exhausted. Returns the raw page.
async fn fetch_public_repos_page(
    client: &reqwest::Client,
    cursor: u64,
    token_manager: &TokenManager,
) -> Result<Vec<GitHubRepo>> {
    let url = format!(
        "https://api.github.com/repositories?since={}&per_page=100",
        cursor
    );
    loop {
        // Refresh the token as needed (App installation tokens expire ~hourly).
        let token = token_manager.token().await;
        let mut response = github_headers(client.get(&url), &token)
            .send()
            .await
            .context("GitHub API request failed")?;

        // A 401 can mean the token was revoked before expiry; re-mint and retry.
        if response.status().as_u16() == 401 {
            token_manager.force_refresh().await;
            let token = token_manager.token().await;
            response = github_headers(client.get(&url), &token)
                .send()
                .await
                .context("GitHub API request failed")?;
        }

        // Rate-limit handling: back off when exhausted, then retry.
        if response.status().as_u16() == 403 || response.status().as_u16() == 429 {
            let remaining = response
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if remaining <= 0 {
                let reset = response
                    .headers()
                    .get("x-ratelimit-reset")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or_else(|| current_unix_time() + 60);
                let wait = reset.saturating_sub(current_unix_time()).clamp(1, 3600);
                app::warn("github", format!("rate limit hit; sleeping {}s", wait));
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }
            anyhow::bail!("GitHub API returned {}", response.status());
        }

        if !response.status().is_success() {
            anyhow::bail!("GitHub API returned {}", response.status());
        }

        return response
            .json()
            .await
            .context("GitHub API response decode failed");
    }
}

/// Fetch one page of public repositories starting after `cursor`.
///
/// Returns the repo clone URLs on this page together with the cursor to pass on
/// the next call. When the returned cursor equals the input `cursor`,
/// enumeration has reached the end of GitHub (no more repositories). This is the
/// building block the server loops over to enqueue work continuously.
pub(crate) async fn enumerate_public_repos_page(
    client: &reqwest::Client,
    cursor: u64,
    token_manager: &TokenManager,
) -> Result<(Vec<String>, u64)> {
    let page = fetch_public_repos_page(client, cursor, token_manager).await?;
    if page.is_empty() {
        return Ok((Vec::new(), cursor));
    }

    let mut max_id = cursor;
    let mut repos = Vec::new();
    for repo in &page {
        max_id = max_id.max(repo.id);
        if let Some(url) = repo.best_url() {
            repos.push(url);
        }
    }
    Ok((repos, max_id))
}

/// Enumerate public repositories using GitHub's documented
/// "List public repositories" endpoint (`GET /repositories?since=`), which
/// walks repos in ascending numeric ID order. Supports sharding across a
/// distributed fleet via `shard_count`/`shard_index` (id % count == index)
/// and an optional upper-bound `until` cursor so each worker owns a range.
///
/// Honors GitHub rate limits with backoff. Requires a token (via .env /
/// GITHUB_TOKEN) for any realistic volume — anonymous is capped at 60 req/hr.
pub(crate) async fn enumerate_public_repos(
    since: u64,
    until: Option<u64>,
    shard_count: u64,
    shard_index: u64,
    limit: usize,
    token_manager: &TokenManager,
) -> Result<Vec<String>> {
    if token_manager.token().await.is_none() {
        app::warn(
            "github",
            "no GitHub token found; using anonymous API access (60 req/hour)",
        );
    }
    let shard_count = shard_count.max(1);
    let client = reqwest::Client::new();
    let mut cursor = since;
    let mut collected: Vec<String> = Vec::new();

    app::info(
        "github",
        format!(
            "enumerating repos since={}{} shard={}/{}",
            since,
            until.map(|u| format!("..{}", u)).unwrap_or_default(),
            shard_index,
            shard_count
        ),
    );

    while collected.len() < limit {
        let page = fetch_public_repos_page(&client, cursor, token_manager).await?;
        if page.is_empty() {
            break;
        }

        let mut max_id = cursor;
        for repo in &page {
            max_id = max_id.max(repo.id);
            if let Some(upper) = until {
                if repo.id > upper {
                    app::info(
                        "github",
                        format!("reached upper bound; collected {}", collected.len()),
                    );
                    return Ok(collected);
                }
            }
            if repo.id % shard_count != shard_index {
                continue; // belongs to another shard/worker
            }
            if let Some(url) = repo.best_url() {
                collected.push(url);
                if collected.len() >= limit {
                    break;
                }
            }
        }

        // Advance the cursor; guard against no forward progress.
        if max_id <= cursor {
            break;
        }
        cursor = max_id;
    }

    app::info("github", format!("collected {} repos", collected.len()));
    Ok(collected)
}

/// Parse `owner/name` out of a GitHub repository URL, if possible.
pub(crate) fn repo_full_name(repo_url: &str) -> Option<String> {
    let trimmed = repo_url.trim_end_matches('/').trim_end_matches(".git");
    let after = trimmed.split("github.com/").nth(1)?;
    let mut parts = after.splitn(3, '/');
    let owner = parts.next()?;
    let name = parts.next()?;
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some(format!("{}/{}", owner, name))
}
