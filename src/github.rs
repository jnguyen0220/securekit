//! GitHub REST API helpers: shared request headers, repository search, and
//! public-repo enumeration (with sharding) for research / responsible
//! disclosure.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::app;
use crate::github_auth::TokenManager;
use crate::util::{
    current_unix_time, github_user_agent, jittered_delay, u64_from_env, RetryPolicy,
};

const DEFAULT_GITHUB_5XX_RETRIES: u32 = 3;

#[derive(Clone)]
struct CachedPublicRepoPage {
    etag: String,
    page: Vec<GitHubRepo>,
}

static PUBLIC_REPO_PAGE_CACHE: OnceLock<Mutex<HashMap<u64, CachedPublicRepoPage>>> =
    OnceLock::new();

fn page_cache() -> &'static Mutex<HashMap<u64, CachedPublicRepoPage>> {
    PUBLIC_REPO_PAGE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn github_5xx_retries() -> u32 {
    u64_from_env(
        "SECUREKIT_GITHUB_5XX_RETRIES",
        u64::from(DEFAULT_GITHUB_5XX_RETRIES),
    ) as u32
}

fn github_5xx_retry_policy() -> RetryPolicy {
    RetryPolicy::new(
        github_5xx_retries(),
        Duration::from_secs(2),
        4,
        Duration::from_secs(2),
    )
}

fn cached_public_repo_page(cursor: u64) -> Option<CachedPublicRepoPage> {
    let cache = page_cache().lock().unwrap();
    cache.get(&cursor).cloned()
}

fn cache_public_repo_page(cursor: u64, etag: String, page: Vec<GitHubRepo>) {
    let mut cache = page_cache().lock().unwrap();
    cache.insert(cursor, CachedPublicRepoPage { etag, page });
}

#[derive(Clone, Debug, Deserialize)]
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
        .header("User-Agent", github_user_agent())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(token) = token {
        b = b.header("Authorization", format!("Bearer {}", token));
    }
    b
}

fn build_public_repo_request(
    client: &reqwest::Client,
    url: &str,
    token: &Option<String>,
    if_none_match: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut request = github_headers(client.get(url), token);
    if let Some(etag) = if_none_match {
        request = request.header("If-None-Match", etag);
    }
    request
}

async fn send_public_repo_request(
    client: &reqwest::Client,
    url: &str,
    token_manager: &TokenManager,
    if_none_match: Option<&str>,
) -> Result<reqwest::Response> {
    let token = token_manager.token().await;
    let mut response = build_public_repo_request(client, url, &token, if_none_match)
        .send()
        .await
        .context("GitHub API request failed")?;

    // A 401 can mean the token was revoked before expiry; re-mint and retry.
    if response.status().as_u16() == 401 {
        token_manager.force_refresh().await;
        let token = token_manager.token().await;
        response = build_public_repo_request(client, url, &token, if_none_match)
            .send()
            .await
            .context("GitHub API request failed")?;
    }

    Ok(response)
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
    let cached = cached_public_repo_page(cursor);
    let retry_policy = github_5xx_retry_policy();
    let mut failures = 0u32;

    loop {
        let if_none_match = cached.as_ref().map(|entry| entry.etag.as_str());
        let response = send_public_repo_request(client, &url, token_manager, if_none_match).await?;

        // Reuse cached content when the page has not changed.
        if response.status().as_u16() == 304 {
            if let Some(entry) = cached.as_ref() {
                return Ok(entry.page.clone());
            }
            let delay = jittered_delay(Duration::from_secs(1), Duration::from_secs(1));
            tokio::time::sleep(delay).await;
            continue;
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

        if response.status().is_server_error() {
            if retry_policy.can_retry(failures) {
                let delay = retry_policy.delay_for_attempt(failures);
                app::warn(
                    "github",
                    format!(
                        "GitHub API {} on cursor {}; retrying in {:?}",
                        response.status(),
                        cursor,
                        delay
                    ),
                );
                failures += 1;
                tokio::time::sleep(delay).await;
                continue;
            }
            anyhow::bail!("GitHub API returned {}", response.status());
        }

        if !response.status().is_success() {
            anyhow::bail!("GitHub API returned {}", response.status());
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        let page: Vec<GitHubRepo> = response
            .json()
            .await
            .context("GitHub API response decode failed")?;

        if let Some(etag) = etag {
            cache_public_repo_page(cursor, etag, page.clone());
        }

        return Ok(page);
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
