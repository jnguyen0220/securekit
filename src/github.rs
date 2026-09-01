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
    current_unix_time, github_user_agent, jittered_delay, parse_rfc3339_to_unix, u64_from_env,
    RetryPolicy,
};

const DEFAULT_GITHUB_5XX_RETRIES: u32 = 3;
const DEFAULT_ENUM_PAGE_DELAY_MS: u64 = 500;
const SECONDARY_RATE_LIMIT_BASE: Duration = Duration::from_secs(60);
const MAX_SECONDARY_RETRIES: u32 = 5;
/// Repos whose last push is older than this many years are skipped during
/// enumeration. Override via `SECUREKIT_MAX_REPO_AGE_YEARS`.
const DEFAULT_MAX_REPO_AGE_YEARS: u64 = 5;
/// Seconds in an average year (365.25 days), used to derive the age cutoff.
const SECS_PER_YEAR: u64 = 31_557_600;
/// GitHub GraphQL endpoint, used to batch-resolve repo push dates.
const GITHUB_GRAPHQL_URL: &str = "https://api.github.com/graphql";

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

/// Configurable pause between successive enumeration page fetches, throttling
/// request rate to stay clear of GitHub's secondary rate limits.
pub(crate) fn enum_page_delay() -> Duration {
    Duration::from_millis(u64_from_env(
        "SECUREKIT_ENUM_PAGE_DELAY_MS",
        DEFAULT_ENUM_PAGE_DELAY_MS,
    ))
}

/// Seconds requested by a `Retry-After` header, if present and numeric.
fn retry_after_secs(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Bounded, minute-plus backoff for secondary rate limits that arrive without a
/// `Retry-After`, following GitHub's guidance to wait at least a minute.
fn secondary_rate_limit_backoff(attempt: u32) -> Duration {
    let factor = 2u32.saturating_pow(attempt.min(4));
    let base = SECONDARY_RATE_LIMIT_BASE.saturating_mul(factor);
    jittered_delay(base, Duration::from_secs(5))
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
    /// GraphQL global node id, used to batch-fetch `pushedAt` in one request.
    node_id: Option<String>,
    clone_url: Option<String>,
    html_url: Option<String>,
    full_name: Option<String>,
    /// Per-repo GitHub API URL (present on list responses); used to fetch
    /// details such as `pushed_at` that the list endpoint omits.
    url: Option<String>,
    /// Last push timestamp (RFC 3339). Absent from the list endpoint, present
    /// on the single-repo detail endpoint.
    pushed_at: Option<String>,
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

/// Outcome of a GitHub GET that has already passed rate-limit/5xx handling.
enum GithubGet {
    /// Server returned 304 Not Modified (only possible when an ETag was sent).
    NotModified,
    /// A successful (2xx) response ready to be decoded.
    Success(reqwest::Response),
}

/// Issue a GET against the GitHub API, transparently handling token refresh,
/// primary/secondary rate limits (with backoff), and 5xx retries. `label` is
/// used only for log context. Returns once a terminal outcome is reached.
async fn github_get_with_backoff(
    client: &reqwest::Client,
    url: &str,
    token_manager: &TokenManager,
    if_none_match: Option<&str>,
    label: &str,
) -> Result<GithubGet> {
    let retry_policy = github_5xx_retry_policy();
    let mut failures = 0u32;
    let mut secondary_failures = 0u32;

    loop {
        let response = send_public_repo_request(client, url, token_manager, if_none_match).await?;

        if response.status().as_u16() == 304 {
            return Ok(GithubGet::NotModified);
        }

        // Rate-limit handling: back off when exhausted, then retry.
        if response.status().as_u16() == 403 || response.status().as_u16() == 429 {
            // Secondary (abuse) limits ask us to wait via Retry-After; honor it
            // even when the primary quota still shows requests remaining.
            if let Some(retry_after) = retry_after_secs(&response) {
                let wait = retry_after.clamp(1, 3600);
                app::warn(
                    "github",
                    format!("secondary rate limit; retry-after {}s", wait),
                );
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }

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

            // Secondary limit without Retry-After: wait a minute-plus (bounded)
            // before retrying rather than failing the whole enumeration.
            if secondary_failures < MAX_SECONDARY_RETRIES {
                let delay = secondary_rate_limit_backoff(secondary_failures);
                app::warn(
                    "github",
                    format!("secondary rate limit on {}; backing off {:?}", label, delay),
                );
                secondary_failures += 1;
                tokio::time::sleep(delay).await;
                continue;
            }
            anyhow::bail!(
                "GitHub API returned {} (secondary rate limit)",
                response.status()
            );
        }

        if response.status().is_server_error() {
            if retry_policy.can_retry(failures) {
                let delay = retry_policy.delay_for_attempt(failures);
                app::warn(
                    "github",
                    format!(
                        "GitHub API {} on {}; retrying in {:?}",
                        response.status(),
                        label,
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

        return Ok(GithubGet::Success(response));
    }
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
    let label = format!("cursor {}", cursor);

    loop {
        let if_none_match = cached.as_ref().map(|entry| entry.etag.as_str());
        match github_get_with_backoff(client, &url, token_manager, if_none_match, &label).await? {
            // Reuse cached content when the page has not changed.
            GithubGet::NotModified => {
                if let Some(entry) = cached.as_ref() {
                    return Ok(entry.page.clone());
                }
                let delay = jittered_delay(Duration::from_secs(1), Duration::from_secs(1));
                tokio::time::sleep(delay).await;
                continue;
            }
            GithubGet::Success(response) => {
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
    }
}

/// Configured maximum repository age (by last push), in years.
fn max_repo_age_years() -> u64 {
    u64_from_env("SECUREKIT_MAX_REPO_AGE_YEARS", DEFAULT_MAX_REPO_AGE_YEARS)
}

/// Earliest acceptable `pushed_at` (unix seconds): repos pushed before this are
/// considered too old to process.
fn recent_push_cutoff() -> u64 {
    current_unix_time().saturating_sub(max_repo_age_years().saturating_mul(SECS_PER_YEAR))
}

/// Resolve a repo's last-push time (unix seconds). The list endpoint omits
/// `pushed_at`, so fall back to a single-repo detail fetch via its API `url`.
async fn fetch_repo_pushed_at(
    client: &reqwest::Client,
    repo: &GitHubRepo,
    token_manager: &TokenManager,
) -> Result<Option<u64>> {
    if let Some(ts) = repo.pushed_at.as_deref().and_then(parse_rfc3339_to_unix) {
        return Ok(Some(ts));
    }
    let Some(url) = repo.url.as_deref() else {
        return Ok(None);
    };
    let label = repo.full_name.as_deref().unwrap_or(url);
    match github_get_with_backoff(client, url, token_manager, None, label).await? {
        GithubGet::NotModified => Ok(None),
        GithubGet::Success(response) => {
            let detail: GitHubRepo = response
                .json()
                .await
                .context("GitHub repo detail decode failed")?;
            Ok(detail.pushed_at.as_deref().and_then(parse_rfc3339_to_unix))
        }
    }
}

/// Whether a repo was pushed within the configured age window. Repos whose push
/// time cannot be determined (missing data or a transient error) are kept, so a
/// hiccup never silently drops potentially-recent repos.
async fn repo_pushed_recently(
    client: &reqwest::Client,
    repo: &GitHubRepo,
    cutoff: u64,
    token_manager: &TokenManager,
) -> bool {
    match fetch_repo_pushed_at(client, repo, token_manager).await {
        Ok(Some(ts)) => ts >= cutoff,
        Ok(None) => true,
        Err(e) => {
            app::warn(
                "github",
                format!(
                    "could not determine push date for {}; keeping it ({})",
                    repo.full_name.as_deref().unwrap_or("<unknown>"),
                    e
                ),
            );
            true
        }
    }
}

#[derive(Deserialize)]
struct GraphQlPushResponse {
    data: Option<GraphQlPushData>,
}

#[derive(Deserialize)]
struct GraphQlPushData {
    nodes: Vec<Option<GraphQlRepoNode>>,
}

#[derive(Deserialize)]
struct GraphQlRepoNode {
    id: String,
    #[serde(rename = "pushedAt")]
    pushed_at: Option<String>,
}

/// Resolve last-push times (unix seconds) for a whole page of repos in a single
/// GraphQL request, keyed by GitHub node id. This replaces up to 100 per-repo
/// REST detail calls with one cheap query. Returns an empty map when no token is
/// available (GraphQL rejects anonymous requests) or the request fails, so
/// callers transparently fall back to the per-repo REST path.
async fn batch_pushed_at(
    client: &reqwest::Client,
    repos: &[GitHubRepo],
    token_manager: &TokenManager,
) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    let ids: Vec<&str> = repos.iter().filter_map(|r| r.node_id.as_deref()).collect();
    if ids.is_empty() {
        return out;
    }
    let token = token_manager.token().await;
    if token.is_none() {
        return out; // GraphQL requires authentication.
    }

    let query = "query($ids:[ID!]!){nodes(ids:$ids){... on Repository{id pushedAt}}}";
    let body = serde_json::json!({ "query": query, "variables": { "ids": ids } });
    let request = github_headers(client.post(GITHUB_GRAPHQL_URL), &token).json(&body);

    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            app::warn("github", format!("GraphQL push-date query failed: {}", e));
            return out;
        }
    };
    if !response.status().is_success() {
        app::warn(
            "github",
            format!("GraphQL push-date query returned {}", response.status()),
        );
        return out;
    }
    let parsed: GraphQlPushResponse = match response.json().await {
        Ok(p) => p,
        Err(e) => {
            app::warn("github", format!("GraphQL push-date decode failed: {}", e));
            return out;
        }
    };
    let Some(data) = parsed.data else {
        return out;
    };
    for node in data.nodes.into_iter().flatten() {
        if let Some(ts) = node.pushed_at.as_deref().and_then(parse_rfc3339_to_unix) {
            out.insert(node.id, ts);
        }
    }
    out
}

/// Whether a repo was pushed within the age window, preferring the batched
/// GraphQL result and falling back to a per-repo REST lookup only when the repo
/// is absent from the batch (no token, GraphQL error, or a null/deleted node).
async fn repo_recent(
    pushed: &HashMap<String, u64>,
    client: &reqwest::Client,
    repo: &GitHubRepo,
    cutoff: u64,
    token_manager: &TokenManager,
) -> bool {
    if let Some(ts) = repo.node_id.as_deref().and_then(|id| pushed.get(id)) {
        return *ts >= cutoff;
    }
    repo_pushed_recently(client, repo, cutoff, token_manager).await
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

    let cutoff = recent_push_cutoff();
    let pushed = batch_pushed_at(client, &page, token_manager).await;
    let mut max_id = cursor;
    let mut repos = Vec::new();
    for repo in &page {
        max_id = max_id.max(repo.id);
        // Skip repos whose last push is older than the age window.
        if !repo_recent(&pushed, client, repo, cutoff, token_manager).await {
            continue;
        }
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
    let cutoff = recent_push_cutoff();

    app::info(
        "github",
        format!(
            "enumerating repos since={}{} shard={}/{} (max age {}y)",
            since,
            until.map(|u| format!("..{}", u)).unwrap_or_default(),
            shard_index,
            shard_count,
            max_repo_age_years(),
        ),
    );

    while collected.len() < limit {
        let page = fetch_public_repos_page(&client, cursor, token_manager).await?;
        if page.is_empty() {
            break;
        }

        let mut max_id = cursor;
        let pushed = batch_pushed_at(&client, &page, token_manager).await;
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
            // Skip repos whose last push is older than the age window.
            if !repo_recent(&pushed, &client, repo, cutoff, token_manager).await {
                continue;
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
        // Throttle request rate to stay under GitHub's rate limits.
        tokio::time::sleep(enum_page_delay()).await;
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
