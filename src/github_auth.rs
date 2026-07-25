//! GitHub authentication helpers.
//!
//! Resolves the best available credential for GitHub API calls and
//! authenticated `git clone`, in priority order:
//!   1. GitHub **App** installation token (when the `GITHUB_APP_*` env vars are
//!      configured) — much higher rate limits than a PAT, and rotates
//!      automatically.
//!   2. **Personal access token** (`GITHUB_TOKEN`, then `GH_TOKEN`).
//!   3. **Anonymous** (`None`) — heavily rate-limited (60 req/hr).
//!
//! App auth works by minting a short-lived RS256 JWT signed with the App's
//! private key and exchanging it for an installation access token (valid ~1
//! hour) via `POST /app/installations/{id}/access_tokens`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::app;
use crate::github::github_headers;
use crate::util::current_unix_time;

/// GitHub installation tokens are valid for one hour. We refresh a bit early so
/// a request never goes out with a token that is about to expire.
const INSTALLATION_TOKEN_LIFETIME_SECS: u64 = 3600;
const REFRESH_BUFFER_SECS: u64 = 300;
/// After a failed refresh (with a still-usable token in hand) retry soon.
const RETRY_AFTER_SECS: u64 = 60;

/// JWT claims for a GitHub App: issued-at, expiry, and issuer (the App ID).
#[derive(Debug, Serialize)]
struct AppClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
}

/// Personal access token from the environment (`GITHUB_TOKEN`, then `GH_TOKEN`).
pub fn personal_token() -> Option<String> {
    env_nonempty("GITHUB_TOKEN").or_else(|| env_nonempty("GH_TOKEN"))
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Read the App private key from `GITHUB_APP_PRIVATE_KEY_PATH` (a `.pem` file)
/// or inline `GITHUB_APP_PRIVATE_KEY` (literal `\n` escapes are expanded).
fn app_private_key_pem() -> Option<Vec<u8>> {
    if let Some(path) = env_nonempty("GITHUB_APP_PRIVATE_KEY_PATH") {
        match std::fs::read(&path) {
            Ok(bytes) => return Some(bytes),
            Err(e) => app::warn(
                "github-auth",
                format!("could not read GITHUB_APP_PRIVATE_KEY_PATH {}: {}", path, e),
            ),
        }
    }
    if let Some(inline) = env_nonempty("GITHUB_APP_PRIVATE_KEY") {
        // Allow the PEM to be supplied on a single line using \n escapes.
        return Some(inline.replace("\\n", "\n").into_bytes());
    }
    None
}

/// Mint a short-lived App JWT (RS256) signed with the App's private key.
fn mint_app_jwt(app_id: &str, key_pem: &[u8]) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_secs();
    let claims = AppClaims {
        // Backdate 60s to tolerate minor clock skew, per GitHub's guidance.
        iat: now.saturating_sub(60),
        // GitHub allows up to 10 minutes; use 9 for a safety margin.
        exp: now + 9 * 60,
        iss: app_id.to_string(),
    };
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(key_pem)
        .context("GitHub App private key invalid (expected RSA PEM)")?;
    jsonwebtoken::encode(&header, &claims, &key).context("GitHub App JWT signing failed")
}

/// Exchange an App JWT for an installation access token (valid ~1 hour).
async fn fetch_installation_token(jwt: &str, installation_id: &str) -> Result<String> {
    let url = format!(
        "https://api.github.com/app/installations/{}/access_tokens",
        installation_id
    );
    let resp = github_headers(reqwest::Client::new().post(&url), &Some(jwt.to_string()))
        .send()
        .await
        .context("installation token request failed")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("installation token exchange failed ({}): {}", status, body);
    }
    let parsed: InstallationTokenResponse = resp
        .json()
        .await
        .context("installation token response decode failed")?;
    Ok(parsed.token)
}

/// How the process authenticates to GitHub.
enum Auth {
    /// GitHub App: mint/refresh installation tokens on demand.
    App {
        app_id: String,
        installation_id: String,
        key_pem: Vec<u8>,
    },
    /// A fixed credential: a PAT, or `None` for anonymous access.
    Static(Option<String>),
}

impl Auth {
    /// Resolve the credential from the environment, in priority order: GitHub
    /// App (when `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID` and a private key
    /// are all set) → PAT (`GITHUB_TOKEN`/`GH_TOKEN`) → anonymous.
    fn from_env() -> Self {
        let app_id = env_nonempty("GITHUB_APP_ID");
        let installation_id = env_nonempty("GITHUB_APP_INSTALLATION_ID");
        let key = app_private_key_pem();

        match (app_id, installation_id, key) {
            (Some(app_id), Some(installation_id), Some(key_pem)) => Auth::App {
                app_id,
                installation_id,
                key_pem,
            },
            _ => Auth::Static(personal_token()),
        }
    }
}

/// Cached token plus the time at which it should be refreshed.
struct TokenState {
    token: Option<String>,
    /// Unix time to refresh at. `u64::MAX` means "never" (static credentials).
    refresh_at: u64,
}

/// Resolves and, for GitHub Apps, **auto-refreshes** the GitHub credential.
///
/// Installation tokens expire after ~1 hour, so a long-running crawl or bot
/// would otherwise start failing mid-run. Callers fetch the current token via
/// [`TokenManager::token`] before each unit of work (each claim batch, each
/// enumeration page, each scan chunk); the manager transparently re-mints the
/// token as it nears expiry, and [`TokenManager::force_refresh`] lets a caller
/// re-mint immediately after a `401 Unauthorized`.
pub struct TokenManager {
    auth: Auth,
    state: Mutex<TokenState>,
}

impl TokenManager {
    /// Build a manager from the environment and prime the initial token.
    ///
    /// Priority: GitHub App (when `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`
    /// and a private key are all set) → PAT (`GITHUB_TOKEN`/`GH_TOKEN`) →
    /// anonymous.
    pub async fn from_env() -> Self {
        let auth = Auth::from_env();

        let manager = TokenManager {
            auth,
            state: Mutex::new(TokenState {
                token: None,
                refresh_at: 0,
            }),
        };
        // Prime the token (and surface any App-auth issues) up front.
        manager.token().await;
        manager
    }

    /// Return the current token, refreshing an App installation token if it is
    /// missing or near expiry. `None` means anonymous access.
    pub async fn token(&self) -> Option<String> {
        match &self.auth {
            Auth::Static(t) => t.clone(),
            Auth::App {
                app_id,
                installation_id,
                key_pem,
            } => {
                let mut state = self.state.lock().await;
                let now = current_unix_time();
                if state.token.is_none() || now >= state.refresh_at {
                    match mint_app_jwt(app_id, key_pem) {
                        Ok(jwt) => match fetch_installation_token(&jwt, installation_id).await {
                            Ok(tok) => {
                                let first = state.token.is_none();
                                state.token = Some(tok);
                                state.refresh_at =
                                    now + INSTALLATION_TOKEN_LIFETIME_SECS - REFRESH_BUFFER_SECS;
                                if first {
                                    app::info(
                                        "github-auth",
                                        format!(
                                            "authenticated as app {} installation {}",
                                            app_id, installation_id
                                        ),
                                    );
                                } else {
                                    app::debug("github-auth", "refreshed installation token");
                                }
                            }
                            Err(e) => self.handle_refresh_error(&mut state, now, e),
                        },
                        Err(e) => self.handle_refresh_error(&mut state, now, e),
                    }
                }
                state.token.clone()
            }
        }
    }

    /// Force the next [`token`](Self::token) call to re-mint. Call this after a
    /// `401 Unauthorized` in case the token was revoked before its expiry.
    pub async fn force_refresh(&self) {
        if let Auth::App { .. } = &self.auth {
            let mut state = self.state.lock().await;
            state.refresh_at = 0;
        }
    }

    /// Handle a failed App-token refresh: keep any usable token and retry soon;
    /// otherwise fall back to a PAT (or anonymous) permanently.
    fn handle_refresh_error(&self, state: &mut TokenState, now: u64, err: anyhow::Error) {
        app::warn("github-auth", format!("app token refresh failed: {}", err));
        if state.token.is_some() {
            // Keep serving the (possibly still-valid) token; retry shortly.
            state.refresh_at = now + RETRY_AFTER_SECS;
        } else {
            app::warn("github-auth", "falling back to PAT or anonymous access");
            state.token = personal_token();
            state.refresh_at = u64::MAX;
        }
    }
}
