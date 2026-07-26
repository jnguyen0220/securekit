//! Optional live-secret validation checks.
//!
//! Validation is best-effort and intentionally conservative:
//! - `valid` means the provider API accepted the credential or it passed a
//!   strict local check.
//! - `invalid` means the token/string is malformed, expired, or explicitly
//!   rejected by a provider API.
//! - `unknown` means we could not prove either way (network/provider ambiguity
//!   or validation requires extra context not present in the leaked value).

use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn validate_secret(
    kind: &str,
    secret: &str,
    azure_active_probe: bool,
) -> Option<String> {
    let status = match kind {
        "aws_access_key" => validate_aws_access_key(secret),
        "github_token" | "github_oauth" | "github_pat" => validate_github_token(secret),
        "slack_token" => validate_slack_token(secret),
        "slack_webhook" => validate_slack_webhook(secret),
        "google_api_key" => validate_google_api_key(secret),
        "azure_storage_connection_string" => {
            validate_azure_storage_connection_string(secret, azure_active_probe)
        }
        "azure_sas_token" => validate_azure_sas_token(secret, azure_active_probe),
        "stripe_secret_key" | "stripe_restricted_key" => validate_stripe_key(secret),
        "openai_api_key" => validate_openai_key(secret),
        "gitlab_pat" => validate_gitlab_pat(secret),
        "npm_token" => validate_npm_token(secret),
        "sendgrid_api_key" => validate_sendgrid_key(secret),
        "twilio_api_key" => validate_twilio_key(secret),
        "private_key" => validate_private_key(secret),
        "jwt" => validate_jwt(secret),
        _ => SecretValidity::Unknown,
    };

    Some(match status {
        SecretValidity::Valid => "valid".to_string(),
        SecretValidity::Invalid => "invalid".to_string(),
        SecretValidity::Unknown => "unknown".to_string(),
    })
}

enum SecretValidity {
    Valid,
    Invalid,
    Unknown,
}

fn http_client() -> Option<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .ok()
}

fn validate_aws_access_key(access_key_id: &str) -> SecretValidity {
    // STS GetAccessKeyInfo checks whether the key id maps to an AWS account.
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let url = format!(
        "https://sts.amazonaws.com/?Action=GetAccessKeyInfo&AccessKeyId={}&Version=2011-06-15",
        access_key_id
    );

    let resp = match client.get(url).send() {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    let body = match resp.text() {
        Ok(t) => t,
        Err(_) => return SecretValidity::Unknown,
    };

    if body.contains("<GetAccessKeyInfoResult>") && body.contains("<Account>") {
        return SecretValidity::Valid;
    }
    if body.contains("InvalidClientTokenId")
        || body.contains("ValidationError")
        || body.contains("The security token included in the request is invalid")
    {
        return SecretValidity::Invalid;
    }

    SecretValidity::Unknown
}

fn validate_github_token(token: &str) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let resp = match client
        .get("https://api.github.com/user")
        .header("User-Agent", "securekit")
        .bearer_auth(token)
        .send()
    {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    match resp.status() {
        StatusCode::OK => SecretValidity::Valid,
        StatusCode::UNAUTHORIZED => SecretValidity::Invalid,
        _ => SecretValidity::Unknown,
    }
}

fn validate_slack_token(token: &str) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let resp = match client
        .post("https://slack.com/api/auth.test")
        .bearer_auth(token)
        .send()
    {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    let body: Value = match resp.json() {
        Ok(v) => v,
        Err(_) => return SecretValidity::Unknown,
    };

    if body.get("ok").and_then(Value::as_bool) == Some(true) {
        SecretValidity::Valid
    } else if body.get("error").and_then(Value::as_str) == Some("invalid_auth")
        || body.get("error").and_then(Value::as_str) == Some("token_revoked")
    {
        SecretValidity::Invalid
    } else {
        SecretValidity::Unknown
    }
}

fn validate_slack_webhook(secret: &str) -> SecretValidity {
    if secret.starts_with("https://hooks.slack.com/services/") {
        SecretValidity::Unknown
    } else {
        SecretValidity::Invalid
    }
}

fn validate_google_api_key(secret: &str) -> SecretValidity {
    if secret.len() == 39 && secret.starts_with("AIza") {
        // Live verification can burn quota and requires API-specific calls.
        SecretValidity::Unknown
    } else {
        SecretValidity::Invalid
    }
}

struct AzureConnectionString {
    account_name: String,
    account_key_b64: String,
    endpoint_suffix: String,
}

fn parse_azure_connection_string(secret: &str) -> Option<AzureConnectionString> {
    let mut account_name: Option<&str> = None;
    let mut account_key: Option<&str> = None;
    let mut endpoint_suffix: Option<&str> = None;

    for part in secret.split(';') {
        let mut kv = part.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let value = kv.next().unwrap_or("").trim();
        match key {
            "AccountName" => account_name = Some(value),
            "AccountKey" => account_key = Some(value),
            "EndpointSuffix" => endpoint_suffix = Some(value),
            _ => {}
        }
    }

    let name = account_name?;
    let key = account_key?;
    let suffix = endpoint_suffix.unwrap_or("core.windows.net");

    let valid_name = name.len() >= 3
        && name.len() <= 24
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if !valid_name {
        return None;
    }

    let likely_b64 = key.len() >= 40
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !likely_b64 {
        return None;
    }

    Some(AzureConnectionString {
        account_name: name.to_string(),
        account_key_b64: key.to_string(),
        endpoint_suffix: suffix.to_string(),
    })
}

fn validate_azure_storage_connection_string(
    secret: &str,
    azure_active_probe: bool,
) -> SecretValidity {
    let Some(conn) = parse_azure_connection_string(secret) else {
        return SecretValidity::Invalid;
    };

    if azure_active_probe {
        return probe_azure_storage_shared_key(&conn);
    }

    SecretValidity::Unknown
}

fn validate_azure_sas_token(secret: &str, azure_active_probe: bool) -> SecretValidity {
    let has_sv = secret.contains("sv=");
    let has_sig = secret.contains("sig=");
    let has_se = secret.contains("se=");

    if !(has_sv && has_sig && has_se) {
        return SecretValidity::Invalid;
    }

    if let Some(expiry) = query_param(secret, "se") {
        if is_iso8601_expired(&expiry) == Some(true) {
            return SecretValidity::Invalid;
        }
    }

    if azure_active_probe {
        return probe_azure_sas(secret);
    }

    SecretValidity::Unknown
}

fn probe_azure_storage_shared_key(conn: &AzureConnectionString) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let key_bytes = match BASE64_STANDARD.decode(conn.account_key_b64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => return SecretValidity::Invalid,
    };

    let host = format!("{}.blob.{}", conn.account_name, conn.endpoint_suffix);
    let path_and_query = "/?comp=list&maxresults=1";
    let url = format!("https://{}{}", host, path_and_query);
    let x_ms_date = httpdate::fmt_http_date(SystemTime::now());
    let x_ms_version = "2021-12-02";

    let canonical_headers = format!("x-ms-date:{}\nx-ms-version:{}\n", x_ms_date, x_ms_version);
    let canonical_resource = format!("/{}/\ncomp:list\nmaxresults:1", conn.account_name);
    let string_to_sign = format!(
        "GET\n\n\n\n\n\n\n\n\n\n\n\n{}{}",
        canonical_headers, canonical_resource
    );

    let mut mac = match HmacSha256::new_from_slice(&key_bytes) {
        Ok(m) => m,
        Err(_) => return SecretValidity::Invalid,
    };
    mac.update(string_to_sign.as_bytes());
    let signature = BASE64_STANDARD.encode(mac.finalize().into_bytes());
    let auth = format!("SharedKey {}:{}", conn.account_name, signature);

    let resp = match client
        .get(&url)
        .header("x-ms-date", &x_ms_date)
        .header("x-ms-version", x_ms_version)
        .header("Authorization", auth)
        .send()
    {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    match resp.status() {
        StatusCode::OK => SecretValidity::Valid,
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => SecretValidity::Invalid,
        StatusCode::NOT_FOUND => SecretValidity::Invalid,
        _ => SecretValidity::Unknown,
    }
}

fn probe_azure_sas(secret: &str) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let url = if secret.starts_with("https://") || secret.starts_with("http://") {
        secret.to_string()
    } else {
        // Without a concrete resource URL, SAS signature cannot be verified online.
        return SecretValidity::Unknown;
    };

    let resp = match client.get(url).send() {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    if resp.status().is_success() {
        return SecretValidity::Valid;
    }

    let body = resp.text().unwrap_or_default();
    if body.contains("AuthenticationFailed")
        || body.contains("AuthorizationFailure")
        || body.contains("ExpiredAuthenticationToken")
        || body.contains("Signature fields not well formed")
    {
        return SecretValidity::Invalid;
    }

    SecretValidity::Unknown
}

fn validate_stripe_key(secret: &str) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let resp = match client
        .get("https://api.stripe.com/v1/balance")
        .basic_auth(secret, Some(""))
        .send()
    {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    match resp.status() {
        StatusCode::OK => SecretValidity::Valid,
        StatusCode::UNAUTHORIZED => SecretValidity::Invalid,
        _ => SecretValidity::Unknown,
    }
}

fn validate_openai_key(secret: &str) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let resp = match client
        .get("https://api.openai.com/v1/models")
        .bearer_auth(secret)
        .send()
    {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    match resp.status() {
        StatusCode::OK => SecretValidity::Valid,
        StatusCode::UNAUTHORIZED => SecretValidity::Invalid,
        _ => SecretValidity::Unknown,
    }
}

fn validate_gitlab_pat(secret: &str) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let resp = match client
        .get("https://gitlab.com/api/v4/user")
        .header("PRIVATE-TOKEN", secret)
        .send()
    {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    match resp.status() {
        StatusCode::OK => SecretValidity::Valid,
        StatusCode::UNAUTHORIZED => SecretValidity::Invalid,
        StatusCode::FORBIDDEN => SecretValidity::Invalid,
        _ => SecretValidity::Unknown,
    }
}

fn validate_npm_token(secret: &str) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let resp = match client
        .get("https://registry.npmjs.org/-/whoami")
        .bearer_auth(secret)
        .send()
    {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    match resp.status() {
        StatusCode::OK => SecretValidity::Valid,
        StatusCode::UNAUTHORIZED => SecretValidity::Invalid,
        _ => SecretValidity::Unknown,
    }
}

fn validate_sendgrid_key(secret: &str) -> SecretValidity {
    let Some(client) = http_client() else {
        return SecretValidity::Unknown;
    };

    let resp = match client
        .get("https://api.sendgrid.com/v3/user/profile")
        .bearer_auth(secret)
        .send()
    {
        Ok(r) => r,
        Err(_) => return SecretValidity::Unknown,
    };

    match resp.status() {
        StatusCode::OK => SecretValidity::Valid,
        StatusCode::UNAUTHORIZED => SecretValidity::Invalid,
        StatusCode::FORBIDDEN => SecretValidity::Invalid,
        _ => SecretValidity::Unknown,
    }
}

fn validate_twilio_key(secret: &str) -> SecretValidity {
    if secret.len() == 34
        && secret.starts_with("SK")
        && secret.chars().skip(2).all(|c| c.is_ascii_hexdigit())
    {
        // Twilio API key validity requires Account SID + API secret pair.
        SecretValidity::Unknown
    } else {
        SecretValidity::Invalid
    }
}

fn validate_private_key(secret: &str) -> SecretValidity {
    if secret.starts_with("-----BEGIN ") && secret.ends_with("PRIVATE KEY-----") {
        SecretValidity::Unknown
    } else {
        SecretValidity::Invalid
    }
}

fn validate_jwt(secret: &str) -> SecretValidity {
    let mut parts = secret.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return SecretValidity::Invalid;
    };

    if h.is_empty() || p.is_empty() || s.is_empty() {
        return SecretValidity::Invalid;
    }

    let Some(header_raw) = b64url_decode(h) else {
        return SecretValidity::Invalid;
    };
    let Some(payload_raw) = b64url_decode(p) else {
        return SecretValidity::Invalid;
    };

    let header_json: Value = match serde_json::from_slice(&header_raw) {
        Ok(v) => v,
        Err(_) => return SecretValidity::Invalid,
    };
    let payload_json: Value = match serde_json::from_slice(&payload_raw) {
        Ok(v) => v,
        Err(_) => return SecretValidity::Invalid,
    };

    if header_json.get("alg").and_then(Value::as_str).is_none() {
        return SecretValidity::Invalid;
    }

    if let Some(exp) = payload_json.get("exp").and_then(Value::as_i64) {
        let now = current_unix_time_i64();
        if exp <= now {
            return SecretValidity::Invalid;
        }
    }

    SecretValidity::Unknown
}

fn query_param(query_like: &str, key: &str) -> Option<String> {
    for pair in query_like.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?.trim();
        let v = it.next().unwrap_or("").trim();
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1] as char;
            let h2 = bytes[i + 2] as char;
            if let (Some(a), Some(b)) = (h1.to_digit(16), h2.to_digit(16)) {
                out.push(((a << 4) as u8) | (b as u8));
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn is_iso8601_expired(ts: &str) -> Option<bool> {
    // Supports common Azure format: YYYY-MM-DDTHH:MM:SSZ
    if ts.len() < 20 || !ts.ends_with('Z') {
        return None;
    }
    let year = ts.get(0..4)?.parse::<i32>().ok()?;
    let month = ts.get(5..7)?.parse::<u32>().ok()?;
    let day = ts.get(8..10)?.parse::<u32>().ok()?;
    let hour = ts.get(11..13)?.parse::<u32>().ok()?;
    let minute = ts.get(14..16)?.parse::<u32>().ok()?;
    let second = ts.get(17..19)?.parse::<u32>().ok()?;

    let expiry = ymd_hms_to_unix(year, month, day, hour, minute, second)?;
    Some(expiry <= current_unix_time_i64())
}

fn current_unix_time_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn ymd_hms_to_unix(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }

    let y = year as i64;
    let m = month as i64;
    let d = day as i64;

    // Civil date to days since Unix epoch (1970-01-01).
    let y_adj = y - if m <= 2 { 1 } else { 0 };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    Some(days * 86_400 + (hour as i64) * 3600 + (min as i64) * 60 + sec as i64)
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut s = input.replace('-', "+").replace('_', "/");
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }

    // Small local base64 decoder (standard alphabet), avoiding extra deps.
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    for chunk in bytes.chunks_exact(4) {
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let c = if chunk[2] == b'=' {
            64
        } else {
            b64_val(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            64
        } else {
            b64_val(chunk[3])?
        };

        out.push((a << 2) | (b >> 4));
        if c != 64 {
            out.push((b << 4) | (c >> 2));
        }
        if d != 64 {
            out.push((c << 6) | d);
        }
    }

    Some(out)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_azure_sas_missing_required_fields() {
        assert!(matches!(
            validate_azure_sas_token("sv=2020-01-01", false),
            SecretValidity::Invalid
        ));
    }

    #[test]
    fn invalid_jwt_when_malformed() {
        assert!(matches!(validate_jwt("not.a.jwt"), SecretValidity::Invalid));
    }

    #[test]
    fn invalid_azure_conn_string_when_missing_key() {
        let s = "DefaultEndpointsProtocol=https;AccountName=abc;EndpointSuffix=core.windows.net";
        assert!(matches!(
            validate_azure_storage_connection_string(s, false),
            SecretValidity::Invalid
        ));
    }

    #[test]
    fn parse_azure_conn_string_success() {
        let s = "DefaultEndpointsProtocol=https;AccountName=abc123;AccountKey=QWxhZGRpbjpvcGVuIHNlc2FtZUV4YW1wbGVLZXlMb25nZXI9PQ==;EndpointSuffix=core.windows.net";
        let parsed = parse_azure_connection_string(s);
        assert!(parsed.is_some());
    }
}
