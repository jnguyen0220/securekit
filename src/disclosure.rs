//! Responsible-disclosure reports: for each repository with findings, write a
//! Markdown notice (secrets always redacted) telling the owner how to reach the
//! maintainers and what to rotate.

use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::app;
use crate::github::{github_headers, repo_full_name};
use crate::report::Report;
use crate::util::redact_secret;

/// Look up a contact channel for responsible disclosure: the repo owner and
/// whether it publishes a SECURITY.md / security policy.
async fn lookup_disclosure_contact(repo_url: &str, token: &Option<String>) -> String {
    let Some(full_name) = repo_full_name(repo_url) else {
        return "Unknown (could not parse owner/repo from URL)".to_string();
    };
    let client = reqwest::Client::new();
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("Repository: https://github.com/{}", full_name));

    let sec_url = format!(
        "https://api.github.com/repos/{}/contents/SECURITY.md",
        full_name
    );
    if let Ok(resp) = github_headers(client.get(&sec_url), token).send().await {
        if resp.status().is_success() {
            lines.push(format!(
                "Security policy: https://github.com/{}/security/policy",
                full_name
            ));
        }
    }

    lines.push(format!(
        "Report privately via a GitHub security advisory: https://github.com/{}/security/advisories/new",
        full_name
    ));
    if let Some((owner, _)) = full_name.split_once('/') {
        lines.push(format!("Owner profile: https://github.com/{}", owner));
    }
    lines.join("\n")
}

/// Write a responsible-disclosure report (Markdown) for a single repo that has
/// findings. Secrets are always redacted in disclosure reports; the owner is
/// given the location + fingerprint so they can locate and revoke the key.
pub(crate) async fn write_disclosure_report(
    dir: &Path,
    report: &Report,
    token: &Option<String>,
) -> Result<()> {
    fs::create_dir_all(dir)?;
    let contact = lookup_disclosure_contact(&report.repo, token).await;
    let slug = repo_full_name(&report.repo)
        .unwrap_or_else(|| report.repo.clone())
        .replace('/', "__");
    let path = dir.join(format!("{}.md", slug));

    let mut out = String::new();
    out.push_str(&format!("# Potential secret leak: {}\n\n", report.repo));
    out.push_str(
        "This is an automated responsible-disclosure notice. A public scan detected \
         patterns that look like live credentials committed to this repository. \
         Please verify and, if valid, **rotate/revoke the affected credentials immediately** \
         and purge them from git history.\n\n",
    );
    out.push_str("## How to reach the maintainers\n\n");
    out.push_str(&contact);
    out.push_str("\n\n## Findings (secrets redacted)\n\n");
    out.push_str("| Type | File | Validity | Redacted value | Fingerprint |\n");
    out.push_str("|------|------|----------|----------------|-------------|\n");
    for f in &report.findings {
        out.push_str(&format!(
            "| {} | {} | {} | `{}` | `{}` |\n",
            f.kind,
            f.file,
            f.validity.as_deref().unwrap_or("unchecked"),
            redact_secret(&f.match_text),
            f.fingerprint
        ));
    }
    out.push_str(
        "\n_Values are redacted intentionally. If you are the maintainer and need the \
         exact location, the file path and fingerprint above are sufficient to identify \
         the credential in your history._\n",
    );

    fs::write(&path, out)?;
    app::info("disclosure", format!("wrote {}", path.display()));
    Ok(())
}
