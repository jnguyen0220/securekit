use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about = "Scan repositories for likely leaked secrets")]
struct Args {
    #[arg(value_name = "REPO", help = "GitHub repository URL or local path")]
    repos: Vec<String>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Text file with one repository URL/path per line"
    )]
    repo_file: Option<PathBuf>,

    #[arg(long, value_name = "FORMAT", value_enum, default_value_t = OutputFormat::Text, help = "Output format")]
    output: OutputFormat,

    #[arg(
        long,
        value_name = "PATH",
        help = "Write results to this file instead of stdout"
    )]
    output_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "N",
        default_value_t = 4,
        help = "Maximum number of repositories to scan in parallel"
    )]
    max_workers: usize,

    #[arg(
        long,
        value_name = "PATTERN",
        help = "Regex pattern to ignore; can be provided multiple times"
    )]
    ignore_pattern: Vec<String>,

    #[arg(
        long,
        value_name = "FILE",
        help = "Text file with one ignore regex per line"
    )]
    ignore_file: Option<PathBuf>,

    #[arg(
        long,
        help = "Disable the built-in ignore rules for common false positives"
    )]
    no_default_ignores: bool,

    #[arg(
        long,
        value_name = "QUERY",
        help = "Search GitHub for repositories matching query (e.g., 'stars:10..500 language:python')"
    )]
    github_search: Option<String>,

    #[arg(long, value_enum, help = "Use a preset GitHub search template")]
    github_preset: Option<GitHubPreset>,

    #[arg(
        long,
        value_name = "N",
        default_value_t = 10,
        help = "Maximum number of repositories to fetch from GitHub search"
    )]
    github_limit: usize,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum GitHubPreset {
    #[value(name = "suspicious")]
    Suspicious,
    #[value(name = "active-python")]
    ActivePython,
    #[value(name = "active-js")]
    ActiveJs,
    #[value(name = "forked")]
    Forked,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

#[derive(Debug, Deserialize)]
struct GitHubRepo {
    clone_url: Option<String>,
    html_url: Option<String>,
    full_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubSearchResponse {
    items: Vec<GitHubRepo>,
}

#[derive(Clone, Debug, Serialize)]
struct Finding {
    kind: String,
    match_text: String,
    file: String,
}

#[derive(Clone, Debug, Serialize)]
struct Report {
    repo: String,
    finding_count: usize,
    findings: Vec<Finding>,
    has_leak: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped: Option<String>,
    #[serde(skip)]
    commit_sha: Option<String>,
}

#[derive(Debug, Serialize)]
struct SummaryReport {
    scanned_repositories: usize,
    repositories_with_likely_leaked_secrets: usize,
    leak_percentage: f64,
    reports: Vec<Report>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedRepo {
    url: String,
    commit_sha: String,
    timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanCache {
    repos: Vec<CachedRepo>,
}

fn load_repo_list(args: &Args) -> Result<Vec<String>> {
    let mut repos = args.repos.clone();
    if let Some(path) = &args.repo_file {
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

const CACHE_FILE: &str = ".scan-cache.json";

fn load_cache() -> Result<ScanCache> {
    if Path::new(CACHE_FILE).exists() {
        let content = fs::read_to_string(CACHE_FILE)?;
        Ok(serde_json::from_str(&content).unwrap_or_else(|_| ScanCache { repos: Vec::new() }))
    } else {
        Ok(ScanCache { repos: Vec::new() })
    }
}

fn save_cache(cache: &ScanCache) -> Result<()> {
    let content = serde_json::to_string_pretty(cache)?;
    fs::write(CACHE_FILE, content)?;
    Ok(())
}

fn get_repo_commit_sha(repo_dir: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(repo_dir)
        .output()
        .context("failed to get commit SHA")?;

    if !output.status.success() {
        anyhow::bail!("failed to get commit SHA from {}", repo_dir.display());
    }

    Ok(String::from_utf8(output.stdout)
        .context("failed to parse commit SHA")?
        .trim()
        .to_string())
}

fn find_cached_sha(repo_url: &str, cache: &ScanCache) -> Option<String> {
    cache
        .repos
        .iter()
        .find(|cached| cached.url == repo_url)
        .map(|cached| cached.commit_sha.clone())
}

fn get_preset_query(preset: GitHubPreset) -> &'static str {
    match preset {
        GitHubPreset::Suspicious => "stars:10..500 language:python pushed:>2024-06-01",
        GitHubPreset::ActivePython => "stars:100..5000 language:python pushed:>2024-01-01",
        GitHubPreset::ActiveJs => "stars:100..5000 language:javascript pushed:>2024-01-01",
        GitHubPreset::Forked => "fork:true stars:50..1000 pushed:>2024-06-01",
    }
}

async fn search_github(query: &str, limit: usize) -> Result<Vec<String>> {
    let client = reqwest::Client::new();
    // Fetch 5x the limit to account for cached/skipped repos
    let fetch_limit = (limit * 5).min(100); // GitHub API max is 100 per request
    let search_query = format!(
        "{}q={}&per_page={}&sort=stars&order=desc",
        "https://api.github.com/search/repositories?",
        urlencoding::encode(query),
        fetch_limit
    );

    println!("Searching GitHub for repositories: {}", query);

    let response = client
        .get(&search_query)
        .header("User-Agent", "secret-repo-scanner")
        .send()
        .await
        .context("Failed to connect to GitHub API")?;

    if !response.status().is_success() {
        anyhow::bail!("GitHub API error: {}", response.status());
    }

    let search_result: GitHubSearchResponse = response
        .json()
        .await
        .context("Failed to parse GitHub API response")?;

    let repos: Vec<String> = search_result
        .items
        .into_iter()
        .filter_map(|item| {
            item.clone_url.or(item.html_url).or_else(|| {
                item.full_name
                    .map(|name| format!("https://github.com/{}", name))
            })
        })
        .collect();

    println!("Found {} repositories", repos.len());
    Ok(repos)
}

fn load_ignore_patterns(args: &Args) -> Result<Vec<Regex>> {
    let mut patterns = Vec::new();
    if !args.no_default_ignores {
        patterns.push(Regex::new(r"(?i)(example|placeholder|changeme|dummy|fake|testdata|your[_-]?token|your[_-]?api[_-]?key)")?);
    }

    for pattern in &args.ignore_pattern {
        patterns.push(Regex::new(pattern)?);
    }

    if let Some(path) = &args.ignore_file {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read ignore file: {}", path.display()))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                patterns.push(Regex::new(trimmed)?);
            }
        }
    }

    Ok(patterns)
}

fn should_ignore_finding(finding: &Finding, ignore_patterns: &[Regex]) -> bool {
    let haystack = format!("{} {} {}", finding.kind, finding.file, finding.match_text);
    ignore_patterns
        .iter()
        .any(|pattern| pattern.is_match(&haystack))
}

fn scan_repo_dir(path: &Path) -> Result<Vec<Finding>> {
    let patterns = vec![
        ("aws_access_key", Regex::new(r"AKIA[0-9A-Z]{16}")?),
        ("github_token", Regex::new(r"ghp_[A-Za-z0-9]{36}")?),
        ("github_pat", Regex::new(r"github_pat_[A-Za-z0-9_]{20,}")?),
        (
            "slack_webhook",
            Regex::new(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")?,
        ),
    ];

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
    let skip_exts = [
        ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".woff", ".woff2", ".ico",
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
            if skip_exts.contains(&format!(".{}", ext).as_str()) {
                continue;
            }

            if let Ok(content) = fs::read_to_string(entry.path()) {
                for (kind, pattern) in &patterns {
                    for m in pattern.find_iter(&content) {
                        findings.push(Finding {
                            kind: kind.to_string(),
                            match_text: m.as_str().to_string(),
                            file: entry
                                .path()
                                .strip_prefix(path)
                                .unwrap_or(entry.path())
                                .display()
                                .to_string(),
                        });
                    }
                }
            }
        }
    }

    Ok(findings)
}

fn clone_repo(repo_url: &str) -> Result<PathBuf> {
    let repo_name = repo_url
        .trim_end_matches('/')
        .split('/')
        .last()
        .unwrap_or("repo");
    let temp_dir =
        std::env::temp_dir().join(format!("secret-scan-{}-{}", repo_name, current_unix_time()));
    fs::create_dir_all(&temp_dir)?;

    let status = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg(repo_url)
        .arg(&temp_dir)
        .status()
        .with_context(|| format!("failed to run git clone for {}", repo_url))?;

    if !status.success() {
        anyhow::bail!("git clone failed for {}", repo_url);
    }

    Ok(temp_dir)
}

fn scan_repo(repo: &str, ignore_patterns: &[Regex], cache: &ScanCache) -> Result<Report> {
    // For remote repos, check if we should skip based on cache
    if !Path::new(repo).exists() {
        if let Some(cached_sha) = find_cached_sha(repo, cache) {
            // Clone just to get the current SHA
            let temp_dir = clone_repo(repo)?;
            let current_sha = get_repo_commit_sha(&temp_dir)?;
            let _ = fs::remove_dir_all(&temp_dir);

            if current_sha == cached_sha {
                println!("Skipping {} (no changes since last scan)", repo);
                return Ok(Report {
                    repo: repo.to_string(),
                    finding_count: 0,
                    findings: Vec::new(),
                    has_leak: false,
                    skipped: Some("no changes".to_string()),
                    commit_sha: None,
                });
            }
        }
    }

    let (findings, sha) = if Path::new(repo).exists() {
        (scan_repo_dir(Path::new(repo))?, None)
    } else {
        let repo_dir = clone_repo(repo)?;
        let sha = get_repo_commit_sha(&repo_dir).ok();
        let result = scan_repo_dir(&repo_dir);
        let _ = fs::remove_dir_all(&repo_dir);
        (result?, sha)
    };

    let findings: Vec<Finding> = findings
        .into_iter()
        .filter(|finding| !should_ignore_finding(finding, ignore_patterns))
        .collect();

    Ok(Report {
        repo: repo.to_string(),
        finding_count: findings.len(),
        findings: findings.clone(),
        has_leak: !findings.is_empty(),
        skipped: None,
        commit_sha: sha,
    })
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_output(writer: &mut dyn Write, output: OutputFormat, reports: &[Report]) -> Result<()> {
    let summary = SummaryReport {
        scanned_repositories: reports.len(),
        repositories_with_likely_leaked_secrets: reports
            .iter()
            .filter(|report| report.has_leak)
            .count(),
        leak_percentage: if reports.is_empty() {
            0.0
        } else {
            (reports.iter().filter(|report| report.has_leak).count() as f64 / reports.len() as f64)
                * 100.0
        },
        reports: reports.to_vec(),
    };

    match output {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut *writer, &summary)?;
            writeln!(writer)?;
        }
        OutputFormat::Csv => {
            let mut csv_writer = csv::Writer::from_writer(writer);
            csv_writer.write_record([
                "repo",
                "finding_count",
                "has_leak",
                "kind",
                "match_text",
                "file",
            ])?;
            for report in reports {
                if report.findings.is_empty() {
                    csv_writer.write_record([report.repo.as_str(), "0", "false", "", "", ""])?;
                } else {
                    for finding in &report.findings {
                        csv_writer.write_record([
                            report.repo.as_str(),
                            &report.finding_count.to_string(),
                            if report.has_leak { "true" } else { "false" },
                            finding.kind.as_str(),
                            finding.match_text.as_str(),
                            finding.file.as_str(),
                        ])?;
                    }
                }
            }
            csv_writer.flush()?;
        }
        OutputFormat::Text => {
            writeln!(
                writer,
                "Scanned repositories: {}",
                summary.scanned_repositories
            )?;
            writeln!(
                writer,
                "Repositories with likely leaked secrets: {}",
                summary.repositories_with_likely_leaked_secrets
            )?;
            writeln!(writer, "Leak percentage: {:.2}%", summary.leak_percentage)?;
            for report in reports {
                writeln!(writer, "Repository: {}", report.repo)?;
                writeln!(writer, "Findings: {}", report.finding_count)?;
                for finding in &report.findings {
                    writeln!(
                        writer,
                        "- {} in {}: {}",
                        finding.kind, finding.file, finding.match_text
                    )?;
                }
                writeln!(writer)?;
            }
        }
    }

    Ok(())
}

async fn main_inner() -> Result<()> {
    let args = Args::parse();
    let mut repos = load_repo_list(&args)?;
    let mut did_github_search = false;

    // Handle GitHub search
    if let Some(preset) = args.github_preset {
        let query = get_preset_query(preset);
        let github_repos = search_github(query, args.github_limit).await?;
        repos.extend(github_repos);
        did_github_search = true;
    } else if let Some(query) = &args.github_search {
        let github_repos = search_github(query, args.github_limit).await?;
        repos.extend(github_repos);
        did_github_search = true;
    }

    if repos.is_empty() {
        // Default to scanning a public repo if none provided
        repos.push("https://github.com/torvalds/linux".to_string());
        println!(
            "No repository specified. Scanning default repository: {}",
            repos[0]
        );
    }

    let ignore_patterns = load_ignore_patterns(&args)?;
    let mut cache = load_cache()?;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.max_workers.max(1))
        .build()?;

    let reports: Result<Vec<Report>> = pool.install(|| {
        repos
            .par_iter()
            .map(|repo| scan_repo(repo, &ignore_patterns, &cache))
            .collect()
    });
    let mut reports = reports?;

    // Update cache with new commit SHAs
    for report in &reports {
        if let Some(sha) = &report.commit_sha {
            // Remove old entry if exists
            cache.repos.retain(|r| r.url != report.repo);
            // Add new entry
            cache.repos.push(CachedRepo {
                url: report.repo.clone(),
                commit_sha: sha.clone(),
                timestamp: current_unix_time(),
            });
        }
    }

    // Save updated cache
    save_cache(&cache)?;

    // Filter out skipped repos from output
    reports.retain(|r| r.skipped.is_none());

    // Only keep up to the requested limit of non-skipped repos if we did a GitHub search
    if did_github_search {
        reports.truncate(args.github_limit);
    }

    let mut output_writer: Box<dyn Write> = if let Some(path) = &args.output_file {
        Box::new(
            File::create(path)
                .with_context(|| format!("failed to create output file: {}", path.display()))?,
        )
    } else {
        Box::new(io::stdout())
    };

    write_output(&mut *output_writer, args.output, &reports)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    main_inner().await
}
