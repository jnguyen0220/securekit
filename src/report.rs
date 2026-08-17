//! Scan result data model and output rendering (text, JSON, CSV).

use std::io::Write;

use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Csv,
}

/// A single secret match discovered while scanning a repository.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Finding {
    pub(crate) kind: String,
    pub(crate) match_text: String,
    pub(crate) fingerprint: String,
    pub(crate) file: String,
    #[serde(skip)]
    pub(crate) line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) validity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) validity_reason: Option<String>,
}

/// The result of scanning one repository.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Report {
    pub(crate) repo: String,
    pub(crate) finding_count: usize,
    pub(crate) findings: Vec<Finding>,
    pub(crate) has_leak: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) skipped: Option<String>,
    #[serde(skip)]
    pub(crate) commit_sha: Option<String>,
}

#[derive(Debug, Serialize)]
struct SummaryReport {
    scanned_repositories: usize,
    repositories_with_likely_leaked_secrets: usize,
    leak_percentage: f64,
    reports: Vec<Report>,
}

pub(crate) fn write_output(
    writer: &mut dyn Write,
    output: OutputFormat,
    reports: &[Report],
) -> Result<()> {
    let leaked = reports.iter().filter(|report| report.has_leak).count();
    let summary = SummaryReport {
        scanned_repositories: reports.len(),
        repositories_with_likely_leaked_secrets: leaked,
        leak_percentage: if reports.is_empty() {
            0.0
        } else {
            (leaked as f64 / reports.len() as f64) * 100.0
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
                "fingerprint",
                "file",
                "validity",
                "validity_reason",
            ])?;
            for report in reports {
                if report.findings.is_empty() {
                    csv_writer.write_record([
                        report.repo.as_str(),
                        "0",
                        "false",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                    ])?;
                } else {
                    for finding in &report.findings {
                        csv_writer.write_record([
                            report.repo.as_str(),
                            &report.finding_count.to_string(),
                            if report.has_leak { "true" } else { "false" },
                            finding.kind.as_str(),
                            finding.match_text.as_str(),
                            finding.fingerprint.as_str(),
                            finding.file.as_str(),
                            finding.validity.as_deref().unwrap_or(""),
                            finding.validity_reason.as_deref().unwrap_or(""),
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
                    let validity = finding.validity.as_deref().unwrap_or("unchecked");
                    let reason = finding.validity_reason.as_deref().unwrap_or("n/a");
                    writeln!(
                        writer,
                        "- {} in {} ({}; reason: {}): {}",
                        finding.kind, finding.file, validity, reason, finding.match_text
                    )?;
                }
                writeln!(writer)?;
            }
        }
    }

    Ok(())
}
