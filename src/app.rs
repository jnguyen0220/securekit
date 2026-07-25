//! Shared application-level conventions for logging and status text.
//!
//! This module is the single source of truth for operational messages emitted
//! by the scanner, client, and server.

use std::sync::OnceLock;

/// Log severity used by the lightweight logger.
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

#[derive(Debug)]
struct LogPolicy {
    verbose: bool,
}

static LOG_POLICY: OnceLock<LogPolicy> = OnceLock::new();

fn policy() -> &'static LogPolicy {
    LOG_POLICY.get_or_init(|| LogPolicy {
        verbose: std::env::var("SECUREKIT_VERBOSE")
            .ok()
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false),
    })
}

fn enabled(level: LogLevel) -> bool {
    match level {
        LogLevel::Debug => policy().verbose,
        LogLevel::Info | LogLevel::Warn | LogLevel::Error => true,
    }
}

/// Emit a structured log line.
pub fn log(level: LogLevel, scope: &str, message: impl AsRef<str>) {
    if !enabled(level) {
        return;
    }

    let line = match level {
        LogLevel::Info => format!("[{}] {}", scope, message.as_ref()),
        LogLevel::Warn => format!("[{}][warn] {}", scope, message.as_ref()),
        LogLevel::Error => format!("[{}][error] {}", scope, message.as_ref()),
        LogLevel::Debug => format!("[{}][debug] {}", scope, message.as_ref()),
    };

    match level {
        LogLevel::Warn | LogLevel::Error => eprintln!("{}", line),
        LogLevel::Info | LogLevel::Debug => println!("{}", line),
    }
}

pub fn info(scope: &str, message: impl AsRef<str>) {
    log(LogLevel::Info, scope, message);
}

pub fn warn(scope: &str, message: impl AsRef<str>) {
    log(LogLevel::Warn, scope, message);
}

pub fn error(scope: &str, message: impl AsRef<str>) {
    log(LogLevel::Error, scope, message);
}

pub fn debug(scope: &str, message: impl AsRef<str>) {
    log(LogLevel::Debug, scope, message);
}

/// Canonical status labels used in progress logs.
pub fn scan_status(has_error: bool, has_leak: bool) -> &'static str {
    if has_error {
        "error"
    } else if has_leak {
        "leak"
    } else {
        "clean"
    }
}

/// Render errors as a compact single line suitable for logs.
pub fn concise_error(err: &str) -> String {
    err.replace('\n', " | ")
}
