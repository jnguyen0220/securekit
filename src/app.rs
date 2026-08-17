//! Shared application-level conventions for logging and status text.
//!
//! This module is the single source of truth for operational messages emitted
//! by the scanner, client, and server.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use crate::util::{bool_from_env, current_unix_time};

/// Log severity used by the lightweight logger.
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

/// How chatty the logger is. `Quiet` collapses the per-repo firehose into a
/// periodic heartbeat; `Verbose` also emits debug lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

#[derive(Debug)]
struct LogPolicy {
    verbosity: Verbosity,
}

static LOG_POLICY: OnceLock<LogPolicy> = OnceLock::new();

/// Throttle state for quiet-mode progress heartbeats.
static PROGRESS_COUNT: AtomicU64 = AtomicU64::new(0);
static PROGRESS_LAST_EMIT: AtomicU64 = AtomicU64::new(0);

/// Seconds between quiet-mode heartbeat lines.
const QUIET_PROGRESS_INTERVAL_SECS: u64 = 5;

fn policy() -> &'static LogPolicy {
    LOG_POLICY.get_or_init(|| {
        // Verbose wins over quiet if someone sets both.
        let verbosity = if bool_from_env("SECUREKIT_VERBOSE", false) {
            Verbosity::Verbose
        } else if bool_from_env("SECUREKIT_QUIET", false) {
            Verbosity::Quiet
        } else {
            Verbosity::Normal
        };
        LogPolicy { verbosity }
    })
}

fn enabled(level: LogLevel) -> bool {
    match level {
        LogLevel::Debug => policy().verbosity == Verbosity::Verbose,
        LogLevel::Info => policy().verbosity != Verbosity::Quiet,
        LogLevel::Warn | LogLevel::Error => true,
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

/// Emit a high-frequency per-item progress line.
///
/// In normal/verbose modes this is just an `info` line. In quiet mode the flood
/// is suppressed: `important` events (leaks, errors) still print in full, while
/// routine lines are collapsed into a heartbeat emitted at most once every
/// [`QUIET_PROGRESS_INTERVAL_SECS`] so the operator can still see work happening.
pub fn progress(scope: &str, important: bool, message: impl AsRef<str>) {
    if policy().verbosity != Verbosity::Quiet {
        info(scope, message);
        return;
    }

    let processed = PROGRESS_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if important {
        println!("[{}] {}", scope, message.as_ref());
        return;
    }

    let now = current_unix_time();
    let last = PROGRESS_LAST_EMIT.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= QUIET_PROGRESS_INTERVAL_SECS
        && PROGRESS_LAST_EMIT
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        println!("[{}] working | processed={}", scope, processed);
    }
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
