//! `securekit-server` — coordination server.
//!
//! Hands out repositories to scan and collects the (redacted) findings that
//! `securekit-client` bots report back. All configuration is read from the
//! environment (or a `.env` file); see the README and `.env.example`:
//!
//!   SECUREKIT_BIND, SECUREKIT_LIST_FILE, SECUREKIT_RESULTS_FILE,
//!   SECUREKIT_LEASE_SECS

use anyhow::Result;
use clap::Parser;
use securekit::app;
use securekit::{load_dotenv, load_dotenv_from, server};

#[derive(Parser, Debug)]
#[command(
    name = "securekit-server",
    author,
    version,
    about = "Coordination server: distribute the shared repo list and collect redacted results",
    long_about = "Configuration is read from the environment / .env: SECUREKIT_BIND, \
                  SECUREKIT_LIST_FILE, SECUREKIT_RESULTS_FILE, SECUREKIT_LEASE_SECS."
)]
struct Args {
    #[arg(
        long,
        value_name = "PATH",
        help = "Path to a .env file to load (defaults to ./.env if present)"
    )]
    env_file: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // Load .env so SECUREKIT_* settings and any GitHub token are picked up.
    match args.env_file.as_deref() {
        Some(path) => {
            if !load_dotenv_from(path) {
                app::warn(
                    "securekit-server",
                    format!("env file not found: {}; continuing", path.display()),
                );
            }
        }
        None => load_dotenv(),
    }
    server::run_server().await
}
