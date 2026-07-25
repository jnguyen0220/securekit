//! `securekit-client` — scanning bot.
//!
//! A zero-config worker: give it the coordination server's URL and nothing
//! else — no `.env`, no credential, no environment settings. The server
//! enumerates public repositories centrally and hands out their clone URLs via
//! the claim queue; the client clones them anonymously, scans locally, and
//! reports back ONLY redacted findings (raw secret values never leave this
//! machine). Exits when the server's queue is drained.

use anyhow::Result;
use clap::Parser;
use securekit::client;

#[derive(Parser, Debug)]
#[command(
    name = "securekit-client",
    author,
    version,
    about = "Scanning bot: join a coordination server, claim public repos, scan them anonymously, report redacted findings"
)]
struct Args {
    #[arg(
        value_name = "SERVER_URL",
        help = "Coordination server base URL, e.g. http://127.0.0.1:8080"
    )]
    server_url: String,

    #[arg(
        long,
        value_name = "ID",
        help = "Stable worker id (defaults to an auto-generated one)"
    )]
    worker_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    client::run_client(&args.server_url, args.worker_id).await
}
