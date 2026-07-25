//! securekit — shared library crate.
//!
//! Contains the secret-scanning core plus the coordination server and client
//! logic. The three executables are thin front-ends over this library:
//!   * `securekit`         — standalone scan ([`run_scan`])
//!   * `securekit-server`  — coordination server ([`server::run_server`])
//!   * `securekit-client`  — scanning bot ([`client::run_client`])

// Distributed server/client mode.
pub mod client;
pub mod github_auth;
pub mod protocol;
pub mod registry;
pub mod server;
mod server_config;
mod server_orchestration;
mod server_usecase;
pub mod store;

// Standalone scanning core.
pub mod app;
mod cache;
mod config;
mod disclosure;
mod github;
mod lifecycle;
mod report;
mod runner;
mod scan;
mod util;
mod validation;

pub use config::ScanConfig;
pub use report::OutputFormat;
pub use runner::run_scan;
pub use scan::compile_ignore_patterns;
pub use util::load_dotenv;
pub use util::load_dotenv_from;

// Re-exported for the in-crate distributed client (`client.rs`).
pub(crate) use cache::ScanCache;
pub(crate) use scan::scan_repo;
