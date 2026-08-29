//! Client imperative shell: the single choke point for all network I/O.
//!
//! Every request the worker makes to the coordination server flows through
//! [`ServerLink`], and every one of those requests is funneled through the one
//! private [`ServerLink::post_json`] method. Centralizing the side effects here
//! means there is exactly one place to add retries, tracing, timeouts, or
//! auth — and exactly one place errors are shaped, so troubleshooting a failing
//! fleet never means hunting scattered `reqwest` calls. The functional core
//! ([`crate::client_core`]) stays pure; this module is where the impurity lives.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::protocol::{
    Ack, ClaimRequest, ClaimResponse, RegisterRequest, SubmitReport, UnregisterRequest,
    WorkerConfig,
};

/// A cheap-to-clone handle to the coordination server. Cloning shares the
/// underlying `reqwest` connection pool, so heartbeat and report tasks can each
/// hold their own copy.
#[derive(Clone)]
pub(crate) struct ServerLink {
    http: reqwest::Client,
    base: String,
}

impl ServerLink {
    pub(crate) fn new(server_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: server_url.trim_end_matches('/').to_string(),
        }
    }

    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// The one choke point every request passes through. All network errors,
    /// non-success statuses, and decode failures are shaped here with the
    /// operation name (`op`) so a failing call is unambiguous in the logs.
    async fn post_json<Req, Res>(&self, path: &str, body: &Req, op: &str) -> Result<Res>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let resp = self
            .http
            .post(format!("{}/{}", self.base, path))
            .json(body)
            .send()
            .await
            .with_context(|| format!("{op} request failed"))?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("{op} rejected: HTTP {status}");
        }

        resp.json()
            .await
            .with_context(|| format!("{op} response decode failed"))
    }

    /// Register with the server and return the initial worker config.
    pub(crate) async fn register(&self, worker_id: &str) -> Result<WorkerConfig> {
        self.post_json(
            "register",
            &RegisterRequest {
                worker_id: worker_id.to_string(),
            },
            "register",
        )
        .await
    }

    /// Lease up to `count` repositories from the server's claim queue.
    pub(crate) async fn claim(&self, worker_id: &str, count: usize) -> Result<ClaimResponse> {
        self.post_json(
            "claim",
            &ClaimRequest {
                worker_id: worker_id.to_string(),
                count,
            },
            "claim",
        )
        .await
    }

    /// Submit a redacted scan report and return the server's acknowledgement.
    pub(crate) async fn report(&self, report: &SubmitReport) -> Result<Ack> {
        self.post_json("report", report, "report").await
    }

    /// Refresh this worker's liveness so its leases keep flowing.
    pub(crate) async fn heartbeat(&self, worker_id: &str) -> Result<()> {
        let _: WorkerConfig = self
            .post_json(
                "heartbeat",
                &RegisterRequest {
                    worker_id: worker_id.to_string(),
                },
                "heartbeat",
            )
            .await?;
        Ok(())
    }

    /// Best-effort unregister for graceful shutdown.
    pub(crate) async fn unregister(&self, worker_id: &str) -> Result<()> {
        let ack: Ack = self
            .post_json(
                "unregister",
                &UnregisterRequest {
                    worker_id: worker_id.to_string(),
                },
                "unregister",
            )
            .await?;
        if !ack.ok {
            anyhow::bail!("unregister rejected by server");
        }
        Ok(())
    }
}
