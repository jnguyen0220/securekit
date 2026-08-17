use std::sync::Arc;

use anyhow::Result;

use crate::app;
use crate::github_auth::TokenManager;
use crate::protocol::{Ack, ClaimRequest, ClaimResponse, SubmitReport, WorkerConfig};
use crate::registry::WorkerRegistry;
use crate::store::TargetStore;
use crate::util::github_authenticated_url;

const MAX_CLAIM: usize = 100;

type SharedStore = Arc<dyn TargetStore>;

#[derive(Clone)]
pub(crate) struct WorkerSettings {
    pub(crate) ignore_patterns: Arc<Vec<String>>,
    pub(crate) scan_workers: usize,
    pub(crate) claim_batch: usize,
    pub(crate) validate_secrets: bool,
    pub(crate) azure_active_probe: bool,
}

#[derive(Clone)]
pub(crate) struct WorkerLifecycleService {
    registry: Arc<WorkerRegistry>,
    settings: WorkerSettings,
}

impl WorkerLifecycleService {
    pub(crate) fn new(registry: Arc<WorkerRegistry>, settings: WorkerSettings) -> Self {
        Self { registry, settings }
    }

    pub(crate) fn register(&self, worker_id: &str) -> WorkerConfig {
        self.worker_config(worker_id)
    }

    pub(crate) fn heartbeat(&self, worker_id: &str) -> WorkerConfig {
        self.worker_config(worker_id)
    }

    pub(crate) fn unregister(&self, worker_id: &str) -> Ack {
        self.registry.unregister(worker_id);
        Ack { ok: true }
    }

    fn worker_config(&self, worker_id: &str) -> WorkerConfig {
        WorkerConfig {
            ttl_secs: self.registry.touch(worker_id),
            ignore_patterns: (*self.settings.ignore_patterns).clone(),
            scan_workers: self.settings.scan_workers,
            claim_batch: self.settings.claim_batch,
            validate_secrets: self.settings.validate_secrets,
            azure_active_probe: self.settings.azure_active_probe,
        }
    }
}

#[derive(Clone)]
pub(crate) struct ClaimService {
    store: SharedStore,
    registry: Arc<WorkerRegistry>,
    token_manager: Arc<TokenManager>,
    lease_secs: u64,
}

impl ClaimService {
    pub(crate) fn new(
        store: SharedStore,
        registry: Arc<WorkerRegistry>,
        token_manager: Arc<TokenManager>,
        lease_secs: u64,
    ) -> Self {
        Self {
            store,
            registry,
            token_manager,
            lease_secs,
        }
    }

    pub(crate) async fn claim(&self, req: &ClaimRequest) -> ClaimResponse {
        let stats = self.store.stats();
        let active_workers = self.registry.active_count();
        let count = fair_claim_count(req.count, stats.pending, active_workers);
        let mut items = self.store.claim(count, self.lease_secs);
        let token = self.token_manager.token().await;
        for item in &mut items {
            item.clone_url = github_authenticated_url(&item.repo, token.as_deref());
        }

        let enumeration_done = items.is_empty() && self.store.enumeration_drained();
        ClaimResponse {
            items,
            enumeration_done,
        }
    }
}

pub(crate) trait RepoCacheWriter: Send + Sync {
    fn upsert_sha(&self, repo: &str, sha: &str) -> Result<()>;
}

#[derive(Clone)]
pub(crate) struct ReportService<C>
where
    C: RepoCacheWriter,
{
    store: SharedStore,
    cache: Arc<C>,
}

impl<C> ReportService<C>
where
    C: RepoCacheWriter,
{
    pub(crate) fn new(store: SharedStore, cache: Arc<C>) -> Self {
        Self { store, cache }
    }

    pub(crate) fn submit(&self, report: SubmitReport) -> Ack {
        let worker_id = report.worker_id.clone();
        let repo = report.repo.clone();
        let sha = report.commit_sha.clone();
        let finding_count = report.finding_count;
        let has_leak = report.has_leak;
        let reason = report
            .error
            .as_deref()
            .map(app::concise_error)
            .map(|e| format!(" | reason: {}", e))
            .unwrap_or_default();
        let status = if report.error.is_some() {
            "skip"
        } else {
            "scan"
        };

        match self.store.complete(report) {
            Ok(()) => {
                let important = has_leak || status == "skip";
                app::progress(
                    "server",
                    important,
                    format!(
                        "{} | repo={} | status={} | findings={}{}",
                        worker_id, repo, status, finding_count, reason
                    ),
                );
                if let Some(commit_sha) = sha {
                    if let Err(e) = self.cache.upsert_sha(&repo, &commit_sha) {
                        app::warn(
                            "server",
                            format!("failed to update cache for {}: {}", repo, e),
                        );
                    }
                }
                Ack { ok: true }
            }
            Err(e) => {
                app::error("server", format!("failed to record report: {}", e));
                Ack { ok: false }
            }
        }
    }
}

/// Compute a fair per-request claim size so one worker cannot monopolize the
/// queue when multiple workers are active.
pub(crate) fn fair_claim_count(requested: usize, pending: usize, active_workers: usize) -> usize {
    let requested = requested.clamp(1, MAX_CLAIM);
    let workers = active_workers.max(1);
    let fair_share = pending.max(1).div_ceil(workers).max(1);
    requested.min(fair_share)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::protocol::StoreStats;
    use crate::protocol::WireFinding;
    use crate::protocol::WorkItem;

    struct MockStore {
        pending: Mutex<VecDeque<WorkItem>>,
        drained: bool,
        complete_ok: bool,
        completed: Mutex<usize>,
    }

    impl MockStore {
        fn with_items(items: Vec<WorkItem>, drained: bool) -> Self {
            Self {
                pending: Mutex::new(items.into()),
                drained,
                complete_ok: true,
                completed: Mutex::new(0),
            }
        }

        fn with_complete_result(ok: bool) -> Self {
            Self {
                pending: Mutex::new(VecDeque::new()),
                drained: true,
                complete_ok: ok,
                completed: Mutex::new(0),
            }
        }
    }

    impl TargetStore for MockStore {
        fn claim(&self, count: usize, _lease_secs: u64) -> Vec<WorkItem> {
            let mut q = self.pending.lock().unwrap();
            let mut out = Vec::new();
            for _ in 0..count {
                let Some(item) = q.pop_front() else {
                    break;
                };
                out.push(item);
            }
            out
        }

        fn enqueue(&self, repos: Vec<String>) {
            let mut q = self.pending.lock().unwrap();
            for (next_id, repo) in (10_000u64..).zip(repos) {
                q.push_back(WorkItem {
                    id: next_id,
                    repo,
                    clone_url: None,
                });
            }
        }

        fn set_enumeration_done(&self) {}

        fn enumeration_drained(&self) -> bool {
            self.drained
        }

        fn complete(&self, _report: SubmitReport) -> Result<()> {
            if self.complete_ok {
                *self.completed.lock().unwrap() += 1;
                Ok(())
            } else {
                anyhow::bail!("complete failed")
            }
        }

        fn stats(&self) -> StoreStats {
            StoreStats {
                pending: self.pending.lock().unwrap().len(),
                inflight: 0,
                done: *self.completed.lock().unwrap(),
                repos_with_leaks: 0,
                active_workers: 0,
                perf: None,
            }
        }
    }

    #[derive(Default)]
    struct MockCache {
        writes: Mutex<Vec<(String, String)>>,
    }

    impl RepoCacheWriter for MockCache {
        fn upsert_sha(&self, repo: &str, sha: &str) -> Result<()> {
            self.writes
                .lock()
                .unwrap()
                .push((repo.to_string(), sha.to_string()));
            Ok(())
        }
    }

    #[test]
    fn claim_service_returns_items_and_done_false_when_items_present() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store: Arc<dyn TargetStore> = Arc::new(MockStore::with_items(
                vec![WorkItem {
                    id: 1,
                    repo: "https://github.com/acme/repo".to_string(),
                    clone_url: None,
                }],
                true,
            ));
            let registry = Arc::new(WorkerRegistry::new(60));
            registry.touch("w1");
            let token_manager = Arc::new(TokenManager::from_env().await);
            let service = ClaimService::new(store, registry, token_manager, 30);

            let resp = service
                .claim(&ClaimRequest {
                    worker_id: "w1".to_string(),
                    count: 1,
                })
                .await;

            assert_eq!(resp.items.len(), 1);
            assert!(!resp.enumeration_done);
        });
    }

    #[test]
    fn claim_service_marks_done_when_queue_empty_and_drained() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store: Arc<dyn TargetStore> = Arc::new(MockStore::with_items(vec![], true));
            let registry = Arc::new(WorkerRegistry::new(60));
            registry.touch("w1");
            let token_manager = Arc::new(TokenManager::from_env().await);
            let service = ClaimService::new(store, registry, token_manager, 30);

            let resp = service
                .claim(&ClaimRequest {
                    worker_id: "w1".to_string(),
                    count: 5,
                })
                .await;

            assert!(resp.items.is_empty());
            assert!(resp.enumeration_done);
        });
    }

    #[test]
    fn report_service_success_updates_cache_and_returns_ok() {
        let store: Arc<dyn TargetStore> = Arc::new(MockStore::with_complete_result(true));
        let cache = Arc::new(MockCache::default());
        let service = ReportService::new(store, Arc::clone(&cache));

        let ack = service.submit(SubmitReport {
            worker_id: "w1".to_string(),
            item_id: Some(1),
            repo: "https://github.com/acme/repo".to_string(),
            has_leak: false,
            finding_count: 0,
            findings: Vec::<WireFinding>::new(),
            commit_sha: Some("abc123".to_string()),
            error: None,
        });

        assert!(ack.ok);
        let writes = cache.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, "https://github.com/acme/repo");
        assert_eq!(writes[0].1, "abc123");
    }

    #[test]
    fn report_service_failure_returns_not_ok_and_skips_cache_write() {
        let store: Arc<dyn TargetStore> = Arc::new(MockStore::with_complete_result(false));
        let cache = Arc::new(MockCache::default());
        let service = ReportService::new(store, Arc::clone(&cache));

        let ack = service.submit(SubmitReport {
            worker_id: "w1".to_string(),
            item_id: Some(1),
            repo: "https://github.com/acme/repo".to_string(),
            has_leak: false,
            finding_count: 0,
            findings: Vec::<WireFinding>::new(),
            commit_sha: Some("abc123".to_string()),
            error: None,
        });

        assert!(!ack.ok);
        let writes = cache.writes.lock().unwrap();
        assert!(writes.is_empty());
    }
}
