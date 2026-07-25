//! Dynamic worker registry: liveness tracking for the scanning fleet.
//!
//! Every scanning client registers with the server and periodically sends a
//! heartbeat. The registry tracks which workers are *currently active* (seen
//! within their TTL) so the server can report an accurate fleet size via
//! `/stats`. Workers that stop heartbeating expire automatically.
//!
//! Work itself is distributed centrally through the claim queue (see
//! [`crate::store`]), not by this registry — a client needs nothing from here
//! beyond staying counted as alive.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::lifecycle::WorkerLifecycleState;
use crate::util::current_unix_time;

/// How long (seconds) a worker may go without a heartbeat before it is
/// considered dead. Overridable via `SECUREKIT_WORKER_TTL_SECS`.
pub const DEFAULT_WORKER_TTL_SECS: u64 = 60;

struct Inner {
    /// worker_id -> lifecycle record.
    workers: HashMap<String, WorkerRecord>,
}

#[derive(Clone, Debug)]
struct WorkerRecord {
    last_seen: u64,
    state: WorkerLifecycleState,
}

/// Thread-safe registry of active scanning workers.
pub struct WorkerRegistry {
    inner: Mutex<Inner>,
    ttl_secs: u64,
}

impl WorkerRegistry {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                workers: HashMap::new(),
            }),
            ttl_secs: ttl_secs.max(1),
        }
    }

    /// Register or refresh `worker_id`'s liveness and return the heartbeat TTL
    /// (seconds) the client must ping within. Used by both `/register` and
    /// `/heartbeat`.
    pub fn touch(&self, worker_id: &str) -> u64 {
        let now = current_unix_time();
        let mut inner = self.inner.lock().unwrap();

        // Mark stale workers first, then refresh current worker.
        inner.mark_stale(now, self.ttl_secs);
        let entry = inner
            .workers
            .entry(worker_id.to_string())
            .or_insert(WorkerRecord {
                last_seen: now,
                state: WorkerLifecycleState::Registered,
            });
        entry.last_seen = now;
        entry.state = entry.state.on_touch();

        self.ttl_secs
    }

    /// Number of workers considered active right now (expiring stale ones).
    pub fn active_count(&self) -> usize {
        let now = current_unix_time();
        let mut inner = self.inner.lock().unwrap();
        inner.mark_stale(now, self.ttl_secs);
        inner
            .workers
            .values()
            .filter(|r| r.state.is_active())
            .count()
    }

    /// Remove a worker from the active set immediately.
    pub fn unregister(&self, worker_id: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(worker) = inner.workers.get_mut(worker_id) {
            worker.state = worker.state.on_unregister();
        }
        inner.workers.remove(worker_id);
    }
}

impl Inner {
    fn mark_stale(&mut self, now: u64, ttl_secs: u64) {
        for worker in self.workers.values_mut() {
            if now.saturating_sub(worker.last_seen) > ttl_secs {
                worker.state = worker.state.on_expire();
            }
        }
    }
}
