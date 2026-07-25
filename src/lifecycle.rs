#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerLifecycleState {
    Registered,
    Active,
    Stale,
    Unregistered,
}

impl WorkerLifecycleState {
    pub(crate) fn on_touch(self) -> Self {
        match self {
            WorkerLifecycleState::Registered
            | WorkerLifecycleState::Active
            | WorkerLifecycleState::Stale
            | WorkerLifecycleState::Unregistered => WorkerLifecycleState::Active,
        }
    }

    pub(crate) fn on_expire(self) -> Self {
        match self {
            WorkerLifecycleState::Active | WorkerLifecycleState::Registered => {
                WorkerLifecycleState::Stale
            }
            WorkerLifecycleState::Stale => WorkerLifecycleState::Stale,
            WorkerLifecycleState::Unregistered => WorkerLifecycleState::Unregistered,
        }
    }

    pub(crate) fn on_unregister(self) -> Self {
        match self {
            WorkerLifecycleState::Registered
            | WorkerLifecycleState::Active
            | WorkerLifecycleState::Stale
            | WorkerLifecycleState::Unregistered => WorkerLifecycleState::Unregistered,
        }
    }

    pub(crate) fn is_active(self) -> bool {
        matches!(self, WorkerLifecycleState::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkItemLifecycleState {
    Pending,
    Leased,
    Completed,
}

impl WorkItemLifecycleState {
    pub(crate) fn on_enqueue() -> Self {
        WorkItemLifecycleState::Pending
    }

    pub(crate) fn on_claim(self) -> Self {
        match self {
            WorkItemLifecycleState::Pending => WorkItemLifecycleState::Leased,
            WorkItemLifecycleState::Leased => WorkItemLifecycleState::Leased,
            WorkItemLifecycleState::Completed => WorkItemLifecycleState::Completed,
        }
    }

    pub(crate) fn on_lease_expire(self) -> Self {
        match self {
            WorkItemLifecycleState::Leased => WorkItemLifecycleState::Pending,
            WorkItemLifecycleState::Pending => WorkItemLifecycleState::Pending,
            WorkItemLifecycleState::Completed => WorkItemLifecycleState::Completed,
        }
    }

    pub(crate) fn on_complete(self) -> Self {
        match self {
            WorkItemLifecycleState::Pending
            | WorkItemLifecycleState::Leased
            | WorkItemLifecycleState::Completed => WorkItemLifecycleState::Completed,
        }
    }
}
