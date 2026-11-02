//! Grant-owned authorization state. Network I/O belongs outside this module's state mutex.
//! Commit closures must be short, nonblocking transport handoffs; returning an owned future
//! is supported, but a future must not borrow the supplied credential.
use broker_proto::{Credential, PendingDestination};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{watch, Mutex as AsyncMutex, OwnedMutexGuard};
use zeroize::Zeroize;

mod clock;
pub use clock::{Clock, ContinuousClock};

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("Broker is locked")]
    Locked,
    #[error("Grant was revoked by the operator")]
    OperatorLocked,
    #[error("Broker is already unlocked")]
    AlreadyUnlocked,
    #[error("Grant has expired")]
    Expired,
    #[error("Grant is no longer current")]
    StaleGrant,
    #[error("Harness identity is not authorized")]
    UnauthorizedHarness,
    #[error("Invalid operator input: {0}")]
    InvalidInput(&'static str),
    #[error("Target {target}:{port} requires operator approval")]
    ApprovalRequired {
        target: String,
        port: u16,
        host_key_fingerprint: String,
    },
    #[error("Target {target}:{port} was rejected or not found")]
    TargetNotFound { target: String, port: u16 },
    #[error("Authentication attempt budget exhausted for {target}:{port}")]
    BudgetExhausted { target: String, port: u16 },
    #[error("Server requires operator renewal after cached credential was rejected")]
    RenewalRequired { target: String, port: u16 },
    #[error("No remaining credentials in pool")]
    PoolExhausted,
    #[error("Host key mismatch for pinned destination {pinned_ip}:{port}")]
    HostKeyMismatch { pinned_ip: String, port: u16 },
    #[error("Pending approvals queue is full (max {0})")]
    PendingQueueFull(usize),
    #[error("Password authentication was rejected")]
    AuthenticationRejected,
    #[error("SSH transport failed")]
    TransportFailure,
    #[error("Attempt has already completed or was not committed")]
    InvalidAttempt,
}
impl CoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Locked | Self::StaleGrant => "BROKER_LOCKED",
            Self::OperatorLocked => "BROKER_LOCK",
            Self::Expired => "BROKER_EXPIRED",
            Self::AlreadyUnlocked => "ALREADY_UNLOCKED",
            Self::UnauthorizedHarness => "PERMISSION_DENIED",
            Self::InvalidInput(_) => "INPUT_ERROR",
            Self::ApprovalRequired { .. } => "APPROVAL_REQUIRED",
            Self::TargetNotFound { .. } => "NOT_FOUND",
            Self::BudgetExhausted { .. } => "BUDGET_EXHAUSTED",
            Self::RenewalRequired { .. } => "RENEWAL_REQUIRED",
            Self::PoolExhausted | Self::AuthenticationRejected => "AUTHENTICATION_REJECTED",
            Self::HostKeyMismatch { .. } => "HOST_KEY_MISMATCH",
            Self::PendingQueueFull(_) => "RESOURCE_LIMIT",
            Self::TransportFailure => "TRANSPORT_FAILURE",
            Self::InvalidAttempt => "PROTOCOL_ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    Locked,
    Expired,
}
impl Revocation {
    fn error(self) -> CoreError {
        match self {
            Self::Locked => CoreError::OperatorLocked,
            Self::Expired => CoreError::Expired,
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::Locked => "BROKER_LOCK",
            Self::Expired => "BROKER_EXPIRED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GrantToken {
    generation: u64,
    deadline: Duration,
    cancellation: watch::Receiver<Option<Revocation>>,
}
impl GrantToken {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Absolute continuous-clock time, not a wall-clock timestamp or generation number.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }
    pub fn cancellation_reason(&self) -> Option<Revocation> {
        *self.cancellation.borrow()
    }
    pub async fn cancelled(&self) -> Revocation {
        let mut receiver = self.cancellation.clone();
        loop {
            if let Some(reason) = *receiver.borrow_and_update() {
                return reason;
            }
            if receiver.changed().await.is_err() {
                return Revocation::Locked;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApprovedTarget {
    pub target: String,
    pub port: u16,
    pub pinned_ip: String,
    pub host_key_fingerprint: String,
    pub attempt_budget: u32,
    pub attempts_consumed: u32,
    pub discovery_cursor: usize,
    pub cached_match: bool,
    pub renewal_required: bool,
    identity: Identity,
    generation: u64,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub unlocked: bool,
    pub remaining_ttl: Option<Duration>,
    pub pending_approvals: usize,
    pub approved_targets: usize,
    pub active_sessions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Alias {
    target: String,
    port: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Identity {
    address: IpAddr,
    port: u16,
    fingerprint: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingKey {
    alias: Alias,
    identity: Identity,
}

struct IdentityState {
    approved: bool,
    budget: u32,
    consumed: u32,
    reserved: u32,
    cursor: usize,
    rejected: HashSet<usize>,
    cached: Option<usize>,
    renewal: bool,
    gate: Arc<AsyncMutex<()>>,
    completed_round: u64,
    last_outcome: Option<CoreError>,
    attempts: HashMap<u64, bool>,
}
impl IdentityState {
    fn new(budget: u32) -> Self {
        Self {
            approved: true,
            budget,
            consumed: 0,
            reserved: 0,
            cursor: 0,
            rejected: HashSet::new(),
            cached: None,
            renewal: false,
            gate: Arc::new(AsyncMutex::new(())),
            completed_round: 0,
            last_outcome: None,
            attempts: HashMap::new(),
        }
    }
}

struct Grant {
    token: GrantToken,
    cancellation: watch::Sender<Option<Revocation>>,
    harness_uid: u32,
    credentials: Vec<Credential>,
    locked_memory: Vec<(usize, usize)>,
    aliases: HashMap<Alias, Identity>,
    identities: HashMap<Identity, IdentityState>,
    pending: HashMap<PendingKey, PendingDestination>,
    next_attempt: u64,
    active_sessions: usize,
}
impl Drop for Grant {
    fn drop(&mut self) {
        let reason = self
            .token
            .cancellation_reason()
            .unwrap_or(Revocation::Locked);
        self.cancellation.send_replace(Some(reason));
        for credential in &mut self.credentials {
            credential.zeroize();
        }
        #[cfg(unix)]
        for &(address, length) in &self.locked_memory {
            unsafe {
                libc::munlock(address as *const libc::c_void, length);
            }
        }
        #[cfg(not(unix))]
        let _ = &self.locked_memory;
    }
}
struct State {
    next_generation: u64,
    grant: Option<Grant>,
}

pub struct StateEngine {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    max_pending: usize,
}
impl StateEngine {
    pub fn new(max_pending: usize) -> Self {
        Self::with_clock(max_pending, Arc::new(ContinuousClock::new()))
    }
    /// The clock seam permits deterministic deadline tests without altering wall time.
    pub fn with_clock(max_pending: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Mutex::new(State {
                next_generation: 0,
                grant: None,
            }),
            clock,
            max_pending,
        }
    }
    fn state(&self) -> MutexGuard<'_, State> {
        // A panic inside a commit closure must fail closed, never recover authorization.
        self.state
            .lock()
            .expect("authorization state mutex poisoned")
    }
    fn expire_locked(&self, state: &mut State) -> bool {
        if state
            .grant
            .as_ref()
            .is_some_and(|g| self.clock.now() >= g.token.deadline)
        {
            Self::revoke(state, Revocation::Expired);
            true
        } else {
            false
        }
    }
    fn revoke(state: &mut State, reason: Revocation) {
        if let Some(grant) = state.grant.take() {
            // Taking the grant invalidates it under the commit lock before notifying work.
            grant.cancellation.send_replace(Some(reason));
            drop(grant);
        }
    }
    fn live<'a>(
        &self,
        state: &'a mut State,
        token: Option<&GrantToken>,
    ) -> Result<&'a mut Grant, CoreError> {
        self.expire_locked(state);
        if let Some(token) = token {
            if let Some(reason) = token.cancellation_reason() {
                return Err(reason.error());
            }
        }
        let grant = state.grant.as_mut().ok_or(CoreError::Locked)?;
        if let Some(token) = token {
            if token.generation != grant.token.generation
                || !token.cancellation.same_channel(&grant.token.cancellation)
            {
                return Err(CoreError::StaleGrant);
            }
        }
        Ok(grant)
    }
    pub fn unlock(
        self: &Arc<Self>,
        ttl: Duration,
        credentials: Vec<Credential>,
        harness_uid: Option<u32>,
    ) -> Result<GrantToken, CoreError> {
        let mut state = self.state();
        self.expire_locked(&mut state);
        if state.grant.is_some() {
            return Err(CoreError::AlreadyUnlocked);
        }
        if !(Duration::from_secs(60)..=Duration::from_secs(8 * 60 * 60)).contains(&ttl) {
            return Err(CoreError::InvalidInput(
                "duration must be one minute through eight hours",
            ));
        }
        let harness_uid = harness_uid.ok_or(CoreError::InvalidInput("harness UID is required"))?;
        validate_credentials(&credentials)?;
        let deadline = self
            .clock
            .now()
            .checked_add(ttl)
            .ok_or(CoreError::InvalidInput("deadline overflow"))?;
        state.next_generation = state
            .next_generation
            .checked_add(1)
            .ok_or(CoreError::InvalidInput("generation overflow"))?;
        let (sender, receiver) = watch::channel(None);
        let token = GrantToken {
            generation: state.next_generation,
            deadline,
            cancellation: receiver,
        };
        let locked_memory = lock_credentials(&credentials);
        state.grant = Some(Grant {
            token: token.clone(),
            cancellation: sender,
            harness_uid,
            credentials,
            locked_memory,
            aliases: HashMap::new(),
            identities: HashMap::new(),
            pending: HashMap::new(),
            next_attempt: 0,
            active_sessions: 0,
        });
        drop(state);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(self);
            let timer_token = token.clone();
            runtime.spawn(async move {
                loop {
                    tokio::select! {
                        _ = timer_token.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                    let Some(engine) = weak.upgrade() else {
                        break;
                    };
                    engine.expire_due();
                }
            });
        }
        Ok(token)
    }
    pub fn lock(&self) {
        Self::revoke(&mut self.state(), Revocation::Locked);
    }
    /// Called by the automatic Tokio expiry monitor; also usable by synchronous embedders.
    pub fn expire_due(&self) -> bool {
        self.expire_locked(&mut self.state())
    }
    pub fn status(&self) -> Status {
        let mut state = self.state();
        self.expire_locked(&mut state);
        match &state.grant {
            Some(g) => Status {
                unlocked: true,
                remaining_ttl: Some(g.token.deadline.saturating_sub(self.clock.now())),
                pending_approvals: g.pending.len(),
                approved_targets: g
                    .aliases
                    .values()
                    .filter(|id| g.identities.get(*id).is_some_and(|s| s.approved))
                    .count(),
                active_sessions: g.active_sessions,
            },
            None => Status {
                unlocked: false,
                remaining_ttl: None,
                pending_approvals: 0,
                approved_targets: 0,
                active_sessions: 0,
            },
        }
    }
    pub fn grant_token(&self, harness_uid: u32) -> Result<GrantToken, CoreError> {
        let mut state = self.state();
        let grant = self.live(&mut state, None)?;
        if grant.harness_uid != harness_uid {
            return Err(CoreError::UnauthorizedHarness);
        }
        Ok(grant.token.clone())
    }
    pub fn register_pending(
        &self,
        token: &GrantToken,
        mut pending: PendingDestination,
    ) -> Result<(), CoreError> {
        let identity = validate_destination(&pending)?;
        pending.resolved_ip = identity.address.to_string();
        let key = PendingKey {
            alias: alias(&pending.target, pending.port),
            identity,
        };
        let mut state = self.state();
        let grant = self.live(&mut state, Some(token))?;
        if grant.pending.len() >= self.max_pending && !grant.pending.contains_key(&key) {
            return Err(CoreError::PendingQueueFull(self.max_pending));
        }
        grant.pending.insert(key, pending);
        Ok(())
    }
    pub fn list_pending(&self) -> Result<Vec<PendingDestination>, CoreError> {
        let mut state = self.state();
        let grant = self.live(&mut state, None)?;
        let mut pending: Vec<_> = grant.pending.values().cloned().collect();
        pending.sort_by(|a, b| {
            (&a.target, a.port, &a.resolved_ip, &a.host_key_fingerprint).cmp(&(
                &b.target,
                b.port,
                &b.resolved_ip,
                &b.host_key_fingerprint,
            ))
        });
        Ok(pending)
    }
    pub fn approve_target(
        &self,
        target: String,
        port: u16,
        pinned_ip: String,
        host_key_fingerprint: String,
        attempt_budget: u32,
    ) -> Result<(), CoreError> {
        if attempt_budget == 0 {
            return Err(CoreError::InvalidInput("attempt budget must be positive"));
        }
        let address = pinned_ip
            .parse()
            .map_err(|_| CoreError::InvalidInput("approval requires a numeric address"))?;
        let id = Identity {
            address,
            port,
            fingerprint: host_key_fingerprint,
        };
        let alias = alias(&target, port);
        let key = PendingKey {
            alias: alias.clone(),
            identity: id.clone(),
        };
        let mut state = self.state();
        let grant = self.live(&mut state, None)?;
        if !grant.pending.contains_key(&key) {
            return Err(CoreError::TargetNotFound { target, port });
        }
        grant.pending.remove(&key);
        // An alias or reapproval never replenishes a canonical identity's budget or cursor.
        grant
            .identities
            .entry(id.clone())
            .or_insert_with(|| IdentityState::new(attempt_budget))
            .approved = true;
        grant.aliases.insert(alias, id);
        Ok(())
    }
    pub fn deny_target(&self, target: String, port: u16) -> Result<(), CoreError> {
        let mut state = self.state();
        let grant = self.live(&mut state, None)?;
        let alias = alias(&target, port);
        grant.pending.retain(|key, _| key.alias != alias);
        Ok(())
    }
    pub fn add_budget(&self, target: String, port: u16, additional: u32) -> Result<(), CoreError> {
        self.change_budget(target, port, additional, false)
    }
    pub fn resume_discovery(
        &self,
        target: String,
        port: u16,
        additional: u32,
    ) -> Result<(), CoreError> {
        self.change_budget(target, port, additional, true)
    }
    fn change_budget(
        &self,
        target: String,
        port: u16,
        additional: u32,
        resume: bool,
    ) -> Result<(), CoreError> {
        if additional == 0 {
            return Err(CoreError::InvalidInput(
                "additional budget must be positive",
            ));
        }
        let mut state = self.state();
        let grant = self.live(&mut state, None)?;
        let id =
            grant
                .aliases
                .get(&alias(&target, port))
                .ok_or_else(|| CoreError::TargetNotFound {
                    target: target.clone(),
                    port,
                })?;
        let identity = grant.identities.get_mut(id).ok_or(CoreError::StaleGrant)?;
        if !identity.approved {
            return Err(CoreError::TargetNotFound { target, port });
        }
        identity.budget = identity
            .budget
            .checked_add(additional)
            .ok_or(CoreError::InvalidInput("attempt budget overflow"))?;
        if resume {
            identity.renewal = false;
            identity.cached = None;
        }
        Ok(())
    }
    pub fn resolve_pinned_target(
        &self,
        token: &GrantToken,
        target: &str,
        port: u16,
    ) -> Result<ApprovedTarget, CoreError> {
        let mut state = self.state();
        let grant = self.live(&mut state, Some(token))?;
        let id =
            grant
                .aliases
                .get(&alias(target, port))
                .ok_or_else(|| CoreError::ApprovalRequired {
                    target: target.into(),
                    port,
                    host_key_fingerprint: String::new(),
                })?;
        let identity = grant.identities.get(id).ok_or(CoreError::StaleGrant)?;
        if !identity.approved {
            return Err(CoreError::ApprovalRequired {
                target: target.into(),
                port,
                host_key_fingerprint: String::new(),
            });
        }
        Ok(ApprovedTarget {
            target: target.into(),
            port,
            pinned_ip: id.address.to_string(),
            host_key_fingerprint: id.fingerprint.clone(),
            attempt_budget: identity.budget,
            attempts_consumed: identity.consumed,
            discovery_cursor: identity.cursor,
            cached_match: identity.cached.is_some(),
            renewal_required: identity.renewal,
            identity: id.clone(),
            generation: token.generation,
        })
    }
    pub fn verify_host_key(
        &self,
        token: &GrantToken,
        target: &ApprovedTarget,
        observed: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.state();
        let grant = self.live(&mut state, Some(token))?;
        let identity = checked_identity(grant, target)?;
        if observed != target.identity.fingerprint {
            identity.approved = false;
            identity.cached = None;
            return Err(CoreError::HostKeyMismatch {
                pinned_ip: target.pinned_ip.clone(),
                port: target.port,
            });
        }
        Ok(())
    }
    /// Hold this guard across the complete ordered discovery loop, not just one attempt.
    /// Waiters share a failed discovery outcome. After success they use separate cached logins.
    pub async fn acquire_identity(
        self: &Arc<Self>,
        token: &GrantToken,
        target: &ApprovedTarget,
    ) -> Result<DiscoveryGuard, CoreError> {
        let (gate, observed_round) = {
            let mut state = self.state();
            let identity = checked_identity(self.live(&mut state, Some(token))?, target)?;
            (identity.gate.clone(), identity.completed_round)
        };
        let guard = tokio::select! {
            guard = gate.lock_owned() => guard,
            reason = token.cancelled() => return Err(reason.error()),
        };
        {
            let mut state = self.state();
            let identity = checked_identity(self.live(&mut state, Some(token))?, target)?;
            if identity.completed_round != observed_round && identity.cached.is_none() {
                if let Some(error) = &identity.last_outcome {
                    return Err(error.clone());
                }
            }
        }
        Ok(DiscoveryGuard {
            lease: Arc::new(DiscoveryLease {
                engine: self.clone(),
                token: token.clone(),
                target: target.clone(),
                outcome: Mutex::new(Some(CoreError::TransportFailure)),
                _guard: guard,
            }),
        })
    }
    pub fn reserve_attempt(
        self: &Arc<Self>,
        guard: &DiscoveryGuard,
    ) -> Result<AttemptReservation, CoreError> {
        if !Arc::ptr_eq(self, &guard.lease.engine) {
            return Err(CoreError::StaleGrant);
        }
        let mut state = self.state();
        let grant = self.live(&mut state, Some(&guard.lease.token))?;
        let pool_len = grant.credentials.len();
        let identity = checked_identity(grant, &guard.lease.target)?;
        let target = &guard.lease.target;
        let error = if identity.renewal {
            Some(CoreError::RenewalRequired {
                target: target.target.clone(),
                port: target.port,
            })
        } else if identity.consumed.saturating_add(identity.reserved) >= identity.budget {
            Some(CoreError::BudgetExhausted {
                target: target.target.clone(),
                port: target.port,
            })
        } else {
            None
        };
        if let Some(error) = error {
            *guard
                .lease
                .outcome
                .lock()
                .expect("discovery outcome poisoned") = Some(error.clone());
            return Err(error);
        }
        if !identity.attempts.is_empty() {
            return Err(CoreError::InvalidAttempt);
        }
        let index = match identity.cached {
            Some(index) => index,
            None => {
                while identity.cursor < pool_len && identity.rejected.contains(&identity.cursor) {
                    identity.cursor += 1;
                }
                if identity.cursor == pool_len {
                    *guard
                        .lease
                        .outcome
                        .lock()
                        .expect("discovery outcome poisoned") = Some(CoreError::PoolExhausted);
                    return Err(CoreError::PoolExhausted);
                }
                identity.cursor
            }
        };
        let was_cached = identity.cached == Some(index);
        grant.next_attempt = grant
            .next_attempt
            .checked_add(1)
            .ok_or(CoreError::InvalidAttempt)?;
        let attempt_id = grant.next_attempt;
        let identity = grant
            .identities
            .get_mut(&target.identity)
            .ok_or(CoreError::StaleGrant)?;
        identity.reserved += 1;
        identity.attempts.insert(attempt_id, false);
        Ok(AttemptReservation {
            lease: guard.lease.clone(),
            attempt_id,
            index,
            was_cached,
            finished: false,
        })
    }
    /// Poll a transport operation under the same synchronization as grant revocation.
    /// The closure must return promptly and must not reenter this engine.
    pub fn with_active_grant<T>(
        &self,
        token: &GrantToken,
        operation: impl FnOnce() -> T,
    ) -> Result<T, CoreError> {
        let mut state = self.state();
        self.live(&mut state, Some(token))?;
        Ok(operation())
    }
    /// The closure commits channel creation (or enqueues it) under the revocation lock.
    /// The returned lease keeps active-session accounting and cancellation tied to this grant.
    pub fn commit_session<T>(
        &self,
        authentication: &Authenticated,
        commit: impl FnOnce() -> T,
    ) -> Result<(T, SessionLease), CoreError> {
        if !std::ptr::eq(self, authentication.engine.as_ref()) {
            return Err(CoreError::StaleGrant);
        }
        let mut state = self.state();
        let grant = self.live(&mut state, Some(&authentication.token))?;
        let identity = grant
            .identities
            .get(&authentication.identity)
            .ok_or(CoreError::StaleGrant)?;
        if !identity.approved {
            return Err(CoreError::HostKeyMismatch {
                pinned_ip: authentication.identity.address.to_string(),
                port: authentication.identity.port,
            });
        }
        if authentication
            .opened
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(CoreError::InvalidAttempt);
        }
        grant.active_sessions += 1;
        let value = commit();
        Ok((
            value,
            SessionLease {
                engine: authentication.engine.clone(),
                token: authentication.token.clone(),
            },
        ))
    }
}

fn lock_credentials(credentials: &[Credential]) -> Vec<(usize, usize)> {
    #[cfg(not(unix))]
    let locked = Vec::new();
    #[cfg(unix)]
    let mut locked = Vec::new();
    #[cfg(unix)]
    for credential in credentials {
        for value in [&credential.username, &credential.password] {
            // Best effort: RLIMIT_MEMLOCK and platform policy can reject this request.
            // No plaintext is copied and the fixed pool never reallocates these strings.
            if unsafe { libc::mlock(value.as_ptr().cast(), value.len()) } == 0 {
                locked.push((value.as_ptr() as usize, value.len()));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = credentials;
    locked
}
fn alias(target: &str, port: u16) -> Alias {
    let target = target
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| target.trim_end_matches('.').to_ascii_lowercase());
    Alias { target, port }
}
fn validate_credentials(credentials: &[Credential]) -> Result<(), CoreError> {
    if credentials.is_empty() {
        return Err(CoreError::InvalidInput("credential pool is empty"));
    }
    let mut seen = HashSet::new();
    for credential in credentials {
        if credential.username.is_empty()
            || credential.password.is_empty()
            || credential.username.contains('\0')
            || credential.password.contains('\0')
        {
            return Err(CoreError::InvalidInput(
                "credential fields must be nonempty and contain no NUL",
            ));
        }
        if !seen.insert((credential.username.as_str(), credential.password.as_str())) {
            return Err(CoreError::InvalidInput(
                "credential pool contains duplicate entries",
            ));
        }
    }
    Ok(())
}
fn validate_destination(pending: &PendingDestination) -> Result<Identity, CoreError> {
    if pending.target.is_empty()
        || pending.target.len() > broker_proto::MAX_TARGET_LEN
        || pending.port == 0
        || pending.host_key_fingerprint.is_empty()
        || pending.host_key_type.is_empty()
    {
        return Err(CoreError::InvalidInput(
            "pending destination fields are invalid",
        ));
    }
    let address = pending
        .resolved_ip
        .parse()
        .map_err(|_| CoreError::InvalidInput("pending destination requires a numeric address"))?;
    Ok(Identity {
        address,
        port: pending.port,
        fingerprint: pending.host_key_fingerprint.clone(),
    })
}
fn checked_identity<'a>(
    grant: &'a mut Grant,
    target: &ApprovedTarget,
) -> Result<&'a mut IdentityState, CoreError> {
    if target.generation != grant.token.generation
        || grant.aliases.get(&alias(&target.target, target.port)) != Some(&target.identity)
    {
        return Err(CoreError::StaleGrant);
    }
    let identity = grant
        .identities
        .get_mut(&target.identity)
        .ok_or(CoreError::StaleGrant)?;
    if !identity.approved {
        return Err(CoreError::ApprovalRequired {
            target: target.target.clone(),
            port: target.port,
            host_key_fingerprint: target.host_key_fingerprint.clone(),
        });
    }
    Ok(identity)
}

pub struct DiscoveryGuard {
    lease: Arc<DiscoveryLease>,
}
struct DiscoveryLease {
    engine: Arc<StateEngine>,
    token: GrantToken,
    target: ApprovedTarget,
    outcome: Mutex<Option<CoreError>>,
    _guard: OwnedMutexGuard<()>,
}
impl DiscoveryGuard {
    /// Classify a connection failure before dropping the discovery guard. No raw SSH text.
    pub fn record_transport_failure(&self) {
        *self
            .lease
            .outcome
            .lock()
            .expect("discovery outcome poisoned") = Some(CoreError::TransportFailure);
    }
}
impl Drop for DiscoveryLease {
    fn drop(&mut self) {
        let mut state = self.engine.state();
        if let Ok(grant) = self.engine.live(&mut state, Some(&self.token)) {
            if let Some(identity) = grant.identities.get_mut(&self.target.identity) {
                identity.completed_round = identity.completed_round.saturating_add(1);
                identity.last_outcome = self
                    .outcome
                    .lock()
                    .expect("discovery outcome poisoned")
                    .clone();
            }
        }
    }
}

pub struct AttemptReservation {
    lease: Arc<DiscoveryLease>,
    attempt_id: u64,
    index: usize,
    was_cached: bool,
    finished: bool,
}
impl AttemptReservation {
    /// Exactly-once credential handoff. A dropped uncommitted reservation is refunded;
    /// once the closure runs the attempt stays consumed even if its result is uncertain.
    /// The closure must not block, await, reenter state, or retain a credential reference.
    pub fn commit_credentials<T>(
        &mut self,
        commit: impl FnOnce(&Credential) -> T,
    ) -> Result<T, CoreError> {
        let mut state = self.lease.engine.state();
        let grant = self
            .lease
            .engine
            .live(&mut state, Some(&self.lease.token))?;
        let identity = checked_identity(grant, &self.lease.target)?;
        let committed = identity
            .attempts
            .get_mut(&self.attempt_id)
            .ok_or(CoreError::InvalidAttempt)?;
        if *committed || self.finished {
            return Err(CoreError::InvalidAttempt);
        }
        *committed = true;
        identity.reserved -= 1;
        identity.consumed += 1;
        Ok(commit(&grant.credentials[self.index]))
    }
    pub fn record_auth_success(&mut self) -> Result<Authenticated, CoreError> {
        let mut state = self.lease.engine.state();
        let grant = self
            .lease
            .engine
            .live(&mut state, Some(&self.lease.token))?;
        let identity = checked_identity(grant, &self.lease.target)?;
        if self.finished || identity.attempts.get(&self.attempt_id) != Some(&true) {
            return Err(CoreError::InvalidAttempt);
        }
        identity.attempts.remove(&self.attempt_id);
        identity.cached = Some(self.index);
        self.finished = true;
        *self
            .lease
            .outcome
            .lock()
            .expect("discovery outcome poisoned") = None;
        Ok(Authenticated {
            engine: self.lease.engine.clone(),
            token: self.lease.token.clone(),
            identity: self.lease.target.identity.clone(),
            opened: std::sync::atomic::AtomicBool::new(false),
        })
    }
    pub fn record_auth_rejection(&mut self) -> Result<(), CoreError> {
        let mut state = self.lease.engine.state();
        let grant = self
            .lease
            .engine
            .live(&mut state, Some(&self.lease.token))?;
        let identity = checked_identity(grant, &self.lease.target)?;
        if self.finished || identity.attempts.get(&self.attempt_id) != Some(&true) {
            return Err(CoreError::InvalidAttempt);
        }
        identity.attempts.remove(&self.attempt_id);
        identity.rejected.insert(self.index);
        identity.cursor = identity.cursor.max(self.index + 1);
        if self.was_cached {
            identity.cached = None;
            identity.renewal = true;
            // Renewal authorizes fresh attempts, never an old unspent allowance.
            identity.budget = identity.consumed;
        }
        self.finished = true;
        *self
            .lease
            .outcome
            .lock()
            .expect("discovery outcome poisoned") = Some(CoreError::AuthenticationRejected);
        Ok(())
    }
}
impl Drop for AttemptReservation {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut state = self.lease.engine.state();
        if let Ok(grant) = self.lease.engine.live(&mut state, Some(&self.lease.token)) {
            if let Some(identity) = grant.identities.get_mut(&self.lease.target.identity) {
                if let Some(committed) = identity.attempts.remove(&self.attempt_id) {
                    if !committed {
                        identity.reserved -= 1;
                    }
                }
            }
        }
    }
}

pub struct Authenticated {
    engine: Arc<StateEngine>,
    token: GrantToken,
    identity: Identity,
    opened: std::sync::atomic::AtomicBool,
}
pub struct SessionLease {
    engine: Arc<StateEngine>,
    token: GrantToken,
}
impl SessionLease {
    pub fn token(&self) -> &GrantToken {
        &self.token
    }
    pub async fn cancelled(&self) -> Revocation {
        self.token.cancelled().await
    }
}
impl Drop for SessionLease {
    fn drop(&mut self) {
        let mut state = self.engine.state();
        if let Ok(grant) = self.engine.live(&mut state, Some(&self.token)) {
            grant.active_sessions = grant.active_sessions.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests;
