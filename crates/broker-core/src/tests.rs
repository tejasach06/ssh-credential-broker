use super::*;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;

#[derive(Default)]
struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
}
impl TestClock {
    fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}
fn credentials() -> Vec<Credential> {
    ["first", "second", "third"]
        .into_iter()
        .map(|username| Credential {
            username: username.into(),
            password: "synthetic-test-password".into(),
        })
        .collect()
}
fn unlocked() -> (Arc<StateEngine>, Arc<TestClock>, GrantToken) {
    let clock = Arc::new(TestClock::default());
    let engine = Arc::new(StateEngine::with_clock(4, clock.clone()));
    let token = engine
        .unlock(Duration::from_secs(60), credentials(), Some(1001))
        .unwrap();
    (engine, clock, token)
}
fn pending(target: &str, ip: &str, fingerprint: &str) -> PendingDestination {
    PendingDestination {
        target: target.into(),
        port: 22,
        resolved_ip: ip.into(),
        host_key_fingerprint: fingerprint.into(),
        host_key_type: "ssh-ed25519".into(),
    }
}
fn approve(engine: &StateEngine, token: &GrantToken, target: &str, budget: u32) -> ApprovedTarget {
    engine
        .register_pending(token, pending(target, "192.0.2.1", "SHA256:test"))
        .unwrap();
    engine
        .approve_target(
            target.into(),
            22,
            "192.0.2.1".into(),
            "SHA256:test".into(),
            budget,
        )
        .unwrap();
    engine.resolve_pinned_target(token, target, 22).unwrap()
}
async fn is_pending<F: Future>(future: Pin<&mut F>) -> bool {
    let mut future = future;
    poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await
}
fn submit(reservation: &mut AttemptReservation) -> String {
    reservation
        .commit_credentials(|credential| credential.username.clone())
        .unwrap()
}

#[tokio::test]
async fn starts_locked_and_rejects_invalid_or_duplicate_fixed_pool() {
    let engine = Arc::new(StateEngine::new(4));
    assert!(!engine.status().unlocked);
    assert!(matches!(engine.grant_token(1001), Err(CoreError::Locked)));
    let mut duplicate = credentials();
    duplicate.push(duplicate[0].clone());
    assert!(matches!(
        engine.unlock(Duration::from_secs(60), duplicate, Some(1001)),
        Err(CoreError::InvalidInput(_))
    ));
    let mut empty = credentials();
    empty[0].password.clear();
    assert!(matches!(
        engine.unlock(Duration::from_secs(60), empty, Some(1001)),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        engine.unlock(Duration::from_secs(59), credentials(), Some(1001)),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        engine.unlock(Duration::from_secs(60), credentials(), None),
        Err(CoreError::InvalidInput(_))
    ));
    let token = engine
        .unlock(Duration::from_secs(60), credentials(), Some(1001))
        .unwrap();
    assert_eq!(token.generation(), 1);
    assert!(matches!(
        engine.grant_token(1002),
        Err(CoreError::UnauthorizedHarness)
    ));
    assert!(matches!(
        engine.unlock(Duration::from_secs(60), credentials(), Some(1001)),
        Err(CoreError::AlreadyUnlocked)
    ));
}

#[tokio::test]
async fn approval_requires_exact_pending_numeric_endpoint_and_key() {
    let (engine, _, token) = unlocked();
    assert!(matches!(
        engine.approve_target(
            "server".into(),
            22,
            "192.0.2.1".into(),
            "SHA256:test".into(),
            1
        ),
        Err(CoreError::TargetNotFound { .. })
    ));
    engine
        .register_pending(&token, pending("server", "192.0.2.1", "SHA256:test"))
        .unwrap();
    assert!(matches!(
        engine.approve_target(
            "server".into(),
            22,
            "192.0.2.2".into(),
            "SHA256:test".into(),
            1
        ),
        Err(CoreError::TargetNotFound { .. })
    ));
    assert!(matches!(
        engine.approve_target(
            "server".into(),
            22,
            "192.0.2.1".into(),
            "SHA256:other".into(),
            1
        ),
        Err(CoreError::TargetNotFound { .. })
    ));
    assert_eq!(engine.list_pending().unwrap().len(), 1);
    engine
        .approve_target(
            "server".into(),
            22,
            "192.0.2.1".into(),
            "SHA256:test".into(),
            1,
        )
        .unwrap();
    assert_eq!(
        engine
            .resolve_pinned_target(&token, "server", 22)
            .unwrap()
            .pinned_ip,
        "192.0.2.1"
    );
}

#[tokio::test]
async fn pending_queue_collapses_identical_requests_and_denial_preserves_approval() {
    let (engine, _, token) = unlocked();
    let target = approve(&engine, &token, "approved", 1);
    for _ in 0..8 {
        engine
            .register_pending(&token, pending("one", "192.0.2.2", "SHA256:one"))
            .unwrap();
    }
    for name in ["two", "three", "four"] {
        engine
            .register_pending(&token, pending(name, "192.0.2.2", "SHA256:one"))
            .unwrap();
    }
    assert_eq!(engine.list_pending().unwrap().len(), 4);
    assert!(matches!(
        engine.register_pending(&token, pending("five", "192.0.2.2", "SHA256:one")),
        Err(CoreError::PendingQueueFull(4))
    ));
    engine.deny_target("one".into(), 22).unwrap();
    assert_eq!(engine.list_pending().unwrap().len(), 3);
    engine.deny_target(target.target.clone(), 22).unwrap();
    assert!(engine
        .resolve_pinned_target(&token, &target.target, 22)
        .is_ok());
}

#[tokio::test]
async fn aliases_and_reapproval_share_budget_cache_and_cursor() {
    let (engine, _, token) = unlocked();
    let first = approve(&engine, &token, "server", 1);
    let second = approve(&engine, &token, "alias", 100);
    let guard = engine.acquire_identity(&token, &first).await.unwrap();
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut attempt), "first");
    attempt.record_auth_rejection().unwrap();
    drop(attempt);
    drop(guard);
    assert!(matches!(
        engine.reserve_attempt(&engine.acquire_identity(&token, &second).await.unwrap()),
        Err(CoreError::BudgetExhausted { .. })
    ));
    let fresh = approve(&engine, &token, "server", 100);
    assert_eq!(fresh.attempt_budget, 1);
    assert_eq!(fresh.attempts_consumed, 1);
    assert_eq!(fresh.discovery_cursor, 1);
    engine.add_budget("alias".into(), 22, 1).unwrap();
    let guard = engine.acquire_identity(&token, &fresh).await.unwrap();
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut attempt), "second");
    attempt.record_auth_success().unwrap();
    drop(attempt);
    drop(guard);
    assert!(
        engine
            .resolve_pinned_target(&token, "alias", 22)
            .unwrap()
            .cached_match
    );
}

#[tokio::test]
async fn mapped_ipv6_alias_shares_budget_gate_cache_and_cursor_with_ipv4() {
    for succeeds in [false, true] {
        let (engine, _, token) = unlocked();
        let first = approve(&engine, &token, "ipv4-server", 1);
        engine
            .register_pending(
                &token,
                pending("mapped-alias", "::ffff:192.0.2.1", "SHA256:test"),
            )
            .unwrap();
        assert_eq!(engine.list_pending().unwrap()[0].resolved_ip, "192.0.2.1");
        engine
            .approve_target(
                "mapped-alias".into(),
                22,
                "::ffff:c000:201".into(),
                "SHA256:test".into(),
                100,
            )
            .unwrap();
        let mapped = engine
            .resolve_pinned_target(&token, "mapped-alias", 22)
            .unwrap();
        assert_eq!(mapped.pinned_ip, "192.0.2.1");
        assert_eq!(mapped.attempt_budget, 1);
        let guard = engine.acquire_identity(&token, &first).await.unwrap();
        let mut waiting = Box::pin(engine.acquire_identity(&token, &mapped));
        assert!(is_pending(waiting.as_mut()).await);
        drop(waiting);
        let mut attempt = engine.reserve_attempt(&guard).unwrap();
        assert_eq!(submit(&mut attempt), "first");
        if succeeds {
            attempt.record_auth_success().unwrap();
        } else {
            attempt.record_auth_rejection().unwrap();
        }
        drop(attempt);
        drop(guard);
        // Reapproving the alternate spelling must not reset the canonical state.
        engine
            .register_pending(
                &token,
                pending("mapped-alias", "::ffff:c000:201", "SHA256:test"),
            )
            .unwrap();
        engine
            .approve_target(
                "mapped-alias".into(),
                22,
                "192.0.2.1".into(),
                "SHA256:test".into(),
                100,
            )
            .unwrap();
        let mapped = engine
            .resolve_pinned_target(&token, "mapped-alias", 22)
            .unwrap();
        assert_eq!(mapped.attempt_budget, 1);
        assert_eq!(mapped.attempts_consumed, 1);
        assert_eq!(mapped.discovery_cursor, usize::from(!succeeds));
        assert_eq!(mapped.cached_match, succeeds);
        let guard = engine.acquire_identity(&token, &mapped).await.unwrap();
        assert!(matches!(
            engine.reserve_attempt(&guard),
            Err(CoreError::BudgetExhausted { .. })
        ));
    }
}

#[tokio::test]
async fn mapped_ipv6_and_ipv4_numeric_targets_refer_to_same_pending_alias() {
    let (engine, _, token) = unlocked();
    engine
        .register_pending(
            &token,
            pending("::ffff:192.0.2.1", "::ffff:192.0.2.1", "SHA256:test"),
        )
        .unwrap();
    engine
        .register_pending(&token, pending("192.0.2.1", "192.0.2.1", "SHA256:test"))
        .unwrap();
    assert_eq!(engine.list_pending().unwrap().len(), 1);
    engine
        .approve_target(
            "::ffff:c000:201".into(),
            22,
            "192.0.2.1".into(),
            "SHA256:test".into(),
            1,
        )
        .unwrap();
    for target in ["192.0.2.1", "::ffff:192.0.2.1", "::ffff:c000:201"] {
        assert_eq!(
            engine
                .resolve_pinned_target(&token, target, 22)
                .unwrap()
                .pinned_ip,
            "192.0.2.1"
        );
    }
}

#[tokio::test]
async fn reservation_refunds_before_commit_but_uncertain_submission_stays_consumed() {
    let (engine, _, token) = unlocked();
    let target = approve(&engine, &token, "server", 1);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    drop(engine.reserve_attempt(&guard).unwrap());
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut attempt), "first");
    assert!(matches!(
        attempt.commit_credentials(|_| ()),
        Err(CoreError::InvalidAttempt)
    ));
    drop(attempt);
    let state = engine.resolve_pinned_target(&token, "server", 22).unwrap();
    assert_eq!(state.attempts_consumed, 1);
    assert_eq!(state.discovery_cursor, 0);
    assert!(matches!(
        engine.reserve_attempt(&guard),
        Err(CoreError::BudgetExhausted { .. })
    ));
}

#[tokio::test]
async fn cached_rejection_stops_until_explicit_resume_after_rejected_entry() {
    let (engine, _, token) = unlocked();
    let target = approve(&engine, &token, "server", 4);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut first = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut first), "first");
    first.record_auth_rejection().unwrap();
    drop(first);
    let mut second = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut second), "second");
    second.record_auth_success().unwrap();
    drop(second);
    drop(guard);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut cached = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut cached), "second");
    cached.record_auth_rejection().unwrap();
    drop(cached);
    let rejected = engine.resolve_pinned_target(&token, "server", 22).unwrap();
    assert_eq!(rejected.attempt_budget, rejected.attempts_consumed);
    engine.add_budget("server".into(), 22, 1).unwrap();
    assert!(matches!(
        engine.reserve_attempt(&guard),
        Err(CoreError::RenewalRequired { .. })
    ));
    engine.resume_discovery("server".into(), 22, 1).unwrap();
    let mut next = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut next), "third");
}

#[tokio::test]
async fn expiry_before_commit_prevents_handoff_and_cancels_token() {
    let (engine, clock, token) = unlocked();
    let target = approve(&engine, &token, "server", 1);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    clock.advance(60);
    let mut handed_off = false;
    assert_eq!(
        attempt.commit_credentials(|_| {
            handed_off = true;
        }),
        Err(CoreError::Expired)
    );
    assert!(!handed_off);
    assert_eq!(token.cancelled().await, Revocation::Expired);
    assert!(!engine.status().unlocked);
    assert_eq!(engine.status().approved_targets, 0);
}

#[tokio::test]
async fn lock_after_commit_prevents_success_and_stale_callbacks_cannot_mutate_new_grant() {
    let (engine, _, old) = unlocked();
    let target = approve(&engine, &old, "server", 1);
    let guard = engine.acquire_identity(&old, &target).await.unwrap();
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    submit(&mut attempt);
    engine.lock();
    assert_eq!(old.cancelled().await, Revocation::Locked);
    let new = engine
        .unlock(Duration::from_secs(60), credentials(), Some(1001))
        .unwrap();
    let target = approve(&engine, &new, "server", 1);
    assert!(new.generation() > old.generation());
    assert!(matches!(
        attempt.record_auth_success(),
        Err(CoreError::OperatorLocked)
    ));
    assert!(matches!(
        attempt.record_auth_rejection(),
        Err(CoreError::OperatorLocked)
    ));
    drop(attempt);
    drop(guard);
    let snapshot = engine.resolve_pinned_target(&new, "server", 22).unwrap();
    assert!(!snapshot.cached_match);
    assert_eq!(snapshot.attempts_consumed, 0);
    assert_eq!(snapshot.discovery_cursor, 0);
    let new_guard = engine.acquire_identity(&new, &target).await.unwrap();
    assert!(engine.reserve_attempt(&new_guard).is_ok());
}

#[tokio::test]
async fn authenticated_completion_cannot_open_channel_after_expiry() {
    let (engine, clock, token) = unlocked();
    let target = approve(&engine, &token, "server", 1);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    submit(&mut attempt);
    let authenticated = attempt.record_auth_success().unwrap();
    clock.advance(61);
    let mut opened = false;
    assert!(matches!(
        engine.commit_session(&authenticated, || {
            opened = true;
        }),
        Err(CoreError::Expired)
    ));
    assert!(!opened);
}

#[tokio::test]
async fn active_session_receives_lock_and_expiry_and_old_lease_cannot_decrement_new_count() {
    let (engine, clock, token) = unlocked();
    let target = approve(&engine, &token, "server", 1);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    submit(&mut attempt);
    let authenticated = attempt.record_auth_success().unwrap();
    let (_, session) = engine.commit_session(&authenticated, || ()).unwrap();
    assert_eq!(engine.status().active_sessions, 1);
    assert!(matches!(
        engine.commit_session(&authenticated, || ()),
        Err(CoreError::InvalidAttempt)
    ));
    clock.advance(60);
    assert!(engine.expire_due());
    assert_eq!(session.cancelled().await, Revocation::Expired);
    let token = engine
        .unlock(Duration::from_secs(60), credentials(), Some(1001))
        .unwrap();
    let target = approve(&engine, &token, "server", 1);
    let new_guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut attempt = engine.reserve_attempt(&new_guard).unwrap();
    submit(&mut attempt);
    let authenticated = attempt.record_auth_success().unwrap();
    let (_, new_session) = engine.commit_session(&authenticated, || ()).unwrap();
    drop(session);
    assert_eq!(engine.status().active_sessions, 1);
    engine.lock();
    assert_eq!(new_session.cancelled().await, Revocation::Locked);
    assert_eq!(engine.status().active_sessions, 0);
}

#[tokio::test]
async fn host_key_change_invalidates_aliases_and_match_until_new_pending_decision() {
    let (engine, _, token) = unlocked();
    let target = approve(&engine, &token, "server", 2);
    approve(&engine, &token, "alias", 2);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    submit(&mut attempt);
    attempt.record_auth_success().unwrap();
    assert!(matches!(
        engine.verify_host_key(&token, &target, "SHA256:changed"),
        Err(CoreError::HostKeyMismatch { .. })
    ));
    assert!(matches!(
        engine.resolve_pinned_target(&token, "alias", 22),
        Err(CoreError::ApprovalRequired { .. })
    ));
    assert!(matches!(
        engine.reserve_attempt(&guard),
        Err(CoreError::ApprovalRequired { .. })
    ));
    engine
        .register_pending(&token, pending("server", "192.0.2.1", "SHA256:changed"))
        .unwrap();
    engine
        .approve_target(
            "server".into(),
            22,
            "192.0.2.1".into(),
            "SHA256:changed".into(),
            1,
        )
        .unwrap();
    let changed = engine.resolve_pinned_target(&token, "server", 22).unwrap();
    assert!(!changed.cached_match);
    assert_eq!(changed.host_key_fingerprint, "SHA256:changed");
}

#[tokio::test]
async fn concurrent_first_requests_share_failed_discovery_not_duplicate_scan() {
    let (engine, _, token) = unlocked();
    let target = approve(&engine, &token, "server", 3);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut waiting = Box::pin(engine.acquire_identity(&token, &target));
    assert!(is_pending(waiting.as_mut()).await);
    let mut attempt = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut attempt), "first");
    attempt.record_auth_rejection().unwrap();
    drop(attempt);
    drop(guard);
    assert!(matches!(
        waiting.await,
        Err(CoreError::AuthenticationRejected)
    ));
    assert_eq!(
        engine
            .resolve_pinned_target(&token, "server", 22)
            .unwrap()
            .attempts_consumed,
        1
    );
}

#[tokio::test]
async fn reservation_keeps_serialization_even_if_caller_drops_discovery_guard() {
    let (engine, _, token) = unlocked();
    let target = approve(&engine, &token, "server", 1);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let reservation = engine.reserve_attempt(&guard).unwrap();
    drop(guard);
    let mut waiting = Box::pin(engine.acquire_identity(&token, &target));
    assert!(is_pending(waiting.as_mut()).await);
    drop(reservation);
    assert!(matches!(waiting.await, Err(CoreError::TransportFailure)));
}

#[tokio::test]
async fn concurrent_cached_requests_cannot_commit_more_than_remaining_budget() {
    let (engine, _, token) = unlocked();
    let target = approve(&engine, &token, "server", 2);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut first = engine.reserve_attempt(&guard).unwrap();
    submit(&mut first);
    first.record_auth_success().unwrap();
    drop(first);
    drop(guard);
    let guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut waiting = Box::pin(engine.acquire_identity(&token, &target));
    assert!(is_pending(waiting.as_mut()).await);
    let mut last = engine.reserve_attempt(&guard).unwrap();
    assert_eq!(submit(&mut last), "first");
    last.record_auth_success().unwrap();
    drop(last);
    drop(guard);
    let waiting_guard = waiting.await.unwrap();
    assert!(matches!(
        engine.reserve_attempt(&waiting_guard),
        Err(CoreError::BudgetExhausted { .. })
    ));
    assert_eq!(
        engine
            .resolve_pinned_target(&token, "server", 22)
            .unwrap()
            .attempts_consumed,
        2
    );
}

#[tokio::test]
async fn queued_work_cancels_without_waiting_for_discovery_holder() {
    let (engine, _, token) = unlocked();
    let target = approve(&engine, &token, "server", 1);
    let _guard = engine.acquire_identity(&token, &target).await.unwrap();
    let mut waiting = Box::pin(engine.acquire_identity(&token, &target));
    assert!(is_pending(waiting.as_mut()).await);
    engine.lock();
    assert!(matches!(waiting.await, Err(CoreError::OperatorLocked)));
}

#[tokio::test]
async fn continuous_deadline_and_generation_are_distinct_and_polling_is_guarded() {
    let (engine, clock, token) = unlocked();
    assert_eq!(token.generation(), 1);
    assert_eq!(token.deadline(), Duration::from_secs(60));
    assert_eq!(engine.with_active_grant(&token, || 7), Ok(7));
    clock.advance(61);
    let mut polled = false;
    assert_eq!(
        engine.with_active_grant(&token, || {
            polled = true;
        }),
        Err(CoreError::Expired)
    );
    assert!(!polled);
    assert_eq!(token.cancellation_reason(), Some(Revocation::Expired));
}
