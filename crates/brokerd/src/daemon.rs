use crate::{platform, transport};
use broker_core::{CoreError, StateEngine};
use broker_proto::{
    read_frame, write_frame, AdminEnvelope, AdminRequest, AdminResponse, ErrorCode, ExecRequest,
};
#[cfg(unix)]
use clap::Parser;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;

#[derive(Parser)]
#[cfg(unix)]
struct Options {
    #[arg(long)]
    runtime_dir: PathBuf,
    #[arg(long)]
    operator_uid: u32,
    #[arg(long)]
    harness_uid: u32,
    #[arg(long)]
    exec_gid: u32,
    #[arg(long)]
    admin_gid: u32,
}

#[cfg(unix)]
pub async fn run() -> Result<(), &'static str> {
    let options = Options::parse();
    let service_uid = platform::harden()?;
    if options.harness_uid == 0
        || options.harness_uid == options.operator_uid
        || options.harness_uid == service_uid
        || options.operator_uid == service_uid
        || options.exec_gid == options.admin_gid
    {
        return Err(
            "operator, harness, and service identities must be separate; harness must not be root",
        );
    }
    let runtime = platform::secure_runtime(&options.runtime_dir, service_uid)?;
    let exec_path = runtime.join("exec.sock");
    let admin_path = runtime.join("admin.sock");
    let execution = platform::listener(&exec_path, service_uid, options.exec_gid)?;
    let administration = match platform::listener(&admin_path, service_uid, options.admin_gid) {
        Ok(listener) => listener,
        Err(e) => {
            let _ = std::fs::remove_file(&exec_path);
            return Err(e);
        }
    };
    let _cleanup = platform::SocketCleanup(exec_path, admin_path);
    let state = Arc::new(StateEngine::new(32));
    let exec_slots = Arc::new(Semaphore::new(64));
    let admin_slots = Arc::new(Semaphore::new(4));
    let operations = Arc::new(Semaphore::new(32));
    let mut termination = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "cannot install termination handler")?;
    loop {
        tokio::select! {
            _ = termination.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
            incoming = execution.accept() => {
                let (stream, _) = incoming.map_err(|_| "execution socket failed")?;
                if platform::peer_uid(&stream).ok() != Some(options.harness_uid) { continue; }
                let Ok(slot) = exec_slots.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                let operations = operations.clone();
                let uid = options.harness_uid;
                tokio::spawn(async move {
                    let _slot = slot;
                    serve_execution(stream, state, uid, operations).await;
                });
            }
            incoming = administration.accept() => {
                let (stream, _) = incoming.map_err(|_| "administration socket failed")?;
                if platform::peer_uid(&stream).ok() != Some(options.operator_uid) { continue; }
                let Ok(slot) = admin_slots.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                let uid = options.harness_uid;
                tokio::spawn(async move {
                    let _slot = slot;
                    serve_admin(stream, state, uid).await;
                });
            }
        }
    }
    state.lock();
    Ok(())
}

pub(crate) async fn serve_admin<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    state: Arc<StateEngine>,
    configured_uid: u32,
) {
    let request = tokio::time::timeout(
        Duration::from_secs(30),
        read_frame::<_, AdminEnvelope>(&mut stream),
    )
    .await;
    let response = match request {
        Ok(Ok(envelope)) => admin_request(&state, envelope.request, configured_uid),
        _ => ErrorCode::ProtocolError.admin_response(),
    };
    let _ =
        tokio::time::timeout(Duration::from_secs(30), write_frame(&mut stream, &response)).await;
}

fn admin_request(
    state: &Arc<StateEngine>,
    request: AdminRequest,
    configured_uid: u32,
) -> AdminResponse {
    let result = match request {
        AdminRequest::Unlock {
            ttl_seconds,
            credentials,
            harness_uid,
        } => {
            if harness_uid.is_some_and(|uid| uid != configured_uid) {
                return ErrorCode::PermissionDenied.admin_response();
            }
            state
                .unlock(
                    Duration::from_secs(ttl_seconds),
                    credentials,
                    Some(configured_uid),
                )
                .map(|_| ())
        }
        AdminRequest::Lock => {
            state.lock();
            Ok(())
        }
        AdminRequest::ListPending => {
            return match state.list_pending() {
                Ok(items) => AdminResponse::PendingList(items),
                Err(error) => admin_error(error),
            }
        }
        AdminRequest::Status => {
            let status = state.status();
            return AdminResponse::Status {
                unlocked: status.unlocked,
                remaining_ttl_seconds: status.remaining_ttl.map(|ttl| ttl.as_secs()),
                pending_approvals: status.pending_approvals,
                approved_targets: status.approved_targets,
            };
        }
        AdminRequest::ApproveTarget {
            target,
            port,
            pinned_ip,
            host_key_fingerprint,
            attempt_budget,
        } => state.approve_target(
            target,
            port,
            pinned_ip,
            host_key_fingerprint,
            attempt_budget,
        ),
        AdminRequest::DenyTarget { target, port } => state.deny_target(target, port),
        AdminRequest::AddBudget {
            target,
            port,
            additional_attempts,
        } => state.add_budget(target, port, additional_attempts),
        AdminRequest::ResumeDiscovery {
            target,
            port,
            additional_attempts,
        } => state.resume_discovery(target, port, additional_attempts),
    };
    match result {
        Ok(()) => AdminResponse::Ok,
        Err(error) => admin_error(error),
    }
}

fn admin_error(error: CoreError) -> AdminResponse {
    classify(&error).admin_response()
}

pub(crate) async fn serve_execution<S>(
    mut stream: S,
    state: Arc<StateEngine>,
    uid: u32,
    operations: Arc<Semaphore>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + platform::DisconnectMonitor,
{
    let request = tokio::time::timeout(
        Duration::from_secs(10),
        read_frame::<_, ExecRequest>(&mut stream),
    )
    .await;
    let request = match request {
        Ok(Ok(request @ ExecRequest::Connect { .. })) => request,
        _ => {
            send_error(&mut stream, ErrorCode::ProtocolError).await;
            return;
        }
    };
    let Ok(_operation) = operations.try_acquire_owned() else {
        send_error(&mut stream, ErrorCode::ResourceLimit).await;
        return;
    };
    let token = match state.grant_token(uid) {
        Ok(token) => token,
        Err(error) => {
            send_error(&mut stream, classify(&error)).await;
            return;
        }
    };
    let Ok(disconnect) = stream.disconnect_monitor() else {
        send_error(&mut stream, ErrorCode::LocalIo).await;
        return;
    };
    let (reader, mut writer) = tokio::io::split(stream);
    let (responses, mut outgoing) = tokio::sync::mpsc::channel::<broker_proto::ExecResponse>(8);
    // This task alone owns framing. Revocation cancels SSH work, never a partial
    // frame followed by another frame on the same byte stream.
    let mut output = tokio::spawn(async move {
        while let Some(response) = outgoing.recv().await {
            write_frame(&mut writer, &response).await?;
        }
        Ok::<(), broker_proto::ProtoError>(())
    });
    let result = tokio::select! {
        biased;
        _ = token.cancelled() => {
            let code = token.cancellation_reason().and_then(|reason| ErrorCode::from_code(reason.code())).unwrap_or(ErrorCode::BrokerLock);
            Err(transport::Failure(code))
        },
        _ = &mut output => return,
        outcome = transport::execute(&state, &token, request, reader, &responses, disconnect) => outcome,
    };
    let failed = result.is_err();
    if let Err(error) = result {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            responses.send(error.0.exec_response()),
        )
        .await;
    }
    drop(responses);
    if !failed {
        tokio::select! {
            _ = &mut output => return,
            _ = token.cancelled() => {}
        }
    }
    if tokio::time::timeout(Duration::from_secs(5), &mut output)
        .await
        .is_err()
    {
        output.abort();
        let _ = output.await;
    }
}

async fn send_error<S: AsyncWrite + Unpin>(stream: &mut S, code: ErrorCode) {
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        write_frame(stream, &code.exec_response()),
    )
    .await;
}

pub fn classify(error: &CoreError) -> ErrorCode {
    ErrorCode::from_code(error.code()).unwrap_or(ErrorCode::InternalError)
}
