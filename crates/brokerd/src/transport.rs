use crate::daemon::classify;
use broker_core::{ApprovedTarget, CoreError, GrantToken, StateEngine};
use broker_proto::{
    read_frame, write_frame, ErrorCode, ExecRequest, ExecResponse, PendingDestination,
    MAX_STREAM_DATA,
};
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::{client, Channel, ChannelMsg};
use std::future::{poll_fn, Future};
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, watch};

pub struct Failure(pub ErrorCode);
impl From<CoreError> for Failure {
    fn from(error: CoreError) -> Self {
        Self(classify(&error))
    }
}
fn network(_: impl std::fmt::Debug) -> Failure {
    Failure(ErrorCode::TransportFailure)
}

struct SocketGuard(std::net::TcpStream);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}
struct Connection {
    handle: client::Handle<Handler>,
    _socket: SocketGuard,
}

#[derive(Debug, Clone)]
struct ObservedKey {
    fingerprint: String,
    algorithm: String,
}
struct Handler {
    observed: Arc<Mutex<Option<ObservedKey>>>,
    approval: Option<(Arc<StateEngine>, GrantToken, ApprovedTarget)>,
}

impl client::Handler for Handler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let public = key.public_key();
        let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
        if let Ok(mut observed) = self.observed.lock() {
            *observed = Some(ObservedKey {
                fingerprint: fingerprint.clone(),
                algorithm: public.algorithm().to_string(),
            });
        }
        Ok(self
            .approval
            .as_ref()
            .is_some_and(|(state, token, target)| {
                state.verify_host_key(token, target, &fingerprint).is_ok()
            }))
    }
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: client::ChannelOpenHandle,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        reply: client::ChannelOpenHandle,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
    async fn server_channel_open_agent_forward(
        &mut self,
        _: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
    async fn server_channel_open_session(
        &mut self,
        _: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
    async fn server_channel_open_direct_tcpip(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: client::ChannelOpenHandle,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        reply: client::ChannelOpenHandle,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
    async fn server_channel_open_x11(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        _: u32,
        reply: client::ChannelOpenHandle,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        drop(reply);
        Ok(())
    }
}

async fn connect(address: SocketAddr, handler: Handler) -> Result<Connection, Failure> {
    let tcp = tokio::net::TcpStream::connect(address)
        .await
        .map_err(network)?;
    let native = tcp.into_std().map_err(network)?;
    let socket = SocketGuard(native.try_clone().map_err(network)?);
    let tcp = tokio::net::TcpStream::from_std(native).map_err(network)?;
    let config = client::Config {
        channel_buffer_size: 8,
        window_size: 64 * 1024,
        maximum_packet_size: 32 * 1024,
        ..Default::default()
    };
    let handle = client::connect_stream(Arc::new(config), tcp, handler)
        .await
        .map_err(network)?;
    Ok(Connection {
        handle,
        _socket: socket,
    })
}

async fn bounded<F: Future>(future: F) -> Result<F::Output, Failure> {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .map_err(|_| Failure(ErrorCode::TransportFailure))
}

async fn guarded<F: Future>(
    state: &StateEngine,
    token: &GrantToken,
    future: F,
) -> Result<F::Output, Failure> {
    let mut future = Box::pin(future);
    poll_fn(
        |cx| match state.with_active_grant(token, || future.as_mut().poll(cx)) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error.into())),
        },
    )
    .await
}

struct InputTask(tokio::task::JoinHandle<()>);
impl Drop for InputTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn execute(
    state: &Arc<StateEngine>,
    token: &GrantToken,
    request: ExecRequest,
    reader: OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Failure> {
    let (tx, mut input) = mpsc::channel(8);
    let (disconnected, mut disconnect_rx) = watch::channel(false);
    let _input_task = InputTask(tokio::spawn(async move {
        let mut reader = reader;
        loop {
            match read_frame::<_, ExecRequest>(&mut reader).await {
                Ok(ExecRequest::Cancel) | Err(_) => {
                    let _ = disconnected.send(true);
                    break;
                }
                Ok(ExecRequest::Connect { .. }) => {
                    let _ = disconnected.send(true);
                    break;
                }
                Ok(message) => {
                    if tx.send(message).await.is_err() {
                        break;
                    }
                }
            }
        }
    }));
    tokio::select! {
        biased;
        _ = disconnect_rx.changed() => Err(Failure(ErrorCode::Cancelled)),
        result = execute_connected(state, token, request, &mut input, writer) => result,
    }
}

async fn execute_connected(
    state: &Arc<StateEngine>,
    token: &GrantToken,
    request: ExecRequest,
    input: &mut mpsc::Receiver<ExecRequest>,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Failure> {
    let ExecRequest::Connect {
        target,
        port,
        command,
        pty,
        ..
    } = request
    else {
        return Err(Failure(ErrorCode::ProtocolError));
    };
    let port = port.unwrap_or(22);
    let target = target.as_str();
    let approved = match state.resolve_pinned_target(token, target, port) {
        Ok(approved) => approved,
        Err(CoreError::ApprovalRequired { .. }) => {
            let mut addresses = bounded(tokio::net::lookup_host((target, port)))
                .await?
                .map_err(network)?;
            let address = addresses
                .next()
                .ok_or(Failure(ErrorCode::TransportFailure))?;
            let observed = Arc::new(Mutex::new(None));
            let handler = Handler {
                observed: observed.clone(),
                approval: None,
            };
            // The probe deliberately rejects the key before any SSH user authentication.
            let _ = bounded(connect(address, handler)).await?;
            let key = observed
                .lock()
                .map_err(network)?
                .clone()
                .ok_or(Failure(ErrorCode::TransportFailure))?;
            state.register_pending(
                token,
                PendingDestination {
                    target: target.into(),
                    port,
                    resolved_ip: address.ip().to_string(),
                    host_key_fingerprint: key.fingerprint.clone(),
                    host_key_type: key.algorithm,
                },
            )?;
            write_frame(
                writer,
                &ExecResponse::ApprovalRequired {
                    target: target.into(),
                    port,
                    host_key_fingerprint: key.fingerprint,
                },
            )
            .await
            .map_err(network)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let guard = state.acquire_identity(token, &approved).await?;
    loop {
        let mut attempt = state.reserve_attempt(&guard)?;
        let observed = Arc::new(Mutex::new(None));
        let handler = Handler {
            observed: observed.clone(),
            approval: Some((state.clone(), token.clone(), approved.clone())),
        };
        let address = SocketAddr::new(approved.pinned_ip.parse::<IpAddr>().map_err(network)?, port);
        let result = bounded(connect(address, handler)).await?;
        let mut connection = match result {
            Ok(connection) => connection,
            Err(error) => {
                let key = observed.lock().map_err(network)?.clone();
                if let Some(key) = key {
                    state.verify_host_key(token, &approved, &key.fingerprint)?;
                }
                return Err(error);
            }
        };
        let authentication = attempt.commit_credentials(|credential| {
            connection
                .handle
                .authenticate_password(credential.username.clone(), credential.password.clone())
        })?;
        let result = bounded(guarded(state, token, authentication))
            .await??
            .map_err(network)?;
        if result.success() {
            let authenticated = attempt.record_auth_success()?;
            drop(attempt);
            let (channel_future, lease) = state
                .commit_session(&authenticated, || connection.handle.channel_open_session())?;
            let mut channel = bounded(guarded(state, token, channel_future))
                .await??
                .map_err(network)?;
            drop(guard);
            let _lease = lease;
            if let Some(pty) = &pty {
                bounded(channel.request_pty(
                    true,
                    &pty.term,
                    u32::from(pty.cols),
                    u32::from(pty.rows),
                    0,
                    0,
                    &[],
                ))
                .await?
                .map_err(network)?;
                channel_reply(&mut channel).await?;
            }
            match &command {
                Some(command) => {
                    bounded(channel.exec(true, command.as_bytes()))
                        .await?
                        .map_err(network)?;
                }
                None => {
                    bounded(channel.request_shell(true))
                        .await?
                        .map_err(network)?;
                }
            }
            channel_reply(&mut channel).await?;
            write_frame(writer, &ExecResponse::SessionReady)
                .await
                .map_err(network)?;
            pump(channel, input, writer, pty.is_some()).await?;
            let _ = bounded(
                connection
                    .handle
                    .disconnect(russh::Disconnect::ByApplication, "", ""),
            )
            .await;
            return Ok(());
        }
        if let client::AuthResult::Failure {
            remaining_methods,
            partial_success,
        } = result
        {
            if partial_success || !remaining_methods.contains(&russh::MethodKind::Password) {
                return Err(Failure(ErrorCode::Unsupported));
            }
        }
        attempt.record_auth_rejection()?;
        // A fresh transport is required for the next credential.
        drop(connection);
    }
}

async fn channel_reply(channel: &mut Channel<client::Msg>) -> Result<(), Failure> {
    bounded(async {
        match channel.wait().await {
            Some(ChannelMsg::Success) => Ok(()),
            _ => Err(Failure(ErrorCode::TransportFailure)),
        }
    })
    .await?
}

async fn pump(
    channel: Channel<client::Msg>,
    input: &mut mpsc::Receiver<ExecRequest>,
    writer: &mut OwnedWriteHalf,
    terminal: bool,
) -> Result<(), Failure> {
    let (mut output, input_channel) = channel.split();
    let send_input = async {
        let mut eof = false;
        loop {
            match input.recv().await {
                Some(ExecRequest::StdinData(data)) if !eof => input_channel
                    .data_bytes(bytes::Bytes::from(data))
                    .await
                    .map_err(network)?,
                Some(ExecRequest::StdinEof) if !eof => {
                    input_channel.eof().await.map_err(network)?;
                    eof = true;
                }
                Some(ExecRequest::ResizePty { cols, rows }) if terminal => input_channel
                    .window_change(u32::from(cols), u32::from(rows), 0, 0)
                    .await
                    .map_err(network)?,
                _ => return Err::<(), Failure>(Failure(ErrorCode::ProtocolError)),
            }
        }
    };
    let receive_output = async {
        let mut exit_status = None;
        let mut signal = None;
        while let Some(message) = output.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    for bytes in data.chunks(MAX_STREAM_DATA) {
                        write_frame(writer, &ExecResponse::StdoutData(bytes.to_vec()))
                            .await
                            .map_err(network)?;
                    }
                }
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    for bytes in data.chunks(MAX_STREAM_DATA) {
                        write_frame(writer, &ExecResponse::StderrData(bytes.to_vec()))
                            .await
                            .map_err(network)?;
                    }
                }
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => exit_status = Some(status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    signal = Some(format!("{signal_name:?}"))
                }
                _ => {}
            }
        }
        if exit_status.is_none() && signal.is_none() {
            return Err(Failure(ErrorCode::MissingRemoteStatus));
        }
        write_frame(
            writer,
            &ExecResponse::ProcessExit {
                exit_status,
                signal,
            },
        )
        .await
        .map_err(network)?;
        Ok(())
    };
    tokio::select! {
        result = send_input => result,
        result = receive_output => result,
    }
}
