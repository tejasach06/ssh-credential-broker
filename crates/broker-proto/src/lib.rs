use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{self, Write};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_SIZE: usize = 64 * 1024;
pub const MAX_TARGET_LEN: usize = 1024;
pub const MAX_COMMAND_LEN: usize = 64 * 1024;
pub const MAX_STREAM_DATA: usize = 4096;
pub const MAX_CREDENTIALS: usize = 64;
pub const MAX_USERNAME_LEN: usize = 1024;
pub const MAX_PASSWORD_LEN: usize = 4096;
pub const MAX_PENDING_DESTINATIONS: usize = 32;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("frame exceeds limit")]
    FrameTooLarge(usize),
    #[error("IPC transport failure")]
    Io(#[from] io::Error),
    #[error("malformed protocol frame")]
    Json,
    #[error("invalid protocol field")]
    InvalidField,
    #[error("truncated protocol frame")]
    Truncated,
    #[error("protocol version mismatch")]
    VersionMismatch { client: u32, server: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InputError,
    BrokerLocked,
    ApprovalRequired,
    AuthenticationRejected,
    BudgetExhausted,
    HostKeyMismatch,
    TransportFailure,
    BrokerLock,
    BrokerExpired,
    RenewalRequired,
    ResourceLimit,
    PermissionDenied,
    Unsupported,
    ProtocolError,
    AlreadyUnlocked,
    NotFound,
    Cancelled,
    MissingRemoteStatus,
    RemoteSignal,
    LocalIo,
    InternalError,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputError => "INPUT_ERROR",
            Self::BrokerLocked => "BROKER_LOCKED",
            Self::ApprovalRequired => "APPROVAL_REQUIRED",
            Self::AuthenticationRejected => "AUTHENTICATION_REJECTED",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
            Self::HostKeyMismatch => "HOST_KEY_MISMATCH",
            Self::TransportFailure => "TRANSPORT_FAILURE",
            Self::BrokerLock => "BROKER_LOCK",
            Self::BrokerExpired => "BROKER_EXPIRED",
            Self::RenewalRequired => "RENEWAL_REQUIRED",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Unsupported => "UNSUPPORTED",
            Self::ProtocolError => "PROTOCOL_ERROR",
            Self::AlreadyUnlocked => "ALREADY_UNLOCKED",
            Self::NotFound => "NOT_FOUND",
            Self::Cancelled => "CANCELLED",
            Self::MissingRemoteStatus => "MISSING_REMOTE_STATUS",
            Self::RemoteSignal => "REMOTE_SIGNAL",
            Self::LocalIo => "LOCAL_IO",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::InputError => "invalid input",
            Self::BrokerLocked => "broker is locked",
            Self::ApprovalRequired => "operator destination approval required",
            Self::AuthenticationRejected => "password authentication rejected",
            Self::BudgetExhausted => "authentication attempt budget exhausted",
            Self::HostKeyMismatch => "server identity changed",
            Self::TransportFailure => "transport failure",
            Self::BrokerLock => "operator locked the broker",
            Self::BrokerExpired => "broker grant expired",
            Self::RenewalRequired => "operator discovery renewal required",
            Self::ResourceLimit => "resource limit reached",
            Self::PermissionDenied => "permission denied",
            Self::Unsupported => "operation is unsupported",
            Self::ProtocolError => "invalid broker protocol",
            Self::AlreadyUnlocked => "broker is already unlocked",
            Self::NotFound => "destination not found",
            Self::Cancelled => "request cancelled",
            Self::MissingRemoteStatus => "remote status was not received",
            Self::RemoteSignal => "remote process terminated by signal",
            Self::LocalIo => "local input or output failed",
            Self::InternalError => "broker internal failure",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::InputError,
            Self::BrokerLocked,
            Self::ApprovalRequired,
            Self::AuthenticationRejected,
            Self::BudgetExhausted,
            Self::HostKeyMismatch,
            Self::TransportFailure,
            Self::BrokerLock,
            Self::BrokerExpired,
            Self::RenewalRequired,
            Self::ResourceLimit,
            Self::PermissionDenied,
            Self::Unsupported,
            Self::ProtocolError,
            Self::AlreadyUnlocked,
            Self::NotFound,
            Self::Cancelled,
            Self::MissingRemoteStatus,
            Self::RemoteSignal,
            Self::LocalIo,
            Self::InternalError,
        ]
        .into_iter()
        .find(|value| value.as_str() == code)
    }

    pub fn exec_response(self) -> ExecResponse {
        ExecResponse::Error {
            code: self.as_str().into(),
            message: self.message().into(),
        }
    }

    pub fn admin_response(self) -> AdminResponse {
        AdminResponse::Error {
            code: self.as_str().into(),
            message: self.message().into(),
        }
    }
}

#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Protect already-decoded fields if a later field is missing, duplicated,
        // malformed, or unknown. Ordinary String fields would not erase on failure.
        struct SecretInput(Zeroizing<String>);
        impl<'de> Deserialize<'de> for SecretInput {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
            }
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            username: SecretInput,
            password: SecretInput,
        }
        let mut fields = Fields::deserialize(deserializer)?;
        Ok(Self {
            username: std::mem::take(&mut *fields.username.0),
            password: std::mem::take(&mut *fields.password.0),
        })
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential([REDACTED])")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExecRequest {
    Connect {
        version: u32,
        target: String,
        port: Option<u16>,
        command: Option<String>,
        pty: Option<PtyRequest>,
    },
    StdinData(Vec<u8>),
    StdinEof,
    ResizePty {
        cols: u16,
        rows: u16,
    },
    Cancel,
}

impl std::fmt::Debug for ExecRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExecRequest([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PtyRequest {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExecResponse {
    ApprovalRequired {
        target: String,
        port: u16,
        host_key_fingerprint: String,
    },
    SessionReady,
    StdoutData(Vec<u8>),
    StderrData(Vec<u8>),
    ProcessExit {
        exit_status: Option<u32>,
        signal: Option<String>,
    },
    Error {
        code: String,
        message: String,
    },
}

impl std::fmt::Debug for ExecResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExecResponse([REDACTED])")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AdminRequest {
    Unlock {
        ttl_seconds: u64,
        credentials: Vec<Credential>,
        harness_uid: Option<u32>,
    },
    Lock,
    ListPending,
    ApproveTarget {
        target: String,
        port: u16,
        pinned_ip: String,
        host_key_fingerprint: String,
        attempt_budget: u32,
    },
    DenyTarget {
        target: String,
        port: u16,
    },
    AddBudget {
        target: String,
        port: u16,
        additional_attempts: u32,
    },
    ResumeDiscovery {
        target: String,
        port: u16,
        additional_attempts: u32,
    },
    Status,
}

impl std::fmt::Debug for AdminRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminRequest([REDACTED])")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminEnvelope {
    pub version: u32,
    pub request: AdminRequest,
}

impl std::fmt::Debug for AdminEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminEnvelope([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDestination {
    pub target: String,
    pub port: u16,
    pub resolved_ip: String,
    pub host_key_fingerprint: String,
    pub host_key_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AdminResponse {
    Ok,
    Status {
        unlocked: bool,
        remaining_ttl_seconds: Option<u64>,
        pending_approvals: usize,
        approved_targets: usize,
    },
    PendingList(Vec<PendingDestination>),
    Error {
        code: String,
        message: String,
    },
}

pub trait WireMessage: Serialize + DeserializeOwned {
    fn validate(&self) -> Result<(), ProtoError>;
}

fn require(valid: bool) -> Result<(), ProtoError> {
    if valid {
        Ok(())
    } else {
        Err(ProtoError::InvalidField)
    }
}

pub fn validate_target(target: &str) -> Result<(), ProtoError> {
    require(!target.is_empty() && target.len() <= MAX_TARGET_LEN && !target.contains('\0'))?;
    if target.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    require(
        target.is_ascii()
            && target.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
    )
}

fn fingerprint(value: &str) -> Result<(), ProtoError> {
    require(
        value.starts_with("SHA256:")
            && (8..=128).contains(&value.len())
            && value[7..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)),
    )
}

fn endpoint(target: &str, port: u16) -> Result<(), ProtoError> {
    validate_target(target)?;
    require(port != 0)
}

fn version(value: u32) -> Result<(), ProtoError> {
    if value == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtoError::VersionMismatch {
            client: value,
            server: PROTOCOL_VERSION,
        })
    }
}

impl WireMessage for ExecRequest {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::Connect {
                version: v,
                target,
                port,
                command,
                pty,
            } => {
                version(*v)?;
                endpoint(target, port.unwrap_or(22))?;
                if let Some(command) = command {
                    require(
                        command.len() <= MAX_COMMAND_LEN
                            && !command.contains('\0')
                            && pty.is_none(),
                    )?;
                }
                if let Some(pty) = pty {
                    require(
                        pty.cols > 0
                            && pty.rows > 0
                            && !pty.term.is_empty()
                            && pty.term.len() <= 128
                            && pty
                                .term
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b)),
                    )?;
                }
                Ok(())
            }
            Self::StdinData(data) => require(data.len() <= MAX_STREAM_DATA),
            Self::ResizePty { cols, rows } => require(*cols > 0 && *rows > 0),
            Self::StdinEof | Self::Cancel => Ok(()),
        }
    }
}

pub fn validate_credentials(credentials: &[Credential]) -> Result<(), ProtoError> {
    require(!credentials.is_empty() && credentials.len() <= MAX_CREDENTIALS)?;
    for (index, credential) in credentials.iter().enumerate() {
        require(
            !credential.username.is_empty()
                && credential.username.len() <= MAX_USERNAME_LEN
                && !credential.password.is_empty()
                && credential.password.len() <= MAX_PASSWORD_LEN
                && !credential.username.contains('\0')
                && !credential.password.contains('\0'),
        )?;
        require(!credentials[..index].iter().any(|prior| {
            prior.username == credential.username && prior.password == credential.password
        }))?;
    }
    Ok(())
}

impl WireMessage for AdminEnvelope {
    fn validate(&self) -> Result<(), ProtoError> {
        version(self.version)?;
        match &self.request {
            AdminRequest::Unlock {
                ttl_seconds,
                credentials,
                harness_uid,
            } => {
                require((60..=28800).contains(ttl_seconds) && harness_uid.is_some())?;
                validate_credentials(credentials)
            }
            AdminRequest::ApproveTarget {
                target,
                port,
                pinned_ip,
                host_key_fingerprint,
                attempt_budget,
            } => {
                endpoint(target, *port)?;
                require(pinned_ip.parse::<std::net::IpAddr>().is_ok() && *attempt_budget > 0)?;
                fingerprint(host_key_fingerprint)
            }
            AdminRequest::DenyTarget { target, port } => endpoint(target, *port),
            AdminRequest::AddBudget {
                target,
                port,
                additional_attempts,
            }
            | AdminRequest::ResumeDiscovery {
                target,
                port,
                additional_attempts,
            } => {
                endpoint(target, *port)?;
                require(*additional_attempts > 0)
            }
            AdminRequest::Lock | AdminRequest::ListPending | AdminRequest::Status => Ok(()),
        }
    }
}

impl WireMessage for Vec<Credential> {
    fn validate(&self) -> Result<(), ProtoError> {
        validate_credentials(self)
    }
}

fn classified_error(code: &str, message: &str) -> Result<(), ProtoError> {
    require(ErrorCode::from_code(code).is_some_and(|value| value.message() == message))
}

impl WireMessage for ExecResponse {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::ApprovalRequired {
                target,
                port,
                host_key_fingerprint,
            } => {
                endpoint(target, *port)?;
                fingerprint(host_key_fingerprint)
            }
            Self::StdoutData(data) | Self::StderrData(data) => {
                require(data.len() <= MAX_STREAM_DATA)
            }
            Self::ProcessExit {
                exit_status,
                signal,
            } => {
                require(!(exit_status.is_some() && signal.is_some()))?;
                if let Some(signal) = signal {
                    require(
                        !signal.is_empty()
                            && signal.len() <= 64
                            && signal
                                .bytes()
                                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'),
                    )?;
                }
                Ok(())
            }
            Self::Error { code, message } => classified_error(code, message),
            Self::SessionReady => Ok(()),
        }
    }
}

impl WireMessage for AdminResponse {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::PendingList(pending) => {
                require(pending.len() <= MAX_PENDING_DESTINATIONS)?;
                for item in pending {
                    endpoint(&item.target, item.port)?;
                    require(
                        item.resolved_ip.parse::<std::net::IpAddr>().is_ok()
                            && !item.host_key_type.is_empty()
                            && item.host_key_type.len() <= 128
                            && item
                                .host_key_type
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-@._".contains(&b)),
                    )?;
                    fingerprint(&item.host_key_fingerprint)?;
                }
                Ok(())
            }
            Self::Error { code, message } => classified_error(code, message),
            Self::Status {
                remaining_ttl_seconds,
                ..
            } => require(remaining_ttl_seconds.is_none_or(|seconds| seconds <= 28800)),
            Self::Ok => Ok(()),
        }
    }
}

struct BoundedBuffer(Zeroizing<Vec<u8>>);

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_FRAME_SIZE.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes one bounded frame. The private serialization buffer is erased on every exit,
/// including cancellation. The caller must close the transport if this future is cancelled.
pub async fn write_frame<W: AsyncWrite + Unpin, T: WireMessage>(
    writer: &mut W,
    item: &T,
) -> Result<(), ProtoError> {
    item.validate()?;
    let mut data = BoundedBuffer(Zeroizing::new(Vec::with_capacity(MAX_FRAME_SIZE)));
    serde_json::to_writer(&mut data, item).map_err(|error| {
        if error.is_io() {
            ProtoError::FrameTooLarge(MAX_FRAME_SIZE + 1)
        } else {
            ProtoError::Json
        }
    })?;
    let length =
        u32::try_from(data.0.len()).map_err(|_| ProtoError::FrameTooLarge(data.0.len()))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&data.0).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads exactly one frame, rejecting length before allocation and erasing the input
/// on parse failure, validation failure, success, and cancellation. Do not restart a
/// cancelled read on the same transport: framing may already have been consumed.
pub async fn read_frame<R: AsyncRead + Unpin, T: WireMessage>(
    reader: &mut R,
) -> Result<T, ProtoError> {
    let mut header = [0; 4];
    reader.read_exact(&mut header).await.map_err(read_error)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| ProtoError::FrameTooLarge(usize::MAX))?;
    if length > MAX_FRAME_SIZE {
        return Err(ProtoError::FrameTooLarge(length));
    }
    if length == 0 {
        return Err(ProtoError::Json);
    }
    let mut data = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut data).await.map_err(read_error)?;
    let item: T = serde_json::from_slice(&data).map_err(|_| ProtoError::Json)?;
    item.validate()?;
    Ok(item)
}

fn read_error(error: io::Error) -> ProtoError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        ProtoError::Truncated
    } else {
        ProtoError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malicious_length_is_rejected_without_body() {
        let input = u32::MAX.to_be_bytes();
        let error = read_frame::<_, ExecRequest>(&mut input.as_slice())
            .await
            .err()
            .unwrap();
        assert!(matches!(error, ProtoError::FrameTooLarge(_)));
    }

    #[tokio::test]
    async fn truncated_and_wrong_message_frames_are_rejected() {
        for input in [
            &[0, 0, 0][..],
            &[0, 0, 0, 20, b'{'][..],
            &[0, 0, 0, 4, b'n', b'u', b'l', b'l'][..],
        ] {
            assert!(read_frame::<_, ExecRequest>(&mut &*input).await.is_err());
        }
    }

    #[tokio::test]
    async fn binary_stream_and_eof_preserve_all_bytes() {
        let bytes: Vec<u8> = (0..=255).cycle().take(MAX_STREAM_DATA).collect();
        let mut wire = Vec::new();
        write_frame(&mut wire, &ExecResponse::StdoutData(bytes.clone()))
            .await
            .unwrap();
        write_frame(&mut wire, &ExecResponse::StderrData(vec![0, 255, 128]))
            .await
            .unwrap();
        write_frame(
            &mut wire,
            &ExecResponse::ProcessExit {
                exit_status: Some(37),
                signal: None,
            },
        )
        .await
        .unwrap();
        let mut input = wire.as_slice();
        match read_frame::<_, ExecResponse>(&mut input).await.unwrap() {
            ExecResponse::StdoutData(actual) => assert_eq!(actual, bytes),
            _ => panic!("wrong stream"),
        }
        match read_frame::<_, ExecResponse>(&mut input).await.unwrap() {
            ExecResponse::StderrData(actual) => assert_eq!(actual, vec![0, 255, 128]),
            _ => panic!("wrong stream"),
        }
        assert!(matches!(
            read_frame::<_, ExecResponse>(&mut input).await.unwrap(),
            ExecResponse::ProcessExit {
                exit_status: Some(37),
                signal: None
            }
        ));
        assert!(input.is_empty());
    }

    #[tokio::test]
    async fn unclassified_error_payload_cannot_cross_boundary() {
        let mut wire = Vec::new();
        let result = write_frame(
            &mut wire,
            &ExecResponse::Error {
                code: "TRANSPORT_FAILURE".into(),
                message: "synthetic secret server banner".into(),
            },
        )
        .await;
        assert!(result.is_err());
        assert!(wire.is_empty());
    }

    #[tokio::test]
    async fn oversized_serialized_admin_request_is_bounded() {
        let credentials = (0..32)
            .map(|index| Credential {
                username: format!("test-{index}"),
                password: "x".repeat(MAX_PASSWORD_LEN),
            })
            .collect();
        let request = AdminEnvelope {
            version: PROTOCOL_VERSION,
            request: AdminRequest::Unlock {
                ttl_seconds: 60,
                credentials,
                harness_uid: Some(1000),
            },
        };
        let mut output = Vec::new();
        assert!(matches!(
            write_frame(&mut output, &request).await,
            Err(ProtoError::FrameTooLarge(_))
        ));
        assert!(output.is_empty());
    }
}
