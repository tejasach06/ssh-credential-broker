#[path = "unix_input.rs"]
mod unix_input;
use crate::common::{report, write_response};

use broker_proto::{
    read_frame, write_frame, AdminEnvelope, AdminRequest, AdminResponse, Credential, ErrorCode,
    WireMessage, MAX_CREDENTIALS, MAX_PASSWORD_LEN, MAX_USERNAME_LEN, PROTOCOL_VERSION,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::signal::unix::{signal, SignalKind};
use unix_input::{private_input, Prompt};

#[derive(Parser)]
#[command(
    version,
    about = "Trusted operator administration for the SSH credential broker"
)]
struct Args {
    #[arg(long, global = true)]
    admin_socket: Option<PathBuf>,
    #[arg(long, global = true)]
    standalone: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Unlock {
        #[arg(long, default_value_t = 1800, value_parser = clap::value_parser!(u64).range(60..=28800))]
        ttl_seconds: u64,
        #[arg(long)]
        harness_uid: u32,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64), conflicts_with = "private_json_stdin")]
        credential_count: u32,
        /// Read a 4-byte big-endian length followed by a JSON credential array from private stdin.
        #[arg(long)]
        private_json_stdin: bool,
    },
    Lock,
    Status,
    Pending,
    Approve {
        target: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long)]
        pinned_ip: String,
        /// Independently verify this fingerprint before approving.
        #[arg(long)]
        fingerprint: String,
        #[arg(long, default_value_t = 1)]
        attempt_budget: u32,
    },
    Deny {
        target: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
    },
    Budget {
        target: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long)]
        additional_attempts: u32,
    },
    Resume {
        target: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long)]
        additional_attempts: u32,
    },
}

fn default_socket(standalone: bool) -> PathBuf {
    if standalone {
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime).join("ssh-credential-broker/admin.sock")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/state/ssh-credential-broker/admin.sock")
        } else {
            let uid = unsafe { libc::geteuid() };
            PathBuf::from(format!("/tmp/ssh-credential-broker-{uid}/admin.sock"))
        }
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/private/var/db/ssh-credential-broker/run/admin.sock")
    } else {
        PathBuf::from("/run/ssh-credential-broker/admin.sock")
    }
}

pub async fn run() -> u8 {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return 0;
        }
        Err(_) => {
            report(ErrorCode::InputError);
            return 125;
        }
    };
    let mut interrupts = match signal(SignalKind::interrupt()) {
        Ok(value) => value,
        Err(_) => {
            report(ErrorCode::LocalIo);
            return 125;
        }
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(value) => value,
        Err(_) => {
            report(ErrorCode::LocalIo);
            return 125;
        }
    };
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(value) => value,
        Err(_) => {
            report(ErrorCode::LocalIo);
            return 125;
        }
    };
    let mut quit = match signal(SignalKind::quit()) {
        Ok(value) => value,
        Err(_) => {
            report(ErrorCode::LocalIo);
            return 125;
        }
    };
    let result = tokio::select! {
        result = execute(args) => result,
        _ = interrupts.recv() => Err(ErrorCode::Cancelled),
        _ = terminate.recv() => Err(ErrorCode::Cancelled),
        _ = hangup.recv() => Err(ErrorCode::Cancelled),
        _ = quit.recv() => Err(ErrorCode::Cancelled),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            report(error);
            125
        }
    }
}

async fn execute(args: Args) -> Result<(), ErrorCode> {
    let request = match args.command {
        Command::Unlock {
            ttl_seconds,
            harness_uid,
            credential_count,
            private_json_stdin,
        } => {
            let credentials: Vec<Credential> = if private_json_stdin {
                let mut input = private_input().map_err(|_| ErrorCode::PermissionDenied)?;
                tokio::time::timeout(Duration::from_secs(30), read_frame(&mut input))
                    .await
                    .map_err(|_| ErrorCode::InputError)?
                    .map_err(|_| ErrorCode::InputError)?
            } else {
                let prompt = Prompt::open().map_err(|_| ErrorCode::LocalIo)?;
                let mut entries =
                    Vec::with_capacity((credential_count as usize).min(MAX_CREDENTIALS));
                for index in 0..credential_count {
                    prompt.label(index + 1).map_err(|_| ErrorCode::LocalIo)?;
                    let mut username = prompt
                        .read_secret(b"Username (hidden): ", MAX_USERNAME_LEN)
                        .await
                        .map_err(|_| ErrorCode::InputError)?;
                    let mut password = prompt
                        .read_secret(b"Password (hidden): ", MAX_PASSWORD_LEN)
                        .await
                        .map_err(|_| ErrorCode::InputError)?;
                    let credential = Credential {
                        username: std::mem::take(&mut *username),
                        password: std::mem::take(&mut *password),
                    };
                    entries.push(credential);
                }
                entries
            };
            AdminRequest::Unlock {
                ttl_seconds,
                credentials,
                harness_uid: Some(harness_uid),
            }
        }
        Command::Lock => AdminRequest::Lock,
        Command::Status => AdminRequest::Status,
        Command::Pending => AdminRequest::ListPending,
        Command::Approve {
            target,
            port,
            pinned_ip,
            fingerprint,
            attempt_budget,
        } => AdminRequest::ApproveTarget {
            target,
            port,
            pinned_ip,
            host_key_fingerprint: fingerprint,
            attempt_budget,
        },
        Command::Deny { target, port } => AdminRequest::DenyTarget { target, port },
        Command::Budget {
            target,
            port,
            additional_attempts,
        } => AdminRequest::AddBudget {
            target,
            port,
            additional_attempts,
        },
        Command::Resume {
            target,
            port,
            additional_attempts,
        } => AdminRequest::ResumeDiscovery {
            target,
            port,
            additional_attempts,
        },
    };
    let envelope = AdminEnvelope {
        version: PROTOCOL_VERSION,
        request,
    };
    envelope.validate().map_err(|_| ErrorCode::InputError)?;
    let socket_path = args
        .admin_socket
        .unwrap_or_else(|| default_socket(args.standalone));
    let response: AdminResponse = tokio::time::timeout(Duration::from_secs(30), async {
        let mut socket = UnixStream::connect(&socket_path)
            .await
            .map_err(|_| ErrorCode::TransportFailure)?;
        write_frame(&mut socket, &envelope)
            .await
            .map_err(|_| ErrorCode::ProtocolError)?;
        // Do not retain the credential pool while waiting for an administration result.
        drop(envelope);
        read_frame(&mut socket)
            .await
            .map_err(|_| ErrorCode::ProtocolError)
    })
    .await
    .map_err(|_| ErrorCode::TransportFailure)??;
    write_response(&response)
}
