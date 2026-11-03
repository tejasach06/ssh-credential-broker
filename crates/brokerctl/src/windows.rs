use crate::common::{report, write_response};
use crate::windows_input;
use broker_proto::{
    read_frame, write_frame, AdminEnvelope, AdminRequest, AdminResponse, ErrorCode, WireMessage,
    PROTOCOL_VERSION,
};
use clap::{Parser, Subcommand};
use std::time::Duration;

#[derive(Parser)]
#[command(
    version,
    about = "Trusted operator administration for the SSH credential broker"
)]
struct Args {
    /// Connect to a custom operator administration named pipe
    #[arg(long, global = true)]
    admin_pipe: Option<String>,
    /// Connect to the default standalone operator administration pipe
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
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64), conflicts_with = "private_json_stdin")]
        credential_count: u32,
        /// Read length-framed credential JSON from a private inherited pipe owned by this user.
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
    let result = async {
        let mut interrupt = tokio::signal::windows::ctrl_c().map_err(|_| ErrorCode::LocalIo)?;
        let mut quit = tokio::signal::windows::ctrl_break().map_err(|_| ErrorCode::LocalIo)?;
        tokio::select! {
            result = execute(args) => result,
            _ = interrupt.recv() => Err(ErrorCode::Cancelled),
            _ = quit.recv() => Err(ErrorCode::Cancelled),
        }
    }
    .await;
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
            credential_count,
            private_json_stdin,
        } => {
            let credentials = if private_json_stdin {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    windows_input::credentials(credential_count, true),
                )
                .await
                .map_err(|_| ErrorCode::InputError)??
            } else {
                windows_input::credentials(credential_count, false).await?
            };
            AdminRequest::Unlock {
                ttl_seconds,
                credentials,
                harness_uid: None,
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
    let response: AdminResponse = tokio::time::timeout(Duration::from_secs(30), async {
        let pipe_name = if let Some(pipe) = &args.admin_pipe {
            pipe.as_str()
        } else if args.standalone {
            broker_windows::STANDALONE_ADMIN_PIPE
        } else {
            broker_windows::ADMIN_PIPE
        };
        let mut pipe = broker_windows::connect(pipe_name)
            .await
            .map_err(|_| ErrorCode::TransportFailure)?;
        write_frame(&mut pipe, &envelope)
            .await
            .map_err(|_| ErrorCode::ProtocolError)?;
        drop(envelope);
        read_frame(&mut pipe)
            .await
            .map_err(|_| ErrorCode::ProtocolError)
    })
    .await
    .map_err(|_| ErrorCode::TransportFailure)??;
    write_response(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_does_not_require_a_unix_uid() {
        assert!(Args::try_parse_from(["brokerctl", "unlock"]).is_ok());
        assert!(Args::try_parse_from(["brokerctl", "unlock", "--private-json-stdin"]).is_ok());
        assert!(Args::try_parse_from(["brokerctl", "unlock", "--harness-uid", "1"]).is_err());
    }

    #[test]
    fn unlock_preserves_ttl_and_credential_count_bounds() {
        assert!(Args::try_parse_from(["brokerctl", "unlock", "--ttl-seconds", "59"]).is_err());
        assert!(Args::try_parse_from(["brokerctl", "unlock", "--credential-count", "65"]).is_err());
        assert!(Args::try_parse_from([
            "brokerctl",
            "unlock",
            "--credential-count",
            "2",
            "--private-json-stdin"
        ])
        .is_err());
    }
    #[test]
    fn args_supports_standalone_and_admin_pipe() {
        assert!(Args::try_parse_from(["brokerctl", "--standalone", "status"]).is_ok());
        assert!(Args::try_parse_from([
            "brokerctl",
            "--admin-pipe",
            r"\\.\pipe\custom-admin",
            "status"
        ])
        .is_ok());
    }
}
