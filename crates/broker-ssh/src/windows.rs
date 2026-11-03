use crate::windows_io::{self, terminal_size, Input, Output, Terminal};
use broker_proto::{
    read_frame, write_frame, ErrorCode, ExecRequest, ExecResponse, PtyRequest, WireMessage,
    PROTOCOL_VERSION,
};
use clap::Parser;
use std::fs::File;
use std::io::{self, Write};
use std::time::Duration;
use tokio::io::AsyncWrite;
use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};

#[derive(Parser)]
#[command(version, about = "Execute through the isolated SSH credential broker")]
struct Args {
    /// Connect to a custom execution named pipe
    #[arg(long)]
    pipe: Option<String>,
    /// Connect to the default standalone execution named pipe
    #[arg(long)]
    standalone: bool,
    target: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// A single remote shell command, following --; omit for an interactive shell.
    #[arg(last = true)]
    command: Option<String>,
    /// Write structured outcomes to an inherited Windows HANDLE, separate from SSH output.
    #[arg(long)]
    outcome_handle: Option<usize>,
}

struct Outcome {
    exit: u8,
    error: Option<ErrorCode>,
    remote_status: Option<u32>,
    signal: Option<String>,
}
impl Outcome {
    fn failure(error: ErrorCode) -> Self {
        Self {
            exit: 125,
            error: Some(error),
            remote_status: None,
            signal: None,
        }
    }
}
fn report(outcome: &Outcome, descriptor: Option<&mut File>) -> io::Result<()> {
    let value = if let Some(error) = outcome.error {
        serde_json::json!({"outcome":"client_error", "code":error.as_str(), "message":error.message()})
    } else if let Some(signal) = &outcome.signal {
        serde_json::json!({"outcome":"remote_signal", "code":"REMOTE_SIGNAL", "signal":signal})
    } else {
        serde_json::json!({"outcome":"remote_exit", "exit_status":outcome.remote_status})
    };
    if let Some(file) = descriptor {
        writeln!(file, "{value}")?;
    } else if outcome.error.is_some() || outcome.signal.is_some() {
        writeln!(std::io::stderr(), "{value}")?;
    }
    Ok(())
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
            let _ = report(&Outcome::failure(ErrorCode::InputError), None);
            return 125;
        }
    };
    let mut descriptor = match windows_io::outcome_file(args.outcome_handle) {
        Ok(descriptor) => descriptor,
        Err(_) => {
            let _ = report(&Outcome::failure(ErrorCode::LocalIo), None);
            return 125;
        }
    };
    let outcome = execute(&args).await.unwrap_or_else(Outcome::failure);
    if report(&outcome, descriptor.as_mut()).is_err() {
        let _ = report(&Outcome::failure(ErrorCode::LocalIo), None);
        return 125;
    }
    outcome.exit
}

async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &ExecRequest,
) -> Result<(), ErrorCode> {
    write_frame(writer, request)
        .await
        .map_err(|_| ErrorCode::TransportFailure)
}

async fn execute(args: &Args) -> Result<Outcome, ErrorCode> {
    let interactive = args.command.is_none();
    let mut interrupts = tokio::signal::windows::ctrl_c().map_err(|_| ErrorCode::LocalIo)?;
    let mut breaks = tokio::signal::windows::ctrl_break().map_err(|_| ErrorCode::LocalIo)?;
    let mut closes = tokio::signal::windows::ctrl_close().map_err(|_| ErrorCode::LocalIo)?;
    let session = async {
        let mut size = if interactive {
            terminal_size().map_err(|_| ErrorCode::LocalIo)?
        } else {
            (0, 0)
        };
        let request = ExecRequest::Connect {
            version: PROTOCOL_VERSION,
            target: args.target.clone(),
            port: Some(args.port),
            command: args.command.clone(),
            pty: interactive.then(|| PtyRequest {
                term: "xterm-256color".into(),
                cols: size.0,
                rows: size.1,
            }),
        };
        request.validate().map_err(|_| ErrorCode::InputError)?;
        let pipe_name = if let Some(pipe) = &args.pipe {
            pipe.as_str()
        } else if args.standalone {
            broker_windows::STANDALONE_EXEC_PIPE
        } else {
            broker_windows::EXEC_PIPE
        };
        let pipe =
            tokio::time::timeout(Duration::from_secs(30), broker_windows::connect(pipe_name))
                .await
                .map_err(|_| ErrorCode::TransportFailure)?
                .map_err(|_| ErrorCode::TransportFailure)?;
        let (mut reader, mut writer) = tokio::io::split(pipe);
        tokio::time::timeout(Duration::from_secs(30), send(&mut writer, &request))
            .await
            .map_err(|_| ErrorCode::TransportFailure)??;
        match tokio::time::timeout(
            Duration::from_secs(30),
            read_frame::<_, ExecResponse>(&mut reader),
        )
        .await
        .map_err(|_| ErrorCode::TransportFailure)?
        .map_err(|_| ErrorCode::ProtocolError)?
        {
            ExecResponse::SessionReady => {}
            ExecResponse::ApprovalRequired { .. } => return Err(ErrorCode::ApprovalRequired),
            ExecResponse::Error { code, .. } => {
                return Err(ErrorCode::from_code(&code).unwrap_or(ErrorCode::ProtocolError))
            }
            _ => return Err(ErrorCode::ProtocolError),
        }
        // Declared first so all workers are canceled and joined before restoring
        // console modes/codepages. Raw mode turns Ctrl-C into the remote byte 03.
        let _terminal = if interactive {
            Some(Terminal::raw().map_err(|_| ErrorCode::LocalIo)?)
        } else {
            None
        };
        let mut input = Input::stdin().map_err(|_| ErrorCode::LocalIo)?;
        let output = Output::new(STD_OUTPUT_HANDLE).map_err(|_| ErrorCode::LocalIo)?;
        let errors = Output::new(STD_ERROR_HANDLE).map_err(|_| ErrorCode::LocalIo)?;
        let input_stream = async {
            let mut eof = false;
            let mut resize = tokio::time::interval(Duration::from_millis(100));
            resize.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    data = input.read(), if !eof => {
                        let data = match data {
                            Ok(data) => data,
                            Err(_) => return Err::<(), ErrorCode>(ErrorCode::LocalIo),
                        };
                        if data.is_empty() { send(&mut writer, &ExecRequest::StdinEof).await?; eof = true; }
                        else { send(&mut writer, &ExecRequest::StdinData(data)).await?; }
                    }
                    _ = resize.tick(), if interactive => {
                        let current = terminal_size().map_err(|_| ErrorCode::LocalIo)?;
                        if current != size {
                            size = current;
                            send(&mut writer, &ExecRequest::ResizePty { cols: size.0, rows: size.1 }).await?;
                        }
                    }
                    else => std::future::pending::<()>().await,
                }
            }
        };
        let output_stream = async {
            loop {
                match read_frame::<_, ExecResponse>(&mut reader)
                    .await
                    .map_err(|_| ErrorCode::ProtocolError)?
                {
                    ExecResponse::StdoutData(data) => {
                        output.write(data).await.map_err(|_| ErrorCode::LocalIo)?
                    }
                    ExecResponse::StderrData(data) => {
                        errors.write(data).await.map_err(|_| ErrorCode::LocalIo)?
                    }
                    ExecResponse::Error { code, .. } => {
                        return Err(ErrorCode::from_code(&code).unwrap_or(ErrorCode::ProtocolError))
                    }
                    ExecResponse::ProcessExit {
                        exit_status: Some(status),
                        signal: None,
                    } => {
                        return Ok(Outcome {
                            exit: (status & 255) as u8,
                            error: None,
                            remote_status: Some(status),
                            signal: None,
                        })
                    }
                    ExecResponse::ProcessExit {
                        exit_status: None,
                        signal: Some(signal),
                    } => {
                        return Ok(Outcome {
                            exit: 128u8.saturating_add(remote_signal(&signal)),
                            error: None,
                            remote_status: None,
                            signal: Some(signal),
                        })
                    }
                    ExecResponse::ProcessExit {
                        exit_status: None,
                        signal: None,
                    } => return Err(ErrorCode::MissingRemoteStatus),
                    _ => return Err(ErrorCode::ProtocolError),
                }
            }
        };
        tokio::select! {
            result = output_stream => result,
            result = input_stream => { result?; Err(ErrorCode::TransportFailure) }
        }
    };
    tokio::select! {
        result = session => result,
        _ = interrupts.recv(), if !interactive => Err(ErrorCode::Cancelled),
        _ = breaks.recv() => Err(ErrorCode::Cancelled),
        _ = closes.recv() => Err(ErrorCode::Cancelled),
    }
}

fn remote_signal(signal: &str) -> u8 {
    // These are remote POSIX signal numbers, never Windows process signals.
    match signal.strip_prefix("SIG").unwrap_or(signal) {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "ABRT" => 6,
        "FPE" => 8,
        "KILL" => 9,
        "SEGV" => 11,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "USR1" => 10,
        "USR2" => 12,
        "BUS" => 7,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_cli_accepts_outcome_handle_and_single_remote_command() {
        let args = Args::try_parse_from([
            "broker-ssh",
            "host.example",
            "--outcome-handle",
            "128",
            "--",
            "printf hello",
        ])
        .unwrap();
        assert_eq!(args.outcome_handle, Some(128));
        assert_eq!(args.command.as_deref(), Some("printf hello"));
    }
    #[test]
    fn remote_signals_use_posix_numbers() {
        assert_eq!(remote_signal("SIGINT"), 2);
        assert_eq!(remote_signal("TERM"), 15);
        assert_eq!(remote_signal("unknown"), 0);
    }
    #[test]
    fn native_cli_accepts_standalone_and_custom_pipe() {
        let args = Args::try_parse_from(["broker-ssh", "--standalone", "host.example"]).unwrap();
        assert!(args.standalone);
        let args = Args::try_parse_from([
            "broker-ssh",
            "--pipe",
            r"\\.\pipe\custom-exec",
            "host.example",
        ])
        .unwrap();
        assert_eq!(args.pipe.as_deref(), Some(r"\\.\pipe\custom-exec"));
    }
}
