#[path = "unix_io.rs"]
mod unix_io;

use crate::outcome::{remote_signal, report, Outcome};
use broker_proto::{
    read_frame, write_frame, ErrorCode, ExecRequest, ExecResponse, PtyRequest, WireMessage,
    MAX_STREAM_DATA, PROTOCOL_VERSION,
};
use clap::Parser;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::{unix::OwnedWriteHalf, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use unix_io::{terminal_size, LocalIo, Terminal};

#[derive(Parser)]
#[command(version, about = "Execute through the isolated SSH credential broker")]
struct Args {
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long)]
    standalone: bool,
    target: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// A single remote shell command, following --; omit for an interactive shell.
    #[arg(last = true)]
    command: Option<String>,
    /// Write structured outcomes to an already-open descriptor, separate from SSH output.
    #[arg(long, value_parser = clap::value_parser!(i32).range(3..))]
    outcome_fd: Option<i32>,
}

fn default_socket(standalone: bool) -> PathBuf {
    if standalone {
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime).join("ssh-credential-broker/exec.sock")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/state/ssh-credential-broker/exec.sock")
        } else {
            let uid = unsafe { libc::geteuid() };
            PathBuf::from(format!("/tmp/ssh-credential-broker-{uid}/exec.sock"))
        }
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/private/var/db/ssh-credential-broker/run/exec.sock")
    } else {
        PathBuf::from("/run/ssh-credential-broker/exec.sock")
    }
}

fn outcome_file(descriptor: Option<i32>) -> io::Result<Option<File>> {
    let Some(fd) = descriptor else {
        return Ok(None);
    };
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(duplicated) };
    let flags = unsafe { libc::fcntl(duplicated, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE == libc::O_RDONLY {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(Some(file))
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
    let mut descriptor = match outcome_file(args.outcome_fd) {
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

async fn send(writer: &mut OwnedWriteHalf, request: &ExecRequest) -> Result<(), ErrorCode> {
    write_frame(writer, request)
        .await
        .map_err(|_| ErrorCode::TransportFailure)
}

async fn execute(args: &Args) -> Result<Outcome, ErrorCode> {
    let interactive = args.command.is_none();
    let pty = if interactive {
        let (cols, rows) = terminal_size().map_err(|_| ErrorCode::LocalIo)?;
        Some(PtyRequest {
            term: "xterm-256color".into(),
            cols,
            rows,
        })
    } else {
        None
    };
    let request = ExecRequest::Connect {
        version: PROTOCOL_VERSION,
        target: args.target.clone(),
        port: Some(args.port),
        command: args.command.clone(),
        pty,
    };
    request.validate().map_err(|_| ErrorCode::InputError)?;
    let default_path;
    let socket_path = if let Some(path) = args.socket.as_deref() {
        path
    } else {
        default_path = default_socket(args.standalone);
        &default_path
    };
    let stream = tokio::time::timeout(Duration::from_secs(30), UnixStream::connect(socket_path))
        .await
        .map_err(|_| ErrorCode::TransportFailure)?
        .map_err(|_| ErrorCode::TransportFailure)?;
    let (mut reader, mut writer) = stream.into_split();
    tokio::time::timeout(Duration::from_secs(30), send(&mut writer, &request))
        .await
        .map_err(|_| ErrorCode::TransportFailure)??;
    let mut interrupts = signal(SignalKind::interrupt()).map_err(|_| ErrorCode::LocalIo)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| ErrorCode::LocalIo)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(|_| ErrorCode::LocalIo)?;
    let mut quit = signal(SignalKind::quit()).map_err(|_| ErrorCode::LocalIo)?;
    let mut resize = signal(SignalKind::window_change()).map_err(|_| ErrorCode::LocalIo)?;
    let session = async {
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
        let input = LocalIo::new(libc::STDIN_FILENO).map_err(|_| ErrorCode::LocalIo)?;
        let output = LocalIo::new(libc::STDOUT_FILENO).map_err(|_| ErrorCode::LocalIo)?;
        let errors = LocalIo::new(libc::STDERR_FILENO).map_err(|_| ErrorCode::LocalIo)?;
        let _terminal = if interactive {
            Some(Terminal::raw(libc::STDIN_FILENO).map_err(|_| ErrorCode::LocalIo)?)
        } else {
            None
        };

        // Each direction owns its in-progress I/O until completion. A blocked
        // stdin frame must not prevent draining output (or the reverse).
        let input_stream = async {
            let mut eof = false;
            let mut buffer = [0; MAX_STREAM_DATA];
            loop {
                tokio::select! {
                    count = input.read(&mut buffer), if !eof => {
                        let count = match count {
                            Ok(count) => count,
                            Err(_) => return Err::<(), ErrorCode>(ErrorCode::LocalIo),
                        };
                        if count == 0 {
                            send(&mut writer, &ExecRequest::StdinEof).await?;
                            eof = true;
                        } else {
                            send(&mut writer, &ExecRequest::StdinData(buffer[..count].to_vec())).await?;
                        }
                    }
                    _ = resize.recv(), if interactive => {
                        let (cols, rows) = terminal_size().map_err(|_| ErrorCode::LocalIo)?;
                        send(&mut writer, &ExecRequest::ResizePty { cols, rows }).await?;
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
                    ExecResponse::StdoutData(data) => output
                        .write_all(&data)
                        .await
                        .map_err(|_| ErrorCode::LocalIo)?,
                    ExecResponse::StderrData(data) => errors
                        .write_all(&data)
                        .await
                        .map_err(|_| ErrorCode::LocalIo)?,
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
                        });
                    }
                    ExecResponse::ProcessExit {
                        exit_status: None,
                        signal: Some(signal),
                    } => {
                        let (_, number) = remote_signal(&signal);
                        return Ok(Outcome {
                            exit: 128u8.saturating_add(number),
                            error: None,
                            remote_status: None,
                            signal: Some(signal),
                        });
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
            result = input_stream => {
                result?;
                Err(ErrorCode::TransportFailure)
            }
        }
    };
    let result = if interactive {
        // In interactive mode, terminal is in raw mode and Ctrl-C/INT travels
        // through stdin to the remote PTY as \x03 byte. Local process termination signals (TERM/HUP)
        // still cancel the session.
        tokio::select! {
            result = session => result,
            _ = terminate.recv() => Err(ErrorCode::Cancelled),
            _ = hangup.recv() => Err(ErrorCode::Cancelled),
        }
    } else {
        tokio::select! {
            result = session => result,
            _ = interrupts.recv() => Err(ErrorCode::Cancelled),
            _ = terminate.recv() => Err(ErrorCode::Cancelled),
            _ = hangup.recv() => Err(ErrorCode::Cancelled),
            _ = quit.recv() => Err(ErrorCode::Cancelled),
        }
    };
    result
}
