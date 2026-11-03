use broker_proto::ErrorCode;
use std::fs::File;
use std::io::{self, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub exit: u8,
    pub error: Option<ErrorCode>,
    pub remote_status: Option<u32>,
    pub signal: Option<String>,
}

impl Outcome {
    pub fn failure(error: ErrorCode) -> Self {
        Self {
            exit: 125,
            error: Some(error),
            remote_status: None,
            signal: None,
        }
    }
}

pub fn report(outcome: &Outcome, descriptor: Option<&mut File>) -> io::Result<()> {
    let value = if let Some(error) = outcome.error {
        serde_json::json!({
            "outcome": "client_error",
            "code": error.as_str(),
            "message": error.message()
        })
    } else if let Some(signal) = &outcome.signal {
        serde_json::json!({
            "outcome": "remote_signal",
            "code": "REMOTE_SIGNAL",
            "signal": signal
        })
    } else {
        serde_json::json!({
            "outcome": "remote_exit",
            "exit_status": outcome.remote_status
        })
    };
    if let Some(file) = descriptor {
        writeln!(file, "{value}")?;
    } else if outcome.error.is_some() || outcome.signal.is_some() {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        writeln!(stderr, "{value}")?;
    }
    Ok(())
}

pub fn remote_signal(signal: &str) -> (&'static str, u8) {
    let raw = signal.strip_prefix("SIG").unwrap_or(signal);
    match raw {
        "HUP" => ("HUP", 1),
        "INT" => ("INT", 2),
        "QUIT" => ("QUIT", 3),
        "ILL" => ("ILL", 4),
        "TRAP" => ("TRAP", 5),
        "ABRT" => ("ABRT", 6),
        "BUS" => ("BUS", 7),
        "FPE" => ("FPE", 8),
        "KILL" => ("KILL", 9),
        "USR1" => ("USR1", 10),
        "SEGV" => ("SEGV", 11),
        "USR2" => ("USR2", 12),
        "PIPE" => ("PIPE", 13),
        "ALRM" => ("ALRM", 14),
        "TERM" => ("TERM", 15),
        _ => ("UNKNOWN", 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_signals_match_posix() {
        assert_eq!(remote_signal("SIGINT"), ("INT", 2));
        assert_eq!(remote_signal("TERM"), ("TERM", 15));
        assert_eq!(remote_signal("unknown"), ("UNKNOWN", 0));
    }
}
