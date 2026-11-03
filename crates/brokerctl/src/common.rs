use broker_proto::{AdminResponse, ErrorCode};
use std::io::Write;

pub fn report(error: ErrorCode) {
    let value = serde_json::json!({
        "outcome": "client_error",
        "code": error.as_str(),
        "message": error.message()
    });
    let _ = writeln!(std::io::stderr(), "{value}");
}

pub fn write_response(response: &AdminResponse) -> Result<(), ErrorCode> {
    if let AdminResponse::Error { code, .. } = response {
        return Err(ErrorCode::from_code(code).unwrap_or(ErrorCode::ProtocolError));
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, response).map_err(|_| ErrorCode::LocalIo)?;
    output.write_all(b"\n").map_err(|_| ErrorCode::LocalIo)
}
