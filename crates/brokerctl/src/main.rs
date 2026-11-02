#[cfg(unix)]
mod unix;

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(unix::run().await)
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("{{\"code\":\"UNSUPPORTED\",\"message\":\"operation is unsupported\"}}");
    std::process::ExitCode::from(125)
}
