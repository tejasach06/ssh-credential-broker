mod daemon;
#[cfg(unix)]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;
mod transport;

#[cfg(unix)]
#[tokio::main]
async fn main() {
    if let Err(message) = daemon::run().await {
        eprintln!("ssh-brokerd: {message}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn main() {
    if let Err(message) = platform::run_service() {
        eprintln!("ssh-brokerd: {message}");
        std::process::exit(1);
    }
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("ssh-brokerd: unsupported platform");
    std::process::exit(1);
}
