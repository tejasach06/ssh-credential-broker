#[cfg(unix)]
mod daemon;
#[cfg(unix)]
mod platform;
#[cfg(unix)]
mod transport;

#[cfg(unix)]
#[tokio::main]
async fn main() {
    if let Err(message) = daemon::run().await {
        eprintln!("ssh-brokerd: {message}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ssh-brokerd requires Linux or macOS; Windows service isolation is not supported");
    std::process::exit(1);
}
