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
    if std::env::args().any(|arg| arg == "--standalone" || arg == "-s") {
        use clap::Parser;
        let options = match platform::StandaloneOptions::try_parse() {
            Ok(opts) => opts,
            Err(err) => {
                let _ = err.print();
                std::process::exit(1);
            }
        };
        if let Err(message) = platform::run_standalone(options) {
            eprintln!("ssh-brokerd: {message}");
            std::process::exit(1);
        }
    } else if let Err(message) = platform::run_service() {
        eprintln!("ssh-brokerd: {message}");
        std::process::exit(1);
    }
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("ssh-brokerd: unsupported platform");
    std::process::exit(1);
}
