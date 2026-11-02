use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};

pub fn harden() -> Result<u32, &'static str> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return Err("the daemon must run as a dedicated unprivileged service account");
    }
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err("could not disable core dumps");
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err("could not disable process dumping");
    }
    unsafe { libc::umask(0o077) };
    Ok(uid)
}

pub fn secure_runtime(path: &Path, uid: u32) -> Result<PathBuf, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "runtime directory is missing")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(
            "runtime directory must be owned by the service account and cannot be a symlink",
        );
    }
    if metadata.mode() & 0o777 != 0o751 {
        return Err("runtime directory permissions must be 0751");
    }
    let canonical = fs::canonicalize(path).map_err(|_| "runtime directory cannot be resolved")?;
    for parent in canonical.ancestors().skip(1) {
        let m = fs::metadata(parent).map_err(|_| "cannot inspect runtime parent")?;
        if (m.uid() != 0 && m.uid() != uid) || m.mode() & 0o022 != 0 {
            return Err("runtime ancestors must be administrator or service owned and not writable by others");
        }
    }
    Ok(canonical)
}

pub fn listener(path: &Path, uid: u32, gid: u32) -> Result<UnixListener, &'static str> {
    match fs::symlink_metadata(path) {
        Ok(m) => {
            if !m.file_type().is_socket() || m.uid() != uid {
                return Err("existing socket path is not a service-owned socket");
            }
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err("another broker is already listening");
            }
            fs::remove_file(path).map_err(|_| "cannot remove stale service socket")?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("cannot inspect service socket"),
    }
    let listener = UnixListener::bind(path).map_err(|_| "cannot bind service socket")?;
    use std::os::unix::ffi::OsStrExt;
    let name =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| "invalid socket path")?;
    if unsafe { libc::chown(name.as_ptr(), uid, gid) } != 0 {
        let _ = fs::remove_file(path);
        return Err("cannot assign socket group; service must belong to both socket groups");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
        .map_err(|_| "cannot protect service socket")?;
    Ok(listener)
}

pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    stream.peer_cred().map(|peer| peer.uid())
}

pub struct SocketCleanup(pub PathBuf, pub PathBuf);
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(&self.1);
    }
}
