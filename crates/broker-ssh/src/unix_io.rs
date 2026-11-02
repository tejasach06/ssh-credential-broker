use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use tokio::io::unix::AsyncFd;

pub struct Terminal {
    fd: RawFd,
    original: libc::termios,
}

impl Terminal {
    pub fn raw(fd: RawFd) -> io::Result<Self> {
        let mut original = std::mem::MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

pub fn terminal_size() -> io::Result<(u16, u16)> {
    let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, size.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let size = unsafe { size.assume_init() };
    Ok((size.ws_col.max(1), size.ws_row.max(1)))
}

enum Descriptor {
    Ready(AsyncFd<OwnedFd>),
    Regular(OwnedFd),
}

pub struct LocalIo {
    descriptor: Descriptor,
    flags: libc::c_int,
}

impl LocalIo {
    pub fn new(fd: RawFd) -> io::Result<Self> {
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(duplicated) };
        let flags = unsafe { libc::fcntl(duplicated, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(duplicated, stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        let mode = stat.st_mode & libc::S_IFMT;
        // Only /dev/null is safe for synchronous character-device I/O.
        let null_device = mode == libc::S_IFCHR
            && std::fs::metadata("/dev/null")
                .is_ok_and(|metadata| metadata.rdev() == stat.st_rdev as u64);
        let regular = mode == libc::S_IFREG || null_device;
        if regular {
            return Ok(Self {
                descriptor: Descriptor::Regular(owned),
                flags,
            });
        }
        if unsafe { libc::fcntl(duplicated, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        match AsyncFd::new(owned) {
            Ok(ready) => Ok(Self {
                descriptor: Descriptor::Ready(ready),
                flags,
            }),
            Err(error) => {
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
                Err(error)
            }
        }
    }

    fn fd(&self) -> RawFd {
        match &self.descriptor {
            Descriptor::Ready(ready) => ready.get_ref().as_raw_fd(),
            Descriptor::Regular(fd) => fd.as_raw_fd(),
        }
    }

    pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut call = || {
                let count =
                    unsafe { libc::read(self.fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            };
            let result = match &self.descriptor {
                Descriptor::Ready(ready) => {
                    let mut guard = ready.readable().await?;
                    match guard.try_io(|_| call()) {
                        Ok(result) => result,
                        Err(_) => continue,
                    }
                }
                Descriptor::Regular(_) => call(),
            };
            match result {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }

    pub async fn write_all(&self, mut buffer: &[u8]) -> io::Result<()> {
        while !buffer.is_empty() {
            let call = || {
                let count = unsafe { libc::write(self.fd(), buffer.as_ptr().cast(), buffer.len()) };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            };
            let result = match &self.descriptor {
                Descriptor::Ready(ready) => {
                    let mut guard = ready.writable().await?;
                    match guard.try_io(|_| call()) {
                        Ok(result) => result,
                        Err(_) => continue,
                    }
                }
                Descriptor::Regular(_) => call(),
            };
            match result {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "output closed")),
                Ok(count) => buffer = &buffer[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl Drop for LocalIo {
    fn drop(&mut self) {
        unsafe { libc::fcntl(self.fd(), libc::F_SETFL, self.flags) };
    }
}
