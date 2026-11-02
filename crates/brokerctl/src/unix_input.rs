use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{unix::AsyncFd, AsyncRead, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

struct EchoGuard<'a> {
    file: &'a File,
    original: libc::termios,
}

impl<'a> EchoGuard<'a> {
    fn hide(file: &'a File) -> io::Result<Self> {
        let mut original = std::mem::MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(file.as_raw_fd(), original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON);
        hidden.c_cc[libc::VMIN] = 1;
        hidden.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(file.as_raw_fd(), libc::TCSAFLUSH, &hidden) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file, original })
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &self.original) };
        let mut file = self.file;
        let _ = file.write_all(b"\n");
    }
}

pub struct Prompt(AsyncFd<File>);

impl Prompt {
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/tty")?;
        // SAFETY: File owns a fixed descriptor for the entire registration.
        Ok(Self(unsafe { AsyncFd::register(file) }?))
    }

    pub fn label(&self, ordinal: u32) -> io::Result<()> {
        let mut file = self.0.get_ref();
        writeln!(file, "Credential {ordinal}")
    }

    pub async fn read_secret(&self, label: &[u8], limit: usize) -> io::Result<Zeroizing<String>> {
        let _guard = EchoGuard::hide(self.0.get_ref())?;
        let mut file = self.0.get_ref();
        file.write_all(label)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
        loop {
            let mut byte = Zeroizing::new([0u8]);
            let mut guard = self.0.readable().await?;
            let count = match guard.try_io(|fd| {
                let mut file = fd.get_ref();
                file.read(&mut *byte)
            }) {
                Ok(result) => match result {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                },
                Err(_) => continue,
            };
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            match byte[0] {
                b'\n' | b'\r' => break,
                0 | 4 => return Err(io::ErrorKind::InvalidInput.into()),
                8 | 127 => {
                    while let Some(last) = bytes.pop() {
                        if last & 0xc0 != 0x80 {
                            break;
                        }
                    }
                }
                21 => bytes.zeroize(),
                value => {
                    if bytes.len() == limit {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    bytes.push(value);
                }
            }
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(Zeroizing::new(text.to_owned()))
    }
}

enum InputKind {
    Regular(File),
    Ready(AsyncFd<File>),
}

pub struct PrivateInput {
    input: InputKind,
    flags: libc::c_int,
}

pub fn private_input() -> io::Result<PrivateInput> {
    let duplicated = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(duplicated) };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    let kind = stat.st_mode & libc::S_IFMT;
    let anonymous_pipe = kind == libc::S_IFIFO && unsafe { libc::isatty(duplicated) } == 0;
    if !anonymous_pipe {
        if stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & 0o077 != 0
            || (kind != libc::S_IFREG && kind != libc::S_IFSOCK)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if kind == libc::S_IFREG {
        return Ok(PrivateInput {
            input: InputKind::Regular(file),
            flags,
        });
    }
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: File owns a fixed descriptor for the entire registration.
    match unsafe { AsyncFd::register(file) } {
        Ok(file) => Ok(PrivateInput {
            input: InputKind::Ready(file),
            flags,
        }),
        Err(error) => {
            unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, flags) };
            Err(error.into())
        }
    }
}

impl AsyncRead for PrivateInput {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let result = match &self.input {
                InputKind::Regular(file) => (&*file).read(buffer.initialize_unfilled()),
                InputKind::Ready(file) => {
                    let mut guard = std::task::ready!(file.poll_read_ready(context))?;
                    match guard.try_io(|file| {
                        let mut file = file.get_ref();
                        file.read(buffer.initialize_unfilled())
                    }) {
                        Ok(result) => result,
                        Err(_) => continue,
                    }
                }
            };
            return match result {
                Ok(count) => {
                    buffer.advance(count);
                    Poll::Ready(Ok(()))
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => Poll::Ready(Err(error)),
            };
        }
    }
}

impl Drop for PrivateInput {
    fn drop(&mut self) {
        let fd = match &self.input {
            InputKind::Regular(file) => file.as_raw_fd(),
            InputKind::Ready(file) => file.get_ref().as_raw_fd(),
        };
        unsafe { libc::fcntl(fd, libc::F_SETFL, self.flags) };
    }
}
