use broker_proto::{Credential, ErrorCode, MAX_FRAME_SIZE, MAX_PASSWORD_LEN, MAX_USERNAME_LEN};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use std::time::Duration;
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, GetHandleInformation, LocalFree, DUPLICATE_SAME_ACCESS, HANDLE,
        HANDLE_FLAG_INHERIT,
    },
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, GetAce, GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
        OWNER_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
    System::{
        Console::{
            GetConsoleMode, GetStdHandle, ReadConsoleW, SetConsoleMode, ENABLE_ECHO_INPUT,
            ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, STD_INPUT_HANDLE,
        },
        Pipes::{
            GetNamedPipeClientProcessId, GetNamedPipeInfo, GetNamedPipeServerProcessId,
            PIPE_SERVER_END,
        },
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
        IO::CancelSynchronousIo,
    },
};
use zeroize::Zeroizing;

struct Worker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // Cancellation can race the next synchronous read. Repeat until the
            // worker has actually exited; its buffers and echo guard stay alive.
            while !thread.is_finished() {
                unsafe { CancelSynchronousIo(thread.as_raw_handle()) };
                std::thread::sleep(Duration::from_millis(1));
            }
            let _ = thread.join();
        }
    }
}

pub async fn credentials(count: u32, private: bool) -> Result<Vec<Credential>, ErrorCode> {
    let input = if private {
        Some(private_input().map_err(|_| ErrorCode::PermissionDenied)?)
    } else {
        None
    };
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("broker-credential-input".into())
        .spawn(move || {
            let result = match input {
                Some(file) => read_private(file, &worker_stop),
                None => prompt(count, &worker_stop),
            };
            let _ = sender.send(result);
        })
        .map_err(|_| ErrorCode::LocalIo)?;
    let _worker = Worker {
        stop,
        thread: Some(thread),
    };
    receiver
        .await
        .map_err(|_| ErrorCode::LocalIo)?
        .map_err(|error| {
            if error.raw_os_error() == Some(995) || error.kind() == io::ErrorKind::Interrupted {
                ErrorCode::Cancelled
            } else {
                ErrorCode::InputError
            }
        })
}

fn check_stop(stop: &AtomicBool) -> io::Result<()> {
    if stop.load(Ordering::Acquire) {
        Err(io::ErrorKind::Interrupted.into())
    } else {
        Ok(())
    }
}

fn read_private(mut file: File, stop: &AtomicBool) -> io::Result<Vec<Credential>> {
    check_stop(stop)?;
    let mut size = [0; 4];
    file.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME_SIZE {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    check_stop(stop)?;
    file.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| io::ErrorKind::InvalidInput.into())
}

struct EchoGuard<'a> {
    file: &'a File,
    mode: u32,
}

impl<'a> EchoGuard<'a> {
    fn hide(file: &'a File) -> io::Result<Self> {
        let mut mode = 0;
        if unsafe { GetConsoleMode(file.as_raw_handle(), &mut mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let hidden = (mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)) | ENABLE_PROCESSED_INPUT;
        if unsafe { SetConsoleMode(file.as_raw_handle(), hidden) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file, mode })
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        unsafe { SetConsoleMode(self.file.as_raw_handle(), self.mode) };
    }
}

fn secret(
    input: &File,
    output: &mut File,
    label: &[u8],
    limit: usize,
    stop: &AtomicBool,
) -> io::Result<Zeroizing<String>> {
    check_stop(stop)?;
    output.write_all(label)?;
    let mut units = Zeroizing::new(Vec::<u16>::with_capacity(limit));
    loop {
        check_stop(stop)?;
        let mut unit = Zeroizing::new([0u16; 1]);
        let mut read = 0;
        if unsafe {
            ReadConsoleW(
                input.as_raw_handle(),
                unit.as_mut_ptr().cast(),
                1,
                &mut read,
                std::ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        match unit[0] {
            13 | 10 => break,
            0 | 4 => return Err(io::ErrorKind::InvalidInput.into()),
            8 | 127 => {
                if let Some(last) = units.pop() {
                    if (0xdc00..=0xdfff).contains(&last) {
                        units.pop();
                    }
                }
            }
            21 => {
                use zeroize::Zeroize;
                units.zeroize();
            }
            value => {
                if units.len() >= limit {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                units.push(value);
            }
        }
    }
    output.write_all(b"\r\n")?;
    let value =
        Zeroizing::new(String::from_utf16(&units).map_err(|_| io::ErrorKind::InvalidInput)?);
    if value.len() > limit {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(value)
}

fn prompt(count: u32, stop: &AtomicBool) -> io::Result<Vec<Credential>> {
    let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
    let mut output = OpenOptions::new().write(true).open("CONOUT$")?;
    let _echo = EchoGuard::hide(&input)?;
    let mut credentials = Vec::with_capacity(count as usize);
    for index in 1..=count {
        check_stop(stop)?;
        writeln!(output, "Credential {index}")?;
        let mut username = secret(
            &input,
            &mut output,
            b"Username (hidden): ",
            MAX_USERNAME_LEN,
            stop,
        )?;
        let mut password = secret(
            &input,
            &mut output,
            b"Password (hidden): ",
            MAX_PASSWORD_LEN,
            stop,
        )?;
        credentials.push(Credential {
            username: std::mem::take(&mut *username),
            password: std::mem::take(&mut *password),
        });
    }
    Ok(credentials)
}

fn token_user(process: HANDLE) -> io::Result<Vec<usize>> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut length,
        )
    };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            bytes.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}

fn user_sid(token: &[usize]) -> PSID {
    // TOKEN_USER and its SID remain inside the aligned, immovable token buffer.
    unsafe { (*(token.as_ptr().cast::<TOKEN_USER>())).User.Sid }
}

struct SecurityDescriptor(*mut std::ffi::c_void);
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn private_input() -> io::Result<File> {
    let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut flags = 0;
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE
        || unsafe { GetHandleInformation(handle, &mut flags) } == 0
        || flags & HANDLE_FLAG_INHERIT == 0
    {
        return Err(denied());
    }
    let me = token_user(unsafe { GetCurrentProcess() })?;
    let sid = user_sid(&me);
    let mut owner = std::ptr::null_mut();
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let error = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let _descriptor = SecurityDescriptor(descriptor);
    if owner.is_null() || acl.is_null() || unsafe { EqualSid(owner, sid) } == 0 {
        return Err(denied());
    }
    let mut user_allowed = false;
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 {
            return Err(denied());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match header.AceType {
            0 => {
                let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let principal = (&allowed.SidStart as *const u32).cast_mut().cast();
                let own = unsafe { EqualSid(principal, sid) } != 0;
                if !own && unsafe { IsWellKnownSid(principal, WinLocalSystemSid) } == 0 {
                    return Err(denied());
                }
                user_allowed |= own;
            }
            1 => {} // A deny ACE cannot broaden access.
            _ => return Err(denied()),
        }
    }
    if !user_allowed {
        return Err(denied());
    }
    let mut mode = 0;
    if unsafe {
        GetNamedPipeInfo(
            handle,
            &mut mode,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(denied());
    }
    let mut pid = 0;
    let success = unsafe {
        if mode & PIPE_SERVER_END != 0 {
            GetNamedPipeClientProcessId(handle, &mut pid)
        } else {
            GetNamedPipeServerProcessId(handle, &mut pid)
        }
    };
    if success == 0 || pid == 0 {
        return Err(denied());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(denied());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let producer = token_user(process.as_raw_handle())?;
    if unsafe { EqualSid(sid, user_sid(&producer)) } == 0 {
        return Err(denied());
    }
    let mut duplicate = std::ptr::null_mut();
    let current = unsafe { GetCurrentProcess() };
    if unsafe {
        DuplicateHandle(
            current,
            handle,
            current,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(duplicate) })
}
