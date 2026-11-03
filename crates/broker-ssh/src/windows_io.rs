use broker_proto::MAX_STREAM_DATA;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, GetHandleInformation, DUPLICATE_SAME_ACCESS, HANDLE, HANDLE_FLAG_INHERIT,
    },
    Storage::FileSystem::{
        GetFileType, FILE_APPEND_DATA, FILE_TYPE_DISK, FILE_TYPE_PIPE, FILE_WRITE_DATA,
    },
    System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION,
    System::{Console::*, Threading::GetCurrentProcess, IO::CancelSynchronousIo},
};

pub fn duplicate(handle: HANDLE) -> io::Result<File> {
    let process = unsafe { GetCurrentProcess() };
    let mut owned = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            process,
            handle,
            process,
            &mut owned,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(owned) })
}

pub fn outcome_file(value: Option<usize>) -> io::Result<Option<File>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let handle = value as HANDLE;
    let mut flags = 0;
    if value == 0
        || value == usize::MAX
        || unsafe { GetHandleInformation(handle, &mut flags) } == 0
        || flags & HANDLE_FLAG_INHERIT == 0
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    // Outcomes must never alias the SSH stdout/stderr channels.
    for standard in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let other = unsafe { GetStdHandle(standard) };
        if handle == other
            || unsafe { windows_sys::Win32::Foundation::CompareObjectHandles(handle, other) } != 0
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    let kind = unsafe { GetFileType(handle) };
    if kind != FILE_TYPE_DISK && kind != FILE_TYPE_PIPE {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let status = unsafe {
        NtQueryObject(
            handle,
            ObjectBasicInformation,
            (&mut information as *mut PUBLIC_OBJECT_BASIC_INFORMATION).cast(),
            std::mem::size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    let writable = information.GrantedAccess & FILE_WRITE_DATA != 0
        || (kind == FILE_TYPE_DISK && information.GrantedAccess & FILE_APPEND_DATA != 0);
    if status < 0 || !writable {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    duplicate(handle).map(Some)
}

struct Worker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // Keep the handle and buffers alive until cancellation completes.
            // Retrying covers cancellation just before the worker enters ReadFile.
            while !thread.is_finished() {
                unsafe { CancelSynchronousIo(thread.as_raw_handle()) };
                std::thread::sleep(Duration::from_millis(1));
            }
            let _ = thread.join();
        }
    }
}

pub struct Input {
    receiver: Option<mpsc::Receiver<io::Result<Vec<u8>>>>,
    worker: Worker,
}
impl Input {
    pub fn stdin() -> io::Result<Self> {
        let mut file = duplicate(unsafe { GetStdHandle(STD_INPUT_HANDLE) })?;
        let (sender, receiver) = mpsc::channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("broker-stdin".into())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    let mut data = vec![0; MAX_STREAM_DATA];
                    let result = file.read(&mut data).map(|count| {
                        data.truncate(count);
                        data
                    });
                    let finished = result.as_ref().map_or(true, |data| data.is_empty());
                    if sender.blocking_send(result).is_err() || finished {
                        break;
                    }
                }
            })?;
        Ok(Self {
            receiver: Some(receiver),
            worker: Worker {
                stop,
                thread: Some(thread),
            },
        })
    }
    pub async fn read(&mut self) -> io::Result<Vec<u8>> {
        self.receiver
            .as_mut()
            .unwrap()
            .recv()
            .await
            .unwrap_or_else(|| Err(io::ErrorKind::UnexpectedEof.into()))
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        self.worker.stop.store(true, Ordering::Release);
        // Unblock blocking_send before Worker cancels a pending OS read and joins.
        self.receiver.take();
    }
}

struct WriteRequest {
    data: Vec<u8>,
    result: oneshot::Sender<io::Result<()>>,
}
pub struct Output {
    sender: Option<mpsc::Sender<WriteRequest>>,
    worker: Worker,
}
impl Output {
    pub fn new(standard: u32) -> io::Result<Self> {
        let mut file = duplicate(unsafe { GetStdHandle(standard) })?;
        let (sender, mut receiver) = mpsc::channel::<WriteRequest>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("broker-output".into())
            .spawn(move || {
                while let Some(request) = receiver.blocking_recv() {
                    if worker_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let result = file.write_all(&request.data);
                    let failed = result.is_err();
                    let _ = request.result.send(result);
                    if failed {
                        break;
                    }
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            worker: Worker {
                stop,
                thread: Some(thread),
            },
        })
    }
    pub async fn write(&self, data: Vec<u8>) -> io::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .unwrap()
            .send(WriteRequest {
                data,
                result: sender,
            })
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        receiver.await.map_err(|_| io::ErrorKind::BrokenPipe)?
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        self.worker.stop.store(true, Ordering::Release);
        self.sender.take();
    }
}

pub fn terminal_size() -> io::Result<(u16, u16)> {
    let mut info = std::mem::MaybeUninit::<CONSOLE_SCREEN_BUFFER_INFO>::uninit();
    if unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), info.as_mut_ptr()) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    let cols = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
    let rows = i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
    if cols <= 0 || rows <= 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let cols = u16::try_from(cols).map_err(|_| io::ErrorKind::InvalidData)?;
    let rows = u16::try_from(rows).map_err(|_| io::ErrorKind::InvalidData)?;
    Ok((cols, rows))
}

pub struct Terminal {
    modes: Vec<(File, u32)>,
    input_cp: u32,
    output_cp: u32,
}
impl Terminal {
    pub fn raw() -> io::Result<Self> {
        let mut terminal = Self {
            modes: Vec::new(),
            input_cp: unsafe { GetConsoleCP() },
            output_cp: unsafe { GetConsoleOutputCP() },
        };
        for standard in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let file = duplicate(unsafe { GetStdHandle(standard) })?;
            let mut mode = 0;
            if unsafe { GetConsoleMode(file.as_raw_handle(), &mut mode) } == 0 {
                if standard != STD_ERROR_HANDLE {
                    return Err(io::Error::last_os_error());
                }
                continue; // stderr may be separately redirected.
            }
            terminal.modes.push((file, mode));
        }
        for (index, (file, original)) in terminal.modes.iter().enumerate() {
            let mode = if index == 0 {
                (original
                    & !(ENABLE_LINE_INPUT
                        | ENABLE_ECHO_INPUT
                        | ENABLE_PROCESSED_INPUT
                        | ENABLE_QUICK_EDIT_MODE))
                    | ENABLE_EXTENDED_FLAGS
                    | ENABLE_VIRTUAL_TERMINAL_INPUT
            } else {
                original
                    | ENABLE_PROCESSED_OUTPUT
                    | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                    | DISABLE_NEWLINE_AUTO_RETURN
            };
            if unsafe { SetConsoleMode(file.as_raw_handle(), mode) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if unsafe { SetConsoleCP(65001) } == 0 || unsafe { SetConsoleOutputCP(65001) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(terminal)
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        for (index, (file, mode)) in self.modes.iter().enumerate().rev() {
            let mode = if index == 0 {
                *mode | ENABLE_EXTENDED_FLAGS
            } else {
                *mode
            };
            unsafe { SetConsoleMode(file.as_raw_handle(), mode) };
        }
        if self.input_cp != 0 {
            unsafe { SetConsoleCP(self.input_cp) };
        }
        if self.output_cp != 0 {
            unsafe { SetConsoleOutputCP(self.output_cp) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::SetHandleInformation;

    #[test]
    fn outcome_rejects_read_only_file_without_writing() {
        let path = std::env::temp_dir().join(format!(
            "broker-outcome-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"unchanged").unwrap();
        drop(file);
        let file = File::open(&path).unwrap();
        assert_ne!(
            unsafe {
                SetHandleInformation(
                    file.as_raw_handle(),
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                )
            },
            0
        );
        assert!(outcome_file(Some(file.as_raw_handle() as usize)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn outcome_rejects_non_io_process_handle() {
        let mut handle = std::ptr::null_mut();
        let process = unsafe { GetCurrentProcess() };
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    process,
                    process,
                    process,
                    &mut handle,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) };
        assert!(outcome_file(Some(handle.as_raw_handle() as usize)).is_err());
    }
}
