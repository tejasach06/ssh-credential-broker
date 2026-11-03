#![cfg(windows)]

use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;

pub const SERVICE_NAME: &str = "ssh-brokerd";
pub const EXEC_PIPE: &str = r"\\.\pipe\ssh-credential-broker-exec";
pub const ADMIN_PIPE: &str = r"\\.\pipe\ssh-credential-broker-admin";
// Generic write includes FILE_CREATE_PIPE_INSTANCE. Clients must never receive it.
const CLIENT_ACCESS: u32 = 0x0012_019b;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
fn check(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    check(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
    let allocation = Local(text.cast());
    let mut len = 0;
    unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
    }
    let result =
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) }).map_err(|_| denied());
    drop(allocation);
    result
}

/// Parse and canonicalize before using SID text in an ACL.
pub fn canonical_sid(text: &str) -> io::Result<String> {
    if text.contains('\0') {
        return Err(denied());
    }
    let mut sid = null_mut();
    check(unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) })?;
    let allocation = Local(sid);
    let result = sid_string(sid);
    drop(allocation);
    result
}

pub fn service_sid() -> io::Result<String> {
    let name = wide(r"NT SERVICE\ssh-brokerd");
    let mut sid_len = 0;
    let mut domain_len = 0;
    let mut kind = 0;
    unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            null_mut(),
            &mut sid_len,
            null_mut(),
            &mut domain_len,
            &mut kind,
        );
    }
    if sid_len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0usize; (sid_len as usize).div_ceil(size_of::<usize>())];
    let mut domain = vec![0u16; domain_len as usize];
    check(unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    })?;
    sid_string(sid.as_mut_ptr().cast())
}

fn information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<usize>> {
    let mut len = 0;
    unsafe {
        GetTokenInformation(token, class, null_mut(), 0, &mut len);
    }
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut data = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
    check(unsafe { GetTokenInformation(token, class, data.as_mut_ptr().cast(), len, &mut len) })?;
    Ok(data)
}
fn token_user(token: HANDLE) -> io::Result<String> {
    let data = information(token, TokenUser)?;
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}
fn process_token(process: HANDLE, access: u32) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    check(unsafe { OpenProcessToken(process, access, &mut token) })?;
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

fn unprivileged(token: HANDLE, service: bool) -> io::Result<()> {
    let groups = information(token, TokenGroups)?;
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    for group in entries {
        let sid = sid_string(group.Sid)?;
        // Include deny-only administrator groups: a filtered administrator is not a harness.
        if matches!(
            sid.as_str(),
            "S-1-5-32-544"
                | "S-1-5-32-548"
                | "S-1-5-32-549"
                | "S-1-5-32-550"
                | "S-1-5-32-551"
                | "S-1-5-32-552"
        ) {
            return Err(denied());
        }
        if !service
            && sid.starts_with("S-1-16-")
            && sid
                .rsplit('-')
                .next()
                .and_then(|v| v.parse::<u32>().ok())
                .is_some_and(|v| v > 8192)
        {
            return Err(denied());
        }
    }
    let privileges = information(token, TokenPrivileges)?;
    let privileges = unsafe { &*privileges.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let entries = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    for privilege in entries {
        let mut len = 0;
        unsafe {
            LookupPrivilegeNameW(null(), &privilege.Luid, null_mut(), &mut len);
        }
        let mut name = vec![0u16; len as usize + 1];
        check(unsafe {
            LookupPrivilegeNameW(null(), &privilege.Luid, name.as_mut_ptr(), &mut len)
        })?;
        let name = String::from_utf16(&name[..len as usize]).map_err(|_| denied())?;
        // Reject dangerous privileges even when currently disabled: holders can enable them.
        if !matches!(
            name.as_str(),
            "SeChangeNotifyPrivilege"
                | "SeIncreaseWorkingSetPrivilege"
                | "SeTimeZonePrivilege"
                | "SeShutdownPrivilege"
                | "SeUndockPrivilege"
        ) {
            return Err(denied());
        }
    }
    Ok(())
}

fn descriptor(sddl: &str) -> io::Result<Local> {
    let mut sd = null_mut();
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            1,
            &mut sd,
            null_mut(),
        )
    })?;
    Ok(Local(sd))
}

/// Called before creating listeners or accepting a credential pool.
pub fn harden() -> io::Result<String> {
    let sid = service_sid()?;
    let token = process_token(unsafe { GetCurrentProcess() }, TOKEN_QUERY | WRITE_DAC)?;
    if token_user(token.as_raw_handle())? != sid {
        return Err(denied());
    }
    unprivileged(token.as_raw_handle(), true)?;
    // Query-only access allows clients to authenticate the pipe server. No VM read,
    // handle duplication, token duplication, adjustment, termination or injection.
    let process_sd = descriptor(&format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})(A;;0x1000;;;WD)"
    ))?;
    check(unsafe {
        SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, process_sd.0)
    })?;
    let token_sd = descriptor(&format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})(A;;0x8;;;WD)"
    ))?;
    check(unsafe {
        SetKernelObjectSecurity(token.as_raw_handle(), DACL_SECURITY_INFORMATION, token_sd.0)
    })?;
    Ok(sid)
}

pub struct Listener {
    name: &'static str,
    security: Local,
}

impl Listener {
    pub fn new(name: &'static str, principal: &str, service: &str) -> io::Result<Self> {
        if name != EXEC_PIPE && name != ADMIN_PIPE {
            return Err(denied());
        }
        let principal = canonical_sid(principal)?;
        let service = canonical_sid(service)?;
        let security = descriptor(&format!(
            "D:P(A;;GA;;;{service})(A;;0x{CLIENT_ACCESS:x};;;{principal})"
        ))?;
        Ok(Self { name, security })
    }

    pub fn create(&self, first: bool) -> io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.security.0,
            bInheritHandle: 0,
        };
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    self.name,
                    (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
                )
        }
    }
}

struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        // Continuing with an impersonation token on a Tokio worker is unsafe.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

/// No await may occur between impersonation and restoration.
fn authorize(pipe: &NamedPipeServer, expected: &str, harness: bool) -> io::Result<()> {
    check(unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) })?;
    let _revert = Revert;
    let mut token = null_mut();
    check(unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) })?;
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    if token_user(token.as_raw_handle())? != expected {
        return Err(denied());
    }
    if harness {
        unprivileged(token.as_raw_handle(), false)?;
    }
    Ok(())
}

pub async fn accept_identity(
    pipe: &mut NamedPipeServer,
    expected: &str,
    harness: bool,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        // ImpersonateNamedPipeClient identifies the token of the last read message.
        if pipe.read_u8().await? != 1 {
            return Err(denied());
        }
        authorize(pipe, expected, harness)?;
        pipe.write_u8(1).await
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

pub async fn connect(name: &str) -> io::Result<NamedPipeClient> {
    if name != EXEC_PIPE && name != ADMIN_PIPE {
        return Err(denied());
    }
    let expected = service_sid()?;
    let name = wide(name);
    let mut pipe = loop {
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                CLIENT_ACCESS,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
            break unsafe { NamedPipeClient::from_raw_handle(handle.into_raw_handle()) }?;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let mut pid = 0;
    check(unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) })?;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let token = process_token(process.as_raw_handle(), TOKEN_QUERY)?;
    if token_user(token.as_raw_handle())? != expected {
        return Err(denied());
    }
    // Never send credentials to a server until its OS identity is established.
    pipe.write_u8(1).await?;
    if pipe.read_u8().await? != 1 {
        return Err(denied());
    }
    Ok(pipe)
}

pub fn disconnect_monitor(pipe: &NamedPipeServer) -> io::Result<impl Future<Output = ()> + Send> {
    let mut handle = null_mut();
    check(unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            pipe.as_raw_handle(),
            GetCurrentProcess(),
            &mut handle,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    })?;
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    Ok(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if unsafe {
                PeekNamedPipe(
                    handle.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            } == 0
            {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sid_text_cannot_inject_acl() {
        assert!(canonical_sid("S-1-5-18)(A;;GA;;;WD)").is_err());
        assert_eq!(canonical_sid("S-1-5-18").unwrap(), "S-1-5-18");
    }
    #[test]
    fn client_cannot_create_pipe_instances() {
        assert_eq!(CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
    }
}
