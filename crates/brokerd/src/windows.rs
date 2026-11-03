use crate::daemon;
use broker_core::StateEngine;
use broker_windows::{ADMIN_PIPE, EXEC_PIPE, SERVICE_NAME};
use clap::Parser;
use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::{watch, Semaphore};
use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::*;

pub trait DisconnectMonitor {
    fn disconnect_monitor(&self) -> io::Result<impl Future<Output = ()> + Send + 'static>;
}
impl DisconnectMonitor for NamedPipeServer {
    fn disconnect_monitor(&self) -> io::Result<impl Future<Output = ()> + Send + 'static> {
        broker_windows::disconnect_monitor(self)
    }
}

#[derive(Parser)]
struct Options {
    #[arg(long)]
    operator_sid: String,
    #[arg(long)]
    harness_sid: String,
}

static STATUS: AtomicUsize = AtomicUsize::new(0);
static STOP: OnceLock<watch::Sender<bool>> = OnceLock::new();

fn set_status(state: u32, failed: bool) -> Result<(), &'static str> {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if failed {
            ERROR_SERVICE_SPECIFIC_ERROR
        } else {
            NO_ERROR
        },
        dwServiceSpecificExitCode: u32::from(failed),
        dwCheckPoint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            1
        } else {
            0
        },
        dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            10_000
        } else {
            0
        },
    };
    if unsafe {
        SetServiceStatus(
            STATUS.load(Ordering::Acquire) as SERVICE_STATUS_HANDLE,
            &status,
        )
    } == 0
    {
        return Err("cannot report service status");
    }
    Ok(())
}

unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            let _ = set_status(SERVICE_STOP_PENDING, false);
            if let Some(stop) = STOP.get() {
                let _ = stop.send(true);
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let (stop, receiver) = watch::channel(false);
    if STOP.set(stop).is_err() {
        return;
    }
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null()) };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle as usize, Ordering::Release);
    if set_status(SERVICE_START_PENDING, false).is_err() {
        return;
    }
    // Never log library errors or command-line values from a credential-bearing process.
    let result = Options::try_parse()
        .map_err(|_| "invalid service configuration")
        .and_then(|options| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|_| "cannot start service runtime")?;
            runtime.block_on(run(options, receiver))
        });
    let _ = set_status(SERVICE_STOPPED, result.is_err());
}

pub fn run_service() -> Result<(), &'static str> {
    let mut name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err("Windows daemon must be started by the Service Control Manager");
    }
    Ok(())
}

async fn run(options: Options, mut stop: watch::Receiver<bool>) -> Result<(), &'static str> {
    let operator =
        broker_windows::canonical_sid(&options.operator_sid).map_err(|_| "invalid operator SID")?;
    let harness =
        broker_windows::canonical_sid(&options.harness_sid).map_err(|_| "invalid harness SID")?;
    let service =
        broker_windows::harden().map_err(|_| "service identity or process security is unsafe")?;
    if operator == harness
        || operator == service
        || harness == service
        || !harness.starts_with("S-1-5-21-")
    {
        return Err(
            "operator, harness, and service must be separate; harness must be a user account",
        );
    }
    let exec_security = broker_windows::Listener::new(EXEC_PIPE, &harness, &service)
        .map_err(|_| "cannot secure execution pipe")?;
    let admin_security = broker_windows::Listener::new(ADMIN_PIPE, &operator, &service)
        .map_err(|_| "cannot secure administration pipe")?;
    let mut execution = exec_security
        .create(true)
        .map_err(|_| "cannot create execution pipe")?;
    let mut administration = admin_security
        .create(true)
        .map_err(|_| "cannot create administration pipe")?;
    let state = Arc::new(StateEngine::new(32));
    let exec_slots = Arc::new(Semaphore::new(64));
    let admin_slots = Arc::new(Semaphore::new(4));
    let operations = Arc::new(Semaphore::new(32));
    set_status(SERVICE_RUNNING, false)?;
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            incoming = execution.connect() => {
                incoming.map_err(|_| "execution pipe failed")?;
                // Keep the namespace continuously owned while replacing its listening instance.
                let next = exec_security.create(false).map_err(|_| "cannot replace execution pipe")?;
                let mut stream = std::mem::replace(&mut execution, next);
                let Ok(slot) = exec_slots.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                let operations = operations.clone();
                let expected = harness.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    if broker_windows::accept_identity(&mut stream, &expected, true).await.is_ok() {
                        // StateEngine's u32 identity is an internal label, never a Windows RID.
                        // Only an authenticated configured harness SID reaches this label.
                        daemon::serve_execution(stream, state, 1, operations).await;
                    }
                });
            }
            incoming = administration.connect() => {
                incoming.map_err(|_| "administration pipe failed")?;
                let next = admin_security.create(false).map_err(|_| "cannot replace administration pipe")?;
                let mut stream = std::mem::replace(&mut administration, next);
                let Ok(slot) = admin_slots.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                let expected = operator.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    if broker_windows::accept_identity(&mut stream, &expected, false).await.is_ok() {
                        daemon::serve_admin(stream, state, 1).await;
                    }
                });
            }
        }
    }
    state.lock();
    Ok(())
}
