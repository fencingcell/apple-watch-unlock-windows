//! Native Windows SCM service host, AGPL-3.0-only.
use crate::{gatt, storage};
use anyhow::{ensure, Result};
use std::sync::{
    atomic::{AtomicPtr, Ordering},
    Mutex,
};
use windows::{
    core::{w, PWSTR},
    Win32::System::Services::*,
};
pub const NAME: &str = "WatchLoginProbe";
static HANDLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static STATUS_LOCK: Mutex<()> = Mutex::new(());
fn status(state: SERVICE_STATUS_CURRENT_STATE, error: u32) -> Result<()> {
    let _guard = STATUS_LOCK.lock().unwrap();
    let state = if state == SERVICE_RUNNING && gatt::STOP.load(Ordering::Acquire) {
        SERVICE_STOP_PENDING
    } else {
        state
    };
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let value = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: error,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: if pending { 1 } else { 0 },
        dwWaitHint: if pending { 60_000 } else { 0 },
    };
    unsafe {
        SetServiceStatus(
            SERVICE_STATUS_HANDLE(HANDLE.load(Ordering::Acquire)),
            &value,
        )?;
    }
    crate::events::record(&format!("scm_state={} win32_exit_code={error}", state.0));
    Ok(())
}
unsafe extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            gatt::STOP.store(true, Ordering::Release);
            let _ = status(SERVICE_STOP_PENDING, 0);
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => 120,
    }
}
unsafe extern "system" fn entry(_argc: u32, _argv: *mut PWSTR) {
    let Ok(handle) = RegisterServiceCtrlHandlerExW(w!("WatchLoginProbe"), Some(handler), None)
    else {
        return;
    };
    HANDLE.store(handle.0, Ordering::Release);
    let result = (|| -> Result<()> {
        status(SERVICE_START_PENDING, 0)?;
        ensure!(
            storage::current_sid()? == "S-1-5-18",
            "service requires LocalSystem"
        );
        let root = storage::data_root(true)?;
        ensure!(
            root.join("public").is_dir() && root.join("secrets").is_dir(),
            "run administrator installer first"
        );
        crate::events::initialize(&root.join("public"))?;
        let key = storage::identity(&root)?;
        let watch = storage::load_watch(&root)?;
        gatt::run(key, watch, None, || status(SERVICE_RUNNING, 0))
    })();
    if let Err(error) = &result {
        crate::events::record(&format!("service=failed error={error:#}"));
    }
    // SCM sees failure when initialization/advertising fails. Stop is reported only after GATT Drop drains jobs.
    let _ = status(
        SERVICE_STOPPED,
        if result.is_ok() || gatt::STOP.load(Ordering::Acquire) {
            0
        } else {
            31
        },
    );
    HANDLE.store(std::ptr::null_mut(), Ordering::Release);
}
pub fn dispatch() -> Result<()> {
    let mut name: Vec<u16> = NAME.encode_utf16().chain(Some(0)).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(entry),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    unsafe {
        StartServiceCtrlDispatcherW(table.as_ptr())?;
    }
    Ok(())
}
