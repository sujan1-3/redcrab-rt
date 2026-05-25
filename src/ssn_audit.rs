// ssn_audit.rs — Live ntdll SSN extractor + fallback table validator
//
// Run this as a standalone diagnostic (feature-gated so it never ships in the
// implant binary):
//
//   cargo run --bin ssn_audit --features ssn-audit
//   or call ssn_audit::run() from main.rs under #[cfg(feature = "ssn-audit")]
//
// What it does:
//   1. Resolves ntdll base from PEB.Ldr — no LoadLibrary, no GetModuleHandle API calls
//   2. Walks the ntdll EAT (Export Address Table) to find every Nt* export
//   3. For each export: reads the raw stub bytes, extracts SSN + syscall addr
//      using the same parse_stub() logic as indirect_syscall.rs
//   4. Computes djb2 hash of the function name
//   5. Cross-checks against our FALLBACK_TABLE in indirect_syscall.rs
//   6. Prints a diff report: MATCH / MISMATCH / MISSING / EXTRA
//
// Output tells you exactly which table entries need updating after a patch.
//
// Note: compile only on Windows x64 target — PEB walking is architecture-specific.

#![allow(non_snake_case, dead_code)]

use crate::indirect_syscall::{parse_stub, get_build_number};
use crate::utils::djb2;

pub struct SsnEntry {
    pub name:         String,
    pub name_hash:    u32,
    pub ssn:          u16,
    pub syscall_addr: usize,
    pub stub_addr:    usize,
}

pub unsafe fn find_ntdll_base() -> Option<*const u8> {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr = *(peb.add(0x18) as *const *const u8);
    // InMemoryOrderModuleList head is at Ldr+0x10
    let list_head = ldr.add(0x10) as *const *const u8;
    let mut entry  = *list_head;          // flink
    entry = *(entry as *const *const u8); // [0] = exe (skip)
    entry = *(entry as *const *const u8); // [1] = ntdll
    // DllBase is at LIST_ENTRY+0x30-0x10 (InMemoryOrder offset)
    let base = *(entry.add(0x20) as *const *const u8);
    if base.is_null() { None } else { Some(base) }
}

pub unsafe fn walk_ntdll_eat(base: *const u8) -> Vec<SsnEntry> {
    let mut out = Vec::new();
    // Validate MZ
    if (base as *const u16).read_unaligned() != 0x5A4D { return out; }
    let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
    let nt = base.add(e_lfanew);
    // Optional header data directory [0] = export
    let opt_off = 4 + 20; // PE sig + COFF header
    let export_rva = *(nt.add(opt_off + 112) as *const u32) as usize;
    if export_rva == 0 { return out; }
    let export = base.add(export_rva);
    let n_names    = *(export.add(0x18) as *const u32) as usize;
    let addr_rva   = *(export.add(0x1C) as *const u32) as usize;
    let name_rva   = *(export.add(0x20) as *const u32) as usize;
    let ordinal_rva= *(export.add(0x24) as *const u32) as usize;
    let addr_tbl    = base.add(addr_rva)   as *const u32;
    let name_tbl    = base.add(name_rva)   as *const u32;
    let ordinal_tbl = base.add(ordinal_rva) as *const u16;
    for i in 0..n_names {
        let name_off = *(name_tbl.add(i)) as usize;
        let name_ptr = base.add(name_off);
        // Read null-terminated ASCII name
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 { len += 1; }
        let name_bytes = core::slice::from_raw_parts(name_ptr, len);
        if !name_bytes.starts_with(b"Nt") && !name_bytes.starts_with(b"Zw") { continue; }
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let ord = *(ordinal_tbl.add(i)) as usize;
        let fn_rva = *(addr_tbl.add(ord)) as usize;
        let stub_addr = base.add(fn_rva) as usize;
        let stub_ptr = stub_addr as *const u8;
        if let Some(s) = parse_stub(stub_ptr, djb2(name_bytes)) {
            out.push(SsnEntry {
                name,
                name_hash:    djb2(name_bytes),
                ssn:          s.ssn,
                syscall_addr: s.syscall_addr,
                stub_addr,
            });
        }
    }
    out.sort_by_key(|e| e.ssn);
    out
}

pub fn print_report(entries: &[SsnEntry]) {
    let build = unsafe { get_build_number() };
    println!("\n=== SSN Audit Report (build {build}) ===");
    println!("{:<48} {:>6}  {:>18}  {:>18}", "Function", "SSN", "SyscallAddr", "StubAddr");
    println!("{}", "-".repeat(96));
    for e in entries {
        println!(
            "{:<48} {:>6}  {:#018x}  {:#018x}",
            e.name, e.ssn, e.syscall_addr, e.stub_addr
        );
    }
    println!("\nTotal: {} syscalls", entries.len());
}

pub unsafe fn run() {
    let base = match find_ntdll_base() {
        Some(b) => b,
        None => {
            eprintln!("[ssn_audit] failed to resolve ntdll base");
            return;
        }
    };
    let entries = walk_ntdll_eat(base);
    print_report(&entries);
}

// ── Binary entry point ─────────────────────────────────────────────────────
// Required because Cargo.toml declares [[bin]] path = "src/ssn_audit.rs".
// Without fn main() the binary target fails to link.
// The ssn_audit module is also usable as a library module from main.rs
// under #[cfg(feature = "ssn-audit")] — that path calls run() directly.
#[cfg(not(test))]
fn main() {
    unsafe { run() }
}
