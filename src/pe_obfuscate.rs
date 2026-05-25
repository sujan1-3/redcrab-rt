//! pe_obfuscate.rs — Compile-time string XOR + import hash obfuscation

pub const fn xor_bytes(s: &[u8], key: u8) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut i = 0;
    while i < s.len() && i < 64 {
        out[i] = s[i] ^ key;
        i += 1;
    }
    out
}

#[macro_export]
macro_rules! xor_str {
    ($s:expr, $key:expr) => {{
        const OBFUSCATED: [u8; 64] = $crate::pe_obfuscate::xor_bytes($s.as_bytes(), $key);
        OBFUSCATED
    }};
}

pub fn decode_xor(enc: &[u8], key: u8) -> Vec<u8> {
    let mut out: Vec<u8> = enc.iter().map(|b| b ^ key).collect();
    if let Some(pos) = out.iter().position(|&b| b == 0) {
        out.truncate(pos + 1);
    }
    out
}

pub const fn hash_str(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        h = h.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    h
}

pub unsafe fn resolve_by_hash(module_base: *const u8, target_hash: u32) -> *const u8 {
    use winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64,
    };
    let dos = module_base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D { return std::ptr::null(); }
    let nt = module_base.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let export_rva = (*nt).OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    if export_rva == 0 { return std::ptr::null(); }
    let exp = module_base.add(export_rva) as *const IMAGE_EXPORT_DIRECTORY;
    let names  = module_base.add((*exp).AddressOfNames as usize)         as *const u32;
    let funcs  = module_base.add((*exp).AddressOfFunctions as usize)     as *const u32;
    let ords   = module_base.add((*exp).AddressOfNameOrdinals as usize)  as *const u16;
    let count  = (*exp).NumberOfNames as usize;
    for i in 0..count {
        let name_rva = *names.add(i) as usize;
        let name_ptr = module_base.add(name_rva);
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 { len += 1; }
        let name_bytes = std::slice::from_raw_parts(name_ptr, len);
        let h = hash_str(name_bytes);
        if h == target_hash {
            let ord = *ords.add(i) as usize;
            let func_rva = *funcs.add(ord) as usize;
            return module_base.add(func_rva);
        }
    }
    std::ptr::null()
}

pub fn xor_payload_inplace(buf: &mut [u8], key: &[u8]) {
    if key.is_empty() { return; }
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

pub fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// Convert a UTF-8 &str to a null-terminated UTF-16 Vec<u16>.
pub fn wide_ptr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
