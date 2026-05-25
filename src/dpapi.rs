//! dpapi.rs — Credential blob encryption/decryption via CryptProtectData / CryptUnprotectData
#![allow(dead_code, non_snake_case)]

use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE};
use winapi::um::wincrypt::DATA_BLOB;
use winapi::um::winbase::LocalFree;
use winapi::shared::minwindef::DWORD;

pub unsafe fn dpapi_encrypt(plaintext: &[u8]) -> Option<Vec<u8>> {
    let mut in_blob = DATA_BLOB {
        cbData: plaintext.len() as DWORD,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB { cbData: 0, pbData: core::ptr::null_mut() };

    let ok = CryptProtectData(
        &mut in_blob,
        core::ptr::null(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        CRYPTPROTECT_LOCAL_MACHINE,
        &mut out_blob,
    );
    if ok == 0 { return None; }

    let data = core::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
    LocalFree(out_blob.pbData as *mut _);
    Some(data)
}

pub unsafe fn dpapi_decrypt(ciphertext: &[u8]) -> Option<Vec<u8>> {
    let mut in_blob = DATA_BLOB {
        cbData: ciphertext.len() as DWORD,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB { cbData: 0, pbData: core::ptr::null_mut() };

    let ok = CryptUnprotectData(
        &mut in_blob,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        0,
        &mut out_blob,
    );
    if ok == 0 { return None; }

    let data = core::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
    LocalFree(out_blob.pbData as *mut _);
    Some(data)
}
