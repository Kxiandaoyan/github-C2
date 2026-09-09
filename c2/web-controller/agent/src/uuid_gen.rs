/// Agent ID derivation strategy:
///
/// Priority:
///   1. Hardware-bound ID = SHA256(/etc/machine-id + first non-loopback MAC) -> UUID format
///      - Stable; survives agent reinstall; not tied to deletable files
///   2. /etc/machine-id only (when no MAC available)
///   3. MAC only (when no machine-id available)
///   4. Random UUID (fallback; persisted to file)
///
/// Windows: reads HKLM\..\MachineGuid + MAC
/// Linux:   /etc/machine-id or /var/lib/dbus/machine-id + /sys/class/net/*/address

use std::path::PathBuf;
use std::sync::OnceLock;

static HWID: OnceLock<String> = OnceLock::new();

// ─── Public API ───────────────────────────────────────────────────────────────

/// Get or create the Agent ID.
///
/// Unix: derived from hardware info (machine-id + MAC) first, stable across reinstall.
/// Windows: uses registry MachineGuid.
/// If all hardware sources fail, falls back to a random UUID persisted to a file.
pub fn get_or_create_agent_id() -> String {
    HWID.get_or_init(compute_agent_id).clone()
}

fn compute_agent_id() -> String {
    // 1. Hardware-derived ID (stable)
    let hw_id = derive_hardware_id();
    if !hw_id.is_empty() {
        // Also write to file for older controller compatibility
        let id_file = get_id_file_path();
        if let Some(parent) = id_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = stealth_write(&id_file, hw_id.as_bytes());
        return hw_id;
    }

    // 2. Load existing ID from file
    let id_file = get_id_file_path();
    if let Ok(content) = std::fs::read_to_string(&id_file) {
        let trimmed = content.trim();
        if !trimmed.is_empty() && trimmed.len() == 36 {
            return trimmed.to_string();
        }
    }

    // 3. Generate random UUID and persist (final fallback)
    let uuid = generate_random_uuid();
    if let Some(parent) = id_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    for _ in 0..3 {
        if stealth_write(&id_file, uuid.as_bytes()).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    uuid
}

// ─── Hardware ID derivation ───────────────────────────────────────────────────

fn derive_hardware_id() -> String {
    let machine_id = get_machine_id();
    let mac = get_first_mac();

    let combined = match (machine_id.is_empty(), mac.is_empty()) {
        (false, false) => format!("{}:{}", machine_id, mac),
        (false, true)  => machine_id,
        (true,  false) => mac,
        (true,  true)  => return String::new(),
    };

    let hash = sha256_hex(combined.as_bytes());
    // Format as UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    format!(
        "{}-{}-{}-{}-{}",
        &hash[0..8],
        &hash[8..12],
        &hash[12..16],
        &hash[16..20],
        &hash[20..32]
    )
}

// ─── machine-id reading ───────────────────────────────────────────────────────

#[cfg(unix)]
fn get_machine_id() -> String {
    // Standard systemd location: /etc/machine-id
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(windows)]
fn get_machine_id() -> String {
    use std::ptr;
    type HKEY = *mut std::ffi::c_void;
    const HKEY_LOCAL_MACHINE: HKEY = 0x80000002u32 as usize as HKEY;
    const KEY_READ: u32 = 0x20019;

    unsafe extern "system" {
        fn RegOpenKeyExW(key: HKEY, sub: *const u16, opt: u32, sam: u32, result: *mut HKEY) -> i32;
        fn RegQueryValueExW(key: HKEY, name: *const u16, res: *mut u32, typ: *mut u32, data: *mut u8, len: *mut u32) -> i32;
        fn RegCloseKey(key: HKEY) -> i32;
    }

    let sub: Vec<u16> = "SOFTWARE\\Microsoft\\Cryptography\0".encode_utf16().collect();
    let val: Vec<u16> = "MachineGuid\0".encode_utf16().collect();
    let mut hkey: HKEY = ptr::null_mut();

    unsafe {
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return String::new();
        }
        let mut buf = vec![0u8; 512];
        let mut buf_len = buf.len() as u32;
        let mut typ: u32 = 0;
        if RegQueryValueExW(hkey, val.as_ptr(), ptr::null_mut(), &mut typ, buf.as_mut_ptr(), &mut buf_len) != 0 {
            RegCloseKey(hkey);
            return String::new();
        }
        RegCloseKey(hkey);
        let wchars: &[u16] = std::slice::from_raw_parts(buf.as_ptr() as *const u16, (buf_len as usize) / 2);
        String::from_utf16_lossy(wchars).trim_end_matches('\0').to_string()
    }
}

// ─── MAC address reading ──────────────────────────────────────────────────────

#[cfg(unix)]
fn get_first_mac() -> String {
    // Read from /sys/class/net/<iface>/address, skipping loopback
    let net_dir = "/sys/class/net";
    let Ok(entries) = std::fs::read_dir(net_dir) else { return String::new() };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" { continue; }
        let addr_path = format!("{}/{}/address", net_dir, name);
        if let Ok(mac) = std::fs::read_to_string(&addr_path) {
            let mac = mac.trim();
            if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                return mac.to_string();
            }
        }
    }
    String::new()
}

#[cfg(windows)]
fn get_first_mac() -> String {
    String::new() // Windows: machine-id alone is sufficient
}

// ─── File paths ───────────────────────────────────────────────────────────────

fn get_id_file_path() -> PathBuf {
    #[cfg(windows)]
    {
        let username = whoami::username();
        PathBuf::from(format!(r"C:\Users\{}\AppData\Local\.config\agent_id.txt", username))
    }
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            PathBuf::from("/var/tmp/.systemd/agent_id")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            PathBuf::from(format!("{}/.local/share/agent_id", home))
        }
    }
}

// ─── SHA-256 (uses existing sha2 dependency) ──────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─── Random UUID fallback ─────────────────────────────────────────────────────

fn generate_random_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        rng.gen::<u32>(),
        rng.gen::<u16>(),
        rng.gen::<u16>() & 0x0fff,
        rng.gen::<u16>() & 0x3fff | 0x8000,
        rng.gen::<u64>() & 0xffffffffffff
    )
}

// ─── Stealth write (preserves parent directory mtime) ─────────────────────────

#[cfg(unix)]
fn stealth_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent();
    let dir_time = parent.and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok());

    std::fs::write(path, data)?;

    if let (Some(parent), Some(mtime)) = (parent, dir_time) {
        use filetime::{FileTime, set_file_times};
        let ft = FileTime::from_system_time(mtime);
        let _ = set_file_times(parent, ft, ft);
    }
    Ok(())
}

#[cfg(not(unix))]
fn stealth_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}
