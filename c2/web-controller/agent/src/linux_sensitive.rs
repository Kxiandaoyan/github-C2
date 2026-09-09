/// Linux sensitive information collection.
///
/// One-shot enumeration of high-value information on the target:
/// - High-value files (keys, configs, history)
/// - Currently logged-in users
/// - Sudo privilege summary
/// - SUID/SGID binaries (privilege escalation paths)
/// - Scheduled tasks
/// - Listening ports

#[cfg(unix)]
pub fn collect_sensitive() -> String {
    let mut sections: Vec<String> = Vec::new();

    // ── 1. High-value files ───────────────────────────────────────────────────
    let sensitive_paths = [
        "/root/.ssh/id_rsa",
        "/root/.ssh/authorized_keys",
        "/root/.bash_history",
        "/home/*/.ssh/id_rsa",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.aws/credentials",
        "/root/.docker/config.json",
    ];
    let mut found_files: Vec<String> = Vec::new();
    for path in &sensitive_paths {
        // Expand /home/* glob
        if path.contains('*') {
            if let Ok(home) = std::fs::read_dir("/home") {
                for entry in home.flatten() {
                    let expanded = path.replace("*", &entry.file_name().to_string_lossy());
                    if std::path::Path::new(&expanded).exists() {
                        found_files.push(expanded);
                    }
                }
            }
        } else if std::path::Path::new(path).exists() {
            found_files.push(path.to_string());
        }
    }
    if !found_files.is_empty() {
        sections.push(format!("[Sensitive Files]\n{}", found_files.join("\n")));
    }

    // ── 2. Currently logged-in users ──────────────────────────────────────────
    let logged_in = get_logged_in_users();
    if !logged_in.is_empty() {
        sections.push(format!("[Logged In Users]\n{}", logged_in));
    }

    // ── 3. Sudo privileges ────────────────────────────────────────────────────
    let sudo_info = get_sudo_info();
    if !sudo_info.is_empty() {
        sections.push(format!("[Sudo Rules]\n{}", sudo_info));
    }

    // ── 4. Scheduled tasks ────────────────────────────────────────────────────
    let crontabs = collect_crontabs();
    if !crontabs.is_empty() {
        sections.push(format!("[Crontabs]\n{}", crontabs));
    }

    // ── 5. Listening ports (/proc/net/tcp + tcp6) ────────────────────────────
    let ports = collect_listen_ports();
    if !ports.is_empty() {
        sections.push(format!("[Listening Ports]\n{}", ports));
    }

    // ── 6. SUID binaries (common high-value paths only) ──────────────────────
    let suid = collect_suid_binaries();
    if !suid.is_empty() {
        sections.push(format!("[SUID Binaries]\n{}", suid));
    }

    if sections.is_empty() {
        "No sensitive info found".to_string()
    } else {
        sections.join("\n\n")
    }
}

#[cfg(unix)]
fn get_logged_in_users() -> String {
    // Primary method: /proc/<pid>/loginuid — kernel sets this to the real login UID per session.
    // Processes with a valid loginuid (not 4294967295) correspond to real login sessions.
    let mut users: std::collections::HashSet<String> = std::collections::HashSet::new();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();

    // Primary: processes where /proc/<pid>/loginuid is a valid UID
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.chars().all(|c| c.is_ascii_digit()) { continue; }
            let loginuid_path = format!("/proc/{}/loginuid", name);
            if let Ok(s) = std::fs::read_to_string(&loginuid_path) {
                let uid: u32 = s.trim().parse().unwrap_or(u32::MAX);
                if uid == u32::MAX { continue; } // MAX (4294967295) = not set by kernel
                // uid=0 is root — DO include it; root SSH sessions are valid logged-in users
                for line in passwd.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 3 && parts[2] == uid.to_string() {
                        users.insert(parts[0].to_string());
                        break;
                    }
                }
            }
        }
    }

    // Fallback: if loginuid produced no results (some kernel configs), use sessionid
    if users.is_empty() {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) { continue; }
                let sessionid = std::fs::read_to_string(format!("/proc/{}/sessionid", name))
                    .unwrap_or_default();
                // sessionid == 0 means kernel thread — skip
                if sessionid.trim() == "0" { continue; }
                let status = std::fs::read_to_string(format!("/proc/{}/status", name))
                    .unwrap_or_default();
                let uid: u32 = status.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(u32::MAX);
                if uid == 0 || uid == u32::MAX { continue; }
                for line in passwd.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 3 && parts[2] == uid.to_string() {
                        users.insert(parts[0].to_string());
                        break;
                    }
                }
            }
        }
    }

    let mut v: Vec<String> = users.into_iter().collect();
    v.sort();
    if v.is_empty() { "none".to_string() } else { v.join(", ") }
}

#[cfg(unix)]
fn get_sudo_info() -> String {
    // Read /etc/sudoers plus all files in /etc/sudoers.d/
    let mut lines: Vec<String> = Vec::new();
    let add_lines = |content: &str, lines: &mut Vec<String>| {
        for l in content.lines() {
            let t = l.trim();
            if !t.is_empty() && !t.starts_with('#') {
                lines.push(t.to_string());
            }
        }
    };

    if let Ok(content) = std::fs::read_to_string("/etc/sudoers") {
        add_lines(&content, &mut lines);
    }
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        let mut paths: Vec<_> = entries.flatten()
            .map(|e| e.path())
            .collect();
        paths.sort();
        for path in paths {
            if let Ok(content) = std::fs::read_to_string(&path) {
                lines.push(format!("# {}", path.display()));
                add_lines(&content, &mut lines);
            }
        }
    }
    if lines.is_empty() {
        "no readable sudoers".to_string()
    } else {
        lines.into_iter().take(40).collect::<Vec<_>>().join("\n")
    }
}

#[cfg(unix)]
fn collect_crontabs() -> String {
    let mut result = Vec::new();
    // root crontab — try both Debian/Ubuntu and RHEL/CentOS paths
    for path in &["/var/spool/cron/crontabs/root", "/var/spool/cron/root"] {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        if !content.trim().is_empty() {
            result.push(format!("[root crontab]\n{}", content.trim()));
            break; // use first valid one
        }
    }
    // /etc/cron.d/
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                let lines: Vec<&str> = content.lines()
                    .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                    .collect();
                if !lines.is_empty() {
                    result.push(format!("[{}]\n{}", entry.file_name().to_string_lossy(), lines.join("\n")));
                }
            }
        }
    }
    result.join("\n")
}

#[cfg(unix)]
fn collect_listen_ports() -> String {
    let mut ports: Vec<String> = Vec::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 { continue; }
                // state 0A = LISTEN
                if parts[3] == "0A" {
                    if let Some(local) = parts.get(1) {
                        let port_hex = local.split(':').last().unwrap_or("0");
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            let port_str = port.to_string();
                            if !ports.contains(&port_str) {
                                ports.push(port_str);
                            }
                        }
                    }
                }
            }
        }
    }
    ports.sort_by_key(|p| p.parse::<u16>().unwrap_or(0));
    ports.join(", ")
}

#[cfg(unix)]
fn collect_suid_binaries() -> String {
    // Check only common high-value paths to avoid the noise of a full-disk find
    let check_paths = [
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/newgrp",
        "/usr/bin/pkexec", "/usr/bin/passwd", "/usr/bin/chsh",
        "/bin/bash", "/usr/bin/python3", "/usr/bin/python",
        "/usr/bin/perl", "/usr/bin/ruby",
    ];
    let mut suid: Vec<String> = Vec::new();
    for path in &check_paths {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.mode() & 0o4000 != 0 {
                suid.push(path.to_string());
            }
        }
    }
    suid.join("\n")
}

#[cfg(not(unix))]
pub fn collect_sensitive() -> String {
    "Not Linux".to_string()
}
