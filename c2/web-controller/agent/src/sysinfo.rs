/// System information collection.
///
/// Hostname and username are read via libc syscalls — more reliable and harder to spoof
/// than reading environment variables.

pub fn collect_sysinfo() -> String {
    let hostname = get_hostname();
    let username = get_username();

    #[cfg(unix)]
    {
        let platform = crate::platform::detect();
        let ip_addrs = get_ip_addresses();
        format!(
            "Hostname: {}\nUser: {}\nOS: {}\nPrivilege: {}\nKernel: {}\nArch: {}{}",
            hostname,
            username,
            platform.display_os(),
            platform.privilege_label(),
            platform.kernel_version,
            platform.arch,
            if ip_addrs.is_empty() { String::new() } else { format!("\nIPs: {}", ip_addrs) }
        )
    }

    #[cfg(not(unix))]
    {
        let os = whoami::distro();
        format!("Hostname: {}\nUser: {}\nOS: {}", hostname, username, os)
    }
}

// ─── Hostname (libc::gethostname preferred) ───────────────────────────────────

#[cfg(unix)]
fn get_hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
        if !name.is_empty() {
            return name;
        }
    }
    whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(not(unix))]
fn get_hostname() -> String {
    whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string())
}

// ─── Username (parse /etc/passwd directly to avoid getpwuid thread-safety issues) ─
// getpwuid returns a pointer to a static buffer — unsafe in multi-threaded / async context.
// Reading /etc/passwd is thread-safe and works on minimal systems without NSS.

#[cfg(unix)]
fn get_username() -> String {
    unsafe {
        let uid = libc::getuid();
        // Use reentrant getpwuid_r to avoid static-buffer race conditions
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0i8; 1024];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        );
        if rc == 0 && !result.is_null() {
            if let Ok(name) = std::ffi::CStr::from_ptr((*result).pw_name).to_str() {
                return name.to_string();
            }
        }
    }
    // Fallback: parse /etc/passwd directly
    let uid = unsafe { libc::getuid() };
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(line_uid) = parts[2].parse::<u32>() {
                    if line_uid == uid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(not(unix))]
fn get_username() -> String {
    whoami::username()
}

// ─── IP addresses (from /proc/net/fib_trie + /proc/net/if_inet6) ──────────────

#[cfg(unix)]
fn get_ip_addresses() -> String {
    let mut addrs: Vec<String> = Vec::new();

    // IPv4: forward-scan /proc/net/fib_trie — look for dotted-decimal lines
    // followed by a "32 LOCAL" marker within the next 3 lines.
    if let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") {
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            // IP line: pure dotted-decimal, 4 parts, no '/'
            if trimmed.contains('.') && !trimmed.contains('/') && !trimmed.contains(' ') {
                let parts: Vec<&str> = trimmed.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                    // Look ahead for "32 LOCAL" marker (up to 3 lines)
                    let is_local = lines.get(i+1..=(i+3).min(lines.len().saturating_sub(1)))
                        .unwrap_or(&[])
                        .iter()
                        .any(|l| {
                            let t = l.trim();
                            t.ends_with("LOCAL") && (t.contains("/32") || t.starts_with("32"))
                        });
                    if is_local
                        && trimmed != "0.0.0.0"
                        && trimmed != "255.255.255.255"
                        && !trimmed.starts_with("127.")
                        && !addrs.contains(&trimmed.to_string())
                    {
                        addrs.push(trimmed.to_string());
                    }
                }
            }
            i += 1;
        }
    }

    // IPv6: parse /proc/net/if_inet6 with simple RFC5952-style compression
    if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 { continue; }
            let iface = parts[5];
            if iface == "lo" { continue; }
            let hex = parts[0];
            if hex.len() != 32 { continue; }
            // Parse into u16[8] array
            let groups: Vec<u16> = (0..8)
                .filter_map(|i| u16::from_str_radix(&hex[i*4..(i+1)*4], 16).ok())
                .collect();
            if groups.len() != 8 { continue; }
            // Skip loopback (::1) and all-zero
            if groups.iter().all(|&g| g == 0) { continue; }
            if groups[..7].iter().all(|&g| g == 0) && groups[7] == 1 { continue; }
            // Skip link-local (fe80::/10)
            if groups[0] & 0xffc0 == 0xfe80 { continue; }
            let ipv6 = groups.iter()
                .map(|g| format!("{:x}", g))
                .collect::<Vec<_>>()
                .join(":");
            if !addrs.contains(&ipv6) {
                addrs.push(ipv6);
            }
        }
    }

    addrs.join(", ")
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn get_ip_addresses() -> String {
    String::new()
}
