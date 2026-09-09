/// WS PTY long-connection shell — Linux only.
///
/// Adapted from cliws (github.com/b23r0/Cliws) rconnect() / xnix.rs.
///
/// Design guarantees:
///   1. Only ONE instance at a time (WS_PTY_ACTIVE atomic flag).
///   2. Runs in a plain OS thread (std::thread) — never blocks tokio runtime.
///   3. bash process is independent of WS transport while the *same* WS is up.
///   4. Connect failures retry (MAX_RETRIES / RETRY_DELAY). After a session has
///      actually bridged, do **not** auto-reconnect: cliws `-b` is one-shot
///      (agent + proxy pair). Reconnecting poisons the next browser session
///      (connects, then both sides close in ~1ms, no data).
///   5. PTY fd ownership: master_fd kept alive by run_session across retries;
///      each bridge_pty_ws call receives a fresh dup() for its reader thread,
///      and a shared dup() for the writer — avoids double-close UB.
///   6. On session end, child bash is killed cleanly.
///
/// Protocol (cliws-compatible):
///   Agent → Controller: Binary frames = raw PTY output bytes
///   Controller → Agent: Binary frames = keyboard input bytes
///   Resize packet (6 bytes): [0x37, 0x37, rows_hi, rows_lo, cols_hi, cols_lo]
///
/// URL: ws://<ip>:<port>/api/v2/stream/<agent_id>

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use websocket::sync::Client;
#[cfg(unix)]
use websocket::{ClientBuilder, OwnedMessage};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// MAGIC_FLAG for resize packets — matches cliws utils.rs: [0x37, 0x37]
#[cfg(unix)]
const MAGIC_FLAG: [u8; 2] = [0x37, 0x37];

/// Max WS reconnection attempts before giving up.
/// Large number so the session stays alive through temporary network drops.
/// The loop is `for attempt in 0..=MAX_RETRIES`, so MAX_RETRIES=60 means
/// 61 total attempts.  To retry indefinitely replace the for-loop with `loop`.
#[cfg(unix)]
const MAX_RETRIES: u32 = 60;

/// Delay between retry attempts.
#[cfg(unix)]
const RETRY_DELAY: Duration = Duration::from_secs(10);

// ── Global state (one session per agent process) ─────────────────────────────

/// True while a WS PTY session is running.
#[cfg(unix)]
static WS_PTY_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Set to true to request the running session to stop.
#[cfg(unix)]
static WS_PTY_STOP: AtomicBool = AtomicBool::new(false);

/// PID of the bash child — stored so we can kill it on stop.
#[cfg(unix)]
static BASH_PID: AtomicI32 = AtomicI32::new(-1);

/// Session generation — incremented each start(). Monitor threads only set
/// WS_PTY_STOP if their generation matches the current one (prevents stale
/// threads from aborting a subsequent session).
#[cfg(unix)]
static SESSION_GEN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Bridge (reconnect-attempt) generation — bumped before EVERY bridge_pty_ws
/// call. The PTY reader thread of a previous attempt polls this counter and
/// exits when it goes stale: without it, an old reader blocked in read()
/// races the new attempt's reader on the same open file description and can
/// swallow the first output block after reconnect.
#[cfg(unix)]
static BRIDGE_GEN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

// ── Public API ───────────────────────────────────────────────────────────────

/// True if a WS PTY session is currently active.
#[cfg(unix)]
pub fn is_active() -> bool {
    WS_PTY_ACTIVE.load(Ordering::Relaxed)
}

/// Request the running session to stop and kill the bash child.
#[cfg(unix)]
pub fn request_stop() {
    crate::debug_log("WS PTY: stop requested");
    WS_PTY_STOP.store(true, Ordering::Relaxed);
    let pid = BASH_PID.load(Ordering::Relaxed);
    if pid > 0 {
        crate::debug_log(&format!("WS PTY: sending SIGTERM to bash pgid={}", pid));
        unsafe { libc::kill(-pid, libc::SIGTERM); }
    }
}

/// Start a reverse WS PTY session.
/// Returns when the session ends (after retries exhausted or stop requested).
/// Intended to be called via std::thread::spawn — never blocks tokio runtime.
#[cfg(unix)]
pub fn start(ws_url: String) -> String {
    // A second `wspty` (new browser session) must replace the old one.
    // cliws is one-shot: leaving the old reconnect loop running makes the
    // next pair connect-and-die with no PTY data.
    if WS_PTY_ACTIVE.swap(true, Ordering::SeqCst) {
        crate::debug_log("WS PTY: start() while active — stopping previous session");
        request_stop();
        for _ in 0..50 {
            if !WS_PTY_ACTIVE.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if WS_PTY_ACTIVE.swap(true, Ordering::SeqCst) {
            crate::debug_log("WS PTY: start() rejected — previous session did not unwind");
            return "WS PTY already active (only one session per agent)".to_string();
        }
    }
    crate::debug_log(&format!("WS PTY: starting session url={}", ws_url));
    WS_PTY_STOP.store(false, Ordering::Relaxed);
    BASH_PID.store(-1, Ordering::Relaxed);
    let my_gen = SESSION_GEN.fetch_add(1, Ordering::SeqCst).wrapping_add(1);

    let result = run_session(&ws_url);

    // Only the current generation may clear the flags — a replacement
    // start() may already have claimed WS_PTY_ACTIVE.
    if SESSION_GEN.load(Ordering::SeqCst) == my_gen {
        BASH_PID.store(-1, Ordering::Relaxed);
        WS_PTY_ACTIVE.store(false, Ordering::SeqCst);
        WS_PTY_STOP.store(false, Ordering::Relaxed);
    }
    crate::debug_log(&format!("WS PTY: session closed, result={}", result));
    result
}

// ── Session implementation ───────────────────────────────────────────────────

#[cfg(unix)]
fn run_session(ws_url: &str) -> String {
    use nix::pty::openpty;
    use nix::unistd::{fork, ForkResult};

    // ── Open PTY ────────────────────────────────────────────────────────────
    let ends = match openpty(None, None) {
        Ok(e) => e,
        Err(e) => {
            crate::debug_log(&format!("WS PTY: openpty failed: {}", e));
            return format!("openpty failed: {}", e);
        }
    };

    // Extract raw fds, consuming OwnedFd so ends doesn't double-close on drop.
    // Both Linux and non-Linux must use into_raw_fd() to transfer ownership.
    // as_raw_fd() would leave ends holding OwnedFd; when run_session returns,
    // ends.drop() would close fds that we've already closed or transferred.
    use std::os::unix::io::IntoRawFd;
    let (master_fd, slave_fd) = (ends.master.into_raw_fd(), ends.slave.into_raw_fd());

    // ── Build envp BEFORE fork (safe to use Rust allocator here) ───────────
    // execve replaces the entire environment; we must include PATH/HOME/USER
    // etc. or the interactive bash will be crippled.
    let env_home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let env_user = std::env::var("USER").unwrap_or_else(|_| {
        std::env::var("LOGNAME").unwrap_or_else(|_| "root".to_string())
    });
    let env_path = std::env::var("PATH").unwrap_or_else(|_|
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()
    );
    let env_lang = std::env::var("LANG").unwrap_or_else(|_| "en_US.UTF-8".to_string());

    let env_strings: Vec<std::ffi::CString> = [
        format!("TERM=xterm-256color"),
        format!("HOME={}", env_home),
        format!("USER={}", env_user),
        format!("LOGNAME={}", env_user),
        format!("PATH={}", env_path),
        format!("LANG={}", env_lang),
        format!("SHELL=/bin/bash"),
        format!("HISTFILE=/dev/null"),
        format!("HISTSIZE=0"),
        format!("HISTFILESIZE=0"),
        format!("SAVEHIST=0"),
        format!("HISTCONTROL=ignoreboth"),
    ].iter().filter_map(|s| std::ffi::CString::new(s.as_str()).ok()).collect();

    let env_ptrs: Vec<*const libc::c_char> = env_strings.iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // ── Double-fork bash → detach from agent process tree ──────────────────
    // fork → child1 (setsid + fork) → grandchild (exec bash)
    // child1 exits immediately → grandchild is adopted by init (PID 1)
    // so `ps auxf` never shows agent → bash parent-child relationship.
    // Grandchild PID is sent back to parent via pipe.
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        unsafe { libc::close(master_fd); libc::close(slave_fd); }
        return "pipe() failed".to_string();
    }
    let (pipe_r, pipe_w) = (pipe_fds[0], pipe_fds[1]);

    let child_pid = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            unsafe {
                libc::close(pipe_r);
                libc::setsid();

                let grandchild = libc::fork();
                if grandchild < 0 {
                    libc::close(pipe_w);
                    libc::_exit(1);
                }
                if grandchild > 0 {
                    let pid_bytes = grandchild.to_ne_bytes();
                    libc::write(pipe_w, pid_bytes.as_ptr() as *const _, 4);
                    libc::close(pipe_w);
                    libc::_exit(0);
                }

                libc::close(pipe_w);
                libc::setsid();
                libc::ioctl(slave_fd, libc::TIOCSCTTY, 0i32);
                libc::dup2(slave_fd, 0);
                libc::dup2(slave_fd, 1);
                libc::dup2(slave_fd, 2);
                if slave_fd > 2 { libc::close(slave_fd); }
                libc::close(master_fd);

                let shell = b"/bin/bash\0";
                let arg0  = b"bash\0";
                let arg1  = b"-i\0";
                let argv: [*const libc::c_char; 3] = [
                    arg0.as_ptr() as _,
                    arg1.as_ptr() as _,
                    std::ptr::null(),
                ];
                libc::execve(
                    shell.as_ptr() as _,
                    argv.as_ptr(),
                    env_ptrs.as_ptr(),
                );
                libc::_exit(1);
            }
        }
        Ok(ForkResult::Parent { child: pid, .. }) => {
            unsafe {
                libc::close(pipe_w);
                libc::close(slave_fd);
                // Reap the intermediate child (exits immediately)
                libc::waitpid(i32::from(pid), std::ptr::null_mut(), 0);
                // Read grandchild PID from pipe
                let mut pid_buf = [0u8; 4];
                let n = libc::read(pipe_r, pid_buf.as_mut_ptr() as *mut _, 4);
                libc::close(pipe_r);
                if n != 4 {
                    // Grandchild may already be running — scan for orphan bash on our PTY.
                    // Best-effort: close master so bash gets SIGHUP when slave detects hangup.
                    libc::close(master_fd);
                    crate::debug_log("WS PTY: double-fork pipe read failed, closing master to SIGHUP orphan");
                    return "double-fork: pipe read failed".to_string();
                }
                let gc_pid = i32::from_ne_bytes(pid_buf);
                if gc_pid <= 0 {
                    libc::close(master_fd);
                    crate::debug_log(&format!("WS PTY: invalid grandchild pid={}", gc_pid));
                    return "double-fork: invalid grandchild PID".to_string();
                }
                crate::debug_log(&format!("WS PTY: bash double-forked grandchild pid={}", gc_pid));
                gc_pid
            }
        }
        Err(e) => {
            unsafe { libc::close(master_fd); libc::close(slave_fd); libc::close(pipe_r); libc::close(pipe_w); }
            crate::debug_log(&format!("WS PTY: fork failed: {}", e));
            return format!("fork failed: {}", e);
        }
    };

    BASH_PID.store(child_pid, Ordering::Relaxed);

    // Monitor grandchild via kill(pid, 0) — can't waitpid since it's not our child.
    // PTY EOF (master read → 0/EIO) is the primary exit signal; this is a backup.
    // Capture session generation so this thread won't affect a later session.
    let gc_pid = child_pid;
    let my_gen = SESSION_GEN.load(Ordering::Relaxed);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(3));
            if SESSION_GEN.load(Ordering::Relaxed) != my_gen { return; }
            if WS_PTY_STOP.load(Ordering::Relaxed) { return; }
            if unsafe { libc::kill(gc_pid, 0) } != 0 { break; }
        }
        if SESSION_GEN.load(Ordering::Relaxed) == my_gen {
            crate::debug_log(&format!("WS PTY: grandchild {} gone, signalling stop", gc_pid));
            WS_PTY_STOP.store(true, Ordering::Relaxed);
        }
    });

    // ── dup() master fd for write; each retry gets a fresh dup for read ─────
    //
    // master_fd       : kept alive by run_session for the entire session lifetime
    //                   so we can dup() it on each retry attempt.
    // master_write_fd : one dup shared across all retries for writing keyboard
    //                   input and resize packets into the PTY.
    // per-attempt read_fd: fresh dup passed to each bridge_pty_ws call; Thread A
    //                   takes ownership via File and closes it when the thread exits.
    //
    // This avoids the use-after-close / fd-number-reuse hazard that occurs if
    // Thread A from attempt N closes master_fd before attempt N+1 begins.
    let master_write_fd = unsafe { libc::dup(master_fd) };

    if master_write_fd < 0 {
        unsafe { libc::kill(-child_pid, libc::SIGKILL); libc::close(master_fd); }
        crate::debug_log("WS PTY: dup(master) for write failed");
        return "dup(master) for write failed".to_string();
    }

    // ── Connect with retries ─────────────────────────────────────────────────
    for attempt in 0..=MAX_RETRIES {
        if WS_PTY_STOP.load(Ordering::Relaxed) {
            crate::debug_log("WS PTY: stop flag set before connect");
            break;
        }

        if attempt > 0 {
            crate::debug_log(&format!("WS PTY: retry {}/{}", attempt, MAX_RETRIES));
            thread::sleep(RETRY_DELAY);
            if WS_PTY_STOP.load(Ordering::Relaxed) {
                crate::debug_log("WS PTY: stop flag set during retry delay");
                break;
            }
        }

        let client = match ClientBuilder::new(ws_url) {
            Err(e) => {
                crate::debug_log(&format!("WS PTY: bad URL: {}", e));
                break; // Bad URL — no point retrying
            }
            Ok(builder) => {
                // Compute agent token: sha256(web_password:agent_id)
                // Extract agent_id from URL path (last segment)
                let agent_id = ws_url.rsplit('/').next().unwrap_or("");
                // Prefer the runtime env var so that a backup-config update (which
                // calls std::env::set_var("ENCRYPTION_PASSWORD", …)) takes effect
                // immediately without recompiling the binary.
                let password_owned = std::env::var("ENCRYPTION_PASSWORD")
                    .unwrap_or_else(|_| crate::embedded_config::encryption_password());
                let token = {
                    use sha2::{Sha256, Digest};
                    let mut h = Sha256::new();
                    h.update(format!("{}:{}", password_owned, agent_id).as_bytes());
                    format!("{:x}", h.finalize())
                };
                use websocket::header::Headers;
                let mut extra_headers = Headers::new();
                extra_headers.set_raw("X-Agent-Token", vec![token.as_bytes().to_vec()]);
                match builder
                    .add_protocol("pty")
                    .custom_headers(&extra_headers)
                    .connect_insecure()
                {
                    Err(e) => {
                        crate::debug_log(&format!("WS PTY: connect failed: {}", e));
                        continue;
                    }
                    Ok(c) => c,
                }
            }
        };

        crate::debug_log(&format!("WS PTY: connected (attempt {})", attempt + 1));

        // Fresh dup for this attempt — Thread A (PTY reader) takes ownership
        // via File and closes it when the thread exits.
        let read_fd = unsafe { libc::dup(master_fd) };
        if read_fd < 0 {
            crate::debug_log("WS PTY: dup(master_fd) for read failed");
            break;
        }

        // Invalidate any still-blocked reader from the PREVIOUS attempt so it
        // cannot race this attempt's reader on the shared open file description.
        let bridge_gen = BRIDGE_GEN.fetch_add(1, Ordering::Relaxed).wrapping_add(1);

        // Run bridge; returns when WS closes
        bridge_pty_ws(read_fd, master_write_fd, client, bridge_gen);

        if WS_PTY_STOP.load(Ordering::Relaxed) {
            crate::debug_log("WS PTY: stop flag set after bridge returned, not retrying");
            break;
        }
        // Connected once: do not auto-reconnect. cliws `-b` pairs one agent
        // socket with one proxy socket; a silent reconnect occupies the
        // next slot and the following browser session gets a dead pipe.
        crate::debug_log("WS PTY: peer closed after a live session — waiting for a new wspty command");
        break;
    }

    // ── Clean up ─────────────────────────────────────────────────────────────
    let pid = BASH_PID.load(Ordering::Relaxed);
    if pid > 0 {
        crate::debug_log(&format!("WS PTY: cleanup — killing process group pgid={}", pid));
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
            thread::sleep(Duration::from_millis(500));
            libc::kill(-pid, libc::SIGKILL);
        }
    }

    // Close master_fd (kept alive across retries) and master_write_fd.
    unsafe { libc::close(master_fd); }
    unsafe { libc::close(master_write_fd); }

    crate::debug_log("WS PTY: session ended");
    "WS PTY session ended".to_string()
}

/// Bidirectional bridge: master PTY ↔ WebSocket.
/// Returns when WS closes, errors, or STOP flag is set.
/// Safe: master_read_fd and master_write_fd are dup()'d — each File owns its fd.
#[cfg(unix)]
fn bridge_pty_ws(
    master_read_fd: std::os::unix::io::RawFd,
    master_write_fd: std::os::unix::io::RawFd,
    client: Client<std::net::TcpStream>,
    bridge_gen: u32,
) {
    use std::sync::mpsc::channel;

    let (mut ws_rx, mut ws_tx) = match client.split() {
        Ok(p) => p,
        Err(e) => {
            crate::debug_log(&format!("WS PTY: split failed: {}", e));
            return;
        }
    };

    // Channel: PTY output → WS sender
    let (tx, rx) = channel::<OwnedMessage>();
    let tx_stop = tx.clone();

    // ── Thread A: read PTY → send to controller ──────────────────────────
    // Owns read_fd via File. When thread ends, File is dropped → fd closed.
    // Polls with a 500 ms timeout instead of blocking forever in read(): a
    // stale reader from a PREVIOUS bridge attempt must notice BRIDGE_GEN has
    // moved on and exit, otherwise it races the new attempt's reader on the
    // same open file description and can swallow the first output block.
    let pty_read_file = unsafe { File::from_raw_fd(master_read_fd) };
    thread::spawn(move || {
        let mut pty_out = pty_read_file;
        use std::os::unix::io::AsRawFd;
        let fd = pty_out.as_raw_fd();
        let mut buf = [0u8; 4096];
        loop {
            if WS_PTY_STOP.load(Ordering::Relaxed)
                || BRIDGE_GEN.load(Ordering::Relaxed) != bridge_gen
            {
                let _ = tx.send(OwnedMessage::Close(None));
                return;
            }
            let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let ret = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 500) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted { continue; }
                crate::debug_log(&format!("WS PTY: poll error: {}", err));
                let _ = tx.send(OwnedMessage::Close(None));
                return;
            }
            if ret == 0 || (pfd.revents & libc::POLLIN) == 0 {
                continue; // timeout / no data — re-check flags
            }
            match pty_out.read(&mut buf) {
                Ok(0) => {
                    crate::debug_log("WS PTY: PTY read EOF");
                    let _ = tx.send(OwnedMessage::Close(None));
                    return;
                }
                Err(e) => {
                    crate::debug_log(&format!("WS PTY: PTY read error: {}", e));
                    let _ = tx.send(OwnedMessage::Close(None));
                    return;
                }
                Ok(n) => {
                    // Re-check staleness AFTER the read: if a new attempt has
                    // started, this channel is dead — do not send.
                    if BRIDGE_GEN.load(Ordering::Relaxed) != bridge_gen {
                        return;
                    }
                    let msg = OwnedMessage::Binary(buf[..n].to_vec());
                    if tx.send(msg).is_err() {
                        return;
                    }
                }
            }
        }
    });

    // ── Thread B: WS sender ──────────────────────────────────────────────
    let send_loop = thread::spawn(move || {
        loop {
            let msg = match rx.recv() {
                Ok(m) => m,
                Err(_) => return,
            };
            match msg {
                OwnedMessage::Close(_) => {
                    let _ = ws_tx.send_message(&OwnedMessage::Close(None));
                    return;
                }
                OwnedMessage::Binary(_) | OwnedMessage::Text(_) => {
                    if let Err(e) = ws_tx.send_message(&msg) {
                        crate::debug_log(&format!("WS PTY: send to controller failed: {}", e));
                        return;
                    }
                }
                OwnedMessage::Ping(p) => {
                    let _ = ws_tx.send_message(&OwnedMessage::Pong(p));
                }
                OwnedMessage::Pong(p) => {
                    let _ = ws_tx.send_message(&OwnedMessage::Pong(p));
                }
            }
        }
    });

    // ── Main: receive from controller → write to PTY ─────────────────────
    // Write via raw libc::write() to master_write_fd.
    // We do NOT create a File from master_write_fd here — that fd is managed
    // by run_session and closed there after bridge_pty_ws returns.
    for message in ws_rx.incoming_messages() {
        if WS_PTY_STOP.load(Ordering::Relaxed) {
            let _ = tx_stop.send(OwnedMessage::Close(None));
            break;
        }

        let message = match message {
            Ok(m) => m,
            Err(e) => {
                crate::debug_log(&format!("WS PTY: incoming_messages error: {}", e));
                let _ = tx_stop.send(OwnedMessage::Close(None));
                break;
            }
        };

        match message {
            OwnedMessage::Close(_) => {
                crate::debug_log("WS PTY: received Close frame from controller");
                let _ = tx_stop.send(OwnedMessage::Close(None));
                break;
            }
            OwnedMessage::Ping(p) => {
                let _ = tx_stop.send(OwnedMessage::Pong(p));
            }
            OwnedMessage::Binary(data) => {
                // Resize magic packet: [0x37, 0x37, rows_hi, rows_lo, cols_hi, cols_lo]
                if data.len() == 6
                    && data[0] == MAGIC_FLAG[0]
                    && data[1] == MAGIC_FLAG[1]
                {
                    let rows = ((data[2] as u16) << 8) | data[3] as u16;
                    let cols = ((data[4] as u16) << 8) | data[5] as u16;
                    let ws = libc::winsize {
                        ws_row: rows,
                        ws_col: cols,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    unsafe { libc::ioctl(master_write_fd, libc::TIOCSWINSZ, &ws); }
                    crate::debug_log(&format!("WS PTY: resize {}x{}", cols, rows));
                    continue;
                }
                // Write keyboard input to PTY master
                let mut written = 0usize;
                while written < data.len() {
                    let ret = unsafe {
                        libc::write(
                            master_write_fd,
                            data[written..].as_ptr() as *const libc::c_void,
                            data.len() - written,
                        )
                    };
                    if ret <= 0 {
                        crate::debug_log(&format!("WS PTY: PTY write error ret={} written={}/{}", ret, written, data.len()));
                        break;
                    }
                    written += ret as usize;
                }
            }
            OwnedMessage::Text(text) => {
                let bytes = text.as_bytes();
                let mut written = 0usize;
                while written < bytes.len() {
                    let ret = unsafe {
                        libc::write(
                            master_write_fd,
                            bytes[written..].as_ptr() as *const libc::c_void,
                            bytes.len() - written,
                        )
                    };
                    if ret <= 0 { break; }
                    written += ret as usize;
                }
            }
            OwnedMessage::Pong(_) => {}
        }
    }

    // Signal Thread B (WS sender) to stop, regardless of why the for-loop exited.
    // Without this, if incoming_messages() exhausts naturally (server closed the TCP
    // connection without sending a WS Close frame), Thread B stays blocked on
    // rx.recv() forever and send_loop.join() deadlocks.
    // Once Thread B receives Close and exits (dropping rx), Thread A's next tx.send()
    // returns Err and Thread A exits as well.
    let _ = tx_stop.send(OwnedMessage::Close(None));

    // read_fd is closed by Thread A's File drop.
    // master_write_fd is NOT closed here — run_session() closes it after we return.
    let _ = send_loop.join();
}

// ── Non-unix stubs ────────────────────────────────────────────────────────────

#[cfg(not(unix))]
pub fn is_active() -> bool { false }
#[cfg(not(unix))]
pub fn request_stop() {}
#[cfg(not(unix))]
pub fn start(_ws_url: String) -> String {
    "WS PTY not supported on this platform".to_string()
}
