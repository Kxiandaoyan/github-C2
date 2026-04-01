use std::process::Command;

pub fn self_delete() {
    let exe = std::env::current_exe().unwrap();

    #[cfg(windows)]
    {
        Command::new("cmd")
            .args(&[
                "/c",
                &format!("timeout /t 2 /nobreak >nul & del \"{}\"", exe.display()),
            ])
            .spawn()
            .ok();
    }

    #[cfg(unix)]
    {
        let escaped = exe.display().to_string().replace("'", "'\\''");
        Command::new("sh")
            .args(&["-c", &format!("sleep 2 && rm '{}'", escaped)])
            .spawn()
            .ok();
    }

    std::process::exit(0);
}
