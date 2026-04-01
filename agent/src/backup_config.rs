use std::time::Duration;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct BackupConfig {
    pub github_token: String,
    pub github_repo: String,
    pub password: String,
}

pub fn fetch_backup_config(url: &str) -> Result<BackupConfig, String> {
    // 强制 HTTPS
    if !url.starts_with("https://") {
        return Err("Backup URL must use HTTPS".to_string());
    }

    // 重试 3 次
    for attempt in 1..=3 {
        match fetch_backup_config_once(url) {
            Ok(config) => return Ok(config),
            Err(e) => {
                if attempt < 3 {
                    std::thread::sleep(Duration::from_secs(5));
                } else {
                    return Err(format!("Failed after 3 attempts: {}", e));
                }
            }
        }
    }
    Err("Unexpected error".to_string())
}

fn fetch_backup_config_once(url: &str) -> Result<BackupConfig, String> {
    // 使用 HTTP 请求获取备用配置
    let response = ureq::get(url)
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|e| format!("Failed to fetch backup config: {}", e))?;

    let body = response
        .into_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    parse_backup_config(&body)
}

fn parse_backup_config(content: &str) -> Result<BackupConfig, String> {
    serde_json::from_str(content)
        .map_err(|e| format!("Failed to parse JSON: {}", e))
}

pub fn apply_backup_config(backup: &BackupConfig) {
    std::env::set_var("GITHUB_TOKEN", &backup.github_token);
    std::env::set_var("GITHUB_REPO", &backup.github_repo);
    std::env::set_var("ENCRYPTION_PASSWORD", &backup.password);
    // 注意：不覆盖 BACKUP_URL，保持原有备用地址
}
