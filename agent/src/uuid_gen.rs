use std::fs;
use std::path::PathBuf;

pub fn get_or_create_agent_id() -> String {
    let id_file = get_id_file_path();

    if let Ok(content) = fs::read_to_string(&id_file) {
        let trimmed = content.trim();
        if !trimmed.is_empty() && trimmed.len() == 36 {
            return trimmed.to_string();
        }
    }

    let uuid = generate_uuid();
    if let Some(parent) = id_file.parent() {
        let _ = fs::create_dir_all(parent);
    }

    // 重试写入 3 次
    for _ in 0..3 {
        if fs::write(&id_file, &uuid).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    uuid
}

fn get_id_file_path() -> PathBuf {
    #[cfg(windows)]
    {
        let username = whoami::username();
        PathBuf::from(format!(r"C:\Users\{}\AppData\Local\.config\agent_id.txt", username))
    }
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            PathBuf::from("/var/lib/systemd/.agent_id")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(format!("{}/.local/share/.agent_id", home))
        }
    }
}

fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        rng.gen::<u32>(),
        rng.gen::<u16>(),
        rng.gen::<u16>() & 0x0fff,
        rng.gen::<u16>() & 0x3fff | 0x8000,
        rng.gen::<u64>() & 0xffffffffffff
    )
}
