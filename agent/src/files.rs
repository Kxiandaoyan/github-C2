use std::fs;

pub fn list_files(path: &str) -> String {
    // Windows特殊处理：空路径或"DRIVES"返回磁盘列表
    #[cfg(windows)]
    if path.is_empty() || path == "DRIVES" {
        return list_drives();
    }

    // Linux下处理路径
    #[cfg(unix)]
    let path = if path.is_empty() {
        "/"
    } else if !path.starts_with('/') {
        // 相对路径转绝对路径
        return match std::env::current_dir() {
            Ok(cwd) => list_files(&cwd.join(path).to_string_lossy()),
            Err(_) => "Error: Cannot get current directory".to_string(),
        };
    } else {
        path
    };

    match fs::read_dir(path) {
        Ok(entries) => {
            let mut result = String::from("[FILES]\n");
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let is_dir = path.is_dir();
                let size = if is_dir {
                    0
                } else {
                    fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
                };
                result.push_str(&format!("{}|{}|{}\n", name, if is_dir { "DIR" } else { "FILE" }, size));
            }
            result
        }
        Err(e) => format!("Error: {}", e),
    }
}

pub fn read_file(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("Error: {}", e))
}

pub fn write_file(path: &str, data: &[u8]) -> Result<String, String> {
    fs::write(path, data)
        .map(|_| "File written".to_string())
        .map_err(|e| format!("Error: {}", e))
}

#[cfg(windows)]
fn list_drives() -> String {
    let mut result = String::from("[FILES]\n");
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:\\", letter as char);
        if std::path::Path::new(&drive).exists() {
            result.push_str(&format!("{}|DIR|0\n", drive));
        }
    }
    result
}
