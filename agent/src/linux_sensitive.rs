#[cfg(unix)]
pub fn collect_sensitive() -> String {
    use std::fs;
    let mut info = Vec::new();
    
    if let Ok(files) = fs::read_dir("/root") {
        info.push("Root files:".to_string());
        for f in files.filter_map(|e| e.ok()) {
            info.push(format!("  {}", f.path().display()));
        }
    }
    
    if let Ok(history) = fs::read_to_string("/root/.bash_history") {
        info.push(format!("Bash history: {} lines", history.lines().count()));
    }
    
    info.join("\n")
}

#[cfg(not(unix))]
pub fn collect_sensitive() -> String {
    "Not Linux".to_string()
}
