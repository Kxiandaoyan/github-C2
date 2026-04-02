use base64::{engine::general_purpose, Engine as _};
use serde::Serialize;

const CHUNK_SIZE: usize = 40000; // ~40KB per chunk (base64 encoded will be ~53KB)

#[derive(Serialize)]
struct FileUploadResponse {
    name: String,
    data: String,
}

pub fn upload_file(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Error: {}", e))?;
    let name = std::path::Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let encoded = if data.len() <= CHUNK_SIZE {
        general_purpose::STANDARD.encode(&data)
    } else {
        // For large files, return chunked format
        let mut result = String::from("[FILE_START]\n");
        for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            result.push_str(&format!("[CHUNK_{}]\n", i));
            result.push_str(&general_purpose::STANDARD.encode(chunk));
            result.push('\n');
        }
        result.push_str("[FILE_END]");
        result
    };

    serde_json::to_string(&FileUploadResponse {
        name,
        data: encoded,
    })
    .map_err(|e| format!("Error: {}", e))
}

pub fn download_file(path: &str, base64_data: &str) -> Result<String, String> {
    let data = if base64_data.contains("[FILE_START]") {
        // Reassemble chunked file
        let mut full_data = Vec::new();
        for line in base64_data.lines() {
            if line.starts_with("[CHUNK_") {
                continue;
            }
            if line == "[FILE_START]" || line == "[FILE_END]" {
                continue;
            }
            if let Ok(chunk) = general_purpose::STANDARD.decode(line) {
                full_data.extend_from_slice(&chunk);
            }
        }
        full_data
    } else {
        general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| format!("Error: {}", e))?
    };

    std::fs::write(path, data).map_err(|e| format!("Error: {}", e))?;
    Ok("File saved".to_string())
}
