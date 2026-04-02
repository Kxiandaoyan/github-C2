use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 40000; // ~40KB per chunk (base64 encoded will be ~53KB)

#[derive(Serialize)]
struct FileUploadResponse {
    name: String,
    data: String,
}

#[derive(Deserialize)]
pub struct UploadChunkRequest {
    pub transfer_id: String,
    pub path: String,
    pub chunk_index: usize,
    pub total_chunks: usize,
    pub data: String,
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

pub fn handle_upload_chunk(request: UploadChunkRequest) -> Result<String, String> {
    let state_dir = get_upload_state_dir(&request.transfer_id)?;
    fs::create_dir_all(&state_dir).map_err(|e| format!("Error: {}", e))?;

    let meta_path = state_dir.join("meta.json");
    let meta = serde_json::json!({
        "path": request.path,
        "total_chunks": request.total_chunks,
    });
    fs::write(
        &meta_path,
        serde_json::to_vec(&meta).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Error: {}", e))?;

    let part_path = state_dir.join(format!("part_{:08}", request.chunk_index));
    let decoded = general_purpose::STANDARD
        .decode(request.data)
        .map_err(|e| format!("Error: {}", e))?;
    fs::write(part_path, decoded).map_err(|e| format!("Error: {}", e))?;

    let received = count_received_parts(&state_dir)?;
    if received < request.total_chunks {
        return Ok(format!(
            "[UPLOAD_PROGRESS] {}/{} {}",
            received, request.total_chunks, request.transfer_id
        ));
    }

    assemble_uploaded_file(&state_dir, &request.path, request.total_chunks)?;
    fs::remove_dir_all(&state_dir).ok();
    Ok(format!("[UPLOAD_COMPLETE] {}", request.path))
}

fn get_upload_state_dir(transfer_id: &str) -> Result<PathBuf, String> {
    let base = get_upload_base_dir()?;
    Ok(base.join(transfer_id))
}

fn get_upload_base_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let username = whoami::username();
        Ok(PathBuf::from(format!(
            r"C:\Users\{}\AppData\Local\.config\uploads",
            username
        )))
    }

    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            Ok(PathBuf::from("/var/lib/systemd/.uploads"))
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            Ok(PathBuf::from(format!("{}/.local/share/.uploads", home)))
        }
    }
}

fn count_received_parts(state_dir: &Path) -> Result<usize, String> {
    let mut count = 0;
    for entry in fs::read_dir(state_dir).map_err(|e| format!("Error: {}", e))? {
        let entry = entry.map_err(|e| format!("Error: {}", e))?;
        if entry.file_name().to_string_lossy().starts_with("part_") {
            count += 1;
        }
    }
    Ok(count)
}

fn assemble_uploaded_file(
    state_dir: &Path,
    target_path: &str,
    total_chunks: usize,
) -> Result<(), String> {
    let target = PathBuf::from(target_path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Error: {}", e))?;
    }

    let temp_target = target.with_extension("uploading_tmp");
    let mut output = fs::File::create(&temp_target).map_err(|e| format!("Error: {}", e))?;
    for idx in 0..total_chunks {
        let part_path = state_dir.join(format!("part_{:08}", idx));
        let data = fs::read(&part_path).map_err(|e| format!("Error: {}", e))?;
        std::io::Write::write_all(&mut output, &data).map_err(|e| format!("Error: {}", e))?;
    }
    drop(output);

    if target.exists() {
        fs::remove_file(&target).map_err(|e| format!("Error: {}", e))?;
    }
    fs::rename(&temp_target, &target).map_err(|e| format!("Error: {}", e))?;
    Ok(())
}
