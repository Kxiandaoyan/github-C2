//! schedule.rs — agent 内部调度（bin 与 SO 双 crate 根共用）。
//!
//! 响应 `schedule ...` 控制命令，由 agent 自己在轮询循环里判断到期，不依赖
//! crontab、不做外部调用。表驻内存；bin 侧经 stor.rs 把快照落盘（重启保留），
//! SO 侧只驻内存（进程生命周期内有效）。
//!
//! 命令语法：
//!   schedule add <间隔秒> <命令...>      # 新增周期任务（间隔下限 10s）
//!   schedule ls                          # 列出全部任务
//!   schedule rm <id>                     # 删除指定任务
//!   schedule clear                       # 清空全部任务

use std::sync::{Mutex, OnceLock};

/// 持久化了哪些字段无需求——bin 侧仅通过 snapshot/restore JSON 字符串桥连 stor。
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SchedEntry {
    pub id: u64,
    pub interval_secs: u64,
    pub command: String,
    /// 下次到期 Unix 秒（校准时钟，见 net::now_unix_secs）。
    pub next_due_unix: i64,
}

fn table() -> &'static Mutex<Vec<SchedEntry>> {
    static T: OnceLock<Mutex<Vec<SchedEntry>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(Vec::new()))
}

fn next_id() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// 处理 `schedule ...` 控制命令；非 schedule 开头时返回 None 供命令分发链继续。
pub fn handle_command(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if trimmed != "schedule" && !trimmed.starts_with("schedule ") {
        return None;
    }
    let rest = trimmed.strip_prefix("schedule").unwrap_or("").trim();
    if rest.is_empty() || rest == "ls" || rest == "list" {
        return Some(list());
    }
    if rest == "clear" {
        if let Ok(mut g) = table().lock() {
            g.clear();
        }
        notify_changed();
        return Some("schedule cleared".to_string());
    }
    if let Some(v) = rest.strip_prefix("rm ") {
        let id: u64 = match v.trim().parse() {
            Ok(id) if id > 0 => id,
            _ => return Some("Usage: schedule rm <id>".to_string()),
        };
        let mut removed = false;
        if let Ok(mut g) = table().lock() {
            let before = g.len();
            g.retain(|e| e.id != id);
            removed = g.len() < before;
        }
        let reply = if removed {
            format!("schedule #{} removed", id)
        } else {
            format!("schedule #{} not found", id)
        };
        if removed {
            notify_changed();
        }
        return Some(reply);
    }
    if let Some(v) = rest.strip_prefix("add ") {
        let parts: Vec<&str> = v.splitn(2, ' ').collect();
        let (interval_s, command) = match parts.as_slice() {
            [int_s, cmd_s] if !cmd_s.trim().is_empty() => {
                match int_s.trim().parse::<u64>() {
                    Ok(i) if i >= 10 && i <= 7 * 86400 => (i, cmd_s.to_string()),
                    _ => return Some("Usage: schedule add <间隔秒10..604800> <命令...>".to_string()),
                }
            }
            _ => return Some("Usage: schedule add <间隔秒> <命令...>".to_string()),
        };
        let id = next_id();
        let now = crate::net::now_unix_secs();
        let entry = SchedEntry {
            id,
            interval_secs: interval_s,
            command: command.clone(),
            next_due_unix: now + interval_s as i64,
        };
        if let Ok(mut g) = table().lock() {
            g.push(entry);
        }
        notify_changed();
        return Some(format!(
            "schedule #{} added: every {}s -> {}", id, interval_s, command)
        );
    }
    Some("Usage: schedule add <间隔秒> <命令...> | schedule ls | schedule rm <id> | schedule clear".to_string())
}

fn list() -> String {
    let snapshot = match table().lock() {
        Ok(g) => g.clone(),
        Err(p) => (*(p.into_inner())).clone(),
    };
    if snapshot.is_empty() {
        return "schedule: (empty)".to_string();
    }
    let mut out = "schedule:".to_string();
    for e in &snapshot {
        out.push_str(&format!("\n  #{} every {}s next-in-{}s: {}", e.id,
            e.interval_secs,
            (e.next_due_unix - crate::net::now_unix_secs()).max(0),
            e.command));
    }
    out
}

/// 取出所有到期任务并重新安排下一轮到期时间。返回 (id, command_id, command) 列表。
///
/// 语义：到期即执行一次（错过的周期不补发，离线 1 小时回来也只执行一次）。
/// 审计修复（bug#13）：本轮额度（max_per_cycle）满时**不推进** next_due——
/// 到期时间保持原值，下一轮循环先执行它（真正的 FIFO 顺延）；旧实现把
/// next_due 推到 now+interval，等于把本次到期静默丢弃一整个周期。
/// changed 仅在确有到期项时置位，避免每个轮询周期都触发一次无谓落盘。
pub fn due_now(max_per_cycle: usize) -> Vec<(u64, String, String)> {
    let now = crate::net::now_unix_secs();
    let mut due = Vec::new();
    let mut changed = false;
    if let Ok(mut g) = table().lock() {
        let mut next: Vec<SchedEntry> = Vec::new();
        for mut e in g.drain(..) {
            if e.next_due_unix <= now && due.len() < max_per_cycle {
                due.push((e.id, format!("sched-{}", e.id), e.command.clone()));
                e.next_due_unix = now + e.interval_secs as i64;
                changed = true;
            }
            // 额度已满的到期项：next_due 原样保留，下轮先执行
            next.push(e);
        }
        *g = next;
    }
    if changed {
        notify_changed(); // 下次到期时间已推进——落盘，避免重启后立即重复触发
    }
    due
}

// ── bin 侧持久化桥（stor.rs 调用；SO 侧不落盘）──────────────────────────────

pub fn snapshot_json() -> Option<String> {
    let snap = match table().lock() {
        Ok(g) => g.clone(),
        Err(p) => (*(p.into_inner())).clone(),
    };
    serde_json::to_string(&snap).ok()
}

pub fn restore_json(json: &str) {
    if let Ok(entries) = serde_json::from_str::<Vec<SchedEntry>>(json) {
        if let Ok(mut g) = table().lock() {
            *g = entries;
        }
    }
}

// ── 变更通知：bin 树注册为目录落盘（stor.rs）；SO 树不注册、默认空 ─────────
//
// 用注册回调而非 cfg(feature) 判断构建侧：SO 的生产构建与 cross-check
// 都可能不带 `shared-lib-entry` feature，直接引用 crate::stor 会在这两种
// 场景编译失败；回调注册让本模块在双 crate 根下都无需条件编译。

static ON_CHANGE: OnceLock<Mutex<Option<fn()>>> = OnceLock::new();

/// bin 树在启动时调用，把调度表变更接入目录持久化。
pub fn set_on_change(f: Option<fn()>) {
    let mut locked = match ON_CHANGE.get_or_init(|| Mutex::new(None)).lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    *locked = f;
}

fn notify_changed() {
    if let Ok(g) = ON_CHANGE.get_or_init(|| Mutex::new(None)).lock() {
        if let Some(f) = *g {
            f();
        }
    }
}
