//! failover.rs — 双通道故障转移（项 2；bin 专用，不落盘）。
//!
//! 方向（本次架构调整）：**Worker 为主，GitHub 为备**。理由：中继是操作者
//! 自己的基础设施（无 API 限额、无封号风险、D1 直读），GitHub 作为第三方
//! 依赖更脆弱，更适合当备用。链路状态全部驻内存，重启回到主通道。
//!
//! 状态机：
//!   - Worker（主）上任一取命令/发响应失败 → fail_count += 1；连续失败
//!     >= failover_threshold 且 GitHub 备份身份可用 → 切入备用
//!     （on_backup=true，计数清零）。阈值可由 Builder 配置（默认 3）。
//!   - 备用（GitHub）连续成功满 probe_after_oks 轮 → 做一次主通道探测
//!     （调用方负责，TCP 探中继）；探测成功（且 worker 重新注册成功）→
//!     切回主。探测失败 → ok_count 清零，再攒 probe_after_oks 轮。
//!   - 备用自身失败 → ok 连胜清零；连续失败 >= failover_threshold →
//!     允许立刻探测主（避免备用也挂时永远卡在备用）。
//!   - 任何成功 → fail_count 清零。
//!
//! 水位不归本模块管：worker 命令的 D1 id 水位持久化在 stor.rs 的 catalog
//! （worker_cursor，M1 修复），GitHub 评论号水位仍在 random-seed——两个
//! id 空间彻底分离，跨模式不再互相污染。
//!
//! 本模块不引用 Config（通道可用性由调用方判定后传入），保持双树无耦合；
//! 它只由 main.rs（bin 树）声明并使用。

use std::sync::{Mutex, OnceLock};

/// 默认主通道连续失败多少次后切入备用（可被 Builder 配置覆盖，见 init）。
const DEFAULT_FAILOVER_THRESHOLD: u32 = 3;
/// 默认备用上连续成功多少轮后探测一次主通道（可被 Builder 配置覆盖）。
const DEFAULT_PROBE_AFTER_OKS: u32 = 5;

struct Ctx {
    /// 主通道 id（worker = "w-<id8>"）；空 = 无 worker 通道（纯 github/notion）。
    worker_id: String,
    /// 备份通道 id（GitHub issue 号）；空 = 无备份。
    github_id: String,
    /// worker+github 双通道已启用（两者 init 时皆非空）。
    dual: bool,
    /// 当前是否工作于 GitHub 备份。
    on_backup: bool,
    /// 活动通道连续失败数。
    fail_count: u32,
    /// 备用通道连续成功轮数。
    ok_count: u32,
    /// 切换阈值（>=1，Builder 可配）。
    failover_threshold: u32,
    /// 探测间隔轮数（>=1，Builder 可配）。
    probe_after_oks: u32,
}

fn default_ctx() -> Ctx {
    Ctx {
        worker_id: String::new(),
        github_id: String::new(),
        dual: false,
        on_backup: false,
        fail_count: 0,
        ok_count: 0,
        failover_threshold: DEFAULT_FAILOVER_THRESHOLD,
        probe_after_oks: DEFAULT_PROBE_AFTER_OKS,
    }
}

fn ctx_guard() -> &'static Mutex<Ctx> {
    static CTX: OnceLock<Mutex<Ctx>> = OnceLock::new();
    CTX.get_or_init(|| Mutex::new(default_ctx()))
}

fn with_ctx<T>(f: impl FnOnce(&mut Ctx) -> T) -> T {
    match ctx_guard().lock() {
        Ok(mut g) => f(&mut g),
        Err(p) => {
            let mut g = p.into_inner();
            f(&mut g)
        }
    }
}

// ── 初始化 ──────────────────────────────────────────────────────────────────

/// 设置通道上下文。`worker_id`/`github_id` 任一为空表示该通道不可用；
/// 两者皆非空 → dual 模式（worker 主 / github 备）。
/// `threshold`/`probe_after` 来自 Builder 配置（项 2 控制面板），0 取默认。
pub fn init(
    worker_id: &str,
    github_id: &str,
    start_on_backup: bool,
    threshold: u32,
    probe_after: u32,
) {
    let mut ctx = match ctx_guard().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    ctx.worker_id = worker_id.to_string();
    // w-<id8> / unused 不能进 github 槽：否则 github_backup_id() 非空，
    // 补建重试会被跳过，dual 永远武装不起来。
    ctx.github_id = if is_real_github_backup_id(github_id) {
        github_id.trim().to_string()
    } else {
        String::new()
    };
    ctx.dual = !ctx.worker_id.is_empty() && is_real_github_backup_id(&ctx.github_id);
    ctx.failover_threshold = if threshold == 0 { DEFAULT_FAILOVER_THRESHOLD } else { threshold };
    ctx.probe_after_oks = if probe_after == 0 { DEFAULT_PROBE_AFTER_OKS } else { probe_after };
    ctx.on_backup = if start_on_backup && ctx.dual {
        crate::debug_log("failover: 启动时 Worker 主通道不可达，直接工作于 GitHub 备用通道");
        true
    } else {
        false
    };
    ctx.fail_count = 0;
    ctx.ok_count = 0;
}

/// dual 双通道已启用（路由谓词用：启用后按 on_backup 路由，而非 channel_type）。
pub fn dual_engaged() -> bool {
    with_ctx(|c| c.dual)
}

/// 真 GitHub issue 号：纯数字。`w-<id8>` / unused / 空都不是备份身份
/// （纯 worker 会把 w-id 同时塞进两个字段，不能据此升 dual）。
pub fn is_real_github_backup_id(id: &str) -> bool {
    let s = id.trim();
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// GitHub 备份 issue id 更新（降级时补建 issue 后写入）。
pub fn set_github_backup_id(id: &str) {
    with_ctx(|c| {
        if !is_real_github_backup_id(id) {
            return;
        }
        c.github_id = id.trim().to_string();
        if !c.worker_id.is_empty() && c.worker_id != c.github_id {
            c.dual = true;
        }
    });
}

/// 当前 GitHub 备份 issue id（可能为空——启动时未建成且尚未补建）。
pub fn github_backup_id() -> String {
    with_ctx(|c| c.github_id.clone())
}

/// worker 通道可用（worker_id 非空）。
pub fn worker_available() -> bool {
    with_ctx(|c| !c.worker_id.is_empty())
}

// ── 状态查询 ─────────────────────────────────────────────────────────────────

/// 当前是否工作于 GitHub 备用通道。
pub fn on_backup() -> bool {
    with_ctx(|c| c.on_backup)
}

/// 当前活动通道是否走 worker：
///   dual → !on_backup（主即 worker）；
///   非 dual → worker_id 非空（纯 worker 恒真；纯 github/notion 恒假）。
/// 路由谓词（post_comment / check_commands / check_kill）在 dual_engaged()
/// 时必须以此为准而非 config.is_worker()——否则 channel=worker 的 dual 构建
/// 在备用期间仍会把响应投向已死的 worker。
pub fn active_is_worker() -> bool {
    with_ctx(|c| {
        if c.worker_id.is_empty() {
            return false;
        }
        if c.dual {
            !c.on_backup
        } else {
            true
        }
    })
}

/// 当前活动通道应使用的 issue id。
pub fn active_issue_id() -> String {
    with_ctx(|c| {
        if c.dual && c.on_backup {
            c.github_id.clone()
        } else if !c.worker_id.is_empty() {
            c.worker_id.clone()
        } else {
            c.github_id.clone()
        }
    })
}

/// 强制切入备用（启动时主通道不可达）。
pub fn force_degrade() {
    with_ctx(|c| {
        if c.dual {
            c.on_backup = true;
            c.fail_count = 0;
            c.ok_count = 0;
            crate::debug_log("failover: 强制切到 GitHub 备用通道");
        }
    });
}

// ── 成败计数 ─────────────────────────────────────────────────────────────────

/// 活动通道一次成功（每轮最多一次）。
pub fn note_success() {
    with_ctx(|c| {
        if c.on_backup {
            c.ok_count += 1;
            if c.ok_count >= c.probe_after_oks {
                c.ok_count = c.probe_after_oks; // 封顶：本窗口内可探测
            }
        }
        c.fail_count = 0;
    });
}

/// 活动通道一次失败。
pub fn note_failure() {
    with_ctx(|c| {
        if !c.on_backup {
            c.fail_count += 1;
            if c.fail_count >= c.failover_threshold && c.dual {
                c.on_backup = true;
                c.fail_count = 0;
                c.ok_count = 0;
                crate::debug_log("failover: Worker 主通道连续失败，切到 GitHub 备用通道");
            }
        } else {
            c.ok_count = 0; // 备用自身失败 → 连胜清零
            c.fail_count = c.fail_count.saturating_add(1);
            // 备用也连续挂掉：打开探主窗口，下一轮 should_probe_primary()=true。
            // 主通道若也不可达，primary_probe_failed 会再清零，不会来回切。
            if c.fail_count >= c.failover_threshold {
                c.ok_count = c.probe_after_oks;
                crate::debug_log("failover: GitHub 备用连续失败，允许探测 Worker 主通道");
            }
        }
    });
}

/// 备用状态下是否应做一次主通道探测（攒满 probe_after_oks 轮成功）。
pub fn should_probe_primary() -> bool {
    with_ctx(|c| c.on_backup && c.ok_count >= c.probe_after_oks)
}

/// 主通道探测成功：切回 Worker 主通道。
pub fn primary_probe_succeeded() {
    with_ctx(|c| {
        c.on_backup = false;
        c.fail_count = 0;
        c.ok_count = 0;
        crate::debug_log("failover: Worker 主通道探测成功，切回主通道");
    });
}

/// 主通道探测失败：留在备用，ok_count 清零——下一次探测需再攒满
/// probe_after_oks 轮成功（避免主通道长时间故障时每轮都做 8s 探测）。
pub fn primary_probe_failed() {
    with_ctx(|c| {
        c.ok_count = 0;
        c.fail_count = 0; // 探主失败后重新累计备用失败，避免每轮都打主通道
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset(worker: &str, github: &str, on_backup: bool, threshold: u32, probe: u32) -> std::sync::MutexGuard<'static, ()> {
        static TEST_LOCK: Mutex<()> = Mutex::new(());
        let g = match TEST_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        init(worker, github, on_backup, threshold, probe);
        g
    }

    fn reinit(worker: &str, github: &str, on_backup: bool, threshold: u32, probe: u32) {
        init(worker, github, on_backup, threshold, probe);
    }

    #[test]
    fn dual_normal_runs_on_worker_and_degrades_to_github() {
        let _g = reset("w-abcd1234", "42", false, 3, 5);
        assert!(dual_engaged());
        assert!(active_is_worker());
        assert_eq!(active_issue_id(), "w-abcd1234");
        note_failure();
        note_failure();
        assert!(!on_backup());
        note_failure();
        assert!(on_backup());
        assert!(!active_is_worker());
        assert_eq!(active_issue_id(), "42");
    }

    #[test]
    fn empty_github_id_never_degrades() {
        let _g = reset("w-abcd1234", "", false, 3, 5);
        note_failure();
        note_failure();
        note_failure();
        assert!(!on_backup());
        assert_eq!(active_issue_id(), "w-abcd1234");
    }

    #[test]
    fn backup_failures_allow_primary_probe() {
        let _g = reset("w-abcd1234", "42", true, 3, 5);
        assert!(!should_probe_primary());
        note_failure();
        note_failure();
        assert!(!should_probe_primary());
        note_failure();
        assert!(should_probe_primary());
        primary_probe_failed();
        assert!(!should_probe_primary());
    }

    #[test]
    fn pure_worker_routes_to_worker_without_dual() {
        let _g = reset("w-abcd1234", "", false, 3, 5);
        assert!(!dual_engaged());
        assert!(active_is_worker());
        // 纯 worker 没有 github 备份：失败再多也不切。
        for _ in 0..6 {
            note_failure();
        }
        assert!(!on_backup());
    }

    #[test]
    fn same_id_in_both_slots_is_not_dual() {
        // 纯 worker 的 startup 形态：create_or_load_issue 返回的 w-<id8> 同时
        // 落进 worker_id 与 github_id——必须不判成 dual（否则连败后切去
        // 拿 unused 凭据打 GitHub，纯 worker 变聋）。
        let _g = reset("w-abcd1234", "w-abcd1234", false, 3, 5);
        assert!(!dual_engaged());
        assert!(active_is_worker());
        for _ in 0..6 {
            note_failure();
        }
        assert!(!on_backup());
        assert_eq!(active_issue_id(), "w-abcd1234");
    }

    #[test]
    fn set_github_backup_id_rejects_worker_shaped_id() {
        let _g = reset("w-abcd1234", "", false, 3, 5);
        set_github_backup_id("w-abcd1234");
        assert!(!dual_engaged());
        assert!(github_backup_id().is_empty());
        set_github_backup_id("unused");
        assert!(!dual_engaged());
        assert!(github_backup_id().is_empty());
        set_github_backup_id("42");
        assert!(dual_engaged());
        assert_eq!(github_backup_id(), "42");
    }

    #[test]
    fn unused_or_wid_github_slot_is_sanitized() {
        let _g = reset("w-abcd1234", "unused", false, 3, 5);
        assert!(!dual_engaged());
        assert!(github_backup_id().is_empty());
        reinit("w-abcd1234", "w-abcd1234", false, 3, 5);
        assert!(github_backup_id().is_empty());
        assert!(is_real_github_backup_id("42"));
        assert!(!is_real_github_backup_id("w-abcd1234"));
        assert!(!is_real_github_backup_id("unused"));
    }

    #[test]
    fn pure_github_routes_to_github() {
        let _g = reset("", "42", false, 3, 5);
        assert!(!dual_engaged());
        assert!(!active_is_worker());
        assert_eq!(active_issue_id(), "42");
    }

    #[test]
    fn late_github_id_upgrades_to_dual() {
        let _g = reset("w-abcd1234", "", true, 3, 5);
        assert!(!dual_engaged());
        set_github_backup_id("42");
        assert!(dual_engaged());
        assert_eq!(github_backup_id(), "42");
        // start_on_backup 无效（当时非 dual）——重新降级走 note_failure 路径。
        assert!(!on_backup());
    }

    #[test]
    fn probe_success_rereads_as_worker() {
        let _g = reset("w-abcd1234", "42", true, 3, 5);
        assert_eq!(active_issue_id(), "42");
        primary_probe_succeeded();
        assert!(!on_backup());
        assert_eq!(active_issue_id(), "w-abcd1234");
        assert!(active_is_worker());
    }

    #[test]
    fn placeholder_wid_after_register_fail_stays_dual_on_github() {
        // 启动注册失败仍传入确定性 w-<id8> + start_on_backup，才能探回主通道。
        let _g = reset("w-abcd1234", "42", true, 3, 5);
        assert!(dual_engaged());
        assert!(on_backup());
        assert!(!active_is_worker());
        assert_eq!(active_issue_id(), "42");
        for _ in 0..5 {
            note_success();
        }
        assert!(should_probe_primary());
    }

    #[test]
    fn missing_worker_id_cannot_engage_dual() {
        let _g = reset("", "42", true, 3, 5);
        assert!(!dual_engaged());
        assert!(!on_backup());
        assert!(!active_is_worker());
        assert_eq!(active_issue_id(), "42");
        assert!(!should_probe_primary());
    }
}
