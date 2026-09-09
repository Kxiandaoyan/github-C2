use chrono::{FixedOffset, Timelike, Utc};

fn beijing_now() -> chrono::DateTime<FixedOffset> {
    let bj = FixedOffset::east_opt(8 * 3600).expect("valid UTC+8 offset");
    // C/E：时间源统一走网络层校准时钟（host 时钟 ± 已校准的偏移），
    // 活动窗口、日抖动与启动抖动都以校准后的“当前时间”为准，
    // 避免 host 时钟漂移导致窗口判断偏移。
    match chrono::DateTime::from_timestamp(crate::net::now_unix_secs(), 0) {
        Some(dt) => dt.with_timezone(&bj),
        None => Utc::now().with_timezone(&bj), // 保守回退：转换失败则用本机时钟
    }
}

// ─── Deterministic daily jitter ───────────────────────────────────────────────

/// Compute a deterministic jitter in minutes from an arbitrary seed string.
/// Uses FNV-1a 64-bit hash; output range [-max_jitter, +max_jitter].
/// Same seed always produces the same value; include the date to vary daily.
fn daily_jitter_minutes(seed: &str, max_jitter_mins: i32) -> i32 {
    let max_jitter_mins = max_jitter_mins.max(0);
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    let range = (max_jitter_mins * 2 + 1) as u64;
    (h % range) as i32 - max_jitter_mins
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Check whether the current Beijing time is within the active window (with daily jitter).
///
/// `agent_id` is used to compute a per-agent daily offset, so different agents have
/// slightly staggered active windows — preventing a recognisable traffic pulse when
/// many agents enter/exit the window simultaneously.
///
/// Jitter design:
/// - Daily deterministic offset: ±20 min, derived from hash(agent_id + date + "S/E")
/// - Runtime random noise: ±5 min extra, preventing exact boundary measurement
/// - Each call is evaluated independently; on/off transitions are not predictable
pub fn is_in_active_window_with_jitter(agent_id: &str) -> bool {
    let time_window = get_time_window();
    if time_window.is_empty() {
        return true;
    }

    let now = beijing_now();
    let today = now.format("%Y%m%d").to_string();
    let current = now.hour() * 60 + now.minute();

    // Format: "HH:MM-HH:MM"
    if time_window.contains('-') && time_window.contains(':') {
        if let Some((start_str, end_str)) = time_window.split_once('-') {
            if let (Some((sh, sm)), Some((eh, em))) = (parse_time(start_str), parse_time(end_str)) {
                let base_start = (sh * 60 + sm) as i32;
                let base_end   = (eh * 60 + em) as i32;

                // Daily deterministic offset (±20 min)
                let s_jitter = daily_jitter_minutes(
                    &format!("{}{}S{}", agent_id, today, time_window), 20,
                );
                let e_jitter = daily_jitter_minutes(
                    &format!("{}{}E{}", agent_id, today, time_window), 20,
                );

                // Hourly deterministic noise (±5 min): changes each hour, not each call.
                // Using the current hour in the seed prevents per-call flapping while
                // still varying the boundary over time to avoid exact fingerprinting.
                let current_hour = now.hour();
                let s_noise = daily_jitter_minutes(
                    &format!("{}{}SN{}{}", agent_id, today, time_window, current_hour), 5,
                );
                let e_noise = daily_jitter_minutes(
                    &format!("{}{}EN{}{}", agent_id, today, time_window, current_hour), 5,
                );

                let start_min = (base_start + s_jitter + s_noise).max(0).min(1439) as u32;
                let end_min   = (base_end   + e_jitter + e_noise).max(0).min(1439) as u32;

                return if start_min <= end_min {
                    current >= start_min && current <= end_min
                } else {
                    // Cross-midnight window (e.g. 22:00-06:00)
                    current >= start_min || current <= end_min
                };
            }
        }
    }

    // Format: "9,10,11,..." hour list
    let active_hours: Vec<u32> = time_window
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    if !active_hours.is_empty() {
        // Apply daily offset before checking, making exact hour transitions unpredictable
        let h_jitter = daily_jitter_minutes(
            &format!("{}{}H", agent_id, today), 25,
        );
        let adjusted = (current as i32 + h_jitter).max(0).min(1439) as u32;
        let adj_hour = adjusted / 60;
        // Only use the jitter-adjusted hour to avoid a wider window than configured
        return active_hours.contains(&adj_hour);
    }

    true
}

/// Non-jitter version (backward compatibility).

/// Random sleep duration (seconds) when outside the active window.
///
/// Range: 5–20 min base + 0–120 s fine noise.
/// A fixed 600 s interval would be a recognisable traffic pattern.
pub fn outside_window_sleep_secs() -> u64 {
    let base:   u64 = 300;                        // 5 min floor
    let spread: u64 = rand::random::<u64>() % 900; // 0-15 min random increment
    let fine:   u64 = rand::random::<u64>() % 120; // 0-120 s fine noise
    base + spread + fine
}

/// Random startup delay (seconds) before the first GitHub API call.
///
/// Prevents multiple agents restarted in the same batch (e.g. cron @reboot, system recovery)
/// from hitting the API simultaneously and creating a recognisable concurrent spike.
///
/// Design:
/// - Daily deterministic base offset (from agent_id) — different agents start at different times
/// - Runtime random noise (0-30 s) — same agent doesn't start at the exact same time each reboot
pub fn startup_jitter_secs(agent_id: &str) -> u64 {
    let today = beijing_now().format("%Y%m%d").to_string();
    let seed  = format!("{}{}startup", agent_id, today);
    let base  = (daily_jitter_minutes(&seed, 30).unsigned_abs() as u64) + 3; // 3-33 s
    let noise = rand::random::<u64>() % 30; // 0-30 s
    (base + noise).min(90) // cap at 90 s
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn get_time_window() -> String {
    std::env::var("TIME_WINDOW")
        .or_else(|_| {
            option_env!("TIME_WINDOW")
                .map(|s| s.to_string())
                .ok_or(std::env::VarError::NotPresent)
        })
        .unwrap_or_default()
}

fn parse_time(time: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = time.trim().split(':').collect();
    if parts.len() == 2 {
        let hour: u32   = parts[0].parse().ok()?;
        let minute: u32 = parts[1].parse().ok()?;
        if hour < 24 && minute < 60 {
            return Some((hour, minute));
        }
    }
    None
}
