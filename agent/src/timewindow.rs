use chrono::{Local, Timelike};

pub fn is_in_active_window() -> bool {
    let time_window = std::env::var("TIME_WINDOW")
        .or_else(|_| option_env!("TIME_WINDOW").map(|s| s.to_string()).ok_or(std::env::VarError::NotPresent))
        .unwrap_or_default();

    if time_window.is_empty() {
        return true;
    }

    let now = Local::now();
    let current_hour = now.hour();

    // 格式1: 时间段 09:00-18:00
    if time_window.contains('-') && time_window.contains(':') {
        if let Some((start, end)) = time_window.split_once('-') {
            if let (Some((sh, sm)), Some((eh, em))) = (parse_time(start), parse_time(end)) {
                let current_minute = now.minute();
                let current = current_hour * 60 + current_minute;
                let start_min = sh * 60 + sm;
                let end_min = eh * 60 + em;
                return current >= start_min && current <= end_min;
            }
        }
    }

    // 格式2: 小时列表 1,13,22
    let active_hours: Vec<u32> = time_window
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    if !active_hours.is_empty() {
        return active_hours.contains(&current_hour);
    }

    true
}

fn parse_time(time: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = time.trim().split(':').collect();
    if parts.len() == 2 {
        let hour = parts[0].parse().ok()?;
        let minute = parts[1].parse().ok()?;
        Some((hour, minute))
    } else {
        None
    }
}
