// en.js — English language pack (键=中文原文，值=英文)
// 覆盖所有主要 UI 区域：导航、设置、Builder、隧道、升级、文件管理、toast
window.LANG_EN = {
  // ═══ Navigation ═══
  "终端": "Terminal", "文件管理": "Files", "文件": "Files",
  "系统信息": "SysInfo", "资料库": "Library", "报告": "Report",
  "升级": "Upgrade", "隧道": "Tunnel", "扫描": "Scan", "设置": "Settings",
  "生成器": "Builder", "反弹Shell": "Rev Shell",
  "MCP 接入": "MCP", "控制台工具": "Console Tools",

  // ═══ Common Actions ═══
  "刷新": "Refresh", "保存": "Save", "删除": "Delete", "关闭": "Close",
  "确认": "Confirm", "取消": "Cancel", "发送": "Send", "停止": "Stop",
  "启动": "Start", "连接": "Connect", "断开": "Disconnect", "下载": "Download",
  "上传": "Upload", "清空": "Clear All", "搜索": "Search", "编辑": "Edit",
  "新建": "New", "预览": "Preview", "复制": "Copy", "粘贴": "Paste",
  "安装": "Install", "卸载": "Uninstall", "清理": "Cleanup",

  // ═══ Agent Status ═══
  "在线": "Online", "空闲": "Idle", "离线": "Offline", "安静": "Quiet",
  "未知": "Unknown", "掉线": "Down", "已配置": "Configured",
  "未配置": "Not configured", "运行中": "Running", "已停止": "Stopped",
  "等待中": "Waiting", "未运行": "Not running",

  // ═══ Builder Page ═══
  "构建配置": "Build Configuration",
  "源码路径": "Source Path",
  "通道": "Channel",
  "通信 Secret": "Comm Secret",
  "备用配置 URL": "Backup Config URL",
  "轮询间隔 (秒)": "Poll Interval (s)",
  "活跃时段": "Active Hours",
  "调试日志": "Debug Log",
  "目标架构": "Target Architecture",
  "发布标识": "Release Tag",
  "保存配置": "Save Config",
  "编译 Agent": "Build Agent",
  "压缩 (strip + UPX)": "Compress (strip + UPX)",
  "字段速查": "Field Guide",
  "守卫与伪装（可选 OPSEC）": "Guards & Disguise (Optional OPSEC)",
  "GitHub 单通道": "GitHub Only",
  "Notion 单通道": "Notion Only",
  "Worker 单通道": "Worker Only",
  "双通道（Worker 主 + GitHub 备）": "Dual (Worker primary + GitHub backup)",
  "切换阈值 (轮)": "Failover Threshold",
  "主探测间隔 (轮)": "Probe Interval",
  "Worker 主 URLs": "Worker Primary URLs",
  "Worker Secret": "Worker Secret",
  "Worker Path": "Worker Path",
  "GitHub Token (备用):": "GitHub Token (backup):",
  "Repo (备用, owner/repo):": "Repo (backup, owner/repo):",
  "通信加密 Secret": "Encryption Secret",
  "进程伪装名": "Process Name",
  "落地路径": "Drop Path",
  "内存下限 (MB)": "Min Memory (MB)",

  // ═══ Settings Page ═══
  "控制器设置": "Controller Settings",
  "GitHub 通道": "GitHub Channel",
  "Notion 通道": "Notion Channel",
  "Worker 中继": "Worker Relay",
  "控制器解密密码": "Decryption Password",
  "面板登录凭据": "Panel Login",
  "轮询与清理": "Polling & Cleanup",
  "Agent 升级": "Agent Upgrade",
  "保存设置": "Save Settings",
  "仓库列表 (逗号分隔)": "Repositories (comma-separated)",
  "轮询间隔(秒)": "Poll Interval (s)",
  "保留 Issue 数量": "Keep Issues",
  "过期天数": "Stale Days",
  "用户名": "Username", "密码": "Password",
  "面板用户名": "Panel Username", "面板密码": "Panel Password",
  "通信 Secret（AES 密钥）": "Comm Secret (AES key)",
  "GitHub Token:": "GitHub Token:",
  "仓库 (owner/repo):": "Repo (owner/repo):",
  "Notion Token:": "Notion Token:",
  "Database ID:": "Database ID:",
  "Worker URLs:": "Worker URLs:",

  // ═══ Tunnel Page ═══
  "Admin 服务端": "Admin Server",
  "隧道 Secret": "Tunnel Secret",
  "SOCKS5 端口": "SOCKS5 Port",
  "监听端口": "Listen Port",
  "启动服务端": "Start Server",
  "停止服务端": "Stop Server",
  "目标端（Agent 内置，无需落地文件）": "Agent side (built-in, no file drop)",
  "向当前选中 Agent 下发隧道启动命令（内置节点，无文件落地）": "Send tunnel start command to selected agent (built-in, fileless)",
  "停止 Agent 内置隧道节点——纯内存实现，停止即清理，无文件残留": "Stop agent tunnel node (memory-only, clean on stop)",
  "启动控制器本机的 stowaway_admin 服务端": "Start local stowaway_admin server",

  // ═══ Upgrade Page ═══
  "二进制下载 URL": "Binary Download URL",
  "保存路径": "Save Path",
  "下载并升级": "Download & Upgrade",
  "仅发送升级命令": "Send Upgrade Cmd Only",
  "升级流程": "Upgrade Flow",
  "手动升级": "Manual Upgrade",

  // ═══ File Manager ═══
  "当前路径": "Current Path",
  "等待 Agent 返回目录列表": "Waiting for directory listing",
  "Agent 离线 · 显示缓存数据": "Agent offline · showing cached data",
  "文件名": "Name", "大小": "Size", "类型": "Type", "修改时间": "Modified",
  "文件预览": "File Preview",
  "上传文件到 Agent": "Upload file to agent",
  "新建笔记": "New Note",

  // ═══ SysInfo / Sensitive ═══
  "采集系统信息": "Collect SysInfo",
  "采集敏感数据": "Collect Sensitive Data",
  "系统信息 — ": "SysInfo — ",
  "敏感数据 — ": "Sensitive — ",

  // ═══ WS Shell ═══
  "反弹 Shell（WS Shell）": "Reverse Shell (WS Shell)",
  "启动 cliws 桥接": "Start cliws bridge",
  "下发反弹命令": "Send reverse cmd",
  "断开反弹会话": "Disconnect session",

  // ═══ MCP ═══
  "MCP 接入": "MCP Integration",

  // ═══ Worker Admin ═══
  "一键部署中转": "Deploy Relay",
  "中转部署成功": "Relay deployed",
  "Cloudflare API Token": "Cloudflare API Token",
  "Worker 名称": "Worker Name",

  // ═══ Toast Messages ═══
  "已保存": "Saved", "已发送": "Sent", "已停止": "Stopped",
  "保存失败": "Save failed", "发送失败": "Send failed",
  "删除成功": "Deleted", "操作成功": "Success",
  "请先选择 agent": "Select an agent first",
  "请先选择 Agent": "Select an agent first",
  "构建已启动": "Build started",
  "配置已保存": "Config saved",
  "未配置任何通道": "No channel configured",
  "通信加密 Secret 未设置": "Encryption secret not set",
  "已设置，留空": "Set, leave empty",
  "命令已发送": "Command sent",
  "加载中…": "Loading…",
  "刷新中…": "Refreshing…",
  "已启动": "Started",
  "无任何活动记录": "No activity record",
  "前活跃": "ago active",
  "分钟前活跃": "min ago",
  "最后活跃于": "Last active",

  // ═══ Report ═══
  "生成报告": "Generate Report",

  // ═══ Library ═══
  "资料库": "Library",
  "全部文件": "All Files",
  "笔记": "Notes",

  // ═══ Scan ═══
  "扫描目标": "Scan Target",
  "扫描结果": "Scan Result",

  // ═══ Misc Labels ═══
  "回连 IP": "Callback IP",
  "回连端口": "Callback Port",
  "目标架构": "Architecture",
  "操作": "Action",
  "状态": "Status",
  "备注": "Note",
  "版本": "Version",
  "渠道": "Channel",
  "主机名": "Hostname",
  "权限": "Privilege",
  "内核": "Kernel",
  "架构：": "Architecture:",
  "最后活跃": "Last Active",
};
