# Cloudflare 网页控制台部署教程（零命令行）

全程在 https://dash.cloudflare.com 完成，无需安装 wrangler。
唯一要在本机做的事：最后跑一次 `test_relay.sh` 验证。

## 准备

- 一个 Cloudflare 账号（免费版即可）
- 生成两串随机值当密钥（Git Bash：`openssl rand -hex 16` 各跑一次，或用任意密码生成器）：
  - `AUTH 值` —— 中转密钥（记下来，之后控制端/agent 都要填）
  - `PATH 值` —— 随机路径前缀（仅数字字母连字符，如 `a3f9k2-status`）

## 第 1 步：建 Worker

1. 左侧 **Workers & Pages** → **Create** → 选 **Worker** → 名字填 `c2relay` → **Deploy**
2. 部署成功后点 **Edit code**（编辑代码）
3. 打开本仓库 `cloudflare-worker/worker.js`，全选复制，**替换**编辑器里的全部内容 → **Save and Deploy**

## 第 2 步：建 D1 数据库并执行建表

1. 左侧 **Storage & Databases** → **D1 SQL Database** → **Create**
   名字 `c2relay` → 创建
2. 进入该库 → **Console**（控制台）标签
3. 打开本仓库 `cloudflare-worker/schema.sql`，把**全部内容**粘进 Console 输入框 → **Execute**
   （应显示 3 张表创建成功：agents / comments / kill_flag）
4. 在库的 **Settings** 页找到 **Database ID**，复制留用（下一步要贴）

## 第 3 步：绑定 D1 到 Worker（变量名必须是 DB）

1. 回到 **Workers & Pages** → `c2relay` → **Settings**
2. **Bindings** → **Add** → 选 **D1 database**
   - Variable name: `DB` ← **必须 exactly 是 DB**（代码里读 env.DB）
   - D1 database: 选刚建的 `c2relay`
3. 保存

## 第 4 步：设置两道门禁（Secrets）

仍在 `c2relay` → **Settings** → **Variables and Secrets** → **Add**：

| Type | Name | Value |
|---|---|---|
| Secret | `C2_AUTH` | 准备阶段的 AUTH 值 |
| Secret | `PATH_SECRET` | 准备阶段的 PATH 值 |

（Deploy 后生效。之后所有请求走 `https://<域名>/<PATH值>/...` 并带 `X-C2-Auth` 头。）

## 第 5 步：加定时清理（Cron）

`c2relay` → **Settings** → **Trigger Events / Cron Triggers** → **Add**
Cron 表达式：`0 * * * *`（每小时清理：每 agent 每方向保最新 500 条、14 天未活跃 agent 删除）

## 第 6 步（可选但推荐）：绑自定义域名 = 双域名互备

`c2relay` → **Settings** → **Domains & Routes** → **Add** → **Custom domain**
选你托管在 Cloudflare 的域名（如 `cdn.你的域.com`）。
默认的 `c2relay.<你的子域>.workers.dev` **保持启用不动** —— 于是两个域名同时在线，
任一域名出问题（过期/被墙）agent 自动切到另一个。

## 第 7 步：验证（本机 Git Bash）

```bash
cd "D:\Code_Space\github-c2 (2)\cloudflare-worker"
BASE=https://c2relay.你的子域.workers.dev \
PATH_SECRET=<PATH值> AUTH=<AUTH值> \
bash test_relay.sh
# 绑了自定义域再加：BASE2=https://cdn.你的域.com 一并验证双域名
```

期望输出：`===== relay matrix: 12 passed, 0 failed =====`

全绿后：控制端 Settings 填 Worker URLs（两个域名逗号分隔）+ Worker Secret（AUTH 值），
Builder 通道选 ☁️ Worker 同样填这两个值，即可接入。把验证输出发我（不用发密钥）。
