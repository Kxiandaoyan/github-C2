# 手动部署 Cloudflare Worker 中继

控制台「设置 → 一键部署 Worker」能自动做完下面这些事。这一页是**不用一键、自己在 Cloudflare 里搭中继**的说明。中继只负责搬加密信封，**不存主机明文**。

英文（与本文一一对应）：[WORKER_EN.md](WORKER_EN.md)  
回产品说明：[README.md](README.md)

> 仅限你拥有或已获书面授权的环境。

---

## 先分清三件套（Path ≠ Secret）

很多人把 **Worker Path** 当成密码，和 **Worker Secret**、**通信 Secret** 填反。三个东西完全不是一回事：

| 填在哪 | Cloudflare 里的名字 | 干什么 | 填错会怎样 |
|---|---|---|---|
| **Worker URL** | workers.dev 或你绑的域名 | 中继的**主机地址**，不要带后面的路径 | 连不上 |
| **Worker Path** | Secret 名：`PATH_SECRET` | URL 的**第一段路径**，像网站目录名。不是密码，也不放进 HTTP 头 | 中继当普通访客，回 **404** |
| **Worker Secret** | Secret 名：`C2_AUTH` | 请求头 **`X-C2-Auth`** 里的共享密钥，这才是中继口令 | 路径对了也会 **401** |
| **通信 Secret**（生成器 / 控制台解密密码） | *不在 Cloudflare 上* | AES-256-GCM 信封的密钥，载荷加解密用 | 能连上中继，但**解不开命令和回显** |

**不要**把通信 Secret 填进 Worker Secret。  
**不要**把 Worker Secret 填进 Path。  
**不要**在 Path 栏里贴整段 URL。

### 举例

假设你填的是：

```text
Worker URL:    https://c2relay.abc123.workers.dev
Worker Path:   a3f9k2-status
Worker Secret: 8f3c9e1a…
```

Agent / 控制台真正访问的地址是：

```text
https://c2relay.abc123.workers.dev/a3f9k2-status/reg
Header: X-C2-Auth: 8f3c9e1a…
```

- Path 写 `a3f9k2-status`，**不要**写成 `/a3f9k2-status`，也**不要**写成整段 URL。
- 只允许字母、数字、连字符（例如 `a3f9k2-status`）。
- Path 留空时，客户端会打到 `/reg`，中继强制要求 `/<PATH_SECRET>/…`，所以是 **404**，看起来像网站不存在。
- 一键部署成功后，设置 / 生成器会自动写入这三件套，一般不用手填。

Cloudflare API Token（一键部署用的那枚）**只用来搭中继**，不会编进 Agent。和上面三件套、GitHub Token 都不是同一个东西。权限见 [README.md](README.md)「凭据与权限」。

---

## 方式 A：Cloudflare 网页（不用命令行）

全程在 [dash.cloudflare.com](https://dash.cloudflare.com)。免费档即可。

先在本机生成两串随机值（不要互相套用）：

```bash
openssl rand -hex 16    # → 当作 Worker Secret / C2_AUTH
openssl rand -hex 8     # → 当作 Worker Path / PATH_SECRET（可再加连字符，如 a3f9k2-status）
```

没有 openssl 就用任意密码生成器。Path 只放字母数字和连字符。

### 1. 建 Worker

1. 左侧 **Workers 和 Pages / Workers & Pages** → **创建 / Create** → 选 **Worker**。
2. 名字填 `c2relay`（可改）→ **部署 / Deploy**。
3. **编辑代码 / Edit code**。
4. 打开本仓库 `c2/web-controller/cloudflare-worker/worker.js`，全选复制，**整份替换**编辑器内容 → **保存并部署 / Save and Deploy**。

### 2. 建 D1 并建表

1. 左侧 **存储和数据库 / Storage & Databases** → **D1 SQL 数据库 / D1 SQL Database** → **创建 / Create**，名字 `c2relay`。
2. 进这个库 → **控制台 / Console**。
3. 打开本仓库 `c2/web-controller/cloudflare-worker/schema.sql`，**全部**粘进输入框 → **执行 / Execute**。应出现三张表：`agents`、`comments`、`kill_flag`。

### 3. 把 D1 绑到 Worker（变量名必须是 `DB`）

1. 回到 Worker `c2relay` → **设置 / Settings** → **绑定 / Bindings** → **添加 / Add** → **D1 database**。
2. **变量名 / Variable name** 必须正好是 `DB`（代码读 `env.DB`，写成别的会挂）。
3. 数据库选刚建的 `c2relay` → 保存。

### 4. 写入两道门（这里最容易和 Path 搞混）

仍在该 Worker → **设置 / Settings** → **变量和机密 / Variables and Secrets** → **添加 / Add**：

| 类型 / Type | 名称 / Name | 填什么 |
|---|---|---|
| Secret | `C2_AUTH` | 准备阶段的 **Worker Secret**（请求头口令） |
| Secret | `PATH_SECRET` | 准备阶段的 **Worker Path**（URL 第一段，不是口令） |

保存后再部署一次才生效。之后所有接口都走：

```text
https://<你的域名>/<PATH_SECRET>/…
头：X-C2-Auth: <C2_AUTH>
```

### 5. 每小时清理（Cron）

Worker → **设置 / Settings** → **触发器 / Triggers**（或 **Cron Triggers**）→ **添加 / Add**。

表达式：`0 * * * *`（每小时：每个 Agent 每个方向保留最新约 500 条，长期不活跃的注册会清掉）。

### 6. 记下地址（可选：再绑一个自定义域）

默认会有 `https://c2relay.<你的子域>.workers.dev`。**URL 栏只填到域名为止**，不要把 `/a3f9k2-status/` 拼进去。

可选：同一 Worker → **域和路由 / Domains & Routes** → 绑你在 Cloudflare 上的域名（例如 `cdn.example.com`）。`workers.dev` **保持开着**，设置里 URL 可以写成两个、逗号分隔，互为备用。

---

## 方式 B：wrangler 命令行

在仓库的 `c2/web-controller/cloudflare-worker/` 目录：

```bash
npm i -g wrangler
wrangler login
wrangler d1 create c2relay
# 把打印出来的 database_id 填进 wrangler.toml 的 database_id
wrangler d1 execute c2relay --remote --file=schema.sql
wrangler secret put C2_AUTH          # 粘贴 Worker Secret
wrangler secret put PATH_SECRET      # 粘贴 Worker Path（URL 第一段）
wrangler deploy
```

部署结束会打印 `https://c2relay.<子域>.workers.dev`。同样：**这个地址填进 URL，Path 单独填 PATH_SECRET 那一串。**

---

## 部署之后填到控制台哪里

| 控制台位置 | 填什么 |
|---|---|
| 设置 → Worker URLs | `https://c2relay.xxx.workers.dev`（可两个、逗号分隔）。**不要带 Path。** |
| 设置 → Worker Secret | 与 `C2_AUTH` 相同 |
| 设置 → Worker Path | 与 `PATH_SECRET` 相同（只要那一段，不要 `/`） |
| 生成器里同名三栏 | 必须和控制台一致，否则编出来的 Agent 对不上中继 |

空字段保存**不会覆盖**已有值。真要清空某一项，填单独一个 `-`。

填完后：生成器选 **双通道** 或 **Worker 单通道** → 编包。侧栏应出现 Worker 徽章。

可选自检（在 `c2/web-controller/cloudflare-worker/`）：

```bash
BASE=https://c2relay.xxx.workers.dev \
PATH_SECRET=a3f9k2-status \
AUTH='你的C2_AUTH' \
bash test_relay.sh
```

期望看到全部通过。不要把 `AUTH` / Token 贴进聊天或提交进仓库。

---

## 和一键部署的关系

一键部署会：建 D1、执行 `schema.sql`、上传 `worker.js`、写入 `C2_AUTH` + `PATH_SECRET`、挂每小时 cron、打开 workers.dev，并写回设置 / 生成器。

- 已经一键成功：不必再走这一页，除非你要换账号或重搭。
- 只想自己搭、不想把 Cloudflare API Token 交给控制台：走这一页，再把三件套手填进设置。

Cloudflare API Token 的权限（中英对照）见 [README.md](README.md)「凭据与权限」。那枚 Token **只用于部署中继，不会进 Agent**。

---

## 删掉中继

脚本和一键部署都**不会**自动删你云上的东西。到 [Cloudflare Dashboard](https://dash.cloudflare.com) 里分别删除 Worker 和 D1 即可。
