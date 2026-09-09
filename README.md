# GitHub C2

授权实验室使用的红队指挥平台。浏览器里管理目标机上的 Agent：发命令、交互 Shell、传文件、穿隧道、扫描、采集、编包、升级。通信默认走你自己的 Cloudflare Worker 中继，GitHub Issue 作为备用通道；主路断了自动切备用，备用稳定后再切回来。

> 仅限你拥有或已获书面授权的环境。未授权侵入他人系统违法。

英文文档（与本文一一对应）：[README_EN.md](README_EN.md)

---

## 介绍

### 产品定位

GitHub C2 由三部分组成：

| 组件 | 作用 |
|---|---|
| **Web 控制台** | Flask 网页后台。侧栏选 Agent，顶栏切换功能。自带中 / 英语言包。 |
| **Agent** | Rust 编写，部署在目标机。轮询取令、加密回传、可持久化与伪装。 |
| **通道** | 把指令和回显搬过去。主通道是 Cloudflare Worker + D1；备用是 GitHub Issue；也可只用 Notion 或只用其中一条。 |

控制台和 Agent 之间的载荷一律是 **AES-256-GCM 信封**。中继数据库里**不存主机明文身份**。一台机器若同时挂了 Worker 和 GitHub，**侧栏合成一条**，不会当成两台。

### 亮点

和其他「只把 GitHub 当信道」的工具比，这几条是真正不一样的：

- **自己的中继，GitHub 只当备胎。** 一键在 Cloudflare 上部署 Worker + D1；主路断了**自动切 GitHub**，好了**自动切回**，终端有 `[Channel]` 通知。双通道在侧栏仍是**一台**，不是两台 Agent。
- **时间窗。** 只在你规定的时段说话；窗外面板显示**安静**，不是掉线。边界每天抖动，整群不会同一秒苏醒。紧急停机在窗外**照样生效**。
- **轮询全自动识别冷热。** 编包只填一个基数。有人在操作就加快，闲着就自己放慢，不用手调。
- **Token 失效不用重新编包。** 填 Backup URL，Agent 自己去拉一份新 JSON 配置并热重启。
- **目标机少落文件。** 反弹 Shell、隧道节点都编在 Agent 里，纯内存；还可以 memfd **无文件**上线。
- **载荷全程加密**，控制台自带 **中 / 英语言包**（右上角 **EN / 中文**）。

### 架构

```mermaid
flowchart LR
  OP[操作员浏览器] --> CTRL[Web 控制台]
  AI[MCP / AI 客户端] --> CTRL
  CTRL -->|主通道 HTTPS| WR[Cloudflare Worker + D1]
  CTRL -->|备用 Issue 评论| GH[GitHub]
  CTRL -.->|可选| NT[Notion]
  WR --> AG[目标机 Agent]
  GH --> AG
  NT -.-> AG
  AG -->|内置节点| SOCKS[本机 SOCKS5 隧道]
  AG -->|内置 wspty| PTY[本机交互 Shell]
```

```mermaid
mindmap
  root((GitHub C2))
    通道
      Worker 主
      GitHub 备
      Notion 可选
      故障自动切换
    控制台功能
      终端
      反弹 Shell
      文件
      隧道
      扫描
      系统信息
      资料库
      报告
      升级
      生成器
      MCP
      设置
    Agent
      加密通信
      时间窗
      进程伪装
      无文件执行
      热升级 / 卸载
```

### 界面

侧栏列出已上线的 Agent，顶部切换业务页。终端、反弹 Shell、文件、隧道、扫描、系统信息、资料库、报告、升级在同一工作区。

控制台内置语言包（`static/js/lang/zh.js`、`en.js`）。右上角 **EN / 中文** 一键切换，选择会记在浏览器里；未选过则按系统语言默认。下面截图是中文界面，切到 EN 后同一套页面为英文。

![控制台终端](img/console.png)

生成器在网页里选通道、填凭据、编译，完成后直接下载二进制。双通道为 **Worker 主 + GitHub 备**。

![Agent 生成器](img/builder.png)

### 凭据与权限

两种 Token 用途完全不同，不要共用、不要给多余权限。

| Token | 用在哪 | 会不会进 Agent | 干什么 |
|---|---|---|---|
| **Cloudflare API Token** | 只在控制台「设置 → 一键部署 Worker」 | **不会。** 只留在控制台服务器 | 部署中继：建 D1、上传 Worker、绑密钥 |
| **GitHub Token** | 生成器编包 / 设置里的扫描列表 | **会。** 写进二进制，目标机上能被抠出来 | Agent 上线：读 Issue 命令、回评论 |

#### Cloudflare API Token（只用于部署中继）

打开 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens) → **Create Token** → **Create Custom Token**。Cloudflare 控制台中英文下权限名称不一样，请按下表对照勾选（资源选 **所有帐户 / All accounts**，或只包含你的那一个帐户）。

| 中文控制台 | English dashboard | 级别 |
|---|---|---|
| 帐户 · D1 · **编辑** | Account · D1 · **Edit** | 建库、建表 |
| 帐户 · Workers 脚本 · **编辑** | Account · Workers Scripts · **Edit** | 上传 Worker、绑 Secret、挂 cron |
| 帐户 · 帐户设置 · **读取** | Account · Account Settings · **Read** | 自动定位帐户（`GET /accounts`） |

列表页上会缩成「帐户.D1、帐户.Workers 脚本、+1」；点进摘要应能看到上面三条：

![Cloudflare Token 列表](img/cf-token-list.png)

![Cloudflare Token 权限摘要](img/cf-token-perms.png)

这个 Token **只给控制台用来部署中继**，不要编进 Agent，部署完成后可在 Cloudflare 面板删掉或收紧。若 Token 看不到帐户列表，把 Dashboard 右侧的 **帐户 ID / Account ID** 填进部署表单即可。

#### GitHub Token（编进 Agent，用于上线）

GitHub Token 会随二进制落到目标机。权限过大等于把仓库钥匙交给任何拿到样本的人。请用 **Fine-grained personal access token**，只开一个**私有**仓库：

1. 只选你建好的隐私仓库（Only select repositories）。
2. Repository permissions：
   - **Issues** → **Read and write**（读命令、写回显评论）
   - **Metadata** → **Read-only**（系统必选，不要再加 Contents / Administration / Actions）

![GitHub Token 最小权限](img/github-token.png)

图中红字标注即：选择你事先建好的隐私仓库。

不要给 `repo` 经典全仓库权限，不要给组织管理员、不要给多个仓库。控制台设置里用于扫描的 Token 也按同一最小权限配置。

---

### 控制台功能

#### 侧栏

- 显示 Agent 总数、在线数；按主机名 / 用户 / 系统 / 备注搜索。
- 每条卡片展示主机、用户、权限、系统、通道徽章（Worker / GitHub / Notion）、最近回显时间。
- 双通道同一台机器只显示一行，点进去两条通道都能用。
- 可给 Agent 写备注（保存在控制台本地库，切换通道不丢）。
- **刷新列表**：主动向已配置的通道拉一次注册信息。
- **清理通道消息**：按设置里的条数 / 过期天数裁剪 GitHub 侧旧评论（中继侧也可清缓冲）。
- **退出登录**。

#### 终端

网页命令行，不是假日志窗。

- 输入命令下发到当前选中的 Agent，回显按块显示。
- **Interactive**：勾选后命令以交互会话方式执行（前缀 `interactive:`）。
- 过滤条：按关键字筛行；cmd / resp / sys 三类可单独开关并计数。
- Live 滚动可暂停，避免长输出把视线带走。
- 上 / 下键翻本机输入历史；历史下拉可重发。
- **清空历史**：清掉该 Agent 在控制台里的会话记录（通道里的旧评论需用侧栏「清理通道消息」）。
- 缓冲上限 500 块，防止超长输出撑爆页面。

#### 反弹 Shell

**真交互 PTY**，走 WebSocket，**不靠 30 秒轮询**。

- **服务端**：控制台本机自带的 `cliws`，默认监听 `7337`。点「启动服务端」即可，不必另下软件。
- **目标端**：Agent **内置** `wspty`。点「启动目标端反弹」下发回连，**目标机不落额外文件**。
- 连上后页面就是 xterm 终端，可直接敲。
- 可改控制端 IP / 端口（Agent 回连地址，防火墙需放行）。
- 历史会话可回看，再切回直播。
- 换选 Agent 时会断开旧会话，避免串台。
- 收工：先停目标端反弹，再停本机服务端。

#### 文件

远程目录浏览器。

- 路径栏、面包屑、快捷目录（`/`、`/tmp`、`/etc`、`/var/log`、`/home`、`/root`、`/dev/shm`）。
- 进目录、回上级、刷新。
- 点文件名按魔数预览：文本、图片、PDF、其余显示十六进制。
- **下载到资料库**：把目标机文件取回控制台本机。
- **上传**：从浏览器传到目标机当前目录（分片下发）。
- **sendit**：大文件经临时中转取回，避免走评论通道的体积限制。

#### 隧道

内网 SOCKS5，基于 Stowaway。

- **服务端**：控制台本机自带 `stowaway_admin`。配置监听端口（默认 9998）和 SOCKS5 端口（默认 1080），点「启动服务端」。
- **目标端**：Agent **内置隧道节点，纯内存，不落文件**。填回连 IP / 端口 / Secret，点「启动目标端隧道」。
- 浏览器或代理工具连 `127.0.0.1:SOCKS端口`，即以目标机为跳板进其内网。
- Secret 与设置页隧道密钥一致，页面不回显全文。
- SOCKS 账密可在隧道管理里改（出厂默认仅适合本机 / 内网）。
- 收工：停目标端（停止即清理）+ 停服务端。

#### 扫描

在目标机上下发并运行 [fscan](https://github.com/shadow1ng/fscan)。

- 填写二进制下载 URL，保存后可重复用。
- 参数框写完整 fscan 参数；右侧有常用示例，一点即可填入。
- **下发并运行**：下载到 `/tmp/.san` 后立刻扫。
- **运行**：已有二进制则直接跑。
- **停止**：杀掉扫描进程。
- **清理痕迹**：停进程并删除 `/tmp/.san`。
- **读取结果**：默认 `cat /tmp/r.txt`，输出显示在右侧。

#### 系统信息

- **采集系统信息**：主机、内核、网卡、权限等，带历史快照，可来回看。
- **采集敏感数据**：按目标环境搜集常见敏感路径与凭据痕迹，同样有历史。
- **卸载 Agent**：向当前 Agent 下发卸载（见「卸载」一节）。

#### 资料库

控制台本机上、按 Agent 分开的笔记与文件柜，不经过目标机。

- 新建笔记、新建文件、上传、树状浏览。
- 文本可编辑保存；Markdown 可预览。
- 二进制只能下载，不能在浏览器里改。
- 路径显示在页顶，方便对照磁盘位置。

#### 报告

把该 Agent 的备注、命令历史、回显、系统信息等汇总成一份报告。

- 页内搜索。
- 刷新重新生成。
- 下载 Markdown，便于归档或交接。

#### 升级

给已上线的 Linux Agent 换新二进制，**身份（agent id / 通道身份）保留**。

1. 在生成器编好新版本，复制下载地址。
2. 填「新二进制 URL」和目标机临时路径（默认 `/tmp/.agent_upg`）。
3. 点 **Download & Upgrade**：Agent 自行下载、校验、替换隐藏路径上的文件、重装持久化、清掉旧 hook，然后重启。
4. 约 30–60 秒后重新出现在侧栏。

也可在目标机已有文件时，直接发 `upgrade <路径>`。升级失败则旧进程继续跑。Windows Agent 请改用手动替换。本页也可下发卸载。

#### 生成器

在控制台本机用 Rust 交叉编译 Agent，编完可下载。

**通道四档**

| 档位 | 行为 |
|---|---|
| GitHub 单通道 | 只走 GitHub Issue 评论。 |
| Notion 单通道 | 只走 Notion 数据库页。 |
| Worker 单通道 | 只走 Cloudflare Worker。 |
| 双通道 | **Worker 为主，GitHub 为备。** Worker 连续失败达到阈值后切 GitHub；备用连续成功后再探主路。 |

**编包字段**

- 通信 Secret：与控制台解密密码相同。部署时写过一次，编包可留空沿用。**改了则旧 Agent 全部解不开。**
- GitHub Token / 仓库：单 GitHub 或双通道备用时必填。此 Token **会编进 Agent**，只开 Issues 读写，见「凭据与权限」。
- Worker URL、Secret、Path：Worker / 双通道必填；Path 空则中继返回 404。
- 切换阈值 / 主探测间隔：仅双通道，默认 3 轮切备、5 轮探主。
- **轮询间隔（全自动识别）：** 你只填基数，默认 `30` 秒。Agent **自己判断有没有人在操作**，不用手调快慢：
  - **热**（近 2 分钟有过命令）→ 加快，最快 15 秒
  - **温**（1 小时内有过命令）→ 按你填的基数
  - **冷**（超过 1 小时没命令）→ 放慢到基数 × 4，最长 5 分钟
- **时间窗（加重）：** 按**北京时间**判断，时钟会用网络校准，不单信目标机系统钟。两种写法：
  - 区间：`09:00-18:00`（也支持跨夜，如 `22:00-06:00`）
  - 小时列表：`9,10,11,14`
  - **留空 = 全天在线**
  - 每台 Agent、每一天的开关边界都会抖：日抖动约 ±20 分钟，再加约 ±5 分钟噪声，整群不会同一秒苏醒、同一秒消失。
  - **窗外不走 C2 通信**，随机睡 5–20 分钟；侧栏显示 **安静**，不是掉线。
  - **紧急停机在窗外照样检查**，不会因为「下班窗口」停不下来。
- 架构：推荐 `x86_64-unknown-linux-musl`（静态、不依赖 glibc）；另有 aarch64、gnu。
- Release：自定义版本标签，空则用构建时的 git 短号。
- Debug：生产保持关，避免在目标机落日志指纹。
- **Backup URL（远程换票，可选）：** 给一个 **HTTPS** 地址。GitHub Token 返回 **401**，或连续失败约 5 轮时，Agent 会 GET 这份 JSON，校验后写入新凭据并重启。**留空 = 不启用。** 同一地址 1 小时内最多拉一次；拉下来的内容和当前一样则不重启。

  这个地址上必须是一份 **JSON**（`Content-Type` 随意，正文能被解析即可），字段如下：

  ```json
  {
    "channel": "github",
    "github_token": "github_pat_替换成新的Fine-grainedToken",
    "github_repo": "owner/private-repo",
    "password": "和当前通信Secret相同或你准备同时改掉的新Secret",
    "hmac_sig": ""
  }
  ```

  | 字段 | 必填 | 含义 |
  |---|---|---|
  | `channel` | 否，默认 `github` | `github` 或 `notion`。Notion 时：`github_token` 填 Integration Token（`ntn_`），`github_repo` 填 Database ID。 |
  | `github_token` | 是 | 新的上线 Token。**同样会落到目标机**，权限仍按「凭据与权限」收紧。 |
  | `github_repo` | 是 | GitHub 填 `owner/repo`；Notion 填数据库 ID。 |
  | `password` | 是 | 通信 Secret。若改了，控制台解密密码必须一起改，否则解不开回包。 |
  | `hmac_sig` | 视情况 | 网页生成器默认**不校验签名**，可留空。只有你编译时设置了环境变量 `BACKUP_SECRET`，Agent 才强制校验：对 `channel\|github_token\|github_repo\|password` 做 HMAC-SHA256，值写成小写 hex。 |

  地址必须是 `https://`。JSON 里是新 Token，**不要放在能被猜到或被搜索引擎扫到的公开路径**（公开 Gist 等于把新钥匙贴网上）。可用你控制的站点、带随机长路径的对象存储，或自建 Worker。Backup URL 本身不会被这份 JSON 改掉。
- **Guards：** 可限定主机名、用户、标记文件、最低内存；不满足则**静默退出**（防沙箱 / 蜜罐）。
- **进程伪装名 / 落地路径：** 空则按发行版**自动扮系统守护进程**。
- Compress：strip 去符号；勾选后再用 UPX 压缩（需本机已装 `upx`）。

**无文件模式（Linux）**

- **A · memfd 部署（无文件）：** 生成一条可粘贴到目标机的命令，Agent **在内存里跑，不落盘、不装持久化，重启即无**。需要目标机 Python 3.8+。
- **B · 原生 shellcode**：粘贴 hex / `\xNN` / base64，生成 mmap RWX 跳转执行命令。

#### MCP 接入

把控制台交给支持 MCP 的 AI 客户端（stdio）。

- 页面按当前登录态生成说明、能力 JSON、客户端注册 JSON，可一键复制。
- 可下载 `mcp_server.py`。
- 工具分三档（环境变量 `GITHUB_C2_MCP_TOOLS`）：
  - **handoff**（默认）：只列出 Agent。
  - **core**：发命令、读回显、系统信息、统计、列目录、审计、看隧道状态。
  - **full**：再加上传文件、采敏感数据、紧急停机（停机必须确认串 `YES-DESTROY-ALL`）。

页面杀开关已从设置里拿掉，避免误触全灭；需要时走 MCP full 档。

#### 设置

- **GitHub Token**：可加多枚，只显示末四位，轮流使用以减轻限额。编包用的那枚会进 Agent，权限必须按「凭据与权限」收紧。
- **控制器解密密码**：加解密指令与回包，与生成器通信 Secret 同步。
- **仓库列表**：控制台扫描 / 发令用的 `owner/repo`。双通道备用仓库会并进扫描列表。
- **Notion**：Token、数据库 ID；可一键给库补齐所需列。
- **Worker**：URL（可多个、逗号分隔）、共享密钥、路径前缀。空字段保存不覆盖；填单独一个 `-` 才清空。
- **轮询间隔 / 评论保留条数 / 过期天数**：控制后台扫描节奏和自动清理。
- **Web 用户名 / 密码**：改控制台登录；改完重启后仍有效。
- **一键部署 Worker**：填 **Cloudflare API Token**（只用于部署中继，不会进 Agent）。自动建 D1、建表、上传 Worker、绑密钥、挂每小时清理、打开 workers.dev，并写回设置 / 生成器（第一次会把空的 GitHub 单通道提升为双通道，之后不再擅自改档）。权限见「凭据与权限」。
- **审计日志**：谁在何时对哪台 Agent 做了什么。

空 Token、空密码保存时不会把已有机密覆盖掉。设置页的 GET 接口不把 Secret 全文回给浏览器。

### 通道与可靠性

- 双通道运行时，命令按**最近活跃通道**走；同一条命令会同时写到兄弟通道，Agent 去重，避免切通道时丢令。
- Worker 连败达到阈值 → **自动切 GitHub**，终端可见 `[Channel]` 通知；通知失败则**回滚**，避免控制台和 Agent 各听一边。
- GitHub 备用上稳定后探 Worker，注册成功再**自动切回**，同样发通知。
- 中继 D1 被重建、自增 id 从头计数时，Agent 与控制台会识别水位失效并复位，不会一直收不到新命令。
- **紧急停机（Kill）在时间窗外也会检查**，避免「下班窗口」里停不下来。

---

## 安装

### 环境

| 项目 | 要求 |
|---|---|
| 控制台主机 | Linux（Debian / Ubuntu 最省事），Python 3，公网或实验室可达 |
| 生成 Agent | 同机需 Rust（`deploy.sh` 可代装 rustup + `x86_64-unknown-linux-musl`） |
| 可选 | `gcc` / `binutils`（链接与 strip）、`upx`（压缩）、Cloudflare 账号（Worker 中继） |
| 目标机 | 按编包架构：Linux musl / gnu，x86_64 或 aarch64 |

随包已带隧道服务端 `stowaway_admin` 和反弹 Shell 服务端 `cliws`，一般不必再下。

### 标准安装

```bash
git clone https://github.com/Kxiandaoyan/github-C2.git
cd github-C2
bash deploy.sh
```

脚本会：

1. 识别源码目录 `c2/`（或旁路的压缩包）。
2. 创建 Python 虚拟环境并安装依赖。
3. 询问（或用参数传入）网页账号、通信 Secret、端口、绑定地址。
4. 把凭据写入 `c2/.runtime.env`（权限 0600）和数据库。
5. 检查隧道 / Shell 二进制；按需安装 Rust 与 musl 目标。
6. 用 systemd 单元 `c2-controller` 拉起控制台（无 systemd 则 5 秒自动拉起）。
7. 做登录 + 接口健康检查；升级失败会回滚上一份快照。

完成后终端会打印访问地址，形如：

```text
http://<服务器IP>:<端口>/?login=<用户名>&pass=<密码>
```

用地址参数登录，页面本身不放登录表单。首次打开后把地址栏里的密码清掉即可。

### 命令行参数

```bash
bash deploy.sh --user admin --pass '你的密码' --c2-secret '通信密钥' --port 8080 --bind 0.0.0.0
```

| 参数 | 含义 |
|---|---|
| `--user` / `--pass` | 控制台登录。重装时回车沿用旧值。 |
| `--c2-secret` | 通信加密 Secret，编包与解密共用。 |
| `--port` / `--bind` | 监听端口与网卡。默认 `8080`、`0.0.0.0`。 |
| `--noninteractive` | 无人值守。密码可用环境变量 `C2_WEB_PASS`。 |
| `--skip-toolchain` | 不装 Rust。生成器将无法编译。 |
| `--skip-always-poll` | 浏览器闲置约 90 秒后停止后台扫描（默认一直扫）。 |
| `--no-systemd` | 不用 systemd，改用脚本循环拉起。 |

无人值守若要顺便装编译链：`C2_INSTALL_TOOLCHAIN=1 bash deploy.sh --noninteractive ...`

### 安装之后

1. 浏览器打开脚本打印的地址，进入控制台。需要英文界面时点右上角 **EN / 中文**。
2. **设置 → Cloudflare Worker 中转**：用「凭据与权限」里的 Cloudflare Token 一键部署中继（只用于部署，不会写进 Agent）。也可按 `c2/web-controller/cloudflare-worker/README.md` 手动 wrangler。
3. **生成器**选「双通道」，确认 Worker 三件套，再填**最小权限**的 GitHub 备用 Token / 仓库（此 Token 会编进 Agent）。点编译，下载二进制。
4. 在授权目标机运行 Agent。侧栏出现一条记录，通道徽章为 Worker + GitHub。
5. 先在终端发一条无害命令确认回显，再使用 Shell / 文件 / 隧道等页。

也可以只编 GitHub、只编 Worker 或只编 Notion，与生成器档位一致即可。

### 升级控制台

在已部署的机器上再次执行 `bash deploy.sh`。回车沿用账号和 Secret。健康检查失败时自动回到升级前的代码和数据库快照。

---

## 卸载

分两层：卸掉**控制台**（你的服务器），以及卸掉**目标机上的 Agent**。

### 卸载控制台

以 root 安装为例：

```bash
# 1. 停服务
systemctl stop c2-controller
systemctl disable c2-controller
rm -f /etc/systemd/system/c2-controller.service
systemctl daemon-reload

# 若当时是普通用户安装：
# systemctl --user stop c2-controller
# systemctl --user disable c2-controller
# rm -f ~/.config/systemd/user/c2-controller.service

# 2. 若没用 systemd
pkill -f 'run-controller.sh --respawn' || true

# 3. 可选：日志轮转
rm -f /etc/logrotate.d/c2-controller

# 4. 删目录（含数据库、虚拟环境、运行时凭据）
# 仓库若在 /opt/github-C2：
rm -rf /opt/github-C2
```

隧道服务端、cliws 随目录一起删除。Cloudflare 上的 Worker / D1 需到 [Cloudflare Dashboard](https://dash.cloudflare.com) 里单独删，脚本不会动你的云账号。

### 卸载 Agent

在控制台打开该 Agent → **系统信息** 或 **升级** → **卸载 Agent**。下发 `uninstall` 后，Agent 会：

1. 拆除持久化（systemd、cron、bashrc、rc.local、用户服务等，视安装时用了哪些）。
2. 拆除已装的隐藏模块（若有）。
3. 删除状态目录里的身份与水位文件。
4. 约 5 秒后删除自身进程文件并退出。

无文件（memfd）模式本来就没有落地文件和持久化，目标机重启即无；仍可下发卸载以结束当前进程。

时间窗外的 Agent 也会检查紧急停机信号。需要一次清掉所有 Agent 时，使用 MCP **full** 档的 killswitch，并传入确认串 `YES-DESTROY-ALL`。
