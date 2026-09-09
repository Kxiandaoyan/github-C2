# GitHub C2

A red-team command console for authorized labs. From the browser you drive agents on target hosts: commands, interactive shells, files, tunnels, scanning, collection, builds, and upgrades. Traffic prefers your own Cloudflare Worker relay; GitHub Issues are the backup. If the primary path dies the agent fails over; when the relay is healthy it fails back.

> Use only on systems you own or are written-authorized to test. Unauthorized access is illegal.

Chinese document (same sections, same order): [README.md](README.md)

---

## Introduction

### Product overview

GitHub C2 has three parts:

| Component | Role |
|---|---|
| **Web console** | Flask dashboard. Pick an agent in the sidebar, switch features in the top bar. Ships with Chinese / English language packs. |
| **Agent** | Written in Rust, runs on the target. Polls for commands, returns encrypted output, can persist and disguise itself. |
| **Channels** | Move commands and replies. Primary is Cloudflare Worker + D1; backup is GitHub Issues. You can also use Notion alone, or any single channel. |

Payloads between the console and the agent are always **AES-256-GCM envelopes**. The relay database **does not store plaintext host identity**. If one machine is on both Worker and GitHub, the sidebar shows **a single row**, not two agents.

### Highlights

These are the parts that are actually different from a “GitHub-as-the-only-channel” tool:

- **Your own relay; GitHub is only the spare.** One-click Cloudflare Worker + D1. If the primary dies the agent **fails over to GitHub**; when the relay is healthy it **fails back**. The terminal shows a `[Channel]` notice. Dual-channel still appears as **one** sidebar row.
- **Time window.** The agent talks only in the hours you set. Outside the window the panel shows **Quiet**, not offline. Window edges jitter per agent per day so the fleet does not wake as one pulse. **Kill still works after hours.**
- **Fully automatic poll heat.** You set one base interval. The agent speeds up when someone is operating and slows down when idle. No manual day/night profile.
- **Rotate a dead token without rebuilding.** Fill Backup URL; the agent fetches a new JSON config and restarts itself.
- **Little or nothing written on the target.** Reverse shell and the tunnel node are built into the agent and stay in memory. You can also check in **fileless** via memfd.
- **Everything on the wire is encrypted.** The console ships **Chinese / English language packs** (top-right **EN / 中文**).

### Architecture

```mermaid
flowchart LR
  OP[Operator browser] --> CTRL[Web console]
  AI[MCP / AI client] --> CTRL
  CTRL -->|primary HTTPS| WR[Cloudflare Worker + D1]
  CTRL -->|backup issue comments| GH[GitHub]
  CTRL -.->|optional| NT[Notion]
  WR --> AG[Target agent]
  GH --> AG
  NT -.-> AG
  AG -->|built-in node| SOCKS[Local SOCKS5 tunnel]
  AG -->|built-in wspty| PTY[Local interactive shell]
```

```mermaid
mindmap
  root((GitHub C2))
    Channels
      Worker primary
      GitHub backup
      Optional Notion
      Automatic failover
    Console features
      Terminal
      Reverse shell
      Files
      Tunnel
      Scan
      System info
      Library
      Report
      Upgrade
      Builder
      MCP
      Settings
    Agent
      Encrypted comms
      Time window
      Process disguise
      Fileless exec
      Live upgrade / uninstall
```

### Interface

The sidebar lists live agents. The top bar switches workspaces: Terminal, Reverse Shell, Files, Tunnel, Scan, System Info, Library, Report, Upgrade.

The console ships language packs (`static/js/lang/zh.js`, `en.js`). Use the **EN / 中文** button at the top-right to switch; the choice is stored in the browser. If you have never chosen, it follows the system language. Screenshots below are the Chinese UI; the same pages become English after you click EN.

![Console terminal](img/console.png)

The builder picks a channel, takes credentials, compiles, then lets you download the binary. Dual-channel means **Worker primary + GitHub backup**.

![Agent builder](img/builder.png)

### Credentials and permissions

The two tokens do different jobs. Do not reuse one for both, and do not grant extra scopes.

| Token | Where it is used | Embedded in the agent? | Purpose |
|---|---|---|---|
| **Cloudflare API Token** | Console only: Settings → one-click Worker deploy | **No.** Stays on the console server | Deploy the relay: create D1, upload the Worker, bind secrets |
| **GitHub Token** | Builder (compile) / Settings scan list | **Yes.** Written into the binary; recoverable on the target | Agent check-in: read Issue commands, post reply comments |

#### Cloudflare API Token (relay deploy only)

Open [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens) → **Create Token** → **Create Custom Token**. Permission names differ between the Chinese and English Cloudflare dashboards. Tick the rows in this table (resources: **所有帐户 / All accounts**, or only your own account).

| 中文控制台 | English dashboard | Level |
|---|---|---|
| 帐户 · D1 · **编辑** | Account · D1 · **Edit** | Create the database and tables |
| 帐户 · Workers 脚本 · **编辑** | Account · Workers Scripts · **Edit** | Upload the Worker, bind secrets, attach cron |
| 帐户 · 帐户设置 · **读取** | Account · Account Settings · **Read** | Auto-locate the account (`GET /accounts`) |

The token list shortens this to “帐户.D1, 帐户.Workers 脚本, +1”. The summary page should show the three rows above:

![Cloudflare token list](img/cf-token-list.png)

![Cloudflare token permission summary](img/cf-token-perms.png)

This token is **only for the console to deploy the relay**. Do not bake it into the agent. After deploy you may delete or tighten it in the Cloudflare dashboard. If the token cannot list accounts, paste the **帐户 ID / Account ID** from the right side of the dashboard into the deploy form.

#### GitHub token (baked into the agent for check-in)

The GitHub token ships inside the binary on the target. Extra scopes are equivalent to handing the repo keys to anyone who captures the sample. Use a **fine-grained personal access token** on a single **private** repository:

1. **Only select repositories** — pick the private repo you created.
2. Repository permissions:
   - **Issues** → **Read and write** (read commands, write reply comments)
   - **Metadata** → **Read-only** (required by GitHub; do not add Contents / Administration / Actions)

![GitHub token least privilege](img/github-token.png)

The red note on the screenshot is Chinese for “select the private repository you created.”

Do not grant classic `repo` (full repository). Do not grant org admin. Do not attach extra repositories. Tokens used by the console for scanning should use the same least privilege.

---

### Console features

#### Sidebar

- Shows agent count and online count; search by hostname / user / OS / note.
- Each card shows host, user, privilege, OS, channel badges (Worker / GitHub / Notion), and last reply time.
- A dual-channel host is one row; both channels are usable from that row.
- Notes are stored in the console database and survive channel switches.
- **Refresh list**: pull registrations from configured channels now.
- **Clear channel messages**: trim old GitHub comments by the count / stale-days in Settings (the relay buffer can be purged too).
- **Log out**.

#### Terminal

A real command line in the page, not a fake log pane.

- Commands go to the selected agent; replies render in chunks.
- **Interactive**: run as an interactive session (prefix `interactive:`).
- Filter bar: keyword search; cmd / resp / sys chips can be toggled and counted.
- Live scroll can be paused so long output does not steal the viewport.
- Up / down for local input history; the history dropdown can resend.
- **Clear history**: wipe this agent’s console session (old channel comments still need “Clear channel messages”).
- Buffer cap is 500 chunks so huge output cannot blow up the page.

#### Reverse shell

A **real PTY** over WebSocket. It **does not wait for the 30-second poll**.

- **Server side**: bundled `cliws` on the console host, default port `7337`. Click Start server — no extra download.
- **Target side**: **built-in** `wspty` in the agent. Click Start target bounce; **no extra file on the target**.
- Once connected, the page is an xterm you can type into.
- Controller IP / port are editable (the address the agent dials; open the firewall).
- Past sessions can be reviewed, then you return to live.
- Switching agents closes the old session so you do not mix hosts.
- Tear down: stop the target bounce, then stop the local server.

#### Files

Remote directory browser.

- Path box, breadcrumbs, shortcuts (`/`, `/tmp`, `/etc`, `/var/log`, `/home`, `/root`, `/dev/shm`).
- Enter a folder, go up, refresh.
- Click a name to preview by magic bytes: text, image, PDF, otherwise hex.
- **Download to Library**: pull the file onto the console host.
- **Upload**: browser → current directory on the target (chunked).
- **sendit**: pull large files through a temporary relay so they do not ride the comment channel.

#### Tunnel

Internal SOCKS5, based on Stowaway.

- **Server side**: bundled `stowaway_admin` on the console. Set listen port (default 9998) and SOCKS5 port (default 1080), then Start server.
- **Target side**: **in-memory tunnel node in the agent, no file on disk**. Fill callback IP / port / Secret, then Start target tunnel.
- Point a browser or proxy at `127.0.0.1:<SOCKS port>` to use the target as a hop into its LAN.
- The secret matches Settings; the page never echoes the full value.
- SOCKS user/pass can be changed in tunnel admin (factory defaults are for localhost / lab LAN only).
- Tear down: stop the target (stop = cleanup) + stop the server.

#### Scan

Push and run [fscan](https://github.com/shadow1ng/fscan) on the target.

- Save a binary download URL for reuse.
- The argument box takes a full fscan command; examples on the right fill it in one click.
- **Deploy and run**: download to `/tmp/.san` and scan immediately.
- **Run**: start an already-present binary.
- **Stop**: kill the scanner.
- **Wipe**: stop the process and delete `/tmp/.san`.
- **Read result**: default `cat /tmp/r.txt`, shown on the right.

#### System info

- **Collect system info**: host, kernel, NICs, privilege, with snapshots you can reopen.
- **Collect sensitive data**: common sensitive paths and credential traces for that environment, also with history.
- **Uninstall Agent**: send uninstall to the current agent (see Uninstall).

#### Library

Per-agent notes and files on the **console** disk. Traffic does not go to the target.

- New note, new file, upload, tree browse.
- Text can be edited and saved; Markdown can be previewed.
- Binaries can only be downloaded, not edited in the browser.
- The on-disk path is shown at the top.

#### Report

Builds one report from that agent’s notes, command history, output, and system info.

- In-page search.
- Refresh to regenerate.
- Download Markdown for archive or handoff.

#### Upgrade

Replace the binary on a live Linux agent. **Identity (agent id / channel id) is kept.**

1. Build a new version in the Builder and copy the download URL.
2. Fill **New binary URL** and a temp path on the target (default `/tmp/.agent_upg`).
3. Click **Download & Upgrade**: the agent downloads, checks, replaces the hidden-path file, reinstalls persistence, clears old hooks, then restarts.
4. It reappears in the sidebar in about 30–60 seconds.

If the file is already on the target, send `upgrade <path>` directly. A failed upgrade leaves the old process running. Windows agents should be replaced by hand. This page can also send uninstall.

#### Builder

Cross-compiles the agent with Rust on the console host, then offers a download.

**Four channel profiles**

| Profile | Behavior |
|---|---|
| GitHub only | GitHub Issue comments only. |
| Notion only | Notion database pages only. |
| Worker only | Cloudflare Worker only. |
| Dual-channel | **Worker primary, GitHub backup.** After enough Worker failures it moves to GitHub; after enough backup successes it probes the primary again. |

**Build fields**

- Channel secret: same as the console decrypt password. If you set it at deploy time, leave the builder field empty to reuse. **Changing it orphans every old agent.**
- GitHub token / repo: required for GitHub-only or dual backup. This token **is compiled into the agent**. Grant Issues read/write only — see Credentials and permissions.
- Worker URL, secret, path: required for Worker / dual. An empty path makes the relay return 404.
- Failover threshold / primary probe interval: dual only. Defaults: 3 rounds to fail over, 5 rounds before probing primary.
- **Poll interval (fully automatic):** you only set the base, default `30` seconds. The agent **detects operator activity by itself** — you do not tune fast/slow by hand:
  - **Hot** (a command in the last 2 minutes) → faster, 15 seconds at most
  - **Warm** (a command in the last hour) → your base interval
  - **Cold** (no command for over an hour) → base × 4, 5 minutes at most
- **Time window (emphasized):** evaluated in **Beijing time**. The clock is calibrated from the network, not only the target’s system clock. Two spellings:
  - Range: `09:00-18:00` (overnight works, e.g. `22:00-06:00`)
  - Hour list: `9,10,11,14`
  - **Empty = online all day**
  - Each agent, each day, jitters its edges: about ±20 minutes daily plus about ±5 minutes of noise, so the fleet does not wake or vanish on the same second.
  - **No C2 traffic outside the window**; it sleeps 5–20 minutes at random. The sidebar shows **Quiet**, not offline.
  - **Kill is still checked after hours**, so an off-window stop still lands.
- Arch: prefer `x86_64-unknown-linux-musl` (static, no glibc). Also aarch64 and gnu.
- Release: custom version label; empty uses the git short hash at build time.
- Debug: keep off in production so the target does not grow a log fingerprint.
- **Backup URL (remote ticket rotation, optional):** an **HTTPS** URL. When the GitHub token returns **401**, or after about 5 consecutive failures, the agent GETs this JSON, applies new credentials, and restarts. **Empty = off.** The same URL is fetched at most once per hour; if the body matches the current config it does not restart.

  The URL must serve **JSON** (any `Content-Type` is fine as long as the body parses). Fields:

  ```json
  {
    "channel": "github",
    "github_token": "github_pat_replace_with_new_fine_grained_token",
    "github_repo": "owner/private-repo",
    "password": "same-channel-secret-or-the-new-secret-you-will-change-together",
    "hmac_sig": ""
  }
  ```

  | Field | Required | Meaning |
  |---|---|---|
  | `channel` | No, default `github` | `github` or `notion`. For Notion: `github_token` is the Integration Token (`ntn_`), `github_repo` is the Database ID. |
  | `github_token` | Yes | The new check-in token. **It will also live on the target** — keep the same least privilege as in Credentials and permissions. |
  | `github_repo` | Yes | GitHub: `owner/repo`. Notion: database ID. |
  | `password` | Yes | Channel secret. If you change it, change the console decrypt password too or replies will not decrypt. |
  | `hmac_sig` | Situational | The web builder **does not verify a signature** by default; leave it empty. Only if you compiled with `BACKUP_SECRET` set does the agent require HMAC-SHA256 of `channel\|github_token\|github_repo\|password`, written as lowercase hex. |

  The URL must be `https://`. The JSON holds a new token — **do not put it on a guessable or search-indexed public path** (a public Gist is posting the new key on the internet). Use a host you control, object storage with a long random path, or your own Worker. The Backup URL itself is not changed by this JSON.
- **Guards:** optional hostname, user, marker file, minimum RAM; mismatch **exits silently** (sandbox / honeypot).
- **Process name / install path:** empty = **auto-disguise as a distro daemon**.
- Compress: strip symbols; optional UPX (needs `upx` on the console).

**Fileless modes (Linux)**

- **A · memfd deploy (fileless):** one pasteable command; the agent **runs in memory, no disk, no persistence, gone after reboot**. Needs Python 3.8+ on the target.
- **B · raw shellcode**: paste hex / `\xNN` / base64; generates an mmap-RWX jump command.

#### MCP

Expose the console to MCP-capable AI clients over stdio.

- The page fills a guide, capability JSON, and client registration JSON from the current login; all are one-click copy.
- You can download `mcp_server.py`.
- Three toolsets (`GITHUB_C2_MCP_TOOLS`):
  - **handoff** (default): list agents only.
  - **core**: run commands, read output, sysinfo, stats, list files, audit, tunnel status.
  - **full**: plus upload, sensitive collection, and killswitch (must confirm with `YES-DESTROY-ALL`).

The on-page kill button was removed from Settings to prevent wiping the fleet by accident. Use MCP full when you really need it.

#### Settings

- **GitHub tokens**: add several; only the last four characters are shown; they rotate to ease rate limits. The one used at build time is embedded in the agent — keep it least-privilege as in Credentials and permissions.
- **Console decrypt password**: encrypts commands and decrypts replies; synced with the builder channel secret.
- **Repository list**: `owner/repo` used for scan / send. Dual-channel backup repos are merged into this list.
- **Notion**: token and database IDs; one click adds the required columns.
- **Worker**: URLs (comma-separated), shared secret, path prefix. Empty fields do not overwrite; a single `-` clears a field.
- **Poll interval / comment cap / stale days**: background scan pace and auto-cleanup.
- **Web username / password**: console login; survives restart.
- **One-click Worker deploy**: paste a **Cloudflare API Token** (relay deploy only — never baked into the agent). Creates D1, applies schema, uploads the Worker, binds secrets, attaches hourly cleanup, enables workers.dev, and writes Settings / Builder (the first time it may promote an empty GitHub profile to dual; later it leaves your profile alone). Permissions: see Credentials and permissions.
- **Audit log**: who did what, to which agent, when.

Saving empty tokens or passwords does not wipe stored secrets. Settings GET responses never return full secrets to the browser.

### Channels and reliability

- On dual-channel, commands follow the **most recently active path**; the same command is also written to the sibling channel. The agent deduplicates so a switch does not drop the order.
- After enough Worker failures the agent **fails over to GitHub** and posts a visible `[Channel]` notice. If the notice fails, the switch **rolls back** so the console and the agent do not listen on different paths.
- After the GitHub backup is stable the agent probes Worker, re-registers, then **fails back** — also with a notice.
- If D1 is rebuilt and AUTOINCREMENT restarts, the agent and the console detect the stale watermark and reset it instead of staying deaf.
- **Kill is still checked outside the time window**, so an after-hours stop still lands.

---

## Install

### Requirements

| Item | Need |
|---|---|
| Console host | Linux (Debian / Ubuntu is easiest), Python 3, reachable from your lab |
| Building agents | Rust on the same host (`deploy.sh` can install rustup + `x86_64-unknown-linux-musl`) |
| Optional | `gcc` / `binutils` (link + strip), `upx` (pack), a Cloudflare account (Worker relay) |
| Targets | Per build: Linux musl / gnu, x86_64 or aarch64 |

The bundle already includes the tunnel server `stowaway_admin` and the reverse-shell server `cliws`. You usually do not download anything else.

### Standard install

```bash
git clone https://github.com/Kxiandaoyan/github-C2.git
cd github-C2
bash deploy.sh
```

The script will:

1. Find the `c2/` source tree (or a sidecar tarball).
2. Create a Python venv and install dependencies.
3. Ask for (or take from flags) the web account, channel secret, port, and bind address.
4. Write credentials to `c2/.runtime.env` (mode 0600) and the database.
5. Check tunnel / shell binaries; install Rust and the musl target if needed.
6. Start the console as systemd unit `c2-controller` (or a 5-second respawn loop if there is no systemd).
7. Health-check login + API. A failed upgrade rolls back to the previous snapshot.

When it finishes it prints a URL like:

```text
http://<server-ip>:<port>/?login=<user>&pass=<password>
```

Login is via query parameters; the page itself has no login form. Clear the password from the address bar after the first open.

### Command-line flags

```bash
bash deploy.sh --user admin --pass 'your-password' --c2-secret 'channel-secret' --port 8080 --bind 0.0.0.0
```

| Flag | Meaning |
|---|---|
| `--user` / `--pass` | Console login. On reinstall, Enter keeps the old values. |
| `--c2-secret` | Channel crypto secret, shared by builder and decrypt. |
| `--port` / `--bind` | Listen port and interface. Defaults `8080`, `0.0.0.0`. |
| `--noninteractive` | Unattended. Password may come from `C2_WEB_PASS`. |
| `--skip-toolchain` | Do not install Rust. The builder will not compile. |
| `--skip-always-poll` | Stop background scans after ~90s without a browser (default: always poll). |
| `--no-systemd` | Use the script respawn loop instead of systemd. |

Unattended plus toolchain: `C2_INSTALL_TOOLCHAIN=1 bash deploy.sh --noninteractive ...`

### After install

1. Open the printed URL and enter the console. Use **EN / 中文** at the top-right for the English UI.
2. **Settings → Cloudflare Worker relay**: deploy the relay with the Cloudflare token from Credentials and permissions (deploy only — not written into the agent). Or follow `c2/web-controller/cloudflare-worker/README.md` and use wrangler by hand.
3. **Builder** → Dual-channel. Confirm the Worker triple, then fill a **least-privilege** GitHub backup token / repo (this token **is compiled into the agent**). Build and download.
4. Run the agent on an authorized target. One sidebar row should appear with Worker + GitHub badges.
5. Send a harmless terminal command and confirm the echo before using Shell / Files / Tunnel.

You can also build GitHub-only, Worker-only, or Notion-only. Match the builder profile.

### Upgrade the console

Run `bash deploy.sh` again on the same host. Enter keeps the account and secret. A failed health check restores the previous code and database snapshot.

---

## Uninstall

Two layers: the **console** (your server) and the **agent** on the target.

### Uninstall the console

Root install example:

```bash
# 1. Stop the service
systemctl stop c2-controller
systemctl disable c2-controller
rm -f /etc/systemd/system/c2-controller.service
systemctl daemon-reload

# If it was installed as a normal user:
# systemctl --user stop c2-controller
# systemctl --user disable c2-controller
# rm -f ~/.config/systemd/user/c2-controller.service

# 2. If systemd was not used
pkill -f 'run-controller.sh --respawn' || true

# 3. Optional: logrotate
rm -f /etc/logrotate.d/c2-controller

# 4. Remove the tree (database, venv, runtime credentials)
# If the repo lives in /opt/github-C2:
rm -rf /opt/github-C2
```

The tunnel server and cliws go away with the directory. Delete the Cloudflare Worker / D1 yourself in the [Cloudflare Dashboard](https://dash.cloudflare.com). The script does not touch your cloud account.

### Uninstall an agent

Open that agent → **System info** or **Upgrade** → **Uninstall Agent**. After `uninstall` the agent will:

1. Remove persistence (systemd, cron, bashrc, rc.local, user services — whichever was installed).
2. Remove any hide module that was loaded.
3. Delete identity and watermark files in the state directory.
4. Delete its own binary and exit after about 5 seconds.

Memfd (fileless) mode never wrote a disk binary or persistence; a reboot clears it. You can still send uninstall to kill the live process.

Agents also honor kill outside the time window. To destroy every agent at once, use the MCP **full** killswitch with `YES-DESTROY-ALL`.
