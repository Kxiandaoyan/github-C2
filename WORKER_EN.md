# Manual Cloudflare Worker relay deploy

**Settings → one-click Worker deploy** does everything on this page for you. Use this page when you want to **build the relay yourself** in Cloudflare, without the one-click button. The relay only moves encrypted envelopes. **It does not store plaintext host identity.**

Chinese (same sections, same order): [WORKER.md](WORKER.md)  
Back to the product guide: [README_EN.md](README_EN.md)

> Use only on systems you own or are written-authorized to test.

---

## The three values (Path is not Secret)

People often treat **Worker Path** as a password and swap it with **Worker Secret** or the **channel secret**. They are three different things:

| Field in the console | Name in Cloudflare | What it is | If you get it wrong |
|---|---|---|---|
| **Worker URL** | workers.dev or your bound domain | The relay **host**. No path on the end | Cannot connect |
| **Worker Path** | Secret name: `PATH_SECRET` | The **first URL segment**, like a folder name. Not a password. Not an HTTP header | The relay treats you as a stranger and returns **404** |
| **Worker Secret** | Secret name: `C2_AUTH` | Shared key in the **`X-C2-Auth`** header. This is the relay password | Path can be right and you still get **401** |
| **Channel secret** (builder / console decrypt password) | *Not on Cloudflare* | AES-256-GCM envelope key | You can reach the relay but **commands and replies will not decrypt** |

**Do not** put the channel secret in Worker Secret.  
**Do not** put Worker Secret in Path.  
**Do not** paste a full URL into the Path box.

### Example

If you filled in:

```text
Worker URL:    https://c2relay.abc123.workers.dev
Worker Path:   a3f9k2-status
Worker Secret: 8f3c9e1a…
```

the agent / console actually calls:

```text
https://c2relay.abc123.workers.dev/a3f9k2-status/reg
Header: X-C2-Auth: 8f3c9e1a…
```

- Path is `a3f9k2-status`. **Not** `/a3f9k2-status`. **Not** the full URL.
- Use letters, digits, and hyphens only (e.g. `a3f9k2-status`).
- If Path is empty the client hits `/reg`. The relay requires `/<PATH_SECRET>/…`, so you get **404** — it looks like the site does not exist.
- After a successful one-click deploy, Settings / Builder are filled for you.

The Cloudflare API Token (one-click deploy) is **only for building the relay**. It is not compiled into the agent. It is not any of the three values above, and it is not the GitHub token. Permissions: [README_EN.md](README_EN.md) → Credentials and permissions.

---

## Path A: Cloudflare dashboard (no CLI)

All in [dash.cloudflare.com](https://dash.cloudflare.com). The free plan is enough.

Generate two random strings first (do not reuse one for both):

```bash
openssl rand -hex 16    # → Worker Secret / C2_AUTH
openssl rand -hex 8     # → Worker Path / PATH_SECRET (you may add hyphens, e.g. a3f9k2-status)
```

Any password generator works if you do not have openssl. Path: letters, digits, hyphens only.

### 1. Create the Worker

1. Left nav **Workers 和 Pages / Workers & Pages** → **创建 / Create** → **Worker**.
2. Name it `c2relay` (or another name) → **部署 / Deploy**.
3. **编辑代码 / Edit code**.
4. Open `c2/web-controller/cloudflare-worker/worker.js` in this repo, copy all of it, **replace** the editor contents → **保存并部署 / Save and Deploy**.

### 2. Create D1 and apply the schema

1. Left nav **存储和数据库 / Storage & Databases** → **D1 SQL 数据库 / D1 SQL Database** → **创建 / Create**, name `c2relay`.
2. Open that database → **控制台 / Console**.
3. Open `c2/web-controller/cloudflare-worker/schema.sql` in this repo, paste **all of it** → **执行 / Execute**. You should see three tables: `agents`, `comments`, `kill_flag`.

### 3. Bind D1 to the Worker (the variable name must be `DB`)

1. Back to Worker `c2relay` → **设置 / Settings** → **绑定 / Bindings** → **添加 / Add** → **D1 database**.
2. **变量名 / Variable name** must be exactly `DB` (the script reads `env.DB`).
3. Pick the `c2relay` database → save.

### 4. Set the two doors (this is where Path gets mixed up)

Still on that Worker → **设置 / Settings** → **变量和机密 / Variables and Secrets** → **添加 / Add**:

| Type | Name | Value |
|---|---|---|
| Secret | `C2_AUTH` | The **Worker Secret** from the prep step (header password) |
| Secret | `PATH_SECRET` | The **Worker Path** from the prep step (first URL segment, not a password) |

Deploy again after saving. Every endpoint then lives at:

```text
https://<your-host>/<PATH_SECRET>/…
Header: X-C2-Auth: <C2_AUTH>
```

### 5. Hourly cleanup (Cron)

Worker → **设置 / Settings** → **触发器 / Triggers** (or **Cron Triggers**) → **添加 / Add**.

Expression: `0 * * * *` (hourly: keep about the newest 500 rows per agent per direction; drop registrations that have been idle too long).

### 6. Copy the URL (optional second domain)

You get `https://c2relay.<your-subdomain>.workers.dev`. Put **only the origin** in the URL field — do not append `/a3f9k2-status/`.

Optional: same Worker → **域和路由 / Domains & Routes** → bind a hostname you already have on Cloudflare (e.g. `cdn.example.com`). Keep `workers.dev` **enabled**. Settings can take two URLs, comma-separated, as backups of each other.

---

## Path B: wrangler CLI

From `c2/web-controller/cloudflare-worker/` in this repo:

```bash
npm i -g wrangler
wrangler login
wrangler d1 create c2relay
# paste the printed database_id into wrangler.toml
wrangler d1 execute c2relay --remote --file=schema.sql
wrangler secret put C2_AUTH          # paste Worker Secret
wrangler secret put PATH_SECRET      # paste Worker Path (first URL segment)
wrangler deploy
```

The command prints `https://c2relay.<subdomain>.workers.dev`. Same rule: **that value goes in URL; PATH_SECRET goes in Path by itself.**

---

## Where to paste it in the console

| Console field | What to paste |
|---|---|
| Settings → Worker URLs | `https://c2relay.xxx.workers.dev` (two hosts, comma-separated, is fine). **No Path on the end.** |
| Settings → Worker Secret | Same as `C2_AUTH` |
| Settings → Worker Path | Same as `PATH_SECRET` (the segment only, no `/`) |
| The same three boxes in the Builder | Must match Settings or the compiled agent will miss the relay |

Saving an empty field **does not overwrite** a stored value. To clear one field, type a single `-`.

Then: Builder → **Dual-channel** or **Worker only** → compile. The sidebar should show a Worker badge.

Optional check (in `c2/web-controller/cloudflare-worker/`):

```bash
BASE=https://c2relay.xxx.workers.dev \
PATH_SECRET=a3f9k2-status \
AUTH='your-C2_AUTH' \
bash test_relay.sh
```

Expect a full pass. Do not paste `AUTH` or tokens into chat or commit them.

---

## Versus one-click deploy

One-click will: create D1, apply `schema.sql`, upload `worker.js`, set `C2_AUTH` + `PATH_SECRET`, attach hourly cron, enable workers.dev, and write Settings / Builder.

- Already deployed with one-click: you do not need this page unless you are moving accounts or rebuilding.
- You do not want to give the console a Cloudflare API Token: follow this page, then type the three values into Settings yourself.

Cloudflare API Token permissions (Chinese / English names) are in [README_EN.md](README_EN.md) → Credentials and permissions. That token is **relay deploy only — never baked into the agent**.

---

## Delete the relay

Neither `deploy.sh` nor one-click deletes your cloud resources. Remove the Worker and the D1 database yourself in the [Cloudflare Dashboard](https://dash.cloudflare.com).
