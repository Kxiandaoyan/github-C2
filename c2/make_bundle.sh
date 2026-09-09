#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# make_bundle.sh — 打包部署 bundle（正本同步，产物落在 deploy/ 根）
#
# 用法（仓库任意位置）：bash deploy/c2/make_bundle.sh
# 产物：deploy/c2-bundle.tar.gz（deploy/ 根，与 deploy.sh/README 并列）
# 服务器：上传 deploy.sh + c2-bundle.tar.gz → bash deploy.sh
#
# 正本位置（改代码就改这些地方）：
#   web-controller/          控制器（stowaway/stowaway_admin、cliws/cliws 二进制）
#   deploy/c2/agent          Agent 源码
#   deploy/deploy.sh         一键部署脚本（根目录正本；打包时同步副本进 c2/）
#   cloudflare-worker/       Worker 中转源（正本在 web-controller/cloudflare-worker/，
#                            即项目根内；app.py 优先读该目录，旧 worker_relay.js 布局仅兼容）
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # 仓库根
C2="$ROOT/deploy/c2"
WC="$ROOT/web-controller"
OUT="$ROOT/deploy/c2-bundle.tar.gz"

# ── 1. 同步 web-controller 到 c2/web-controller（每次整体重建，不会漂移）──
# agent 源码也住在 web-controller/ 里 —— 整个系统一个文件夹，打包天然单目录。
rm -rf "$C2/web-controller"
mkdir -p "$C2/web-controller/cliws" "$C2/web-controller/stowaway"

cp "$WC"/app.py "$WC"/db.py "$WC"/crypto.py "$WC"/github_api.py \
   "$WC"/notion_api.py "$WC"/worker_api.py "$WC"/mcp_server.py \
   "$WC"/requirements.txt "$C2/web-controller/"

cp -r "$WC/templates" "$C2/web-controller/templates"
rm -f "$C2/web-controller/templates/login.html"          # 隐形模式下永不渲染

cp -r "$WC/static"  "$C2/web-controller/static"

cp -r "$WC/tests"   "$C2/web-controller/tests"
rm -rf "$C2/web-controller/tests/__pycache__"

# Agent 源码（生成器在 web-controller/agent 编译它；排除 482MB 构建产物）
cp -r "$WC/agent" "$C2/web-controller/agent"
rm -rf "$C2/web-controller/agent/target"
rm -f  "$C2/web-controller/agent/check.ps1"

# cliws 只带二进制（源码留仓库正本，服务器无需重编译）
cp "$WC/cliws/cliws" "$C2/web-controller/cliws/cliws"
cp "$WC/stowaway/stowaway_admin" "$C2/web-controller/stowaway/stowaway_admin"

# Worker 中转源（一键部署用；住在 web-controller/ 项目根内的 cloudflare-worker/）
cp -r "$WC/cloudflare-worker" "$C2/web-controller/cloudflare-worker"

# 注意：deploy.sh 只存在于 deploy/ 根（解压者），绝不进包/不进 c2/——
# 包内的解压脚本没人能先解出来用，纯冗余。

# 清理工具/会话状态目录
find "$C2" -type d \( -name ".mimosa" -o -name ".claude" -o -name ".git" \
    -o -name "__pycache__" -o -name ".pytest_cache" \) -prune -exec rm -rf {} + 2>/dev/null || true

# ── 1b. 版本戳（git rev + 时间 + 关键文件哈希）────────────────────────────
_hash() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}
REV="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if git -C "$ROOT" status --porcelain 2>/dev/null | grep -q .; then REV="${REV}-dirty"; fi
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
FILES_HASH="$(
    { _hash "$C2/web-controller/app.py"
      _hash "$C2/web-controller/db.py"
      _hash "$C2/web-controller/mcp_server.py"
      _hash "$C2/web-controller/static/js/app.js"
      _hash "$C2/web-controller/agent/src/main.rs"
      _hash "$C2/web-controller/cloudflare-worker/worker.js"
    } | sort | { sha256sum 2>/dev/null || shasum -a 256; } | awk '{print $1}'
)"
{
    printf 'rev=%s\n' "$REV"
    printf 'date=%s\n' "$DATE"
    printf 'files_sha256=%s\n' "$FILES_HASH"
} > "$C2/web-controller/version.txt"
cp -f "$C2/web-controller/version.txt" "$WC/version.txt"

# ── 2. 单源打包（bundle 内只有一个文件夹：c2/web-controller）──────────────
tar --exclude="c2/make_bundle.sh" --exclude="c2/check_sync.sh" \
    --exclude="c2/.runtime.env" --exclude="c2/logs" \
    --exclude="c2/web-controller/venv" --exclude="c2/web-controller/c2_web.db" \
    --exclude="c2/web-controller/downloads" --exclude="c2/web-controller/agent/target" \
    -czf "$OUT" -C "$ROOT/deploy" c2

# ── 3. 产物校验（对 tarball 本身）────────────────────────────────────────────
LIST="$(tar -tzf "$OUT")"
for must in \
    c2/web-controller/app.py c2/web-controller/db.py c2/web-controller/requirements.txt \
    c2/web-controller/mcp_server.py c2/web-controller/static/js/app.js \
    c2/web-controller/templates/index.html c2/web-controller/version.txt \
    c2/run-controller.sh \
    c2/web-controller/stowaway/stowaway_admin c2/web-controller/cliws/cliws \
    c2/web-controller/cloudflare-worker/worker.js c2/web-controller/cloudflare-worker/schema.sql \
    c2/web-controller/agent/src/main.rs c2/web-controller/agent/Cargo.toml; do
    echo "$LIST" | grep -qx "$must" || { echo "[-] 缺少 $must" >&2; exit 1; }
done
# 包内绝不出现部署脚本（解压者在外面）、构建产物与多余源码
if echo "$LIST" | grep -qE '(__pycache__|\.pyc|c2_web\.db|/venv/|login\.html|\.mimosa|/target/|\.log$|\.ico$|cliws/src|cliws/Cargo|cliws/example|^c2/deploy\.sh$|^c2/agent)'; then
    echo "[-] 包内混入脏文件/多余内容：" >&2
    echo "$LIST" | grep -E '(__pycache__|\.pyc|c2_web\.db|/venv/|login\.html|\.mimosa|/target/|\.log$|\.ico$|cliws/src|cliws/Cargo|cliws/example|^c2/deploy\.sh$|^c2/agent)' >&2
    exit 1
fi

BUNDLE_SHA="$( { sha256sum "$OUT" 2>/dev/null || shasum -a 256 "$OUT"; } | awk '{print $1}' )"
echo "=============================================="
echo " bundle 就绪：$OUT"
echo " 大小：$(du -h "$OUT" | cut -f1)   文件数：$(echo "$LIST" | wc -l)"
echo " rev：$REV"
echo " sha256：$BUNDLE_SHA"
echo " 上传 deploy/deploy.sh + deploy/c2-bundle.tar.gz → bash deploy.sh"
echo "=============================================="
