#!/bin/bash
# 根 web-controller/ 与 deploy/c2/web-controller/ 关键文件哈希比对。
# 不一致则失败——挡住「改了根忘 repack」或「只改了副本」。
# 用法：bash deploy/c2/check_sync.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
A="$ROOT/web-controller"
B="$ROOT/deploy/c2/web-controller"

FILES=(
    app.py
    db.py
    crypto.py
    mcp_server.py
    worker_api.py
    notion_api.py
    github_api.py
    requirements.txt
    static/js/app.js
    templates/index.html
    cloudflare-worker/worker.js
    agent/src/main.rs
    agent/src/worker.rs
    agent/src/failover.rs
    agent/src/net.rs
    agent/src/crypto.rs
    agent/src/persist.rs
    agent/src/stor.rs
    agent/src/ws_pty.rs
    agent/src/commands.rs
    agent/src/stowaway.rs
    agent/Cargo.toml
    tests/test_controller_units.py
)

hash_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

fail=0
missing=0
for rel in "${FILES[@]}"; do
    fa="$A/$rel"
    fb="$B/$rel"
    if [[ ! -f "$fa" ]]; then
        echo "[-] 正本缺失 $fa" >&2
        missing=1
        continue
    fi
    if [[ ! -f "$fb" ]]; then
        echo "[-] 副本缺失 $fb" >&2
        fail=1
        continue
    fi
    ha="$(hash_of "$fa")"
    hb="$(hash_of "$fb")"
    if [[ "$ha" != "$hb" ]]; then
        echo "[-] 漂移 $rel" >&2
        echo "    root   $ha" >&2
        echo "    deploy $hb" >&2
        fail=1
    fi
done

if [[ $missing -ne 0 ]]; then
    echo "[-] 仓库根没有 web-controller/，无法比对" >&2
    exit 2
fi
if [[ $fail -ne 0 ]]; then
    echo "[-] 双树不一致。改代码只改 web-controller/，然后跑 deploy/c2/make_bundle.sh 再提交。" >&2
    exit 1
fi
echo "[+] 关键文件与正本一致（${#FILES[@]} 个）"
