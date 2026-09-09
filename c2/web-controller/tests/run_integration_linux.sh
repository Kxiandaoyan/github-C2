#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Agent 端到端集成测试（仅 Linux；在一次性容器/虚拟机中运行）
#
# 流程：构建 musl agent（无 TLS，走 http mock）→ 启动 mock GitHub →
#       运行 agent（C2_LAB 指向 mock，env 契约见 lab_run_agent.py）→
#       断言注册 / 命令往返 / 大输出分片
#
# 用法：  bash run_integration_linux.sh
#         测试口令自动取自 test_crypto.py 的金向量（单一事实源）。
# 依赖：  rust musl 目标、python3、同一仓库内的 web-controller/
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGENT_DIR="$ROOT/c2-linux-deploy/agent"
TESTS_DIR="$ROOT/web-controller/tests"
PORT="${MOCK_PORT:-8480}"
AGENT_BIN="$AGENT_DIR/target/x86_64-unknown-linux-musl/release/github-c2-agent"

# Single source of truth: the golden-vector password from the conformance tests
PASSWORD="$(python3 -c 'import sys; sys.path.insert(0, "'"$(dirname "$(realpath "$0")")"'"); import test_crypto; print(test_crypto.PWD)')"
[ -n "$PASSWORD" ] || { echo "[-] could not read vector password from test_crypto.py" >&2; exit 2; }

fail() { echo "[-] $*" >&2; exit 1; }
step() { echo "[*] $*"; }

cleanup() {
    [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
    [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. 构建（无 TLS 足够对 http mock 通信，构建也更快）────────────────────
step "building agent (musl, no TLS — http mock only)..."
( cd "$AGENT_DIR" && cargo build --release --target x86_64-unknown-linux-musl --no-default-features )
[ -f "$AGENT_BIN" ] || fail "agent binary not found"

# ── 2. 启动 mock SaaS ────────────────────────────────────────────────────────
step "starting mock SaaS on :$PORT ..."
python3 "$TESTS_DIR/mock_saas.py" "$PORT" &
MOCK_PID=$!
sleep 1
curl -sf -X POST "http://127.0.0.1:$PORT/__admin/reset" >/dev/null || fail "mock not reachable"

# ── 3. 运行 agent（环境契约全部封装在 lab_run_agent.py）───────────────────────
step "launching agent against mock..."
rm -rf /var/tmp/.systemd 2>/dev/null || true
AGENT_PID=$(python3 "$TESTS_DIR/lab_run_agent.py" "$AGENT_BIN" "http://127.0.0.1:$PORT" "$PASSWORD")
sleep 2

# ── 4. 断言 1：注册（Issue 创建）────────────────────────────────────────────
step "waiting for registration issue..."
FOUND=""
for _ in $(seq 1 40); do
    FOUND=$(curl -sf "http://127.0.0.1:$PORT/__admin/state" \
        | python3 -c 'import json,sys; s=json.load(sys.stdin); print(next(iter(s["issues"]), ""))')
    [ -n "$FOUND" ] && break
    sleep 1
done
[ -n "$FOUND" ] || fail "agent never registered (no issue created)"
ISSUE="$FOUND"
step "registered: issue #$ISSUE"

# ── 5. 注入命令并等待响应 ────────────────────────────────────────────────────
send_cmd() {  # $1 = command text → prints command_id
    ISSUE="$ISSUE" PORT="$PORT" WC_DIR="$ROOT/web-controller" \
    python3 - "$PASSWORD" "$1" <<'PYEOF'
import json, sys, os, urllib.request
sys.path.insert(0, os.environ["WC_DIR"])
import crypto
password, command = sys.argv[1], sys.argv[2]
cmd_id = "cmd-integ-001"
payload = json.dumps({"command_id": cmd_id, "command": command})
enc = crypto.encrypt(payload, password)
issue = os.environ["ISSUE"]
req = urllib.request.Request(
    f"http://127.0.0.1:{os.environ['PORT']}/__admin/command",
    data=json.dumps({"issue": issue, "body": f"<!-- c -->{enc}"}).encode(),
    headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req)
print(cmd_id)
PYEOF
}

collect_responses() {  # 打印解密+重组后的全部响应（含分片）
    ISSUE="$ISSUE" PORT="$PORT" WC_DIR="$ROOT/web-controller" \
    python3 - "$PASSWORD" <<'PYEOF'
import json, os, re, sys, urllib.request
sys.path.insert(0, os.environ["WC_DIR"])
import crypto
state = json.load(urllib.request.urlopen(
    f"http://127.0.0.1:{os.environ['PORT']}/__admin/state"))
parts = {}
for c in state["comments"].get(os.environ["ISSUE"], []):
    body = c["body"]
    if not body.startswith("<!-- r -->"):
        continue
    dec = crypto.decrypt(body[10:], sys.argv[1])
    if dec is None:
        continue
    env = json.loads(dec)
    content = env.get("content", "")
    m = re.match(r"\[Part ([^/]+)/(\d+)/(\d+)\]\n(.*)", content, re.S)
    if m:
        parts.setdefault(m.group(1), {})[int(m.group(2))] = m.group(4)
    else:
        print(content)
for resp_id, chunks in parts.items():
    print("".join(chunks[i] for i in sorted(chunks)))
PYEOF
}

step "sending command: id -un"
CMD_ID=$(send_cmd "id -un") || fail "send failed"
RESP=""
for _ in $(seq 1 30); do
    RESP=$(collect_responses | grep -v "^$" | head -1)
    [ -n "$RESP" ] && break
    sleep 1
done
[ -n "$RESP" ] || fail "no response received for $CMD_ID"
step "response: $RESP"

step "sending command: seq 1 9000  (~57 KB output → forces chunking)"
send_cmd "seq 1 9000" >/dev/null
CHUNKED=""
for _ in $(seq 1 60); do
    CHUNKED=$(collect_responses | tail -1)
    echo "$CHUNKED" | grep -qx "9000" && break
    sleep 1
done
echo "$CHUNKED" | grep -qx "9000" || fail "chunked response incomplete"
LINES=$(echo "$CHUNKED" | wc -l)
step "chunked response OK ($LINES lines, ends at 9000)"

step ""
step "ALL INTEGRATION CHECKS PASSED"
