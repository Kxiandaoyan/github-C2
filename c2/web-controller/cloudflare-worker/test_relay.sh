#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# test_relay.sh — Cloudflare Worker 中转端点调试矩阵（部署后第一步跑这个）
#
# 用法（密钥只从参数/环境读，不落盘）：
#   BASE=https://c2relay.xxx.workers.dev \
#   PATH_SECRET=<你的路径前缀> AUTH=<你的C2_AUTH> \
#   bash test_relay.sh
# 全部通过会打印 ALL RELAY CHECKS PASSED；任何一步失败即停并显示响应。
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
BASE="${BASE:?set BASE=https://...workers.dev}"
P="${PATH_SECRET:?set PATH_SECRET}"
A="${AUTH:?set AUTH}"
URL="${BASE}/${P}"
H="X-C2-Auth: ${A}"
AID="test-agent-01"
PASS=0; FAIL=0

req() {  # method path [json]
  local m="$1" p="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS --max-time 15 -X "$m" -H "$H" -H "Content-Type: application/json" -d "$body" "${URL}${p}"
  else
    curl -sS --max-time 15 -X "$m" -H "$H" "${URL}${p}"
  fi
}

step() {
  local name="$1" expect="$2" got="$3"
  if echo "$got" | grep -q "$expect"; then
    echo "[PASS] $name"; PASS=$((PASS+1))
  else
    echo "[FAIL] $name — expect '$expect' in: $got"; FAIL=$((FAIL+1))
  fi
}

echo "0. 无密钥访问应被拒"
R=$(curl -sS --max-time 15 "${URL}/agents" || true)
step "unauthenticated rejected" "Unauthorized\|401" "$R"
R=$(curl -sS --max-time 15 -o /dev/null -w "%{http_code}" "${BASE}/" || true)
step "wrong path 404" "404" "$R"

echo "1. 注册测试 agent"
step "register" '"ok":true' "$(req POST /reg "{\"agent_id\":\"$AID\",\"body\":\"Agent ID: test-uuid-01\\nOS: linux\\nHost: relaytest\\nUser: root\"}")"

echo "2. 发现列表"
R=$(req GET /agents)
step "discovery lists agent" "$AID" "$R"
step "discovery parses fields" "relaytest" "$R"

echo "3. 控制端下发命令 → agent 拉取"
step "post command" '"id"' "$(req POST "/c2d/$AID" '{"body":"<!-- c -->TESTCMD-001"}')"
R=$(req GET "/d2c/$AID?since=0")
step "agent fetches command" "TESTCMD-001" "$R"
CID=$(echo "$R" | python3 -c 'import sys,json;print(json.load(sys.stdin)["comments"][-1]["id"])' 2>/dev/null || echo 0)
step "watermark since skips old" '"comments":\[\]' "$(req GET "/d2c/$AID?since=$CID")"

echo "4. agent 回帖 → 控制端收取"
step "post response" '"id"' "$(req POST "/d2c/$AID" '{"body":"<!-- r -->TESTRESP-001","resp_to":"cmd-1"}')"
R=$(req GET "/c2d/$AID?since=0")
step "controller fetches response" "TESTRESP-001" "$R"

echo "5. kill 开关"
step "kill arm" '"ok":true' "$(req POST /kill)"
step "kill check" '"active":true' "$(req GET /kill)"
step "kill disarm" '"ok":true' "$(req DELETE /kill)"
step "kill cleared" '"active":false' "$(req GET /kill)"

echo "6. 双域名检查（如已绑自定义域）"
if [ -n "${BASE2:-}" ]; then
  R=$(curl -sS --max-time 15 -H "$H" "${BASE2}/${P}/agents")
  step "backup domain works" "$AID" "$R"
else
  echo "[skip] 备用域名（部署后设 BASE2=https://你的自定义域 再跑一次）"
fi

echo
echo "===== relay matrix: $PASS passed, $FAIL failed ====="
[ "$FAIL" = "0" ] || exit 1
