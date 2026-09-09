#!/bin/bash
# 控制器启动器：source .runtime.env（支持 bash %q 引用），再 exec venv python。
# systemd 的 EnvironmentFile 读不懂 %q，所以凭据必须走这条包装，不能直接 EnvironmentFile。
#   一次运行：  bash run-controller.sh
#   崩溃重拉：  bash run-controller.sh --respawn     # 5 秒循环，给没有 systemd 的机器
set -euo pipefail

# 实战修复（lab E2E）：systemd 服务环境无 HOME，控制器内 expanduser 解析
# ~/.cargo/env 会失败 → Builder 构建命令丢失 cargo 前缀 → cargo: command not found。
export HOME="${HOME:-/root}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVFILE="$HERE/.runtime.env"
APP_PY="$HERE/web-controller/app.py"
VENV_PY="$HERE/web-controller/venv/bin/python"
LOGDIR="$HERE/logs"
LOG="$LOGDIR/controller.log"
PIDFILE="$LOGDIR/controller.pid"

mkdir -p "$LOGDIR"

rotate_log() {
    local f="$1"
    local max="${C2_LOG_MAX_BYTES:-20971520}"   # 20 MiB
    [[ -f "$f" ]] || return 0
    local sz
    sz="$(wc -c < "$f" 2>/dev/null || echo 0)"
    [[ "$sz" -gt "$max" ]] || return 0
    # 进程已停或尚未起来：可以直接改名。运行中由 logrotate copytruncate 接手。
    local i
    for i in 3 2 1; do
        [[ -f "$f.$i" ]] && mv -f "$f.$i" "$f.$((i + 1))"
    done
    mv -f "$f" "$f.1"
    rm -f "$f.4"
}

load_env() {
    [[ -f "$ENVFILE" ]] || { echo "missing $ENVFILE" >&2; exit 1; }
    [[ -x "$VENV_PY" ]] || { echo "missing venv: $VENV_PY" >&2; exit 1; }
    set -a
    # shellcheck disable=SC1090
    . "$ENVFILE"
    set +a
}

run_once() {
    load_env
    rotate_log "$LOG"
    echo $$ > "$PIDFILE"
    exec "$VENV_PY" "$APP_PY"
}

run_respawn() {
    load_env
    echo $$ > "$PIDFILE"
    while true; do
        rotate_log "$LOG"
        "$VENV_PY" "$APP_PY" >> "$LOG" 2>&1 || true
        echo "$(date -Is) controller exited, respawn in 5s" >> "$LOG"
        sleep 5
    done
}

case "${1:-}" in
    --respawn) run_respawn ;;
    --once|"") run_once ;;
    *) echo "usage: $0 [--once|--respawn]" >&2; exit 2 ;;
esac
