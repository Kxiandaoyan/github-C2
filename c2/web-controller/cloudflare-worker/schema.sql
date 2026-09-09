CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  reg_body TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL,
  direction TEXT NOT NULL,
  resp_to TEXT,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_comments_agent ON comments(agent_id, direction, id);

CREATE TABLE IF NOT EXISTS kill_flag (
  k INTEGER PRIMARY KEY CHECK (k = 1),
  raised_at TEXT NOT NULL
);
