use rusqlite::{Connection, Result};
use std::path::PathBuf;

fn get_db_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("c2_gui.db");
        }
    }
    PathBuf::from("c2_gui.db")
}

pub fn init_db() -> Result<Connection> {
    let conn = Connection::open(get_db_path())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            agent_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            content TEXT NOT NULL,
            is_command INTEGER NOT NULL,
            command_id TEXT,
            response_to TEXT,
            message_type TEXT
        )",
        [],
    )?;

    let _ = conn.execute("ALTER TABLE messages ADD COLUMN command_id TEXT", []);
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN response_to TEXT", []);
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN message_type TEXT", []);

    conn.execute(
        "CREATE TABLE IF NOT EXISTS file_list (
            id INTEGER PRIMARY KEY,
            agent_id TEXT NOT NULL,
            path TEXT NOT NULL,
            name TEXT NOT NULL,
            is_dir INTEGER NOT NULL,
            size INTEGER,
            timestamp TEXT NOT NULL,
            UNIQUE(agent_id, path, name)
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS file_cache (
            id INTEGER PRIMARY KEY,
            agent_id TEXT NOT NULL,
            path TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            UNIQUE(agent_id, path)
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS processed_comments (
            agent_id TEXT NOT NULL,
            comment_id INTEGER NOT NULL,
            PRIMARY KEY (agent_id, comment_id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunk_state (
            agent_id TEXT NOT NULL,
            response_id TEXT NOT NULL,
            total INTEGER NOT NULL,
            current INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (agent_id, response_id, current)
        )",
        [],
    )?;

    let _ = conn.execute(
        "ALTER TABLE chunk_state ADD COLUMN timestamp TEXT NOT NULL DEFAULT (datetime('now'))",
        [],
    );

    Ok(conn)
}

pub fn save_config(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        [key, value],
    )?;
    Ok(())
}

pub fn get_config(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM config WHERE key = ?")?;
    let mut rows = stmt.query([key])?;

    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

pub fn save_message(
    conn: &Connection,
    agent_id: &str,
    content: &str,
    is_command: bool,
    command_id: Option<&str>,
    response_to: Option<&str>,
    message_type: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO messages (agent_id, timestamp, content, is_command, command_id, response_to, message_type) VALUES (?, datetime('now'), ?, ?, ?, ?, ?)",
        rusqlite::params![
            agent_id,
            content,
            if is_command { 1 } else { 0 },
            command_id,
            response_to,
            message_type,
        ],
    )?;
    Ok(())
}

pub fn get_messages(
    conn: &Connection,
    agent_id: &str,
) -> Result<
    Vec<(
        String,
        String,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
    )>,
> {
    let mut stmt = conn.prepare(
        "SELECT timestamp, content, is_command, command_id, response_to, message_type FROM messages WHERE agent_id = ? ORDER BY id",
    )?;
    let rows = stmt.query_map([agent_id], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get::<_, i32>(2)? == 1,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

pub fn save_file_list(
    conn: &Connection,
    agent_id: &str,
    path: &str,
    name: &str,
    is_dir: bool,
    size: i64,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO file_list (agent_id, path, name, is_dir, size, timestamp) VALUES (?, ?, ?, ?, ?, datetime('now'))",
        rusqlite::params![agent_id, path, name, if is_dir { 1 } else { 0 }, size],
    )?;
    Ok(())
}

pub fn clear_file_list(conn: &Connection, agent_id: &str, path: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM file_list WHERE agent_id = ? AND path = ?",
        [agent_id, path],
    )?;
    Ok(())
}

pub fn get_file_list(
    conn: &Connection,
    agent_id: &str,
    path: &str,
) -> Result<Vec<(String, bool, i64)>> {
    let mut stmt = conn.prepare("SELECT name, is_dir, size FROM file_list WHERE agent_id = ? AND path = ? ORDER BY is_dir DESC, name")?;
    let rows = stmt.query_map([agent_id, path], |row| {
        Ok((row.get(0)?, row.get::<_, i32>(1)? == 1, row.get(2)?))
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

pub fn is_comment_processed(conn: &Connection, agent_id: &str, comment_id: i64) -> Result<bool> {
    let mut stmt =
        conn.prepare("SELECT 1 FROM processed_comments WHERE agent_id = ? AND comment_id = ?")?;
    Ok(stmt.exists([agent_id, &comment_id.to_string()])?)
}

pub fn mark_comment_processed(conn: &Connection, agent_id: &str, comment_id: i64) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO processed_comments (agent_id, comment_id) VALUES (?, ?)",
        [agent_id, &comment_id.to_string()],
    )?;
    Ok(())
}

pub fn save_chunk_part(
    conn: &Connection,
    agent_id: &str,
    response_id: &str,
    total: usize,
    current: usize,
    content: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO chunk_state (agent_id, response_id, total, current, content, timestamp) VALUES (?, ?, ?, ?, ?, datetime('now'))",
        rusqlite::params![agent_id, response_id, total as i64, current as i64, content],
    )?;
    Ok(())
}

pub fn load_chunk_parts(
    conn: &Connection,
    agent_id: &str,
    response_id: &str,
) -> Result<Vec<(usize, usize, String)>> {
    let mut stmt = conn.prepare(
        "SELECT total, current, content FROM chunk_state WHERE agent_id = ? AND response_id = ? ORDER BY current",
    )?;
    let rows = stmt.query_map([agent_id, response_id], |row| {
        Ok((
            row.get::<_, i64>(0)? as usize,
            row.get::<_, i64>(1)? as usize,
            row.get(2)?,
        ))
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

pub fn clear_chunk_parts(conn: &Connection, agent_id: &str, response_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM chunk_state WHERE agent_id = ? AND response_id = ?",
        [agent_id, response_id],
    )?;
    Ok(())
}

pub fn cleanup_stale_chunk_parts(conn: &Connection, max_age_minutes: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM chunk_state WHERE timestamp < datetime('now', ?)",
        [format!("-{} minutes", max_age_minutes)],
    )?;
    Ok(())
}
