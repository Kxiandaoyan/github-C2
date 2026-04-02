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
            is_command INTEGER NOT NULL
        )",
        [],
    )?;

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

    Ok(conn)
}

pub fn get_cached_files(conn: &Connection, agent_id: &str, path: &str) -> Result<Option<String>> {
    let mut stmt =
        conn.prepare("SELECT content FROM file_cache WHERE agent_id = ? AND path = ?")?;
    let mut rows = stmt.query([agent_id, path])?;

    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

pub fn save_file_cache(conn: &Connection, agent_id: &str, path: &str, content: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO file_cache (agent_id, path, content, timestamp) VALUES (?, ?, ?, datetime('now'))",
        [agent_id, path, content],
    )?;
    Ok(())
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
) -> Result<()> {
    conn.execute(
        "INSERT INTO messages (agent_id, timestamp, content, is_command) VALUES (?, datetime('now'), ?, ?)",
        [agent_id, content, if is_command { "1" } else { "0" }],
    )?;
    Ok(())
}

pub fn get_messages(conn: &Connection, agent_id: &str) -> Result<Vec<(String, String, bool)>> {
    let mut stmt = conn.prepare(
        "SELECT timestamp, content, is_command FROM messages WHERE agent_id = ? ORDER BY id",
    )?;
    let rows = stmt.query_map([agent_id], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get::<_, i32>(2)? == 1))
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
