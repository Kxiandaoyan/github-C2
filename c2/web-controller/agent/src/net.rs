//! net.rs — 统一网络层（bin 与 SO 双 crate 根共用，见 lib_entry.rs mod 声明）。
//!
//! 将原先分散在各调用点的裸 `ureq::get/post` 收敛到一个模块，三项加固集中实现：
//!   C. TLS：默认后端即 rustls + 编译期内置的 webpki-roots（Mozilla 静态根库），
//!      适应无 ca-certificates 的极简系统（Alpine 等）。此层额外提供
//!      「证书/连接错误 → 忽略校验重试一次」的降级回退（危险模式只作为兜底）。
//!   E. 代理出口：依次尊重 ALL_PROXY/HTTPS_PROXY/HTTP_PROXY（含小写变体），
//!      并按 NO_PROXY/no_proxy 对目标 host 做旁路判断（ureq 自身不读 NO_PROXY）。
//!   F. 时钟偏移：从任何成功响应的 `Date` 头反算「主机时钟 − 服务器时钟」偏移，
//!      供 timewindow.rs 等统一消费；仅内存保存，bin 侧由 stor.rs 负责持久化，
//!      重启后先按旧偏移工作、下一次成功往返后重新校准。

use std::sync::{Mutex, OnceLock};

// ── F: 时钟偏移 ────────────────────────────────────────────────────────────

static CLOCK_OFFSET: OnceLock<Mutex<Option<i64>>> = OnceLock::new();

fn offset_guard() -> &'static Mutex<Option<i64>> {
    CLOCK_OFFSET.get_or_init(|| Mutex::new(None))
}

/// 主机本地 Unix 秒（未校准）。
pub fn host_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 校准后的 Unix 秒：主机时钟 + 最近一次网络往返测得的偏移。
/// 无偏移（尚未校准/持久化）时等同 host_unix_secs()。
pub fn now_unix_secs() -> i64 {
    let off = match offset_guard().lock() {
        Ok(g) => match *g { Some(v) => v, None => 0 },
        Err(p) => match *(p.into_inner()) { Some(v) => v, None => 0 },
    };
    host_unix_secs() + off
}

/// 当前偏移（秒）；None = 尚未测得。
pub fn current_offset_secs() -> Option<i64> {
    match offset_guard().lock() {
        Ok(g) => *g,
        Err(p) => *(p.into_inner()),
    }
}

/// 写入偏移（来自网络往返校准或启动时的持久化恢复）。
pub fn set_offset_secs(v: i64) {
    if let Ok(mut g) = offset_guard().lock() {
        let cur = *g;
        if cur != Some(v) {
            *g = Some(v);
        }
    }
}

/// 从服务器响应头提取 `Date`（RFC 7231，如 "Sun, 06 Nov 1994 08:49:37 GMT"），
/// 与本地时钟求差并校准。差值超过 ±48h（VM 快照/无 NTP 以外的的情况多为坏头）
/// 时忽略，防止把错误值写坏。
pub fn note_response_headers(resp: &ureq::Response) {
    let Some(date_s) = resp.header("date") else { return };
    let Some(server_secs) = parse_http_date(date_s) else { return };
    let delta = server_secs - host_unix_secs();
    if delta.abs() < 48 * 3600 {
        set_offset_secs(delta);
    }
}

fn parse_http_date(s: &str) -> Option<i64> {
    // "Sun, 06 Nov 1994 08:49:37 GMT" — 跳过 weekday 前缀与尾部时区名
    let rest = if let Some(idx) = s.find(',') { s[idx + 1..].trim() } else { s };
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 4 { return None; }
    let day: u32 = parts[0].parse().ok()?;
    let month = match parts[1] {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    };
    let year: i32 = parts[2].parse().ok()?;
    let hms: Vec<&str> = parts[3].split(':').collect();
    if hms.len() != 3 { return None; }
    let hour: u32 = hms[0].parse().ok()?;
    let minute: u32 = hms[1].parse().ok()?;
    let second: u32 = hms[2].parse().ok()?;
    if hour >= 24 || minute >= 60 || second >= 60 { return None; }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86400 + (hour * 3600 + minute * 60 + second) as i64)
}

/// Howard Hinnant 的 civil→days 算法（返回自 1970-01-01 的天数）。
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if m < 1 || m > 12 || d == 0 || d > 31 { return None; }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;                      // [0, 399]
    let mp = if m > 2 { (m - 3) as u64 } else { (m + 9) as u64 };
    let doy = (153 * mp + 2) / 5 + (d - 1) as u64;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097) as i64 + doe as i64 - 719468)
}

// ── E: 代理与 NO_PROXY ───────────────────────────────────────────────────────

fn env_first(keys: &[&'static str]) -> Option<String> {
    for k in keys {
        if let Ok(v) = std::env::var(k) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn proxy_env_value() -> Option<String> {
    env_first(&[
        "ALL_PROXY", "all_proxy",
        "HTTPS_PROXY", "https_proxy",
        "HTTP_PROXY", "http_proxy",
    ])
}

/// 解析 URL 中的主机名（去除 scheme、路径、端口），用于 NO_PROXY 判断。
fn url_host(url: &str) -> String {
    let u = url.trim();
    let rest = if let Some(hi) = u.find("://") { &u[hi + 3..] } else { u };
    let path_trim = match rest.split_once('/') { Some((h, _)) => h, None => rest };
    let host = if let Some(ci) = path_trim.rfind(':') { &path_trim[..ci] } else { path_trim };
    let host = host.trim();
    if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        host[1..host.len() - 1].to_lowercase()
    } else {
        host.to_lowercase()
    }
}

/// 是否命中 NO_PROXY/no_proxy 白名单。支持 `*`、精确主机名、`.域名后缀` 与 `*.域名`。
fn no_proxy_matches(host: &str) -> bool {
    let raw = env_first(&["NO_PROXY", "no_proxy"]).unwrap_or_default();
    if raw.trim() == "*" { return true; }
    if host.is_empty() { return false; }
    let host_l = host.to_lowercase();
    for opt in raw.split(',') {
        let opt = opt.trim().to_lowercase();
        if opt.is_empty() { continue; }
        let opt_host = if let Some(colon) = opt.rfind(':') {
            if opt[colon + 1..].chars().all(|c| c.is_ascii_digit()) {
                opt[..colon].trim()  // 忽略端口，仅按主机匹配
            } else {
                opt.as_str()
            }
        } else {
            opt.as_str()
        };
        let opt_host = opt_host.trim();
        if opt_host == host_l { return true; }
        if opt_host.starts_with('.') && host_l.ends_with(opt_host) { return true; }
        if opt_host.starts_with("*.") && host_l.ends_with(&opt_host[1..]) { return true; }
    }
    false
}

// ── Agent 池（懒构建一次，连接池复用）─────────────────────────────────────

fn build_agent(proxy: Option<ureq::Proxy>) -> ureq::Agent {
    let mut b = ureq::AgentBuilder::new();
    if let Some(p) = proxy {
        b = b.proxy(p);
    }
    b.build()
}

fn direct_agent() -> &'static ureq::Agent {
    static DIRECT: OnceLock<ureq::Agent> = OnceLock::new();
    DIRECT.get_or_init(|| build_agent(None))
}

fn proxied_agent() -> Option<&'static ureq::Agent> {
    // 进程生命周期内代理环境变量不会变化；首次访问时求值一次即可。
    static PROXIED: OnceLock<Option<ureq::Agent>> = OnceLock::new();
    PROXIED.get_or_init(|| {
        proxy_env_value()
            .and_then(|v| ureq::Proxy::new(&v).ok())
            .map(|pr| build_agent(Some(pr)))
    }).as_ref()
}

/// 忽略证书校验的降级 agent（rustls danger verifier）。无 TLS 特性的交叉
/// 检查构建直接禁用该回退。审计修复（bug#9）：与主路径同样挂代理——
/// 仅代理出网的环境里，代理路径 TLS 校验失败后的降级重试若走直连必然
/// 连不上，回退等于没有。`use_proxy=false` 用于 NO_PROXY 命中的旁路请求。
#[cfg(feature = "tls")]
fn insecure_agent(use_proxy: bool) -> Option<&'static ureq::Agent> {
    if !use_proxy {
        static INSECURE_DIRECT: OnceLock<ureq::Agent> = OnceLock::new();
        return Some(INSECURE_DIRECT.get_or_init(|| build_insecure_agent(false)));
    }
    static INSECURE_PROXIED: OnceLock<Option<ureq::Agent>> = OnceLock::new();
    INSECURE_PROXIED
        .get_or_init(|| proxy_env_value()
            .and_then(|v| ureq::Proxy::new(&v).ok())
            .map(|_| build_insecure_agent(true)))
        .as_ref()
}

#[cfg(not(feature = "tls"))]
fn insecure_agent(_use_proxy: bool) -> Option<&'static ureq::Agent> {
    None
}

#[cfg(feature = "tls")]
fn build_insecure_agent(with_proxy: bool) -> ureq::Agent {
    use std::sync::Arc;
    use rustls::client::danger::ServerCertVerifier;
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(NoVerify {});
    let cfg = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_no_client_auth();
    let mut b = ureq::AgentBuilder::new().tls_config(Arc::new(cfg));
    if with_proxy {
        if let Some(pr) = proxy_env_value().and_then(|v| ureq::Proxy::new(&v).ok()) {
            b = b.proxy(pr);
        }
    }
    b.build()
}

/// 恒真校验器：接受任意证书链（校验失败后的一次性兜底）。
#[cfg(feature = "tls")]
#[derive(Debug)]
struct NoVerify;

#[cfg(feature = "tls")]
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme;
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED448,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA1,
        ]
    }
}

// ── NetReq：请求构建器（API 与 ureq 的链式写法对齐）─────────────────────────

enum NetBody {
    None,
    Str(String),
    Json(serde_json::Value),
}

pub struct NetReq {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: NetBody,
    timeout: Option<std::time::Duration>,
}

pub fn request(method: &str, url: &str) -> NetReq {
    NetReq {
        method: method.to_string(),
        url: url.to_string(),
        headers: Vec::new(),
        body: NetBody::None,
        timeout: None,
    }
}

pub fn get(url: &str) -> NetReq {
    request("GET", url)
}

pub fn post(url: &str) -> NetReq {
    request("POST", url)
}

impl NetReq {
    /// 传输层错误是否值得用「忽略校验」降级重试。
    /// 审计修复（bug#10）：
    ///   - Dns / ConnectionFailed：请求从未发出（DNS 解析失败、TCP/TLS 握手
    ///     失败——rustls 证书校验失败也归类于此），任何方法重试都安全；
    ///   - Io：可能发生在响应读取阶段（服务端已处理请求），对 POST 重试会
    ///     双发评论/注册——仅幂等方法（GET/HEAD）允许自动重试。
    /// HTTP 状态类错误（Error::Status，如 401/403/429）保持原有语义，不重试。
    fn is_retryable_conn(&self, e: &ureq::Error) -> bool {
        match e.kind() {
            ureq::ErrorKind::Dns
            | ureq::ErrorKind::ConnectionFailed => true,
            ureq::ErrorKind::Io => self.method == "GET" || self.method == "HEAD",
            _ => false,
        }
    }

    pub fn timeout(mut self, d: std::time::Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    pub fn set(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    fn run_with(&self, agent: &ureq::Agent) -> Result<ureq::Response, ureq::Error> {
        let mut req = agent.request(&self.method, &self.url);
        if let Some(t) = self.timeout {
            req = req.timeout(t);
        }
        for (k, v) in &self.headers {
            req = req.set(k, v);
        }
        match &self.body {
            NetBody::None => req.call(),
            NetBody::Str(s) => req.send_string(s),
            NetBody::Json(v) => req.send_json(v.clone()),
        }
    }

    fn exec(self) -> Result<ureq::Response, ureq::Error> {
        // E: 目标命中 NO_PROXY → 直连 agent；否则使用（若配置的）代理 agent。
        let host = url_host(&self.url);
        let byp = no_proxy_matches(&host);
        let proxied = proxied_agent();
        let agent = if byp { direct_agent() } else { match proxied { Some(a) => a, None => direct_agent() } };

        let first = self.run_with(agent);
        match first {
            Ok(r) => {
                note_response_headers(&r);   // F: 任何成功往返都可校准时钟
                Ok(r)
            }
            Err(e) if self.is_retryable_conn(&e) => {
                // TLS「证书校验失败」等传输错误：降级为忽略校验重试一次，
                // 覆盖无 ca-certificates/内网自签证书等场景。审计修复
                // （bug#8）：NO_PROXY 旁路（byp=true）同样允许回退——旁路
                // 直连一样会遇到坏证书库；重试 agent 与首选路径同路由
                // （byp → 直连 insecure；否则 → 带代理 insecure，无代理则直连）。
                let use_proxy = !byp && proxied.is_some();
                if let Some(ins) = insecure_agent(use_proxy) {
                    match self.run_with(ins) {
                        Ok(r) => {
                            note_response_headers(&r);
                            Ok(r)
                        }
                        Err(_) => Err(e),  // 保留原始（校验）错误，语义更诚实
                    }
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn call(self) -> Result<ureq::Response, ureq::Error> {
        self.exec()
    }

    pub fn send_string(mut self, data: &str) -> Result<ureq::Response, ureq::Error> {
        self.body = NetBody::Str(data.to_string());
        self.exec()
    }

    pub fn send_json(mut self, data: &serde_json::Value) -> Result<ureq::Response, ureq::Error> {
        self.body = NetBody::Json(data.clone());
        self.exec()
    }
}
