// CONFIG 读取统一收敛到 crate::config::config()（panic 依据见 config.rs），
// 本文件不直接引用 CONFIG。
use crate::sys;
use rustls::ServerConfig;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 抽象连接：明文 TCP 或 TLS 流。
/// 用组合 trait 规避 dyn 多 non-auto trait 限制。
pub trait DynIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DynIo for T {}
pub type DynConn = Box<dyn DynIo>;

/// 设置 TCP keepalive（60 秒），等价于 Go 的 SetKeepAlive + SetKeepAlivePeriod。
pub fn set_tcp_keepalive(stream: TcpStream) -> io::Result<TcpStream> {
    let std_stream = stream.into_std()?;
    let sock = socket2::Socket::from(std_stream);
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60));
    sock.set_tcp_keepalive(&ka)?;
    let std_back = std::net::TcpStream::from(sock);
    std_back.set_nonblocking(true)?;
    TcpStream::from_std(std_back)
}

const HTTP_METHODS: [&[u8]; 14] = [
    b"CONNECT", b"GET", b"POST", b"HEAD", b"PUT", b"COPY", b"DELETE", b"MOVE", b"OPTIONS",
    b"LINK", b"UNLINK", b"TRACE", b"PATCH", b"WRAPPED",
];

pub fn is_http_header(header: &[u8]) -> bool {
    HTTP_METHODS.iter().any(|m| header.starts_with(m))
}

pub fn rsp_header(header: &[u8]) -> Vec<u8> {
    if header.windows(9).any(|w| w == b"WebSocket") {
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: CuteBi Network Tunnel, (%>w<%)\r\n\r\n".to_vec()
    } else if header.starts_with(b"CON") {
        b"HTTP/1.1 200 Connection established\r\nServer: CuteBi Network Tunnel, (%>w<%)\r\nConnection: keep-alive\r\n\r\n".to_vec()
    } else {
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: CuteBi Network Tunnel, (%>w<%)\r\nConnection: keep-alive\r\n\r\n".to_vec()
    }
}

/// 解析监听地址，返回 `(首选地址, 可选回退地址)`。
///
/// 兼容 Go 风格的 `":port"` 通配形式：Go 的 `net.ResolveTCPAddr` 允许省略主机段
/// （绑定全部接口），示例配置与文档用的都是这种形式；而 Rust `SocketAddr::from_str`
/// 要求主机段非空，直接 parse 会把整套示例配置打进 exit 7（LISTEN fail-closed）。
/// 补齐规则：
///
/// - `IP:port` / `[IP]:port`：原样 parse，`(addr, None)`；
/// - `:port`：双栈通配 `[::]:port`，v6 socket 建不出来时回退 `0.0.0.0:port`；
/// - 其余（含空串、裸主机名）：`InvalidInput` 拒绝——监听地址应是 IP 字面量或
///   `:port`，域名词解析不该发生在监听路径上。
pub(crate) fn resolve_listen_addr(listen_addr: &str) -> io::Result<(std::net::SocketAddr, Option<std::net::SocketAddr>)> {
    if let Ok(addr) = listen_addr.parse::<std::net::SocketAddr>() {
        return Ok((addr, None));
    }
    if let Some(port_s) = listen_addr.strip_prefix(':') {
        let port: u16 = port_s
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
        let v6 = std::net::SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port);
        let v4 = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
        return Ok((v6, Some(v4)));
    }
    Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported listen_addr form"))
}

/// 绑定单个已解析地址，开启 SO_REUSEADDR，可选 TCP FastOpen。
///
/// IPv6 通配地址（`[::]:port`，含 `:port` 简写展开）显式关 `V6ONLY` 开
/// 双栈，对齐 Go 通配监听语义；显式地址不动该项，保持内核默认。
async fn bind_exact(addr: std::net::SocketAddr, enable_tfo: bool) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        // 失败按内核默认继续：多数 Linux 默认 bindv6only=0，本就是双栈。
        let _ = sock.set_only_v6(false);
    }
    if enable_tfo {
        sys::enable_tcp_fastopen(&sock);
    }
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    sock.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_listener)
}

/// 创建 TCP 监听器：先绑首选地址，带回退地址时（`:port` 通配）v6 建不出
/// 来则退 v4——对齐 Go 在无 IPv6 内核上的行为；两个都失败才报错。
pub async fn bind_tcp_listener(listen_addr: &str, enable_tfo: bool) -> io::Result<TcpListener> {
    let (primary, fallback) = resolve_listen_addr(listen_addr)?;
    match bind_exact(primary, enable_tfo).await {
        Ok(l) => Ok(l),
        Err(primary_err) => match fallback {
            Some(v4) => bind_exact(v4, enable_tfo).await,
            None => Err(primary_err),
        },
    }
}

/// 单侧 flag 的子串命中判定。
///
/// 空 flag **不参与分流**（返回 false）：`windows(0)` 本会 panic；且「空串
/// 处处命中」等于把该侧分支变成默认吞流口，与下方「先 rust 后旧」的显式
/// 顺序语义相抵。未配置（空串）的一侧跳过判定，流量落入后续分支。
fn flag_hit(head: &[u8], flag: &[u8]) -> bool {
    !flag.is_empty() && head.windows(flag.len()).any(|w| w == flag)
}

/// 读 HTTP 首包：持续读直到非 HTTP 判定成立、读到 `\n\r\n` 头尾或缓冲满。
///
/// 返回已读字节数；读失败/超时关连接后返回 `None`。
async fn read_first_packet(
    conn: &mut DynConn,
    payload: &mut [u8],
    tcp_timeout: Duration,
) -> Option<usize> {
    let mut payload_len = 0usize;
    loop {
        if payload_len >= payload.len() {
            break;
        }
        let n = match timeout(tcp_timeout, conn.read(&mut payload[payload_len..])).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                let _ = conn.shutdown().await;
                return None;
            }
        };
        payload_len += n;
        if !is_http_header(&payload[..payload_len])
            || payload[..payload_len].ends_with(b"\n\r\n")
        {
            break;
        }
    }
    Some(payload_len)
}

/// TLS 升级（三处共用：非 HTTP 分支 / HTTP 分支 / `tls_side::start_tls`）。
///
/// 对齐 Go 语义：已读首包直接消费（不喂回 TLS），TLS 从后续字节开始。
/// 握手受 `tcp_timeout` 约束——慢握手的连接不能无限占用任务。
async fn upgrade_to_tls(
    tls_config: Arc<ServerConfig>,
    conn: DynConn,
    tcp_timeout: Duration,
) -> Option<DynConn> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    match timeout(tcp_timeout, acceptor.accept(conn)).await {
        Ok(Ok(tls_stream)) => Some(Box::new(tls_stream)),
        _ => {
            svc_log!("http: TLS 握手失败");
            None
        }
    }
}

/// 处理单条连接：读取 HTTP 首包，分流到 httpDNS / TCP / UDP / TLS 升级。
pub async fn handle_tunnel(
    mut conn: DynConn,
    mut payload: Box<[u8; 8192]>,
    tls_config: Option<Arc<ServerConfig>>,
) {
    let config = crate::config::config();
    // 经防御读取器取值：0 值会让 timeout() 立即超时、会话秒断。
    let tcp_timeout = config.tcp_timeout_duration();

    let Some(payload_len) = read_first_packet(&mut conn, payload.as_mut(), tcp_timeout).await
    else {
        return;
    };
    // 归一为非空：下游 windows / slice 索引均按「长度 ≥ 1」书写。
    let payload_len = payload_len.max(1);

    if !is_http_header(&payload[..payload_len]) {
        // 非 HTTP 首包：走 httpUDP 协议；配置了 TLS 则先升级再交付。
        let init = payload[..payload_len].to_vec();
        if let Some(tls_config) = tls_config {
            match upgrade_to_tls(tls_config, conn, tcp_timeout).await {
                Some(tls_stream) => crate::udp::handle_udp_session(tls_stream, Some(init)).await,
                None => {}
            }
            return;
        }
        crate::udp::handle_udp_session(conn, Some(init)).await;
        return;
    }

    // HTTP 首包：httpDNS 优先接管。
    if config.enable_http_dns
        && crate::dns::respond_http_dns(&mut conn, &payload[..payload_len]).await
    {
        let _ = conn.shutdown().await;
        return;
    }

    // 回复隧道握手响应头。
    let rsp = rsp_header(&payload[..payload_len]);
    if timeout(tcp_timeout, conn.write_all(&rsp)).await.is_err() {
        let _ = conn.shutdown().await;
        return;
    }

    // 有 TLS 配置则升级；已读的 HTTP 头不再喂回 TLS。
    if let Some(tls_config) = tls_config {
        conn = match upgrade_to_tls(tls_config, conn, tcp_timeout).await {
            Some(tls_stream) => tls_stream,
            None => return,
        };
    }

    // 先匹配 cns-rust 的新 flag，再匹配旧协议 flag。
    //
    // 两个 flag 都是「首包是否含某子串」的判定：若两者有包含关系且顺序反了，
    // 新协议客户端会被旧协议分支吃掉，表现为「连上了但数据面全错」，比连不上
    // 更难查。默认值互不为子串，但配置可改，故显式固定顺序而不押在默认值上。
    let head = &payload[..payload_len];
    let rust_flag = config.udp_flag_rust.as_bytes();
    if flag_hit(head, rust_flag) {
        // cns-rust 的握手即 HTTP 首包本身，无前置初始数据，
        // 故 XOR keystream 从握手之后的第一个字节起算。
        crate::udp_rust::handle_udp_session_rust(conn).await;
        return;
    }
    let udp_flag = config.udp_flag.as_bytes();
    if flag_hit(head, udp_flag) {
        crate::udp::handle_udp_session(conn, None).await;
    } else {
        crate::tcp::handle_tcp_session(conn, payload[..payload_len].to_vec()).await;
    }
}

/// accept 循环体；拆为独立任务以便 [`nwproxy_watch_accept`] 观测其 panic。
async fn nwproxy_accept_loop_body<F, Fut>(listener: TcpListener, handler: F)
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    loop {
        let conn = match listener.accept().await {
            Ok((c, _peer)) => c,
            Err(e) => {
                svc_log!("listen: accept 失败 {:?}", e.kind());
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };
        let conn = match set_tcp_keepalive(conn) {
            Ok(c) => c,
            Err(e) => {
                svc_log!("listen: keepalive 设置失败 {:?}", e.kind());
                continue;
            }
        };
        tokio::spawn(handler(conn));
    }
}

/// 观测 accept 循环任务终态。此前循环 panic 是静默的：句柄随手丢弃，
/// supervisor 无从感知。此处用 tokio 原生 `JoinError::is_panic()` 观测
/// （cns 无 futures 依赖，这是零新依赖的 catch_unwind 等价物），明文与
/// TLS 两处监听共用（唯一 choke point 在 [`spawn_accept_loop`]）。
///
/// 注意：`svc_log!` 受 `server-log` 特性门控（默认关），panic 明细由默认
/// panic hook 直落 stderr、不受门控；默认配置下「死的是哪个监听」不可观测，
/// 除非启用 `spawn_accept_loop` 里那档快死退避。勿因默认配置看不到日志而
/// 误判观测无效。
///
/// `on_death` 在任务终态确定后被调用：`false` = 无 panic 返回（loop 无出口，
/// 出现即异常），`true` = panic 终止。
fn nwproxy_watch_accept(
    handle: tokio::task::JoinHandle<()>,
    _name: &'static str,
    on_death: impl FnOnce(bool) + Send + 'static,
) {
    tokio::spawn(async move {
        match handle.await {
            Ok(()) => on_death(false),
            Err(e) if e.is_panic() => on_death(true),
            // runtime 关停取消任务，正常。
            Err(_) => {}
        }
    });
}

/// 监听 accept 循环（明文与 TLS 两处监听同构，收敛于此）：
/// accept 失败 3s 节流续收；keepalive 设置失败的连接直接丢弃；
/// 每条连接 spawn 独立 handler 任务。
pub(crate) fn spawn_accept_loop<F, Fut>(listener: TcpListener, handler: F)
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let inner = tokio::spawn(nwproxy_accept_loop_body(listener, handler));
    nwproxy_watch_accept(inner, "accept", |panicked| {
        if panicked {
            // 备选（默认不启用）：此处可 std::process::exit(exit_code::LISTEN)
            // 把单监听故障升级为 child 快死退出，由 supervisor 退避重建全部监听
            // ——与 bind_or_exit 同构，默认只留痕不退出。
            svc_log!("listen: accept 循环 panic 终止");
        } else {
            svc_log!("listen: accept 循环意外退出（无重启）");
        }
    });
}

/// 监听器绑定失败时的统一出口：记日志 + fail-closed 退出
/// （exit_code::LISTEN=7），避免「进程永挂、监听静默缺席」。
pub(crate) async fn bind_or_exit(listen_addr: &str, enable_tfo: bool) -> TcpListener {
    match bind_tcp_listener(listen_addr, enable_tfo).await {
        Ok(l) => l,
        Err(e) => {
            svc_log!("listen: {:?} 监听失败 {:?}", listen_addr, e.kind());
            std::process::exit(crate::exit_code::LISTEN);
        }
    }
}

/// 启动普通 HTTP 隧道监听。
pub async fn start_http_tunnel(listen_addr: String, tls_config: Option<Arc<ServerConfig>>) {
    let enable_tfo = crate::config::config().enable_tfo;
    let listener = bind_or_exit(&listen_addr, enable_tfo).await;
    spawn_accept_loop(listener, move |conn| {
        let tls_config = tls_config.clone();
        async move {
            handle_tunnel(Box::new(conn), Box::new([0u8; 8192]), tls_config).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_method_detection() {
        assert!(is_http_header(b"CONNECT host:80 HTTP/1.1"));
        assert!(is_http_header(b"GET / HTTP/1.1"));
        assert!(is_http_header(b"POST / HTTP/1.1"));
        assert!(is_http_header(b"HEAD /"));
        assert!(is_http_header(b"WRAPPED something"));
        assert!(!is_http_header(b"not-http"));
        assert!(!is_http_header(b"\x16\x03\x01..."));
        assert!(!is_http_header(b""));
    }

    // 按 Upgrade 种类回对应 101 / 200 响应头（两个同体用例表驱动合并）。
    #[test]
    fn rsp_header_replies_by_upgrade_kind() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"GET / HTTP/1.1\r\nUpgrade: WebSocket\r\n\r\n", b"HTTP/1.1 101 Switching Protocols"),
            (b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 Connection established"),
        ];
        for &(h, want) in cases {
            let rsp = rsp_header(h);
            assert!(rsp.starts_with(want), "rsp_header({:?}) 前缀不符", h);
        }
    }

    #[test]
    fn rsp_generic() {
        let h = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";
        let rsp = rsp_header(h);
        assert!(rsp.starts_with(b"HTTP/1.1 200 OK"));
        assert!(rsp.windows(7).any(|w| w == b"chunked"));
    }

    #[test]
    fn flag_hit_skips_empty_flag_and_matches_nonempty() {
        // 单侧 flag 配空串（load_config 只拦同值，不拦单侧空）：空侧必须
        // 不命中且不 panic（windows(0) 防护），流量留给后续分支。
        assert!(!flag_hit(b"GET / HTTP/1.1\r\n\r\n", b""));
        // flag 比 head 长：windows 返回空迭代器，本就不 panic、不命中。
        assert!(!flag_hit(b"short", b"httpUDP"));
        // rust 侧 / 旧协议侧常规命中面各保一条。
        assert!(flag_hit(b"xx cnsrUDP yy", b"cnsrUDP"));
        assert!(flag_hit(b"xx httpUDP yy", b"httpUDP"));
    }

    // 监听地址解析面：示例配置用 Go 风格 ":port" 通配形式，而 Rust
    // `SocketAddr::from_str` 不接受缺主机段——不补齐会把整套示例配置
    // 打进 exit 7。以下钉住解析面（bind 面需要真实端口，留待有工具链的环境）。
    #[test]
    fn resolve_listen_addr_supports_go_wildcard_port() {
        let (v6, fallback) = resolve_listen_addr(":2222").expect(":port 必须可解析");
        assert_eq!(
            v6,
            "[::]:2222".parse::<std::net::SocketAddr>().unwrap(),
            "通配首选应为 v6 双栈"
        );
        assert_eq!(
            fallback,
            Some("0.0.0.0:2222".parse::<std::net::SocketAddr>().unwrap()),
            "通配必须带 v4 回退"
        );
    }

    #[test]
    fn resolve_listen_addr_keeps_explicit_addrs() {
        for (form, want) in [
            ("127.0.0.1:8978", "127.0.0.1:8978"),
            ("[::1]:1224", "[::1]:1224"),
            ("[::]:9635", "[::]:9635"),
        ] {
            let (addr, fallback) =
                resolve_listen_addr(form).unwrap_or_else(|_| panic!("{form} 应可解析"));
            assert_eq!(addr, want.parse::<std::net::SocketAddr>().unwrap());
            assert_eq!(fallback, None, "显式地址不带回退：{form}");
        }
    }

    #[test]
    fn resolve_listen_addr_rejects_bad_forms() {
        for bad in ["", "nosuchhost:2222", "example.com", ":notaport", ":99999"] {
            assert!(resolve_listen_addr(bad).is_err(), "{bad:?} 必须被拒绝");
        }
    }

    // accept 循环 panic 观测：两终态（正常退出 / panic）均须触发 on_death
    // 回调，且回调拿到正确的 panicked 标记。
    #[tokio::test]
    async fn watch_accept_reports_normal_death_as_not_panicked() {
        let seen = Arc::new(std::sync::Mutex::new(None::<bool>));
        let f = Arc::clone(&seen);
        let handle = tokio::spawn(async {});
        nwproxy_watch_accept(handle, "nwproxy-test", move |panicked| {
            *f.lock().unwrap() = Some(panicked);
        });
        for _ in 0..100 {
            if seen.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            *seen.lock().unwrap(),
            Some(false),
            "正常退出必须触发回调且 panicked=false"
        );
    }

    #[tokio::test]
    async fn watch_accept_reports_panic_death_as_panicked() {
        let seen = Arc::new(std::sync::Mutex::new(None::<bool>));
        let f = Arc::clone(&seen);
        let handle = tokio::spawn(async {
            panic!("nwproxy 测试注入：accept 循环 panic");
        });
        nwproxy_watch_accept(handle, "nwproxy-test", move |panicked| {
            *f.lock().unwrap() = Some(panicked);
        });
        for _ in 0..100 {
            if seen.lock().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            *seen.lock().unwrap(),
            Some(true),
            "panic 终止必须触发回调且 panicked=true"
        );
    }
}
