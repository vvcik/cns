// CONFIG（OnceLock）仅被本文件的 `#[cfg(test)]` 用例用于 `set` 注入；生产路径
// 一律走 `config()`（见 config.rs 文档）。不加 cfg 门控则非 test 构建报
// unused_imports——与 tcp.rs 同款处理。
#[cfg(test)]
use crate::config::CONFIG;
use crate::http_tunnel::DynConn;
use crate::util::find_subslice;
use crate::xorcrypt::{encrypt_enabled, xor_crypt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// TCP DNS over UDP DNS：把客户端的 TCP DNS 请求（2 字节长度前缀 + 载荷）
/// 转为对同一 host 的 UDP DNS 请求，收到应答后按 TCP 长度前缀写回。
/// 缓冲固定 8192（对齐 Go 的 header 复用缓冲），避免短 HTTP 头导致大 DNS 包误判。
pub async fn dns_tcp_over_udp(c_conn: DynConn, host: String) {
    let config = crate::config::config();
    // 经防御读取器取值——0 值穿透 timeout() 即会话秒断，入口消毒 + 此处兜底。
    let tcp_timeout = config.tcp_timeout_duration();
    let udp_timeout = config.udp_timeout_duration();

    let mut c_conn = c_conn;
    let mut buffer = vec![0u8; 8192];
    let Some(payload_len) = read_dns_frame(&mut c_conn, &mut buffer, tcp_timeout).await else {
        svc_log!("dns: 客户端读失败");
        return;
    };

    /* 连接目标 UDP 地址 */
    let s_conn = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            svc_log!("dns: 建 socket 失败 {:?}", e.kind());
            return;
        }
    };
    let resolved = resolve_udp_target(&s_conn, &host).await;
    if let Some(addr) = resolved {
        if let Err(_e) = timeout(tcp_timeout, s_conn.connect(addr)).await {
            // 不打印 `_e` 本身：这里的 `Err` 是 `timeout` 的 `Elapsed`，本身就
            // 不含地址，但内层 `connect` 的 io::Error 被它吞掉了，为保持一致
            // 一律不展开错误对象——省得后来者「顺手改成打印 e」又带出域名。
            svc_log!("dns: 连接目标失败或超时");
            let msg = format!("Proxy address [{host}] DNS Dial() error");
            let _ = c_conn.write_all(msg.as_bytes()).await;
            return;
        }
    }

    let data = buffer[2..payload_len].to_vec();
    match timeout(tcp_timeout, s_conn.send(&data)).await {
        Ok(Ok(n)) if n > 0 => {}
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
            svc_log!("dns: 目标写入失败");
            return;
        }
    }
    let n = match timeout(udp_timeout, s_conn.recv(&mut buffer[2..])).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            svc_log!("dns: 目标读取失败");
            return;
        }
    };
    /* 包长度前缀 */
    buffer[0] = (n >> 8) as u8;
    buffer[1] = n as u8;
    if encrypt_enabled() {
        xor_crypt(&mut buffer[..2 + n], 0);
    }
    let _ = timeout(tcp_timeout, c_conn.write_all(&buffer[..2 + n])).await;
}

/// 读取一个完整请求帧：「2 字节大端长度前缀 + DNS 载荷」，载荷在连接上
/// 增量读取、边读边 XOR 解密（sub 从 0 起，Go 同构）。
/// 返回已入缓冲的总长度（前缀 + 载荷）；None = 读失败/超时/声明长度
/// 超过 8192 缓冲（防越界）直接返回 None。
async fn read_dns_frame(
    c_conn: &mut DynConn,
    buffer: &mut [u8],
    tcp_timeout: std::time::Duration,
) -> Option<usize> {
    let mut payload_len = 0usize;
    let mut xor_sub = 0usize;
    loop {
        let n = match timeout(tcp_timeout, c_conn.read(&mut buffer[payload_len..])).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };
        if encrypt_enabled() {
            xor_sub = xor_crypt(&mut buffer[payload_len..payload_len + n], xor_sub);
        }
        payload_len += n;
        if payload_len > 2 {
            let pkg_len = ((buffer[0] as usize) << 8) | buffer[1] as usize;
            /* 防止访问非法数据 */
            if pkg_len + 2 > buffer.len() {
                return None;
            }
            if pkg_len + 2 <= payload_len {
                break;
            }
        }
    }
    Some(payload_len)
}

/// 解析目标 host 并对已绑定 socket 做 UDP connect。
///
/// `UdpSocket::connect(&host)` 的域名词路径在 async 线程上做同步 getaddrinfo
/// （`timeout()` 包不住），故改为阻塞池解析，再对已解析地址 connect（UDP connect
/// 是即时 syscall，不再含解析阻塞）。选址对齐 tokio 原生语义：优先取与 socket
/// 同族的首个地址，无同族时退回首地址。
///
/// host 走 &str 式 ToSocketAddrs——"ip:port" 命中 std parse 快速路径、端口取串内
/// 值（元组式 `(host, 0u16)` 会让 ip:port 复合串落入 getaddrinfo 被 EAI_NONAME
/// 拒绝、裸 IP 快速路径端口恒取 0）。
///
/// ⚠ 铁律（同 tcp.rs）：不得在 async 上下文直接调用任何 ToSocketAddrs 的域名词
/// 路径；本文件两处解析点（httpDNS + 此处）均已收口阻塞池。
///
/// 返回 None = 解析失败（调用方跳过 connect，让后续 `send` 因未连接走既有「目标
/// 写入失败」出口——不新增回包）。
async fn resolve_udp_target(s_conn: &UdpSocket, host: &str) -> Option<std::net::SocketAddr> {
    let host = host.to_string();
    match tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        host.as_str()
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
    })
    .await
    {
        Ok(Ok(addrs)) => {
            let sock_v4 = s_conn
                .local_addr()
                .map(|a| a.is_ipv4())
                .unwrap_or(true);
            addrs
                .iter()
                .find(|a| a.is_ipv4() == sock_v4)
                .or_else(|| addrs.first())
                .copied()
        }
        _ => None,
    }
}

/// 处理 HTTP DNS 请求（uri 带 `dn=`）。返回是否已处理。
pub async fn respond_http_dns(c_conn: &mut DynConn, header: &[u8]) -> bool {
    let dn_pos = match find_subslice(header, b"dn=") {
        Some(p) => p,
        None => return false,
    };

    /* 读取 dn= 后的第一个非空白 token，等价于 Go 的 fmt.Sscanf("%s") */
    let rest = &header[dn_pos + 3..];
    let token_start = match rest.iter().position(|b| !b.is_ascii_whitespace()) {
        Some(p) => p,
        None => {
            svc_log!("dns: httpDNS 缺域名 token");
            return false;
        }
    };
    let token = &rest[token_start..];
    let token_end = token
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(token.len());
    let domain_begin = &token[..token_end];
    let domain = match domain_begin.iter().position(|&b| b == b'&') {
        Some(p) => &domain_begin[..p],
        None => domain_begin,
    };
    let domain = std::str::from_utf8(domain).unwrap_or("");

    let is_ipv6 = find_subslice(header, b"type=AAAA").is_some();
    let with_ttl = find_subslice(header, b"ttl=1").is_some();

    // tokio 的 `lookup_host` 在域名词路径上就是同步 getaddrinfo（阻塞当前
    // worker），与上方 TCP-DNS 路径同源；且 httpDNS 是无认证面（`dn=` 即查），
    // 解析风暴会把 worker 逐个挂死、放大成全服务瘫。故在阻塞池执行。
    // ⚠ 不得在 async 上下文直接 ToSocketAddrs。
    let domain_owned = domain.to_string();
    let ips = match tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (domain_owned.as_str(), 0u16)
            .to_socket_addrs()
            .map(|iter| iter.map(|sa| sa.ip()).collect::<Vec<_>>())
    })
    .await
    {
        Ok(Ok(ips)) => ips,
        _ => Vec::new(),
    };
    let found = if ips.is_empty() {
        None
    } else {
        ips.iter()
            .find(|ip| ip.is_ipv6() == is_ipv6)
            .map(|ip| *ip)
    };

    if let Some(ip) = found {
        let mut ip_str = ip.to_string();
        if with_ttl {
            ip_str.push_str(",60");
        }
        let body = ip_str.as_bytes();
        let resp = format!(
            "HTTP/1.0 200 OK\r\nConnection: Close\r\nServer: CuteBi Linux Network httpDNS, (%>w<%)\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = c_conn.write_all(resp.as_bytes()).await;
        let _ = c_conn.write_all(body).await;
    } else {
        let body = "HTTP/1.0 404 Not Found\r\nConnection: Close\r\nServer: CuteBi Linux Network httpDNS, (%>w<%)\r\nContent-type: charset=utf-8\r\n\r\n<html><head><title>HTTP DNS Server</title></head><body>查询域名失败<br/><br/>By: 萌萌萌得不要不要哒<br/>E-mail: 915445800@qq.com</body></html>";
        let _ = c_conn.write_all(body.as_bytes()).await;
    }
    true
}

// 测试区：dns.rs 的回环测试（TCP-DNS-over-UDP 的 2 字节长度前缀 + xor 往返），
// 以纯追加落在文件尾，生产区零改动。
//
// 夹具与全 crate 既有测试兼容（OnceLock「首设者胜出」）：proxy_key 与 tcp.rs 的
// install_config 对齐（"\nHost: "）、XOR_PASSWORD 与 tcp.rs/xorcrypt.rs 对齐
// （b"666"）——任何设置顺序下等价；tcp/udp_timeout 取 1s，超时面用例只断言
// 「窗口内零回包」这一顺序无关性质，即便设置顺序反转也不误报。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{JsonConfig, XOR_PASSWORD};
    use std::time::Duration;
    use tokio::io::duplex;

    /// 全局态夹具：取值与 tcp.rs / xorcrypt.rs 既有测试对齐，任何设置顺序下等价。
    fn install_dns_loop_fixture() {
        let _ = CONFIG.set(JsonConfig {
            proxy_key: "\nHost: ".into(),
            tcp_timeout: 1,
            udp_timeout: 1,
            enable_dns_tcp_over_udp: true,
            ..Default::default()
        });
        let _ = XOR_PASSWORD.set(b"666".to_vec());
    }

    /// 断言客户端侧在窗口内读到 EOF（函数已退出）且零回包。
    async fn read_eof_zero_payload(client: &mut tokio::io::DuplexStream, win: Duration) {
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(win, client.read(&mut buf))
            .await
            .expect("窗口内应有确定性结果（EOF），不得无限挂死");
        assert_eq!(n.expect("客户端读不应出错"), 0, "该路径必须零回包干净退出");
    }

    /// 畸形输入面①：声明长度超固定缓冲（0xFFFF+2 > 8192）——读循环内的守卫必须
    /// 静默退出：零回包、不挂死、不越界读。
    #[tokio::test]
    async fn dns_loop_malformed_declared_len_over_buffer_returns_silent() {
        let _guard = crate::config::global_lock();
        install_dns_loop_fixture();
        let (mut client, server) = duplex(8192);
        let conn: DynConn = Box::new(server);
        tokio::spawn(async move {
            dns_tcp_over_udp(conn, "127.0.0.1:53".to_string()).await;
        });
        // 前缀声明 0xFFFF、仅带 1 字节载荷：守卫在解析出声明值即刻 return，
        // 到不了 UDP 面。字节经 xor 加密模拟加密会话。
        let mut frame = vec![0xFFu8, 0xFF, 0xAA];
        xor_crypt(&mut frame, 0); // 夹具已设 XOR_PASSWORD=b"666"，函数侧按流续解
        client.write_all(&frame).await.expect("写入畸形帧");
        read_eof_zero_payload(&mut client, Duration::from_secs(5)).await;
    }

    /// 畸形输入面②：2 字节前缀后流终结（EOF 截断帧）——payload_len=2 不满足 >2
    /// 的解析条件，继续读遇 Ok(0) 走「客户端读失败」出口，静默退出零回包。
    #[tokio::test]
    async fn dns_loop_truncated_frame_after_prefix_eof_returns_silent() {
        let _guard = crate::config::global_lock();
        install_dns_loop_fixture();
        let (mut client, server) = duplex(8192);
        let conn: DynConn = Box::new(server);
        tokio::spawn(async move {
            dns_tcp_over_udp(conn, "127.0.0.1:53".to_string()).await;
        });
        // 仅发 2 字节前缀（声明 5 字节载荷），随即关闭写侧——截断帧形态。
        let mut frame = vec![0x00u8, 0x05];
        xor_crypt(&mut frame, 0);
        client.write_all(&frame).await.expect("写入截断帧");
        client.shutdown().await.expect("客户端写侧关闭");
        read_eof_zero_payload(&mut client, Duration::from_secs(5)).await;
    }

    /// 超时面：静默客户端（只连不发）——首读被 timeout(tcp_timeout) 包裹，确定性
    /// 上界退出且零回包。夹具 tcp_timeout=1s；若 OnceLock 被其他模块先设
    /// （tcp_timeout=600s），2s 窗口断言退化为「零回包 + 测试自身有界」仍成立。
    #[tokio::test]
    async fn dns_loop_silent_client_no_response_within_window() {
        let _guard = crate::config::global_lock();
        install_dns_loop_fixture();
        let (mut client, server) = duplex(8192);
        let conn: DynConn = Box::new(server);
        tokio::spawn(async move {
            dns_tcp_over_udp(conn, "127.0.0.1:53".to_string()).await;
        });
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await {
            // tcp_timeout=1s（常规序）：~1s Elapsed 退出 → EOF
            Ok(Ok(0)) => {}
            // 逆序异常态（tcp_timeout=600s）：2s 窗口内仍在等待——零回包即超时面成立
            Err(_) => {}
            Ok(Ok(n)) => panic!("静默客户端不得收到任何回包（收到 {n} 字节）"),
            Ok(Err(e)) => panic!("客户端读意外 io 错误: {e}"),
        }
    }

    /// 主钉：请求-响应闭环（2 字节长度前缀 + xor 往返）可执行规格，同时钉四个
    /// 环节：客户端帧组装（前缀+载荷整体 xor）→ 函数流式解密与帧组装 → UDP 侧
    /// 发送剥离前缀的明文载荷 → 应答加 2 字节前缀并整体 xor 后写回。
    #[tokio::test]
    async fn dns_loop_request_response_roundtrip_2byte_prefix_xor() {
        let _guard = crate::config::global_lock();
        install_dns_loop_fixture();

        // 期望明文：最小 DNS A 查询（example.com，ID=0x1234，QD=1）
        let req_plain: Vec<u8> = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ]
        .to_vec();
        // 期望明文：最小 DNS 应答（QR=1，QD=1，AN=1，A 记录 93.184.216.34）
        let resp_plain: Vec<u8> = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
            0x5d, 0xb8, 0xd8, 0x22,
        ]
        .to_vec();

        // UDP 桩服务器：收到明文查询即回固定应答
        let stub = UdpSocket::bind("127.0.0.1:0").await.expect("绑定 UDP 桩");
        let stub_port = stub.local_addr().expect("桩地址").port();
        let req_expected = req_plain.clone();
        let resp_for_stub = resp_plain.clone();
        let stub_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, src) = stub.recv_from(&mut buf).await.expect("桩接收请求");
            assert_eq!(&buf[..n], &req_expected[..], "UDP 侧应收到剥离前缀的明文查询");
            let _ = stub.send_to(&resp_for_stub, src).await;
        });

        let (mut client, server) = duplex(8192);
        let conn: DynConn = Box::new(server);
        let host = format!("127.0.0.1:{stub_port}");
        let server_task = tokio::spawn(async move {
            dns_tcp_over_udp(conn, host).await;
        });

        // 客户端侧：TCP 帧 = [len_hi, len_lo] + 明文载荷，整体 xor 加密（sub=0）
        let mut frame = Vec::with_capacity(2 + req_plain.len());
        frame.extend_from_slice(&(req_plain.len() as u16).to_be_bytes());
        frame.extend_from_slice(&req_plain);
        xor_crypt(&mut frame, 0);
        client.write_all(&frame).await.expect("写入加密查询帧");

        // 读回：函数对 [2 字节前缀 + 应答] 整体 xor（sub=0）后写回
        let frame_len = 2 + resp_plain.len();
        let mut got = vec![0u8; frame_len];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got))
            .await
            .expect("5s 内应收到完整应答帧")
            .expect("读应答帧不应出错");
        xor_crypt(&mut got, 0);
        let mut expect_wire = Vec::with_capacity(frame_len);
        expect_wire.extend_from_slice(&(resp_plain.len() as u16).to_be_bytes());
        expect_wire.extend_from_slice(&resp_plain);
        assert_eq!(got, expect_wire, "回环应答必须＝[2 字节前缀]+xor 还原后的原始应答");

        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), stub_task).await;
    }

    /// 回归①：裸 IP:port 整串解析——生产区同型的 &str 式 ToSocketAddrs 必须命中
    /// std parse 快速路径且端口取串内值。纯形态级断言：零 getaddrinfo、零网络。
    #[test]
    fn dns_resolve_bare_ip_literal_whole_string_port_from_string() {
        use std::net::ToSocketAddrs;
        // 快速路径前提：整串 "ip:port" 可直接 parse 为 SocketAddr（不经 getaddrinfo）
        let host = "127.0.0.1:9527";
        assert!(
            host.parse::<std::net::SocketAddr>().is_ok(),
            "IP 字面量:port 必须走 std parse 快速路径"
        );
        // 生产同型解析：端口必须来自串内值，而非元组缺省 0
        let addrs: Vec<std::net::SocketAddr> = host
            .to_socket_addrs()
            .expect("裸 IP:port 必须解析成功")
            .collect();
        assert_eq!(addrs.len(), 1, "IP 字面量快速路径应恰产出一个地址");
        assert_eq!(addrs[0].to_string(), "127.0.0.1:9527");
        assert_eq!(addrs[0].port(), 9527, "端口必须取串内值（元组式会恒取 0）");
        // IPv6 括号形态同族覆盖：同样命中快速路径
        assert!("[::1]:9527".parse::<std::net::SocketAddr>().is_ok());
        let v6: Vec<std::net::SocketAddr> = "[::1]:9527"
            .to_socket_addrs()
            .expect("IPv6 字面量:port 必须解析成功")
            .collect();
        assert_eq!(v6[0].to_string(), "[::1]:9527");
    }

    /// 回归②：域名形态解析路径——零网络依赖的形态级断言：
    /// · 路径分野：域名复合串不命中 std parse 快速路径（与裸 IP 不同）；
    /// · 拆段语义：&str 式解析把 "host:port" 拆 (host, port) 后才交 getaddrinfo
    ///   ——缺端口/非法端口/空串在进 getaddrinfo 前即被分类为 InvalidInput（零 syscall）；
    /// · 失败去向：解析失败在生产区折叠为 None → 跳过 connect → 既有「目标写入失败」
    ///   出口；本用例钉住其输入侧分类本身。
    #[test]
    fn dns_resolve_domain_form_failure_classification() {
        use std::net::ToSocketAddrs;
        // 路径分野：域名复合串不得误入 IP 字面量快速路径
        assert!(
            "example.com:53".parse::<std::net::SocketAddr>().is_err(),
            "域名复合串必须走 (host, port) 解析器路径"
        );
        let (h, p) = "example.com:53".rsplit_once(':').expect("应有端口段");
        assert_eq!(h, "example.com");
        assert_eq!(p.parse::<u16>().expect("端口段应为合法 u16"), 53);
        // 失败分类一：缺端口段（无冒号）——syscall 前即 InvalidInput
        let no_port = "example.com".to_socket_addrs().err().expect("缺端口必败");
        assert_eq!(no_port.kind(), std::io::ErrorKind::InvalidInput);
        // 失败分类二：端口段非法（超出 u16）——同样 syscall 前被拒
        let bad_port = "example.com:99999".to_socket_addrs().err().expect("非法端口必败");
        assert_eq!(bad_port.kind(), std::io::ErrorKind::InvalidInput);
        // 失败分类三：空串——形态级必败
        let empty = "".to_socket_addrs().err().expect("空串必败");
        assert_eq!(empty.kind(), std::io::ErrorKind::InvalidInput);
    }
}
