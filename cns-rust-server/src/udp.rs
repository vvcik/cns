// CONFIG 读取统一收敛到 crate::config::config()（panic 依据见 config.rs），
// 本文件不直接引用 CONFIG。
use crate::http_tunnel::DynConn;
use crate::xorcrypt::{encrypt_enabled, xor_crypt};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// 单个 httpUDP 数据包的解析结果。
enum PktParse {
    /// 数据不足（或包长非法），等待更多数据
    NeedMore,
    /// 协议头字节错误，应跳过一个字节
    BadHeader,
    /// 解析成功：目标地址、载荷范围（含结束位置）
    Ok {
        addr: SocketAddr,
        start: usize,
        end: usize,
    },
}

/// 解析 httpUDP 协议头。
///
/// 数据流格式：2 字节小端包长 + 协议头（IPv4 12 字节 / IPv6 24 字节）+ UDP 载荷。
fn parse_packet(data: &[u8], pkg_sub: usize) -> PktParse {
    if pkg_sub + 2 >= data.len() {
        return PktParse::NeedMore;
    }
    let pkg_len = (data[pkg_sub] as u16) | ((data[pkg_sub + 1] as u16) << 8);
    if pkg_sub + 2 + pkg_len as usize > data.len() || pkg_len <= 10 {
        return PktParse::NeedMore;
    }
    if data[pkg_sub + 3] != 0 || data[pkg_sub + 4] != 0 {
        return PktParse::BadHeader;
    }
    // ⚠ 这里用相对下标 `data[pkg_sub + 5]`，而非 Go 原版（`udp.go:91`）的
    // 绝对下标 `httpUDP_data[5]`——后者在分包循环里从第 2 个包起仍读**首包**
    // 的 ATYP 字节，一批里首包 v4、后续 v6（或反之）时后续包会被按错误的地址
    // 族解析，长度与偏移全错。这是修正 Go 的 bug，非 bug-for-bug 兼容：
    // `pkg_sub == 0`（单包/首包）时两者等价，行为不变，兼容性不受影响；多包
    // 场景才是「从错改对」。旧客户端只有在依赖此 bug 时才被破坏——那意味着它
    // 本就在发错格式。
    let (ip, port, head_len) = if data[pkg_sub + 5] == 1 {
        /* ipv4 */
        let ip4 = std::net::Ipv4Addr::new(
            data[pkg_sub + 6],
            data[pkg_sub + 7],
            data[pkg_sub + 8],
            data[pkg_sub + 9],
        );
        let port = u16::from_be_bytes([data[pkg_sub + 10], data[pkg_sub + 11]]);
        (SocketAddr::new(ip4.into(), 0), port, 12usize)
    } else {
        /* ipv6 */
        if pkg_len <= 24 {
            return PktParse::NeedMore;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[pkg_sub + 6..pkg_sub + 22]);
        let ip6 = std::net::Ipv6Addr::from(octets);
        let port = u16::from_be_bytes([data[pkg_sub + 22], data[pkg_sub + 23]]);
        (SocketAddr::new(ip6.into(), 0), port, 24usize)
    };
    let addr = SocketAddr::new(ip.ip(), port);
    PktParse::Ok {
        addr,
        start: pkg_sub + head_len,
        end: pkg_sub + 2 + pkg_len as usize,
    }
}

/// httpUDP 协议解析 + 发送到 UDP 目标。
///
/// 返回已消费的字节数；-1 表示发送失败，0 表示数据不足，1 表示协议头错误。
async fn write_to_server(udp_sock: &UdpSocket, data: &[u8]) -> i64 {
    let mut pkg_sub = 0usize;
    loop {
        if pkg_sub + 2 >= data.len() {
            break;
        }
        match parse_packet(data, pkg_sub) {
            PktParse::NeedMore => return 0,
            PktParse::BadHeader => return 1,
            PktParse::Ok { addr, start, end } => {
                let payload = &data[start..end];
                match udp_sock.send_to(payload, addr).await {
                    Ok(n) if n > 0 => {}
                    _ => return -1,
                }
                pkg_sub = end;
            }
        }
    }
    pkg_sub as i64
}

/// 绑定临时 UDP 端口。优先 IPv6 双栈，失败时回退到 IPv4。
async fn bind_udp_socket() -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(false)?;
    let addr: std::net::SocketAddr = "[::]:0"
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

/// 初始化 UDP 会话：
/// - 加密开启且有初始数据时，先校验并解密首包，得到 c2s 方向的 XOR 下标；
/// - 绑定本机临时 UDP 端口。
async fn init_udp(http_udp_data: Option<&mut Vec<u8>>) -> Option<(Arc<UdpSocket>, usize)> {
    let mut c2s_xor_sub = 0usize;
    if let Some(data) = http_udp_data {
        if encrypt_enabled() {
            let mut de = [0u8; 5];
            let n = std::cmp::min(5, data.len());
            de[..n].copy_from_slice(&data[..n]);
            xor_crypt(&mut de, 0);
            if de[2] != 0 || de[3] != 0 || de[4] != 0 {
                return None;
            }
            c2s_xor_sub = xor_crypt(data, 0);
        }
    }
    let socket = match bind_udp_socket().await {
        Ok(s) => s,
        Err(e) => {
            svc_log!("udp: 监听失败 {:?}", e.kind());
            return None;
        }
    };
    Some((Arc::new(socket), c2s_xor_sub))
}

/// UDP server -> client：读 UDP 应答，封装成 httpUDP 协议写回客户端。
async fn udp_server_to_client<W: AsyncWrite + Unpin>(
    udp_sock: &UdpSocket,
    c_write: &mut W,
    payload: &mut [u8; 65536],
    mut s2c_xor_sub: usize,
) {
    let config = crate::config::config();
    // 经防御读取器取值——0 值穿透 timeout() 即会话秒断，入口消毒 + 此处兜底。
    let udp_timeout = config.udp_timeout_duration();

    loop {
        let r = timeout(udp_timeout, udp_sock.recv_from(&mut payload[24..])).await;
        let (payload_len, raddr) = match r {
            Ok(Ok(x)) if x.0 > 0 => x,
            _ => return,
        };
        /* 兼容双栈 socket 收到的 IPv4-mapped 地址，等价于 Go 的
           bytes.HasPrefix(RAddr.IP, {0,0,...,0xff,0xff}) 判断 */
        let ipv4 = match raddr {
            SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped(),
            SocketAddr::V4(v4) => Some(*v4.ip()),
        };
        let ignore_head_len = if let Some(ip4) = ipv4 {
            /* ipv4 */
            payload[12] = (payload_len as u8).wrapping_add(10);
            payload[13] = ((payload_len + 10) >> 8) as u8;
            payload[14..18].copy_from_slice(&[0, 0, 0, 1]);
            payload[18..22].copy_from_slice(&ip4.octets());
            12
        } else if let SocketAddr::V6(v6) = raddr {
            /* ipv6 */
            payload[0] = (payload_len as u8).wrapping_add(22);
            payload[1] = ((payload_len + 22) >> 8) as u8;
            payload[2..6].copy_from_slice(&[0, 0, 0, 3]);
            payload[6..22].copy_from_slice(&v6.ip().octets());
            0
        } else {
            return;
        };
        payload[22] = (raddr.port() >> 8) as u8;
        payload[23] = (raddr.port() & 0xff) as u8;

        let out_len = 24 + payload_len;
        if encrypt_enabled() {
            s2c_xor_sub = xor_crypt(&mut payload[ignore_head_len..out_len], s2c_xor_sub);
        }
        if timeout(udp_timeout, c_write.write_all(&payload[ignore_head_len..out_len]))
            .await
            .is_err()
        {
            return;
        }
    }
}

/// UDP client -> server：读客户端 httpUDP 数据，解析后发送到 UDP 目标。
async fn udp_client_to_server<R: AsyncRead + Unpin>(
    udp_sock: &UdpSocket,
    c_read: &mut R,
    payload: &mut [u8; 65536],
    http_udp_data: Option<Vec<u8>>,
    mut c2s_xor_sub: usize,
) {
    let config = crate::config::config();
    // 经防御读取器取值（同上）。
    let udp_timeout = config.udp_timeout_duration();

    let mut payload_len = 0usize;
    if let Some(data) = http_udp_data {
        /* init_udp 已完成首包解密 */
        let w = write_to_server(udp_sock, &data).await;
        if w == -1 {
            return;
        }
        if (w as usize) < data.len() {
            payload_len = data.len() - w as usize;
            payload[..payload_len].copy_from_slice(&data[w as usize..]);
        }
    }
    loop {
        let r = timeout(udp_timeout, c_read.read(&mut payload[payload_len..])).await;
        let n = match r {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };
        if encrypt_enabled() {
            c2s_xor_sub = xor_crypt(&mut payload[payload_len..payload_len + n], c2s_xor_sub);
        }
        payload_len += n;
        let w = write_to_server(udp_sock, &payload[..payload_len]).await;
        if w == -1 {
            return;
        } else if (w as usize) < payload_len {
            let remain = payload_len - w as usize;
            payload.copy_within(w as usize..payload_len, 0);
            payload_len = remain;
        } else {
            payload_len = 0;
        }
    }
}

/// 处理 httpUDP 会话。http_udp_data 为握手前已读到的初始数据（可能包含多个包）。
pub async fn handle_udp_session(c_conn: DynConn, http_udp_data: Option<Vec<u8>>) {
    let (mut c_read, mut c_write) = tokio::io::split(c_conn);

    let mut http_udp_data = http_udp_data;
    let (udp_sock, c2s_xor_sub) = match init_udp(http_udp_data.as_mut()).await {
        Some(x) => x,
        None => {
            svc_log!("udp: 非 httpUDP 协议或解密失败");
            return;
        }
    };

    let mut buf_c2s = Box::new([0u8; 65536]);
    let mut buf_s2c = Box::new([0u8; 65536]);
    let udp_sock2 = udp_sock.clone();

    let t1 = tokio::spawn(async move {
        udp_client_to_server(
            &udp_sock,
            &mut c_read,
            &mut buf_c2s,
            http_udp_data,
            c2s_xor_sub,
        )
        .await;
    });
    let t2 = tokio::spawn(async move {
        udp_server_to_client(&udp_sock2, &mut c_write, &mut buf_s2c, 0).await;
    });

    let (mut t1, mut t2) = (t1, t2);

    tokio::select! {
        _ = &mut t1 => t2.abort(),
        _ = &mut t2 => t1.abort(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ipv4_packet(ip: [u8; 4], port: u16, payload: &[u8]) -> Vec<u8> {
        let pkg_len = 10 + payload.len();
        let mut v = vec![0u8; 2 + pkg_len];
        v[0] = pkg_len as u8;
        v[1] = (pkg_len >> 8) as u8;
        v[3] = 0;
        v[4] = 0;
        v[5] = 1;
        v[6..10].copy_from_slice(&ip);
        v[10] = (port >> 8) as u8;
        v[11] = (port & 0xff) as u8;
        v[12..].copy_from_slice(payload);
        v
    }

    fn ipv6_packet(ip: Ipv6Addr, port: u16, payload: &[u8]) -> Vec<u8> {
        let pkg_len = 22 + payload.len();
        let mut v = vec![0u8; 2 + pkg_len];
        v[0] = pkg_len as u8;
        v[1] = (pkg_len >> 8) as u8;
        v[3] = 0;
        v[4] = 0;
        v[5] = 3;
        v[6..22].copy_from_slice(&ip.octets());
        v[22] = (port >> 8) as u8;
        v[23] = (port & 0xff) as u8;
        v[24..].copy_from_slice(payload);
        v
    }

    #[test]
    fn parse_ipv4_packet() {
        let data = ipv4_packet([127, 0, 0, 1], 12345, b"hi");
        match parse_packet(&data, 0) {
            PktParse::Ok { addr, start, end } => {
                assert_eq!(addr, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345));
                assert_eq!(&data[start..end], b"hi");
                assert_eq!(end, 14);
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn parse_ipv6_packet() {
        let ip6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let data = ipv6_packet(ip6, 53, b"dns");
        match parse_packet(&data, 0) {
            PktParse::Ok { addr, start, end } => {
                assert_eq!(addr, SocketAddr::new(ip6.into(), 53));
                assert_eq!(&data[start..end], b"dns");
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn parse_bad_header() {
        // data[3] != 0 → BadHeader
        let mut data = ipv4_packet([8, 8, 8, 8], 53, b"x");
        data[3] = 9;
        assert!(matches!(parse_packet(&data, 0), PktParse::BadHeader));
    }

    #[test]
    fn parse_need_more_when_incomplete() {
        let data = ipv4_packet([8, 8, 8, 8], 53, b"abcdef");
        assert!(matches!(parse_packet(&data[..6], 0), PktParse::NeedMore));
    }

    #[test]
    fn parse_pkg_len_too_small() {
        // pkg_len <= 10 → NeedMore
        let data = [10, 0, 0, 0, 0, 1, 1, 2, 3, 4, 0, 53];
        assert!(matches!(parse_packet(&data, 0), PktParse::NeedMore));
    }

    #[test]
    fn consecutive_packets() {
        // 两个包连在一起：第一个消费后，第二个从 end 开始解析
        let p1 = ipv4_packet([1, 1, 1, 1], 1000, b"ab");
        let p2 = ipv4_packet([2, 2, 2, 2], 2000, b"cde");
        let mut data = p1.clone();
        data.extend_from_slice(&p2);
        let addr = match parse_packet(&data, 0) {
            PktParse::Ok { addr, end, .. } => {
                assert_eq!(end, p1.len());
                addr
            }
            _ => panic!(),
        };
        assert_eq!(addr.port(), 1000);
        let addr2 = match parse_packet(&data, p1.len()) {
            PktParse::Ok { addr, end, .. } => {
                assert_eq!(end, data.len());
                addr
            }
            _ => panic!(),
        };
        assert_eq!(addr2.port(), 2000);
    }
}
