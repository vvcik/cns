// 同 dns.rs：CONFIG 只在 `#[cfg(test)]` 用例里 `set` 注入全局配置，生产路径
// 走 `config()`。门控到 test，消除非 test 构建的 unused_imports。
#[cfg(test)]
use crate::config::CONFIG;
use crate::http_tunnel::DynConn;
use crate::util::find_subslice;
use crate::xorcrypt::{decrypt_host, encrypt_enabled, xor_crypt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 把 from 的数据转发到 to。
/// 加密开启时对流做流式 XOR 加密，xor_sub 在多次转发间续用。
/// 传入的 `buffer` 与 Go 原版一致被复用为读缓冲区，调用方传入的 header 内容
/// 不会转发给目标。
///
/// 方向终结时（对端 EOF / 读写错误 / 读超时）对本方向的写半做 `shutdown`——
/// 向对端传播 FIN，让它尽早进入半关闭收尾。shutdown 失败忽略：socket 已坏时
/// shutdown 必然也是错。
async fn tcp_forward<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut from: R,
    mut to: W,
    buf: &mut [u8],
    xor_sub: &mut usize,
) {
    let config = crate::config::config();
    // 经防御读取器取值——0 值穿透 timeout() 即会话秒断，入口消毒 + 此处兜底。
    let tcp_timeout = config.tcp_timeout_duration();

    loop {
        let n = match timeout(tcp_timeout, from.read(buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        if encrypt_enabled() {
            *xor_sub = xor_crypt(&mut buf[..n], *xor_sub);
        }
        if timeout(tcp_timeout, to.write_all(&buf[..n])).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

/// 「头里取不到 host」的次数。仅在 `server-log` 下有意义。
///
/// 只记次数不记内容：这个分支的触发意味着头**不符合预期**，而异常的头
/// 恰恰最容易携带非常规内容（自定义认证头、调试残留）。记下来就等于把
/// 这些写进日志。判断「协议对不对得上」只需要计数。
static HOST_MISSING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn host_missing() -> u64 {
    HOST_MISSING.load(std::sync::atomic::Ordering::Relaxed)
}

/// 从请求头中取出 proxy_key 对应的 host。
/// 加密开启时 host 为 Base64 + XOR 后的密文，需解密。
fn get_proxy_host(header: &[u8]) -> String {
    let config = crate::config::config();
    let key = config.proxy_key.as_bytes();
    let pos = match find_subslice(header, key) {
        Some(p) => p,
        None => return String::new(),
    };
    let start = pos + key.len();
    let end = match header[start..].iter().position(|&b| b == b'\r') {
        Some(p) => start + p,
        None => return String::new(),
    };
    let host_bytes = &header[start..end];
    if encrypt_enabled() {
        match decrypt_host(host_bytes) {
            Ok(h) => String::from_utf8_lossy(&h).into_owned(),
            Err(_e) => {
                // 不打 `_e`：错误是 `String`（无 `kind()` 可脱敏），内容来自
                // 请求头密文片段——打出来等于把「谁在连」写进日志。判据固定为
                // 「密码配不上 / 编码不对」，两者都不需要内容。
                svc_log!("tcp: host 解密失败（密码不匹配或编码错误）");
                String::new()
            }
        }
    } else {
        String::from_utf8_lossy(host_bytes).into_owned()
    }
}

/// 在阻塞线程池完成「DNS 解析 + TCP 连接」，回 async 侧转非阻塞 tokio 流。
/// 返回的 `io::Result` 与 `TcpStream::connect(&host)` 同型：解析/连接失败 →
/// 内层 `Err`（`ErrorKind` 语义不变）；阻塞任务 panic（JoinError，理论不可达）
/// → 折算 `Other`，与连接失败同途，不让 panic 逃出会话层。
async fn dial_via_blocking_pool(host: String) -> std::io::Result<TcpStream> {
    let std_stream = tokio::task::spawn_blocking(move || std::net::TcpStream::connect(host))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "dial: blocking task join error")
        })??;
    // `TcpStream::from_std` 要求流处于非阻塞模式（否则 panic），显式置位。
    std_stream.set_nonblocking(true)?;
    TcpStream::from_std(std_stream)
}

/// 处理 TCP 会话：解析目标 host，建立连接并双向转发。
pub async fn handle_tcp_session(c_conn: DynConn, header: Vec<u8>) {
    let config = crate::config::config();

    /* 获取请求头中的 host */
    let host = get_proxy_host(&header);
    if host.is_empty() {
        // 只累加计数：判断「客户端协议版本对不对得上」只需知道失败频率，
        // 不需要知道是哪个域名（原实现把整个请求头打进日志，含 Cookie /
        // Authorization，见 `log` 模块文档）。
        svc_count!(HOST_MISSING.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        svc_log!("tcp: 头中无 host（累计 {} 次）", host_missing());
        let mut c = c_conn;
        let _ = c.write_all(b"No proxy host").await;
        let _ = c.shutdown().await;
        return;
    }

    /* tcpDNS over udpDNS */
    if config.enable_dns_tcp_over_udp && host.ends_with(":53") {
        crate::dns::dns_tcp_over_udp(c_conn, host).await;
        return;
    }

    /* 连接目标地址 */
    let mut host = host;
    if !host.contains(':') {
        host.push_str(":80");
    }
    // tokio 的 `TcpStream::connect(&host)` 在域名词路径上做同步 getaddrinfo
    // （阻塞当前线程），`timeout()` 包不住阻塞段——慢解析/解析风暴会让 tokio
    // worker 逐个挂死，accept 循环停摆即全服务不可用。故解析 + 握手收口到
    // 阻塞线程池。
    //
    // ⚠ 铁律：不得在 async 上下文直接调用任何 ToSocketAddrs（std 或 tokio）
    // 的域名词路径；本文件与 dns.rs 是仅有的两个合法拨号/解析点。
    let s_conn = match dial_via_blocking_pool(host.clone()).await {
        Ok(s) => s,
        Err(e) => {
            // 只打 `kind`：`connect` 的 io error 在解析失败等路径上会带目标
            // 主机名，而主机名正是「使用者访问了什么」。写给客户端的 `msg`
            // 带 host 是允许的——客户端本就知道自己要访问什么。
            svc_log!("tcp: 连接目标失败 {:?}", e.kind());
            let mut c = c_conn;
            let msg = format!("Proxy address [{host}] DialTCP() error");
            let _ = c.write_all(msg.as_bytes()).await;
            let _ = c.shutdown().await;
            return;
        }
    };

    /* 开始双向转发 */
    let (c_read, c_write) = tokio::io::split(c_conn);
    let (s_read, s_write) = s_conn.into_split();

    let mut buf_c2s = Box::new([0u8; 8192]);
    let mut buf_s2c = Box::new([0u8; 8192]);
    let mut xor_c2s = 0usize;
    let mut xor_s2c = 0usize;

    // 半关闭语义：任一方向终结只终结该方向，另一方向继续排空到 EOF/超时，
    // 双向都终结才会话结束。不用 select! + abort——那样首方向一结束就会 abort
    // 对向，客户端半关闭后目标仍在发送的响应尾会被静默丢弃。两方向 join! 并发
    // 跑满，tcp_forward 尾部 shutdown 自己的写半传播 FIN；两方向各受 tcp_timeout
    // 约束，join! 必然终止，无泄漏面。
    tokio::join!(
        tcp_forward(c_read, s_write, &mut buf_c2s[..], &mut xor_c2s),
        tcp_forward(s_read, c_write, &mut buf_s2c[..], &mut xor_s2c),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{JsonConfig, XOR_PASSWORD};

    fn install_config() {
        // 与 cns.go:97 一致：proxy_key 在启动时被格式化为 "\n{key}: "
        let _ = CONFIG.set(JsonConfig {
            proxy_key: "\nHost: ".into(),
            ..Default::default()
        });
    }

    #[test]
    fn get_proxy_host_plain_and_encrypted() {
        let _guard = crate::config::global_lock();

        // 未设密码：明文 host 直接提取。⚠ XOR_PASSWORD 是进程级 OnceLock，
        // 全量套件中若他用例（xorcrypt/dns）已先 set，明文分支即不可达——
        // 按 encrypt_enabled() 实际状态分流；密文分支（Go 生成向量）在两种
        // 状态下都必须成立（solo 跑时明文分支覆盖，套件跑时密文分支覆盖）。
        install_config();
        if !encrypt_enabled() {
            let header = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            assert_eq!(get_proxy_host(header), "example.com");
        }

        // 设置密码后：base64+XOR 密文 host 需解密（向量由 Go 生成）
        let _ = XOR_PASSWORD.set(b"666".to_vec());
        let enc = "U09XW0daUxlVWVoMDgc2";
        let header = format!("GET / HTTP/1.1\r\nHost: {enc}\r\n\r\n");
        assert_eq!(get_proxy_host(header.as_bytes()), "example.com:80");
        // 取到 \r 为止：host 行后跟更多头部也不越界
        let header = format!("GET / HTTP/1.1\r\nHost: {enc}\r\nX-Other: 1\r\n\r\n");
        assert_eq!(get_proxy_host(header.as_bytes()), "example.com:80");
    }

    #[test]
    fn get_proxy_host_missing_or_bad() {
        let _guard = crate::config::global_lock();
        install_config();

        // 无 Host 行
        assert_eq!(get_proxy_host(b"GET / HTTP/1.1\r\n\r\n"), "");

        // Host 行无 \r 结束
        assert_eq!(get_proxy_host(b"GET / HTTP/1.1\r\nHost: example.com"), "");

        // proxy_key 完全不存在
        assert_eq!(get_proxy_host(b"GET / HTTP/1.1\r\nX-A: 1\r\n"), "");
    }

    /// 构造偏移回归：`proxy_key` 用 `find_subslice` 定位后按 `key.len()` 推进，
    /// **不带任何裸数字偏移**。若改成 `pos + 7` 之类硬编码，一旦 `key` 变化就
    /// 会静默吞字节。
    ///
    /// ⚠ 不依赖全局状态：`CONFIG` 是 `OnceLock`，全进程只 `set` 成功一次且用例
    /// 并行共享。故直接对 `find_subslice` + `key.len()`（`get_proxy_host` 内部
    /// 所用的全部机制）验证偏移语义。
    #[test]
    fn get_proxy_host_offset_tracks_key_len_not_literal() {
        for key in ["\nHost: ", "\nX-Proxy: ", "\r\nHost: ", "\r\nHost:"] {
            let key_b = key.as_bytes();
            let host = "pull-flv-q13.douyincdn.com";
            let header = format!("GET / HTTP/1.1{key}{host}\r\n\r\n");

            // 复刻 get_proxy_host 的两步：定位 + 按 key.len() 推进。
            let pos = find_subslice(header.as_bytes(), key_b).expect("应定位到 key");
            let start = pos + key_b.len(); // ← 唯一允许的推进方式
            let end = header.as_bytes()[start..]
                .iter()
                .position(|&b| b == b'\r')
                .map(|p| start + p)
                .expect("应有 \\r 结束");

            assert_eq!(
                &header[start..end],
                host,
                "key={key:?}（len={}）时偏移必须恰为 key.len()，域名首字节不得被吞",
                key_b.len()
            );

            // 负向控制：历史事故的形态是「多吞 1 字节」——证明 +1 确实会
            // 吃掉首字节 ⇒ 该不变量非空。
            assert_eq!(
                &header[start + 1..end],
                &host[1..],
                "偏移多 1 字节必然吞掉域名首字符（pull- → ull-）：这正是事故形态"
            );
        }
    }

    /// 拨号必须经 `dial_via_blocking_pool`（阻塞池），不得在 async 上下文直接
    /// ToSocketAddrs。本用例验证拨号通路对确定性负例（端口 0，Linux 一律拒绝）
    /// 的 `io::Result` 语义：Err 透传、不 panic、不挂死——机制在位即可静态复核
    /// 「解析+握手发生在阻塞池」这一收口。
    #[tokio::test]
    async fn dial_blocking_pool_returns_err_for_dead_target() {
        assert!(dial_via_blocking_pool("127.0.0.1:0".into()).await.is_err());
    }

    /// 构造偏移回归（同上，紧贴形态无空格）：域名首字符不得被吞。
    ///
    /// 同样不依赖全局 `CONFIG`：用 `find_subslice` 直接验证紧贴形态。
    #[test]
    fn get_proxy_host_does_not_eat_first_byte() {
        // 冒号后紧贴（无空格）—— 历史 bug 的暴露形态。
        let key = "\nHost:";
        let host = "pull-flv-q13.douyincdn.com";
        let header = format!("GET / HTTP/1.1{key}{host}\r\n\r\n");

        let pos = find_subslice(header.as_bytes(), key.as_bytes()).expect("应定位到 key");
        let start = pos + key.as_bytes().len();
        let end = header.as_bytes()[start..]
            .iter()
            .position(|&b| b == b'\r')
            .map(|p| start + p)
            .expect("应有 \\r 结束");

        let got = &header[start..end];
        assert_eq!(got, host, "紧贴形态必须原样提取");
        assert!(got.starts_with('p'), "首字符 'p' 不得被吞：got={got:?}");
    }

    /// 半关闭回归：客户端先发完请求再 shutdown 写半，目标服务器读到 EOF 后回
    /// 响应再关连接；响应尾必须完整到达客户端。若实现用 select! + abort，
    /// c→s 方向终结时会 abort s→c 方向、该响应被静默丢弃。
    /// 内容断言用**长度**而非字节：`XOR_PASSWORD` 是进程级 OnceLock，本用例不
    /// 控制其他用例是否已设密——XOR 是长度保持变换，长度断言对加密态不敏感。
    /// host 头同理按加密态自适应构造（密文形态与出站侧 cns_encrypt_host 同构）。
    #[tokio::test]
    async fn half_close_drains_peer_direction() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let _guard = crate::config::global_lock();
        install_config();

        // 目标服务器：读请求直到 EOF（依赖中转层把客户端 shutdown 传播成 FIN），
        // 回响应。
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let up_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut req = Vec::new();
            sock.read_to_end(&mut req).await.unwrap();
            assert_eq!(req.len(), 3, "请求体长度（3 字节）必须原样到达");
            sock.write_all(b"RESPONSE-TAIL").await.unwrap();
        });

        // host 头按加密态构造：加密开启时 get_proxy_host 会 base64+xor 解密。
        let host = up_addr.to_string();
        let host_field = if crate::xorcrypt::encrypt_enabled() {
            use base64::Engine as _;
            let mut raw = host.clone().into_bytes();
            raw.push(0);
            crate::xorcrypt::xor_crypt(&mut raw, 0);
            base64::engine::general_purpose::STANDARD.encode(raw)
        } else {
            host
        };
        let header = format!("GET / HTTP/1.1\r\nHost: {host_field}\r\n\r\n");

        let (mut client, server_side) = tokio::io::duplex(4096);
        let session = tokio::spawn(handle_tcp_session(
            Box::new(server_side),
            header.into_bytes(),
        ));

        // 客户端：发请求 → 半关闭写半 → 读响应到 EOF。
        client.write_all(b"REQ").await.unwrap();
        client.shutdown().await.unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut resp),
        )
        .await
        .expect("5s 内必须收到响应尾（超时即半关闭语义回归）")
        .unwrap();
        assert_eq!(resp.len(), 13, "响应尾长度（13 字节）必须完整到达");

        session.await.unwrap();
        up_task.await.unwrap();
    }
}
