//! cns-rust 协议：与本项目客户端配套重写的 UDP 承载。
//!
//! ## 为什么另起一套而不是修 `udp.rs`
//!
//! `udp.rs` 是 **bug-for-bug 兼容** Go v0.4.3 的实现。它面向「外部既有服务端 /
//! 既有客户端」，是兼容层，**不能**单方面改线规——改了就与那些无法触及的对端
//! 对不上。
//!
//! cns-rust 的定位不同：**两端都是本项目的 Rust 代码**，不必迁就历史包袱，
//! 因此把线规里已知的缺陷一次改对。代价是与旧服务端不互通（有意选择）。
//!
//! 相对旧协议的关键修正：
//!
//! - **ATYP 按每包自己的偏移解析**（旧实现用固定绝对下标判 ATYP，一批多个包时
//!   后续包会沿用首包的地址族）；
//! - **IPv6 用 RFC 1928 的 `ATYP=4`**（旧实现复用域名类型 `3`，却直接跟 16 字节
//!   地址、无长度前缀，既非合法域名编码也非自描述）；
//! - **回包回带客户端源五元组**（旧实现不带标识，客户端只能按端点反查 ⇒ 同一
//!   端点的多客户端互相覆盖）；
//! - **统一 ATYP 前置、长度自描述**（旧实现 v4/v6 两套硬编码偏移，长度语义与
//!   ATYP 耦合）。
//!
//! ## 线规
//!
//! ```text
//! [len: u16 LE][A: 地址块][B: 地址块][payload..]
//! 地址块 = [ATYP: u8][addr][port: u16 BE]
//! ```
//!
//! - `len`：**本帧 A 块起到 payload 末尾**的字节数（不含这 2 字节自身）。
//!   自描述 ⇒ 一帧损坏可以跳过重新同步，不会拖垮整条隧道。
//! - `ATYP`：`1` = IPv4（4B）、`3` = 域名（1B 长度 + 名字）、`4` = IPv6（16B）。
//! - 两个地址块的语义**按方向而定**，帧本身完全对称：
//!
//! | 方向 | A 块 | B 块 |
//! |---|---|---|
//! | 出向 c2s | 目标地址（要发到哪） | 客户端源五元组（谁发的） |
//! | 回向 s2c | 远端源地址（谁回的包） | 客户端源五元组（回给谁） |
//!
//! - `len` 为 LE、`port` 为 BE——沿用旧协议的字节序，因为 XOR keystream
//!   与它绑定，改序会让两端对不上且无收益。
//!
//! ## 为什么用「源五元组」而不是 cookie
//!
//! 用客户端分配的 `u32 cookie`（服务端回显）能工作，但引入一层**两端各自维护、
//! 且必须保持一致**的间接状态：客户端要 `ep → cookie` 分配表（分配、回收、绕开
//! 保留值、处理回绕碰撞），服务端要 `cookie → socket` 表。任一侧泄漏或被回收得
//! 早一点，表现是**回包静默丢弃**，而 cookie 这个抽象整数在日志里**看不出属于
//! 谁**，事后无从归因。
//!
//! 源五元组不一样：它是**客户端本来就有的事实**（承载层拿得到），不需要分配器、
//! 保留值、碰撞处理。服务端表里的键就是真实地址，日志里直接可读。回包路由因此
//! 从「两端协商出的抽象标识」退回「地址本身」，少了一整层状态机。代价是每帧多
//! 6B（v4）或 18B（v6）——相对 65500 的载荷上限可以忽略。
//!
//! ## 服务端的 socket 分配与回收
//!
//! 服务端**每个客户端源五元组一个 socket**（v4/v6 各一），因此不同客户端访问
//! 同一目标时各自有独立源端口，回包靠 `recv_from` 落在哪个 socket 上天然区分
//! ——不需要任何标识查表。
//!
//! 回收靠收包任务自身：任务因 `udp_timeout` 超时退出时把键摘掉，socket 随之释放。
//! 客户端若之后又发包，会新建 socket（拿到新源端口），语义与「长时间静默后重开」
//! 一致。
//!
//! 表有容量上限（[`SOCKMAP_MAX`]）：满表时**新**五元组的帧被丢弃（UDP 语义），
//! 已建立的键不受影响——B 块由客户端任意声明，无界表会把 fd/收包任务逐个吃光。
//!
//! ## 探活（控制帧）
//!
//! ```text
//! [len = 0x0000][cmd: u8]
//! cmd = 1  ECHO_REQ  客户端 → 服务端
//! cmd = 2  ECHO_RESP 服务端 → 客户端
//! ```
//!
//! `len` 为 0 表示「无地址块、无载荷」，数据帧的最小 `len` 是 14，故两者不会
//! 冲突，不需要额外的帧类型字段。
//!
//! **为什么需要它**：UDP 承载跑在一条长连接 TCP 隧道上。TCP 半开（对端主机掉电、
//! 链路中间 NAT 静默失效）时**没有任何通知**：`write` 照样成功，`read` 永远不返回，
//! `SO_KEEPALIVE` 默认要 2 小时才介入。期间所有 UDP 会话的表现是「发出去、没回音」
//! ——与「目标服务器不响应」完全一样，用户无从区分。
//!
//! **为什么判据不能是业务流量**：探活要证明的是**隧道**可达。若拿「业务包有没有
//! 回来」当判据，目标服务器不响应（STUN 黑洞、防火墙静默丢弃、DoH 服务器不认）
//! 会被误判成隧道故障——全是假阳性。服务端对 `ECHO_REQ` **无条件**回应，与转发
//! 到目标的结果无关，因此这个往返只证明一件事：隧道双向可达。
//!
//! **附带收益**：本会话主循环是 `timeout(udp_timeout, c_read.read(..))`，默认 30s
//! 无数据即断链。客户端每 10s 探活一次，于是空闲隧道不会被踢，省掉一次重建与随之
//! 而来的丢包。
//!
//! **未知命令**：未知 `cmd` **跳过而非断链**——将来新增控制帧时，旧服务端静默忽略
//! 即可继续工作；判非法帧会让旧服务端对每一个新特性直接拆链。

// CONFIG 读取统一收敛到 crate::config::config()（panic 依据见 config.rs），
// 本文件不直接引用 CONFIG。
use crate::http_tunnel::DynConn;
use crate::xorcrypt::{encrypt_enabled, xor_crypt};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

/// ATYP：IPv4。
pub const ATYP_V4: u8 = 1;
/// ATYP：域名，后跟 1 字节长度。
///
/// 服务端不做本地解析，域名 ATYP 一律判 `Pkt::Bad`（见 [`parse_addr`]），
/// 因此本常量只在测试里作为「被拒绝的输入」出现。bin crate 的 `pub` 不构成
/// 对外可达面，非 test 构建会报 dead_code，故按实际使用面门控。
#[cfg(test)]
pub const ATYP_DOMAIN: u8 = 3;
/// ATYP：IPv6（RFC 1928）。
pub const ATYP_V6: u8 = 4;

/// 控制帧的 `len` 取值。
///
/// 数据帧最小 `len` 是 14（两个 v4 地址块），故 `0` 永远不会与数据帧冲突，
/// 不需要额外的帧类型字段——帧类型由长度本身区分。
const CTRL_LEN: usize = 0;

/// 控制帧命令：客户端探活请求。服务端必须无条件回 [`CMD_ECHO_RESP`]。
const CMD_ECHO_REQ: u8 = 1;

/// 控制帧命令：探活响应。
const CMD_ECHO_RESP: u8 = 2;

/// 单个地址块的最大长度：`ATYP(1) + IPv6(16) + port(2)`。
const ADDR_MAX: usize = 19;

/// 单帧最大字节数：两个地址块 + 载荷上限 65500 + 长度前缀。
pub const FRAME_MAX: usize = 2 + ADDR_MAX * 2 + 65500;

/// 合法帧的最小 `len`：两个 v4 地址块 `(1+4+2) * 2`。
const FRAME_MIN: usize = 14;

/// 回向汇聚通道容量。满则丢——UDP 没有交付保证，绝不能为此阻塞收包任务。
const IN_QUEUE: usize = 512;

/// 一帧的解析结果。
#[derive(Debug)]
enum Pkt {
    /// 数据还不够，等更多字节。
    NeedMore,
    /// 头非法或对端不是 cns-rust 客户端：无法重新同步，必须断链。
    Bad,
    /// 解析成功。
    Ok {
        /// A 块：出向是目标地址，回向是远端源地址。
        a: SocketAddr,
        /// B 块：客户端源五元组。
        b: SocketAddr,
        start: usize,
        end: usize,
    },
    /// 控制帧：`[len = 0][cmd: u8]`。见 [`CTRL_LEN`]。
    Ctrl { cmd: u8, end: usize },
}

/// 解析一个地址块，返回 `(地址, 下一块的偏移)`。
///
/// 越界或非法的 ATYP 一律 `None`（⇒ 上层判 `Bad` 断链）：地址块是定长的，
/// 解析不出来只可能是流已失同步，继续猜偏移只会读出错的地址且**不报错**——
/// 比断链难查得多。
fn parse_addr(data: &[u8], p: usize, end: usize) -> Option<(SocketAddr, usize)> {
    if p >= end {
        return None;
    }
    match data[p] {
        ATYP_V4 => {
            if p + 7 > end {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(data[p + 1], data[p + 2], data[p + 3], data[p + 4]);
            let port = u16::from_be_bytes([data[p + 5], data[p + 6]]);
            Some((SocketAddr::new(ip.into(), port), p + 7))
        }
        ATYP_V6 => {
            if p + 19 > end {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&data[p + 1..p + 17]);
            let port = u16::from_be_bytes([data[p + 17], data[p + 18]]);
            Some((SocketAddr::new(std::net::Ipv6Addr::from(o).into(), port), p + 19))
        }
        // 域名分支：**刻意判 Bad 而非解析**。
        //
        // `send_to` 需要 `SocketAddr`，域名得先本地解析；而服务端做解析会
        // 引入「谁来解析、解析失败算谁的」一整套语义。当前客户端只在本地
        // 解析后才发 IP，域名形态不需要支持。
        //
        // 判 Bad（断链 + 日志）而不是跳过：跳过会表现为「配了域名没反应」，
        // 比报错难查得多。
        _ => None,
    }
}

/// 解析一帧。`pkg_sub` 是相对 `data` 起点的偏移。
///
/// 每帧都**独立**解析自己的 ATYP，不做跨包状态沿用。
fn parse_frame(data: &[u8], pkg_sub: usize) -> Pkt {
    if pkg_sub + 2 > data.len() {
        return Pkt::NeedMore;
    }
    let len = (data[pkg_sub] as usize) | ((data[pkg_sub + 1] as usize) << 8);
    if len == CTRL_LEN {
        let p = pkg_sub + 2;
        if p + 1 > data.len() {
            return Pkt::NeedMore;
        }
        return Pkt::Ctrl { cmd: data[p], end: p + 1 };
    }
    if len < FRAME_MIN {
        return Pkt::Bad;
    }
    let body = pkg_sub + 2;
    if body + len > data.len() {
        return Pkt::NeedMore;
    }
    let end = body + len;

    let Some((a, p)) = parse_addr(data, body, end) else {
        return Pkt::Bad;
    };
    let Some((b, start)) = parse_addr(data, p, end) else {
        return Pkt::Bad;
    };
    Pkt::Ok { a, b, start, end }
}

/// 地址块的字节数，用于编码时预留。
fn addr_len(a: SocketAddr) -> usize {
    if a.is_ipv4() {
        7
    } else {
        19
    }
}

/// 写一个地址块，返回下一块的偏移。
fn write_addr(out: &mut [u8], p: usize, a: SocketAddr) -> usize {
    match a {
        SocketAddr::V4(v4) => {
            out[p] = ATYP_V4;
            out[p + 1..p + 5].copy_from_slice(&v4.ip().octets());
            out[p + 5..p + 7].copy_from_slice(&a.port().to_be_bytes());
            p + 7
        }
        SocketAddr::V6(v6) => {
            out[p] = ATYP_V6;
            out[p + 1..p + 17].copy_from_slice(&v6.ip().octets());
            out[p + 17..p + 19].copy_from_slice(&a.port().to_be_bytes());
            p + 19
        }
    }
}

/// 把 `(A 地址, B 地址, 载荷)` 编码成一帧写入 `out`，返回帧长；缓冲不够返回 `None`。
fn encode_frame(
    out: &mut [u8],
    a: SocketAddr,
    b: SocketAddr,
    payload: &[u8],
) -> Option<usize> {
    let need = 2 + addr_len(a) + addr_len(b) + payload.len();
    if need > out.len() {
        return None;
    }
    let len = need - 2;
    if len > u16::MAX as usize {
        // len 是 u16，而 FRAME_MAX（= 2 + 38 + 65500）允许 len 达 65538
        // （两个 v6 地址块 + 满载荷即可触达）。超出表示域时按低 16 位截断
        // 会产出坏帧，故显式拒绝：调用方丢弃该包，不断链。
        return None;
    }
    out[0] = (len & 0xff) as u8;
    out[1] = ((len >> 8) & 0xff) as u8;
    let mut p = 2;
    p = write_addr(out, p, a);
    p = write_addr(out, p, b);
    out[p..p + payload.len()].copy_from_slice(payload);
    Some(need)
}

/// 按目标地址族绑定一个临时 socket。
///
/// v4 目标绑 v4、v6 目标绑 v6，不做双栈：双栈 socket 收到的是
/// IPv4-mapped 地址，编码回帧前还得还原一次，各绑各的更直接。
fn bind_udp_socket_for(dst: SocketAddr) -> io::Result<UdpSocket> {
    // 地址用常量构造而非字符串 parse：不制造「恒成功」的 unwrap 面。
    let s = if dst.is_ipv4() {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let addr = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0);
        sock.bind(&addr.into())?;
        sock
    } else {
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_only_v6(true)?;
        let addr = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0);
        sock.bind(&addr.into())?;
        sock
    };
    s.set_nonblocking(true)?;
    UdpSocket::from_std(std::net::UdpSocket::from(s))
}

/// socket 表的键：`(客户端源五元组, 是否 v6)`。
///
/// 带 v6 标志是因为同一个客户端源端口可能同时发往 v4 与 v6 目标，而
/// `send_to` 的地址族必须与 socket 族一致——共用一个 socket 会让另一族
/// 的发送直接失败并断链。
type SockKey = (SocketAddr, bool);

/// 键 → 该客户端源独占的 UDP socket。
type SockMap = Arc<Mutex<HashMap<SockKey, Arc<UdpSocket>>>>;

/// socket 表的容量上限。
///
/// 攻击面：c2s 帧 B 块（客户端源五元组）由客户端**任意声明**，
/// `encrypt_password` 为空时每帧可造新键——表无界则每键 1 个 socket +
/// 1 个收包任务，fd/内存被逐个吃光（服务本身无认证，公网暴露）。
///
/// 表是**每会话一张**（见 [`handle_udp_session_rust`]），故本闸约束的是单条
/// 隧道内的映射数；多会话各自受闸、互不挤占。回收沿既有机制：收包任务
/// `udp_timeout` 超时摘键腾位。取值对齐主栈 `tproxy-upnp` 的
/// `MAX_PROXY_CONNS = 256`。
const SOCKMAP_MAX: usize = 256;

/// 「表满、新键帧被丢」的累计次数。仅 `server-log` 下有意义
/// （零日志下无行为差异）。
static SOCKMAP_FULL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 容量闸判据（纯函数，便于静态测试）：键已在表内恒放行；新键仅在表未满时
/// 放行。判定与值类型无关（只看 len 与键是否已存在）。
fn sockmap_admits(len: usize, key_present: bool) -> bool {
    key_present || len < SOCKMAP_MAX
}

/// 把 `data` 里能解析的帧全部发出，返回已消费字节数；-1 表示失败。
///
/// 新出现的键会在这里建 socket，但**不起收包任务**——那由调用方在
/// 释放锁之后做（见 [`drain_out`]）。
async fn write_to_server(
    socks: &mut HashMap<SockKey, Arc<UdpSocket>>,
    data: &[u8],
    tx: &mpsc::Sender<Vec<u8>>,
) -> i64 {
    let mut pkg_sub = 0usize;
    while pkg_sub + 2 <= data.len() {
        match parse_frame(data, pkg_sub) {
            Pkt::NeedMore => return pkg_sub as i64,
            Pkt::Bad => return -1,
            // 控制帧不产生任何 UDP 流量——这正是它与业务解耦的含义。
            //
            // 未知 cmd **跳过而非断链**：将来新增控制帧时，旧服务端静默忽略
            // 即可继续工作；判 Bad 会让旧服务端对每一个新特性直接断链。
            Pkt::Ctrl { cmd, end } => {
                if cmd == CMD_ECHO_REQ {
                    // 无条件回，且**与目标服务器是否有响应无关**：若用「业务包
                    // 有没有回来」作判据，目标不响应（STUN 黑洞、防火墙丢包、
                    // DoH 服务器静默）会被误判成隧道故障，全是假阳性。
                    //
                    // 响应走汇聚通道，因此自动经过 s2c keystream 加密，与数据
                    // 帧共用同一条流——不需要独立的控制通道。
                    //
                    // `try_send` 而非 `send`：队列满时宁可丢一个探活响应，也
                    // 不能让这里阻塞住出向数据的发送。
                    let _ = tx.try_send(vec![0, 0, CMD_ECHO_RESP]);
                }
                pkg_sub = end;
            }
            Pkt::Ok { a: dst, b: cli, start, end } => {
                let key = (cli, dst.is_ipv6());
                // 满表闸——**新键**丢这一帧（UDP 语义：不保证交付，不为此断链），
                // 已建立的键照常转发；同批其余包继续解析，不受牵连。
                if !sockmap_admits(socks.len(), socks.contains_key(&key)) {
                    svc_count!(SOCKMAP_FULL.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
                    svc_log!("cns-rust: socket 表满（{}），丢弃新源帧", SOCKMAP_MAX);
                    pkg_sub = end;
                    continue;
                }
                let sock = match socks.entry(key) {
                    std::collections::hash_map::Entry::Occupied(e) => Arc::clone(e.get()),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        match bind_udp_socket_for(dst) {
                            Ok(s) => {
                                let s = Arc::new(s);
                                e.insert(Arc::clone(&s));
                                s
                            }
                            Err(_) => return -1,
                        }
                    }
                };
                if sock.send_to(&data[start..end], dst).await.is_err() {
                    return -1;
                }
                pkg_sub = end;
            }
        }
    }
    pkg_sub as i64
}

/// 消费 `pending`：发完所有完整帧，并为**本次新建**的 socket 起收包任务。
///
/// 返回 -1 表示失败（调用方应断链）。
///
/// 只给「本次新建」的键起任务，以保证幂等：若每轮都给所有键起任务，同一个
/// socket 会被两个任务同时 `recv_from`，表现为「回包随机丢一半」——比丢全部
/// 更难查。
async fn drain_out(socks: &SockMap, pending: &mut Vec<u8>, tx: &mpsc::Sender<Vec<u8>>) -> i64 {
    let fresh: Vec<SockKey> = {
        let mut map = socks.lock().await;
        let before: Vec<SockKey> = map.keys().copied().collect();
        let consumed = write_to_server(&mut map, pending, tx).await;
        if consumed < 0 {
            return -1;
        }
        if consumed > 0 {
            pending.drain(..consumed as usize);
        }
        map.keys().copied().filter(|k| !before.contains(k)).collect()
    };

    // 必须出上面的作用域、释放锁之后再取 socket：`spawn_recv` 不需要锁，
    // 但持锁 spawn 会让任务里的首次 `recv_from` 与本处的后续发送串行化，
    // 吞吐退化。
    for key in fresh {
        let sock = {
            let map = socks.lock().await;
            map.get(&key).cloned()
        };
        if let Some(sock) = sock {
            spawn_recv(sock, key, Arc::clone(socks), tx.clone());
        }
    }
    0
}

/// 起一个收包任务：socket 上回来的每个包都带上本键的客户端源编码后送回。
///
/// 退出时（超时或通道关闭）把键从表里摘掉——这就是回收：socket 随 `Arc`
/// 计数归零而关闭，表也不会无限增长。
///
/// 摘键前先核对表里存的是不是**本任务的那个 socket**：本任务退出与客户端下一
/// 帧到达（`drain_out` 为同键 `entry().or_insert` 出新 socket 并 spawn 新收包
/// 任务）之间存在交错窗口，无条件 `remove` 会把新 socket 的键摘掉——那之后
/// 直到客户端再发一帧，新 socket 的回包没有任何任务在收，全部静默丢弃。条件
/// 摘除让过期任务只回收自己那一代的键。
fn spawn_recv(
    sock: Arc<UdpSocket>,
    key: SockKey,
    socks: SockMap,
    tx: mpsc::Sender<Vec<u8>>,
) {
    // 经防御读取器取值：0 值会让 timeout() 立即超时，收包任务沦为
    // 「摘键即退出」的死循环。
    let udp_timeout = crate::config::config().udp_timeout_duration();
    tokio::spawn(async move {
        // 载荷区起点留出最长的头（两个 v6 地址块），短帧会往前排，故统一用
        // 这个偏移，读到的内容再按实际长度拷出。
        let off = 2 + ADDR_MAX * 2;
        let mut buf = vec![0u8; FRAME_MAX];
        // 出向帧缓冲：整个收包任务生命周期复用一份，发送时按实际帧长拷出小
        // 缓冲进汇聚队列。此前是每包 `vec![0; FRAME_MAX]` 零化分配 64KB 再
        // truncate，包率一高就是纯浪费；本任务独享这份缓冲、循环内串行使用，
        // 无并发共享。
        let mut frame = vec![0u8; FRAME_MAX];
        loop {
            let r = timeout(udp_timeout, sock.recv_from(&mut buf[off..])).await;
            let (n, src) = match r {
                Ok(Ok(x)) if x.0 > 0 => x,
                _ => break,
            };
            // A = 远端源（谁回的包），B = 客户端源（回给谁）。
            let Some(len) = encode_frame(&mut frame, src, key.0, &buf[off..off + n]) else {
                // 超大包：UDP 载荷超过 65500 本就不该出现，丢弃而非断链。
                continue;
            };
            // 汇聚通道要所有权，且下一轮还要复用 frame —— 只能按实际帧长
            // 拷出。拷贝 n 字节（典型 ≤1500）远比每包零化 64KB 便宜。
            if tx.send(frame[..len].to_vec()).await.is_err() {
                break;
            }
        }
        let mut map = socks.lock().await;
        // 只回收仍指向本 socket 的键（见上方函数文档的交错窗口分析）。
        if map.get(&key).is_some_and(|s| Arc::ptr_eq(s, &sock)) {
            map.remove(&key);
        }
    });
}

/// 处理一个 cns-rust UDP 会话。
///
/// 出向：客户端帧 → 按客户端源选 socket → 发往目标。
/// 回向：每个 socket 一个任务收包 → 带上客户端源编码 → 汇总写回。
///
/// 入口约定：握手（HTTP 首包）由 `handle_tunnel` 消费，到达本函数的流从握手后
/// 的第一个字节起算——XOR keystream 的 sub 从 0 开始。
pub async fn handle_udp_session_rust(c_conn: DynConn) {
    let config = crate::config::config();
    // 经防御读取器取值：0 值会让 timeout() 立即超时、会话秒断。
    let udp_timeout = config.udp_timeout_duration();

    let mut c2s_sub = 0usize;

    let (mut c_read, mut c_write) = tokio::io::split(c_conn);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(IN_QUEUE);
    let socks: SockMap = Arc::new(Mutex::new(HashMap::new()));

    // 写任务：汇聚各收包任务送来的帧，按 s2c keystream 加密后写回客户端。
    let write_task = tokio::spawn(async move {
        let mut s2c_sub = 0usize;
        while let Some(mut frame) = rx.recv().await {
            if encrypt_enabled() {
                s2c_sub = xor_crypt(&mut frame, s2c_sub);
            }
            if timeout(udp_timeout, c_write.write_all(&frame)).await.is_err() {
                break;
            }
        }
    });

    let mut buf = vec![0u8; FRAME_MAX];
    let mut pending: Vec<u8> = Vec::new();

    loop {
        let r = timeout(udp_timeout, c_read.read(&mut buf)).await;
        let n = match r {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        if encrypt_enabled() {
            c2s_sub = xor_crypt(&mut buf[..n], c2s_sub);
        }
        pending.extend_from_slice(&buf[..n]);
        if pending.len() > FRAME_MAX * 4 {
            // 长时间堆不出一帧完整数据 ⇒ 流已失同步，继续堆只会吃内存。
            // 断链让客户端重建：比静默丢包或 OOM 都好。
            svc_log!("cns-rust: 待解析缓冲超过 {} 字节，判定流失同步，断链", FRAME_MAX * 4);
            break;
        }
        if drain_out(&socks, &mut pending, &tx).await == -1 {
            break;
        }
    }

    drop(tx);
    let _ = write_task.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 控制帧必须被识别为 `Ctrl` 而非 `Ok`/`Bad`。
    ///
    /// 这是探活能被服务端处理的前提：判 `Bad` 会让第一个探活请求直接断链。
    #[test]
    fn ctrl_frame_is_recognized() {
        match parse_frame(&[0, 0, CMD_ECHO_REQ], 0) {
            Pkt::Ctrl { cmd, end } => {
                assert_eq!(cmd, CMD_ECHO_REQ);
                assert_eq!(end, 3, "控制帧长 3 字节（len 2 + cmd 1）");
            }
            other => panic!("控制帧被误判: {other:?}"),
        }
        // 长度不足要等更多字节，不能判 Bad。
        assert!(matches!(parse_frame(&[0, 0], 0), Pkt::NeedMore));
    }

    /// 未知控制命令必须被**跳过**而不是断链——将来的新控制帧不该让旧
    /// 服务端把隧道拆掉。
    #[test]
    fn unknown_ctrl_cmd_is_not_fatal() {
        let mut data = vec![0u8, 0u8, 0x7f];
        let d: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let c: SocketAddr = "10.0.0.2:1111".parse().unwrap();
        let mut f = vec![0u8; FRAME_MAX];
        let len = encode_frame(&mut f, d, c, &[9]).unwrap();
        data.extend_from_slice(&f[..len]);

        match parse_frame(&data, 0) {
            Pkt::Ctrl { cmd, end } => {
                assert_eq!(cmd, 0x7f);
                // 跳过后必须能继续解析后面的数据帧。
                match parse_frame(&data, end) {
                    Pkt::Ok { a, b, .. } => {
                        assert_eq!(a, d);
                        assert_eq!(b, c);
                    }
                    other => panic!("控制帧之后的数据帧解析失败: {other:?}"),
                }
            }
            other => panic!("未知控制帧被误判: {other:?}"),
        }
    }

    /// 相对下标解析：首包 v4、次包 v6，两包必须各自按自己的 ATYP 解析。
    ///
    /// 这正是旧协议 `data[5]` 绝对下标会错的地方——次包会被按首包的 v4
    /// 解析，长度与偏移全错。
    #[test]
    fn second_packet_uses_its_own_atyp() {
        let d1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let c1: SocketAddr = "10.0.0.2:1111".parse().unwrap();
        let d2: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let c2: SocketAddr = "[2001:db8::2]:2222".parse().unwrap();

        let mut data = Vec::new();
        for (d, c) in [(d1, c1), (d2, c2)] {
            let mut f = vec![0u8; FRAME_MAX];
            let len = encode_frame(&mut f, d, c, &[1, 2, 3]).unwrap();
            data.extend_from_slice(&f[..len]);
        }

        let mut off = 0;
        for (d, c) in [(d1, c1), (d2, c2)] {
            match parse_frame(&data, off) {
                Pkt::Ok { a, b, start, end } => {
                    assert_eq!(a, d, "目标地址解析错");
                    assert_eq!(b, c, "客户端源解析错");
                    assert_eq!(&data[start..end], &[1, 2, 3]);
                    off = end;
                }
                other => panic!("解析失败: {other:?}"),
            }
        }
    }

    /// 两个地址块必须**各自**按自己的 ATYP 定长——v6 块不能被 v4 的长度
    /// 截断，否则第二个地址会读串且**不报错**。
    #[test]
    fn udp_rust_mixed_family_addr_blocks() {
        let a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let b: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let mut buf = vec![0u8; FRAME_MAX];
        let len = encode_frame(&mut buf, a, b, b"x").unwrap();
        match parse_frame(&buf, 0) {
            Pkt::Ok { a: ga, b: gb, end, .. } => {
                assert_eq!(ga, a, "v6 块解析错");
                assert_eq!(gb, b, "v4 块解析错");
                assert_eq!(end, len);
            }
            other => panic!("解码失败: {other:?}"),
        }
    }

    /// 编码/解码往返：v4 与 v6 都要还原出同一对地址、同一载荷。
    #[test]
    fn udp_rust_encode_decode_roundtrip() {
        for s in ["1.2.3.4:3478", "[2001:db8::1]:443"] {
            let a: SocketAddr = s.parse().unwrap();
            let b: SocketAddr = "10.9.8.7:4567".parse().unwrap();
            let payload = b"hello";
            let mut buf = vec![0u8; FRAME_MAX];
            let len = encode_frame(&mut buf, a, b, payload).unwrap();
            match parse_frame(&buf, 0) {
                Pkt::Ok { a: ga, b: gb, start, end } => {
                    assert_eq!(ga, a, "{s} A 块往返不一致");
                    assert_eq!(gb, b, "{s} B 块往返不一致");
                    assert_eq!(&buf[start..end], payload, "{s} 载荷往返不一致");
                    assert_eq!(end, len, "{s} 帧长与编码长度不一致");
                }
                other => panic!("{s} 解码失败: {other:?}"),
            }
        }
    }

    /// IPv6 必须用 ATYP=4，不能沿用旧协议的 3。
    #[test]
    fn udp_rust_v6_uses_atyp_four() {
        let a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let b: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let mut buf = vec![0u8; FRAME_MAX];
        let len = encode_frame(&mut buf, a, b, b"x").unwrap();
        assert_eq!(buf[2], ATYP_V6);
        assert_eq!(buf[2], 4, "IPv6 的 ATYP 必须是 4，不是旧协议的 3");
        assert!(len > 0);
    }

    /// 域名 ATYP 必须判 Bad：服务端不做本地解析，放行会静默发到错地址。
    #[test]
    fn domain_atyp_rejected() {
        let mut d = vec![0u8; 2 + 7 + 7];
        d[2] = ATYP_DOMAIN;
        let len = d.len() - 2;
        d[0] = (len & 0xff) as u8;
        d[1] = (len >> 8) as u8;
        assert!(matches!(parse_frame(&d, 0), Pkt::Bad));
    }

    /// 满表闸判据：已存在的键恒放行；新键在表满（SOCKMAP_MAX）时被拒。
    /// 判定与值类型无关（只看 len 与键是否已在表），故用 usize 桩替代真实
    /// socket，避免在测试里绑 256 个 fd。
    #[test]
    fn sockmap_cap_rejects_new_keys_when_full() {
        let mut map: HashMap<SockKey, usize> = HashMap::new();
        for i in 0..SOCKMAP_MAX {
            let cli: SocketAddr = format!("10.0.0.1:{}", 1000 + i).parse().unwrap();
            map.insert((cli, false), i);
        }
        assert_eq!(map.len(), SOCKMAP_MAX, "前置：表确已打满");
        // 满表：新键必须被拒。
        let fresh: SocketAddr = "10.0.0.2:9999".parse().unwrap();
        assert!(
            !sockmap_admits(map.len(), map.contains_key(&(fresh, false))),
            "表满时新键必须被拒绝（丢弃帧而非建映射）"
        );
        // 空表/未满：新键放行（正常路径不被误伤）。
        assert!(sockmap_admits(0, false));
        assert!(sockmap_admits(SOCKMAP_MAX - 1, false));
        // 已建立的键不受闸影响。
        let old: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        assert!(
            sockmap_admits(map.len(), map.contains_key(&(old, false))),
            "已建立的键在满表时必须照常转发"
        );
    }

    /// 回收钉：旧键摘除（收包任务 `udp_timeout` 超时回收，即 spawn_recv 的
    /// 条件摘键）后腾出容量——新键可再次进入，闸不得变成一次性死刑。
    #[test]
    fn sockmap_reusable_after_key_removal() {
        let mut map: HashMap<SockKey, usize> = HashMap::new();
        let mut keys = Vec::new();
        for i in 0..SOCKMAP_MAX {
            let cli: SocketAddr = format!("10.0.0.2:{}", 2000 + i).parse().unwrap();
            let k = (cli, false);
            keys.push(k.clone());
            map.insert(k, i);
        }
        assert!(!sockmap_admits(map.len(), false), "前置：满表拒新键");
        // 回收一个键（对齐 spawn_recv 的超时摘键语义）。
        let victim = keys[0].clone();
        assert!(map.remove(&victim).is_some(), "被摘键必须确在表内");
        assert!(
            sockmap_admits(map.len(), false),
            "摘键后必须腾出容量：新键可再次建立映射"
        );
    }

    /// 帧长不足两个 v4 地址块必须判 Bad，而不是 `NeedMore`——后者会让调用
    /// 方一直等，表现为连接挂起。
    #[test]
    fn short_frame_is_bad_not_needmore() {
        // `len` 是 **LE**，`d[0]` 为低字节；若写成 `[0, 2, ..]` 得到的是 512，
        // 会走 `NeedMore` 分支，断言就不成立。
        let d = vec![2u8, 0, ATYP_V4, 0, 0, 0, 0];
        assert!(matches!(parse_frame(&d, 0), Pkt::Bad));
    }
}
