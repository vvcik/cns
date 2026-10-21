use std::io;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use nwproxy_common::log::{throttled, WINDOW_TUNNEL};
use nwproxy_common::stream::BoxStream;

use crate::udp_datagram::{
    clear_link_fail, enqueue_in, enqueue_out, read_http_header_exact, HANDSHAKE_TIMEOUT,
    IDLE_CLOSE_MIN_LIFETIME, UDP_IN_QUEUE, UDP_OUT_QUEUE,
};
use crate::udp_tunnel::{
    build_udp_handshake, udp_handshake_host, udp_password, udp_server_addr, xor_crypt, UdpEndpoint,
};

pub const CNSR_FLAG: &str = "cnsrUDP";

const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;

const ADDR_MAX: usize = 19;

const FRAME_MAX: usize = 2 + ADDR_MAX * 2 + 65500;

const FRAME_MIN: usize = 14;

const CTRL_LEN: usize = 0;

const CMD_ECHO_REQ: u8 = 1;

const CMD_ECHO_RESP: u8 = 2;

const ECHO_INTERVAL: Duration = Duration::from_secs(10);

const ECHO_MAX_SILENCE: Duration = Duration::from_secs(25);

// out 侧合并写：首帧到达后继续凑批的窗口与上限。窗口内到达的新帧
// 与存量帧共用一次 write_all，逐帧编码语义不变（帧头自带长度前缀，
// XOR 的 sub 跨帧连续滚动），只是把 N 次 write syscall 合成一次。
const CNSR_OUT_BATCH_MAX: usize = 16;
const CNSR_OUT_BATCH_WINDOW: Duration = Duration::from_millis(1);

fn unspecified_v4() -> UdpEndpoint {
    UdpEndpoint::v4([0, 0, 0, 0], 0)
}

type Frame = (UdpEndpoint, Option<UdpEndpoint>, Vec<u8>);

fn map_recv_timeout(
    r: Result<Frame, std::sync::mpsc::RecvTimeoutError>,
) -> io::Result<Option<Frame>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "udp: cns-rust 隧道已关闭",
        )),
    }
}

fn encode_frame(
    buf: &mut Vec<u8>,
    a: &UdpEndpoint,
    b: &UdpEndpoint,
    payload: &[u8],
) -> io::Result<()> {
    let alen = if a.is_ipv4() { 7 } else { 19 };
    let blen = if b.is_ipv4() { 7 } else { 19 };
    let len = alen + blen + payload.len();
    if len > u16::MAX as usize || 2 + len > FRAME_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "udp: cns-rust 帧超长",
        ));
    }
    buf.reserve(2 + len);
    buf.extend_from_slice(&(len as u16).to_le_bytes());
    buf.extend_from_slice(&encode_addr(a));
    buf.extend_from_slice(&encode_addr(b));
    buf.extend_from_slice(payload);
    Ok(())
}

fn encode_addr(ep: &UdpEndpoint) -> Vec<u8> {
    let mut v = Vec::with_capacity(19);
    match ep.addr {
        std::net::IpAddr::V4(v4) => {
            v.push(ATYP_V4);
            v.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            v.push(ATYP_V6);
            v.extend_from_slice(&v6.octets());
        }
    }
    v.extend_from_slice(&ep.port.to_be_bytes());
    v
}

fn parse_addr(data: &[u8], p: usize, end: usize) -> Option<(UdpEndpoint, usize)> {
    if p >= end {
        return None;
    }
    match data[p] {
        ATYP_V4 => parse_addr_v4(data, p, end),
        ATYP_V6 => parse_addr_v6(data, p, end),
        ATYP_DOMAIN => parse_addr_domain(data, p, end),
        _ => None,
    }
}

fn parse_addr_v4(data: &[u8], p: usize, end: usize) -> Option<(UdpEndpoint, usize)> {
    if p + 7 > end {
        return None;
    }
    let ep = UdpEndpoint::v4(
        [data[p + 1], data[p + 2], data[p + 3], data[p + 4]],
        u16::from_be_bytes([data[p + 5], data[p + 6]]),
    );
    Some((ep, p + 7))
}

fn parse_addr_v6(data: &[u8], p: usize, end: usize) -> Option<(UdpEndpoint, usize)> {
    if p + 19 > end {
        return None;
    }
    let mut o = [0u8; 16];
    o.copy_from_slice(&data[p + 1..p + 17]);
    let ep = UdpEndpoint::v6(o, u16::from_be_bytes([data[p + 17], data[p + 18]]));
    Some((ep, p + 19))
}

fn parse_addr_domain(data: &[u8], p: usize, end: usize) -> Option<(UdpEndpoint, usize)> {
    let n = data[p + 1] as usize;
    if p + 2 + n + 2 > end {
        return None;
    }
    let s = match std::str::from_utf8(&data[p + 2..p + 2 + n]) {
        Ok(s) => s.to_string(),
        Err(_) => return None,
    };
    let port = u16::from_be_bytes([data[p + 2 + n], data[p + 3 + n]]);
    let mut ep = UdpEndpoint::v4([0, 0, 0, 0], port);
    ep.domain = s.into(); // R1-N11B（A15 1.2）：String → Arc<str>（encode_addr 不读 domain，AX3 契约不受影响）
    Some((ep, p + 2 + n + 2))
}

type FrameSlice<'a> = (UdpEndpoint, UdpEndpoint, &'a [u8], usize);

fn decode_frame(data: &[u8]) -> io::Result<Option<FrameSlice<'_>>> {
    if data.len() < 2 {
        return Ok(None);
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if len < FRAME_MIN {
        if len == 0 && data.len() < 3 {
            return Ok(None);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp: cns-rust 帧长非法 {len}"),
        ));
    }
    if 2 + len > data.len() {
        return Ok(None);
    }
    let end = 2 + len;
    let Some((a, p)) = parse_addr(data, 2, end) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp: cns-rust A 地址块解析失败",
        ));
    };
    let Some((b, start)) = parse_addr(data, p, end) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp: cns-rust B 地址块解析失败",
        ));
    };
    Ok(Some((a, b, &data[start..end], end)))
}

fn decode_ctrl(data: &[u8]) -> Option<(u8, usize)> {
    if data.len() < 3 {
        return None;
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if len != CTRL_LEN {
        return None;
    }
    Some((data[2], 3))
}

pub struct CnsRustDatagramLink {
    out: tokio::sync::mpsc::Sender<Frame>,
    inp: Mutex<Receiver<Frame>>,
}

impl CnsRustDatagramLink {
    fn build() -> io::Result<Self> {
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(UDP_OUT_QUEUE);
        let (in_tx, in_rx) = sync_channel::<Frame>(UDP_IN_QUEUE);

        thread::Builder::new()
            .name("nw-udp-cnsr".into())
            .spawn(move || cnsr_thread_main(out_rx, in_tx))
            .map_err(io::Error::other)?;

        Ok(Self {
            out: out_tx,
            inp: Mutex::new(in_rx),
        })
    }
}

fn cnsr_thread_main(out_rx: tokio::sync::mpsc::Receiver<Frame>, in_tx: SyncSender<Frame>) {
    if let Err(e) = cnsr_tunnel_task(out_rx, in_tx) {
        crate::udp_datagram::mark_link_fail();
        throttled("udp: cns-rust 隧道退出", WINDOW_TUNNEL, || {
            format!("udp: cns-rust 隧道退出: {e}")
        });
    }
}

impl crate::udp_datagram::UdpDatagramLink for CnsRustDatagramLink {
    fn name(&self) -> &'static str {
        "cns-rust"
    }

    fn send(&self, dst: UdpEndpoint, data: &[u8]) -> io::Result<()> {
        enqueue_out(
            &self.out,
            (dst, None, data.to_vec()),
            io::ErrorKind::BrokenPipe,
            "udp: cns-rust 隧道已关闭",
        )
    }

    fn send_from(&self, src: UdpEndpoint, dst: UdpEndpoint, data: &[u8]) -> io::Result<()> {
        enqueue_out(
            &self.out,
            (dst, Some(src), data.to_vec()),
            io::ErrorKind::BrokenPipe,
            "udp: cns-rust 隧道已关闭",
        )
    }

    fn recv_timeout_with_src(
        &self,
        d: Duration,
    ) -> io::Result<Option<(UdpEndpoint, Option<UdpEndpoint>, Vec<u8>)>> {
        let rx = self
            .inp
            .lock()
            .map_err(|_| io::Error::other("udp: cns-rust 入站队列锁中毒"))?;
        map_recv_timeout(rx.recv_timeout(d))
    }

    fn recv_timeout(&self, d: Duration) -> io::Result<Option<(UdpEndpoint, Vec<u8>)>> {
        Ok(self.recv_timeout_with_src(d)?.map(|(ep, _src, v)| (ep, v)))
    }
}

fn cnsr_tunnel_task(
    out_rx: tokio::sync::mpsc::Receiver<Frame>,
    in_tx: SyncSender<Frame>,
) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(cnsr_run(out_rx, in_tx))
}

async fn cnsr_run(
    out_rx: tokio::sync::mpsc::Receiver<Frame>,
    in_tx: SyncSender<Frame>,
) -> io::Result<()> {
    let mut st = cnsr_handshake().await?;
    let mark = cnsr_tunnel_loop(&mut st, out_rx, in_tx).await;
    if mark {
        crate::udp_datagram::mark_link_fail();
    }
    Ok(())
}

struct CnsrState {
    rd: tokio::io::ReadHalf<BoxStream>,
    wr: tokio::io::WriteHalf<BoxStream>,
    w_sub: usize,
    r_sub: usize,
    password: Vec<u8>,
    rbuf: Vec<u8>,
    pending: Vec<u8>,
    pending_start: usize,
    handshake_at: std::time::Instant,
}

async fn cnsr_handshake() -> io::Result<CnsrState> {
    let cfg = nwproxy_common::config::cfg_snapshot();
    let server = udp_server_addr();
    // F2：拨号前读取出口指纹（与 dialer_dial 内部读取的 current_bind_device 同源），
    // 握手成功后盖印——socket 级绑定属性在此刻固化，之后出口漂移即判护照失效。
    let (bind_dev, bind_ifindex) = crate::udp_datagram::current_egress_fingerprint();
    let egress_gen = nwproxy_common::egress::egress_gen();
    let stream = crate::conn::dial_cns_conn(&cfg, &server).await?;

    let host = udp_handshake_host();
    let password = udp_password();
    let req = build_udp_handshake(CNSR_FLAG, &server, &host, &password);

    let mut stream = stream;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        stream.write_all(req.as_bytes()).await?;
        read_http_header_exact(&mut stream).await
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "udp: cns-rust 握手超时，服务端未返回 101",
        )
    })??;

    let (rd, wr) = tokio::io::split(stream);
    clear_link_fail();
    crate::udp_datagram::stamp_link_passport(&bind_dev, bind_ifindex, egress_gen); // F2：链路护照盖印
    Ok(CnsrState {
        rd,
        wr,
        w_sub: 0,
        r_sub: 0,
        password,
        rbuf: vec![0u8; FRAME_MAX],
        pending: Vec::with_capacity(FRAME_MAX * 2),
        pending_start: 0,
        handshake_at: std::time::Instant::now(),
    })
}

async fn cnsr_tunnel_loop(
    st: &mut CnsrState,
    mut out_rx: tokio::sync::mpsc::Receiver<Frame>,
    in_tx: SyncSender<Frame>,
) -> bool {
    let mut last_echo_resp = std::time::Instant::now();
    let mut next_echo = last_echo_resp + ECHO_INTERVAL;

    loop {
        match cnsr_step(st, &mut out_rx, &in_tx, &mut last_echo_resp, next_echo).await {
            CnsrStep::Continue => {}
            CnsrStep::NextEcho(at) => next_echo = at,
            CnsrStep::Stop(failed) => return failed,
        }
    }
}

enum CnsrStep {
    Continue,
    NextEcho(std::time::Instant),
    Stop(bool),
}

async fn cnsr_step(
    st: &mut CnsrState,
    out_rx: &mut tokio::sync::mpsc::Receiver<Frame>,
    in_tx: &SyncSender<Frame>,
    last_echo_resp: &mut std::time::Instant,
    next_echo: std::time::Instant,
) -> CnsrStep {
    use tokio::io::AsyncReadExt as _;
    let CnsrState {
        rd,
        wr,
        w_sub,
        password,
        rbuf,
        ..
    } = st;

    tokio::select! {
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next_echo)) => {
            cnsr_on_echo_tick(wr, w_sub, password, last_echo_resp).await
        }
        maybe = out_rx.recv() => cnsr_on_out(wr, out_rx, w_sub, password, maybe).await,
        n = rd.read(rbuf) => cnsr_on_read(st, in_tx, n, last_echo_resp).await,
    }
}

async fn cnsr_on_echo_tick(
    wr: &mut tokio::io::WriteHalf<BoxStream>,
    w_sub: &mut usize,
    password: &[u8],
    last_echo_resp: &mut std::time::Instant,
) -> CnsrStep {
    use tokio::io::AsyncWriteExt as _;
    if last_echo_resp.elapsed() > ECHO_MAX_SILENCE {
        throttled("udp: cns-rust 探活超时", WINDOW_TUNNEL, || {
            format!(
                "udp: cns-rust 探活 {}s 无响应，判定隧道失效，断链重建",
                ECHO_MAX_SILENCE.as_secs()
            )
        });
        return CnsrStep::Stop(true);
    }
    let mut frame = vec![0u8, 0u8, CMD_ECHO_REQ];
    if !password.is_empty() {
        xor_crypt(&mut frame, w_sub, password);
    }
    if wr.write_all(&frame).await.is_err() {
        return CnsrStep::Stop(true);
    }
    CnsrStep::NextEcho(std::time::Instant::now() + ECHO_INTERVAL)
}

async fn cnsr_on_out(
    wr: &mut tokio::io::WriteHalf<BoxStream>,
    out_rx: &mut tokio::sync::mpsc::Receiver<Frame>,
    w_sub: &mut usize,
    password: &[u8],
    maybe: Option<Frame>,
) -> CnsrStep {
    let Some((ep, src, data)) = maybe else {
        return CnsrStep::Stop(false);
    };
    if data.is_empty() {
        return CnsrStep::Continue;
    }
    let mut batch: Vec<u8> = Vec::with_capacity(1400);
    let mut frames = 0usize;
    if cnsr_batch_append(&mut batch, w_sub, password, ep, src, data) {
        frames += 1;
    }
    // 存量帧非阻塞收（不引入额外延迟）
    while frames < CNSR_OUT_BATCH_MAX {
        match out_rx.try_recv() {
            Ok((ep, src, data)) => {
                if cnsr_batch_append(&mut batch, w_sub, password, ep, src, data) {
                    frames += 1;
                }
            }
            Err(_) => break,
        }
    }
    // 未满批：开 1ms 窗口收新帧，窗口到或满 16 帧即写
    if frames < CNSR_OUT_BATCH_MAX {
        let deadline = tokio::time::Instant::now() + CNSR_OUT_BATCH_WINDOW;
        while frames < CNSR_OUT_BATCH_MAX {
            match tokio::time::timeout_at(deadline, out_rx.recv()).await {
                Ok(Some((ep, src, data))) => {
                    if cnsr_batch_append(&mut batch, w_sub, password, ep, src, data) {
                        frames += 1;
                    }
                }
                _ => break,
            }
        }
    }
    if batch.is_empty() {
        return CnsrStep::Continue;
    }
    if wr.write_all(&batch).await.is_err() {
        return CnsrStep::Stop(true);
    }
    CnsrStep::Continue
}

// 把一帧 encode+xor 追加进批缓冲；返回 false 表示跳过该帧
//（空载荷或编码失败，与逐帧写的跳过语义一致）。只 XOR 本次
// 追加的字节，w_sub 跨帧连续滚动，密文流与逐帧写完全一致。
fn cnsr_batch_append(
    batch: &mut Vec<u8>,
    w_sub: &mut usize,
    password: &[u8],
    ep: UdpEndpoint,
    src: Option<UdpEndpoint>,
    data: Vec<u8>,
) -> bool {
    if data.is_empty() {
        return false;
    }
    let b = src.unwrap_or_else(unspecified_v4);
    let at = batch.len();
    if encode_frame(batch, &ep, &b, &data).is_err() {
        batch.truncate(at);
        return false;
    }
    if !password.is_empty() {
        xor_crypt(&mut batch[at..], w_sub, password);
    }
    true
}

async fn cnsr_on_read(
    st: &mut CnsrState,
    in_tx: &SyncSender<Frame>,
    n: io::Result<usize>,
    last_echo_resp: &mut std::time::Instant,
) -> CnsrStep {
    let CnsrState {
        r_sub,
        password,
        rbuf,
        pending,
        pending_start,
        handshake_at,
        ..
    } = st;

    let n = match n {
        Ok(0) => {
            let idle = handshake_at.elapsed() >= IDLE_CLOSE_MIN_LIFETIME;
            throttled("udp: cns-rust 隧道 EOF", WINDOW_TUNNEL, || {
                "udp: cns-rust 隧道 EOF".to_string()
            });
            return CnsrStep::Stop(!idle);
        }
        Ok(n) => n,
        Err(_e) => return CnsrStep::Stop(true),
    };

    if !password.is_empty() {
        xor_crypt(&mut rbuf[..n], r_sub, password);
    }
    pending.extend_from_slice(&rbuf[..n]);
    match cnsr_drain_pending(pending, pending_start, in_tx, last_echo_resp) {
        CnsrDrain::Dropped => {
            if pending.len() - *pending_start > FRAME_MAX * 4 {
                crate::udp_datagram::mark_link_fail();
                return CnsrStep::Stop(false);
            }
        }
        CnsrDrain::Stop => return CnsrStep::Stop(false),
    }
    CnsrStep::Continue
}

enum CnsrDrain {
    Dropped,
    Stop,
}

fn cnsr_drain_pending(
    pending: &mut Vec<u8>,
    start: &mut usize,
    in_tx: &SyncSender<Frame>,
    last_echo_resp: &mut std::time::Instant,
) -> CnsrDrain {
    let mut consumed = 0usize;
    loop {
        if let Some((cmd, used)) = decode_ctrl(&pending[*start + consumed..]) {
            if cmd == CMD_ECHO_RESP {
                *last_echo_resp = std::time::Instant::now();
            }
            consumed += used;
            continue;
        }
        match decode_frame(&pending[*start + consumed..]) {
            Ok(Some((remote, cli, payload, used))) => {
                let src = (cli != unspecified_v4()).then_some(cli);
                if enqueue_in(in_tx, (remote, src, payload.to_vec())).is_err() {
                    return CnsrDrain::Stop;
                }
                consumed += used;
            }
            Ok(None) => break,
            Err(e) => {
                crate::udp_datagram::mark_link_fail();
                throttled("udp: cns-rust 坏帧", WINDOW_TUNNEL, || {
                    format!("udp: cns-rust 坏帧，断链重建: {e}")
                });
                return CnsrDrain::Stop;
            }
        }
    }
    if consumed > 0 {
        *start += consumed;
        if *start == pending.len() {
            pending.clear();
            *start = 0;
        }
    }
    CnsrDrain::Dropped
}

pub fn build_cnsr_link() -> io::Result<crate::udp_datagram::SharedLink> {
    Ok(Arc::new(CnsRustDatagramLink::build()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep_v4(a: [u8; 4], port: u16) -> UdpEndpoint {
        UdpEndpoint::v4(a, port)
    }

    // 逐帧写（改动前语义）：每帧独立 encode + xor，sub 跨帧滚动。
    fn sequential_bytes(
        frames: &[(UdpEndpoint, Option<UdpEndpoint>, Vec<u8>)],
        password: &[u8],
    ) -> (Vec<u8>, usize) {
        let mut sub = 0usize;
        let mut out = Vec::new();
        for (ep, src, data) in frames {
            let b = src.clone().unwrap_or_else(unspecified_v4);
            let mut one = Vec::new();
            encode_frame(&mut one, ep, &b, data).unwrap();
            xor_crypt(&mut one, &mut sub, password);
            out.extend_from_slice(&one);
        }
        (out, sub)
    }

    #[test]
    fn batch_matches_sequential_with_password() {
        let frames = vec![
            (
                ep_v4([1, 1, 1, 1], 53),
                Some(ep_v4([192, 168, 1, 2], 5353)),
                b"dns-query-payload".to_vec(),
            ),
            (ep_v4([8, 8, 8, 8], 443), None, vec![0xABu8; 300]),
            (
                ep_v4([10, 0, 0, 9], 1234),
                Some(ep_v4([127, 0, 0, 1], 9999)),
                vec![0x5Au8; 1400],
            ),
        ];
        let password = b"Meng";

        let (want, want_sub) = sequential_bytes(&frames, password);

        let mut batch = Vec::new();
        let mut sub = 0usize;
        for (ep, src, data) in frames {
            assert!(cnsr_batch_append(
                &mut batch, &mut sub, password, ep, src, data
            ));
        }

        assert_eq!(batch, want, "批写字节流必须与逐帧写完全一致");
        assert_eq!(sub, want_sub, "XOR sub 滚动位置必须一致");
    }

    #[test]
    fn batch_matches_sequential_without_password() {
        let frames = vec![
            (ep_v4([1, 1, 1, 1], 53), None, b"plain".to_vec()),
            (ep_v4([2, 2, 2, 2], 80), None, vec![0x11u8; 64]),
        ];
        let (want, want_sub) = sequential_bytes(&frames, b"");
        let mut batch = Vec::new();
        let mut sub = 0usize;
        for (ep, src, data) in frames {
            assert!(cnsr_batch_append(&mut batch, &mut sub, b"", ep, src, data));
        }
        assert_eq!(batch, want);
        assert_eq!(sub, want_sub);
    }

    #[test]
    fn batch_preserves_frame_boundaries() {
        let d1 = vec![0x01u8; 10];
        let d2 = vec![0x02u8; 20];
        let mut batch = Vec::new();
        let mut sub = 0usize;
        assert!(cnsr_batch_append(
            &mut batch,
            &mut sub,
            b"pw",
            ep_v4([1, 1, 1, 1], 53),
            None,
            d1.clone(),
        ));
        assert!(cnsr_batch_append(
            &mut batch,
            &mut sub,
            b"pw",
            ep_v4([2, 2, 2, 2], 80),
            None,
            d2.clone(),
        ));

        // 长度头随帧体一起加密（读侧先整段解密再切帧），故先解密再验边界
        let mut plain = batch.clone();
        let mut rsub = 0usize;
        xor_crypt(&mut plain, &mut rsub, b"pw");

        // 帧1：2B len 头 + 14B 地址（v4/v4）+ 10B 载荷
        let len1 = u16::from_le_bytes([plain[0], plain[1]]) as usize;
        assert_eq!(len1, 14 + d1.len());
        // 帧2 起点紧随帧1，长度头正确
        let off2 = 2 + len1;
        let len2 = u16::from_le_bytes([plain[off2], plain[off2 + 1]]) as usize;
        assert_eq!(len2, 14 + d2.len());
        assert_eq!(plain.len(), off2 + 2 + len2, "批总长=两帧之和，边界无粘连");

        // 解密回来后可按长度头切回两帧（decode 侧依赖的性质）
        assert_eq!(&plain[2 + 14..2 + 14 + 10], &d1[..]);
        assert_eq!(&plain[off2 + 2 + 14..off2 + 2 + 14 + 20], &d2[..]);
    }

    #[test]
    fn batch_skips_empty_and_oversized() {
        let mut batch = Vec::new();
        let mut sub = 0usize;

        // 空载荷：跳过，不产字节
        assert!(!cnsr_batch_append(
            &mut batch,
            &mut sub,
            b"pw",
            ep_v4([1, 1, 1, 1], 53),
            None,
            Vec::new(),
        ));
        assert!(batch.is_empty());

        // 超长帧（len > u16::MAX）：跳过且缓冲回滚，不影响后续帧
        let huge = vec![0x00u8; 65530];
        assert!(!cnsr_batch_append(
            &mut batch,
            &mut sub,
            b"pw",
            ep_v4([1, 1, 1, 1], 53),
            None,
            huge,
        ));
        assert!(batch.is_empty());
        assert_eq!(sub, 0, "被跳过帧不得消耗 sub");

        let ok = vec![0x07u8; 5];
        assert!(cnsr_batch_append(
            &mut batch,
            &mut sub,
            b"pw",
            ep_v4([3, 3, 3, 3], 70),
            None,
            ok.clone(),
        ));
        let mut sub_ref = 0usize;
        let mut want = Vec::new();
        encode_frame(&mut want, &ep_v4([3, 3, 3, 3], 70), &unspecified_v4(), &ok).unwrap();
        xor_crypt(&mut want, &mut sub_ref, b"pw");
        assert_eq!(batch, want);
        assert_eq!(sub, sub_ref);
    }

    #[test]
    fn batch_cap_and_window_constants() {
        assert_eq!(CNSR_OUT_BATCH_MAX, 16);
        assert_eq!(CNSR_OUT_BATCH_WINDOW, Duration::from_millis(1));
    }
}
