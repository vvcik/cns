//! 服务端日志：**默认零输出**。
//!
//! 输出通常落进 systemd journal / `docker logs` / `nohup.out` / 托管面板，
//! 能读到的人（运维、机房方、拿到磁盘者、第三方）与使用者不是同一批。一条
//! `No proxy host: {header}` 就把目标域名、Cookie、`Authorization` 写进去，
//! 且落盘后无从回收。因此默认不打，运行时开关也不设——留一个可打开的开关
//! 等于把风险外包给不知情的部署者。
//!
//! 排障时显式开启 feature 重新编译：`cargo build --release --features server-log`。
//! 即便开启，也**只接受不含用户数据**的载荷（固定字符串 / 计数 / 错误类别）：
//!
//! ```text
//! 允许：svc_log!("tcp: 头解析失败 {} 次", n)
//! 禁止：svc_log!("tcp: {}", host)、svc_log!("{:?}", header)
//! ```
//!
//! 需要带地址排查应在**本地复现**。启动/配置类（版本横幅、加载失败、监听失败、
//! TFO 降级）同样零输出——它们进的是同一个 journal，且启动时打印的路径与地址
//! 会勾勒出部署形态。判障改走**退出码**（见 `main.rs` 的 `exit_code` 模块）：
//! 把「哪一步失败」传给 systemd / 部署脚本，却不传任何内容。唯一保留的输出是
//! `-h` 的 usage——它由使用者在自己终端主动触发，不进任何日志系统。
//!
//! ## 限流
//!
//! [`svc_log!`] 的落点经 [`svc_emit`] 限流，与 `nwproxy_common::log::throttled`
//! **同语义**：key = `file:line`（每调用点独立窗口，防同文件多 warn 互相挤占）、
//! 窗口 60s（同 `WINDOW_TUNNEL`）、首条输出 → 抑制计数 → 窗口末汇总 → 10^n
//! 量级汇报 → 锁中毒直通，被抑制时不格式化消息（闭包承载 `format!`）。
//! 不亦依赖而自持一份，是因为本 crate 刻意零内部依赖（见 Cargo.toml）。
//!
//! 零输出铁律不变：feature 关闭时 `cfg!` 恒 false，限流器调用与格式化闭包整段
//! 被编译期消除。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 服务端运行期日志。默认静默，见模块文档。
///
/// 用 `if cfg!(...)` 而非 `#[cfg]`：后者在 feature 关闭时完全不编译格式串与
/// 参数，日志代码会悄悄腐烂（变量改名、类型变了都不知道）。`cfg!` 保留类型
/// 检查，且是编译期常量，`if false` 会被优化掉，运行期零开销。
#[macro_export]
macro_rules! svc_log {
    ($($arg:tt)*) => {
        if cfg!(feature = "server-log") {
            // 经 svc_emit 限流（key = file:line，60s 窗口）；闭包承载格式化，
            // 被抑制时零格式化开销。
            $crate::log::svc_emit(file!(), line!(), || format!($($arg)*));
        }
    };
}

/// 连接处理路径的计数器。仅在 `server-log` 下执行。
///
/// 参数是**一条完整语句**（如 `COUNTER.fetch_add(1, ..)`）而不是变量，因为
/// 计数器类型是 `AtomicU64`，没有 `+=` 语义。
///
/// 拆出来是因为：不开日志时计数本身也是浪费，但更关键的是**不开日志时不能有
/// 别的行为差异**——计数若影响控制流，开关日志就变成了开关功能。
#[macro_export]
macro_rules! svc_count {
    ($stmt:expr) => {
        if cfg!(feature = "server-log") {
            $stmt;
        }
    };
}

// 限流内核：与 nwproxy_common::log 同值同语义的自持实现（60s 窗口 =
// WINDOW_TUNNEL，状态迁移逐行对齐 throttled）。审计时两侧对照读即可。

/// 服务端日志窗口：与 nwproxy_common::log::WINDOW_TUNNEL 同值（60s）。
const WINDOW_SVC: Duration = Duration::from_secs(60);

/// 量级汇报首阈值：10 → 100 → 1000 …（同 MILESTONE_BASE）。
const MILESTONE_BASE: u64 = 10;

/// 窗口内单条目状态（与 nwproxy_common::log 的 Entry 同形）。
struct Entry {
    last: Instant,
    suppressed: u64,
    next_report: u64,
}

/// 单条目判定结果（与 throttled 的 Verdict 同形）。
#[derive(Debug, PartialEq)]
enum Verdict {
    Emit,
    EmitWithSummary(u64),
    ReportLevel(u64),
    Suppress,
}

/// 状态机核心（逐行对齐 nwproxy_common::log::throttled 的 match 体）。
fn decide(e: &mut Entry, now: Instant, window: Duration) -> Verdict {
    if now.duration_since(e.last) < window {
        e.suppressed = e.suppressed.saturating_add(1);
        if e.suppressed >= e.next_report {
            e.next_report = e.next_report.saturating_mul(10);
            Verdict::ReportLevel(e.suppressed)
        } else {
            Verdict::Suppress
        }
    } else {
        let n = e.suppressed;
        e.last = now;
        e.suppressed = 0;
        e.next_report = MILESTONE_BASE;
        if n == 0 {
            Verdict::Emit
        } else {
            Verdict::EmitWithSummary(n)
        }
    }
}

/// 限流表。key = (file, line)：file!() 是 &'static str，元组键免分配，
/// 且天然区分同文件多调用点（防互相挤占）。
fn table() -> &'static Mutex<HashMap<(&'static str, u32), Entry>> {
    static T: OnceLock<Mutex<HashMap<(&'static str, u32), Entry>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// svc_log! 的落点：以 file:line 为 key 限流输出。
///
/// ⚠ 判定先行：被抑制时**不调用** `msg()`；锁中毒时直通输出——宁可多打一条，
/// 不可丢错误（同 throttled）。
pub(crate) fn svc_emit(file: &'static str, line: u32, msg: impl FnOnce() -> String) {
    let verdict = match table().lock() {
        Ok(mut m) => {
            let now = Instant::now();
            match m.get_mut(&(file, line)) {
                None => {
                    m.insert((file, line), Entry {
                        last: now,
                        suppressed: 0,
                        next_report: MILESTONE_BASE,
                    });
                    Verdict::Emit
                }
                Some(e) => decide(e, now, WINDOW_SVC),
            }
        }
        // 锁中毒（持锁线程 panic 过）：降级为直接输出。诊断面在故障中，
        // 宁多勿少；此处不做恢复，下一轮锁会重建。
        Err(_) => Verdict::Emit,
    };
    match verdict {
        Verdict::Suppress => {}
        Verdict::Emit => eprintln!("{}", msg()),
        Verdict::EmitWithSummary(n) => {
            eprintln!("{}", msg());
            eprintln!("（上述日志已抑制 {n} 条，窗口 {}s）", WINDOW_SVC.as_secs());
        }
        Verdict::ReportLevel(n) => {
            eprintln!("（{file}:{line}：本窗口内已抑制 {n} 条，窗口 {}s）", WINDOW_SVC.as_secs());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试串行锁（表是进程级全局；口径同 nwproxy-common log.rs 测试）。
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn reset() {
        if let Ok(mut m) = table().lock() {
            m.clear();
        }
    }

    /// 首条输出 → 窗口内抑制计数 → 窗口末重述 + 汇总（状态迁移口径）。
    #[test]
    fn svc_throttle_first_emits_then_suppresses_with_counts() {
        let _g = serial();
        reset();
        // 表内首插 = 首条输出（Emit，见 svc_emit 的 None 分支）。
        let mut e = Entry { last: Instant::now(), suppressed: 0, next_report: MILESTONE_BASE };
        assert_eq!(decide(&mut e, Instant::now(), WINDOW_SVC), Verdict::Suppress);
        assert_eq!(e.suppressed, 1);
        for _ in 0..4 {
            let _ = decide(&mut e, Instant::now(), WINDOW_SVC);
        }
        assert_eq!(e.suppressed, 5);
        // 窗口过后的下一次：重述 + 汇总 5 条，计数清零，阈值复位。
        let later = e.last + WINDOW_SVC + Duration::from_secs(1);
        assert_eq!(decide(&mut e, later, WINDOW_SVC), Verdict::EmitWithSummary(5));
        assert_eq!(e.suppressed, 0);
        assert_eq!(e.next_report, MILESTONE_BASE);
    }

    /// 量级汇报：10^n 阈值推进（10 → 100 → 1000）。
    #[test]
    fn svc_throttle_reports_magnitude_per_decade() {
        let _g = serial();
        reset();
        let mut e = Entry { last: Instant::now(), suppressed: 0, next_report: MILESTONE_BASE };
        for _ in 0..9 {
            assert_eq!(decide(&mut e, Instant::now(), WINDOW_SVC), Verdict::Suppress);
        }
        assert_eq!(e.next_report, MILESTONE_BASE, "9 < 10，阈值不该推进");
        assert_eq!(decide(&mut e, Instant::now(), WINDOW_SVC), Verdict::ReportLevel(10));
        assert_eq!(e.next_report, 100);
        let mut reported: Vec<u64> = Vec::new();
        for _ in 0..90 {
            if let Verdict::ReportLevel(n) = decide(&mut e, Instant::now(), WINDOW_SVC) {
                reported.push(n);
            }
        }
        assert_eq!(reported, vec![100]);
        assert_eq!(e.next_report, 1000);
    }

    /// 每调用点独立窗口：svc_emit 以 (file, line) 建键，同文件不同行互不挤占。
    #[test]
    fn svc_throttle_distinct_call_sites_independent() {
        let _g = serial();
        reset();
        svc_emit("a.rs", 1, || String::from("x"));
        svc_emit("a.rs", 2, || String::from("y"));
        svc_emit("b.rs", 1, || String::from("z"));
        svc_emit("a.rs", 1, || String::from("x2"));
        let m = table().lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(m.len(), 3, "三个 (file, line) 键，各一个条目");
        assert_eq!(m.get(&("a.rs", 1)).map(|e| e.suppressed), Some(1));
        assert_eq!(m.get(&("a.rs", 2)).map(|e| e.suppressed), Some(0));
        assert_eq!(m.get(&("b.rs", 1)).map(|e| e.suppressed), Some(0));
    }
}
