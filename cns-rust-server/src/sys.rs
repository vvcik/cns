use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

/// 目标 nofile 上限：1048576（1M）。
#[cfg(unix)]
const NOFILE_TARGET: libc::rlimit = libc::rlimit {
    rlim_cur: 1048576,
    rlim_max: 1048576,
};

/// 提升 nofile 至 [`NOFILE_TARGET`]。
///
/// 直接 `setrlimit` 到 1M 在非 root + 低 hard limit（常见 4096/65535）时静默
/// 失败，服务照旧在 1024 软限下跑，高并发表现为莫名 `EMFILE`。故：先
/// `getrlimit` 留底，直提失败则降级把软限顶到当前 hard（无需特权）；两次都
/// 失败才 `svc_log`。失败只记日志不终止——nofile 是容量调优面不是正确性面。
#[cfg(unix)]
pub fn set_max_nofile() {
    let orig = unsafe {
        let mut r: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) != 0 {
            // 读不到就按保守假设继续（软限低、硬限未知）。
            libc::rlimit { rlim_cur: 1024, rlim_max: libc::RLIM_INFINITY }
        } else {
            r
        }
    };

    let target = NOFILE_TARGET;
    let ok_direct = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &target) } == 0;
    if ok_direct {
        return;
    }
    // 直提失败：多半是 hard 不够（非 root 不能抬高 hard）。软限顶到当前
    // hard；hard=RLIM_INFINITY 时内核拒绝软限取无穷，用 65535 兜底。
    let hard_cap = if orig.rlim_max == libc::RLIM_INFINITY {
        65535
    } else {
        orig.rlim_max
    };
    let fallback = libc::rlimit {
        rlim_cur: hard_cap,
        rlim_max: orig.rlim_max,
    };
    let ok_fallback = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &fallback) } == 0;
    if !ok_fallback {
        svc_log!(
            "sys: nofile 提升失败（目标 {}，当前 soft/hard {}/{:?}）",
            target.rlim_cur,
            orig.rlim_cur,
            orig.rlim_max
        );
    }
}

#[cfg(not(unix))]
pub fn set_max_nofile() {}

#[cfg(unix)]
pub fn setsid() {
    unsafe {
        libc::setsid();
    }
}

#[cfg(not(unix))]
pub fn setsid() {}

/// 返回当前进程有效 UID，非 root 为 0 判断用。
#[cfg(unix)]
pub fn geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub fn geteuid() -> u32 {
    0
}

/// 为监听 socket 开启 TCP FastOpen（Linux / TCP_FASTOPEN=23）。
pub fn enable_tcp_fastopen(sock: &socket2::Socket) {
    #[cfg(unix)]
    {
        const TCP_FASTOPEN: libc::c_int = 23;
        let fd = sock.as_raw_fd();
        let val: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_FASTOPEN,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let e = io::Error::last_os_error();
            svc_log!("sys: TFO 开启失败 {:?}", e.kind());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = sock;
    }
}

/// 由父进程安装的信号标记，收到 SIGTERM/SIGINT/SIGHUP/SIGQUIT 时置位。
pub static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn signal_handler(_sig: libc::c_int) {
    SIGNAL_RECEIVED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
pub fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as extern "C" fn(libc::c_int) as usize);
        libc::signal(libc::SIGINT, signal_handler as extern "C" fn(libc::c_int) as usize);
        libc::signal(libc::SIGHUP, signal_handler as extern "C" fn(libc::c_int) as usize);
        libc::signal(libc::SIGQUIT, signal_handler as extern "C" fn(libc::c_int) as usize);
    }
}

#[cfg(not(unix))]
pub fn install_signal_handlers() {}
