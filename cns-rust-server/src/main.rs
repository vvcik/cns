// ⚠ `log` 必须排在最前：`#[macro_use]` 导出的宏只对**其后**声明的模块可见，
// 放在 `dns` 之后会让 `dns` 里的 `svc_log!` 报「找不到宏」。
#[macro_use]
mod log;
mod config;
mod dns;
mod http_tunnel;
mod sys;
mod tcp;
mod tls_side;
mod udp;
/// cns-rust：与本项目 nwproxy 客户端配套的新 UDP 承载。见模块文档——
/// 它与 `udp`（旧协议兼容层）并存，靠握手里的 flag 区分，互不影响。
mod udp_rust;
/// 内部小工具（纯函数，见模块文档）。
mod util;
mod xorcrypt;

use config::{load_config, JsonConfig, CONFIG, XOR_PASSWORD};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;

/// 版本号，`-version` 输出面（交互式输出，与 `-h` 同口径）。
const VERSION: &str = "0.4.3";

struct CmdArgs {
    json_config_path: String,
    help: bool,
    version: bool,
    enable_daemon: bool,
}

/// 仅响应 `-h` / `-version`：这是**交互式输出**，不是日志——由使用者在
/// 自己的终端上主动触发，不写进任何日志系统，也不含用户信息。
///
/// 其它任何路径（参数错误、缺配置、启动失败）都不再打印它，一律改用退出码，
/// 见 [`exit_code`] 模块。
fn print_usage() {
    println!("Usage of cns:");
    println!("  -daemon");
    println!("    \tdaemon mode switch");
    println!("  -h");
    println!("    \t");
    println!("  -help");
    println!("    \tdisplay this message");
    println!("  -json string");
    println!("    \tjson config path");
    println!("  -version");
    println!("    \tdisplay version");
}

/// 静默失败：**用退出码代替日志**。
///
/// 服务端不写日志（见 `log` 模块文档），但「服务没起来」这件事必须能被
/// 感知——否则运维只能靠客户端实测反推。退出码不含任何信息，却足以让
/// systemd / 部署脚本区分失败原因。
///
/// 码值本身不泄露配置内容：拿到码的人只能知道「哪一步失败」，看不到路径、
/// 域名或证书内容。码表同步 `docs/crates/cns-rust-server.md`。
mod exit_code {
    pub const ARGS: i32 = 2;
    pub const NO_CONFIG: i32 = 3;
    pub const CONFIG_LOAD: i32 = 4;
    pub const SPAWN_CHILD: i32 = 5;
    pub const TLS_CERT: i32 = 6;
    /// 监听绑定失败：`start_tls` / `start_http_tunnel` **任一**地址绑不上即
    /// 整进程退出（fail-closed，非「全部绑不上」）。此前只 `svc_log`（默认零
    /// 输出）后 return，进程永挂而监听静默缺席。
    pub const LISTEN: i32 = 7;
    /// tokio runtime 创建失败。原 `Runtime::new().expect` 以 panic 101 收场，
    /// 101 不在码表内，判障通道漏一槽。
    pub const RUNTIME: i32 = 8;
}

/// 解析当前可执行文件路径；解析失败回退 argv[0]。
///
/// daemon 分支与 supervisor 各需一份，收敛的意义在于回退语义只写一遍
/// （两处回退口径必须一致）。
fn current_exe_or_argv0() -> PathBuf {
    std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from(std::env::args().next().unwrap_or_default()))
}

/// 解析命令行参数，等价于 Go flag 包的行为。
fn parse_args(args: &[String]) -> Result<CmdArgs, String> {
    let mut out = CmdArgs {
        json_config_path: String::new(),
        help: false,
        version: false,
        enable_daemon: false,
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-h" | "--h" | "-help" | "--help" => out.help = true,
            "-version" | "--version" => out.version = true,
            "-daemon" | "--daemon" => out.enable_daemon = true,
            "-daemon=true" | "-daemon=1" => out.enable_daemon = true,
            "-daemon=false" | "-daemon=0" => out.enable_daemon = false,
            "-json" | "--json" => {
                i += 1;
                out.json_config_path = args
                    .get(i)
                    .cloned()
                    .ok_or("flag needs an argument: -json")?;
            }
            _ => {
                if let Some(v) = a.strip_prefix("-json=") {
                    out.json_config_path = v.to_string();
                } else {
                    return Err(format!("flag provided but not defined: {a}"));
                }
            }
        }
        i += 1;
    }
    Ok(out)
}

fn pid_save_to_file(path: &str) {
    if let Ok(mut f) = std::fs::File::create(path) {
        let _ = writeln!(f, "{}", std::process::id());
    }
}

/// 轮询等待子进程退出（50ms 步进），期间随时响应停机信号。
///
/// 返回 `Some(status)`：子进程已退出。
/// 返回 `None`：`try_wait` 出错（子进程句柄异常），调用方按「已退出」处理。
/// 收到信号时杀掉子进程并以信号停机码退出（本函数不返回）。
fn wait_child_or_signal(child: &mut Child) -> Option<ExitStatus> {
    loop {
        if sys::SIGNAL_RECEIVED.load(Ordering::SeqCst) {
            // L1：信号停机走 1，与 nwproxy「1=通用致命」撞码——登记在案，
            // 改码需先与部署脚本域对账（见 README 退出码表注记）。
            let _ = child.kill();
            let _ = child.wait();
            std::process::exit(1);
        }
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// 崩溃自动重启：作为父进程循环拉起子进程（CHILD_PORC=true），
/// 收到 SIGTERM/SIGINT/SIGHUP/SIGQUIT 时杀掉子进程并退出。
fn run_child_supervisor(original_args: &[String]) -> ! {
    let exe = current_exe_or_argv0();
    // 连续快死阈值：子进程每次都在 2s 窗口内退出，说明是永久性失败（证书
    // exit 6 / 监听 exit 7 / 坏配置 exit 4），重启永不会成功。连续
    // FAST_DEATH_MAX 次后以子进程最近一次退出码退出自身（被信号杀死无退出码
    // 时归入槽位 1）。存活超过窗口则计数清零，不影响偶发崩溃的重启。
    const FAST_DEATH_MAX: u32 = 5;
    let mut fast_deaths: u32 = 0;
    let mut last_child_code: Option<i32> = None;
    loop {
        if sys::SIGNAL_RECEIVED.load(Ordering::SeqCst) {
            // 信号停机走 1，与 nwproxy「1=通用致命」撞码——登记在案，改码需
            // 先与部署脚本域对账（README 退出码表注记）。
            std::process::exit(1);
        }
        let started = std::time::Instant::now();
        let mut child = match Command::new(&exe)
            .args(original_args)
            .env_clear()
            .env("CHILD_PORC", "true")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                // 不打印 `e`：spawn 失败的原因里可能带可执行文件路径。
                std::process::exit(exit_code::SPAWN_CHILD);
            }
        };
        if let Some(status) = wait_child_or_signal(&mut child) {
            // 记下子进程退出码，作为放弃重启时 supervisor 自身的退出码。
            last_child_code = status.code();
        }
        // 存活不足 2s 说明在崩溃循环；无间隔重启会退化成 fork 风暴（每次
        // spawn+立即退出不到 1ms，打满 CPU 与进程表，也排空退出码的诊断价值）。
        if started.elapsed() < std::time::Duration::from_secs(2) {
            fast_deaths += 1;
            if fast_deaths >= FAST_DEATH_MAX {
                svc_log!(
                    "cns: child exited quickly {} times in a row, supervisor gives up",
                    FAST_DEATH_MAX
                );
                std::process::exit(last_child_code.unwrap_or(1));
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        } else {
            fast_deaths = 0;
        }
    }
}

/// `-daemon=true`：拉起一个后台子进程（追加 `-daemon=false`）后立即退出。
///
/// ⚠ 此处的 0 仅代表「后台进程拉起成功」，不代表服务已就绪——子进程
/// （supervisor）随后的坏配置 exit(4)/证书 exit(6)/监听 exit(7) 都发生在本
/// 进程退出之后。判障以 supervisor 进程退出码为准（README 完整码表）。
fn fork_daemon(raw_args: &[String]) -> ! {
    let exe = current_exe_or_argv0();
    let mut new_args = raw_args.to_vec();
    new_args.push("-daemon=false".to_string());
    // spawn 失败即以 SPAWN_CHILD 退出，不可吞掉——否则部署侧看到「成功」而
    // 后台 daemon 根本没起。不打印错误：文本可能带可执行文件路径。
    if Command::new(&exe).args(&new_args).spawn().is_err() {
        std::process::exit(exit_code::SPAWN_CHILD);
    }
    std::process::exit(0);
}

fn main() {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    let args = match parse_args(&raw_args) {
        Ok(a) => a,
        // 不打 `e`：它含用户敲错的原始参数（可能是手滑粘进来的路径或口令）。
        Err(_) => std::process::exit(exit_code::ARGS),
    };

    if args.help {
        print_usage();
        std::process::exit(0);
    }
    if args.version {
        println!("cns version {VERSION}");
        std::process::exit(0);
    }
    if args.json_config_path.is_empty() {
        std::process::exit(exit_code::NO_CONFIG);
    }

    if args.enable_daemon {
        fork_daemon(&raw_args);
    }

    /* 加载并预处理配置 */
    let mut cfg = match load_config(&args.json_config_path) {
        Ok(c) => c,
        // 不打 `e`：配置错误常带文件路径或证书路径。
        Err(_) => std::process::exit(exit_code::CONFIG_LOAD),
    };
    cfg.proxy_key = format!("\n{}: ", cfg.proxy_key);

    /* 父进程：监控子进程，崩溃自动重启 */
    if std::env::var("CHILD_PORC").as_deref() != Ok("true") {
        sys::install_signal_handlers();
        run_child_supervisor(&raw_args);
    }

    /* 子进程 */
    sys::setsid();
    sys::set_max_nofile();

    /* 有效 UID 非 root 时关闭 TFO */
    if cfg.enable_tfo && sys::geteuid() != 0 {
        // 静默降级：TFO 开不了不影响功能，只是少一个优化，没有告知的必要。
        cfg.enable_tfo = false;
    }

    let _ = CONFIG.set(cfg.clone());
    let _ = XOR_PASSWORD.set(cfg.encrypt_password.clone().into_bytes());

    if !cfg.pid_path.is_empty() {
        pid_save_to_file(&cfg.pid_path);
    }

    /* 启动 TLS 与普通 HTTP 隧道监听 */
    // runtime 创建失败走码表退出（RUNTIME=8）；match 而非 panic 也顺带对齐
    // 启动路径无 unwrap/expect 的清洁度目标。
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => std::process::exit(exit_code::RUNTIME),
    };
    rt.block_on(spawn_all_listeners(cfg));
}

/// 装配证书并拉起全部监听（TLS / 明文 HTTP 隧道），然后永久挂起。
///
/// 证书装配失败 ⇒ fail-closed：以 `exit_code::TLS_CERT` 退出（不可静默跳过，
/// 否则证书配错时进程照常启动而 TLS 监听全体缺席）。不打印失败详情：证书
/// 错误信息里可能带私钥文件路径。
async fn spawn_all_listeners(cfg: JsonConfig) {
    let tls_config = if cfg.tls.listen_addr.is_empty() {
        None
    } else {
        match tls_side::make_certificate_config(&cfg.tls) {
            Some(tc) => Some(tc),
            None => std::process::exit(exit_code::TLS_CERT),
        }
    };
    for addr in cfg.tls.listen_addr.iter().rev() {
        if let Some(tc) = tls_config.clone() {
            let addr = addr.clone();
            tokio::spawn(tls_side::start_tls(addr, tc));
        }
    }
    for addr in cfg.listen_addr.iter().rev() {
        let addr = addr.clone();
        let tc = tls_config.clone();
        tokio::spawn(http_tunnel::start_http_tunnel(addr, tc));
    }
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: &[&str]) -> Result<CmdArgs, String> {
        parse_args(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    // CLI 解析面回归：Go flag 等价语义。
    #[test]
    fn parse_args_flags() {
        // 各等价写法归一。
        for form in [["-h"], ["--h"], ["-help"], ["--help"]] {
            let a = parse(&form).unwrap();
            assert!(a.help, "{form:?} 应识别为 help");
        }
        let a = parse(&["-version"]).unwrap();
        assert!(a.version);

        let a = parse(&["-json=cns.json", "-daemon=true"]).unwrap();
        assert_eq!(a.json_config_path, "cns.json");
        assert!(a.enable_daemon);

        let a = parse(&["-json", "cns.json", "-daemon=false"]).unwrap();
        assert_eq!(a.json_config_path, "cns.json");
        assert!(!a.enable_daemon);

        // supervisor 给子进程追加的正是 -daemon=false，必须被识别。
        let a = parse(&["-json=x", "-daemon"]).unwrap();
        assert!(a.enable_daemon);

        // 未知 flag → Err（main 侧 exit 2）。
        assert!(parse(&["-bogus"]).is_err());
        // -json 缺参 → Err。
        assert!(parse(&["-json"]).is_err());
        // -daemon= 的非法布尔值 → Err（Go flag 对无效布尔同样报错）。
        assert!(parse(&["-daemon=maybe"]).is_err());
        // 无参：路径合法但缺配置路径 → 后续 NO_CONFIG 兜底。
        let a = parse(&[]).unwrap();
        assert!(a.json_config_path.is_empty());
    }
}
