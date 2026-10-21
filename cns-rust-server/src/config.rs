use serde_json::Value;
use std::sync::OnceLock;

pub static CONFIG: OnceLock<JsonConfig> = OnceLock::new();
pub static XOR_PASSWORD: OnceLock<Vec<u8>> = OnceLock::new();

/// 运行期读取全局配置的唯一入口（原 11 处逐字重复的
/// `CONFIG.get().expect(...)` 收敛于此）。
///
/// 此 panic 是**初始化期不变量**而非运行期降级面：`CONFIG` 仅在 `main` 完成
/// 配置加载后设置一次（早于 runtime 创建与任何监听任务启动），`get` 为 `None`
/// 只可能是初始化顺序被破坏的程序 bug。静默回退默认配置会把「配置没生效」
/// 变成难以归因的运行期行为漂移，比早死难查得多。
pub fn config() -> &'static JsonConfig {
    CONFIG.get().expect("config not initialized")
}

/// timeout 字段的 Go 对齐默认值（与 `JsonConfig::default()` 一致）。
/// 0 值穿透到 `tokio::time::timeout` 会立即 Elapsed——所有会话首包读/转发
/// 读写秒断，UDP 同理。故 timeout 字段的 0/负/错型一律回退这两个值
/// （见 [`as_timeout`]）；「错型回零」仅保留给非 timeout 字段。
pub const DEFAULT_TCP_TIMEOUT: u64 = 600;
pub const DEFAULT_UDP_TIMEOUT: u64 = 30;

/// 串行化所有会修改全局 `CONFIG` / `XOR_PASSWORD` 的测试，避免并行竞态。
/// 使用 `unwrap_or_else(poisoned)` 抵抗某个测试失败带来的锁中毒连锁。
#[cfg(test)]
pub static GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 获取全局测试锁（抗中毒）。
#[cfg(test)]
pub fn global_lock() -> std::sync::MutexGuard<'static, ()> {
    GLOBAL_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// TLS 监听相关配置
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub listen_addr: Vec<String>,
    pub auto_cert_hosts: Vec<String>,
    pub cert_file: String,
    pub key_file: String,
}

/// 对应 Go 版本的 JsonConfig
#[derive(Debug, Clone)]
pub struct JsonConfig {
    pub tls: TlsConfig,
    pub listen_addr: Vec<String>,
    pub proxy_key: String,
    pub udp_flag: String,
    /// cns-rust 新协议的握手 flag。
    ///
    /// 与 `udp_flag` 并存：服务端在握手里**先**匹配本值，命中走 cns-rust，
    /// 未命中再按 `udp_flag` 走旧协议。两者默认不同，故旧客户端不受影响。
    ///
    /// ⚠ 不得与 `udp_flag` 取同一个值，否则旧协议永远分不到流；
    /// 该约束由 `load_config` 在加载期强制（同值配置直接报错拒绝）。
    pub udp_flag_rust: String,
    pub encrypt_password: String,
    pub pid_path: String,
    /// 单位：秒。加载期经 `as_timeout` 消毒：0/负/错型 → `DEFAULT_TCP_TIMEOUT`。
    /// 运行期读取请走 [`JsonConfig::tcp_timeout_duration`]（防御性再兜底）。
    pub tcp_timeout: u64,
    /// 单位：秒。加载期经 `as_timeout` 消毒：0/负/错型 → `DEFAULT_UDP_TIMEOUT`。
    /// 运行期读取请走 [`JsonConfig::udp_timeout_duration`]（防御性再兜底）。
    pub udp_timeout: u64,
    pub enable_dns_tcp_over_udp: bool,
    pub enable_http_dns: bool,
    pub enable_tfo: bool,
}

impl JsonConfig {
    /// tcp_timeout 的防御读取：0 值直接进 `tokio::time::timeout` 等于「会话
    /// 秒断」。`load_config` 已在入口消毒，这里再兜一道底——`JsonConfig` 也可
    /// 能不经 `load_config` 构造（测试、未来代码路径），防御不依赖单点。
    pub fn tcp_timeout_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(if self.tcp_timeout == 0 {
            DEFAULT_TCP_TIMEOUT
        } else {
            self.tcp_timeout
        })
    }

    /// udp_timeout 的防御读取，语义同 [`JsonConfig::tcp_timeout_duration`]。
    pub fn udp_timeout_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(if self.udp_timeout == 0 {
            DEFAULT_UDP_TIMEOUT
        } else {
            self.udp_timeout
        })
    }
}

impl Default for JsonConfig {
    fn default() -> Self {
        JsonConfig {
            tls: TlsConfig::default(),
            listen_addr: Vec::new(),
            proxy_key: "Host".into(),
            udp_flag: "httpUDP".into(),
            udp_flag_rust: "cnsrUDP".into(),
            encrypt_password: String::new(),
            pid_path: String::new(),
            tcp_timeout: 600,
            udp_timeout: 30,
            enable_dns_tcp_over_udp: false,
            enable_http_dns: true,
            enable_tfo: false,
        }
    }
}

fn str_array(v: &Value) -> Vec<String> {
    match v {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|e| e.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

fn as_str(v: &Value) -> String {
    v.as_str().map(|s| s.to_string()).unwrap_or_default()
}

/// 类型零值兜底（unwrap_or 链的一环）。timeout 字段**不得**直接消费本函数的
/// 产物——0 值对 timeout 有毒，必须经 [`as_timeout`] 消毒。
fn as_u64(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

/// timeout 字段专用消毒助手：0、负数、错型（`as_u64` 均折为 0/None）一律回退
/// Go 对齐默认值；正常正整数原样通过。
///
/// 只做值消毒、不返回 Result（「错型不让 load 失败」是不变量）；「回零」仅保留
/// 给非 timeout 字段。
fn as_timeout(field: &str, v: &Value, default: u64) -> u64 {
    match as_u64(v) {
        n if n > 0 => n,
        _ => {
            svc_log!("config: {field} 非法（0/负值/错型），回退默认 {}s", default);
            default
        }
    }
}

fn as_bool(v: &Value) -> bool {
    v.as_bool().unwrap_or(false)
}

/// 从 JSON 配置加载配置。
///
/// 字段名匹配**大小写不敏感**（与 Go `encoding/json` 一致）：键先转小写再匹配。
/// 未知键静默忽略。主体是「键名 → 字段赋值」的规范映射表，每臂一行赋值
/// （数据表本质，不拆）；`tls` 子对象收敛进 [`apply_tls_key`]，新增配置键直接
/// 加臂即可。
///
/// 解析 `tls` 子对象键值到 `TlsConfig`（load_config 的 tls 臂收敛点）。
/// 未知键忽略——与顶层键同口径（配置键大小写不敏感）。
fn apply_tls_key(cfg: &mut TlsConfig, key: &str, val: &Value) {
    match key.to_lowercase().as_str() {
        "listen_addr" => cfg.listen_addr = str_array(val),
        "autocerthosts" | "auto_cert_hosts" => cfg.auto_cert_hosts = str_array(val),
        "certfile" | "cert_file" => cfg.cert_file = as_str(val),
        "keyfile" | "key_file" => cfg.key_file = as_str(val),
        _ => {}
    }
}

pub fn load_config(filename: &str) -> Result<JsonConfig, String> {
    let data = std::fs::read_to_string(filename).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    let obj = v.as_object().ok_or("config root is not a json object")?;

    let mut cfg = JsonConfig::default();

    for (key, val) in obj {
        match key.to_lowercase().as_str() {
            "tls" => {
                if let Some(tls_obj) = val.as_object() {
                    for (tk, tv) in tls_obj {
                        apply_tls_key(&mut cfg.tls, tk, tv);
                    }
                }
            }
            "listen_addr" => cfg.listen_addr = str_array(val),
            "proxy_key" => cfg.proxy_key = as_str(val),
            "udp_flag" => cfg.udp_flag = as_str(val),
            "udp_flag_rust" => cfg.udp_flag_rust = as_str(val),
            "encrypt_password" => cfg.encrypt_password = as_str(val),
            "pid_path" => cfg.pid_path = as_str(val),
            // timeout 字段走消毒助手，0/负/错型一律回退默认值而非 0。
            "tcp_timeout" => cfg.tcp_timeout = as_timeout("tcp_timeout", val, DEFAULT_TCP_TIMEOUT),
            "udp_timeout" => cfg.udp_timeout = as_timeout("udp_timeout", val, DEFAULT_UDP_TIMEOUT),
            "enable_dns_tcpoverudp" => cfg.enable_dns_tcp_over_udp = as_bool(val),
            "enable_httpdns" => cfg.enable_http_dns = as_bool(val),
            "enable_tfo" => cfg.enable_tfo = as_bool(val),
            _ => {}
        }
    }

    // udp_flag 与 udp_flag_rust 同值 ⇒ 分流点先匹配 rust flag，旧协议分支永
    // 不可达。load_config 是配置进入系统的唯一入口，在此统一拒绝而非指望各
    // 消费点设防。走与解析失败相同的 Err 通道（main 侧按 CONFIG_LOAD 退出，
    // 错误内容不回显，不向调用方泄露配置细节）。
    if cfg.udp_flag_rust == cfg.udp_flag {
        return Err(
            "udp_flag and udp_flag_rust must differ: same value would starve the legacy protocol"
                .to_string(),
        );
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_config_file_case_insensitive() {
        let cfg = load_config("cns.json.example").expect("load cns.json.example");
        assert_eq!(cfg.proxy_key, "Host");
        assert_eq!(cfg.tcp_timeout, 600);
        assert_eq!(cfg.udp_timeout, 30);
        assert_eq!(cfg.encrypt_password, "password");
        assert!(cfg.enable_dns_tcp_over_udp);
        assert!(cfg.enable_http_dns);
        assert!(!cfg.enable_tfo);
        assert_eq!(
            cfg.listen_addr,
            vec![":2222".to_string(), ":12224".to_string()]
        );
        assert_eq!(
            cfg.tls.listen_addr,
            vec![
                "127.0.0.1:8978".to_string(),
                "[::1]:1224".to_string(),
                ":9635".to_string()
            ]
        );
        assert_eq!(
            cfg.tls.auto_cert_hosts,
            vec![
                "m.baidu.com".to_string(),
                "yaohuo.me".to_string(),
                "mymy.ip".to_string()
            ]
        );
        assert_eq!(cfg.tls.cert_file, "cert.pem");
        assert_eq!(cfg.tls.key_file, "key.pem");
    }

    #[test]
    fn load_config_rejects_identical_udp_flags() {
        // 同值配置必须在加载期被拒：否则 http_tunnel 先匹配 rust flag，
        // 旧协议分支不可达（编译期发现不了，只能在这里拦）。
        let path = std::env::temp_dir().join(format!(
            "cns_cfg_same_flag_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"udp_flag": "same", "udp_flag_rust": "same"}"#)
            .expect("write temp config");
        let err = load_config(path.to_str().expect("utf-8 temp path"))
            .expect_err("identical udp flags must be rejected");
        assert!(
            err.contains("must differ"),
            "error should explain the same-value rule, got: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_config_accepts_distinct_udp_flags() {
        // 对照组：异值（默认对）必须照常通过，防止误伤合法配置。
        let path = std::env::temp_dir().join(format!(
            "cns_cfg_distinct_flag_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"udp_flag": "httpUDP", "udp_flag_rust": "cnsrUDP"}"#)
            .expect("write temp config");
        let cfg = load_config(path.to_str().expect("utf-8 temp path"))
            .expect("distinct udp flags must load");
        assert_eq!(cfg.udp_flag, "httpUDP");
        assert_eq!(cfg.udp_flag_rust, "cnsrUDP");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn defaults_match_go() {
        let cfg = JsonConfig::default();
        assert_eq!(cfg.proxy_key, "Host");
        assert_eq!(cfg.udp_flag, "httpUDP");
        assert_eq!(cfg.tcp_timeout, 600);
        assert_eq!(cfg.udp_timeout, 30);
        assert!(cfg.enable_http_dns);
        assert!(!cfg.enable_dns_tcp_over_udp);
        assert!(!cfg.enable_tfo);
    }

    #[test]
    fn empty_config_falls_back_to_defaults() {
        // 空对象：解析循环零迭代 ⇒ 全字段保持 Go 对齐默认值。兜底由各助手
        // 在缺键时跳过赋值实现，并非 serde(default) 派生。
        let path = std::env::temp_dir().join(format!(
            "cns_cfg_empty_obj_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{}"#).expect("write temp config");
        let cfg = load_config(path.to_str().expect("utf-8 temp path"))
            .expect("empty object must load with defaults");
        assert_eq!(cfg.proxy_key, "Host");
        assert_eq!(cfg.udp_flag, "httpUDP");
        assert_eq!(cfg.udp_flag_rust, "cnsrUDP");
        assert_eq!(cfg.tcp_timeout, 600);
        assert_eq!(cfg.udp_timeout, 30);
        assert!(cfg.enable_http_dns);
        assert!(!cfg.enable_dns_tcp_over_udp);
        assert!(!cfg.enable_tfo);
        assert!(cfg.listen_addr.is_empty());
        assert!(cfg.tls.listen_addr.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_types_fall_back_to_zero_values_except_timeout() {
        // 错型回退：手写兜底助手的 unwrap_or 链（as_str→""、as_bool→false、
        // str_array→[]）回退到类型零值而非 Go 对齐默认值；错型不得让 load
        // 失败、更不得 panic。例外是 timeout 字段——经 as_timeout 消毒回默认
        // 值（600）而非 0。
        let path = std::env::temp_dir().join(format!(
            "cns_cfg_wrong_types_{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            r#"{"tcp_timeout":"not-a-number","listen_addr":"x","enable_tfo":1}"#,
        )
        .expect("write temp config");
        let cfg = load_config(path.to_str().expect("utf-8 temp path"))
            .expect("wrong-typed fields must not fail the load");
        assert_eq!(cfg.tcp_timeout, 600, "timeout 错型必须回默认而非 0");
        assert!(cfg.listen_addr.is_empty());
        assert!(!cfg.enable_tfo);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn timeout_zero_or_negative_falls_back_to_default() {
        // timeout=0（及负值）若穿透到消费点的 `timeout(Duration::from_secs(0),
        // fut)` 会立即 Elapsed——TCP 首包读秒断、UDP 同理，全服务「活着但啥也
        // 干不了」。加载期必须消毒成默认值，且 load 不失败。
        let path = std::env::temp_dir().join(format!(
            "cns_cfg_timeout_zero_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"tcp_timeout":0,"udp_timeout":-5}"#)
            .expect("write temp config");
        let cfg = load_config(path.to_str().expect("utf-8 temp path"))
            .expect("zero/negative timeout must not fail the load");
        assert_eq!(cfg.tcp_timeout, 600, "tcp_timeout=0 必须回默认 600");
        assert_eq!(cfg.udp_timeout, 30, "udp_timeout=-5（错型折 0）必须回默认 30");
        // 防御读取器双保险：即使值被绕过 load 直接构造也拿不到 0。
        assert_eq!(cfg.tcp_timeout_duration(), std::time::Duration::from_secs(600));
        assert_eq!(cfg.udp_timeout_duration(), std::time::Duration::from_secs(30));
        let _ = std::fs::remove_file(&path);
    }
}
