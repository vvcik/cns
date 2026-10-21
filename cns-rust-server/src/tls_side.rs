use crate::config::TlsConfig;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::sync::Arc;
use time::OffsetDateTime;

/// 按 SNI 从多份证书中选一份，找不到时回退到默认证书。
#[derive(Debug)]
struct CertResolver {
    certs: Vec<(Option<String>, Arc<CertifiedKey>)>,
    default: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // 判定本体在 `resolve_sni`：`ClientHello` 无公开构造器，单测无法构造
        // trait 调用面，故以 `server_name()` 的产物 `Option<&str>` 为参数拆出
        // 可测函数（语义一字不改）。
        self.resolve_sni(client_hello.server_name())
    }
}

impl CertResolver {
    /// SNI 查找的纯逻辑：精确匹配命中即用对应证书——`sni` 为 `None` 时可与
    /// 存成 `None` 的默认项（CertFile 分支）配对；未命中/无匹配项回退
    /// `default`（可能是 `None`，rustls 对 None 的处置即「无证书可提供」）。
    fn resolve_sni(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        for (host, key) in &self.certs {
            if host.as_deref() == sni {
                return Some(key.clone());
            }
        }
        self.default.clone()
    }
}

/// 生成一张有效期 365 天的 ECDSA P256 自签证书，返回 (证书DER, 私钥DER)。
///
/// 失败返回 `None` 而不 panic：本函数跑在启动路径上，调用方（`main`）对
/// `None` 以 `exit_code::TLS_CERT` 退出——panic 叠加 supervisor 自动重启会
/// 变成「证书配错 → 无限崩溃循环」。
///
/// 空 host 走 `CertificateParams::default()`（不带 SAN 的证书，等价 Go 原版，
/// 任何 SNI 都命中默认证书）。不能 `CertificateParams::new(vec![""])`：
/// rcgen 0.13+ 对空 DNS 名返回 `Err`。
fn create_certificate(host: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let key_pair = KeyPair::generate().ok()?;
    let mut params = if host.is_empty() {
        CertificateParams::default()
    } else {
        CertificateParams::new(vec![host.to_string()]).ok()?
    };
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(365);
    params.distinguished_name = DistinguishedName::new();
    let cert = params.self_signed(&key_pair).ok()?;
    Some((cert.der().to_vec(), key_pair.serialize_der()))
}

/// 构建 rustls 的 ServerConfig。
///
/// 优先使用 CertFile/KeyFile；否则按 AutoCertHosts 为每个 host 自动生成
/// ECDSA P256 自签证书（AutoCertHosts 为空时生成一张不含 SAN 的证书，
/// 等价于 Go 原版的空 host 证书，任何 SNI 都会命中默认证书）。
pub fn make_certificate_config(tls: &TlsConfig) -> Option<Arc<ServerConfig>> {
    let provider = CryptoProvider::get_default()
        .map(|p| (**p).clone())
        .unwrap_or_else(rustls::crypto::ring::default_provider);
    let _ = CryptoProvider::install_default(provider.clone());

    let mut certs: Vec<(Option<String>, Arc<CertifiedKey>)> = Vec::new();
    if !tls.cert_file.is_empty() && !tls.key_file.is_empty() {
        let cert_pem = std::fs::read(&tls.cert_file).ok()?;
        let mut cert_reader = &cert_pem[..];
        let certs_der: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(Result::ok)
            .collect();
        if certs_der.is_empty() {
            return None;
        }
        let key_pem = std::fs::read(&tls.key_file).ok()?;
        let mut key_reader = &key_pem[..];
        let key_der: PrivateKeyDer<'static> = match rustls_pemfile::private_key(&mut key_reader) {
            Ok(Some(k)) => k,
            _ => return None,
        };
        let signing_key = provider.key_provider.load_private_key(key_der).ok()?;
        certs.push((None, Arc::new(CertifiedKey::new(certs_der, signing_key))));
    } else {
        let mut hosts = tls.auto_cert_hosts.clone();
        if hosts.is_empty() {
            hosts.push(String::new());
        }
        for h in hosts {
            let (cert_der, key_der) = create_certificate(&h)?;
            // `PrivateKeyDer::try_from` 是本分支最后的 panic 点：key_der 刚由
            // `serialize_der()` 生成、实践不失败，但一旦 pki-types 拒绝，子进程
            // panic → supervisor 记快死 → 5 次后 exit(1)，丢失「是证书问题」的
            // 判障信息。对齐 CertFile 分支的 `.ok()?` 惯例并入 None 通道，
            // 由 main 统一 exit(6)——两分支错误面同构。
            let key_der = match PrivateKeyDer::try_from(key_der) {
                Ok(k) => k,
                // 不打 `e`：DER 转换错误文本可能含密钥材料类内容。
                Err(_) => {
                    svc_log!("tls: 私钥 DER 转换失败（AutoCert）");
                    return None;
                }
            };
            let signing_key = match provider.key_provider.load_private_key(key_der) {
                Ok(k) => k,
                // 不打 `e`也不打 kind：rustls 的私钥错误可能含文件路径片段。
                Err(_) => {
                    svc_log!("tls: 私钥加载失败");
                    return None;
                }
            };
            let cert_host = if h.is_empty() { None } else { Some(h) };
            certs.push((
                cert_host.clone(),
                Arc::new(CertifiedKey::new(vec![CertificateDer::from(cert_der)], signing_key)),
            ));
        }
    }

    let default = certs.first().map(|(_, k)| k.clone());
    let resolver = CertResolver {
        certs: certs.clone(),
        default,
    };
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    Some(Arc::new(server_config))
}

/// 启动 TLS 监听：先完成 TLS 握手，再交给 handle_tunnel 处理。
pub async fn start_tls(listen_addr: String, tls_config: Arc<ServerConfig>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let config = crate::config::config();
    let enable_tfo = config.enable_tfo;
    // 与 handle_tunnel 的 TLS 升级共用同一超时口径：慢握手的连接不能无限占用
    // 任务（明文路径同样受此约束，两路一致）。
    let tcp_timeout = config.tcp_timeout_duration();
    // 监听建不出来以 LISTEN=7 退出（fail-closed），退出码即判障通道；不打印
    // 错误对象：文本可能带地址。
    let listener =
        crate::http_tunnel::bind_or_exit(&listen_addr, enable_tfo).await;

    crate::http_tunnel::spawn_accept_loop(listener, move |conn| {
        let acceptor = acceptor.clone();
        async move {
            match tokio::time::timeout(tcp_timeout, acceptor.accept(conn)).await {
                Ok(Ok(tls_stream)) => {
                    crate::http_tunnel::handle_tunnel(
                        Box::new(tls_stream),
                        Box::new([0u8; 8192]),
                        None,
                    )
                    .await;
                }
                _ => {
                    svc_log!("tls: 握手失败");
                }
            }
        }
    });
}

/// 本模块可静态测的纯逻辑部分：
///
/// - `resolve_sni` 为纯函数：SNI 精确命中、未命中/无 SNI 回退默认；
/// - 「空 AutoCertHosts 生成无 SAN 证书」用例全内存自签，不写文件、不联网；
/// - 不可测：`start_tls` 的真监听（需绑端口）与轮换循环时序（需注入时钟）。

#[cfg(test)]
mod tests {
    use super::*;

    /// 内存自签一张证书并装进 `CertifiedKey`（无文件、无网络依赖），与
    /// `make_certificate_config` 的 AutoCert 分支同一套机制。`host` 传空串即
    /// 生成不含 SAN 的证书（等价 Go 空 host 证书）。
    fn certified_key_for_host(host: &str) -> Arc<CertifiedKey> {
        let provider = rustls::crypto::ring::default_provider();
        let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
        let params = if host.is_empty() {
            rcgen::CertificateParams::default()
        } else {
            rcgen::CertificateParams::new(vec![host.to_string()]).expect("cert params")
        };
        let cert = params.self_signed(&key_pair).expect("self sign");
        let key_der =
            PrivateKeyDer::try_from(key_pair.serialize_der()).expect("key der convert");
        let signing_key = provider
            .key_provider
            .load_private_key(key_der)
            .expect("load private key");
        Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert.der().to_vec())],
            signing_key,
        ))
    }

    #[test]
    fn resolver_sni_exact_hit() {
        // SNI 精确命中：多域名 resolver 各回各的证书，不得串线。
        let k_a = certified_key_for_host("a.example");
        let k_b = certified_key_for_host("b.example");
        let resolver = CertResolver {
            certs: vec![
                (Some("a.example".into()), Arc::clone(&k_a)),
                (Some("b.example".into()), Arc::clone(&k_b)),
            ],
            default: Some(Arc::clone(&k_a)),
        };
        assert!(
            Arc::ptr_eq(
                &resolver.resolve_sni(Some("b.example")).expect("hit"),
                &k_b
            ),
            "SNI b.example 必须精确命中 b 的证书"
        );
        assert!(
            Arc::ptr_eq(
                &resolver.resolve_sni(Some("a.example")).expect("hit"),
                &k_a
            ),
            "SNI a.example 必须精确命中 a 的证书"
        );
    }

    #[test]
    fn resolver_falls_back_to_default_on_miss_and_no_sni() {
        // 未命中 SNI 与无 SNI 一律回退 default（CertFile 分支的默认项即存
        // 为 None 项参与精确配对，此处验证的是回退通道本身）。
        let k_a = certified_key_for_host("a.example");
        let k_def = certified_key_for_host("");
        let resolver = CertResolver {
            certs: vec![(Some("a.example".into()), Arc::clone(&k_a))],
            default: Some(Arc::clone(&k_def)),
        };
        assert!(
            Arc::ptr_eq(
                &resolver
                    .resolve_sni(Some("unknown.example"))
                    .expect("fallback"),
                &k_def
            ),
            "未命中 SNI 必须回默认证书"
        );
        assert!(
            Arc::ptr_eq(&resolver.resolve_sni(None).expect("fallback"), &k_def),
            "无 SNI 必须回默认证书"
        );
    }

    #[test]
    fn make_certificate_config_empty_auto_cert_hosts_succeeds_in_memory() {
        // 空 AutoCertHosts：AutoCert 分支生成一张不含 SAN 的自签证书
        // （等价 Go 空 host 证书），全内存无文件依赖，覆盖 AutoCert 分支路径。
        let tls = TlsConfig {
            listen_addr: vec![],
            auto_cert_hosts: vec![],
            cert_file: String::new(),
            key_file: String::new(),
        };
        let cfg = make_certificate_config(&tls).expect("empty-hosts autocert must build");
        // Arc<ServerConfig> 是真实构建产物（访问公共字段证非占位）。
        let _ = cfg.max_early_data_size;
    }
}
