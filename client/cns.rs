use std::io;

use nwproxy_common::config::Config;
use nwproxy_common::stream::{shutdown_quiet, BoxStream};
use tokio::io::{AsyncWriteExt, BufReader};

use super::conn::{cns_encrypt_host, dial_cns_conn, XorStream};
use super::http_line::{read_line, HANDSHAKE_BUF};

pub fn cns_decoy_host(cfg: &Config) -> &str {
    let host = cfg.cns_host.strip_prefix("tls:").unwrap_or(&cfg.cns_host);
    if !host.is_empty() {
        host
    } else {
        &cfg.cns_server
    }
}

pub fn cns_enabled(cfg: &Config) -> bool {
    cfg.cns_tcp() && !cfg.cns_key.is_empty() && !cfg.cns_server_addr().is_empty()
}

pub fn cns_tls_enabled(cfg: &Config) -> bool {
    cfg.cns_host.starts_with("tls:")
}

pub fn cns_decoy_path(cfg: &Config) -> &str {
    cfg.cns_path.trim()
}

pub fn cns_server_addr(cfg: &Config) -> String {
    cfg.cns_server_addr()
}

pub fn build_cns_request(cfg: &Config, host: &str, port: &str) -> Vec<u8> {
    let decoy = cns_decoy_host(cfg);
    let path = cns_decoy_path(cfg);
    let target = if port.is_empty() {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };
    let target = if let Some(ref pw) = cfg.cns_encrypt {
        cns_encrypt_host(pw, &target)
    } else {
        target
    };

    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(b"GET ");
    b.extend_from_slice(path.as_bytes());
    b.extend_from_slice(b" HTTP/1.1\r\n");
    b.extend_from_slice(cfg.cns_key.as_bytes());
    b.extend_from_slice(b": ");
    b.extend_from_slice(target.as_bytes());
    b.extend_from_slice(b"\r\nHost: ");
    b.extend_from_slice(decoy.as_bytes());
    b.extend_from_slice(b"\r\n\r\n");
    b
}

pub async fn cns_connect(cfg: &Config) -> io::Result<BoxStream> {
    let addr = cns_server_addr(cfg);
    dial_cns_conn(cfg, &addr)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("dial cns-rust-server {}: {}", addr, e)))
}

pub async fn cns_handshake(
    cfg: &Config,
    conn: BoxStream,
    dst_host: &str,
    dst_port: &str,
) -> io::Result<BoxStream> {
    let req = build_cns_request(cfg, dst_host, dst_port);
    let conn = cns_exchange(conn, &req).await?;
    Ok(cns_wrap_encrypt(conn, cfg.cns_encrypt.as_ref()))
}

async fn cns_exchange(conn: BoxStream, req: &[u8]) -> io::Result<BufReader<BoxStream>> {
    let mut conn = conn;
    cns_write_request(&mut conn, req).await?;
    let mut conn = BufReader::with_capacity(HANDSHAKE_BUF, conn);
    cns_read_response(&mut conn).await?;
    Ok(conn)
}

async fn cns_read_response(conn: &mut BufReader<BoxStream>) -> io::Result<()> {
    cns_read_status_line(conn).await?;
    cns_drain_headers(conn).await
}

async fn cns_write_request(conn: &mut BoxStream, req: &[u8]) -> io::Result<()> {
    if let Err(e) = conn.write_all(req).await {
        shutdown_quiet(conn).await;
        return Err(io::Error::new(
            e.kind(),
            format!("write CNS request: {}", e),
        ));
    }
    Ok(())
}

fn cns_wrap_encrypt(conn: BufReader<BoxStream>, pw: Option<&Vec<u8>>) -> BoxStream {
    match pw {
        Some(pw) => Box::new(XorStream::new(conn, pw)),
        None => Box::new(conn),
    }
}

async fn cns_read_status_line(conn: &mut BufReader<BoxStream>) -> io::Result<()> {
    let line = match read_line(conn).await {
        Ok(l) => l,
        Err(e) => {
            shutdown_quiet(conn).await;
            return Err(io::Error::new(e.kind(), format!("read response: {}", e)));
        }
    };
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
    if parts.len() < 2 {
        shutdown_quiet(conn).await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad response line {:?}", trimmed),
        ));
    }
    if parts[1] != "200" && parts[1] != "101" {
        let mut drain = [0u8; 512];
        let _ = tokio::io::AsyncReadExt::read(conn, &mut drain).await;
        shutdown_quiet(conn).await;
        return Err(io::Error::other(format!("cns-rust-server {}", trimmed)));
    }
    Ok(())
}

async fn cns_drain_headers(conn: &mut BufReader<BoxStream>) -> io::Result<()> {
    loop {
        let h = match read_line(conn).await {
            Ok(h) => h,
            Err(e) => {
                shutdown_quiet(conn).await;
                return Err(io::Error::new(
                    e.kind(),
                    format!("read response header: {}", e),
                ));
            }
        };
        if h == "\r\n" || h == "\n" {
            return Ok(());
        }
    }
}

pub async fn dial_cns_server(
    cfg: &Config,
    dst_host: &str,
    dst_port: &str,
) -> io::Result<BoxStream> {
    let conn = cns_connect(cfg).await?;
    cns_handshake(cfg, conn, dst_host, dst_port).await
}
