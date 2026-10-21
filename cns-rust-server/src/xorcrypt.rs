use crate::config::XOR_PASSWORD;
use base64::Engine;

/// 与 Go 版本 `CuteBi_XorCrypt` 一致的流式异或加密。
///
/// 每加密一个字节，密码下标向前走一位，走满密码长度后回绕。
/// 特别的 `data[b] ^= password[ps] | byte(ps)` 设计保证了
/// 密码 `"12"` 与 `"1212"` 的结果不同。
///
/// 返回处理完后的密码下标，供流式加密下一段数据时续用。
pub fn xor_crypt(data: &mut [u8], password_sub: usize) -> usize {
    match XOR_PASSWORD.get() {
        Some(p) if !p.is_empty() => xor_crypt_with(data, p, password_sub),
        _ => password_sub,
    }
}

/// XOR 加解密核心实现，密码显式传入（便于测试）。
pub fn xor_crypt_with(data: &mut [u8], password: &[u8], password_sub: usize) -> usize {
    if password.is_empty() {
        return password_sub;
    }
    let plen = password.len();
    let mut ps = password_sub;
    for b in data.iter_mut() {
        *b ^= password[ps] | (ps as u8);
        ps += 1;
        if ps == plen {
            ps = 0;
        }
    }
    ps
}

/// 是否启用了 XOR 加密（配置了非空密码）。
pub fn encrypt_enabled() -> bool {
    XOR_PASSWORD.get().map(|p| !p.is_empty()).unwrap_or(false)
}

/// 与 Go 版本 `CuteBi_decrypt_host` 一致：
/// Base64 解码后做 XOR 解密，末字节必须为 0，去掉后即为明文 host。
pub fn decrypt_host(host: &[u8]) -> Result<Vec<u8>, String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut dec = engine
        .decode(host)
        .map_err(|e| format!("base64 decode: {e}"))?;
    if dec.is_empty() {
        return Err("Decrypt failed.".into());
    }
    xor_crypt(&mut dec, 0);
    // 校验尾字节为 0（加密端在明文后补 \0）。用模式匹配而非 unwrap：上面的
    // is_empty 守卫虽已保证非空，这里把「不可能分支」也归入 Err 路径，
    // 不在统计上不可达的分支留 unwrap 面。
    match dec.last() {
        Some(&0) => {}
        _ => return Err("Decrypt failed.".into()),
    }
    dec.pop();
    Ok(dec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_vector_matches_go() {
        let pwd = b"666";
        // 与 Go 版 CuteBi_XorCrypt 输出一致的向量
        let mut d = b"hello".to_vec();
        let sub = xor_crypt_with(&mut d, pwd, 0);
        assert_eq!(d, vec![94, 82, 90, 90, 88]);
        assert_eq!(sub, 2);
    }

    #[test]
    fn xor_stream_segments_match_full() {
        let pwd = b"666";
        let plain = b"CuteBi Network Tunnel".to_vec();
        let mut full = plain.clone();
        xor_crypt_with(&mut full, pwd, 0);

        let mut d2 = b"CuteBi ".to_vec();
        let mut d3 = b"Network ".to_vec();
        let mut d4 = b"Tunnel".to_vec();
        let s = xor_crypt_with(&mut d2, pwd, 0);
        let s = xor_crypt_with(&mut d3, pwd, s);
        let _ = xor_crypt_with(&mut d4, pwd, s);
        let mut seg = d2;
        seg.extend_from_slice(&d3);
        seg.extend_from_slice(&d4);
        assert_eq!(seg, full);
    }

    #[test]
    fn xor_roundtrip() {
        let pwd = b"password";
        let mut data = b"some random payload bytes".to_vec();
        let orig = data.clone();
        xor_crypt_with(&mut data, pwd, 0);
        xor_crypt_with(&mut data, pwd, 0);
        assert_eq!(data, orig);
    }

    #[test]
    fn decrypt_host_vector_matches_go() {
        let _guard = crate::config::global_lock();
        // 由 Go 生成：host "example.com:80"，密码 "666"
        let _ = XOR_PASSWORD.set(b"666".to_vec());
        let b64 = b"U09XW0daUxlVWVoMDgc2";
        let host = decrypt_host(b64).unwrap();
        assert_eq!(host, b"example.com:80");
    }

    #[test]
    fn decrypt_host_bad_checksum() {
        let _guard = crate::config::global_lock();
        // 解密后末字节非 0，应报错
        let _ = XOR_PASSWORD.set(b"666".to_vec());
        let bad = base64::engine::general_purpose::STANDARD.encode(b"hello");
        assert!(decrypt_host(bad.as_bytes()).is_err());
    }
}
