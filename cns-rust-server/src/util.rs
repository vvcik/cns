//! cns-rust-server 内部小工具：跨模块复用、无状态依赖的纯函数。
//!
//! 此前 `find_subslice` 在 tcp.rs 与 dns.rs 各持一份逐字节相同的私有拷贝，
//! 收编至此。

/// 子串定位。空 `needle` 返回 `Some(0)`（调用方以 `pos + needle.len()` 推进，
/// 语义上把「空 key」当作命中在 0 位）；`haystack` 短于 `needle` 返回
/// `None`。与 Go 版 `bytes.Index` 行为对齐。
pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
