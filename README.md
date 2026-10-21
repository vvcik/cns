# cns

cns（CuteBi Network Server）服务端的 Rust 重写版（v0.4.3，tokio 异步 + rustls/ring），
与 Go 原版 cns 协议级兼容：目标地址写在自定义 HTTP 头里发给服务端，伪装成普通 HTTP 请求。

- 支持 IPv4 / IPv6 双栈（`:port` 为 Go 风格通配，优先 `[::]`，v6 不可用回退 `0.0.0.0`）
- HTTP CONNECT / 隧道代理、UDP over HTTP 隧道（旧线规 `httpUDP` + 新线规 `cnsrUDP`）
- HTTP DNS（`?dn=域名`）、TCP DNS 转 UDP DNS
- TLS 监听（手动证书或按 host 自动生成自签证书）、TCP FastOpen、WebSocket 升级
- 可选 XOR 流式加密（与 Go 版逐字节兼容）
- 默认零日志，退出码即判障通道；`-daemon=true` 守护进程 + 崩溃自动重启

详细说明见 [cns-rust-说明.txt](cns-rust-说明.txt)，服务端 crate 说明见
[cns-rust-server/README.md](cns-rust-server/README.md)，客户端对接见 [client/](client/)。

## 一键安装（x86-64 Linux）

下载管理脚本后按菜单操作（安装 / 卸载 / 启动 / 停止 / 重启 / 改配置 / 查状态）：

```bash
curl -kLO https://raw.githubusercontent.com/vvcik/cns/main/install.sh && sudo bash install.sh
```

运行一次脚本即会在 `/usr/local/bin` 装好 `cns` 命令：即使不安装服务端，
之后 root 下直接敲 `cns` 也能打开管理菜单。

```
==============================
cns 管理脚本 [v1.1.0]
==============================
  0. 更新脚本
——————————————————————————————
  1. 安装 cns
  2. 卸载 cns
——————————————————————————————
  3. 启动 cns
  4. 停止 cns
  5. 重启 cns
——————————————————————————————
  6. 设置 配置信息
  7. 查看 配置信息
  8. 查看 运行状态
——————————————————————————————
 00. 退出脚本
==============================
```

选 `1` 安装时可自定义：监听端口（默认 80）、加密口令（留空为明文模式）、
是否启用 HTTP DNS。已安装后选 `6` 可随时改配置并自动重启生效。

选 `2` 进入卸载子菜单：`1` 卸载服务端（自动删除 `/opt/cns`，保留 `cns` 命令）、
`2` 完全卸载恢复最初状态。

安装完成后 root 下可直接运行 `cns` 打开管理菜单，无需再找脚本文件。

卸载：在菜单选 `2`，或 `sudo bash install.sh uninstall`。

> 一键脚本从 GitHub Releases 下载预编译二进制（`cns-linux-amd64`）。
> 请先在仓库创建一个 `v0.4.3` 的 Release，并把 `cns-linux-amd64` 作为附件上传，
> 否则脚本会因下载失败而退出并提示。

安装完成后：

- 配置文件：`/opt/cns/cns.json`（安装选项另存于 `/opt/cns/cns.conf`）
- 二进制：`/opt/cns/cns-linux-amd64`
- 管理命令：`cns`（root 下直接运行）
- systemd 服务：`cns`（`systemctl status cns` 查看）
- 验证：`curl -s "http://127.0.0.1:80/?dn=example.com"`

## 手动安装

```bash
# 1) 写最小配置
cat > cns.json <<'EOF'
{
  "listen_addr": [":80"],
  "enable_httpdns": true
}
EOF

# 2) 后台启动
./cns-linux-amd64 -daemon=true -json=cns.json

# 3) 验证
./cns-linux-amd64 -version   # cns version 0.4.3
ss -tlnp | grep 80
```

## 配置速览

完整键表见 `cns-rust-说明.txt`，常用项：

| 键 | 默认值 | 说明 |
|---|---|---|
| `listen_addr` | `[]` | 明文监听地址，如 `[":80"]` |
| `proxy_key` | `Host` | 从请求头取目标 host 的头键 |
| `encrypt_password` | 空 | XOR 流加密口令，两端须一致 |
| `udp_flag` | `httpUDP` | 旧协议 UDP 握手标志 |
| `udp_flag_rust` | `cnsrUDP` | 新线规 UDP 标志（配 nwproxy `udpout: cns-rust`） |
| `enable_httpdns` | `true` | HTTP DNS |
| `enable_dns_tcpoverudp` | `false` | 目标 `*:53` 时 TCP DNS 转 UDP |
| `enable_tfo` | `false` | TCP FastOpen（需 root） |
| `tls.listen_addr` | `[]` | TLS 监听地址 |

## 客户端

- nwproxy 客户端键：`cns / cnsKey / cnshost / cnsEnc / cnsPath / cnsHeaders / cnsUdpFlag`
  （地址键就叫 `cns`，键名全小写）
- UDP 隧道必须配置 `cnsPath` 和 `cnsUdpFlag`；`cnsEnc` 两端须一致
- 新线规：客户端 `udpout: cns-rust` ↔ 服务端 `udp_flag_rust`
- 客户端参考实现见 [client/](client/)（`cns.rs` / `udp_cnsr.rs`）

## 从源码构建

```bash
cargo build --release -p cns        # 产物 target/release/cns
cargo test -p cns                   # 56 个用例，含 Go 原版 XOR 加密向量
```

## 目录结构

```
├── install.sh                 一键安装脚本
├── cns-rust-说明.txt          完整说明文档（配置 / 退出码 / 运维）
├── cns-rust-server/           服务端源码（Rust）
│   ├── Cargo.toml
│   ├── cns.json.example
│   ├── README.md
│   └── src/
└── client/                    客户端参考（cns.md / cns.rs / udp_cnsr.rs）
```

> 预编译二进制 `cns-linux-amd64`（ELF x86-64，glibc 动态链接）请从
> [Releases](https://github.com/vvcik/cns/releases) 下载，
> 未随仓库提交。
