CNS-RUST 服务端（CuteBi Network Server, Rust 重写）

基于 Rust（异步 tokio）重写的网络代理服务端，保持与 Go 原版（v0.4.3）协议级兼容，
支持 IPv6、TCP FastOpen、UDP over HTTP 隧道；需配合专用客户端（如 CLNC、nwproxy
客户端）可实现 TCP/UDP 全局代理。

本文只讲服务端（crate 说明）。客户端侧的配置键（cns / cnsKey / cnshost / cnsEnc /
cnsPath / cnsHeaders / cnsUdpFlag）与请求格式、协议线规（帧格式 / 握手 / 加密 /
探活 / 常量契约），见上层交付包里的 cns-rust-说明.txt。


实际功能（按代码实现）

  1  HTTP CONNECT / 隧道代理
     监听 listen_addr 上的 TCP 连接，识别 HTTP 请求头（CONNECT、GET、POST 等）。
     从请求头中按 proxy_key（默认 Host）取目标 host，建立到目标地址的 TCP 连接，
     双向转发数据。半关闭语义：任一方向终结（EOF/错误）只终结该方向——向对端传播
     FIN 后另一方向继续排空，双向都终结才会话结束。支持可选 XOR 流式加密
     （encrypt_password）；若开启，Host 为 Base64 + XOR 加密后放在请求头中。

  2  HTTP DNS 服务端
     请求 uri 参数中带 dn=域名 时走 HTTP DNS 逻辑：对本机做域名解析，返回 IP。
     参数支持 type=AAAA 返回 IPv6，ttl=1 在响应中带 TTL。本机解析、HTTP 响应。

  3  TCP DNS 转 UDP DNS
     当目标 host 为 *:53 时，将客户端发来的 TCP DNS（2 字节长度 + 载荷）转为对同一
     host 的 UDP DNS 请求，收到 UDP 应答后再按 TCP 长度前缀写回客户端。由配置项
     enable_dns_tcpoverudp 控制，可解决部分 DNS 服务器不支持 TCP DNS 的问题。

  4  UDP over HTTP 隧道（httpUDP / cnsrUDP）
     请求头中包含 udp_flag（默认 httpUDP，旧协议）或 udp_flag_rust（默认 cnsrUDP，
     cns-rust 新线规，与 nwproxy 客户端 udpout: cns-rust 配套）时，该连接被当作
     UDP 会话处理。协议格式：2 字节包长度 + 协议头（IPv4 约 12 字节 / IPv6 约 24
     字节）+ UDP 载荷；服务端解析后对目标 IP:Port 做 UDP 收发，再按同格式回写客户端。
     支持 IPv4 / IPv6；可选 XOR 加密（与 TCP 隧道共用 encrypt_password）。
     服务端先匹配 udp_flag_rust，未命中再按 udp_flag 走旧协议；两者不得取同值。

  5  TLS 与 TCP FastOpen
     TLS：配置 tls.listen_addr，在这些地址上先做 TLS 服务端握手，再按上述同一套隧道
     逻辑处理（HTTP DNS / CONNECT / UDP 隧道）。证书支持 cert_file/key_file 手动指定
     或 autocerthosts 按 host 自动生成 ECDSA P256 证书。
     TCP FastOpen：由 enable_tfo 控制，仅在非 Windows 且进程有效 UID 为 0 时生效。


命令行参数

  -h / -help           显示帮助（--h / --help 等价）后退出
  -version             显示版本号（--version 等价）后退出
  -json <路径>         JSON 配置文件路径（-json=cns.json 或 -json cns.json），必填
  -daemon              -daemon=true（或 =1）开启守护进程；非法布尔值（如 -daemon=maybe）
                       按参数错误处理（exit 2，对齐 Go flag）


配置文件说明（JSON，键名大小写不敏感，未知键忽略，未列键走默认值）

  listen_addr            string[]   明文监听地址；IP:port 绑指定地址，:port 为 Go 风格通配（优先 [::]:port 双栈，v6 不可用时回退 0.0.0.0:port）；裸域名/空串被拒绝（exit 7）
  tcp_timeout / udp_timeout  数值   TCP、UDP 超时（秒）；0/负/错型消毒回默认
  proxy_key             string     从请求头取目标地址的 key，默认 Host
  udp_flag              string     HTTP 请求头中标识 httpUDP 的字符串，默认 httpUDP
  udp_flag_rust         string     cns-rust 新线规 UDP 的握手标志，默认 cnsrUDP；服务端先匹配本值、未命中再按 udp_flag；两者不得取同值（同值 exit 4）
  encrypt_password      string     XOR 加密密码，空则不加密
  enable_dns_tcpoverudp bool       是否开启 TCP DNS 转 UDP DNS
  enable_httpdns        bool       是否开启 HTTP DNS（默认 true）
  enable_tfo            bool       是否开启 TCP FastOpen（仅 Linux + root 生效）
  pid_path              string     可选，写入 PID 的文件路径
  tls.listen_addr       string[]   TLS 监听地址（通配形式同 listen_addr）
  tls.autocerthosts     string[]   按 host 数组生成自签 TLS 证书
  tls.cert_file         string     本地 TLS 证书文件路径
  tls.key_file          string     本地 TLS 密钥文件路径（与 cert_file 必须共存）

  完整示例见 cns.json.example。


退出码判障表（服务端默认零日志，码值即判障通道）

  0   正常退出 / -daemon 拉起成功（仅拉起成功，非就绪保证）
  1   supervisor 收到信号停机（与 nwproxy「1=通用致命」撞码，各自独立不引申）
  2   ARGS          参数解析失败
  3   NO_CONFIG     未给 -json
  4   CONFIG_LOAD   配置装载失败（timeout 0/负/错型会消毒回默认，不会走到这）
  5   SPAWN_CHILD   子进程 spawn 失败
  6   TLS_CERT      证书生成/加载失败（fail-closed）
  7   LISTEN        任一监听地址 bind 失败（fail-closed，任一失败即退）
  8   RUNTIME       tokio runtime 创建失败

  -daemon=true 的父进程退出码 0 仅代表「后台进程拉起成功」，不代表服务已就绪：
  坏配置（4）/证书（6）/监听（7）都发生在父进程退出之后，判障以 supervisor 进程的
  退出码为准。supervisor 连续 5 次 2 秒内快死则放弃重启。


编译与运行

  前置：Rust 工具链（rustc / cargo）。未声明 MSRV——依赖图（tokio 1 / rustls 0.23 /
  rcgen 0.14）经有网 cargo build 按 lock 实际解析为准。

    cargo build --release          # 产物 target/release/cns
    ./target/release/cns -daemon=true -json=cns.json
    cargo test                     # 单元测试含 Go 原版 XOR 加密向量

  依赖与锁文件：本目录是根 workspace 成员，依赖版本由根 [workspace.dependencies]
  统一给出（本 manifest 只用 { workspace = true } 声明消费）。锁文件即根 Cargo.lock，
  全仓一份，cargo build --offline 可用。

  crypto 后端取 ring：rustls 默认后端 aws-lc-rs 要 cmake 编 C 库，在 Android NDK 下
  代价大，故与主栈口径一致。

  -daemon 语义见上「退出码判障表」备注。


项目结构（与源码对应）

  src/main.rs        入口、命令行解析、JSON 配置加载、守护进程与崩溃自动重启、TLS/HTTP 隧道启动
  src/config.rs      JsonConfig/TlsConfig 大小写不敏感载入、全局 CONFIG 与 XOR 密码、测试锁
  src/http_tunnel.rs TCP 监听、首包判断 HTTP/非 HTTP、回复隧道头、分流到 HTTP DNS / TCP 会话 / UDP 会话、普通端口被动 TLS 升级
  src/tcp.rs         从请求头取 host、TCP 转发、:53 时转 dns_tcpOverUdp
  src/udp.rs         httpUDP 旧协议解析（纯函数）、UDP 收发、IPv4/IPv6 头与 XOR 加解密
  src/udp_rust.rs    cns-rust 新线规 UDP 承载（与 nwproxy 客户端配套）：帧解析/编码、SockMap 复用、回向汇聚
  src/dns.rs         HTTP DNS 响应（dn=）、TCP DNS 转 UDP DNS（dns_tcpOverUdp）
  src/tls_side.rs    TLS 监听、证书加载/自动生成（rcgen 自签）、先握手再进隧道逻辑
  src/xorcrypt.rs    XOR 流式加解密（与 Go 版逐字节兼容）、Host 的 Base64+XOR 解密，含向量测试
  src/sys.rs         setrlimit（失败降级 + 事件日志）、setsid、TFO（TCP_FASTOPEN）、信号处理
  src/util.rs        纯函数小工具（子串查找等）
  src/log.rs         事件日志门面：svc_log!/svc_count!（默认零输出，特性开启时可读；限频防刷屏）


Linux 一键（Go 原版，与本 Rust 重写无关）

  以下脚本安装的是 Go 原版 cns 二进制（binary.parso.org），与本 Rust 重写版无关；
  Rust 版请用上方 cargo build 自行编译。

    安装: curl -O http://binary.parso.org/cns/cns.sh && sh cns.sh
    卸载: curl -O http://binary.parso.org/cns/cns.sh && sh cns.sh uninstall
