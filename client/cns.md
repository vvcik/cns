CNS

伪装成 HTTP 请求的隧道协议：目标地址写在自定义头里发给服务端。cns 与 cns-rust 两种名字共用全部配置，TCP 行为一致。它的键名风格和其它协议不同：地址键就叫 cns，不叫 cnsAddr。

最简（明文 + XOR 加密）

  {
    "cns": "203.0.113.60:443",
    "cnsKey": "Proxy_key",
    "cnshost": "www.example.com",
    "cnsEnc": "my-xor-pass",
    "cnsPath": "/api",
    "cnsUdpFlag": "proxy-udp"
  }

完整（TLS 伪装）

  {
    "cns": "203.0.113.60:443",
    "cnsKey": "Proxy_key",
    "cnshost": "tls:www.example.com",
    "cnsPath": "/api",
    "cnsUdpFlag": "proxy-udp",
    "cnsHeaders": ["X-Env: prod"]
  }

逐键说明

  cns          值的样子："203.0.113.60:443"
             服务器地址，写成 host:port（地址和端口在同一个引号里，用冒号隔开）。必填

  cnsKey       值的样子："Proxy_key"
             口令，同时是目标地址所在的自定义头名。必填

  cnshost      值的样子："www.example.com"
             或 "tls:www.example.com"（tls: 前缀=启用 TLS，去掉前缀后作 SNI/Host）
             伪装域名。不填则用 cns 里的 host

  cnsEnc       值的样子："my-xor-pass"
             XOR 流加密口令。不填=明文；两端必须一致

  cnsPath      值的样子："/api"
             伪装请求路径。UDP 隧道必须配置

  cnsUdpFlag   值的样子："proxy-udp"
             UDP 分流标志。UDP 隧道必须配置

  cnsHeaders   值的样子：[ "X-Env: prod" ]
             追加的请求头，中括号列表，每项是完整头行 "名: 值"。只对 UDP 隧道生效

容易踩的坑

  键名是全小写 cnshost，写成 cnsHost 不生效
  用 UDP 隧道时 cnsPath 和 cnsUdpFlag 必须配置，否则建不起来
  cnsEnc 两端不一致时服务端会收到明文目标
  响应状态码不是 200/101 判失败：服务端不认 cnsKey，或前置 CDN/反代回了 40x/30x
  cnsHeaders 项缺少冒号或头名会被跳过并打日志，不是报错
