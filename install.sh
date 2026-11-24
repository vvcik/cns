#!/usr/bin/env bash
# cns 一键安装脚本已迁移到 vvcik/sh 仓库，本文件仅作跳转，老命令继续可用。
set -euo pipefail
exec bash <(curl -fsSL https://raw.githubusercontent.com/vvcik/sh/main/cns-install.sh) "$@"
