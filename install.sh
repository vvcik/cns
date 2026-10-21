#!/usr/bin/env bash
#
# ==============================
# cns 管理脚本 [v1.1.7]
# ==============================
#
# 使用（三种方式）：
#   curl -kLO https://raw.githubusercontent.com/vvcik/cns/main/install.sh && sudo bash install.sh
#   sudo bash <(curl -sL https://raw.githubusercontent.com/vvcik/cns/main/install.sh)
# 安装后 root 可直接运行 cns 打开管理菜单。
#
set -euo pipefail

REPO="vvcik/cns"
TAG="v0.4.3"
BIN_NAME="cns-linux-amd64"
INSTALL_DIR="/opt/cns"
CONF_FILE="${INSTALL_DIR}/cns.conf"
JSON_FILE="${INSTALL_DIR}/cns.json"
SERVICE_NAME="cns"
LEGACY_SERVICE="cns-rust"
CLI_PATH="/usr/local/bin/cns"
SCRIPT_URL="https://raw.githubusercontent.com/${REPO}/main/install.sh"

info() { echo -e "\033[32m[INFO]\033[0m $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m $*"; }
die()  { echo -e "\033[31m[ERROR]\033[0m $*" >&2; exit 1; }

# ---------- 基础判断 ----------
is_installed() { [ -x "${INSTALL_DIR}/${BIN_NAME}" ]; }

is_running() {
  if has_systemd; then
    systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null
  else
    pgrep -f "${INSTALL_DIR}/${BIN_NAME}" >/dev/null 2>&1
  fi
}

has_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

self_path() { readlink -f "$0" 2>/dev/null || echo "$0"; }

load_conf() {
  PORT="80"; ENCRYPT_PASSWORD=""; ENABLE_HTTPDNS="true"
  [ -f "${CONF_FILE}" ] && . "${CONF_FILE}" || true
}

save_conf() {
  mkdir -p "${INSTALL_DIR}"
  # 单引号转义，保证 source 可靠
  local _pw_esc="${ENCRYPT_PASSWORD//\'/\'\\\'\'}"
  cat > "${CONF_FILE}" <<EOF
PORT=${PORT}
ENCRYPT_PASSWORD='${_pw_esc}'
ENABLE_HTTPDNS=${ENABLE_HTTPDNS}
EOF
}

write_json() {
  cat > "${JSON_FILE}" <<EOF
{
  "listen_addr": [":${PORT}"],
  "tcp_timeout": 600,
  "udp_timeout": 30,
  "proxy_key": "Host",
  "encrypt_password": "${ENCRYPT_PASSWORD}",
  "udp_flag": "httpUDP",
  "udp_flag_rust": "cnsrUDP",
  "enable_dns_tcpoverudp": true,
  "enable_httpdns": ${ENABLE_HTTPDNS},
  "enable_tfo": false
}
EOF
}

check_env() {
  [ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo bash install.sh（安装后可直接用 cns 命令）"
  [ "$(uname -m)" = "x86_64" ] || die "仅支持 x86-64，当前架构：$(uname -m)"
  command -v curl >/dev/null 2>&1 || {
    info "正在安装 curl..."
    if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq curl
    elif command -v yum >/dev/null 2>&1; then yum install -y -q curl
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q curl
    elif command -v apk >/dev/null 2>&1; then apk add --no-cache curl
    else die "找不到包管理器，请手动安装 curl 后重试"; fi
  }
}

# 旧版服务名 cns-rust → cns 的一次性迁移
migrate_legacy_service() {
  local legacy="/etc/systemd/system/${LEGACY_SERVICE}.service"
  if [ -f "${legacy}" ]; then
    warn "检测到旧服务名 ${LEGACY_SERVICE}，正在迁移为 ${SERVICE_NAME}..."
    systemctl stop "${LEGACY_SERVICE}" 2>/dev/null || true
    systemctl disable "${LEGACY_SERVICE}" 2>/dev/null || true
    rm -f "${legacy}"
    systemctl daemon-reload 2>/dev/null || true
    info "迁移完成"
  fi
}

# 把管理脚本装为 cns 命令
install_cli() {
  local src; src="$(self_path)"
  # 已通过 cns 命令自身运行：静默返回，避免每次进菜单都重复打印
  [ "${src}" = "${CLI_PATH}" ] && return 0
  if [ -f "${src}" ]; then
    cp -f "${src}" "${CLI_PATH}"
  else
    # 进程替换（bash <(curl ...)）等方式运行时 $0 不是文件，从仓库拉取
    info "从仓库下载管理脚本以安装 cns 命令..."
    curl -fsSL --retry 2 -o "${CLI_PATH}" "${SCRIPT_URL}?t=$(date +%s)" \
      || { warn "cns 命令安装失败，稍后可手动下载安装"; return; }
  fi
  chmod +x "${CLI_PATH}"
  info "已安装 cns 命令：root 下直接运行 cns 即可打开管理菜单"
}

ask_config() {
  echo "---------- 安装配置 ----------"
  read -r -p "监听端口 [${PORT}]: " _port
  _port="${_port:-$PORT}"
  [[ "${_port}" =~ ^[0-9]+$ ]] && [ "${_port}" -ge 1 ] && [ "${_port}" -le 65535 ] \
    || die "端口不合法：${_port}（需为 1-65535）"
  PORT="${_port}"
  if [ -n "${ENCRYPT_PASSWORD}" ]; then
    read -r -s -p "加密口令（已设置，直接回车保持不变，输入新值替换，输入空格+回车可清空）: " _pw; echo
    # 仅输入空格视为清空
    [[ "${_pw}" =~ ^[[:space:]]+$ ]] && _pw=""
  else
    read -r -s -p "加密口令（留空=明文模式）: " _pw; echo
  fi
  ENCRYPT_PASSWORD="${_pw:-$ENCRYPT_PASSWORD}"
  read -r -p "启用 HTTP DNS？(Y/n): " _dns
  case "${_dns}" in n|N|no|NO) ENABLE_HTTPDNS="false" ;; *) ENABLE_HTTPDNS="true" ;; esac
  echo "------------------------------"
  [ -n "${ENCRYPT_PASSWORD}" ] && info "已设置加密口令（XOR 加密开启）" \
    || warn "加密口令为空，将以明文模式运行"
}

download_bin() {
  local url="https://github.com/${REPO}/releases/download/${TAG}/${BIN_NAME}"
  info "下载 ${BIN_NAME} (${TAG})..."
  mkdir -p "${INSTALL_DIR}"
  curl -fsSL --retry 3 -o "${INSTALL_DIR}/${BIN_NAME}" "${url}" \
    || die "二进制下载失败，请确认 Release ${TAG} 已发布：https://github.com/${REPO}/releases"
  chmod +x "${INSTALL_DIR}/${BIN_NAME}"
  "${INSTALL_DIR}/${BIN_NAME}" -version 2>&1 | grep -q "cns version" \
    || die "下载的文件不是有效的 cns 二进制"
  info "二进制校验通过：$("${INSTALL_DIR}/${BIN_NAME}" -version 2>&1)"
}

install_service() {
  if has_systemd; then
    info "写入 systemd 服务..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=cns (CuteBi Network Server, Rust)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BIN_NAME} -json=${JSON_FILE}
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}"
  else
    warn "未检测到 systemd，使用 -daemon 守护模式启动"
    pkill -f "${INSTALL_DIR}/${BIN_NAME}" 2>/dev/null || true
    "${INSTALL_DIR}/${BIN_NAME}" -daemon=true -json="${JSON_FILE}"
  fi
  sleep 2
}

verify_install() {
  if (ss -tln 2>/dev/null || netstat -tln 2>/dev/null) | grep -q ":${PORT} "; then
    info "端口 ${PORT} 监听正常"
  else
    die "端口 ${PORT} 未监听，请检查 ${JSON_FILE}"
  fi
  if [ "${ENABLE_HTTPDNS}" = "true" ]; then
    curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/?dn=example.com" \
      | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
      && info "HTTP DNS 自检通过" \
      || warn "HTTP DNS 自检未通过（不影响隧道功能）"
  fi
  warn "如为云服务器，请在安全组/防火墙放行 TCP/UDP ${PORT} 端口"
}

pub_ip() { curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || echo '<服务器IP>'; }

show_client_info() {
  load_conf
  local ip; ip="$(pub_ip)"
  cat <<EOF

客户端配置参考（nwproxy）：
  cns        = "${ip}:${PORT}"
  cnsKey     = "Host"            # 与服务端 proxy_key 对应
  cnsEnc     = "${ENCRYPT_PASSWORD:-<空，与服务端 encrypt_password 一致>}"
  cnsPath    = "/"               # UDP 隧道必填
  cnsUdpFlag = "httpUDP"         # UDP 隧道必填；新线规用 cnsrUDP + udpout: cns-rust
EOF
}

# ---------- 菜单动作 ----------
do_install() {
  check_env
  if is_installed; then
    read -r -p "检测到已安装，是否覆盖重装？(y/N): " _r
    [[ "${_r}" == "y" || "${_r}" == "Y" ]] || { info "已取消"; return; }
    do_stop >/dev/null 2>&1 || true
  fi
  load_conf
  ask_config
  save_conf
  download_bin
  write_json
  migrate_legacy_service
  install_service
  install_cli
  verify_install
  cat <<EOF

========================================
 cns 安装完成！
========================================
 监听端口 : ${PORT}
 加密模式 : $([ -n "${ENCRYPT_PASSWORD}" ] && echo "XOR 加密已启用" || echo "明文模式")
 HTTP DNS : ${ENABLE_HTTPDNS}
 配置文件 : ${JSON_FILE}
 管理命令 : cns（root 下直接运行）
 服务管理 : 菜单 3/4/5，或 systemctl {start|stop|restart} ${SERVICE_NAME}
EOF
  show_client_info
}

do_uninstall() {
  check_env
  while true; do
    echo ""
    echo "=============================="
    echo " 卸载 cns"
    echo "=============================="
    echo "  1. 卸载 cns 服务端（删除服务与 /opt/cns，保留 cns 命令）"
    echo "  2. 完全卸载（删除服务端、配置与 cns 命令，恢复最初状态）"
    echo "——————————————————————————————"
    echo "  0. 返回主菜单"
    echo "=============================="
    echo ""
    read -r -p " 请输入数字[0-2]: " _c
    case "${_c}" in
      1) uninstall_server ;;
      2)
        read -r -p "确认完全卸载 cns（删除服务端、/opt/cns 与 cns 命令，恢复最初状态）？(y/N): " _f
        if [[ "${_f}" == "y" || "${_f}" == "Y" ]]; then
          SKIP_CONFIRM=1
          uninstall_server
          uninstall_cli
          exit 0
        else
          info "已取消"
        fi
        ;;
      0) return ;;
      *) warn "无效选项，请输入 0-2" ;;
    esac
    echo ""
    read -r -p "按回车继续..." _
  done
}

uninstall_server() {
  is_installed || { warn "服务端当前未安装"; return; }
  if [ "${SKIP_CONFIRM:-0}" != "1" ]; then
    read -r -p "确认卸载 cns 服务端并删除 ${INSTALL_DIR}？(y/N): " _u
    [[ "${_u}" == "y" || "${_u}" == "Y" ]] || { info "已取消"; return; }
  fi
  do_stop >/dev/null 2>&1 || true
  if has_systemd; then
    for _svc in "${SERVICE_NAME}" "${LEGACY_SERVICE}"; do
      systemctl disable "${_svc}" 2>/dev/null || true
      rm -f "/etc/systemd/system/${_svc}.service"
    done
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -rf "${INSTALL_DIR}"
  info "cns 服务端已卸载，${INSTALL_DIR} 已删除，cns 命令保留"
}

uninstall_cli() {
  [ -f "${CLI_PATH}" ] || { warn "cns 命令未安装"; return; }
  if [ "${SKIP_CONFIRM:-0}" != "1" ]; then
    read -r -p "确认卸载 cns 管理命令？(y/N): " _u
    [[ "${_u}" == "y" || "${_u}" == "Y" ]] || { info "已取消"; return; }
  fi
  local me; me="$(self_path)"
  rm -f "${CLI_PATH}"
  if [ "${me}" != "${CLI_PATH}" ] && [ -f "${me}" ] && [ "$(basename "${me}")" = "install.sh" ]; then
    rm -f "${me}"
  fi
  info "cns 命令已卸载"
  if [ "${me}" = "${CLI_PATH}" ]; then
    info "当前会话结束"
    exit 0
  fi
}

do_start() {
  check_env
  is_installed || { warn "当前未安装，请先选 1 安装"; return; }
  migrate_legacy_service
  is_running && { info "服务已在运行中"; return; }
  load_conf
  install_service
  is_running && info "启动成功" || die "启动失败，请检查 ${JSON_FILE}"
}

do_stop() {
  check_env
  is_installed || { warn "当前未安装"; return; }
  migrate_legacy_service
  if has_systemd; then
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
  else
    pkill -f "${INSTALL_DIR}/${BIN_NAME}" 2>/dev/null || true
  fi
  sleep 1
  is_running && warn "停止失败，进程仍在运行" || info "已停止"
}

do_restart() {
  do_stop >/dev/null 2>&1 || true
  do_start
}

do_set_config() {
  check_env
  is_installed || { warn "当前未安装，请先选 1 安装"; return; }
  load_conf
  ask_config
  save_conf
  write_json
  info "配置已更新，正在重启服务..."
  do_restart
  verify_install
}

do_show_config() {
  is_installed || { warn "当前未安装"; return; }
  load_conf
  echo "---------- 当前配置 ----------"
  echo "监听端口   : ${PORT}"
  echo "加密模式   : $([ -n "${ENCRYPT_PASSWORD}" ] && echo "XOR 加密已启用" || echo "明文模式")"
  echo "HTTP DNS   : ${ENABLE_HTTPDNS}"
  echo "配置文件   : ${JSON_FILE}"
  echo "------------------------------"
  cat "${JSON_FILE}"
  show_client_info
}

do_status() {
  is_installed || { warn "当前未安装"; return; }
  load_conf
  echo "---------- 运行状态 ----------"
  if has_systemd; then
    systemctl --no-pager --full status "${SERVICE_NAME}" | head -12 || true
  else
    pgrep -af "${INSTALL_DIR}/${BIN_NAME}" || echo "进程未运行"
  fi
  echo "------------------------------"
  (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep ":${PORT} " || echo "端口 ${PORT} 未监听"
}

do_update() {
  local tmp_new; tmp_new="$(mktemp)"
  info "正在更新脚本..."
  # 加时间戳参数绕过 CDN 缓存
  curl -fsSL --retry 2 -o "${tmp_new}" "${SCRIPT_URL}?t=$(date +%s)" \
    || { warn "脚本下载失败"; rm -f "${tmp_new}"; return; }
  chmod +x "${tmp_new}"
  bash -n "${tmp_new}" || { warn "新脚本语法校验失败，已取消更新"; rm -f "${tmp_new}"; return; }
  local me; me="$(self_path)"
  local updated=0
  if [ -f "${me}" ]; then cp -f "${tmp_new}" "${me}"; updated=1; fi
  if [ "${me}" != "${CLI_PATH}" ]; then
    cp -f "${tmp_new}" "${CLI_PATH}"; chmod +x "${CLI_PATH}"; updated=1
  fi
  rm -f "${tmp_new}"
  [ "${updated}" = "1" ] || { warn "未找到可更新的脚本位置"; return; }
  info "更新完成，重新加载..."
  if [ "${me}" = "${CLI_PATH}" ]; then exec "${CLI_PATH}"; else exec bash "${me}"; fi
}

# 快捷入口：bash install.sh uninstall（仍需终端交互确认）
if [ "${1:-}" = "uninstall" ]; then
  [ -t 0 ] || die "卸载需要交互确认，请在终端中运行"
  do_uninstall
  exit 0
fi

# ---------- 主菜单 ----------
[ -t 0 ] || die "管理脚本需要交互式终端，请先下载再运行：curl -kLO ${SCRIPT_URL} && sudo bash install.sh"

# 跑一次脚本即装好 cns 命令：即使不安装服务端，之后 root 下直接敲 cns 也能进菜单
if [ "$(id -u)" -eq 0 ]; then
  install_cli || true
else
  warn "当前非 root，跳过 cns 命令安装（请用 root 运行一次脚本以安装）"
fi

while true; do
  echo ""
  echo "=============================="
  echo "cns 管理脚本 [v1.1.7]"
  echo "=============================="
  echo "  0. 更新脚本"
  echo "——————————————————————————————"
  echo "  1. 安装 cns"
  echo "  2. 卸载 cns"
  echo "——————————————————————————————"
  echo "  3. 启动 cns"
  echo "  4. 停止 cns"
  echo "  5. 重启 cns"
  echo "——————————————————————————————"
  echo "  6. 设置 配置信息"
  echo "  7. 查看 配置信息"
  echo "  8. 查看 运行状态"
  echo "——————————————————————————————"
  echo " 00. 退出脚本"
  echo "=============================="
  echo ""
  if is_installed; then
    load_conf
    if is_running; then echo " 当前状态: 运行中 (端口 ${PORT})"
    else echo " 当前状态: 已安装未运行"; fi
  else
    echo " 当前状态: 未安装"
  fi
  echo ""
  read -r -p " 请输入数字[0-8]: " choice
  case "${choice}" in
    0) do_update ;;
    1) do_install ;;
    2) do_uninstall ;;
    3) do_start ;;
    4) do_stop ;;
    5) do_restart ;;
    6) do_set_config ;;
    7) do_show_config ;;
    8) do_status ;;
    00|q|Q) echo "退出"; exit 0 ;;
    *) warn "无效选项，请输入 0-8" ;;
  esac
  echo ""
  read -r -p "按回车返回菜单..." _
done
