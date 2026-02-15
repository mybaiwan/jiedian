#!/usr/bin/env bash
set -euo pipefail

# =========================
# Debian 12 节点基建菜单脚本（完整版）
# - 更新/基础包
# - 时间同步 chrony
# - BBR 开启与状态检查
# - 创建运维用户 ops + 写入公钥
# - SSH 加固（防锁死：有 key 才禁密码）
# - 防火墙 nftables（可选仅允许你的IP SSH，可选开放额外端口）
# - fail2ban 防爆破
# - unattended-upgrades 自动安全更新
# - swap 创建
# - 状态报告
#
# 可用环境变量（可选）：
#   SSH_PORT=22
#   ADMIN_IP="1.2.3.4"                 # 限制 SSH 仅此 IP 访问（可选）
#   ALLOW_TCP_PORTS="80,443"           # 额外开放的 TCP 端口（逗号分隔，可选）
#   OPS_USER="ops"                      # 运维用户（默认 ops）
#   OPS_SSH_KEYS="ssh-ed25519 AAA...\nssh-rsa AAA..."  # 写入运维用户的公钥（可选）
#   SET_SWAP_GB=0                       # 创建 swap 大小（GB），0=不创建（可选）
#
# 运行：
#   bash node-menu.sh
# =========================

GREEN="\033[1;32m"; YELLOW="\033[1;33m"; RED="\033[1;31m"; CYAN="\033[1;36m"; NC="\033[0m"
ok()   { echo -e "${GREEN}[成功]${NC} $*"; }
info() { echo -e "${CYAN}[信息]${NC} $*"; }
warn() { echo -e "${YELLOW}[提示]${NC} $*"; }
err()  { echo -e "${RED}[错误]${NC} $*" >&2; }

pause() { read -r -p "按回车键继续..." _; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "请使用 root 身份运行此脚本"
    exit 1
  fi
}

detect_os() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    info "系统：${PRETTY_NAME:-unknown}"
    if [[ "${ID:-}" != "debian" ]]; then
      warn "检测到非 Debian 系统（ID=${ID:-unknown}），脚本以 Debian 12 为默认目标。"
    fi
    if [[ "${VERSION_ID:-}" != "12" ]]; then
      warn "检测到 VERSION_ID=${VERSION_ID:-unknown}，建议 Debian 12 运行。"
    fi
  fi
}

apt_update_upgrade() {
  info "正在更新系统软件包..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  ok "系统更新完成"
}

apt_install_base() {
  info "安装基础组件（curl/chrony/fail2ban/nftables/ssh/自动安全更新等）..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y \
    ca-certificates curl wget gnupg lsb-release \
    vim nano htop unzip \
    chrony \
    fail2ban \
    logrotate \
    nftables \
    unattended-upgrades \
    sudo \
    openssh-server
  ok "基础组件安装完成"
}

setup_time() {
  info "启用时间同步（chrony）..."
  systemctl enable --now chrony >/dev/null 2>&1 || true
  timedatectl set-ntp true >/dev/null 2>&1 || true
  ok "时间同步已启用"
}

setup_unattended_upgrades() {
  info "启用自动安全更新（unattended-upgrades）..."
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "自动安全更新已启用"
}

# ---------- BBR ----------
enable_bbr() {
  info "尝试开启 BBR..."
  local avail
  avail="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
  if ! echo "$avail" | grep -qw bbr; then
    warn "当前内核未列出 bbr：${avail:-unknown}"
    warn "内核版本：$(uname -r)"
    warn "如需 BBR，请确认内核支持（Debian 12 通常支持）。"
    return 0
  fi

  cat >/etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

  sysctl --system >/dev/null 2>&1 || true

  local cc qdisc
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  ok "BBR 已配置：tcp_congestion_control=${cc}, default_qdisc=${qdisc}"
}

# ---------- 运维用户 ----------
create_ops_user() {
  local user="${OPS_USER:-ops}"
  if id "$user" >/dev/null 2>&1; then
    info "运维用户 '${user}' 已存在"
  else
    info "创建运维用户 '${user}' 并加入 sudo..."
    useradd -m -s /bin/bash "$user"
    usermod -aG sudo "$user"
    ok "用户创建完成：${user}"
  fi

  local keys="${OPS_SSH_KEYS:-}"
  if [[ -n "$keys" ]]; then
    info "写入 '${user}' 的 SSH 公钥..."
    install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
    printf "%b\n" "$keys" > "/home/$user/.ssh/authorized_keys"
    chown "$user:$user" "/home/$user/.ssh/authorized_keys"
    chmod 600 "/home/$user/.ssh/authorized_keys"
    ok "已写入公钥到 /home/${user}/.ssh/authorized_keys"
  else
    warn "未提供 OPS_SSH_KEYS，跳过写入公钥（你也可以后续手动添加）"
  fi
}

has_any_ssh_key() {
  local ops="${OPS_USER:-ops}"
  local root_keys="/root/.ssh/authorized_keys"
  local ops_keys="/home/$ops/.ssh/authorized_keys"
  if [[ -s "$root_keys" ]] && grep -qE '^\s*(ssh-(rsa|ed25519)|ecdsa-)' "$root_keys"; then return 0; fi
  if [[ -s "$ops_keys"  ]] && grep -qE '^\s*(ssh-(rsa|ed25519)|ecdsa-)' "$ops_keys";  then return 0; fi
  return 1
}

# ---------- SSH ----------
set_sshd_kv() {
  local cfg="/etc/ssh/sshd_config"
  local key="$1" val="$2"
  if grep -qE "^[#\s]*${key}\s+" "$cfg"; then
    sed -i -E "s|^[#\s]*(${key})\s+.*|\1 ${val}|g" "$cfg"
  else
    echo "${key} ${val}" >> "$cfg"
  fi
}

harden_ssh() {
  local ssh_port="${SSH_PORT:-22}"
  info "SSH 加固（端口：${ssh_port}）..."

  local cfg="/etc/ssh/sshd_config"
  cp -a "$cfg" "${cfg}.bak.$(date +%F-%H%M%S)" || true

  set_sshd_kv "Port" "${ssh_port}"
  set_sshd_kv "Protocol" "2"
  set_sshd_kv "PermitEmptyPasswords" "no"
  set_sshd_kv "X11Forwarding" "no"
  set_sshd_kv "AllowTcpForwarding" "no"
  set_sshd_kv "ClientAliveInterval" "300"
  set_sshd_kv "ClientAliveCountMax" "2"

  if has_any_ssh_key; then
    info "检测到 SSH 公钥 → 关闭密码登录（更安全，且不锁死）"
    set_sshd_kv "PasswordAuthentication" "no"
    set_sshd_kv "KbdInteractiveAuthentication" "no"
    set_sshd_kv "PermitRootLogin" "prohibit-password"
  else
    warn "未检测到 root 或 '${OPS_USER:-ops}' 的 SSH 公钥 → 为避免锁死，将保留密码登录"
    warn "建议：先为 root 或 ops 写入公钥，然后再执行 SSH 加固一次"
    set_sshd_kv "PasswordAuthentication" "yes"
    set_sshd_kv "KbdInteractiveAuthentication" "yes"
    set_sshd_kv "PermitRootLogin" "yes"
  fi

  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
  ok "SSH 配置已应用。若改了端口，请先开新 SSH 会话验证，再关闭旧会话。"
}

# ---------- fail2ban ----------
setup_fail2ban() {
  info "配置 fail2ban（sshd 防爆破）..."
  cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
bantime  = 1h
findtime = 10m
maxretry = 5
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  ok "fail2ban 已启用"
}

# ---------- sysctl 基础 ----------
setup_sysctl_baseline() {
  info "应用基础 sysctl 安全参数..."
  cat >/etc/sysctl.d/99-node-baseline.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
  sysctl --system >/dev/null 2>&1 || true
  ok "sysctl 已应用"
}

# ---------- 防火墙 nftables ----------
setup_nftables_firewall() {
  local ssh_port="${SSH_PORT:-22}"
  local admin_ip="${ADMIN_IP:-}"
  local extra_ports="${ALLOW_TCP_PORTS:-}"

  info "配置 nftables 防火墙..."
  systemctl enable --now nftables >/dev/null 2>&1 || true

  local ssh_rule=""
  if [[ -n "$admin_ip" ]]; then
    ssh_rule="ip saddr ${admin_ip} tcp dport ${ssh_port} accept"
    warn "SSH 将限制仅允许 ADMIN_IP=${admin_ip} 访问（更安全）"
  else
    ssh_rule="tcp dport ${ssh_port} accept"
    warn "未设置 ADMIN_IP，SSH 将对公网开放（建议设置 ADMIN_IP）"
  fi

  local extra_rules=""
  if [[ -n "$extra_ports" ]]; then
    IFS=',' read -ra ports_arr <<< "$extra_ports"
    for p in "${ports_arr[@]}"; do
      p="$(echo "$p" | tr -d '[:space:]')"
      [[ -z "$p" ]] && continue
      extra_rules+=$'\n'"    tcp dport ${p} accept"
    done
  fi

  cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0;

    # 允许本机回环
    iif "lo" accept

    # 允许已建立连接
    ct state established,related accept

    # 允许 ICMP/ICMPv6（ping/PMTU）
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # SSH
    ${ssh_rule}

    # 额外 TCP 端口（可选）
${extra_rules}

    # 其余全部丢弃
    counter drop
  }

  chain forward {
    type filter hook forward priority 0;
    counter drop
  }

  chain output {
    type filter hook output priority 0;
    accept
  }
}
EOF

  nft -f /etc/nftables.conf
  systemctl restart nftables >/dev/null 2>&1 || true
  ok "防火墙已生效：SSH=${ssh_port}${admin_ip:+(仅限 ${admin_ip})}${extra_ports:+，额外开放TCP: ${extra_ports}}"
}

# ---------- Swap ----------
setup_swap() {
  local swap_gb="${SET_SWAP_GB:-0}"
  [[ "$swap_gb" =~ ^[0-9]+$ ]] || swap_gb=0
  if [[ "$swap_gb" -le 0 ]]; then
    warn "SET_SWAP_GB=0 → 不创建 swap"
    return 0
  fi
  if swapon --show | grep -q '.'; then
    warn "系统已有 swap，跳过创建"
    return 0
  fi
  info "创建 ${swap_gb}G swapfile..."
  fallocate -l "${swap_gb}G" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=$((swap_gb*1024))
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  ok "Swap 已启用"
}

# ---------- 状态报告 ----------
show_status() {
  echo
  echo "================= 节点状态报告 ================="
  echo "系统: $(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
  echo "内核: $(uname -r)"
  echo "当前时间: $(date)"
  echo "公网IP: $(curl -fsSL https://api.ipify.org 2>/dev/null || echo '获取失败')"
  echo
  echo "- BBR 可用: $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo n/a)"
  echo "- 拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo n/a)"
  echo "- 默认队列: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo n/a)"
  echo
  echo "- SSH 监听:"
  ss -lntp 2>/dev/null | grep -E 'sshd' || echo "  (未发现 sshd 监听)"
  echo
  echo "- 服务状态:"
  echo "  chrony:              $(systemctl is-active chrony 2>/dev/null || echo n/a)"
  echo "  fail2ban:            $(systemctl is-active fail2ban 2>/dev/null || echo n/a)"
  echo "  nftables:            $(systemctl is-active nftables 2>/dev/null || echo n/a)"
  echo "  unattended-upgrades: $(systemctl is-active unattended-upgrades 2>/dev/null || echo n/a)"
  echo
  echo "- Swap:"
  swapon --show || true
  echo "================================================"
  echo
}

save_report() {
  local out="/root/node-report-$(date +%F-%H%M%S).txt"
  show_status | tee "$out" >/dev/null
  ok "报告已保存：${out}"
}

# ---------- 一键推荐 ----------
run_all_recommended() {
  info "开始执行：一键推荐基建（安全且适合新机器）..."
  apt_update_upgrade
  apt_install_base
  setup_time
  setup_unattended_upgrades
  create_ops_user
  setup_sysctl_baseline
  enable_bbr
  setup_fail2ban
  harden_ssh
  setup_nftables_firewall
  setup_swap
  ok "一键推荐基建已完成"
  save_report
}

# ---------- 菜单 ----------
menu() {
  clear
  echo "========================================================"
  echo " Debian 12 节点基建管理菜单（完整版）"
  echo "========================================================"
  echo "1) 一键执行【推荐基建】(更新+基础包+时间+BBR+fail2ban+SSH+防火墙+swap)"
  echo "2) 仅开启 BBR"
  echo "3) 更新系统（apt update/upgrade）"
  echo "4) 安装基础组件（ssh/chrony/fail2ban/nftables/自动更新等）"
  echo "5) 创建运维用户 + 写入公钥（OPS_USER/OPS_SSH_KEYS）"
  echo "6) SSH 加固（防锁死：有公钥才禁密码）"
  echo "7) 配置防火墙（nftables）（SSH_PORT/ADMIN_IP/ALLOW_TCP_PORTS）"
  echo "8) 启用 fail2ban（sshd 防爆破）"
  echo "9) 启用自动安全更新（unattended-upgrades）"
  echo "10) 创建/启用 Swap（SET_SWAP_GB）"
  echo "S) 查看状态报告"
  echo "R) 保存状态报告到文件"
  echo "Q) 退出"
  echo "--------------------------------------------------------"
  echo "当前变量："
  echo "  SSH_PORT=${SSH_PORT:-22}"
  echo "  ADMIN_IP=${ADMIN_IP:-<未设置>}"
  echo "  ALLOW_TCP_PORTS=${ALLOW_TCP_PORTS:-<未设置>}"
  echo "  OPS_USER=${OPS_USER:-ops}"
  echo "  SET_SWAP_GB=${SET_SWAP_GB:-0}"
  echo "========================================================"
  echo
}

main() {
  require_root
  detect_os

  while true; do
    menu
    read -r -p "请选择操作: " choice
    case "$choice" in
      1) run_all_recommended; pause ;;
      2) enable_bbr; pause ;;
      3) apt_update_upgrade; pause ;;
      4) apt_install_base; pause ;;
      5) create_ops_user; pause ;;
      6) harden_ssh; pause ;;
      7) setup_nftables_firewall; pause ;;
      8) setup_fail2ban; pause ;;
      9) setup_unattended_upgrades; pause ;;
      10) setup_swap; pause ;;
      s|S) show_status; pause ;;
      r|R) save_report; pause ;;
      q|Q) ok "已退出"; exit 0 ;;
      *) warn "无效选项"; pause ;;
    esac
  done
}

main "$@"
