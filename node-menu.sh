#!/usr/bin/env bash
set -euo pipefail

# Debian 12 Node Baseline Menu Script
# - Safe by default: avoids locking you out of SSH
# - Provides menu options for baseline setup + BBR + firewall + fail2ban + swap + backups
#
# Env vars (optional):
#   SSH_PORT=22
#   ADMIN_IP="1.2.3.4"               # restrict SSH to this IP (optional)
#   ALLOW_TCP_PORTS="80,443"         # extra allowed TCP ports (optional)
#   OPS_USER="ops"                   # optional
#   OPS_SSH_KEYS="ssh-ed25519 AAA...\nssh-rsa AAA..."  # optional
#   SET_SWAP_GB=0                    # optional

GREEN="\033[1;32m"; YELLOW="\033[1;33m"; RED="\033[1;31m"; NC="\033[0m"
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Please run as root."
    exit 1
  fi
}

pause() { read -r -p "Press Enter to continue..." _; }

detect_debian12() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" != "debian" ]]; then
      warn "Detected ID=${ID:-unknown} (script tuned for Debian)."
    fi
    if [[ "${VERSION_ID:-}" != "12" ]]; then
      warn "Detected VERSION_ID=${VERSION_ID:-unknown} (script tuned for Debian 12)."
    fi
  fi
}

apt_update_upgrade() {
  log "apt update/upgrade..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
}

apt_install_base() {
  log "Installing base packages..."
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
}

setup_time() {
  log "Enabling time sync (chrony)..."
  systemctl enable --now chrony >/dev/null 2>&1 || true
  timedatectl set-ntp true >/dev/null 2>&1 || true
}

setup_unattended_upgrades() {
  log "Enabling unattended upgrades (security updates)..."
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
}

create_ops_user() {
  local user="${OPS_USER:-ops}"
  if id "$user" >/dev/null 2>&1; then
    log "User '$user' already exists."
  else
    log "Creating user '$user' and adding to sudo..."
    useradd -m -s /bin/bash "$user"
    usermod -aG sudo "$user"
  fi

  local keys="${OPS_SSH_KEYS:-}"
  if [[ -n "$keys" ]]; then
    log "Installing SSH keys for '$user'..."
    install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
    printf "%b\n" "$keys" > "/home/$user/.ssh/authorized_keys"
    chown "$user:$user" "/home/$user/.ssh/authorized_keys"
    chmod 600 "/home/$user/.ssh/authorized_keys"
  else
    warn "OPS_SSH_KEYS not provided. Skipping authorized_keys for '$user'."
  fi
}

has_any_ssh_key() {
  local ops="${OPS_USER:-ops}"
  local root_keys="/root/.ssh/authorized_keys"
  local ops_keys="/home/$ops/.ssh/authorized_keys"
  if [[ -s "$root_keys" ]] && grep -qE '^\s*(ssh-(rsa|ed25519)|ecdsa-)' "$root_keys"; then return 0; fi
  if [[ -s "$ops_keys" ]]  && grep -qE '^\s*(ssh-(rsa|ed25519)|ecdsa-)' "$ops_keys"; then return 0; fi
  return 1
}

harden_ssh() {
  local ssh_port="${SSH_PORT:-22}"
  log "Hardening SSH (Port ${ssh_port})..."

  local cfg="/etc/ssh/sshd_config"
  cp -a "$cfg" "${cfg}.bak.$(date +%F-%H%M%S)" || true

  set_sshd_kv() {
    local key="$1" val="$2"
    if grep -qE "^[#\s]*${key}\s+" "$cfg"; then
      sed -i -E "s|^[#\s]*(${key})\s+.*|\1 ${val}|g" "$cfg"
    else
      echo "${key} ${val}" >> "$cfg"
    fi
  }

  set_sshd_kv "Port" "${ssh_port}"
  set_sshd_kv "Protocol" "2"
  set_sshd_kv "PermitEmptyPasswords" "no"
  set_sshd_kv "X11Forwarding" "no"
  set_sshd_kv "AllowTcpForwarding" "no"
  set_sshd_kv "ClientAliveInterval" "300"
  set_sshd_kv "ClientAliveCountMax" "2"

  if has_any_ssh_key; then
    log "SSH keys detected → disabling password auth (safer)."
    set_sshd_kv "PasswordAuthentication" "no"
    set_sshd_kv "KbdInteractiveAuthentication" "no"
    set_sshd_kv "PermitRootLogin" "prohibit-password"
  else
    warn "No SSH keys detected → keeping password auth enabled to avoid lockout."
    set_sshd_kv "PasswordAuthentication" "yes"
    set_sshd_kv "KbdInteractiveAuthentication" "yes"
    set_sshd_kv "PermitRootLogin" "yes"
  fi

  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
  log "SSH updated. If you changed SSH_PORT, open a NEW SSH session before closing the old one."
}

setup_fail2ban() {
  log "Configuring fail2ban (sshd jail)..."
  cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
bantime  = 1h
findtime = 10m
maxretry = 5
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
}

setup_sysctl_baseline() {
  log "Applying minimal sysctl hardening..."
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
}

enable_bbr() {
  log "Enabling BBR..."
  # Check available
  local avail
  avail="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
  if ! echo "$avail" | grep -qw bbr; then
    warn "BBR not listed in tcp_available_congestion_control. Kernel may not support BBR."
    warn "Kernel: $(uname -r)"
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
  log "BBR status: tcp_congestion_control=${cc}, default_qdisc=${qdisc}"
  lsmod | grep -q tcp_bbr && log "Kernel module tcp_bbr loaded." || warn "tcp_bbr module not shown (may be built-in)."
}

setup_nftables_firewall() {
  local ssh_port="${SSH_PORT:-22}"
  local admin_ip="${ADMIN_IP:-}"
  local extra_ports="${ALLOW_TCP_PORTS:-}"

  log "Configuring nftables firewall..."
  systemctl enable --now nftables >/dev/null 2>&1 || true

  local ssh_rule=""
  if [[ -n "$admin_ip" ]]; then
    ssh_rule="ip saddr ${admin_ip} tcp dport ${ssh_port} accept"
    warn "SSH restricted to ADMIN_IP=${admin_ip}."
  else
    ssh_rule="tcp dport ${ssh_port} accept"
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
    iif "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    ${ssh_rule}
${extra_rules}

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
  log "Firewall applied. SSH=${ssh_port}${admin_ip:+ (ADMIN_IP restricted)}${extra_ports:+, extra TCP allowed: ${extra_ports}}"
}

setup_swap() {
  local swap_gb="${SET_SWAP_GB:-0}"
  [[ "$swap_gb" =~ ^[0-9]+$ ]] || swap_gb=0
  if [[ "$swap_gb" -le 0 ]]; then
    warn "SET_SWAP_GB not set or 0 → skipping swap."
    return 0
  fi

  if swapon --show | grep -q '.'; then
    warn "Swap already exists → skipping."
    return 0
  fi

  log "Creating ${swap_gb}G swapfile..."
  fallocate -l "${swap_gb}G" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=$((swap_gb*1024))
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  log "Swap enabled."
}

xboard_backup() {
  # Safe generic backup for /opt/Xboard if present
  if [[ ! -d /opt/Xboard ]]; then
    warn "/opt/Xboard not found, skipping."
    return 0
  fi
  local outdir="/opt/backup_xboard"
  mkdir -p "$outdir"
  local ts
  ts="$(date +%F-%H%M)"
  local outfile="${outdir}/xboard-${ts}.tar.gz"
  log "Creating Xboard backup: ${outfile}"
  tar -czf "$outfile" /opt/Xboard/.env /opt/Xboard/.docker/.data /opt/Xboard/storage /opt/Xboard/plugins 2>/dev/null || true
  ls -lh "$outfile" || true
}

run_all_recommended() {
  log "Running recommended baseline steps..."
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
  log "Recommended baseline completed."
}

show_status() {
  echo
  echo "===== STATUS ====="
  echo "Kernel: $(uname -r)"
  echo "BBR avail: $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo n/a)"
  echo "CC: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo n/a)"
  echo "Qdisc: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo n/a)"
  echo "SSH: $(ss -lntp 2>/dev/null | grep -E 'sshd' || echo 'sshd not listening?')"
  echo "fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo n/a)"
  echo "nftables: $(systemctl is-active nftables 2>/dev/null || echo n/a)"
  echo "chrony: $(systemctl is-active chrony 2>/dev/null || echo n/a)"
  echo "=================="
  echo
}

menu() {
  clear
  echo "Debian 12 Node Baseline Menu"
  echo "----------------------------"
  echo "1) Run ALL recommended baseline (safe)"
  echo "2) Enable BBR only"
  echo "3) Install base packages"
  echo "4) Create ops user + SSH keys (OPS_USER/OPS_SSH_KEYS)"
  echo "5) Harden SSH (safe: only disables password if keys exist)"
  echo "6) Setup firewall (nftables) (SSH_PORT/ADMIN_IP/ALLOW_TCP_PORTS)"
  echo "7) Setup fail2ban (sshd)"
  echo "8) Create swap (SET_SWAP_GB)"
  echo "9) Backup Xboard (if /opt/Xboard exists)"
  echo "S) Show status"
  echo "Q) Quit"
  echo
  echo "Current vars:"
  echo "  SSH_PORT=${SSH_PORT:-22}"
  echo "  ADMIN_IP=${ADMIN_IP:-<none>}"
  echo "  ALLOW_TCP_PORTS=${ALLOW_TCP_PORTS:-<none>}"
  echo "  OPS_USER=${OPS_USER:-ops}"
  echo "  SET_SWAP_GB=${SET_SWAP_GB:-0}"
  echo
}

main() {
  require_root
  detect_debian12

  while true; do
    menu
    read -r -p "Select an option: " choice
    case "$choice" in
      1) run_all_recommended; pause ;;
      2) enable_bbr; pause ;;
      3) apt_update_upgrade; apt_install_base; pause ;;
      4) create_ops_user; pause ;;
      5) harden_ssh; pause ;;
      6) setup_nftables_firewall; pause ;;
      7) setup_fail2ban; pause ;;
      8) setup_swap; pause ;;
      9) xboard_backup; pause ;;
      s|S) show_status; pause ;;
      q|Q) log "Bye."; exit 0 ;;
      *) warn "Invalid option."; pause ;;
    esac
  done
}

main "$@"
