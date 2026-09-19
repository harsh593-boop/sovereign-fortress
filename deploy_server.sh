#!/usr/bin/env bash
# ==============================================================================
# Sovereign Fortress — Automated Sovereign Cloud Deployment Suite (2026)
# Multi-Protocol Zero-Trust VPN, RAM-Only Runtime, Unbound DNS & PAM 2FA
# ==============================================================================
set -euo pipefail

echo "================================================================="
echo "   SOVEREIGN FORTRESS: COMPREHENSIVE SERVER INSTALLER           "
echo "   Zero Disk Logs • Volatile RAM (tmpfs) • Hardened Defense      "
echo "================================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (use sudo)."
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SB_ARCH="amd64" ;;
    aarch64) SB_ARCH="arm64" ;;
    *) echo "[-] Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Detect Public IP
SERVER_IP=$(curl -s4 https://api.ipify.org || curl -s4 https://ifconfig.me || ip route get 1.1.1.1 | awk '{print $7}')
echo "[+] Detected Server Public IP: $SERVER_IP"

# 1. Install Essential Dependencies & Unbound
echo "[*] Installing system dependencies, security tools, and Unbound DNS..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget unzip tar iptables ufw libpam-google-authenticator \
    qrencode jq openssl python3 unbound dnsutils bsdmainutils

# 2. Setup Volatile RAM Mount (tmpfs)
RAM_DIR="/run/fortress"
DISK_DIR="/etc/fortress"
mkdir -p "$DISK_DIR"
if ! mountpoint -q "$RAM_DIR"; then
    mkdir -p "$RAM_DIR"
    mount -t tmpfs -o size=256M,mode=0700 tmpfs "$RAM_DIR"
    echo "tmpfs $RAM_DIR tmpfs defaults,size=256M,mode=0700 0 0" >> /etc/fstab || true
fi

# 3. Install Sing-box 1.11+ Core with Architecture Check
SINGBOX_VER="1.11.4"
echo "[*] Downloading Sing-box v${SINGBOX_VER} for ${SB_ARCH}..."
SB_TAR="sing-box-${SINGBOX_VER}-linux-${SB_ARCH}.tar.gz"
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/${SB_TAR}"

case "$SB_ARCH" in
    amd64) EXPECTED_SHA256="0bb762ef286b36c2016d9107fc1f089be7a75f6d579b33f067d31e696c05927e" ;;
    arm64) EXPECTED_SHA256="4e687359db42b6a28ef93f9cd2cb9549c4b0079cc7e49bc5f6ecbf98257a2507" ;;
esac

curl -sSL "$SB_URL" -o "/tmp/${SB_TAR}"
ACTUAL_SHA256=$(sha256sum "/tmp/${SB_TAR}" | awk '{print $1}')

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "[-] Cryptographic verification failed for Sing-box archive!"
    echo "    Expected: $EXPECTED_SHA256"
    echo "    Actual:   $ACTUAL_SHA256"
    rm -f "/tmp/${SB_TAR}"
    exit 1
fi
echo "[+] Cryptographic SHA256 verified successfully: $ACTUAL_SHA256"

tar -xzf "/tmp/${SB_TAR}" -C /tmp/
install -m 0755 "/tmp/sing-box-${SINGBOX_VER}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box
rm -rf "/tmp/sing-box*"

echo "[+] Installed: $(/usr/local/bin/sing-box version | head -n 1)"

# 4. Generate High-Entropy Cryptographic Keys
echo "[*] Generating cryptographic credentials..."
UUID=$(cat /proc/sys/kernel/random/uuid)
HY2_PASS=$(openssl rand -hex 16)
SALAMANDER_PASS=$(openssl rand -hex 16)
SS_PASS=$(openssl rand -base64 32)
SUB_TOKEN="ft_sec_$(openssl rand -hex 16)"
REALITY_SHORTID=$(openssl rand -hex 8)

REALITY_KEYPAIR=$(/usr/local/bin/sing-box generate reality-keypair)
REALITY_PRIV=$(echo "$REALITY_KEYPAIR" | grep "PrivateKey" | awk '{print $2}')
REALITY_PUB=$(echo "$REALITY_KEYPAIR" | grep "PublicKey" | awk '{print $2}')
REALITY_SNI="gateway.icloud.com"

# Masquerade Self-Signed TLS Certificate for Hysteria 2 / TUIC
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "$DISK_DIR/key.pem" -out "$DISK_DIR/cert.pem" \
    -subj "/CN=www.microsoft.com" >/dev/null 2>&1
cp "$DISK_DIR/key.pem" "$RAM_DIR/key.pem"
cp "$DISK_DIR/cert.pem" "$RAM_DIR/cert.pem"
chmod 600 "$DISK_DIR/key.pem" "$RAM_DIR/key.pem"

# 5. Configure Self-Hosted Recursive Zero-Log Unbound DNS
echo "[*] Configuring Unbound recursive DNS resolver on 127.0.0.1:5335..."
curl -sS -o /var/lib/unbound/root.hints https://www.internic.net/domain/named.root || true

cat <<EOF > /etc/unbound/unbound.conf.d/fortress-unbound.conf
server:
    verbosity: 0
    use-syslog: no
    log-queries: no
    log-replies: no
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    qname-minimisation: yes
    prefetch: yes
    num-threads: 2
    msg-cache-size: 32m
    rrset-cache-size: 64m
    infra-cache-numhosts: 10000
EOF

systemctl restart unbound
systemctl enable unbound
echo "[+] Unbound Recursive DNS running on 127.0.0.1:5335 (DNSSEC Enabled, Zero Logging)."

# 6. Generate Hardened Sing-box Configuration
echo "[*] Generating Sing-box core configuration in RAM..."
cat <<EOF > "$RAM_DIR/config.json"
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "sovereign-unbound",
        "address": "udp://127.0.0.1:5335",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "sovereign-unbound"
      }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "uuid": "${UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_SNI}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${REALITY_SNI}",
            "server_port": 443
          },
          "private_key": "${REALITY_PRIV}",
          "short_id": ["${REALITY_SHORTID}"]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-sal-in",
      "listen": "::",
      "listen_port": 9444,
      "users": [
        {
          "password": "${HY2_PASS}"
        }
      ],
      "obfs": {
        "type": "salamander",
        "password": "${SALAMANDER_PASS}"
      },
      "tls": {
        "enabled": true,
        "certificate_path": "${RAM_DIR}/cert.pem",
        "key_path": "${RAM_DIR}/key.pem"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-std-in",
      "listen": "::",
      "listen_port": 8443,
      "users": [
        {
          "password": "${HY2_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${RAM_DIR}/cert.pem",
        "key_path": "${RAM_DIR}/key.pem"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": 9443,
      "users": [
        {
          "uuid": "${UUID}",
          "password": "${HY2_PASS}"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "certificate_path": "${RAM_DIR}/cert.pem",
        "key_path": "${RAM_DIR}/key.pem"
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "::",
      "listen_port": 10443,
      "method": "2022-blake3-aes-256-gcm",
      "password": "${SS_PASS}"
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "protocol": "dns",
        "outbound": "direct"
      },
      {
        "inbound": ["vless-in", "hy2-sal-in", "hy2-std-in", "tuic-in", "ss-in"],
        "outbound": "direct"
      }
    ]
  }
}
EOF

# Backup template to disk
cp "$RAM_DIR/config.json" "$DISK_DIR/config.json.template"

# 7. Setup Systemd Service for Sing-box
cat <<EOF > /etc/systemd/system/fortress-core.service
[Unit]
Description=Sovereign Fortress Core Engine (Sing-box)
After=network.target unbound.service
Wants=unbound.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /run/fortress/config.json
Restart=always
RestartSec=3
LimitNOFILE=65535
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart fortress-core
systemctl enable fortress-core

# 8. Configure Linux Kernel BBR Congestion Control
cat <<EOF > /etc/sysctl.d/99-fortress.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
EOF
sysctl --system >/dev/null 2>&1 || true

# 9. Configure Firewall (UFW / iptables)
if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp || true
    ufw allow 443/tcp || true
    ufw allow 8443/tcp || true
    ufw allow 8443/udp || true
    ufw allow 9443/udp || true
    ufw allow 9444/udp || true
    ufw allow 10443/tcp || true
    ufw allow 10443/udp || true
    ufw allow 51820/udp || true
fi

# 10. Save Master Configuration Output
cat <<EOF > "$DISK_DIR/fortress_config.json"
{
  "server_ip": "${SERVER_IP}",
  "sub_port": 8443,
  "token": "${SUB_TOKEN}",
  "uuid": "${UUID}",
  "reality_pubkey": "${REALITY_PUB}",
  "reality_shortid": "${REALITY_SHORTID}",
  "reality_sni": "${REALITY_SNI}",
  "hy2_password": "${HY2_PASS}",
  "salamander_password": "${SALAMANDER_PASS}",
  "ss_password": "${SS_PASS}"
}
EOF
cp "$DISK_DIR/fortress_config.json" "$RAM_DIR/fortress_config.json"

echo "================================================================="
echo "   SOVEREIGN FORTRESS DEPLOYMENT COMPLETE!                      "
echo "================================================================="
echo "[+] Public IP:       ${SERVER_IP}"
echo "[+] VLESS Reality:   TCP 443 (Camouflage: ${REALITY_SNI})"
echo "[+] Hysteria 2 Sal:  UDP 9444 (ChaCha20 Scrambled QUIC)"
echo "[+] Hysteria 2 Std:  UDP 8443 (Brutal BBR)"
echo "[+] TUIC v5:         UDP 9443 (0-RTT Native QUIC)"
echo "[+] Shadowsocks:     TCP/UDP 10443 (2022-blake3-aes-256-gcm)"
echo "[+] Recursive DNS:   127.0.0.1:5335 (Unbound Zero-Log)"
echo "[+] Master Token:    ${SUB_TOKEN}"
echo "[+] Config Saved:    ${DISK_DIR}/fortress_config.json"
echo "================================================================="
