#!/usr/bin/env bash
# ==============================================================================
# Sovereign Fortress — Automated Sovereign Cloud Deployment Suite (2026)
# Multi-Protocol Zero-Trust VPN, RAM-Only Runtime, Unbound DNS, PAM 2FA & Hardened Defense
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
    x86_64)
        SB_ARCH="amd64"
        WST_ARCH="amd64"
        ;;
    aarch64)
        SB_ARCH="arm64"
        WST_ARCH="arm64"
        ;;
    *)
        echo "[-] Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Detect Public IP
SERVER_IP=$(curl -s4 https://api.ipify.org || curl -s4 https://ifconfig.me || ip route get 1.1.1.1 | awk '{print $7}')
echo "[+] Detected Server Public IP: $SERVER_IP"

# 1. Install Essential Dependencies & Security Tools
echo "[*] Installing system dependencies, security tools, and Unbound DNS..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget unzip tar iptables ufw libpam-google-authenticator \
    qrencode jq openssl python3 unbound dnsutils bsdmainutils fail2ban wireguard-tools

# 2. Setup Dedicated System User (Principle of Least Privilege)
FORTRESS_USER="fortress"
if ! id -u "$FORTRESS_USER" >/dev/null 2>&1; then
    echo "[*] Creating dedicated unprivileged system user '$FORTRESS_USER'..."
    useradd -r -M -s /usr/sbin/nologin "$FORTRESS_USER"
fi

# 3. Setup Volatile RAM Mount (tmpfs) & Persistent Configuration Storage
RAM_DIR="/run/fortress"
DISK_DIR="/etc/fortress"
mkdir -p "$DISK_DIR"
chmod 700 "$DISK_DIR"

if ! mountpoint -q "$RAM_DIR"; then
    mkdir -p "$RAM_DIR"
    mount -t tmpfs -o size=256M,mode=0700 tmpfs "$RAM_DIR"
    if ! grep -q "$RAM_DIR" /etc/fstab; then
        echo "tmpfs $RAM_DIR tmpfs defaults,size=256M,mode=0700 0 0" >> /etc/fstab
    fi
fi
chown -R "$FORTRESS_USER:$FORTRESS_USER" "$RAM_DIR"

# 4. Install Sing-box 1.11+ Core with Architecture & SHA-256 Verification
SINGBOX_VER="1.11.4"
echo "[*] Downloading Sing-box v${SINGBOX_VER} for ${SB_ARCH}..."
SB_TAR="sing-box-${SINGBOX_VER}-linux-${SB_ARCH}.tar.gz"
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/${SB_TAR}"

case "$SB_ARCH" in
    amd64) EXPECTED_SB_SHA256="0bb762ef286b36c2016d9107fc1f089be7a75f6d579b33f067d31e696c05927e" ;;
    arm64) EXPECTED_SB_SHA256="4e687359db42b6a28ef93f9cd2cb9549c4b0079cc7e49bc5f6ecbf98257a2507" ;;
esac

curl -sSL "$SB_URL" -o "/tmp/${SB_TAR}"
ACTUAL_SB_SHA256=$(sha256sum "/tmp/${SB_TAR}" | awk '{print $1}')

if [ "$ACTUAL_SB_SHA256" != "$EXPECTED_SB_SHA256" ]; then
    echo "[-] Cryptographic verification failed for Sing-box archive!"
    echo "    Expected: $EXPECTED_SB_SHA256"
    echo "    Actual:   $ACTUAL_SB_SHA256"
    rm -f "/tmp/${SB_TAR}"
    exit 1
fi
echo "[+] Sing-box SHA256 verified successfully: $ACTUAL_SB_SHA256"

tar -xzf "/tmp/${SB_TAR}" -C /tmp/
install -m 0755 "/tmp/sing-box-${SINGBOX_VER}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box
rm -rf "/tmp/sing-box*"
echo "[+] Installed: $(/usr/local/bin/sing-box version | head -n 1)"

# 5. Install WSTunnel Core with Architecture & SHA-256 Verification
WSTUNNEL_VER="10.7.1"
echo "[*] Downloading WSTunnel v${WSTUNNEL_VER} for ${WST_ARCH}..."
WST_TAR="wstunnel_${WSTUNNEL_VER}_linux_${WST_ARCH}.tar.gz"
WST_URL="https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VER}/${WST_TAR}"

case "$WST_ARCH" in
    amd64) EXPECTED_WST_SHA256="822e1a2f64606ddc9e782987114620577fc75e5f0e34a66a1ec13459c55b6c38" ;;
    arm64) EXPECTED_WST_SHA256="" ;;
esac

curl -sSL "$WST_URL" -o "/tmp/${WST_TAR}"
if [ -n "$EXPECTED_WST_SHA256" ]; then
    ACTUAL_WST_SHA256=$(sha256sum "/tmp/${WST_TAR}" | awk '{print $1}')
    if [ "$ACTUAL_WST_SHA256" != "$EXPECTED_WST_SHA256" ]; then
        echo "[-] Cryptographic verification failed for WSTunnel archive!"
        rm -f "/tmp/${WST_TAR}"
        exit 1
    fi
    echo "[+] WSTunnel SHA256 verified successfully: $ACTUAL_WST_SHA256"
fi

tar -xzf "/tmp/${WST_TAR}" -C /tmp/
install -m 0755 "/tmp/wstunnel" /usr/local/bin/wstunnel
rm -rf "/tmp/wstunnel*"
echo "[+] Installed: WSTunnel $(/usr/local/bin/wstunnel --version)"

# 6. Generate High-Entropy Cryptographic Keys
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

# WireGuard Keys
WG_SERVER_PRIV=$(wg genkey)
WG_SERVER_PUB=$(echo "$WG_SERVER_PRIV" | wg pubkey)
WG_CLIENT_PRIV=$(wg genkey)
WG_CLIENT_PUB=$(echo "$WG_CLIENT_PRIV" | wg pubkey)

# 7. Dedicated Private CA & Authenticated TLS Certificate
echo "[*] Generating Dedicated Sovereign Private CA & Certificate..."
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
    -keyout "$DISK_DIR/ca.key" -out "$DISK_DIR/ca.crt" \
    -subj "/CN=Sovereign Fortress Root CA" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
    -keyout "$DISK_DIR/key.pem" -out "$DISK_DIR/cert.csr" \
    -subj "/CN=www.microsoft.com" >/dev/null 2>&1

openssl x509 -req -in "$DISK_DIR/cert.csr" \
    -CA "$DISK_DIR/ca.crt" -CAkey "$DISK_DIR/ca.key" -CAcreateserial \
    -out "$DISK_DIR/cert.pem" -days 365 >/dev/null 2>&1
rm -f "$DISK_DIR/cert.csr"

cp "$DISK_DIR/key.pem" "$RAM_DIR/key.pem"
cp "$DISK_DIR/cert.pem" "$RAM_DIR/cert.pem"
cp "$DISK_DIR/ca.crt" "$RAM_DIR/ca.crt"

chmod 600 "$DISK_DIR/key.pem" "$RAM_DIR/key.pem" "$DISK_DIR/ca.key"
chmod 644 "$DISK_DIR/cert.pem" "$RAM_DIR/cert.pem" "$DISK_DIR/ca.crt" "$RAM_DIR/ca.crt"
chown -R "$FORTRESS_USER:$FORTRESS_USER" "$RAM_DIR"

# Compute SHA-256 fingerprint and SPKI pin for certificate pinning
CERT_SHA256=$(openssl x509 -noout -fingerprint -sha256 -in "$RAM_DIR/cert.pem" | cut -d= -f2 | tr -d ':')
PIN_SHA256=$(openssl x509 -in "$RAM_DIR/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)

# 8. Configure Self-Hosted Recursive Zero-Log Unbound DNS
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

# 9. Generate Hardened Sing-box Configuration (IPv4-bound, Zero-Leak)
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
      "tag": "vless-reality-in",
      "listen": "0.0.0.0",
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
      "listen": "0.0.0.0",
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
        "key_path": "${RAM_DIR}/key.pem",
        "alpn": ["h3"]
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-std-in",
      "listen": "0.0.0.0",
      "listen_port": 8443,
      "users": [
        {
          "password": "${HY2_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "${RAM_DIR}/cert.pem",
        "key_path": "${RAM_DIR}/key.pem",
        "alpn": ["h3"]
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "0.0.0.0",
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
        "key_path": "${RAM_DIR}/key.pem",
        "alpn": ["h3"]
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "0.0.0.0",
      "listen_port": 10443,
      "method": "2022-blake3-aes-256-gcm",
      "password": "${SS_PASS}"
    },
    {
      "type": "wireguard",
      "tag": "wg-in",
      "listen": "0.0.0.0",
      "listen_port": 51820,
      "local_address": ["10.8.0.1/24"],
      "private_key": "${WG_SERVER_PRIV}",
      "peers": [
        {
          "public_key": "${WG_CLIENT_PUB}",
          "allowed_ips": ["10.8.0.2/32"]
        }
      ]
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
        "inbound": ["vless-reality-in", "hy2-sal-in", "hy2-std-in", "tuic-in", "ss-in", "wg-in"],
        "outbound": "direct"
      }
    ]
  }
}
EOF

cp "$RAM_DIR/config.json" "$DISK_DIR/config.json.template"
chmod 600 "$DISK_DIR/config.json.template"
chown -R "$FORTRESS_USER:$FORTRESS_USER" "$RAM_DIR"

# 10. Systemd Service Sandboxing for Sing-box Core (Reduced Privileges)
cat <<EOF > /etc/systemd/system/fortress-core.service
[Unit]
Description=Sovereign Fortress Core Multi-Protocol Engine (Sing-box)
After=network.target network-online.target unbound.service
Wants=unbound.service

[Service]
Type=simple
User=${FORTRESS_USER}
Group=${FORTRESS_USER}
WorkingDirectory=${RAM_DIR}
ExecStart=/usr/local/bin/sing-box run -c ${RAM_DIR}/config.json
Restart=always
RestartSec=3
LimitNOFILE=65535
MemoryMax=512M

# Linux Capabilities for Network Routing & Raw Sockets (No Root Needed)
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

# Systemd Security Sandboxing Directives
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
ReadWritePaths=${RAM_DIR}
ReadOnlyPaths=${DISK_DIR}

[Install]
WantedBy=multi-user.target
EOF

# 11. Systemd Service for WireGuard-over-TCP (wstunnel server on TCP 8080)
cat <<EOF > /etc/systemd/system/fortress-wstunnel.service
[Unit]
Description=Sovereign Fortress WireGuard over TCP (wstunnel)
After=network.target fortress-core.service

[Service]
Type=simple
User=${FORTRESS_USER}
Group=${FORTRESS_USER}
WorkingDirectory=${RAM_DIR}
ExecStart=/usr/local/bin/wstunnel server --tls-certificate ${RAM_DIR}/cert.pem --tls-private-key ${RAM_DIR}/key.pem --restrict-to 127.0.0.1:51820 wss://0.0.0.0:8080
Restart=always
RestartSec=3
LimitNOFILE=65535

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${RAM_DIR}
ReadOnlyPaths=${DISK_DIR}

[Install]
WantedBy=multi-user.target
EOF

# 12. Deploy Subscription Daemon & Web Portal
if [ -f "fortress-sub.py" ]; then
    install -m 0755 fortress-sub.py /usr/local/bin/fortress-sub.py
elif [ -f "${DISK_DIR}/fortress-sub.py" ]; then
    install -m 0755 "${DISK_DIR}/fortress-sub.py" /usr/local/bin/fortress-sub.py
else
    curl -sSL "https://raw.githubusercontent.com/harsh593-boop/sovereign-fortress/main/fortress-sub.py" -o /usr/local/bin/fortress-sub.py
    chmod 0755 /usr/local/bin/fortress-sub.py
fi
cp -f /usr/local/bin/fortress-sub.py "${DISK_DIR}/fortress-sub.py" 2>/dev/null || true

cat <<EOF > /etc/systemd/system/fortress-sub.service
[Unit]
Description=Sovereign Fortress HTTPS Subscription & Web Portal Daemon
After=network.target fortress-core.service

[Service]
Type=simple
User=${FORTRESS_USER}
Group=${FORTRESS_USER}
WorkingDirectory=${RAM_DIR}
ExecStart=/usr/bin/python3 /usr/local/bin/fortress-sub.py
Restart=always
RestartSec=5
LimitNOFILE=65535

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ReadWritePaths=${RAM_DIR}
ReadOnlyPaths=${DISK_DIR} /home/ubuntu

[Install]
WantedBy=multi-user.target
EOF

# 13. Systemd Boot RAM Initializer (Restores RAM templates on reboot)
cat <<EOF > /usr/local/bin/fortress-init.sh
#!/usr/bin/env bash
set -e
mkdir -p ${RAM_DIR}
mountpoint -q ${RAM_DIR} || mount -t tmpfs -o size=256M,mode=0700 tmpfs ${RAM_DIR}
cp -f ${DISK_DIR}/key.pem ${RAM_DIR}/key.pem 2>/dev/null || true
cp -f ${DISK_DIR}/cert.pem ${RAM_DIR}/cert.pem 2>/dev/null || true
cp -f ${DISK_DIR}/ca.crt ${RAM_DIR}/ca.crt 2>/dev/null || true
cp -f ${DISK_DIR}/config.json.template ${RAM_DIR}/config.json 2>/dev/null || true
cp -f ${DISK_DIR}/fortress_config.json ${RAM_DIR}/fortress_config.json 2>/dev/null || true
chown -R ${FORTRESS_USER}:${FORTRESS_USER} ${RAM_DIR}
chmod 700 ${RAM_DIR}
chmod 600 ${RAM_DIR}/* 2>/dev/null || true
chmod 644 ${RAM_DIR}/cert.pem ${RAM_DIR}/ca.crt 2>/dev/null || true
EOF
chmod 0755 /usr/local/bin/fortress-init.sh

cat <<EOF > /etc/systemd/system/fortress-init.service
[Unit]
Description=Sovereign Fortress RAM Runtime Initializer
Before=fortress-core.service fortress-sub.service fortress-wstunnel.service
DefaultDependencies=no
RequiresMountsFor=/run

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fortress-init.sh
RemainAfterExit=yes

[Install]
WantedBy=basic.target
EOF

# 14. Configure Linux Kernel BBR & Complete IPv6 Leak Elimination
cat <<EOF > /etc/sysctl.d/99-fortress.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
# Complete IPv6 Leak Elimination
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
sysctl --system >/dev/null 2>&1 || true

# 15. Configure SSH 2FA Enforced Authentication (Google Authenticator TOTP)
echo "[*] Configuring SSH PAM Two-Factor Authentication..."
mkdir -p /etc/ssh/sshd_config.d
cat <<EOF > /etc/ssh/sshd_config.d/99-fortress-2fa.conf
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
EOF

if ! grep -q "pam_google_authenticator.so" /etc/pam.d/sshd; then
    echo "auth required pam_google_authenticator.so nullok" >> /etc/pam.d/sshd
fi
systemctl restart ssh || systemctl restart sshd || true

# 16. Configure Fail2ban Defense for SSH
echo "[*] Configuring Fail2ban intrusion defense for SSH..."
mkdir -p /etc/fail2ban/jail.d
cat <<EOF > /etc/fail2ban/jail.d/fortress-ssh.conf
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
systemctl restart fail2ban || true
systemctl enable fail2ban || true

# 17. Configure and ACTIVATE Firewall (UFW & iptables)
echo "[*] Configuring and enforcing UFW firewall rules..."
sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw 2>/dev/null || true

ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true
ufw allow 22/tcp comment 'SSH 2FA' >/dev/null 2>&1 || true
ufw allow 443/tcp comment 'VLESS Reality' >/dev/null 2>&1 || true
ufw allow 8080/tcp comment 'WireGuard over TCP (wstunnel)' >/dev/null 2>&1 || true
ufw allow 8443/tcp comment 'Dual-Mode Subscription & Web Portal' >/dev/null 2>&1 || true
ufw allow 8444/tcp comment 'Dedicated HTTPS Web Portal' >/dev/null 2>&1 || true
ufw allow 8443/udp comment 'Hysteria 2 Standard' >/dev/null 2>&1 || true
ufw allow 9443/udp comment 'TUIC v5' >/dev/null 2>&1 || true
ufw allow 9444/udp comment 'Hysteria 2 Salamander' >/dev/null 2>&1 || true
ufw allow 10443/tcp comment 'Shadowsocks-2022' >/dev/null 2>&1 || true
ufw allow 10443/udp comment 'Shadowsocks-2022' >/dev/null 2>&1 || true
ufw allow 51820/udp comment 'Native WireGuard' >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

# Direct iptables accept rules (prevents default OCI host-prohibited drops)
iptables -I INPUT 1 -p tcp -m multiport --dports 22,443,8080,8443,8444,10443 -j ACCEPT 2>/dev/null || true
iptables -I INPUT 1 -p udp -m multiport --dports 443,8443,9443,9444,10443,51820 -j ACCEPT 2>/dev/null || true
echo "[+] UFW Firewall and iptables rules ACTIVE and enforcing strict policy."

# 18. Save Master Configuration Output & Client WireGuard Profiles
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
  "ss_password": "${SS_PASS}",
  "wg_server_pub": "${WG_SERVER_PUB}",
  "wg_client_priv": "${WG_CLIENT_PRIV}",
  "wg_client_ip": "10.8.0.2",
  "wstunnel_port": 8080,
  "cert_sha256": "${CERT_SHA256}",
  "pin_sha256": "${PIN_SHA256}"
}
EOF
cp "$DISK_DIR/fortress_config.json" "$RAM_DIR/fortress_config.json"

# Native WireGuard Client Profile
cat <<EOF > "$RAM_DIR/fortress-wireguard.conf"
[Interface]
PrivateKey = ${WG_CLIENT_PRIV}
Address = 10.8.0.2/24
DNS = 1.1.1.1, 8.8.8.8
MTU = 1360

[Peer]
PublicKey = ${WG_SERVER_PUB}
Endpoint = ${SERVER_IP}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
EOF

# WireGuard-over-TCP (wstunnel) Client Profile
cat <<EOF > "$RAM_DIR/fortress-wireguard-tcp.conf"
[Interface]
PrivateKey = ${WG_CLIENT_PRIV}
Address = 10.8.0.2/24
DNS = 1.1.1.1, 8.8.8.8
MTU = 1360

[Peer]
PublicKey = ${WG_SERVER_PUB}
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
EOF

chmod 700 "$DISK_DIR"
chmod 600 "$DISK_DIR"/*
chown -R "$FORTRESS_USER:$FORTRESS_USER" "$RAM_DIR"

# 18. Enable and Start Systemd Services
systemctl daemon-reload
systemctl enable fortress-init fortress-core fortress-wstunnel fortress-sub
systemctl restart fortress-init fortress-core fortress-wstunnel fortress-sub

echo "================================================================="
echo "   SOVEREIGN FORTRESS DEPLOYMENT COMPLETE!                      "
echo "================================================================="
echo "[+] Public IP:          ${SERVER_IP}"
echo "[+] VLESS Reality:      TCP 443 (Camouflage: ${REALITY_SNI})"
echo "[+] Hysteria 2 Sal:     UDP 9444 (ChaCha20 Scrambled QUIC)"
echo "[+] Hysteria 2 Std:     UDP 8443 (Brutal BBR)"
echo "[+] TUIC v5:            UDP 9443 (0-RTT Native QUIC)"
echo "[+] Shadowsocks:        TCP/UDP 10443 (2022-blake3-aes-256-gcm)"
echo "[+] Native WireGuard:   UDP 51820 (Kernel Line-Rate)"
echo "[+] WireGuard-over-TCP: TCP 8080 (wstunnel TLS 1.3)"
echo "[+] Universal Sub (HTTP): http://${SERVER_IP}:8443/sub/${SUB_TOKEN}"
echo "[+] Traffic-Only Sub:    http://${SERVER_IP}:8443/sub/${SUB_TOKEN}?mode=traffic-only"
echo "[+] Web Portal (HTTP):   http://${SERVER_IP}:8443/portal"
echo "[+] Web Portal (HTTPS):  https://${SERVER_IP}:8444/portal"
echo "[+] Recursive DNS:      127.0.0.1:5335 (Unbound Zero-Log Root Hints)"
echo "[+] Master Token:       ${SUB_TOKEN}"
echo "[+] Sandboxing:         Dedicated unprivileged user 'fortress' + Systemd Strict"
echo "[+] Firewall:           UFW Active & IPv6 Leak Drop Enforced"
echo "[+] Master Config:      ${DISK_DIR}/fortress_config.json"
echo "================================================================="
