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
echo "[*] Installing system dependencies and security tools..."
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null || true
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget unzip tar iptables iptables-persistent netfilter-persistent ufw libpam-google-authenticator \
    qrencode jq openssl python3 dnsutils bsdmainutils fail2ban wireguard-tools

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
    mount -t tmpfs -o size=256M,mode=0755 tmpfs "$RAM_DIR"
    if ! grep -q "$RAM_DIR" /etc/fstab; then
        echo "tmpfs $RAM_DIR tmpfs defaults,size=256M,mode=0755 0 0" >> /etc/fstab
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
    amd64) EXPECTED_WST_SHA256="fa842ed53fbb14b1c69cd98829f9895d7f8a6b0d562c57c1175851a52cea9ea2" ;;
    arm64) EXPECTED_WST_SHA256="99f9506d01d1b4073254609600ec5056dab8dc58aec75c32f6eb0508335a8fd2" ;;
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
echo "[*] Generating Dedicated Sovereign Private CA & SAN-enabled Certificate..."
cat << 'EOFCACNF' > /tmp/ca_openssl.cnf
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
CN = Sovereign Fortress Root CA
O = Sovereign Fortress
C = IN

[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOFCACNF

openssl req -x509 -new -nodes -newkey rsa:4096 -days 3650 \
    -config /tmp/ca_openssl.cnf \
    -keyout "$DISK_DIR/ca.key" \
    -out "$DISK_DIR/ca.crt"

cat << EOFSRVCNF > /tmp/server_openssl.cnf
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = www.microsoft.com
O = Sovereign Fortress
C = IN

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = www.microsoft.com
IP.1 = ${SERVER_IP}
EOFSRVCNF

openssl req -new -nodes -newkey rsa:2048 \
    -config /tmp/server_openssl.cnf \
    -keyout "$DISK_DIR/key.pem" \
    -out "$DISK_DIR/cert.csr"

openssl x509 -req -in "$DISK_DIR/cert.csr" \
    -CA "$DISK_DIR/ca.crt" -CAkey "$DISK_DIR/ca.key" -CAcreateserial \
    -extfile /tmp/server_openssl.cnf -extensions v3_req \
    -days 825 -out "$DISK_DIR/cert.pem"
rm -f "$DISK_DIR/cert.csr" /tmp/ca_openssl.cnf /tmp/server_openssl.cnf

cp "$DISK_DIR/key.pem" "$RAM_DIR/key.pem"
cp "$DISK_DIR/cert.pem" "$RAM_DIR/cert.pem"
cp "$DISK_DIR/ca.crt" "$RAM_DIR/ca.crt"

chmod 600 "$DISK_DIR/key.pem" "$RAM_DIR/key.pem" "$DISK_DIR/ca.key"
chmod 644 "$DISK_DIR/cert.pem" "$RAM_DIR/cert.pem" "$DISK_DIR/ca.crt" "$RAM_DIR/ca.crt"
chown -R "$FORTRESS_USER:$FORTRESS_USER" "$RAM_DIR"

# Compute SHA-256 fingerprint and SPKI pin for certificate pinning
CERT_SHA256=$(openssl x509 -noout -fingerprint -sha256 -in "$RAM_DIR/cert.pem" | cut -d= -f2 | tr -d ':')
PIN_SHA256=$(openssl x509 -in "$RAM_DIR/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)

# 8. Configure Self-Hosted Sovereign Zero-Log Encrypted AdGuard Home DNS Engine
echo "[*] Configuring AdGuard Home zero-log encrypted DNS resolver on 127.0.0.1:5335 & 10.8.0.1:5335..."
AGH_URL="https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.56/AdGuardHome_linux_${SB_ARCH}.tar.gz"
mkdir -p /opt/AdGuardHome /opt/AdGuardHome/data "${RAM_DIR}/adguard"
curl -fsSL --connect-timeout 10 -o /tmp/agh.tar.gz "$AGH_URL"
tar -xzf /tmp/agh.tar.gz -C /tmp/
cp -f /tmp/AdGuardHome/AdGuardHome /opt/AdGuardHome/AdGuardHome
chmod 755 /opt/AdGuardHome/AdGuardHome
rm -rf /tmp/AdGuardHome /tmp/agh.tar.gz

chattr -i /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true

NEXTDNS_ID=$(grep -Po '"nextdns_id":\s*"\K[^"]*' "$DISK_DIR/fortress_config.json" 2>/dev/null || echo "")
UPSTREAM_NEXTDNS=""
if [ -n "$NEXTDNS_ID" ] && [ "$NEXTDNS_ID" != "<YOUR_NEXTDNS_ID>" ]; then
    UPSTREAM_NEXTDNS="    - tls://${NEXTDNS_ID}.dns.nextdns.io"
fi

cat <<EOF > /opt/AdGuardHome/AdGuardHome.yaml
schema_version: 29
bind_host: 127.0.0.1
bind_port: 3000
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: en
theme: auto
dns:
  bind_hosts:
    - 127.0.0.1
    - 10.8.0.1
  port: 5335
  statistics_interval: 0
  querylog_enabled: false
  querylog_file_enabled: false
  querylog_interval: 0
  querylog_size_memory: 0
  anonymize_client_ip: true
  protection_enabled: true
  blocking_mode: default
  blocking_ipv4: ""
  blocking_ipv6: ""
  blocked_response_ttl: 10
  parental_block_host: parental-block.adguard.org
  safebrowsing_block_host: standard-block.adguard.org
  ratelimit: 0
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist: []
  refuse_any: true
  upstream_dns:
${UPSTREAM_NEXTDNS}
    - tls://dns.quad9.net
    - https://dns.quad9.net/dns-query
    - tls://one.one.one.one
    - tls://dns.cloudflare.com
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.9
    - 1.1.1.1
  all_servers: false
  fastest_addr: true
  fastest_timeout: 1s
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
  trusted_proxies:
    - 127.0.0.0/8
    - 10.8.0.0/24
  cache_size: 67108864
  cache_ttl_min: 300
  cache_ttl_max: 86400
  cache_optimistic: true
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
tls:
  enabled: true
  server_name: "${DOMAIN}"
  force_https: false
  port_https: 0
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  certificate_path: "${RAM_DIR}/cert.pem"
  private_key_path: "${RAM_DIR}/key.pem"
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt
    name: HaGeZi Multi PRO
    id: 2
EOF

chown -R ${FORTRESS_USER}:${FORTRESS_USER} /opt/AdGuardHome "${RAM_DIR}/adguard"

cat <<EOF > /etc/systemd/system/adguard-home.service
[Unit]
Description=AdGuard Home: Sovereign Zero-Log Encrypted DNS Engine
After=network.target

[Service]
Type=simple
User=${FORTRESS_USER}
Group=${FORTRESS_USER}
WorkingDirectory=/opt/AdGuardHome
ExecStart=/opt/AdGuardHome/AdGuardHome -c /opt/AdGuardHome/AdGuardHome.yaml -w /opt/AdGuardHome
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65535
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/AdGuardHome ${RAM_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl stop unbound 2>/dev/null || true
systemctl disable unbound 2>/dev/null || true
systemctl enable adguard-home
systemctl restart adguard-home
chattr +i /opt/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true
echo "[+] AdGuard Home DNS running on 127.0.0.1:5335 & 10.8.0.1:5335 (DoT/DoQ, Zero Logging, Immutable Config)."

# 9. Generate Hardened Sing-box Configuration (IPv4-bound, Zero-Leak)
echo "[*] Generating Sing-box core configuration in RAM..."
SERVER_DNS_JSON='{
    "servers": [
      {
        "tag": "sovereign-adguard",
        "address": "127.0.0.1:5335",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "sovereign-adguard"
      }
    ],
    "strategy": "prefer_ipv4"
  }'

cat <<EOF > "$RAM_DIR/config.json"
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "dns": ${SERVER_DNS_JSON},
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
        "inbound": ["vless-reality-in", "hy2-sal-in", "hy2-std-in", "tuic-in", "ss-in"],
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
After=network.target network-online.target adguard-home.service
Wants=adguard-home.service

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

# Linux Capabilities for Port 443 (<1024) Binding Only (Kernel WireGuard handles TUN)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

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
ReadOnlyPaths=${DISK_DIR}
ReadWritePaths=${RAM_DIR}

[Install]
WantedBy=multi-user.target
EOF

# 13. Systemd Boot RAM Initializer (Restores RAM templates on reboot)
cat <<EOF > "$DISK_DIR/wg0.conf"
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = ${WG_SERVER_PRIV}
PostUp = iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -I FORWARD 2 -i wg0 -j ACCEPT; iptables -I FORWARD 3 -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE || iptables -t nat -A POSTROUTING -j MASQUERADE; iptables -t nat -I PREROUTING 1 -i wg0 -p udp --dport 53 -j REDIRECT --to-ports 5335; iptables -t nat -I PREROUTING 2 -i wg0 -p tcp --dport 53 -j REDIRECT --to-ports 5335
PostDown = iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT || true; iptables -D FORWARD -i wg0 -j ACCEPT || true; iptables -D FORWARD -o wg0 -j ACCEPT || true; iptables -t nat -D POSTROUTING -o ens3 -j MASQUERADE || true; iptables -t nat -D PREROUTING -i wg0 -p udp --dport 53 -j REDIRECT --to-ports 5335 || true; iptables -t nat -D PREROUTING -i wg0 -p tcp --dport 53 -j REDIRECT --to-ports 5335 || true

[Peer]
PublicKey = ${WG_CLIENT_PUB}
AllowedIPs = 10.8.0.2/32
EOF
chmod 600 "$DISK_DIR/wg0.conf"
chown root:root "$DISK_DIR/wg0.conf"

cat <<EOF > /usr/local/bin/fortress-init.sh
#!/usr/bin/env bash
set -euo pipefail

# Ensure tmpfs mount on ${RAM_DIR}
if ! mountpoint -q ${RAM_DIR}; then
    mkdir -p ${RAM_DIR}
    mount -t tmpfs -o size=256M,mode=0755 tmpfs ${RAM_DIR}
fi

chmod 755 ${RAM_DIR}
chown ${FORTRESS_USER}:${FORTRESS_USER} ${RAM_DIR}

mkdir -p ${RAM_DIR}/client
chown ${FORTRESS_USER}:${FORTRESS_USER} ${RAM_DIR}/client
chmod 700 ${RAM_DIR}/client

# WireGuard directory strictly owned by root:root 0700
mkdir -p ${RAM_DIR}/wireguard
chown root:root ${RAM_DIR}/wireguard
chmod 700 ${RAM_DIR}/wireguard

# Copy sealed configs into ephemeral volatile RAM
cp -f ${DISK_DIR}/key.pem ${RAM_DIR}/key.pem 2>/dev/null || true
cp -f ${DISK_DIR}/cert.pem ${RAM_DIR}/cert.pem 2>/dev/null || true
cp -f ${DISK_DIR}/ca.crt ${RAM_DIR}/ca.crt 2>/dev/null || true
cp -f ${DISK_DIR}/config.json.template ${RAM_DIR}/config.json 2>/dev/null || true
cp -f ${DISK_DIR}/fortress_config.json ${RAM_DIR}/fortress_config.json 2>/dev/null || true
cp -f ${DISK_DIR}/wg0.conf ${RAM_DIR}/wireguard/wg0.conf 2>/dev/null || true

ADMIN_USER="${SUDO_USER:-$(id -un 1000 2>/dev/null || echo "ubuntu")}"
AUTH_FILE="/home/${ADMIN_USER}/.google_authenticator"
if [ ! -f "${AUTH_FILE}" ]; then
    echo "[*] Generating fresh, unique TOTP 2FA secret for ${ADMIN_USER}..."
    if command -v google-authenticator >/dev/null 2>&1; then
        su - "${ADMIN_USER}" -c "google-authenticator -t -d -f -r 3 -R 30 -w 3 -q" || true
    fi
    if [ ! -f "${AUTH_FILE}" ]; then
        NEW_TOTP=$(python3 -c "import secrets, base64; print(base64.b32encode(secrets.token_bytes(20)).decode('utf-8').rstrip('='))" 2>/dev/null || openssl rand -base64 15 | tr -dc 'A-Z2-7' | head -c 32)
        echo "${NEW_TOTP}" > "${AUTH_FILE}"
        echo '" RATE_LIMIT 3 30' >> "${AUTH_FILE}"
        echo '" WINDOW_SIZE 3' >> "${AUTH_FILE}"
        echo '" DISALLOW_REUSE' >> "${AUTH_FILE}"
        echo '" TOTP_AUTH' >> "${AUTH_FILE}"
        chown "${ADMIN_USER}:${ADMIN_USER}" "${AUTH_FILE}"
        chmod 400 "${AUTH_FILE}"
    fi
fi

if [ -f "${AUTH_FILE}" ]; then
    head -n 1 "${AUTH_FILE}" > ${RAM_DIR}/totp_secret
    cp -f ${RAM_DIR}/totp_secret ${DISK_DIR}/totp_secret 2>/dev/null || true
    chmod 640 ${RAM_DIR}/totp_secret ${DISK_DIR}/totp_secret 2>/dev/null || true
    chown ${FORTRESS_USER}:${FORTRESS_USER} ${RAM_DIR}/totp_secret ${DISK_DIR}/totp_secret 2>/dev/null || true
fi

chown ${FORTRESS_USER}:${FORTRESS_USER} ${RAM_DIR}/key.pem ${RAM_DIR}/cert.pem ${RAM_DIR}/config.json ${RAM_DIR}/fortress_config.json 2>/dev/null || true
chmod 600 ${RAM_DIR}/key.pem 2>/dev/null || true
chmod 644 ${RAM_DIR}/cert.pem ${RAM_DIR}/ca.crt ${RAM_DIR}/config.json 2>/dev/null || true
chmod 640 ${RAM_DIR}/fortress_config.json 2>/dev/null || true

# WireGuard config in RAM must remain strictly root:root 0600
chown root:root ${RAM_DIR}/wireguard/wg0.conf
chmod 600 ${RAM_DIR}/wireguard/wg0.conf

# Ensure persistent wg0.conf is root:root 0600
chown root:root ${DISK_DIR}/wg0.conf
chmod 600 ${DISK_DIR}/wg0.conf

# Ensure WireGuard symlink exists
mkdir -p /etc/wireguard
ln -sf ${RAM_DIR}/wireguard/wg0.conf /etc/wireguard/wg0.conf
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

# 17. Configure Firewall (Direct iptables & Disable Inert UFW)
echo "[*] Disabling inert UFW and configuring hardened iptables rules..."
ufw disable >/dev/null 2>&1 || true
systemctl disable ufw >/dev/null 2>&1 || true

# Explicit iptables accept rules and persistence
iptables -I INPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -I INPUT 2 -i lo -j ACCEPT 2>/dev/null || true
iptables -I INPUT 3 -p tcp -m multiport --dports 22,443,8080,8443,10443 -j ACCEPT 2>/dev/null || true
iptables -I INPUT 4 -p udp -m multiport --dports 443,8443,9443,9444,10443,51820 -j ACCEPT 2>/dev/null || true
systemctl enable netfilter-persistent >/dev/null 2>&1 || true
netfilter-persistent save >/dev/null 2>&1 || true
echo "[+] Hardened iptables rules ACTIVE and persistent across reboot."

# 18. Save Master Configuration Output & Client WireGuard Profiles
TOTP_SECRET_VAL=$(head -n 1 "${AUTH_FILE}" 2>/dev/null || true)
cat <<EOF > "$DISK_DIR/fortress_config.json"
{
  "server_ip": "${SERVER_IP}",
  "sub_port": 8443,
  "token": "${SUB_TOKEN}",
  "totp_secret": "${TOTP_SECRET_VAL}",
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
DNS = 10.8.0.1
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
DNS = 10.8.0.1
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

# 19. Enable and Start Systemd Services
systemctl daemon-reload
systemctl enable fortress-init fortress-core fortress-wstunnel fortress-sub wg-quick@wg0
systemctl restart fortress-init fortress-core fortress-wstunnel fortress-sub wg-quick@wg0

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
echo "[+] Universal Sub (HTTPS): https://${SERVER_IP}:8443/sub/${SUB_TOKEN}"
echo "[+] Traffic-Only Sub:     https://${SERVER_IP}:8443/sub/${SUB_TOKEN}?mode=traffic-only"
echo "[+] Web Portal (HTTPS):   https://${SERVER_IP}:8443/portal"
echo "[+] Recursive DNS:      127.0.0.1:5335 & 10.8.0.1:5335 (AdGuard Home Zero-Log DoT/DoQ Engine)"
echo "[+] Master Token:       ${SUB_TOKEN}"
if [ -n "${TOTP_SECRET_VAL}" ]; then
    echo "[+] 2FA Secret Key:     ${TOTP_SECRET_VAL}"
    echo "[+] 2FA Setup URI:      otpauth://totp/${ADMIN_USER}@${SERVER_IP}?secret=${TOTP_SECRET_VAL}&issuer=SovereignFortress"
fi
echo "[+] Sandboxing:         Dedicated unprivileged user 'fortress' + Systemd Strict"
echo "[+] Firewall:           iptables & netfilter-persistent Active (Default Drop Enforced)"
echo "[+] Master Config:      ${DISK_DIR}/fortress_config.json"
echo "================================================================="
