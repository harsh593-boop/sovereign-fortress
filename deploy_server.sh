#!/usr/bin/env bash
# ==============================================================================
# Sovereign Fortress — Automated Sovereign Cloud Deployment Suite (2026)
# Multi-Protocol test deployment with AdGuard Home DNS and PAM 2FA
# ==============================================================================
set -euo pipefail
umask 077
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "================================================================="
echo "   SOVEREIGN FORTRESS: COMPREHENSIVE SERVER INSTALLER           "
echo "   Review secrets, routing and logging before production use     "
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

# Detect Public IP (allow an explicit value for restricted/offline environments)
SERVER_IP="${FORTRESS_SERVER_IP:-$(curl -s4 https://api.ipify.org || curl -s4 https://ifconfig.me || ip route get 1.1.1.1 | awk '{print $7}')}"
if ! python3 - "$SERVER_IP" <<'PY'
import ipaddress, sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
then
    echo "[-] This release requires a numeric IPv4 endpoint; set FORTRESS_SERVER_IP."
    exit 1
fi
if [[ ! "${FORTRESS_AGH_SHA256:-}" =~ ^[a-fA-F0-9]{64}$ ]] || [ ! -f fortress-sub.py ] || [ ! -f fortress-init.sh ]; then
    echo "[-] Supply the reviewed fortress-sub.py, fortress-init.sh and verified FORTRESS_AGH_SHA256 before installing."
    exit 1
fi

# This installer still generates fresh keys and certificates. Never silently
# invalidate existing clients or replace an active deployment on a rerun.
if [ -e /etc/fortress/fortress_config.json ] || [ -e /etc/fortress/ca.key ] || [ -e /etc/fortress/wg0.conf ]; then
    echo "[-] Existing installation detected. Refusing to rotate live credentials or certificates."
    echo "[-] Review migration/rotation manually; this installer is first-install only."
    exit 1
fi
DOMAIN="${FORTRESS_DOMAIN:-fortress-portal.duckdns.org}"
# DOMAIN is embedded in certificate/configuration heredocs. Reject values that
# could alter those files or produce misleading subscription URLs.
if [[ -z "$DOMAIN" || "$DOMAIN" =~ [^A-Za-z0-9._:\-\[\]] ]]; then
    echo "[-] FORTRESS_DOMAIN must be a hostname or IP literal without whitespace or control characters."
    exit 1
fi
echo "[+] Detected Server Public IP: $SERVER_IP"

# 1. Install Essential Dependencies & Security Tools
echo "[*] Installing system dependencies and security tools..."
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null || true
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget unzip tar iptables iptables-persistent netfilter-persistent ufw libpam-google-authenticator \
    qrencode jq openssl python3 dnsutils bsdmainutils fail2ban wireguard-tools unattended-upgrades apt-listchanges

# Security updates are automatic; kernel reboot is never automatic. ESM remains
# unavailable until the operator attaches Ubuntu Pro or migrates to supported LTS.
cat <<'EOF' > /etc/apt/apt.conf.d/52-fortress-unattended-upgrades
Unattended-Upgrade::Origins-Pattern {
  "origin=Ubuntu,codename=${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Package-Blacklist { "sing-box"; "wstunnel"; "AdGuardHome"; };
EOF
cat <<'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Determine the egress interface from the active default route.  Do not assume
# a cloud-provider-specific name such as ens3.
WAN_IF="${FORTRESS_WAN_IF:-$(ip -4 route show default 2>/dev/null | awk 'NR == 1 {print $5}')}"
if [ -z "$WAN_IF" ]; then
    echo "[-] Unable to determine the default IPv4 interface."
    exit 1
fi

# 2. Setup Dedicated System User (Principle of Least Privilege)
FORTRESS_USER="fortress"
if ! id -u "$FORTRESS_USER" >/dev/null 2>&1; then
    echo "[*] Creating dedicated unprivileged system user '$FORTRESS_USER'..."
    useradd -r -M -s /usr/sbin/nologin "$FORTRESS_USER"
fi
FORTRESS_UID="$(id -u "$FORTRESS_USER")"
FORTRESS_GID="$(id -g "$FORTRESS_USER")"

# 3. Setup Volatile RAM Mount (tmpfs) & Persistent Configuration Storage
RAM_DIR="/run/fortress"
DISK_DIR="/etc/fortress"
STATE_DIR="/var/lib/fortress/subscription"
install -d -m 0700 -o "$FORTRESS_USER" -g "$FORTRESS_USER" "$STATE_DIR"
mkdir -p "$DISK_DIR"
chmod 700 "$DISK_DIR"

ensure_tmpfs_mount() {
    local target="$1"
    local options="$2"
    local fstype

    mkdir -p "$target"
    if mountpoint -q "$target"; then
        fstype="$(findmnt -n -o FSTYPE --target "$target" 2>/dev/null || true)"
        if [ "$fstype" != "tmpfs" ]; then
            echo "[-] $target is mounted as $fstype, refusing to replace it."
            return 1
        fi
        mount -o "remount,$options" "$target"
    else
        mount -t tmpfs -o "$options" tmpfs "$target"
    fi

    if ! awk -v target="$target" '$2 == target { found=1 } END { exit !found }' /etc/fstab; then
        printf 'tmpfs %s tmpfs %s 0 0\n' "$target" "$options" >> /etc/fstab
    fi
}

ensure_tmpfs_mount "$RAM_DIR" "size=256M,mode=0700"
if [ "$(findmnt -n -o FSTYPE --target "$RAM_DIR" 2>/dev/null || true)" != "tmpfs" ]; then
    echo "[-] Refusing to continue: ${RAM_DIR} is not mounted as tmpfs."
    exit 1
fi
chown -R "$FORTRESS_USER:$FORTRESS_USER" "$RAM_DIR"

# 4. Install current pinned core with architecture and SHA-256 verification
SINGBOX_VER="1.14.2"
echo "[*] Downloading Sing-box v${SINGBOX_VER} for ${SB_ARCH}..."
SB_TAR="sing-box-${SINGBOX_VER}-linux-${SB_ARCH}.tar.gz"
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/${SB_TAR}"

case "$SB_ARCH" in
    amd64) EXPECTED_SB_SHA256="a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6" ;;
    arm64) EXPECTED_SB_SHA256="b43a1fb1bda131c6653576741ce527eb2bdeab7c9308ca90ee8b972abb7e4a7f" ;;
esac

curl -fSL --connect-timeout 15 --max-time 180 "$SB_URL" -o "${WORK_DIR}/${SB_TAR}"
printf '%s  %s\n' "$EXPECTED_SB_SHA256" "${WORK_DIR}/${SB_TAR}" | sha256sum -c - >/dev/null
tar -xzf "${WORK_DIR}/${SB_TAR}" -C "$WORK_DIR"
install -m 0755 "${WORK_DIR}/sing-box-${SINGBOX_VER}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box
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

curl -fSL --connect-timeout 15 --max-time 180 "$WST_URL" -o "${WORK_DIR}/${WST_TAR}"
printf '%s  %s\n' "$EXPECTED_WST_SHA256" "${WORK_DIR}/${WST_TAR}" | sha256sum -c - >/dev/null
tar -xzf "${WORK_DIR}/${WST_TAR}" -C "$WORK_DIR"
install -m 0755 "${WORK_DIR}/wstunnel" /usr/local/bin/wstunnel
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
cat << 'EOFCACNF' > "$WORK_DIR/ca_openssl.cnf"
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
    -config "$WORK_DIR/ca_openssl.cnf" \
    -keyout "$DISK_DIR/ca.key" \
    -out "$DISK_DIR/ca.crt"

cat << EOFSRVCNF > "$WORK_DIR/server_openssl.cnf"
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = ${DOMAIN}
O = Sovereign Fortress
C = IN

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${DOMAIN}
IP.1 = ${SERVER_IP}
EOFSRVCNF

openssl req -new -nodes -newkey rsa:2048 \
    -config "$WORK_DIR/server_openssl.cnf" \
    -keyout "$DISK_DIR/key.pem" \
    -out "$DISK_DIR/cert.csr"

openssl x509 -req -in "$DISK_DIR/cert.csr" \
    -CA "$DISK_DIR/ca.crt" -CAkey "$DISK_DIR/ca.key" -CAcreateserial \
    -extfile "$WORK_DIR/server_openssl.cnf" -extensions v3_req \
    -days 825 -out "$DISK_DIR/cert.pem"
rm -f "$DISK_DIR/cert.csr" "$WORK_DIR/ca_openssl.cnf" "$WORK_DIR/server_openssl.cnf"

cp "$DISK_DIR/key.pem" "$RAM_DIR/key.pem"
cp "$DISK_DIR/cert.pem" "$RAM_DIR/cert.pem"
cp "$DISK_DIR/ca.crt" "$RAM_DIR/ca.crt"

chmod 600 "$DISK_DIR/key.pem" "$RAM_DIR/key.pem" "$DISK_DIR/ca.key"
chmod 644 "$DISK_DIR/cert.pem" "$RAM_DIR/cert.pem" "$DISK_DIR/ca.crt" "$RAM_DIR/ca.crt"
chown -R "$FORTRESS_USER:$FORTRESS_USER" "$RAM_DIR"

# Compute SHA-256 fingerprint and SPKI pin for certificate pinning
CERT_SHA256=$(openssl x509 -noout -fingerprint -sha256 -in "$RAM_DIR/cert.pem" | cut -d= -f2 | tr -d ':')
PIN_SHA256=$(openssl x509 -in "$RAM_DIR/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)

# 8. Configure self-hosted AdGuard Home DNS with disabled application query logs
echo "[*] Configuring AdGuard Home on 127.0.0.1:5335 & 10.8.0.1:5335..."
AGH_VER="0.107.79"
AGH_URL="https://github.com/AdguardTeam/AdGuardHome/releases/download/v${AGH_VER}/AdGuardHome_linux_${SB_ARCH}.tar.gz"
case "$SB_ARCH" in
    amd64) EXPECTED_AGH_SHA256="c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f" ;;
    arm64) EXPECTED_AGH_SHA256="3f7893c18e8aaadc456d0452839190561c306ca95175a2254958be80a769c1ae" ;;
esac
if [ -n "${FORTRESS_AGH_SHA256:-}" ] && [ "${FORTRESS_AGH_SHA256,,}" != "$EXPECTED_AGH_SHA256" ]; then
    echo "[-] FORTRESS_AGH_SHA256 does not match the reviewed pinned archive."
    exit 1
fi
FORTRESS_AGH_SHA256="$EXPECTED_AGH_SHA256"
AGH_DIR="/opt/AdGuardHome"
AGH_DATA_DIR="${AGH_DIR}/data"
AGH_CONFIG="${AGH_DIR}/AdGuardHome.yaml"
mkdir -p "$AGH_DIR" "$AGH_DATA_DIR" "${RAM_DIR}/adguard"
curl -fsSL --connect-timeout 15 --max-time 180 -o "$WORK_DIR/agh.tar.gz" "$AGH_URL"
printf '%s  %s\n' "$FORTRESS_AGH_SHA256" "$WORK_DIR/agh.tar.gz" | sha256sum -c - >/dev/null
tar -xzf "$WORK_DIR/agh.tar.gz" -C "$WORK_DIR"
install -m 0755 "$WORK_DIR/AdGuardHome/AdGuardHome" "$AGH_DIR/AdGuardHome"

# Mount AdGuard Home working data on volatile RAM. This minimizes local
# application persistence; it cannot prevent provider, kernel, or host logging.
ensure_tmpfs_mount "$AGH_DATA_DIR" "size=32M,mode=0700,uid=${FORTRESS_UID},gid=${FORTRESS_GID}"
if [ "$(findmnt -n -o FSTYPE --target "$AGH_DATA_DIR" 2>/dev/null || true)" != "tmpfs" ]; then
    echo "[-] Refusing to continue: ${AGH_DATA_DIR} is not mounted as tmpfs."
    exit 1
fi

# The configuration is root-owned and readable by the service, while only the
# data directory is writable by AdGuard Home.  Remove an old immutable bit
# before rewriting so repeated deployments remain safe and idempotent.
if [ -e "$AGH_CONFIG" ]; then
    chattr -i "$AGH_CONFIG" 2>/dev/null || true
fi

# Generate DNSCrypt configuration if not present
if [ ! -f "$DISK_DIR/dnscrypt.yaml" ]; then
    python3 - <<PY
import subprocess, re
def gen_keys(alg):
    out = subprocess.check_output(['openssl', 'genpkey', '-algorithm', alg, '-text']).decode()
    m_priv = re.search(r'priv:\s*([0-9a-f:\s]+?)\s*pub:', out, re.I)
    priv_hex = re.sub(r'[^0-9a-fA-F]', '', m_priv.group(1)).upper()
    m_pub = re.search(r'pub:\s*([0-9a-f:\s]+)', out, re.I)
    pub_hex = re.sub(r'[^0-9a-fA-F]', '', m_pub.group(1))[:64].upper()
    return priv_hex, pub_hex

priv_ed, pub_ed = gen_keys('ed25519')
priv_x, pub_x = gen_keys('x25519')
domain = "${DOMAIN}"
prov = f"2.dnscrypt-cert.{domain}" if domain else "2.dnscrypt-cert.fortress"
content = (
    f"provider_name: {prov}\n"
    f"public_key: {pub_ed}\n"
    f"private_key: {priv_ed}{pub_ed}\n"
    f"resolver_secret: {priv_x}\n"
    f"resolver_public: {pub_x}\n"
    f"es_version: 1\n"
    f"certificate_ttl: 0s\n"
)
with open("$DISK_DIR/dnscrypt.yaml", "w") as f:
    f.write(content)
PY
    chmod 0600 "$DISK_DIR/dnscrypt.yaml"
    chown root:"$FORTRESS_USER" "$DISK_DIR/dnscrypt.yaml"
fi
install -m 0600 -o "$FORTRESS_USER" -g "$FORTRESS_USER" "$DISK_DIR/dnscrypt.yaml" "${RAM_DIR}/adguard/dnscrypt.yaml"

cat <<EOF > "$AGH_CONFIG"
schema_version: 29
http:
  address: 127.0.0.1:3000
  pprof:
    enabled: false
    port: 6060
users: []
querylog:
  enabled: false
  file_enabled: false
  interval: 24h
  size_memory: 0
statistics:
  enabled: false
  interval: 24h
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: en
theme: auto
log:
  enabled: false
  file: ""
  verbose: false
dns:
  bind_hosts:
    - 0.0.0.0
  port: 5335
  anonymize_client_ip: true
  protection_enabled: true
  blocking_mode: default
  blocking_ipv4: ""
  blocking_ipv6: ""
  blocked_response_ttl: 10
  parental_block_host: parental-block.adguard.org
  safebrowsing_block_host: standard-block.adguard.org
  ratelimit: 100
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist:
    - 127.0.0.1
    - 10.8.0.1
  refuse_any: true
  upstream_dns:
    - https://dns.quad9.net/dns-query
    - tls://dns.quad9.net
    - https://cloudflare-dns.com/dns-query
    - quic://dns.adguard-dns.com
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.9
    - 1.1.1.1
  upstream_mode: parallel
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
  cache_size: 4194304
  cache_ttl_min: 300
  cache_ttl_max: 86400
  cache_optimistic: true
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: false
  use_private_ptr_resolvers: false
  serve_plain_dns: true
tls:
  enabled: true
  server_name: "${DOMAIN}"
  force_https: false
  port_https: 8445
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 5443
  dnscrypt_config_file: "${RAM_DIR}/adguard/dnscrypt.yaml"
  allow_unencrypted_doh: false
  certificate_path: "${RAM_DIR}/cert.pem"
  private_key_path: "${RAM_DIR}/key.pem"
filters: []
whitelist_filters: []
user_rules: []
# Add reviewed filter lists out-of-band. No third-party lists are silently fetched.
EOF

for required in \
    'querylog:' \
    '  file_enabled: false' \
    'statistics:'; do
    if ! grep -Fq "$required" "$AGH_CONFIG"; then
        echo "[-] AdGuard Home privacy setting missing: $required"
        exit 1
    fi
done

chown root:root "$AGH_DIR" "$AGH_DIR/AdGuardHome"
chown root:"$FORTRESS_USER" "$AGH_CONFIG"
chmod 0755 "$AGH_DIR" "$AGH_DIR/AdGuardHome"
chmod 0640 "$AGH_CONFIG"
chown "$FORTRESS_USER:$FORTRESS_USER" "$AGH_DATA_DIR" "${RAM_DIR}/adguard"

cat <<EOF > /etc/systemd/system/adguard-home.service
[Unit]
Description=AdGuard Home: Volatile query-log-disabled DNS Engine
After=network.target fortress-init.service wg-quick@wg0.service
Requires=fortress-init.service wg-quick@wg0.service
RequiresMountsFor=${RAM_DIR} ${AGH_DATA_DIR}

[Service]
Type=simple
User=${FORTRESS_USER}
Group=${FORTRESS_USER}
WorkingDirectory=/opt/AdGuardHome
ExecStart=/opt/AdGuardHome/AdGuardHome -c ${RAM_DIR}/adguard/AdGuardHome.yaml -w ${RAM_DIR}/adguard
Restart=always
RestartSec=3
StandardOutput=null
StandardError=null
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65535
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${RAM_DIR}/adguard
NoNewPrivileges=true
LimitCORE=0
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl stop unbound 2>/dev/null || true
systemctl disable unbound 2>/dev/null || true
systemctl enable adguard-home
echo "[+] AdGuard Home configured; it will start after WireGuard creates 10.8.0.1."

# 9. Generate hardened Sing-box configuration (IPv4-bound reference profile)
echo "[*] Generating Sing-box core configuration in RAM..."
SERVER_DNS_JSON=$(cat <<EOF
{
  "servers": [
    {
      "type": "tls",
      "tag": "sovereign-adguard",
      "server": "127.0.0.1",
      "server_port": 853,
      "tls": {"server_name": "${DOMAIN}"}
    }
  ],
  "strategy": "ipv4_only"
}
EOF
)

cat <<EOF > "$RAM_DIR/config.json"
{
  "log": {"disabled": true},
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
            "server_port": 443,
            "domain_resolver": "sovereign-adguard"
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
    }
  ],
  "route": {
    "default_domain_resolver": "sovereign-adguard",
    "auto_detect_interface": true,
    "rules": [
      {
        "ip_cidr": ["10.8.0.1/32", "127.0.0.1/32"],
        "port": 853,
        "outbound": "direct"
      },
      {
        "action": "resolve",
        "strategy": "ipv4_only"
      },
      {
        "ip_is_private": true,
        "action": "reject"
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
After=network.target network-online.target fortress-init.service adguard-home.service
Requires=fortress-init.service adguard-home.service

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
StandardOutput=null
StandardError=null

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
After=network.target fortress-init.service wg-quick@wg0.service
Requires=fortress-init.service wg-quick@wg0.service

[Service]
Type=simple
User=${FORTRESS_USER}
Group=${FORTRESS_USER}
WorkingDirectory=${RAM_DIR}
ExecStart=/usr/local/bin/wstunnel server --tls-certificate ${RAM_DIR}/cert.pem --tls-private-key ${RAM_DIR}/key.pem --restrict-to 127.0.0.1:51820 wss://0.0.0.0:8080
Restart=always
RestartSec=3
LimitNOFILE=65535
StandardOutput=null
StandardError=null

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
    echo "[-] fortress-sub.py is missing locally; refusing an unpinned remote download."
    echo "[-] Supply the reviewed script explicitly before deploying."
    exit 1
fi
cp -f /usr/local/bin/fortress-sub.py "${DISK_DIR}/fortress-sub.py" 2>/dev/null || true

cat <<EOF > /etc/systemd/system/fortress-sub.service
[Unit]
Description=Sovereign Fortress HTTPS Subscription & Web Portal Daemon
After=network.target fortress-init.service fortress-core.service
Requires=fortress-init.service
RequiresMountsFor=${RAM_DIR} ${STATE_DIR}

[Service]
Type=simple
User=${FORTRESS_USER}
Group=${FORTRESS_USER}
WorkingDirectory=${RAM_DIR}
ExecStart=/usr/bin/python3 /usr/local/bin/fortress-sub.py
Restart=always
RestartSec=5
LimitNOFILE=65535
StandardOutput=null
StandardError=null

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ReadOnlyPaths=${DISK_DIR}
ReadWritePaths=${RAM_DIR} ${STATE_DIR}
LimitCORE=0
PrivateTmp=true
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF

# 13. Systemd Boot RAM Initializer (Restores RAM templates on reboot)
cat <<EOF > "$DISK_DIR/wg0.conf"
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = ${WG_SERVER_PRIV}
# Plain DNS redirection intentionally omitted; clients use private DoT/DoH/DoQ.

[Peer]
PublicKey = ${WG_CLIENT_PUB}
AllowedIPs = 10.8.0.2/32
EOF
chmod 600 "$DISK_DIR/wg0.conf"
chown root:root "$DISK_DIR/wg0.conf"

install -m 0755 fortress-init.sh /usr/local/bin/fortress-init.sh
install -m 0755 fortress-adguard-update.sh /usr/local/sbin/fortress-adguard-update.sh
cat <<'EOF' > /etc/systemd/system/fortress-adguard-update.service
[Unit]
Description=Fortress verified AdGuard Home official self-update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fortress-adguard-update.sh
User=root
NoNewPrivileges=false
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/opt/AdGuardHome /run/fortress /root/fortress-backups
StandardOutput=null
StandardError=null
EOF
cat <<'EOF' > /etc/systemd/system/fortress-adguard-update.timer
[Unit]
Description=Weekly Fortress AdGuard Home update check

[Timer]
OnCalendar=Sun *-*-* 04:20:00
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat <<EOF > /etc/systemd/system/fortress-init.service
[Unit]
Description=Sovereign Fortress RAM Runtime Initializer
Before=fortress-core.service fortress-sub.service fortress-wstunnel.service wg-quick@wg0.service adguard-home.service
After=local-fs.target
RequiresMountsFor=${RAM_DIR} ${STATE_DIR}

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fortress-init.sh
RemainAfterExit=yes

[Install]
WantedBy=basic.target
EOF

# 14. Configure the first-install IPv4-only server policy (not a client kill switch)
cat <<EOF > /etc/sysctl.d/99-fortress.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
# IPv4-only server listeners; this does not control physical client interfaces
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
if ! sysctl --system >/dev/null 2>&1; then
    echo "[-] Failed to apply the required IPv4/IPv6 sysctl policy."
    exit 1
fi
for key in net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.lo.disable_ipv6; do
    if [ "$(sysctl -n "$key" 2>/dev/null || echo 0)" != "1" ]; then
        echo "[-] IPv6 disable policy was not applied: $key"
        exit 1
    fi
done

# Keep service diagnostics in volatile journal storage. This reduces local
# persistence without making a host/provider zero-log claim.
mkdir -p /etc/systemd/journald.conf.d
cat <<'EOF' > /etc/systemd/journald.conf.d/fortress.conf
[Journal]
Storage=volatile
RuntimeMaxUse=32M
SystemMaxUse=32M
ForwardToSyslog=no
EOF
systemctl restart systemd-journald
if ! grep -Eq '^Storage=volatile$|^Storage[[:space:]]*=[[:space:]]*volatile$' /etc/systemd/journald.conf.d/fortress.conf \
    || ! grep -Eq '^ForwardToSyslog=no$|^ForwardToSyslog[[:space:]]*=[[:space:]]*no$' /etc/systemd/journald.conf.d/fortress.conf; then
    echo "[-] Journald privacy policy was not written as expected."
    exit 1
fi
# Existing provider, kernel, backup, or pre-deployment logs are outside this
# script's control and must be reviewed separately; no zero-log claim is made.

# 15. SSH policy changes are opt-in and require an independently enrolled admin.
if [ "${FORTRESS_CONFIGURE_SSH_2FA:-0}" = "1" ]; then
if [ -z "${FORTRESS_ADMIN_USER:-}" ] || ! id "$FORTRESS_ADMIN_USER" >/dev/null 2>&1 \
    || [ ! -f "/home/${FORTRESS_ADMIN_USER}/.google_authenticator" ]; then
    echo "[-] Enroll the specified admin in SSH 2FA and verify recovery access first."
    exit 1
fi
echo "[*] Configuring SSH PAM Two-Factor Authentication..."
mkdir -p /etc/ssh/sshd_config.d
cat <<EOF > /etc/ssh/sshd_config.d/99-fortress-2fa.conf
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
EOF

if grep -q "pam_google_authenticator.so" /etc/pam.d/sshd; then
    sed -i -E '/pam_google_authenticator\.so/ s/[[:space:]]+nullok([[:space:]]|$)/\1/g' /etc/pam.d/sshd
else
    echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
fi
if sshd -t; then
    systemctl restart ssh || systemctl restart sshd || true
else
    echo "[-] sshd configuration validation failed; leaving the running daemon unchanged."
    exit 1
fi

# 16. Configure Fail2ban Defense for SSH
echo "[*] Configuring Fail2ban intrusion defense for SSH..."
mkdir -p /etc/fail2ban/jail.d
cat <<EOF > /etc/fail2ban/jail.d/fortress-ssh.conf
[sshd]
enabled = true
port = 22
filter = sshd
backend = systemd
maxretry = 3
bantime = 3600
findtime = 600
EOF
systemctl restart fail2ban || true
systemctl enable fail2ban || true
fi

# 17. Configure Firewall (Direct iptables & Disable Inert UFW)
echo "[*] Disabling inert UFW and configuring hardened iptables rules..."
ufw disable >/dev/null 2>&1 || true
systemctl disable ufw >/dev/null 2>&1 || true

# Explicit rules and default-deny policies.  Rules are checked before adding
# so rerunning the installer does not grow duplicate entries.
iptables -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 2 -i lo -j ACCEPT
iptables -C INPUT -p tcp -m multiport --dports 22,443,853,5443,8080,8443,8445,10443 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 3 -p tcp -m multiport --dports 22,443,853,5443,8080,8443,8445,10443 -j ACCEPT
iptables -C INPUT -p udp -m multiport --dports 443,853,5443,8443,9443,9444,10443,51820 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 4 -p udp -m multiport --dports 443,853,5443,8443,9443,9444,10443,51820 -j ACCEPT
iptables -C INPUT -i wg0 -d 10.8.0.1 -p tcp -m multiport --dports 5335,853,5443,8445 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 5 -i wg0 -d 10.8.0.1 -p tcp -m multiport --dports 5335,853,5443,8445 -j ACCEPT
iptables -C INPUT -i wg0 -d 10.8.0.1 -p udp -m multiport --dports 5335,853,5443,8445 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 6 -i wg0 -d 10.8.0.1 -p udp -m multiport --dports 5335,853,5443,8445 -j ACCEPT

# Keep VPN forwarding in a dedicated chain so its ordering is deterministic:
# metadata is blocked before established/forwarding accepts, and masquerading
# follows the live default interface rather than a hard-coded cloud name.
iptables -N FORTRESS_FORWARD 2>/dev/null || true
iptables -F FORTRESS_FORWARD
iptables -A FORTRESS_FORWARD -d 169.254.0.0/16 -j DROP
iptables -A FORTRESS_FORWARD -d 10.0.0.0/8 -j DROP
iptables -A FORTRESS_FORWARD -d 172.16.0.0/12 -j DROP
iptables -A FORTRESS_FORWARD -d 192.168.0.0/16 -j DROP
iptables -A FORTRESS_FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORTRESS_FORWARD -i wg0 -o "$WAN_IF" -j ACCEPT
iptables -A FORTRESS_FORWARD -i "$WAN_IF" -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -j FORTRESS_FORWARD 2>/dev/null || iptables -I FORWARD 1 -j FORTRESS_FORWARD

iptables -t nat -N FORTRESS_NAT 2>/dev/null || true
iptables -t nat -F FORTRESS_NAT
iptables -t nat -A FORTRESS_NAT -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE
iptables -t nat -C POSTROUTING -j FORTRESS_NAT 2>/dev/null || iptables -t nat -I POSTROUTING 1 -j FORTRESS_NAT
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
systemctl enable netfilter-persistent >/dev/null
netfilter-persistent save >/dev/null
echo "[+] Hardened iptables rules ACTIVE (INPUT/FORWARD default DROP; egress: ${WAN_IF}) and persistent across reboot."

# 18. Save Master Configuration Output & Client WireGuard Profiles
# Build the persistent templates before running the boot initializer.
# Never distribute SSH PAM enrollment material with VPN client settings.
# Portal enrollment is separate from SSH; never export the SSH seed to clients.
# Enable portal_totp_required only after separately enrolling a portal seed.
cat <<EOF > "$DISK_DIR/fortress_config.json"
{
  "server_ip": "${SERVER_IP}",
  "domain": "${DOMAIN}",
  "sub_port": 8443,
  "dns_port": 5335,
  "token": "${SUB_TOKEN}",
  "portal_totp_required": false,
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
printf '%s\n' "$SUB_TOKEN" > "$STATE_DIR/sub_token"
chown "$FORTRESS_USER:$FORTRESS_USER" "$STATE_DIR/sub_token"
chmod 600 "$STATE_DIR/sub_token"
cp "$STATE_DIR/sub_token" "$RAM_DIR/sub_token"

# Native WireGuard Client Profile
cat <<EOF > "$RAM_DIR/fortress-wireguard.conf"
[Interface]
PrivateKey = ${WG_CLIENT_PRIV}
Address = 10.8.0.2/24
# Configure device Private DNS/DoT separately; plain DNS is disabled on the server.
MTU = 1360

[Peer]
PublicKey = ${WG_SERVER_PUB}
Endpoint = ${SERVER_IP}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
EOF

# WireGuard-over-TCP (wstunnel) Client Profile
cat <<EOF > "$RAM_DIR/fortress-wireguard-tcp.conf"
[Interface]
PrivateKey = ${WG_CLIENT_PRIV}
Address = 10.8.0.2/24
# Configure device Private DNS/DoT separately; plain DNS is disabled on the server.
MTU = 1360

[Peer]
PublicKey = ${WG_SERVER_PUB}
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
EOF

# Keep deployment secrets private while allowing the subscription service to
# persist an intentional token rotation in its dedicated state file only.
chown root:"$FORTRESS_USER" "$DISK_DIR"
chmod 750 "$DISK_DIR"
chmod 600 "$DISK_DIR"/*
chown "$FORTRESS_USER:$FORTRESS_USER" "$RAM_DIR"/key.pem "$RAM_DIR"/cert.pem "$RAM_DIR"/ca.crt "$RAM_DIR"/config.json "$RAM_DIR"/fortress_config.json "$RAM_DIR"/sub_token
chmod 600 "$RAM_DIR"/config.json "$RAM_DIR"/fortress_config.json "$RAM_DIR"/sub_token
chown root:root "$RAM_DIR/wireguard/wg0.conf"
chmod 600 "$RAM_DIR/wireguard/wg0.conf"

# 19. Enable and Start Systemd Services
/usr/local/bin/fortress-init.sh
/usr/local/bin/sing-box check -c "$RAM_DIR/config.json"
systemctl daemon-reload
systemctl enable fortress-init fortress-core fortress-wstunnel fortress-sub fortress-adguard-update.timer wg-quick@wg0
systemctl restart fortress-init fortress-core fortress-wstunnel fortress-sub wg-quick@wg0
systemctl restart adguard-home

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
echo "[+] Subscription URLs:   construct locally from the private config; never print bearer tokens."
echo "[+] Web Portal (HTTPS):   https://${DOMAIN}:8443/portal"
echo "[+] DNS:                 127.0.0.1:5335 & 10.8.0.1:5335 (AdGuard query logs/statistics disabled; host visibility remains deployment-dependent)"
echo "[+] Credentials:        private operator files only; no tokens or TOTP seeds printed."
echo "[+] Sandboxing:         Dedicated unprivileged user 'fortress' + Systemd Strict"
echo "[+] Firewall:           iptables & netfilter-persistent Active (Default Drop Enforced)"
echo "[+] Master Config:      ${DISK_DIR}/fortress_config.json"
echo "================================================================="
