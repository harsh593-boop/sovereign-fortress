#!/usr/bin/env bash
# Sovereign Fortress v2 - idempotent server provisioning. Run as root.
# Removes the legacy deployment, installs pinned sing-box (VLESS+Reality :443) and a
# loopback-only AdGuard Home resolver. Firewall is applied separately (firewall.sh).
set -euo pipefail

SB_VER=1.14.3
SB_SHA256=e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-amd64.tar.gz"
REALITY_SNI="${REALITY_SNI:-gateway.icloud.com}"
CONF=/etc/sing-box
DNS_PORT=5353

log() { echo "[provision] $*"; }

# ---------- 1. remove legacy project resources ----------
legacy_cleanup() {
  log "removing legacy fortress deployment"
  for u in fortress-core fortress-sub fortress-wstunnel fortress-init fortress-adguard-update.timer \
           fortress-dnscrypt-refresh.timer fortress-adguard-update fortress-dnscrypt-refresh \
           apache2 unbound wg-quick@wg0; do
    systemctl disable --now "$u" 2>/dev/null || true
  done
  rm -rf /etc/systemd/system/*.service.d/90-fortress-reviewed.conf /etc/systemd/system/fortress-*.service.d \
         /etc/systemd/system/adguard-home.service.d /etc/systemd/system/wg-quick@wg0.service.d /etc/cron.hourly/duckdns-update
  rm -f /etc/systemd/system/fortress-*.service/etc/systemd/system/fortress-*.timer \
        /etc/systemd/system/opt-AdGuardHome-data.mount /etc/systemd/system/adguard-home.service
  umount /opt/AdGuardHome/data 2>/dev/null || true
  umount /var/fortress-storage 2>/dev/null || true
  umount /run/fortress 2>/dev/null || true
  cryptsetup close fortress-secure 2>/dev/null || true
  for l in $(losetup -j /var/fortress.img 2>/dev/null | cut -d: -f1); do losetup -d "$l" || true; done
  rm -rf /etc/fortress /opt/fortress-tools /var/fortress-storage /var/fortress.img \
         /usr/local/bin/fortress-* /usr/local/bin/wstunnel /usr/local/bin/sing-box /run/fortress
  userdel fortress 2>/dev/null || true
  sed -i '/AdGuardHome\/data/d;/fortress-storage/d;/fortress-secure/d' /etc/fstab
  sed -i '/fortress-secure/d' /etc/crypttab 2>/dev/null || true
  systemctl daemon-reload
}

# ---------- 2. sing-box ----------
install_singbox() {
  if [ -x /usr/local/bin/sing-box ] && /usr/local/bin/sing-box version | head -1 | grep -q "$SB_VER"; then
    log "sing-box $SB_VER already installed"; return
  fi
  local t; t=$(mktemp -d)
  curl -fsSL "$SB_URL" -o "$t/sb.tgz"
  echo "$SB_SHA256  $t/sb.tgz" | sha256sum -c - >/dev/null || { echo "sing-box checksum mismatch" >&2; exit 1; }
  tar -xzf "$t/sb.tgz" -C "$t" --strip-components=1
  install -m 0755 "$t/sing-box" /usr/local/bin/sing-box
  rm -rf "$t"
}

write_singbox_config() {
  id -u singbox >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin singbox
  install -d -m 0750 -o root -g singbox "$CONF"
  if [ ! -f "$CONF/params.json" ]; then
    local uuid kp priv pub sid
    uuid=$(/usr/local/bin/sing-box generate uuid)
    kp=$(/usr/local/bin/sing-box generate reality-keypair)
    priv=$(echo "$kp" | awk '/PrivateKey/{print $2}')
    pub=$(echo "$kp" | awk '/PublicKey/{print $2}')
    sid=$(openssl rand -hex 8)
    python3 - "$uuid" "$priv" "$pub" "$sid" "$REALITY_SNI" > "$CONF/params.json" <<'PY'
import json,sys
u,priv,pub,sid,sni=sys.argv[1:]
print(json.dumps({"uuid":u,"private_key":priv,"public_key":pub,"short_id":sid,"sni":sni,"port":443}))
PY
    chmod 0640 "$CONF/params.json"; chown root:singbox "$CONF/params.json"
  fi
  python3 - "$CONF/params.json" "$DNS_PORT" > "$CONF/config.json.new" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); dns=int(sys.argv[2])
cfg={
 "log":{"level":"warn","timestamp":True},
 "inbounds":[{"type":"vless","tag":"vless-reality","listen":"::","listen_port":p["port"],
   "users":[{"name":"main","uuid":p["uuid"],"flow":"xtls-rprx-vision"}],
   "tls":{"enabled":True,"server_name":p["sni"],
     "reality":{"enabled":True,"handshake":{"server":p["sni"],"server_port":443},
                "private_key":p["private_key"],"short_id":[p["short_id"]]}}}],
 "outbounds":[{"type":"direct","tag":"direct"}],
 "route":{"rules":[
   {"ip_cidr":["127.0.0.1/32"],"port":[dns],"action":"route","outbound":"direct"},
   {"ip_is_private":True,"action":"reject"}],
   "final":"direct"}
}
print(json.dumps(cfg,indent=2))
PY
  /usr/local/bin/sing-box check -c "$CONF/config.json.new"
  mv "$CONF/config.json.new" "$CONF/config.json"
  chown root:singbox "$CONF/config.json"; chmod 0640 "$CONF/config.json"
  cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=sing-box (Sovereign Fortress)
After=network-online.target
Wants=network-online.target

[Service]
User=singbox
Group=singbox
ExecStartPre=/usr/local/bin/sing-box check -c /etc/sing-box/config.json
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable sing-box >/dev/null
  systemctl restart sing-box
}

# ---------- 3. AdGuard Home (loopback only, reached through the tunnel) ----------
install_agh() {
  local AGH=/opt/AdGuardHome
  [ -x "$AGH/AdGuardHome" ] || { echo "AdGuardHome binary missing" >&2; exit 1; }
  id -u adguard >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin adguard
  # systemd-resolved stub only holds 127.0.0.53, so 127.0.0.1:$DNS_PORT is free.
  if [ ! -f "$AGH/AdGuardHome.yaml" ] || ! grep -q "port: $DNS_PORT" "$AGH/AdGuardHome.yaml"; then
    systemctl stop adguard-home 2>/dev/null || true
    rm -rf "$AGH/AdGuardHome.yaml" "$AGH/data"
    install -d -o adguard -g adguard "$AGH/data"
    chown -R adguard:adguard "$AGH"
    local pw; pw=$(openssl rand -hex 16)
    local AGH_USER=''   # first launch must run as root; dropped to 'adguard' after setup
    write_agh_unit() { cat > /etc/systemd/system/adguard-home.service <<UNIT
[Unit]
Description=AdGuard Home (Sovereign Fortress resolver)
After=network-online.target

[Service]
$AGH_USER
WorkingDirectory=$AGH
ExecStart=$AGH/AdGuardHome --no-check-update -w $AGH -c $AGH/AdGuardHome.yaml
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
    }
    write_agh_unit
    systemctl daemon-reload; systemctl enable adguard-home >/dev/null; systemctl start adguard-home
    sleep 4
    curl -fsS -X POST http://127.0.0.1:3000/control/install/configure -H 'Content-Type: application/json' \
      -d "{\"web\":{\"ip\":\"127.0.0.1\",\"port\":3001},\"dns\":{\"ip\":\"127.0.0.1\",\"port\":$DNS_PORT},\"username\":\"fortress\",\"password\":\"$pw\"}" >/dev/null
    sleep 3
    echo "fortress:$pw" > /etc/sing-box/agh-admin.secret; chmod 600 /etc/sing-box/agh-admin.secret
    local A=(-u "fortress:$pw" -H 'Content-Type: application/json')
    curl -fsS "${A[@]}" -X POST http://127.0.0.1:3001/control/dns_config -d '{
      "upstream_dns":["tls://1.1.1.1","tls://9.9.9.9","tls://1.0.0.1"],
      "bootstrap_dns":["1.1.1.1","9.9.9.9"],"upstream_mode":"load_balance",
      "cache_enabled":true,"cache_size":4194304,"blocking_mode":"default","dnssec_enabled":false}' >/dev/null
    curl -fsS "${A[@]}" -X PUT http://127.0.0.1:3001/control/querylog/config/update -d '{"enabled":false,"interval":86400000,"anonymize_client_ip":true}' >/dev/null || true
    curl -fsS "${A[@]}" -X PUT http://127.0.0.1:3001/control/stats/config/update -d '{"enabled":true,"interval":86400000}' >/dev/null || true
    systemctl stop adguard-home; chown -R adguard:adguard "$AGH"
    AGH_USER=$'User=adguard\nGroup=adguard'; write_agh_unit; systemctl daemon-reload
  fi
  systemctl enable adguard-home >/dev/null; systemctl restart adguard-home
}

kernel_tuning() {
  cat > /etc/sysctl.d/90-fortress.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
}

legacy_cleanup
install_singbox
write_singbox_config
install_agh
kernel_tuning
sleep 2
systemctl is-active sing-box adguard-home
echo "[provision] done"
