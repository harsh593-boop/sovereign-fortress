#!/usr/bin/env bash
# Sovereign Fortress: wipe legacy state and deploy VLESS-Reality (sing-box) + loopback AdGuard Home.
# Run as root. Inputs: $SRC with the two templates; env VPS_IP, UUID, SHORT_ID, SNI. Fresh Reality keypair each run.
set -euo pipefail
SRC="${SRC:-/tmp/sf}"
: "${VPS_IP:?}" "${SNI:=gateway.icloud.com}"   # UUID / SHORT_ID: generated fresh when unset
SB_VER=1.14.3
SB_SHA=e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

echo "[1] wipe legacy services + dirs"
units=$( { systemctl list-units --all --no-legend --plain 'fortress-*' 'wstunnel*'; systemctl list-unit-files --no-legend 'fortress-*' 'wstunnel*'; } | awk '{print $1}' | sort -u)
for u in sing-box adguard-home adguardhome $units; do
  systemctl disable --now "$u" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/{sing-box,adguard-home,adguardhome}.service /etc/systemd/system/fortress-* /etc/systemd/system/wstunnel*
rm -f /usr/local/bin/sing-box /usr/local/bin/wstunnel
rm -rf /opt/fortress /opt/AdGuardHome /opt/adguardhome /etc/sing-box /etc/adguardhome /var/lib/adguardhome /etc/fortress /run/fortress /etc/sovereign-fortress
systemctl daemon-reload; systemctl reset-failed || true

echo "[2] firewall baseline (INPUT: lo, established, 22 rate-limited, 443)"
iptables-restore --noflush <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
-F INPUT
-F FORWARD
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -p udp --sport 67 --dport 68 -j ACCEPT
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name ssh
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 12 --name ssh -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
EOF
iptables -t nat -F
ip6tables-restore --noflush <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
-F INPUT
-F FORWARD
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p udp --sport 547 --dport 546 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
EOF
mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6

echo "[3] users"
id sing-box >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sing-box
id adguard  >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin adguard

echo "[4] sing-box $SB_VER (sha256-verified)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/sb.tgz" "https://github.com/SagerNet/sing-box/releases/download/v$SB_VER/sing-box-$SB_VER-linux-amd64.tar.gz"
echo "$SB_SHA  $tmp/sb.tgz" | sha256sum -c --quiet -
tar xzf "$tmp/sb.tgz" -C "$tmp"
install -m 0755 "$tmp/sing-box-$SB_VER-linux-amd64/sing-box" /usr/local/bin/sing-box

echo "[5] AdGuard Home (latest, GitHub digest-verified)"
install -d -m 0755 /opt/adguardhome
python3 - <<'EOF'
import hashlib, io, json, os, tarfile, urllib.request
r = json.load(urllib.request.urlopen("https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest"))
a = [x for x in r["assets"] if x["name"] == "AdGuardHome_linux_amd64.tar.gz"][0]
data = urllib.request.urlopen(a["browser_download_url"]).read()
assert a.get("digest") == "sha256:" + hashlib.sha256(data).hexdigest(), "AGH digest mismatch"
t = tarfile.open(fileobj=io.BytesIO(data))
open("/opt/adguardhome/AdGuardHome", "wb").write(t.extractfile("./AdGuardHome/AdGuardHome").read())
os.chmod("/opt/adguardhome/AdGuardHome", 0o755)
print("AdGuardHome", r["tag_name"])
EOF

echo "[6] secrets + configs"
install -d -m 0700 /etc/sovereign-fortress
UUID=${UUID:-$(/usr/local/bin/sing-box generate uuid)}
SHORT_ID=${SHORT_ID:-$(/usr/local/bin/sing-box generate rand --hex 8)}
kp=$(/usr/local/bin/sing-box generate reality-keypair)
PRIV=$(awk '/PrivateKey/{print $2}' <<<"$kp"); PUB=$(awk '/PublicKey/{print $2}' <<<"$kp")
umask 077
printf '{"vps_ip":"%s","uuid":"%s","sni":"%s","short_id":"%s","reality_public":"%s","reality_private":"%s"}\n' \
  "$VPS_IP" "$UUID" "$SNI" "$SHORT_ID" "$PUB" "$PRIV" > /etc/sovereign-fortress/secrets.json
umask 022
printf '{"vps_ip":"%s","uuid":"%s","sni":"%s","short_id":"%s","reality_public":"%s"}\n' \
  "$VPS_IP" "$UUID" "$SNI" "$SHORT_ID" "$PUB" > /etc/sovereign-fortress/client.json
chmod 0644 /etc/sovereign-fortress/client.json; chmod 0711 /etc/sovereign-fortress
install -d -o root -g sing-box -m 0750 /etc/sing-box
sed -e "s|@UUID@|$UUID|g" -e "s|@SNI@|$SNI|g" -e "s|@SHORT_ID@|$SHORT_ID|g" -e "s|@REALITY_PRIVATE@|$PRIV|g" \
  "$SRC/sing-box.server.template.json" > /etc/sing-box/config.json
chown root:sing-box /etc/sing-box/config.json; chmod 0640 /etc/sing-box/config.json
/usr/local/bin/sing-box check -c /etc/sing-box/config.json
install -d -o root -g adguard -m 0750 /etc/adguardhome
install -o root -g adguard -m 0640 "$SRC/AdGuardHome.template.yaml" /etc/adguardhome/AdGuardHome.yaml

echo "[7] systemd units"
cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box VLESS-Reality (Sovereign Fortress)
After=network-online.target adguardhome.service
Wants=network-online.target
[Service]
User=sing-box
Group=sing-box
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
[Install]
WantedBy=multi-user.target
EOF
# AGH runs entirely from a RAM tmpfs (/run/adguardhome): no query log, no stats, nothing persisted.
cat > /etc/systemd/system/adguardhome.service <<'EOF'
[Unit]
Description=AdGuard Home (Sovereign Fortress, loopback-only, RAM-only)
After=network-online.target
Wants=network-online.target
[Service]
User=adguard
Group=adguard
RuntimeDirectory=adguardhome
RuntimeDirectoryMode=0700
ExecStartPre=/bin/cp /etc/adguardhome/AdGuardHome.yaml /run/adguardhome/AdGuardHome.yaml
ExecStart=/opt/adguardhome/AdGuardHome --no-check-update -c /run/adguardhome/AdGuardHome.yaml -w /run/adguardhome
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now adguardhome sing-box
sleep 4

echo "[8] health"
systemctl is-active sing-box adguardhome
ss -tulnp | grep -E ':(22|443|5353|3001)\b' | awk '{print $1,$5,$7}'
dig +short +time=3 @127.0.0.1 -p 5353 example.com A || true
echo "REALITY_PUBLIC=$PUB"
