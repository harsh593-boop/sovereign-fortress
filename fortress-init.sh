#!/usr/bin/env bash
# Restore private runtime files without generating or changing SSH credentials.
set -euo pipefail
umask 077
RAM_DIR=/run/fortress
DISK_DIR=/etc/fortress
STATE_DIR=/var/lib/fortress/subscription
FORTRESS_USER=fortress

if [ "$(id -u)" -ne 0 ]; then
    echo 'Runtime initialization requires root.' >&2
    exit 1
fi
if ! mountpoint -q "$RAM_DIR"; then
    install -d -m 0750 "$RAM_DIR"
    mount -t tmpfs -o size=256M,mode=0750 tmpfs "$RAM_DIR"
fi
if [ "$(findmnt -n -o FSTYPE --target "$RAM_DIR")" != tmpfs ]; then
    echo 'Runtime mount is not tmpfs; refusing to start.' >&2
    exit 1
fi
chown root:"$FORTRESS_USER" "$RAM_DIR"
chmod 0750 "$RAM_DIR"
install -d -m 0700 -o "$FORTRESS_USER" -g "$FORTRESS_USER" "$STATE_DIR" "$RAM_DIR/adguard"
install -d -m 0700 -o root -g root "$RAM_DIR/wireguard"
# AdGuard rewrites its config at startup; restore a reviewed RAM copy each boot.
install -m 0600 -o "$FORTRESS_USER" -g "$FORTRESS_USER" \
    /opt/AdGuardHome/AdGuardHome.yaml "$RAM_DIR/adguard/AdGuardHome.yaml"
if [ -f "$DISK_DIR/dnscrypt.yaml" ]; then
    install -m 0600 -o "$FORTRESS_USER" -g "$FORTRESS_USER" \
        "$DISK_DIR/dnscrypt.yaml" "$RAM_DIR/adguard/dnscrypt.yaml"
fi
if [ -f "$DISK_DIR/vault.enc" ] && [ ! -f "$RAM_DIR/key.pem" ]; then
    echo '[!] Vault is locked on disk (/etc/fortress/vault.enc).' >&2
    echo '[!] Run "sudo python3 manage_server_vault.py unlock" to unlock keys into volatile RAM.' >&2
fi
for file in key.pem cert.pem ca.crt fortress_config.json; do
    if [ -f "$DISK_DIR/$file" ]; then
        install -m 0640 -o root -g "$FORTRESS_USER" "$DISK_DIR/$file" "$RAM_DIR/$file"
    fi
done
if [ -f "$DISK_DIR/config.json.template" ]; then
    install -m 0640 -o root -g "$FORTRESS_USER" "$DISK_DIR/config.json.template" "$RAM_DIR/config.json"
fi
if [ -f "$DISK_DIR/wg0.conf" ]; then
    install -m 0600 -o root -g root "$DISK_DIR/wg0.conf" "$RAM_DIR/wireguard/wg0.conf"
fi
if [ ! -f "$STATE_DIR/sub_token" ] && [ -f "$DISK_DIR/sub_token" ]; then
    # Migrate legacy durable token state once. Never overwrite a newer rotation.
    install -m 0600 -o "$FORTRESS_USER" -g "$FORTRESS_USER" "$DISK_DIR/sub_token" "$STATE_DIR/sub_token"
fi
if [ -f "$STATE_DIR/sub_token" ]; then
    install -m 0640 -o root -g "$FORTRESS_USER" "$STATE_DIR/sub_token" "$RAM_DIR/sub_token"
fi
# Optional portal TOTP lives in the dedicated state directory. SSH PAM seeds
# are not copied into VPN runtime or distributed to clients.
install -d -m 0700 /etc/wireguard
ln -sfn "$RAM_DIR/wireguard/wg0.conf" /etc/wireguard/wg0.conf
