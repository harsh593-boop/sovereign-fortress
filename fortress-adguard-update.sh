#!/usr/bin/env bash
# Official AdGuard Home self-update wrapper with root-only backup and rollback.
set -euo pipefail
umask 077
BIN=/opt/AdGuardHome/AdGuardHome
CONFIG=/opt/AdGuardHome/AdGuardHome.yaml
WORK=/run/fortress/adguard
BACKUP=/root/fortress-backups/adguard-auto
mkdir -p "$BACKUP"
STAMP=$(date -u +%Y%m%d-%H%M%S)
cp -p "$BIN" "$BACKUP/AdGuardHome.$STAMP.before"
cp -p "$CONFIG" "$BACKUP/AdGuardHome.yaml.$STAMP.before"
"$BIN" --update -c "$CONFIG" -w "$WORK"
systemctl restart adguard-home
for _ in $(seq 1 30); do
    systemctl is-active --quiet adguard-home && exit 0
    sleep 1
done
cp -p "$BACKUP/AdGuardHome.$STAMP.before" "$BIN"
systemctl restart adguard-home
exit 1
