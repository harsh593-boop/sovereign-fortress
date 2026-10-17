#!/usr/bin/env bash
# Sovereign Fortress v2 firewall. `apply` loads rules with an automatic 150s rollback timer;
# `commit` cancels the timer and persists the rules. Run as root.
set -euo pipefail
case "${1:-}" in
  apply)
    iptables-save > /root/fw-prev.v4; ip6tables-save > /root/fw-prev.v6
    cat > /root/fw-rollback.sh <<'EOF'
#!/bin/sh
sleep 150
iptables-restore < /root/fw-prev.v4; ip6tables-restore < /root/fw-prev.v6
EOF
    chmod 700 /root/fw-rollback.sh
    setsid nohup /root/fw-rollback.sh >/dev/null 2>&1 < /dev/null &
    iptables-restore <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -p udp --sport 67 --dport 68 -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second -j ACCEPT
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --name ssh --set
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --name ssh --update --seconds 60 --hitcount 12 -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
EOF
    ip6tables-restore <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -p udp --sport 547 --dport 546 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 22,443 -j ACCEPT
COMMIT
EOF
    echo "applied; rollback in 150s unless committed" ;;
  commit)
    pkill -f fw-rollback.sh || true
    install -d /etc/iptables
    iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    echo committed ;;
  *) echo "usage: $0 apply|commit" >&2; exit 2 ;;
esac