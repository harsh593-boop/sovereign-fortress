# Architecture (v2)

**Client:** native sing-box 1.14.3 (pinned, SHA-256 verified) with a TUN adapter `fortress0`, run as a SYSTEM scheduled task
(`SovereignFortress`, AtStartup, auto-restart). Chosen over Hiddify: same sing-box core, but a documented config schema, no GUI state,
scriptable, no undocumented CLI flags. `strict_route` + `auto_route` capture all TCP/UDP incl. apps that ignore proxy settings.
**Server:** Ubuntu 20.04 (x86_64, 1 GB RAM). sing-box VLESS+Reality (xtls-rprx-vision, xudp for UDP) on tcp/443, SNI camouflage `gateway.icloud.com`.
AdGuard Home bound to 127.0.0.1:5353 only (upstream DoT to 1.1.1.1/9.9.9.9, query log off). No public DNS, no subscription service,
no wstunnel/WireGuard/Hysteria (no measured need; every extra protocol is extra attack surface on 1 GB RAM).
**Firewall (server):** default-drop INPUT; only 22 (rate-limited, key+TOTP SSH) and 443. IPv6 same. Persisted via netfilter-persistent.

## Modes
| | Full Tunnel | Traffic-Only |
|---|---|---|
| Routing | all TCP/UDP -> `proxy` | all TCP/UDP -> `proxy`, except RFC1918 and YogaDNS processes (direct) |
| DNS | port 53 hijacked in TUN -> sing-box dns `udp://127.0.0.1:5353` *detoured through the proxy*, i.e. AdGuard Home on the VPS loopback | not touched: OS -> YogaDNS -> NextDNS profile 68f58b |
| IPv6 | TUN owns `::/0`; route rule rejects it (blocked, not leaked) | same |
| Kill switch | Windows Firewall default-outbound=Block + allow-list (sing-box.exe, `fortress0`, DHCP, LAN except 53/853) | optional (`mode traffic ks`) |
| Loop avoidance | `auto_detect_interface` binds sing-box's own socket to the physical NIC; server is an IP literal (no bootstrap DNS) | plus YogaDNS upstream goes direct, not through the tunnel |

## Guarantees and limits
* Browser-native DoH/DoQ is ordinary HTTPS/QUIC: in Full Tunnel it exits via the VPS (hidden from campus) but is not VPS-resolver-controlled; in Traffic-Only it
  bypasses YogaDNS (only app-level settings can fix that).
* Traffic-Only does not hide DNS from the local network: YogaDNS->NextDNS is sent from the physical interface by design.
* Reality server needs the hash-verified binary; GitHub is blocked/intercepted on the campus network so downloads go via the VPS.
* The kill switch changes the Windows Firewall default outbound action; `fortress.ps1 mode off` restores the saved values.
