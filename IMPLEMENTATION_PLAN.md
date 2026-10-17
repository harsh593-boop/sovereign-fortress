# Implementation plan
| ID | Phase | Task | Dependencies | Location | Automation | Acceptance test | Status |
|---|---|---|---|---|---|---|---|
| 1.1 | Discovery | Audit local + VPS (OS, ports, services, DNS) | - | both | tools/vps.py | Facts recorded in STATUS | Done |
| 1.2 | Discovery | SSH key+TOTP auth works | 1.1 | local | tools/vps.py | `python tools/vps.py "id"` | Done |
| 2.1 | Threat model | Requirements/threat model | 1.1 | docs | - | ARCHITECTURE guarantees section | Done |
| 3.1 | Architecture | Select native sing-box + Reality + AGH | 2.1 | docs | - | ARCHITECTURE.md | Done |
| 4.1 | Cleanup | Remove legacy VPS deployment | 1.2 | VPS | server/provision.sh | No fortress-* units, /etc/fortress gone | Done |
| 4.2 | Cleanup | Remove legacy repo files and secret-bearing scripts | 3.1 | local | manual | repo contains only v2 | Done |
| 5.1 | VPS hardening | Default-drop firewall w/ rollback timer | 4.1 | VPS | server/firewall.sh | only 22/443 reachable; SSH ok | Done |
| 6.1 | Server | sing-box VLESS-Reality service | 4.1 | VPS | server/provision.sh | probe via SOCKS returns VPS IP | Done |
| 7.1 | DNS | AdGuard Home loopback resolver | 4.1 | VPS | server/provision.sh | `dig @127.0.0.1 -p 5353` answers | Done |
| 8.1 | Subscription | Not needed (single user, configs generated locally) | - | - | tools/gen_client.py | n/a | Dropped |
| 9.1 | Windows | Fetch+verify sing-box, render/validate configs | 6.1 | local | tools/gen_client.py | `sing-box check` OK both modes | Done |
| 9.2 | Windows | Install SYSTEM task + TUN (needs UAC) | 9.1 | local | client/fortress.ps1 install | task exists | Blocked on UAC |
| 10.1 | Full tunnel | Mode full + kill switch | 9.2 | local | fortress.ps1 mode full | tests/Test-Fortress.ps1 full | Pending |
| 11.1 | Traffic-only | Mode traffic + YogaDNS exemption | 9.2 | local | fortress.ps1 mode traffic | test traffic | Pending |
| 12.1 | Leak tests | IP/DNS/IPv6/STUN/NextDNS | 10.1,11.1 | local | tests/Test-Fortress.ps1 | all PASS | Pending |
| 13.1 | Persistence | VPS reboot, Windows reboot, tunnel-kill | 12.1 | both | manual+script | recovers | Pending |
| 14.1 | Regression | mode transitions, bad config rejected | 12.1 | local | test script | no stale routes/rules | Pending |
| 15.1 | Docs | README, status | all | repo | - | files current | In progress |
