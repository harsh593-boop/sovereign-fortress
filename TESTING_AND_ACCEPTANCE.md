# Testing and acceptance
Run `tests\Test-Fortress.ps1 -Mode full|traffic` (see script). Server-side checks run via `python tools\vps.py`.

| Test | Result | Notes |
|---|---|---|
| Server: sing-box + AGH active, 443 reachable, 22 SSH ok after firewall | PASS | executed |
| Config validation (`sing-box check`) both modes | PASS | executed |
| Reality outbound via SOCKS probe: IPv4 = VPS | PASS | executed (no TUN) |
| Full tunnel: IPv4, DNS path, IPv6, STUN, kill switch | NOT RUN | blocked on UAC |
| Traffic-only: NextDNS 68f58b, YogaDNS exemption, STUN, IPv6 | NOT RUN | blocked on UAC |
| Mode transitions leave no stale rules | NOT RUN | blocked |
| Windows reboot / VPS reboot / tunnel interruption | NOT RUN | blocked |
| Invalid credentials secure failure | NOT RUN | |
| Bad config rejected before activation | PARTIAL | `fortress.ps1` runs `sing-box check` before start; negative test not yet executed |
