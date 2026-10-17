# Implementation status (2026-10-17)

## Done (see IMPLEMENTATION_PLAN.md IDs 1.1-9.1, 4.2, 5.1, 6.1, 7.1)
* VPS (Ubuntu 20.04.6, x86_64, 2 vCPU/1 GB, public IP 144.24.112.45 confirmed): legacy fortress-*/apache/wstunnel/LUKS vault/unbound/WireGuard removed;
  sing-box 1.14.3 VLESS-Reality on tcp/443 (active), AdGuard Home on 127.0.0.1:5353 (active, admin 127.0.0.1:3001), default-drop firewall (22, 443) persisted.
* SSH (key + TOTP) unchanged and verified after firewall change.
* Reality path verified from Windows via a non-TUN SOCKS probe: external IP = 144.24.112.45, HTTPS through VPS works.
* Client configs full.json / traffic.json rendered to %LOCALAPPDATA%\SovereignFortress and pass `sing-box check`.
* Repo reset to v2 (server/, client/, tools/, tests/, docs). Old secret-bearing scripts deleted.
* Cloudflare WARP was disconnected (`warp-cli disconnect`) because it conflicts with the TUN. Reconnect with `warp-cli connect` if wanted.

## Blocker
Creating the TUN adapter / SYSTEM task needs Administrator. The UAC prompt raised by `client\fortress.ps1 install` was not approved
(the session cannot click the secure desktop). Everything below is untested until then.

## Exact next steps
1. Run in an ordinary PowerShell and click **Yes** on the UAC prompt:
   `powershell -ExecutionPolicy Bypass -File C:\Users\harsh\Desktop\sovereign-fortress\client\fortress.ps1 mode full`
2. `powershell -File tests\Test-Fortress.ps1 -Mode full`; fix failures; record in TESTING_AND_ACCEPTANCE.md.
3. Same for `mode traffic`, then transitions, `mode off`, reboot tests, VPS reboot test, tunnel-kill test (kill sing-box.exe with kill switch on).
4. Dependencies: python + paramiko (`pip install paramiko`).

## Security notes
* The TOTP seed and sudo password were echoed in an earlier session transcript; consider rotating them. Credential files in Downloads are untouched.
* Secrets are only in %LOCALAPPDATA%\SovereignFortress, C:\ProgramData\SovereignFortress (admin/SYSTEM ACL) and /etc/sing-box (root:singbox 0640).
