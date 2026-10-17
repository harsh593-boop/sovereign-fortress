# Sovereign Fortress v2
Native sing-box TUN client for Windows + VLESS-Reality / AdGuard Home server. See ARCHITECTURE.md.

```powershell
pip install paramiko
python tools\gen_client.py                       # fetch server params, verify binary, render+validate configs
client\fortress.ps1 mode full                    # full tunnel, VPS DNS, kill switch
client\fortress.ps1 mode traffic                 # tunnel traffic, DNS stays YogaDNS/NextDNS
client\fortress.ps1 mode off                     # stop everything, restore firewall (also the recovery command)
client\fortress.ps1 status
tests\Test-Fortress.ps1 -Mode full               # leak tests
```
Server: `python tools\vps.py --put server\provision.sh /tmp/p.sh; python tools\vps.py "bash /tmp/p.sh" --sudo` (idempotent; firewall via server/firewall.sh apply|commit).
Credentials are read at runtime from your Downloads files (key, topt.txt, keys.txt); never stored in the repo.
Recovery if the network is dead: elevated PowerShell `fortress.ps1 mode off`, or `Set-NetFirewallProfile -All -DefaultOutboundAction Allow`.
