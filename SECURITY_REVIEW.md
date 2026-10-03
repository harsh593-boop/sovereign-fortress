# Security remediation and release status

**Not production-ready.** This report distinguishes checked fixes from untested
protection claims. It intentionally excludes deployment addresses, hostnames,
credentials, private profiles, and raw diagnostic logs.

## Remediated and checked

### Existing-server migration

`apply_server_remediation.py` is an explicit migration for the audited Sing-box
1.11.4 deployment, not a replacement for VM recovery planning. It requires
`--apply`, local reviewed scripts, root, and PyYAML. It creates root-only backups
of changed files and IPv4 rules, validates before restart, and attempts rollback
if service or bounded DNS checks fail. It does not reinstall the VM, change SSH,
upgrade the OS, rotate endpoint credentials, or replace default firewall policies.

- AdGuard uses the actual root-level `querylog` / `statistics` sections:
  query collection, query file logging, statistics, and application logging are
  disabled. Obsolete `dns.querylog_*` keys were ineffective.
- The management UI binds to loopback; DNS binds only to loopback and the private
  WireGuard address, with client restrictions. Unused incoming DoT/DoQ listeners
  are disabled. Existing encrypted upstreams and filter choices are preserved.
- A root-owned persistent AdGuard template is restored into a writable RAM
  config and working directory. This version rewrites config at startup and
  fails if its active config is read-only; that failure was reproduced and fixed.
- Query log files were absent in the new runtime at verification. A statistics
  database can exist even with statistics disabled; file existence is not proof
  of query collection. Working storage was verified as tmpfs.
- Proxy destination policy resolves hostnames before rejecting private,
  loopback, and metadata destinations, except the intended private DNS port.
  Additive firewall rules also protect IPv4 metadata and private WireGuard DNS.
- Services have suppressed output and core dumps, dependencies and resource
  limits. Runtime/master files are permission-restricted; service binaries and
  persistent templates are root-owned.
- Durable subscription state is writable only in its dedicated state directory;
  atomic token publication no longer silently claims success after a failed
  persistent write or reverts to stale boot-restored RAM state.

File-level rollback is **not** a VM/provider snapshot. Reboot recovery, provider
logging, old journals, snapshots, swap, and full-disk encryption remain separate
release gates. Existing data outside application runtime was not wiped.

### Subscription/authentication

- TLS handshakes occur in bounded workers with deadlines, not the accept loop.
- Secure/HttpOnly/SameSite cookies have nonces, bounded signed timestamps,
  session-bound CSRF, and revocation after token rotation.
- Wrong origins/hosts, ambiguous request framing, Unicode credentials, unsupported
  core versions/modes, and token-in-browser-GET authentication are rejected safely.
- Responses minimize referrer/framing exposure; fake usage/quota headers are removed.
- OTP-only subscription URLs and OTP-only portal login are retired. Optional
  portal MFA requires both the token and a **separate** enrolled portal seed.
  The SSH PAM seed is no longer copied/exported in VPN master settings.
  Legacy seed copies were checked unreadable to the service; SSH authentication
  itself was not changed. Portal MFA is opt-in, not automatically enrolled.
- A stale private CA is embedded only when it verifies the active certificate;
  otherwise normal system trust remains. TLS verification is never disabled.
  Hysteria URI pins use the current leaf-certificate fingerprint, not an SPKI pin.

This remains a single-owner design: the subscription/admin token grants broad
access. Per-device credentials, separate admin/client privileges, durable MFA
replay protection, and multi-user provisioning require further design/testing.

### Client, DNS, and local storage

- The DNS hijack rule is restricted to recognized DNS after sniffing. An
  unconditional hijack could divert non-DNS application traffic into DNS handling.
- Profiles are explicitly versioned: validated legacy 1.11.4 and current 1.14.2.
  Current examples use typed DNS, reject actions, WireGuard endpoints, and 1.14
  TUN DNS mode. Legacy fields removed by 1.14 are not silently reused.
- Full-Tunnel captures IPv6 and rejects it while active; private VPS DNS uses a
  proxy detour. This is not a persistent firewall kill switch.
- Traffic-Only sets 1.14 `dns_mode: disabled`, narrows provider exceptions, and
  removes a blanket `cloudflared` bypass. It is still best-effort, not universal.
- Shadowsocks-2022 links follow SIP002 percent-encoding requirements. Common URI
  subscriptions do not include unsupported desktop-only schemes.
- The GUI no longer reports UDP availability from a send/TCP probe, claims vault
  success after failure, or infers protection from configuration. Nested import
  URLs and credentials are encoded; certificate trust needs independent review.
- Private Windows settings/profiles live outside Git, with user-bound DPAPI.
  The GUI can load an encrypted config in memory. Actual client bundles must
  remain private; public examples are placeholders only.
- Vault conversion verifies complete output before deleting a source, refuses
  destination conflicts, uses correct native DPAPI/free signatures, and retains
  recoverable copies on failure. PowerShell wrappers use the same implementation.
- Vault/panic helpers do not enumerate unrelated SSH keys in Downloads. SSD,
  memory, snapshot, and backup erasure is never promised.
- wstunnel enables certificate verification explicitly. Native Sing-box can be
  installed without starting TUN or changing OS DNS/firewall policy.

### Repository/CI

The scanner now detects private-key markers and GitHub token formats, fails on
incomplete/missing Git scans, and interleaves Git blob requests/responses to avoid
pipe deadlock. CI disables bytecode fixtures, pins action commits and engine
archive hashes, and checks examples with the real supported engines. Archival
live verification tools are opt-in and are not release evidence.

History sanitization does not revoke leaked credentials or invalidate old clones,
releases, caches, transcripts, and backups. Rotation was operator-confirmed;
independent revocation across every previously exposed system is not proven here.

## Evidence from this remediation pass

| Check | Observed result |
| --- | --- |
| Standard-library offline regressions | 92 passed |
| Offline policy verifier | 6/6 passed |
| Actual pinned engine checks | 4 generated profiles + 2 current examples passed |
| ShellCheck 0.11.0 / Bash syntax | Passed for installer and initializer |
| Repository worktree + Git-object privacy scan | Passed; detection aid only |
| Live server smoke checks | 37/37 passed, secrets omitted |
| Live systemd unit verification | Passed |
| Native Windows DPAPI / synthetic NTFS conversion | Passed |
| Native Windows encrypted GUI config load | Passed |
| Native Windows 1.14.2 real private-profile schema checks | Both passed; no TUN started |
| Proxy-only HTTPS smoke from WSL, current client | 2/5 passed: standard Hysteria2 and Shadowsocks |
| Proxy-only HTTPS smoke on VPS loopback, legacy client | 3/5 passed: standard Hysteria2, TUIC, Shadowsocks |
| Loopback management access through successful proxies | Rejected |

Reality and Salamander failed the tested HTTPS smoke on both paths. TUIC passed
locally on the VPS but failed from the WSL path. Credential comparisons matched
the running server and the Reality target resolved/reached TLS 1.3, but the
remaining transport failures are **unresolved**, not dismissed as network faults.
These smoke tests do not establish browser, WebRTC, UDP, or TUN failure safety.

## Blocking release gates

1. Diagnose the failing transports and test the automatic selector across real
   destinations, UDP/TCP, MTUs, reconnects, and restricted/unrestricted networks.
2. Establish a supported/maintained host OS and current server-core upgrade plan
   with a VM snapshot, console recovery, SSH verification, and rollback. Legacy
   host extended-security coverage and post-quantum SSH negotiation are unverified.
3. Implement and test independent Windows WFP/firewall fail-closed behavior:
   client crash, TUN removal, reboot, sleep/wake, roaming, interface changes, VPS
   outage, and IPv6 reappearance. No such persistent policy was installed here.
4. Capture physical/TUN interfaces in both modes; test WebRTC/STUN and real DNS
   paths. Hiddify may rewrite imports. Node import or an HTTP IP test is not proof.
5. Test YogaDNS/NextDNS, Windows native DoH, browser DoH, Android Private DNS,
   DNSCrypt, DoQ, hard-coded resolvers and embedded DNS on actual devices.
   Arbitrary HTTPS DoH cannot be universally classified from finite route rules.
   Full-Tunnel encrypts its transit but does not force every application's
   encrypted DNS through AdGuard or make same-domain ad blocking universal.
6. Verify Linux/macOS/Android/iOS/router support and IPv6-only networks. Current
   endpoint generation is IPv4-only. Do not label the bundle all-device compatible.
7. Review provider/kernel/journal/SSH/application logging, older artifacts,
   Hiddify caches, clipboard/memory/swap, disk encryption, backup encryption and
   retention. Application flags and tmpfs cannot guarantee absolute zero logs.
8. Test the first-install script on a disposable VM and the migration through a
   real reboot/restore. Static checks do not prove a fresh install or recovery.

## Official references

- Sing-box migration: https://sing-box.sagernet.org/migration/
- TUN routing/DNS limitations: https://sing-box.sagernet.org/configuration/inbound/tun/
- WireGuard endpoint schema: https://sing-box.sagernet.org/configuration/endpoint/wireguard/
- AdGuard v0.107.56 configuration source: https://github.com/AdguardTeam/AdGuardHome/tree/v0.107.56/internal (navigate to `home`, then `config.go`)
- AdGuard configuration: https://adguard-dns.io/kb/adguard-home/configuration/
- Shadowsocks-2022 URI requirements: https://shadowsocks.org/doc/sip002.html
