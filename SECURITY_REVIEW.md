# Security remediation and release status

**Not production-ready.** This report distinguishes checked fixes from untested
protection claims. It intentionally excludes deployment addresses, hostnames,
credentials, private profiles, and raw diagnostic logs.

## Latest continuation

The application core is now **1.14.2** on the audited VPS, with typed private DNS
and an explicit Reality handshake resolver. A checksum-verified isolated instance
passed all five transports before the file-backed production upgrade. Current
and legacy clients then passed **5/5** local VPS transport checks. The OS itself
was not upgraded; Windows networking enforcement remains blocked on administrator
access. See [HOST_MAINTENANCE.md](HOST_MAINTENANCE.md).

Synchronized client-path capture observed UDP 8443 requests/replies but no arriving
9443/9444 packets during their failed probes. This is a pre-guest drop, not a
proven daemon-authentication bug; OCI ingress and the client network need review.
Read-only Windows readiness checks and the full fail-closed design/test matrix are
in [WINDOWS_NETWORK_READINESS.md](WINDOWS_NETWORK_READINESS.md). No actual kill
switch was implemented by that diagnostic.

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
- The management UI binds to the private WireGuard address; DNS binds only to
  loopback/private WireGuard addresses with client restrictions. Incoming plain
  DNS is disabled; private DoT/DoQ use 853 and private DoH uses 8445 with the
  validated DuckDNS certificate. DNSCrypt remains staged until its provider
  config/stamp is independently verified. Existing encrypted upstreams and
  filter choices are preserved.
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
- Profiles are explicitly versioned. Current Full-Tunnel is 1.14.2-only because
  legacy 1.11 Full-Tunnel would require plaintext/legacy DNS semantics. Legacy
  1.11 Traffic-Only remains a compatibility profile. Current examples use typed
  encrypted DNS, reject actions, WireGuard endpoints, and 1.14 TUN DNS mode.
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
pipe deadlock. Git metadata is pruned before worktree traversal, including
while background object packing is running. CI disables bytecode fixtures, pins action commits and engine
archive hashes, and checks examples with the real supported engines. Archival
live verification tools are opt-in and are not release evidence.

History sanitization does not revoke leaked credentials or invalidate old clones,
releases, caches, transcripts, and backups. Rotation was operator-confirmed;
independent revocation across every previously exposed system is not proven here.

## Evidence from this remediation pass

| Check | Observed result |
| --- | --- |
| Standard-library offline regressions | 119 passed locally, including encrypted-DNS/firewall fixtures |
| Offline policy verifier | 6/6 passed |
| Actual pinned engine checks | 4 generated profiles + 2 current examples + current first-install server template passed |
| ShellCheck 0.11.0 / Bash syntax | Passed for installer and initializer |
| Repository worktree + Git-object privacy scan | Passed; detection aid only |
| Live server smoke checks | 39/39 passed after encrypted DNS migration, secrets omitted |
| Live systemd unit verification | Passed |
| Native Windows DPAPI / synthetic NTFS conversion | Passed |
| Native Windows encrypted GUI config load | Passed |
| Native Windows 1.14.2 real private-profile schema checks | Both passed; no TUN started |
| Proxy-only HTTPS smoke from WSL after current-core upgrade | 3/5 passed: Reality, standard Hysteria2 and Shadowsocks |
| Proxy-only HTTPS smoke on current VPS core | 5/5 passed with current and legacy clients |
| Read-only Windows readiness audit | Executed; no admin token, active TUN/service or verified kill switch |
| Loopback management access through successful proxies | Rejected |

Earlier Reality/Salamander failures on the legacy core recovered after restart;
that did not establish a permanent root cause. The application core was subsequently
upgraded only after isolated validation. All five now pass local VPS probes with
both validated client versions. TUIC and Salamander still fail from the tested WSL
path, with no arriving packets on those ports in a synchronized guest capture.
The upstream drop is **unresolved** pending provider/network authority. These smoke
tests do not establish browser, WebRTC, UDP, or TUN failure safety.

## Current encrypted-DNS state

The VPS now uses a public DuckDNS certificate whose SAN matches the DuckDNS name.
AdGuard v0.107.79 serves private DoT/DoQ on 853 and private DoH on 8445; plain
DNS is disabled. The private admin UI is on the WireGuard address and must be
accessed through a tunnel. A strong AdGuard web user still needs to be created
interactively by the operator. DNSCrypt is intentionally not enabled: its server
provider configuration and client stamp are separate cryptographic material and
must be generated and verified before opening a private listener. The celenityy
recommendation was not imported wholesale because it recommends enabling logs
and statistics, which conflicts with the privacy requirement.

## Blocking release gates

1. Correct/review the pre-guest UDP drops with OCI/network authority and retest
   the automatic selector across real destinations, UDP/TCP, MTUs, reconnects,
   long-running service state, and restricted/unrestricted approved networks.
2. Establish a supported/maintained host OS and current server-core upgrade plan
   with a VM snapshot, console recovery, SSH verification, and rollback. Legacy
   host has no attached extended-security subscription; post-quantum SSH was not
   negotiated. Proxy-core modernization alone does not resolve OS maintenance.
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
- AdGuard Home v0.107.79 configuration: https://adguard-dns.io/kb/adguard-home/configuration/
- AdGuard DNS encryption: https://adguard-dns.io/kb/adguard-home/encryption/
- AdGuard configuration: https://adguard-dns.io/kb/adguard-home/configuration/
- Shadowsocks-2022 URI requirements: https://shadowsocks.org/doc/sip002.html
