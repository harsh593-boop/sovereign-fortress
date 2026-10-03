# Security remediation status (local, unverified)

The current checkout is **not production-ready**. No remote VPN service,
Windows firewall, Hiddify runtime configuration, or user credentials were
changed by this review. The public GitHub `main` history was replaced with an
orphaned sanitized reference commit; this does not rotate previously exposed
credentials or invalidate existing clones. A successful offline unit test is
not evidence of a leak-free deployment.

## Local changes prepared

- Subscription service requires TLS at the socket, uses Secure session cookies,
  and no longer embeds the SSH enrollment seed in dashboard HTML.
- Fresh deployments persist the generated subscription token and explicit
  endpoint domain into the runtime state used by the subscription daemon.
- The installer verifies AdGuard's query-log/statistics settings and both
  runtime data mounts are `tmpfs`; service stdout/stderr is not forwarded to
  journald.
- The portal and client guidance now describe traffic-only DNS as best-effort
  and explicitly reject universal-DNS, zero-log, and persistent-kill-switch
  claims.
- Full-mode sample DNS targets the VPS private resolver address through a proxy
  detour; it does not send plaintext DNS to a public server port.
- Example profiles explicitly reject IPv6 while the TUN is running. This is
  **not** a Windows kill switch when the process or tunnel stops.
- AdGuard service waits for the WireGuard private interface; its data directory
  is volatile and application query logging is disabled in the installer.
- Installer refuses an existing deployment rather than silently rotating its
  credentials. It requires an independently verified AdGuard archive checksum.
- The privacy scanner checks ignored worktree artifacts and Git objects; its
  findings are detection signals, not proof of anonymity or no logging.

## Blocking issues before deployment

1. **Rotate exposed secrets**: SSH key and TOTP seed, subscription tokens,
   proxy credentials, WireGuard private keys, and any DNS-provider API tokens.
   Check public releases, Git history, QR exports and cloud logs. Do not paste
   replacement secrets into chat or commit them.
2. **Do not run the installer against an existing VM.** It is a first-install
   script, not a migration. Review changes on a disposable VM first and plan
   service rollback, backups, certificate migration, and SSH recovery.
3. **Full mode:** Validate that the selected proxy can reach the private DNS
   endpoint and that the server is not exposing that resolver publicly. Check
   AdGuard startup, upstream identity, querylog/statistics, journal, backups,
   and OCI logging independently.
4. **Traffic-only mode:** Generic client-local DNS egress for arbitrary DoH,
   DoQ, DNSCrypt, embedded resolvers, Windows DoH, and ISP DNS is **not
   implemented**. Provider-domain/port exceptions cannot make this guarantee.
   A Windows WFP policy and packet-path verification are needed; Hiddify may
   discard imported DNS, route, and TUN settings. The reference profile is
   intentionally documented as best-effort rather than universal.
5. **Client kill switch:** No persistent Windows WFP fail-closed rule is
   installed. Test VPN-off, crash, reboot, sleep/wake, roaming, network change,
   and IPv6 before relying on either mode. Browser proxy-only mode cannot
   protect raw UDP/WebRTC.
6. **Logging:** tmpfs, disabled AdGuard query log, suppressed service output,
   and `chattr +i` do not prevent hypervisor observation, upstream DNS logging,
   kernel logs, crash dumps, pre-existing journals, backups, or administrator
   changes. No absolute zero-log or untraceable claim is valid.
7. **Deployment correctness:** Fresh installs must be tested for token/domain
   propagation and the installer must be run with LF line endings. The legacy
   live verifier is stale and must not be used as release evidence.
8. **GitHub:** The public `main` branch now contains the sanitized reference
   tree, but previously exposed credentials must still be rotated and old
   clones, releases, caches, and provider logs must be reviewed. Do not treat
   the history rewrite as credential revocation.

## Minimum release gate

Run offline tests (`python3 -m unittest discover -s tests -v`),
`python3 comprehensive_verification.py --offline`, Python compile,
ShellCheck/bash syntax validation on a Linux host, `sing-box check` against
both generated profiles with the pinned target version, and server unit tests.
Then use an independent packet capture on the physical and tunnel interfaces
to test TCP/UDP, WebRTC STUN, IPv4/IPv6, local DNS and arbitrary encrypted DNS,
before/after tunnel failure. Record expected source and destination for each
mode and reject the release on any mismatch. Do not use DNS leak-test resolver
IPs alone as proof of the client's source address; inspect DNS-provider logs
and actual egress packets as well.
