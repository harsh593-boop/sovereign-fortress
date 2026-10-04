# Windows network readiness: diagnostic, not a kill switch

`windows_network_audit.ps1` is a **local, read-only inventory**. It does not
connect to a VPS, validate private profiles, run a tunnel, request elevation,
change firewall/routes/services/adapters/certificates, install drivers, capture
packets, or read private files/logs. **No persistent kill switch is implemented
or verified by this audit.** A healthy inventory is not proof of leak prevention.

## Run safely

From a normal Windows PowerShell 5.1 (or Windows PowerShell-compatible newer
host), in this checkout:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -File .\windows_network_audit.ps1
```

Do not use `-ExecutionPolicy Bypass` or change machine execution policy just to
run this diagnostic. If policy blocks execution, obtain administrator approval
or use a permitted signed-script workflow. There is no `RunAs`/UAC prompt in the
script. An approved rerun in an already elevated shell can improve visibility;
it still makes no networking changes. Avoid `-Verbose`/`-Debug` invocation.
Dot-sourcing defines the audit functions without running queries.

The script emits one compact JSON object. It never exports adapter aliases,
interface descriptions, service names/paths/arguments, rule names, policy
source paths, account names, exception text, IP addresses, DNS lists or secrets.
Native metadata is reduced to the fixed fields below and then discarded; this
is not an inventory of client credentials or private configuration.

### Schema and interpretation

All leaves are booleans, nonnegative integer counts, or JSON `null`.
`schema_version` is currently `1`. No overall readiness/pass flag exists.
Every query section has `query_succeeded`; **false means unavailable/failed,
not absent, safe, or passed**, and its remaining leaves are `null`. Properties
that native APIs leave `NotConfigured`/unrecognized remain `null` even when the
query succeeds. Consumers must distinguish `false`, `0`, and `null`.
A zero count is meaningful only after a successful complete enumeration.
Process exit success means JSON was emitted, not that networking is ready.

| Section | Meaning and limits |
| --- | --- |
| `elevation` | Current token is in the Administrator role; no username or token data emitted. `elevated=false` is a known non-elevated token, not a failure. |
| `adapters` | `Get-NetAdapter -IncludeHidden`: total/up/hardware counts and description-based TUN/Wintun candidate/up counts. A matching description is a heuristic, **not proof of driver identity, capability, signing, ownership or a working tunnel**. No candidate while disconnected is normal when adapters are created on demand. |
| `services` | `Get-Service`: sing-box/Hiddify name/display-name candidate and running counts; `MpsSvc` and `BFE` running booleans. GUI/process-only clients need not register services. A service name does not establish binary trust, pinned core version or routing correctness. No process command lines are read. |
| `firewall_profiles` | Domain/Private/Public from **ActiveStore**, not merely PersistentStore: enabled, default outbound block, local firewall/IPsec rule-merge permission. `fully_known_profile_count` counts rows with all four properties resolved. `NotConfigured` is not silently assumed safe or merge-enabled. These are all profile policies, not a claim that all three are currently active networks. |
| `firewall_rules` | ActiveStore with `TracePolicyStore`: total/enabled counts, enabled outbound `Allow` and `Block` counts, and GroupPolicy-source count. Counts are **not** reachability/conflict analysis; no address/program/service/interface filters are dumped or analyzed. |
| `group_policy` | Local RSOP profile count, explicitly configured outbound action count, and local firewall/IPsec merge-disabled counts. RSOP is the applied GPO sum, not a DC connection. Zero does not rule out MDM/CSP, service-hardening, future refresh, or other WFP policy. |
| `npcap_driver` | Filtered local `Win32_SystemDriver` CIM query for the `npcap` kernel driver: presence/running, not version, capture permission, or installation health. No DLL/file scans. Legacy WinPcap/renamed drivers are outside this test. |
| `capture_tools` | Application command discovery for `pktmon.exe`, without invoking it. Presence does not prove functionality or UAC access. No capture is started. |

`read_only=true` describes this script's operations. The constants
`kill_switch_verified=false`, `packet_paths_verified=false`, and
`gpo_overrides_ruled_out=false` deliberately remain false, regardless of counts.
Query failures are isolated so one inaccessible provider does not hide other
results. Raw failure reasons are intentionally omitted for privacy.

## Supported evaluation modes (not release claims)

The repository's reference Full-Tunnel and Traffic-Only profiles both use
**TUN**, not just a system HTTP proxy. Use a single client at a time and pin the
actual core: public templates target sing-box **1.14**; the explicitly requested
legacy flow uses **1.11.4** syntax. Future documentation/examples can target
newer versions; do not copy their fields into a pinned older core blindly.

- **Full-Tunnel:** payload and DNS should traverse the tunnel. Underlay egress
  should be limited to the declared tunnel endpoint/transport and the minimum
  separately approved network/bootstrap controls. No general local DNS or
  arbitrary app DoH bypass. Approved LAN exceptions must be explicit, recorded
  and tested; they reduce the scope of the claim.
- **Traffic-Only:** payload should traverse TUN; intended DNS egress is local
  through a defined DNS helper/resolver path. This **intentionally exposes DNS
  egress**, and does not guarantee that arbitrary OS/browser/app DoH takes that
  path. Validate helper behavior, OS caching, browser secure-DNS settings and
  client rewrites independently. DNS over encrypted HTTPS cannot universally
  be distinguished from application traffic. App DoH may remain tunneled.

Hiddify may import only proxy nodes and regenerate routing/DNS. An import or
successful connection is not evidence that either mode survived. After explicit
permission, the operator must privately check the generated effective runtime
profile against the pinned core and document differences without publishing
credentials. This audit never opens that profile.

sing-box `auto_route` and Windows `strict_route` address routing and multihomed
DNS behavior while the core is operating; they are not persistent enforcement
when the core exits. In 1.14, `dns_mode=hijack` with `strict_route` blocks port 53
on non-TUN interfaces. That can conflict with Traffic-Only's local DNS helper.
Do **not** disable strict routing or broaden egress globally as a workaround:
test the pinned helper/client interaction and redesign the DNS path if necessary.
Linux `auto_redirect`/interface-selection semantics are not Windows guarantees.

## Proposed fail-closed architecture — privileged design work only

There are **no rule-writing commands in this deliverable**. Implementing the
following requires separate approval, UAC/administrator rights, recovery access,
a maintenance window and disposable VM trials before any real endpoint changes.

1. **Threat boundary:** protect ordinary non-admin apps from direct physical or
   alternate-adapter Internet egress when a tunnel is unavailable. Administrators,
   compromised kernel/driver code and policy authorities can defeat local
   controls. WSL/Hyper-V guests, forwarding, other VPNs and third-party WFP
   providers need explicit scope and separate tests; host inventory is not proof
   that their traffic is covered.
2. **Persistent default-deny:** a reviewed Windows Defender Firewall design must
   enable protection and use default outbound **Block on Domain, Private and
   Public**, with narrow allow exceptions, before releasing app traffic. This is
   a proposal, not the machine's current state. Policy must remain independent
   of GUI/core life and preserve approved transport while blocking ordinary
   underlay traffic even if TUN routes disappear. Boot-time enforcement and BFE/
   firewall-service outages need separate proof; ordinary firewall rules alone
   must not be advertised as kernel/service-outage protection.
3. **Rule precedence is essential:** Windows explicit **Block beats a conflicting
   Allow**, including more-specific Allow rules; there is no user rule ordering.
   Do **not** create an explicit block-all-underlay rule and expect tunnel/DNS
   allow exceptions to override it. Use default Block plus a reviewed allowlist,
   or demonstrably disjoint explicit block scopes. A separately engineered WFP
   implementation is an alternative, not something this audit installs/proves.
4. **Existing outbound allows matter:** default Block does not neutralize explicit
   outbound Allow rules from local policy, GPO, MDM, installers or other sources.
   Broad app/port/service/Any-interface allows can permit direct Internet escape.
   Inventory and review their filters privately; remove/narrow inappropriate
   rules only through an approved change. Check overlapping explicit blocks too:
   they can prevent needed tunnel transport or DNS. Counts cannot resolve this.
   Restrict ordinary app allowances to the trusted TUN where effective; restrict
   core transport to approved executable/service identity, endpoint addresses,
   ports/protocols and necessary underlay. Prevent core direct/fallback outbounds
   from becoming an unrestricted physical-egress exemption. Scope all exceptions
   for IPv4 **and** IPv6 and validate actual Windows packet classification.
5. **GPO/MDM authority:** inspect effective ActiveStore and applied RSOP, not just
   the locally written rules. `AllowLocalFirewallRules=false` can cause local
   exceptions to be ignored. A central broad allow can undermine default Block;
   central default actions and rule refresh can override local assumptions.
   Local Group Policy is also applied even when local rule merging is disabled.
   Do not fight organizational policy: involve the policy owner. Repeat proof
   after refresh and policy changes. Unknown policy visibility is a release gate.
6. **New/changing NICs:** cover all profiles and all untrusted egress, not a
   snapshot of today's Wi-Fi/Ethernet aliases. A newly attached USB/WWAN NIC,
   virtual NIC, alias change, profile transition or TUN recreation must default
   deny before a reconciliation service notices it. Never use a periodic watcher
   as the only containment mechanism. TUN identity drift must not promote a
   spoofed/renamed adapter to trusted; failure to identify it means deny/unready.
   Test physical-interface binding, IPv6 preference, network handover and startup
   races. Do not automatically allow every newly discovered interface.
7. **IPv6 and network controls:** either prove dual-stack tunneling and narrowly
   scoped v6 exceptions or reject non-tunnel IPv6 under the reviewed policy.
   Disabling IPv6 in an app/profile is not host-wide containment. DHCP, DHCPv6,
   ARP and IPv6 neighbor/router discovery may be necessary for underlay use;
   justify minimal link-local controls individually, not broad Internet allows.
   LAN discovery, captive portals, multicast DNS/LLMNR and local intranet access
   are explicit exception decisions, not automatically safe defaults.
8. **DNS-helper exception:** Full-Tunnel must not inherit Traffic-Only's local DNS
   allowlist. In Traffic-Only, permit only the approved helper/service to approved
   resolvers and ports (and required pinned DoH endpoints when justified), not
   TCP/UDP 53 or TCP 443 for every app. A shared `svchost.exe` or helper-wide 443
   allow can be a broad bypass; use service scoping where supported and prove
   classification. Destination ports alone cannot prove DNS-only traffic. Test
   helper compromise/alternate port use within the stated threat model. Prevent
   general payload relay through an allowlisted helper. Helper absence/crash must
   fail DNS closed, not revert to unrestricted system DNS. Define whether narrow
   DNS egress intentionally remains possible when the tunnel is down.
9. **Bootstrap and recovery:** endpoint hostname resolution is a dependency:
   choose an explicit minimal bootstrap path or maintained trusted endpoint set;
   never solve bootstrap by allowing all core/OS DNS/HTTPS indefinitely. Account
   for endpoint rotation and network changes without an unrestricted fallback.
   Activate/reconcile policy transactionally with connectivity blocked during
   incomplete changes. Protect policy/core binaries and service permissions.
   Keep a separately reviewed rollback and local-console recovery procedure;
   do not depend on remote connectivity surviving a failed rollout.

## Packet-level acceptance plan (operator-executed, not run by audit)

Use a disposable Windows VM with local console and snapshot first. Use synthetic
apps, domains and operator-controlled lab endpoints/resolvers, not private
profiles, production secrets or an unapproved VPS. With explicit permission,
prepare separate approved synthetic Full-Tunnel/Traffic-Only profiles and validate
with the exact pinned core's `check` operation. Record core/client/helper versions
and privately compare runtime routing/DNS before connecting. Packet captures and
runtime configs can be sensitive: keep them outside the checkout and publish only
sanitized counts/verdicts. Npcap installation is separate consented driver work;
pktmon is an in-box alternative. Capturing/filter changes usually require UAC.

Capture **all available physical/virtual underlays**, not only TUN, plus an
independent lab gateway observer and tunnel-side observer when possible. Account
for capture offload/duplicates, loopback, WFP drops and capture blind spots.
An apparent missing packet in one capture is not proof of no leak.

| Experiment | Full-Tunnel expected | Traffic-Only expected |
| --- | --- | --- |
| Healthy TCP HTTPS, UDP/QUIC, IPv4/v6 literal connections | Only declared encrypted transport on underlay; payload visible only at lab tunnel exit | Same payload containment |
| OS/app DNS UDP/TCP 53, browser DoH/DoT, helper requests; unique uncached names | Tunnel path; no arbitrary non-TUN DNS; any bootstrap exception measured separately | Declared helper DNS path local; unrelated payload still tunneled; document actual app DoH behavior rather than asserting universal DNS locality |
| Proxy bypass / no system proxy, raw sockets, app bound to physical NIC, STUN/WebRTC UDP | Tunnel or blocked, never direct underlay payload | Same, except declared helper DNS |
| Core crash/kill, GUI exit, service stop, endpoint unreachable, reconnect/fallback | Payload blocked; no DNS fallback beyond the exact approved bootstrap/control budget | Payload blocked; helper DNS only if intentionally allowed in down-state; otherwise blocked |
| Helper stop/crash, DNS timeout, alternate resolver, rogue DoH app | No broadened local fallback | No unrestricted OS/helper fallback; packet evidence for each attempted exception escape |
| TUN deletion/recreation, disconnect/reconnect, sleep/resume, boot/login before client | Containment persists; no startup/teardown race leakage | Same payload containment and declared DNS budget |
| Wi-Fi/Ethernet handover, added USB/virtual/WWAN NIC, profile change, IPv6-only/dual-stack | New path denied until approved; all address families tested | Same plus resolver/interface change analysis |
| Existing broad Allow, conflicting explicit Block, policy refresh, disabled local merge | Demonstrate expected failure/denial and detect policy drift; never silently broaden allowances | Same, with helper-specific conflicts |

Repeat failure injection while sustained synthetic traffic runs, including active
TCP flows and fresh UDP/DNS requests. Measure the full transition window, not
just stable before/after states. Keep an expected underlay packet budget for each
mode (transport, link-local controls, and declared DNS/bootstrap), count all
unexpected traffic, and require **zero unexpected payload/DNS egress**. DNS
exceptions mean Traffic-Only must not be described as blocking every packet when
disconnected. Any untested NIC, address family, app class or failure remains
**unverified**, not passed. Tests of firewall/BFE failures, driver handling, boot,
new NICs, policy refresh and rollback belong in a maintenance/disposable-VM gate.

## Offline and native verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_windows_network_audit.py -v
```

The stdlib suite checks fixed privacy/safety contracts and, when a native
PowerShell executable is available, parses the script and runs **synthetic
mocked queries** for success/empty/unknown/failure cases. It never runs real
network queries in its offline tests. Skipped native tests are reported as skips,
not passes. A separately invoked native read-only smoke proves script/provider
execution only; it cannot satisfy the packet-level acceptance gates above.

### Actual implementation evidence (local snapshot, not a release gate)

- The command above ran **12 tests successfully, with no skips**, including native
  PowerShell parsing (zero parse errors), command-AST safety checks, mocked
  success/absence/error/incomplete-record/unknown-enum cases and privacy checks.
- Native Windows PowerShell **5.1.26100.9444** was available. The read-only smoke
  command below exited zero and every query section returned
  `query_succeeded=true`:

  ```powershell
  powershell.exe -NoLogo -NoProfile -NonInteractive -File .\windows_network_audit.ps1
  ```

- Sanitized snapshot: non-elevated token; 20 adapters (8 up, 2 hardware), zero
  description-based TUN/Wintun candidates; zero sing-box/Hiddify service
  candidates. BFE and firewall services running. All three firewall profiles
  enabled, **all three default outbound Allow**, with local firewall/IPsec rule
  merging allowed. Effective rules: 711 total, 457 enabled, 134 enabled outbound
  Allow, 170 enabled outbound Block, 170 GroupPolicy-source rules. RSOP returned
  three profiles, no explicitly configured outbound actions or disabled merge
  counts. Npcap driver absent; pktmon command present.
- This is **not fail-closed readiness**. The audit did not inspect rule filters or
  private runtime profiles, connect a tunnel, capture traffic, request UAC,
  exercise policy refresh/new NICs, or perform a maintenance/VM rollout. Those
  are still separate consented gates. Future inventory results may differ.

## Authoritative references

- Microsoft [Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules): outbound precedence, default versus explicit block, rule merging, Local GPO behavior.
- Microsoft [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps): ActiveStore and local RSOP semantics.
- Microsoft [Pktmon](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon): in-box packet capture/counting and analysis; discovery is not capture validation.
- sing-box [TUN documentation](https://sing-box.sagernet.org/configuration/inbound/tun/): platform/version-specific routing and Windows strict-route DNS behavior.
- [Wintun project](https://www.wintun.net/): kernel TUN adapter and signed driver distribution; a description match is not driver verification.
