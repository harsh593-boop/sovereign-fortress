# Windows DNS and routing modes

This guide documents the limits of the reference profiles. It deliberately does
not promise universal local DNS, zero logging, or a persistent Windows
kill-switch. Those properties require controls outside a Sing-box JSON profile.
Use this software only on systems and networks you own or are authorized to
operate.

## Full-Tunnel mode

Full-Tunnel mode is the mode that can provide a coherent fail-closed traffic
model while the client is running:

```text
Applications -> Sing-box TUN -> selected proxy -> VPS
DNS hijack   -> private DoT 10.8.0.1:853 through the selected proxy -> AdGuard Home
```

DoH/DoT configured inside applications may still use their own provider through
the tunnel. Full-Tunnel does not magically force encrypted application DNS
through AdGuard or make DNS-based ad blocking universal.

The client profile must not use `127.0.0.1:5335` for the VPS resolver. On
Windows, `127.0.0.1` means the Windows client itself. The reference profile
uses a typed TLS server (`server: 10.8.0.1`, `server_port: 853`, TLS server name
set to the DuckDNS certificate name) with `detour: proxy` in 1.14. Full legacy
1.11 mode is retired rather than falling back to plaintext DNS. The address is private to the
server's WireGuard interface and is reached after the proxy connection
terminates on the VPS.

For this mode:

1. Disable YogaDNS while testing.
2. Disable browser-specific Secure DNS overrides unless they are explicitly
   included in the test plan.
3. Use the generated TUN profile with `strict_route: true`.
4. Treat IPv6 as unavailable unless an IPv6 tunnel and its kill switch have
   been separately audited. The sample profile blocks IPv6 while active.
5. Verify that the tunnel endpoint itself is excluded from the TUN route to
   avoid a route loop.

The server uses AdGuard's actual root-level `querylog` and `statistics` settings,
with `enabled: false` and `querylog.file_enabled: false`. Incoming plain DNS is
disabled; private DoT/DoQ use port 853 and private DoH uses port 8445. Its writable
config and working data are under `/run/fortress/adguard` on checked `tmpfs`; a
root-owned template restores that policy at boot. This minimizes
local application persistence. It cannot prevent host, kernel, cloud-provider,
backup, upstream-DNS, or administrator observation.

## Traffic-Only mode

Traffic-Only mode is a **best-effort compatibility profile**, not a universal
DNS egress mechanism. It currently provides direct handling for:

- selected DNS client process names;
- DNS protocol traffic visible to Sing-box;
- common ports such as 53, 853, and 5353;
- configured provider domain suffixes; and
- RFC1918/private destinations and configured campus domains.

The 1.14 profile sets `dns_mode: disabled`, so TUN does not intentionally replace
native DNS settings. The legacy profile cannot express that 1.14 feature.
Provider exceptions are constrained to DNS-specific names and relevant ports;
`cloudflared` is not a blanket bypass because it can carry non-DNS tunnels.

All other traffic falls back to the proxy. In particular, a JSON route cannot
reliably distinguish arbitrary HTTPS web traffic from DoH on TCP 443. It also
cannot identify every embedded resolver, hard-coded resolver IP, DNSCrypt
flow, DoQ flow on an unusual port, or Windows DNS Client DoH session. A
`direct` Sing-box rule is not proof that the packet physically left through
the Wi-Fi/Ethernet adapter when a TUN owns the default route.

Therefore these requirements cannot all be guaranteed by this profile alone:

- all application TCP/UDP traffic through the VPS;
- every possible DNS implementation physically outside the tunnel; and
- no DNS or WebRTC escape if the tunnel stops.

To claim universal local DNS, add and independently verify a Windows WFP
policy or a dedicated client driver that classifies and permits the intended
resolver egress before the TUN default route is enabled. The repository does
not currently ship such a policy. Do not add `svchost.exe` as a blanket direct
exception: that would bypass unrelated Windows services and would not solve
embedded application resolvers.

If universal local DNS is more important than universal application tunneling,
run the local DNS client without a TUN default route and accept that arbitrary
UDP/WebRTC traffic is then outside the VPN. If universal traffic protection is
more important, use Full-Tunnel mode and send DNS through the VPS.

## YogaDNS and browser configuration

When testing the best-effort Traffic-Only profile:

1. Bind YogaDNS to the physical Wi-Fi/Ethernet interface, not the VPN/TUN
   adapter.
2. Configure only the DNS methods you intend to test; record whether the
   resolver is local UDP/TCP, DoT, DoH, or DNSCrypt.
3. Set Chrome Secure DNS to the system provider for a YogaDNS test, or test
   Chrome's custom DoH separately. Do not treat one as evidence for the other.
4. Do not run multiple VPN/TUN clients simultaneously.
5. Record the actual resolver destination and egress interface with a packet
   capture. The resolver's public IP in a browser leak site is not enough to
   establish the source address.

## WebRTC and IPv6 checks

A system HTTP/SOCKS proxy cannot protect raw UDP WebRTC/STUN traffic. A
running TUN may protect it, but only packet capture and a failure test establish
that claim. For a controlled browser test:

- use a fresh browser process;
- test with the TUN active;
- inspect both the physical and TUN interfaces for STUN packets;
- test IPv4 and IPv6 separately; and
- stop the client and confirm whether traffic is blocked or merely falls back
  to the physical interface.

A browser page showing the VPS address proves only that one HTTP request used
the proxy. It does not prove WebRTC, DNS, UDP, IPv6, or tunnel-failure safety.
