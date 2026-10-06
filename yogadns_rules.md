# Windows DNS and routing modes

This guide documents the limits of the reference profiles. It deliberately does
not promise universal local DNS, zero logging, or a persistent Windows
kill-switch. Those properties require controls outside a Sing-box JSON profile.
Use this software only on systems and networks you own or are authorized to
operate.

## Full-Tunnel mode

Full-Tunnel mode provides a coherent fail-closed traffic model while the client is running:

```text
Applications -> Sing-box TUN -> selected proxy -> VPS
DNS hijack   -> private DNS 10.8.0.1:5335 (UDP) encapsulated inside selected proxy -> AdGuard Home
```

DoH/DoT configured inside applications may still use their own provider through
the tunnel. Full-Tunnel routes system DNS requests into AdGuard Home on the VPS.

Inside the encrypted tunnel, DNS queries are routed directly to `10.8.0.1:5335` (plain UDP DNS)
via `detour: proxy`. Because the entire payload is already encapsulated inside the encrypted
WireGuard, VLESS (Reality), Hysteria 2, or Shadowsocks tunnel, plain UDP DNS provides instant 0-RTT
resolution without double-encryption overhead. Outside the tunnel, port 5335 is strictly blocked
by host iptables firewall rules.

AdGuard Home also runs a dedicated **DNSCrypt v2** server on port `5443` (UDP/TCP) using Curve25519
and Ed25519 authentication, which can be connected to directly using DNS stamps (`sdns://...`)
via YogaDNS, Simple DNSCrypt, or dnscrypt-proxy.

The server uses AdGuard's root-level `querylog` and `statistics` settings with `enabled: false`.
Its caching is configured for optimal performance with `cache_optimistic: true`, `cache_ttl_min: 300`,
and parallel multi-upstream querying (Quad9, Cloudflare, AdGuard).
Its writable config and working data reside on volatile `tmpfs` under `/run/fortress/adguard`.

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
