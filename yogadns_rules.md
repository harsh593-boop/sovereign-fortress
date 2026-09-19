# YogaDNS & Split-Tunnel DNS Architecture for Sovereign Fortress

This document provides a comprehensive technical breakdown of how DNS resolution and network routing function across **Full Traffic (Network Mode)** and **Split/Bypass Mode**, explains the exact root cause behind previous crashes with YogaDNS and Chrome Secure DNS, and provides the step-by-step configuration for seamless coexistence.

---

## 1. Dual-Mode Architecture: Full Traffic vs. Split/Bypass Mode

```
Mode A: Full Traffic (Network Mode)
[All Applications] ---> [Sing-box TUN (0.0.0.0/0)] ---> [Encrypted VPN Tunnel] ---> [Oracle Cloud Mumbai]
                                                                                           |
                                                                                    [Unbound 127.0.0.1:5335]
                                                                                           |
                                                                                    [Root Name Servers (DNSSEC)]

Mode B: Split Intranet (Bypass LAN Mode)
[Browser / Apps]
   |---> Campus Domains (*.campus.internal & 10.0.0.0/8) ---> [Physical Wi-Fi] ---> [Campus DHCP DNS (10.x.x.x)]
   |---> Public Internet Traffic (Web, GitHub, Steam)   ---> [Sing-box TUN]   ---> [Encrypted Tunnel (Mumbai)]
   |---> DNS for Public Internet (DoH)                 ---> [YogaDNS / NextDNS (Port 443)]
```

### Mode 1: Full Traffic (Network Mode)
- **Routing Scope**: 100% of IP traffic (`0.0.0.0/0` and `::/0`) is captured by the virtual TUN adapter (`tun0` / WinTun).
- **DNS Resolution**: Sing-box hijacks UDP/TCP port 53 (`action: hijack-dns`) and forwards all queries inside the encrypted tunnel directly to the server's self-hosted **Unbound** recursive resolver (`127.0.0.1:5335`).
- **Privacy Guarantee**: Unbound queries the 13 root name servers directly using DNSSEC and QNAME minimisation. Zero ISP DNS logging, zero Cloudflare/Google DNS logging, zero Oracle VPC logging (`169.254.169.254` eliminated).
- **Limitation**: Campus intranet domains (`*.campus.internal`, internal Moodle, attendance servers) cannot resolve because public root DNS has no knowledge of internal campus private IP subnets.

### Mode 2: Split Intranet / Bypass LAN Mode (Traffic Only)
- **What is "Bypass LAN"?**: It configures explicit routing table exclusions for RFC 1918 private subnets:
  - `10.0.0.0/8` (Campus Wi-Fi subnets)
  - `172.16.0.0/12` (Host-only / VM subnets)
  - `192.168.0.0/16` (Home / local LAN subnets)
  - `127.0.0.0/8` (Local loopback)
  - `169.254.0.0/16` (Link-local autoconfiguration)
- **How it makes it "Traffic Only"**: Packets matching private destination CIDRs are routed with `outbound: "direct"`. They exit directly through the physical network adapter (Wi-Fi / Ethernet) to the local campus gateway, completely bypassing the VPN tunnel. Only external public Internet traffic enters the proxy tunnel.

---

## 2. Why YogaDNS and Chrome Secure DNS Crashed (Root Cause Analysis)

Users commonly experience crashes, `ERR_NAME_NOT_RESOLVED`, or complete internet freezing when running Hiddify/Sing-box with YogaDNS and Chrome Secure DNS simultaneously. Here is the exact technical explanation of why this happens and why Cloudflare WARP did not experience it:

### Root Cause 1: Windows Filtering Platform (WFP) Kill-Switch Driver Deadlock
- **The Conflict**: Both YogaDNS and Sing-box TUN install kernel callout drivers using the **Windows Filtering Platform (WFP)**.
- **The Trigger (`strict_route: true`)**: When Sing-box TUN has `"strict_route": true`, it installs a strict WFP filter (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`) that acts as an aggressive firewall kill-switch. It drops any outbound packet that is not routed through the TUN adapter or originating from Sing-box's own binary.
- **The Deadlock**: YogaDNS runs as an independent Windows service (`YogaDNS.exe`). When YogaDNS tries to send its DNS-over-HTTPS (DoH) packets (`https://dns.nextdns.io:443`), Sing-box's strict WFP filter detects non-TUN port 443 traffic and **drops it**. YogaDNS hangs waiting for TCP acknowledgment, Windows network service threads become starved, and the network stack freezes or crashes.

### Root Cause 2: Infinite Circular DNS Loop
1. An application initiates a connection to `github.com`.
2. YogaDNS intercepts the DNS request and packages it as an HTTPS query to `https://dns.nextdns.io/doh`.
3. If Hiddify TUN intercepts all port 443 traffic, it routes YogaDNS's DoH packet into the VPN tunnel.
4. But the VPN tunnel itself requires resolving the server's endpoint or domain!
5. This creates an infinite circular dependency: **YogaDNS needs the tunnel to send DoH &rarr; Tunnel needs YogaDNS to resolve endpoints**. Socket buffers exhaust, resulting in connection drops.

### Root Cause 3: Chrome Secure DNS Triple-Interception Collision
- Google Chrome contains its own built-in asynchronous DNS client (`NetworkService`).
- When Chrome's "Secure DNS" is set to "Custom (NextDNS/Cloudflare)", Chrome attempts to establish its own HTTP/2 or HTTP/3 QUIC connection directly to the DoH server.
- Having **three separate layers** (Chrome DoH &rarr; YogaDNS NDIS filter &rarr; Sing-box WinTun WFP driver) attempting to inspect and rewrite the same socket simultaneously leads to race conditions, TLS handshake resets, and `ERR_NETWORK_CHANGED` / `ERR_NAME_NOT_RESOLVED`.

### Why Cloudflare WARP Had No Issues
Cloudflare WARP is a single, monolithic, proprietary client. It bundles its own WireGuard driver and DoH client (`1.1.1.1`) inside a single WFP callout module. It explicitly whitelists its own local resolver IP (`162.159.36.1`) from the tunnel route table. There is only **one** driver operating, so no driver-level collisions occur.

---

## 3. The Definitive Solution: 100% Harmonious Coexistence

To achieve the speed of Sovereign Fortress VPN, the custom DoH blocking of NextDNS, and instant access to campus intranet:

### Step 1: Fix Sing-box TUN Configuration (Already Applied in Repository)
In your Sing-box client profile (`fortress-traffic-only.json` and `fortress-full-tunnel.json`):
1. **Disable `strict_route`**: Set `"strict_route": false`. This prevents the WFP kill-switch from blocking YogaDNS in both Full Traffic and Split Mode.
2. **Add `route_exclude_address`**: Explicitly exempt LAN CIDRs from being intercepted by the TUN driver:
   ```json
   "inbounds": [
     {
       "type": "tun",
       "tag": "tun-in",
       "address": ["172.19.0.1/30"],
       "auto_route": true,
       "strict_route": false,
       "route_exclude_address": [
         "10.0.0.0/8",
         "172.16.0.0/12",
         "192.168.0.0/16",
         "127.0.0.0/8",
         "169.254.0.0/16"
       ],
       "stack": "system",
       "sniff": true
     }
   ]
   ```

### Step 2: Configure YogaDNS Rules
In YogaDNS, go to **Configuration** &rarr; **Rules**:

#### Rule 1: Campus Intranet & Private Networks (Highest Priority)
- **Name**: `Campus Intranet Bypass`
- **User Defined Conditions**:
  ```text
  *.campus.internal
  campus.internal
  10.*.*.*
  172.16.*.*
  192.168.*.*
  *.local
  *.internal
  ```
- **Action**: Select **System Default** (Direct to physical adapter DHCP DNS).

#### Rule 2: Default Rule for Global Encrypted DNS
- **Name**: `NextDNS DoH`
- **Condition**: `Any`
- **Action**: Select your configured NextDNS DoH server (`https://dns.nextdns.io/<YOUR_NEXTDNS_ID>`).

#### Rule 3: Network Interface Binding
- In YogaDNS &rarr; **Configuration** &rarr; **Network Interfaces**:
- Ensure YogaDNS is bound to your physical **Wi-Fi** or **Ethernet** network interface, and NOT set to intercept the virtual `wintun` or `Hiddify` interface.

### Step 3: Configure Google Chrome
To eliminate the triple-interception collision in Chrome:
1. Open Chrome &rarr; **Settings** (`chrome://settings/security`).
2. Scroll to **Use secure DNS**.
3. Select **With your current service provider** (System default).
4. *Result*: Chrome delegates all DNS requests to the Windows network stack, where YogaDNS cleanly intercepts and encrypts them via NextDNS DoH without conflicts!

---

## 4. Verification Checklist

| Test | Expected Behavior | How to Test |
| :--- | :--- | :--- |
| **Campus Portal** | Resolves via 10.x.x.x and loads directly | Navigate to `portal.campus.internal` |
| **NextDNS Logs** | Public domains appear in your NextDNS dashboard | Check `test.nextdns.io` in browser |
| **VPN Tunnel** | IP shows Mumbai Oracle VM (`<YOUR_SERVER_IP>`) | Check `https://api.ipify.org` |
| **DNS Leak** | No campus or ISP DNS servers exposed for public queries | Check `https://browserleaks.com/dns` |
