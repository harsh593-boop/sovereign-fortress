# YogaDNS Configuration Guide for Sovereign Fortress

This guide explains how to configure YogaDNS on Windows 11 so that it works in complete harmony with the Sovereign Fortress VPN, prevents campus DNS hijacking, preserves access to campus intranet, and routes your queries through your personalized NextDNS profile (`<YOUR_NEXTDNS_ID>`) or Self-Hosted Sovereign DNS.

---

## 1. Why YogaDNS is Critical on Campus Wi-Fi
- **The Problem**: Campus firewalls often intercept UDP Port 53 DNS queries and drop Port 853 (DNS-over-TLS).
- **The Solution**: YogaDNS runs locally on Windows as a network driver, intercepting Windows DNS queries before they touch the physical adapter and wrapping them in **DNS-over-HTTPS (DoH)** over Port 443.
- **The Intranet Challenge**: If 100% of DNS is sent to external DNS, campus intranet domains (`*.campus.internal`) will fail to resolve because public DNS does not know internal campus IP addresses.

---

## 2. Step-by-Step YogaDNS Setup

### Step 1: Add the NextDNS Server
1. Open **YogaDNS**.
2. Go to **Configuration** -> **DNS Servers** -> Click **Add...**
3. Configure the server:
   - **Name**: `NextDNS Encrypted`
   - **Type**: `DNS-over-HTTPS`
   - **URL**: `https://dns.nextdns.io/<YOUR_NEXTDNS_ID>`
4. Click **OK**.

---

### Step 2: Configure Routing Rules in YogaDNS
Go to **Configuration** -> **Rules** and set up the following two rules in exact priority order:

#### Rule 1: Campus Intranet & Local Subnets (Top Priority)
- Click **Add...**
- **Name**: `Campus Intranet Bypass`
- **User Defined Conditions**:
  - In the Hostnames/IP box, enter:
    ```text
    *.campus.internal
    campus.internal
    10.*.*.*
    172.16.*.*
    192.168.*.*
    *.local
    ```
- **Action**: Select **System Default** (or **Direct**)
- Click **OK**.
- *Why*: This forces campus portal, Moodle, and intranet attendance domains to resolve via the campus local DHCP DNS server!

#### Rule 2: Default Rule for All Internet Traffic
- Edit the default rule (or create one below Rule 1):
- **Name**: `Default NextDNS Encrypted`
- **Condition**: `Any` (or `*`)
- **Action**: Select **NextDNS Encrypted**
- Click **OK**.

---

## 3. Coexistence with Sovereign Fortress VPN

### Option A: Using Hiddify (VLESS-Reality / Hysteria 2 / TUIC v5)
To ensure Hiddify does not fight YogaDNS:
1. Open **Hiddify** -> **Settings**.
2. Under **DNS Mode** (or Inbound DNS):
   - Choose **System Default** (or Direct).
3. Under **Routing**:
   - Turn **ON** "Bypass LAN" (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
4. **Result**:
   - YogaDNS resolves all public domains securely via NextDNS DoH.
   - Hiddify tunnels all web and app traffic through the Oracle VM in Mumbai.
   - Campus intranet traffic and DNS bypass the tunnel and connect locally.

### Option B: Using WireGuard (Native or WireGuard-over-TCP)
1. Open the WireGuard Windows client.
2. If you want YogaDNS to manage DNS exclusively:
   - Open your WireGuard tunnel configuration (`fortress-wireguard.conf` or `fortress-wireguard-tcp.conf`).
   - Remove or comment out the line:
     `# DNS = 1.1.1.1, 8.8.8.8`
   - Save the tunnel.
3. **Result**:
   - WireGuard routes 100% of IP traffic through Mumbai.
   - YogaDNS continues to resolve all DNS queries via NextDNS without interruption.
