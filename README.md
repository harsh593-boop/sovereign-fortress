# Sovereign Fortress — Multi-Protocol Anti-Censorship & Zero-Trust VPN Suite (2026)

[![Author: harsh593-boop](https://img.shields.io/badge/Author-harsh593--boop-blue.svg)](https://github.com/harsh593-boop)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Android%20%7C%20Linux%20%7C%20iOS%20%7C%20macOS-emerald.svg)]()
[![Free Tier](https://img.shields.io/badge/OCI%20Always%20Free-100%25%20%240%2Fmo-purple.svg)]()
[![Censorship Resistance](https://img.shields.io/badge/Censorship%20Resistance-GFW%20%7C%20FortiGate%20%7C%20DPI%20Slayer-red.svg)]()
[![Self-Hosted DNS](https://img.shields.io/badge/DNS-Recursive%20Unbound%20%7C%20Zero--Log-blueviolet.svg)]()

A modern, sovereign, zero-log multi-protocol VPN and proxy architecture designed to defeat severe network censorship, deep packet inspection (DPI), active probing, captive portals, and nation-state firewalls (GFW, Fortinet FortiGate, RKN).

Runs 100% within the **Oracle Cloud Infrastructure (OCI) Always Free Tier ($0/month forever)**.

---

## 🏗️ System Architecture & Defense Stack

```mermaid
flowchart TD
    subgraph ClientLayer["1. Client Access Layer"]
        Hiddify["Hiddify App (Android / Windows / iOS / macOS)"]
        NativeApp["Sovereign Fortress App (Native Windows GUI)"]
        YogaDNS["YogaDNS (Windows System DNS Driver)"]
    end

    subgraph DefenseGrid["2. Network Transit & Censorship Evasion Matrix"]
        Reality["VLESS + XTLS-Reality (TCP 443)\nCamouflage: gateway.icloud.com (Apple CDN Edge)"]
        Salamander["Hysteria 2 Salamander (UDP 9444)\nChaCha20 XOR QUIC Packet Header Scrambler"]
        Hy2Std["Hysteria 2 Standard (UDP 8443)\nBrutal BBR Congestion Control (Lossy Wi-Fi)"]
        TUIC["TUIC v5 (UDP 9443)\nRFC 9000 QUIC + 0-RTT Mobile Roaming"]
        Shadowsocks["Shadowsocks-2022 (TCP/UDP 10443)\n2022-blake3-aes-256-gcm AEAD Cipher"]
        WSTunnel["WireGuard over TCP / WSTunnel (TCP 8443)\nEncapsulated inside TLS 1.3 WebSockets"]
    end

    subgraph CoreEngine["3. Sovereign Fortress Core (Oracle Cloud Mumbai)"]
        RAMFS["Volatile RAM Runtime (tmpfs /run/fortress)\nZero Disk Logs • Ephemeral Keys"]
        Singbox["Sing-box 1.11+ Core Router"]
        Unbound["Self-Hosted Unbound Recursive DNS\nRoot Hint Recursion • Zero Logs • DNSSEC"]
        SubDaemon["Dynamic 2FA Subscription & Web Portal (TCP 8443)"]
        PAM2FA["SSH PAM Google Authenticator (Key + TOTP Enforced)"]
    end

    subgraph InternetExit["4. External Exit & Destination"]
        Decoy["Active Defense Mirror: Apple CDN / Microsoft"]
        PublicWeb["Uncensored Global Internet"]
        CampusLAN["IISER Berhampur Campus Intranet (*.campus.internal & 10.0.0.0/8)"]
    end

    ClientLayer -->|Encrypted Tunnel| DefenseGrid
    YogaDNS -.->|Split Intranet Bypass| CampusLAN
    DefenseGrid -->|Multi-Protocol Inbounds| Singbox
    Singbox -->|Zero-Log Queries| Unbound
    Singbox -->|Legitimate Outbound| PublicWeb
    Singbox -.->|Active Probing Defense| Decoy
```

---

## 🌐 Dual-Mode Zero-Leak DNS Architecture

```mermaid
flowchart LR
    subgraph QueryOrigin["Client Query Origin"]
        AppQuery["User / App DNS Request"]
    end

    subgraph ModeA["Mode A: Split Intranet (YogaDNS on Windows)"]
        IntranetMatch{"Is domain\n*.campus.internal\nor 10.0.0.0/8?"}
        CampusDNS["Campus Local DHCP DNS (10.0.x.x)\n(Attendance / Moodle / Intranet Portals)"]
        YogaDoH["NextDNS DoH\n(Encrypted Port 443)"]
    end

    subgraph ModeB["Mode B: Full Traffic (Self-Hosted Sovereign DNS)"]
        TunnelDNS["Forced Sing-box TUN / Inbound DNS"]
        LocalUnbound["Oracle VM Local Unbound (Port 5335)\nRecursive Root Resolution\nZero External Vendor Logs\nOracle VPC DNS (169.254.169.254) Eliminated"]
    end

    AppQuery -->|YogaDNS Active| IntranetMatch
    IntranetMatch -->|YES| CampusDNS
    IntranetMatch -->|NO| YogaDoH

    AppQuery -->|Full Tunnel Active| TunnelDNS
    TunnelDNS --> LocalUnbound
```

---

## ⚡ Fortinet FortiGate DPI Evasion Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as User (Lenovo LOQ / Android)
    participant FortiGate as Campus FortiGate DPI Firewall
    participant Fortress as Sovereign Fortress (OCI Cloud Mumbai)
    participant Apple as Apple Mumbai Edge (gateway.icloud.com)
    participant Target as Blocked Internet (GitHub, Reddit, Steam, etc.)

    User->>FortiGate: TLS 1.3 ClientHello (SNI: gateway.icloud.com)
    Note over FortiGate: DPI Inspection: Inspects SNI & ALPN.<br/>Matches legitimate Apple CDN certificate!
    FortiGate->>Fortress: Forward TCP SYN & TLS Handshake
    alt Legitimate User Connection (Authorized Reality Key)
        Fortress->>User: Complete XTLS-Vision Session
        User->>Fortress: Stream Encrypted Traffic Inside TLS 1.3
        Fortress->>Target: Forward to Destination via Mumbai Exit
    else Active Prober / FortiGate Scanner Probe
        Fortress->>Apple: Reverse-proxy connection to real Apple CDN
        Apple-->>FortiGate: Real Apple TLS Certificate & Responses
        Note over FortiGate: Scanner concludes IP is a benign Apple CDN node!
    end
```

---

## 🚀 Censorship Evasion Protocol Comparison

| Protocol Mode | Transport | Port | Congestion / Cipher | Anti-Censorship Superpower | Best Used For |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VLESS + XTLS-Reality** | TCP | `443` | `xtls-rprx-vision` | Borrows real Apple TLS certs; active probers redirected to Apple CDN | Strict DPI & Firewalls |
| **Hysteria 2 Salamander** | UDP | `9444` | ChaCha20 XOR + BLAKE3 | Header scrambling makes QUIC unrecognizable to heuristics | UDP throttling / QUIC drop |
| **Hysteria 2 Standard** | UDP | `8443` | Brutal BBR over QUIC | Up to 1 Gbps throughput on lossy campus Wi-Fi | 4K Streaming & Gaming |
| **TUIC v5** | UDP | `9443` | RFC 9000 QUIC + BBR | 0-RTT handshake delay for instant reconnection | Mobile roaming (Wi-Fi ↔ 5G) |
| **Shadowsocks-2022** | TCP/UDP | `10443` | `2022-blake3-aes-256-gcm` | AEAD with variable-length packet padding | Minimal battery consumption |
| **WireGuard over TCP** | TCP | `8443` | TLS 1.3 WebSockets (`wstunnel`) | Wraps WireGuard inside HTTPS WebSockets | Captive portals blocking UDP |
| **Native WireGuard** | UDP | `51820` | ChaCha20-Poly1305 (Kernel) | Direct Linux kernel line-rate processing | High-speed unrestricted LAN |

---

## 📦 1-Click Server Installation

### Prerequisites
1. An **Oracle Cloud Infrastructure (OCI)** account (Always Free Tier).
2. An Ubuntu 22.04 / 24.04 VM instance (`VM.Standard.E2.1.Micro` or `VM.Standard.A1.Flex`).
3. Ingress Security Rules opened:
   - **TCP**: `22`, `443`, `8443`, `10443`
   - **UDP**: `443`, `8443`, `9443`, `9444`, `10443`, `51820`

### Automated Deployment
On your fresh Ubuntu server, run:
```bash
git clone https://github.com/harsh593-boop/sovereign-fortress.git
cd sovereign-fortress
sudo bash deploy_server.sh
```

The automated installer will:
1. Mount a 256 MB volatile RAM disk (`tmpfs`) at `/run/fortress` for anti-forensic security.
2. Install Sing-box 1.11+ Core and the Unbound recursive zero-log DNS resolver.
3. Configure Google Authenticator PAM 2FA for SSH.
4. Launch the dynamic subscription daemon and management portal on port `8443`.
5. Output your live subscription URL and QR codes!

---

## 💻 Client Applications & Connections

### 1. Universal Hiddify App (Android, Windows, iOS, macOS)
1. Install **Hiddify** from [GitHub Releases](https://github.com/hiddify/hiddify-app/releases) or Google Play Store.
2. Click **+ Add Profile** &rarr; **Add from Clipboard** &rarr; paste your subscription URL:
   ```text
   http://<YOUR_SERVER_IP>:8443/sub/<YOUR_SUBSCRIPTION_TOKEN>
   ```
3. Tap **Connect**!

### 2. Native Windows Desktop Application
Launch `Launch Sovereign Fortress.bat` (or run `SovereignFortressApp.pyw`):
* Dark-mode control center with real-time protocol latency and port status indicators.
* 1-Click import into Hiddify.
* Integrated Web Portal and QR Code launcher.
* Local DPAPI credential protection (`Protect-FortressVault.ps1`) and emergency cryptoshredding panic switch (`Shred-Fortress.ps1`).

### 3. YogaDNS Setup (for Campus Wi-Fi)
See [`yogadns_rules.md`](yogadns_rules.md) for full step-by-step instructions:
* **Rule 1 (Campus Intranet Bypass):** `*.campus.internal` & `10.*` &rarr; `System Default` (Campus DHCP DNS).
* **Rule 2 (General Encrypted DNS):** `*` &rarr; NextDNS DoH (`https://dns.nextdns.io/<YOUR_NEXTDNS_ID>`) or Self-Hosted Sovereign DNS.

---

## 🔐 Zero-Trust & Anti-Forensic Protections

* **SSH 2FA (Google Authenticator via PAM):** Key-only access is rejected. Server requires both the SSH Key and a live 6-digit TOTP code.
* **1-Click Token Revocation:** Instantly kills leaked subscription links in volatile RAM.
* **Dynamic 2FA Subscription:** Append your live 6-digit TOTP code (`/sub/<TOTP>`) to fetch profiles on demand with a 30-second expiry.
* **Active Defense Decoy:** Unauthorized requests automatically redirect (HTTP 302) to `https://www.apple.com/`.
* **Zero Disk Logs:** All active tokens and certificates reside in `/run/fortress` on volatile `tmpfs`.
* **Remote Panic Switch:** A single trigger executes multi-pass cryptoshredding (`shred -u -z -n 3`) on RAM and disk templates before poweroff.

---

## 👤 Author
Developed and maintained by **[harsh593-boop](https://github.com/harsh593-boop)**.

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
