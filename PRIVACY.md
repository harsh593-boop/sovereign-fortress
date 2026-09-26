# Privacy Policy, Zero-Log Architecture & Cookie Disclosure

**Effective Date:** September 2026  
**Commitment:** Strict Ephemeral Privacy & Data Minimization  

---

## 1. Zero-Log Architecture Guarantee

Sovereign Fortress is engineered from the ground up on the principle of **Zero-Knowledge Data Minimization**:

1. **Zero Traffic Inspection:** The server does not inspect, parse, analyze, or intercept user traffic payloads beyond what is cryptographically required for packet forwarding.
2. **Zero Persistent Access Logs:** Systemd journal logging for proxy services (`sing-box`, `wstunnel`, `unbound`) is directed to volatile memory (`Storage=volatile`) or discarded (`StandardOutput=null`, `StandardError=null`).
3. **RAM-Only Runtime (`tmpfs`):** All active session tokens, temporary state, and operational sockets reside exclusively in volatile system RAM (`/run/fortress`). In the event of a server reboot, power interruption, or hardware deprovisioning, all cryptographic keys and runtime states are permanently lost.
4. **Self-Hosted Recursive DNS (Unbound):** When operating in full-tunnel mode, all DNS queries are resolved directly via the 13 Root Name Servers (`127.0.0.1:5335`) with DNSSEC validation. No DNS query logs are stored, and no upstream commercial resolvers (e.g., Google or Cloudflare) receive user query telemetry.

---

## 2. Cookie Disclosure (Strictly Essential Only)

The Sovereign Fortress Web Management Portal (`/portal`) adheres to strict international privacy standards (including GDPR and ePrivacy Directive principles regarding cookie consent):

* **No Tracking or Profiling Cookies:** This service employs **zero advertising, zero tracking, zero analytics, and zero third-party cookies**.
* **Strictly Necessary Session Cookie:** The portal utilizes a single, strictly necessary, first-party HTTP cookie named:
  ```text
  sf_session=<ephemeral_hmac_signature>
  ```
  * **Purpose:** Enables secure, authenticated administrative dashboard access after successful 2FA TOTP or Master Token verification.
  * **Attributes:** `Path=/; HttpOnly; SameSite=Strict; Secure` (inaccessible to client JavaScript, immune to cross-site request forgery, and transmitted only over encrypted TLS 1.3).
  * **Lifecycle:** Stored in volatile server RAM; expires automatically or upon session termination.
  * **Consent Exemption:** Because this cookie is strictly necessary to provide the service explicitly requested by the user, explicit consent banners are not legally required under Article 5(3) of the EU ePrivacy Directive and similar privacy frameworks.

---

## 3. "Respect Choices" & Network Sovereignty Policy

Sovereign Fortress respects network operator autonomy:
* Operators of private local area networks (LANs) and institutional intranets have legitimate authority over their infrastructure.
* Sovereign Fortress provides configurable split-tunneling (`traffic-only` mode) specifically to ensure local intranet subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and internal resources remain routed directly to local campus/enterprise gateways without interference.
* Users must respect institutional boundaries and comply with all network acceptable use guidelines.
