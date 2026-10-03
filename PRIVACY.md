# Privacy and data-handling notes

**Effective date:** September 2026
**Scope:** the reference configuration and scripts in this repository

This document describes intended data handling. It is not a guarantee that a
particular deployment is anonymous, untraceable, or free of logs. Operators
control the host, cloud account, operating-system journal, firewall, DNS
configuration, backups, and monitoring integrations. Those systems can retain
connection metadata even when the example service configuration does not
request application logs.

## 1. Deployment-dependent data handling

The sample deployment attempts to minimize application data by:

* forwarding encrypted traffic without intentionally inspecting payloads;
* placing selected runtime state under `/run/fortress` when the host mounts it
  as `tmpfs`;
* configuring service logging conservatively; and
* configuring AdGuard Home on private/loopback addresses, with upstream DNS
  providers selected by the server operator in full-tunnel mode.

These properties must be verified on the actual host after every deployment
change. `Storage=volatile`, a `tmpfs` mount, or a quiet application logger does
not prevent logs from being created by the kernel, reverse proxy, cloud
provider, DNS peers, SSH, backups, or an administrator's diagnostic tooling.
Power loss and reboot behavior also depends on the host and provider; do not
describe volatile state as cryptographic erasure without a separate, tested
threat-model review.

The repository privacy scanner checks files and Git objects for accidentally
published values. A passing scan only means that its configured patterns were
not found; it does not prove that a server is private or that historical data
cannot be recovered.

## 2. Cookies and web portal

The reference portal uses an `sf_session` cookie for an authenticated session.
Deployers must inspect the running application and any proxy in front of it to
confirm the cookie attributes and retention behavior. The reference code does
not intentionally add advertising or analytics cookies, but an operator can
add middleware, monitoring, or a third-party service that changes this
behavior. Local law and the operator's privacy notice determine any consent
requirements.

The cookie is not a promise of anonymity. Access logs, TLS metadata, client
IP addresses, authentication events, and other operational records may still
exist outside the application process.

## 3. DNS and network choices

Full-tunnel and split-tunnel modes have different data paths. A local forwarding
resolver can reduce client-side DNS disclosure, but configured upstream DNS
providers, network providers, and the host may still observe metadata.
Split-tunnel rules intentionally send selected internal traffic to
the local network. Users must confirm that routing and DNS choices comply with
their network owner's policies.

## 4. Operator checklist

Before making a deployment available to anyone else, document and review:

1. host, cloud-provider, reverse-proxy, firewall, SSH, DNS, and backup logs;
2. retention, access, and deletion controls for each logging system;
3. certificate, token, TOTP, and private-key storage and rotation;
4. the actual `tmpfs` mount and service unit settings; and
5. the jurisdictions and third parties involved in traffic and DNS delivery.

Do not publish `fortress_config.json`, client profiles, private keys,
subscription URLs, QR exports, or generated certificates. Replace all example
placeholders before a private deployment, and rotate any value that may have
been exposed.

## 5. Responsible use

Use the software only on systems and networks you own or are authorized to
operate. See [LEGAL.md](LEGAL.md) and [TERMS.md](TERMS.md) for the project's
research and acceptable-use limitations.
