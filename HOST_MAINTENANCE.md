# Host maintenance and remaining authority gates

This is a recovery/change plan, not proof of production readiness. Never paste
cloud API keys, session tokens, SSH keys or enrollment seeds into reports/chat.

## Completed application-core upgrade

The existing proxy core was upgraded from 1.11.4 to checksum-verified official
**1.14.2**, after an isolated instance passed all five authenticated transports.
The migration preserves endpoint credentials, SSH, firewall policy, and other
services. It converts legacy DNS to typed private DNS and explicitly assigns the
Reality handshake resolver. Typed DNS must not detour to an empty direct outbound:
this passes a schema check but fails at runtime in the current core.

`upgrade_server_core.py` requires root, `--apply`, a reviewed staged candidate
and its executable hash from a separately verified archive. It validates the
converted config before replacing the binary and private active/template files.
It saves root-only file backups and restores on failed service startup. Transport
checks are required immediately after migration; a running process is not enough.

```bash
# On the VPS only; placeholders below are not credentials.
sudo python3 upgrade_server_core.py --apply \
  --candidate /path/to/verified/sing-box \
  --candidate-sha256 '<VERIFIED_EXECUTABLE_HASH>'

# If the explicit post-upgrade transport tests fail:
sudo python3 upgrade_server_core.py --rollback-backup /root/fortress-backups/core-<BACKUP_ID>
```

The older `apply_server_remediation.py` is deliberately constrained to the
validated **1.11.4** deployment. Do not rerun that legacy migration on an upgraded
core or remove its version guard. File rollback is not a boot-volume snapshot.

## UDP ingress gate

After core recovery/upgrade, all five protocols passed local VPS tests. From the
WSL client path, Reality, standard Hysteria2 and Shadowsocks passed, while TUIC
and Salamander failed. A synchronized header-only capture observed requests and
replies for UDP 8443, but **no arriving packets for UDP 9443 or 9444** during the
failed probes. No raw addresses, packet payloads or credential material were
published. This places that drop before the guest; it does not distinguish OCI
security rules from a client/intermediate network restriction.

Through an authenticated OCI session with the operator's authority:

1. Identify the correct instance, VNIC, subnet security lists and all attached
   NSGs. Do not infer them solely from a public IP or alter unrelated resources.
2. Review stateful/stateless ingress and reply/egress handling for the declared
   protocol ports. Keep SSH/recovery rules intact and back up the existing rules.
3. Add only the reviewed missing allowances for the owned VPN endpoint, if OCI
   policy is the cause. Do not replace an entire NSG/security list blindly.
4. Retest headers and authenticated transport from the same client path.
5. If traffic is blocked by the client network, involve that network's owner or
   use an approved supported network/transport. Do not claim the VPS can repair
   or universally bypass upstream policy.

OCI root access inside a VM does not grant tenancy/network IAM authority. Browser
session authentication is preferable to pasted long-lived API keys:

```powershell
# Native Windows CLI, if installed in the private tool environment:
& "$env:LOCALAPPDATA\SovereignFortress\tools\oci-cli\Scripts\oci.exe" session authenticate
```

Select the actual region and complete Oracle sign-in in the browser. Commands
using that session require `--auth security_token` and the selected profile.
Never publish its config, key files, token files or exported session archives.

## Supported OS and security coverage

The audited legacy host uses Ubuntu 20.04 and had **no attached Ubuntu Pro/ESM
subscription**. Updating the proxy binary does not establish OS maintenance or
post-quantum SSH support. Cached APT simulation alone is not an update or a full
security assessment. The OS/package set and provider recovery must be reviewed.

Choose an approved path:

- **Preferred:** build a supported Ubuntu LTS VM, test the stack with synthetic
  profiles, then perform a controlled cutover with verified recovery and rollback.
- **Alternative:** a supported staged in-place LTS upgrade, only after a completed
  boot-volume backup and local/provider console recovery are verified.
- **Interim:** operator-authorized Ubuntu Pro/ESM enrollment and actual package
  update verification. This is not the same as migrating to a current LTS and
  does not automatically provide newer SSH protocol features.

Before an OS change, obtain a completed provider boot-volume backup/snapshot ID,
verify serial-console or equivalent recovery, sufficient disk space, package/PAM
compatibility, certificate restoration, firewall persistence, DNS startup and
key+TOTP SSH access. Do not rely on an SSH connection surviving the upgrade.
Do not invoke `do-release-upgrade` on this live host without these gates.

## Windows administrator gate

The current Windows token is non-elevated and was **not a member of the local
Administrator group**. It cannot install a privileged TUN/service or enforce
machine firewall policy. VPS sudo does not grant Windows administrator rights.
An administrator must approve/run the reviewed client setup under a maintenance
window; passwords belong only in the OS authentication dialog, never chat.

The audit found default outbound Allow, many existing local outbound allows,
GroupPolicy-source blocks, no active TUN/service and no Npcap driver. Default
Block alone does not neutralize existing allows; explicit Block overrides
conflicting Allows. A correct policy needs an approved rule inventory/rollback,
strong interface/process identity, IPv4/IPv6 coverage, new-NIC and boot/crash
behavior, and narrow mode-specific DNS exceptions. DPAPI user-bound files also
need a deliberate handoff to any service account; SYSTEM cannot simply decrypt
another user's protected config.

See [WINDOWS_NETWORK_READINESS.md](WINDOWS_NETWORK_READINESS.md) for the complete
read-only audit, authority limits, fail-closed architecture and packet test matrix.
No kill switch, driver or TUN was installed/activated by the audit.
