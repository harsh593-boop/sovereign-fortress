#!/usr/bin/env python3
"""Idempotent IPv4 host firewall hardening for the existing VPS.

Run as root on the audited host with --apply. It backs up current IPv4/IPv6
rules first, keeps SSH/established/loopback/declared service access, permits
WireGuard forwarding only to the detected WAN interface, and sets INPUT/FORWARD
default DROP while retaining OUTPUT ACCEPT. OCI ingress policy is separate.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import sys

SERVICE_TCP = (22, 443, 5443, 8080, 8443, 10443)
SERVICE_UDP = (443, 5443, 8443, 9443, 9444, 10443, 51820)
PRIVATE_DNS_TCP = (5335, 853, 5443, 8445)
PRIVATE_DNS_UDP = (5335, 853, 5443, 8445)


def run(args, *, check=True, stdin=None):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError('firewall command failed: ' + args[0])
    return result


def exists(chain, args, table='filter'):
    return run(['iptables', '-t', table, '-C', chain, *args], check=False).returncode == 0


def ensure(chain, args, table='filter', position=None):
    if not exists(chain, args, table):
        command = ['iptables', '-t', table, '-I' if position else '-A', chain]
        if position:
            command.append(str(position))
        command.extend(args)
        run(command)


def remove_all(chain, args, table='filter'):
    while exists(chain, args, table):
        run(['iptables', '-t', table, '-D', chain, *args])


def save_backup():
    backup = Path('/root/fortress-backups') / ('firewall-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(parents=True, mode=0o700)
    Path(backup / 'rules.v4').write_bytes(subprocess.check_output(['iptables-save']))
    Path(backup / 'rules.v6').write_bytes(subprocess.check_output(['ip6tables-save']))
    for path in (backup / 'rules.v4', backup / 'rules.v6'):
        path.chmod(0o600)
    return backup


def apply():
    if subprocess.check_output(['id', '-u'], text=True).strip() != '0':
        raise SystemExit('Run as root')
    wan = subprocess.check_output(['bash', '-c', "ip -4 route show default | awk 'NR==1 {print $5}'"], text=True).strip()
    if not wan or wan.startswith('-') or not wan.replace('_', '').replace('-', '').isalnum():
        raise SystemExit('Could not safely identify the IPv4 WAN interface')
    backup = save_backup()
    try:
        ensure('INPUT', ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], position=1)
        ensure('INPUT', ['-i', 'lo', '-j', 'ACCEPT'], position=1)
        ensure('INPUT', ['-i', 'wg0', '-d', '10.8.0.1', '-p', 'tcp', '-m', 'multiport', '--dports', ','.join(map(str, PRIVATE_DNS_TCP)), '-j', 'ACCEPT'], position=1)
        ensure('INPUT', ['-i', 'wg0', '-d', '10.8.0.1', '-p', 'udp', '-m', 'multiport', '--dports', ','.join(map(str, PRIVATE_DNS_UDP)), '-j', 'ACCEPT'], position=1)
        ensure('INPUT', ['-p', 'tcp', '-m', 'multiport', '--dports', ','.join(map(str, SERVICE_TCP)), '-j', 'ACCEPT'])
        ensure('INPUT', ['-p', 'udp', '-m', 'multiport', '--dports', ','.join(map(str, SERVICE_UDP)), '-j', 'ACCEPT'])
        # Remove broad forwarding rules from the previous configuration.
        remove_all('FORWARD', ['-i', 'wg0', '-j', 'ACCEPT'])
        remove_all('FORWARD', ['-o', 'wg0', '-j', 'ACCEPT'])
        run(['iptables', '-N', 'FORTRESS_FORWARD'], check=False)
        run(['iptables', '-F', 'FORTRESS_FORWARD'])
        ensure('FORTRESS_FORWARD', ['-d', '169.254.0.0/16', '-j', 'DROP'])
        ensure('FORTRESS_FORWARD', ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
        ensure('FORTRESS_FORWARD', ['-i', 'wg0', '-o', wan, '-j', 'ACCEPT'])
        ensure('FORTRESS_FORWARD', ['-i', wan, '-o', 'wg0', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
        ensure('FORWARD', ['-j', 'FORTRESS_FORWARD'], position=1)
        run(['iptables', '-t', 'nat', '-N', 'FORTRESS_NAT'], check=False)
        # Recreate NAT chain after ensuring it exists.
        run(['iptables', '-t', 'nat', '-F', 'FORTRESS_NAT'])
        ensure('FORTRESS_NAT', ['-s', '10.8.0.0/24', '-o', wan, '-j', 'MASQUERADE'], 'nat')
        ensure('POSTROUTING', ['-j', 'FORTRESS_NAT'], 'nat', position=1)
        run(['iptables', '-P', 'INPUT', 'DROP'])
        run(['iptables', '-P', 'FORWARD', 'DROP'])
        run(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
        run(['netfilter-persistent', 'save'])
        print('Firewall hardened: INPUT/FORWARD DROP, OUTPUT ACCEPT; backup:', backup)
        print('WAN interface:', wan)
    except Exception:
        run(['iptables-restore'], stdin=(backup / 'rules.v4').read_text(), check=True)
        run(['ip6tables-restore'], stdin=(backup / 'rules.v6').read_text(), check=True)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if not args.apply:
        print('No changes made. Use --apply after confirming console/SSH recovery.')
        return 0
    apply()
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit('Firewall change failed; rollback attempted (' + type(error).__name__ + ')')
