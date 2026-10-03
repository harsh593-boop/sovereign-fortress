#!/usr/bin/env python3
"""Protect an explicitly supplied client bundle with current-user Windows DPAPI.

Input contains credentials: keep it outside the repository with a restricted
ACL, never print it, and remove it after this command. Existing protected
client files are never overwritten. No networking or Windows policy changes.
"""
import argparse
import json
import os
from pathlib import Path

from client_paths import client_config_path, client_directory
from fortress_vault import dpapi_protect, dpapi_unprotect, _publish_new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, help='private temporary JSON bundle')
    args = parser.parse_args()
    if os.name != 'nt':
        raise SystemExit('Run with native Windows Python under the intended user')
    bundle = json.loads(Path(args.input).read_text(encoding='utf-8'))
    directory = client_directory()
    directory.mkdir(parents=True, exist_ok=True)
    files = [(client_config_path(), bundle['client_config']),
             (directory / 'fortress-full-tunnel.json', bundle['full']),
             (directory / 'fortress-traffic-only.json', bundle['traffic_only'])]
    for path, _ in files:
        if path.exists() or Path(str(path) + '.enc').exists():
            raise SystemExit('Existing client settings detected; explicit manual migration required')
    encrypted = []
    for path, value in files:
        data = json.dumps(value, indent=2).encode()
        protected = dpapi_protect(data)
        if dpapi_unprotect(protected) != data:
            raise SystemExit('DPAPI round-trip verification failed; no client files published')
        encrypted.append((str(path) + '.enc', protected))
    for path, data in encrypted:
        _publish_new(path, data)
    print('PASS encrypted client settings and two profiles prepared outside the repository')
    print('No VPN process, TUN adapter, firewall rule, certificate trust, or DNS setting was changed.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit('Bundle installation failed (' + type(error).__name__ + '); private details omitted')
