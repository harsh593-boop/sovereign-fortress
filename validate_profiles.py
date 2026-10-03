#!/usr/bin/env python3
"""Validate synthetic profiles with exact supported Sing-box releases.

Never reads live deployment credentials or contacts a VPN endpoint. Binaries
must be installed and independently checksum-verified before invocation.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--legacy', required=True, help='Sing-box 1.11.4 executable')
    parser.add_argument('--current', required=True, help='Sing-box 1.14.2 executable')
    args = parser.parse_args()
    os.environ['FORTRESS_SUB_OFFLINE_TEST'] = '1'
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    spec = importlib.util.spec_from_file_location('validation_fixture', ROOT / 'fortress-sub.py')
    sub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sub)
    with tempfile.TemporaryDirectory(prefix='fortress-profile-check-') as directory:
        fixture = Path(directory)
        # This is a synthetic certificate, never an operator CA or private key.
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(fixture / 'fixture.key'), '-out', str(fixture / 'ca.crt'),
                        '-subj', '/CN=example.test', '-days', '1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sub.RAM_DIR = sub.DISK_DIR = directory
        sub.SERVER_IP = '192.0.2.1'
        sub.DOMAIN = 'example.test'
        sub.UUID = str(uuid.uuid4())
        keys = subprocess.check_output([args.legacy, 'generate', 'reality-keypair'], text=True)
        sub.REALITY_PUBKEY = next(line.split(':', 1)[1].strip() for line in keys.splitlines() if line.startswith('PublicKey'))
        sub.REALITY_SHORTID = secrets.token_hex(8)
        sub.HY2_PASSWORD = secrets.token_hex(16)
        sub.SALAMANDER_PASSWORD = secrets.token_hex(16)
        sub.SS_PASSWORD = base64.b64encode(secrets.token_bytes(32)).decode()
        sub.WG_SERVER_PUB = base64.b64encode(secrets.token_bytes(32)).decode()
        sub.WG_CLIENT_PRIV = base64.b64encode(secrets.token_bytes(32)).decode()
        replacements = {
            '<YOUR_SERVER_IP>': sub.SERVER_IP,
            '<YOUR_CLIENT_UUID>': sub.UUID,
            '<YOUR_UUID>': sub.UUID,
            '<YOUR_REALITY_PUBLIC_KEY>': sub.REALITY_PUBKEY,
            '<YOUR_REALITY_SHORT_ID>': sub.REALITY_SHORTID,
            '<YOUR_HYSTERIA2_PASSWORD>': sub.HY2_PASSWORD,
            '<YOUR_SALAMANDER_PASSWORD>': sub.SALAMANDER_PASSWORD,
            '<YOUR_SHADOWSOCKS_PASSWORD>': sub.SS_PASSWORD,
            '<YOUR_WG_CLIENT_PRIVATE_KEY>': sub.WG_CLIENT_PRIV,
            '<YOUR_WG_SERVER_PUBLIC_KEY>': sub.WG_SERVER_PUB,
            '<YOUR_TLS_SERVER_NAME>': sub.DOMAIN,
            '<YOUR_CA_CERT_PEM>': (fixture / 'ca.crt').read_text().strip(),
        }
        def populate(value):
            if isinstance(value, dict):
                return {k: populate(v) for k, v in value.items()}
            if isinstance(value, list):
                return [populate(v) for v in value]
            if isinstance(value, str):
                for marker, replacement in replacements.items():
                    value = value.replace(marker, replacement)
            return value
        for core, expected, binary in [('1.11', '1.11.4', args.legacy), ('1.14', '1.14.2', args.current)]:
            version = subprocess.check_output([binary, 'version'], text=True).splitlines()[0]
            if version != 'sing-box version ' + expected:
                raise RuntimeError('Unexpected validation binary version')
            for mode in ('full', 'traffic-only'):
                path = fixture / 'generated.json'
                path.write_text(json.dumps(sub.get_singbox_json_config(mode, core=core)))
                result = subprocess.run([binary, 'check', '-c', str(path)], capture_output=True, text=True)
                if result.returncode:
                    # Only synthetic fixtures are involved, not live operator files.
                    print(result.stderr)
                    raise RuntimeError(f'Generated {mode} / {expected} config rejected')
                print(f'PASS generated {mode}: Sing-box {expected}')
            if core == '1.14':
                for name in ('fortress-full-tunnel.example.json', 'fortress-traffic-only.example.json'):
                    path = fixture / 'example.json'
                    path.write_text(json.dumps(populate(json.loads((ROOT / name).read_text()))))
                    result = subprocess.run([binary, 'check', '-c', str(path)], capture_output=True, text=True)
                    if result.returncode:
                        print(result.stderr)
                        raise RuntimeError(f'Example {name} rejected')
                    print(f'PASS {name}: Sing-box {expected}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
