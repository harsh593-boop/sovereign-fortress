#!/usr/bin/env python3
"""Regenerate public 1.14 profiles from placeholders, never live credentials."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent


def main():
    os.environ['FORTRESS_SUB_OFFLINE_TEST'] = '1'
    spec = importlib.util.spec_from_file_location('public_example_fixture', ROOT / 'fortress-sub.py')
    sub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sub)
    sub.SERVER_IP = '192.0.2.1'
    sub.DOMAIN = 'example.test'
    sub.WG_SERVER_PUB = 'fixture-wg-public'
    sub.WG_CLIENT_PRIV = '<YOUR_WG_CLIENT_PRIVATE_KEY>'
    with tempfile.TemporaryDirectory() as directory:
        sub.RAM_DIR = sub.DISK_DIR = directory
        for mode, filename in [('full', 'fortress-full-tunnel.example.json'),
                               ('traffic-only', 'fortress-traffic-only.example.json')]:
            cfg = sub.get_singbox_json_config(mode, core='1.14')
            for outbound in cfg['outbounds']:
                tls = outbound.get('tls', {})
                if tls.get('enabled') and not tls.get('reality'):
                    tls['certificate'] = ['<YOUR_CA_CERT_PEM>']
            text = json.dumps(cfg, indent=2) + '\n'
            text = text.replace('192.0.2.1', '<YOUR_SERVER_IP>')
            text = text.replace('example.test', '<YOUR_TLS_SERVER_NAME>')
            text = text.replace('fixture-wg-public', '<YOUR_WG_SERVER_PUBLIC_KEY>')
            (ROOT / filename).write_text(text, encoding='utf-8')
    print('Regenerated placeholder-only Sing-box 1.14 profiles')


if __name__ == '__main__':
    main()
