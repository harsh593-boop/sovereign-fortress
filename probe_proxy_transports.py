#!/usr/bin/env python3
"""Explicit proxy-only smoke probes; NOT TUN, WebRTC, or kill-switch evidence.

Requires an operator-provided matching profile kept outside the repository and
a checksum-verified Sing-box 1.11.4 or 1.14.2 binary. Credentials never reach arguments or
output. Only example.com is contacted through each configured stealth proxy.
WireGuard is excluded to avoid taking over an existing peer's connection.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--sing-box', required=True)
    args = parser.parse_args()
    version = subprocess.check_output([args.sing_box, 'version'], text=True).splitlines()[0]
    if version not in ('sing-box version 1.11.4', 'sing-box version 1.14.2'):
        raise SystemExit('Use a validated Sing-box 1.11.4 or 1.14.2 binary')
    original = json.loads(Path(args.profile).read_text())
    if original.get('dns', {}).get('servers', [{}])[0].get('detour') != 'proxy':
        raise SystemExit('Use a Full-Tunnel profile for forced proxy probes')
    transports = [o for o in original['outbounds'] if o.get('type') in ('vless', 'hysteria2', 'tuic', 'shadowsocks')]
    successes = 0
    with tempfile.TemporaryDirectory(prefix='fortress-private-probe-') as directory:
        os.chmod(directory, 0o700)
        for outbound in transports:
            config = copy.deepcopy(original)
            with socket.socket() as free:
                free.bind(('127.0.0.1', 0))
                port = free.getsockname()[1]
            config['inbounds'] = [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': port}]
            config.pop('endpoints', None)
            config['outbounds'] = [
                {'type': 'selector', 'tag': 'proxy', 'outbounds': [outbound['tag']], 'default': outbound['tag']},
                outbound, {'type': 'direct', 'tag': 'direct'}] + [o for o in original['outbounds'] if o.get('type') == 'block']
            # No TUN exists in this probe: force targets through the selected
            # proxy even when testing a VPS via its own loopback address.
            config['route']['rules'] = [r for r in config['route']['rules'] if r.get('outbound') != 'direct']
            config['log'] = {'disabled': True}
            path = Path(directory) / 'probe.json'
            path.write_text(json.dumps(config))
            os.chmod(path, 0o600)
            checked = subprocess.run([args.sing_box, 'check', '-c', str(path)], capture_output=True)
            if checked.returncode:
                print('FAIL ' + outbound['tag'] + ': configuration rejected; private output omitted')
                continue
            process = subprocess.Popen([args.sing_box, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(40):
                    if process.poll() is not None:
                        break
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.1)
                curl = subprocess.run(['curl', '--silent', '--proxy', f'socks5h://127.0.0.1:{port}',
                                       '--noproxy', '', '--max-time', '20', '--output', os.devnull,
                                       '--write-out', '%{http_code}', 'https://example.com'], capture_output=True)
                ok = curl.returncode == 0 and curl.stdout.strip() == b'200'
                successes += ok
                print(('PASS ' if ok else 'FAIL ') + outbound['tag'] + ': authenticated HTTPS proxy smoke'
                      + ('' if ok else ' (curl exit ' + str(curl.returncode) + ')'))
                if ok:
                    blocked = subprocess.run(['curl', '--silent', '--proxy', f'socks5h://127.0.0.1:{port}',
                                              '--noproxy', '', '--max-time', '5', '--output', os.devnull,
                                              'http://127.0.0.1:3000/'], capture_output=True)
                    denied = blocked.returncode != 0
                    print(('PASS ' if denied else 'FAIL ') + outbound['tag'] + ': server loopback UI access denied')
                    if not denied:
                        successes -= 1
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    print(f'PROXY TRANSPORT SMOKE: {successes}/{len(transports)} passed; no TUN/client leak claim.')
    return 0 if successes == len(transports) and transports else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit('Probe failed (' + type(error).__name__ + '); private details omitted')
