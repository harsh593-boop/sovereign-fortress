#!/usr/bin/env python3
"""Secret-redacted live smoke checks. Run explicitly on the VPS as root.

Does not rotate credentials, change policy, print profiles, or query OCI
metadata. A pass is NOT proof of client leak safety, no logging, or anonymity.
"""
import http.client
import json
import os
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import tempfile
import yaml


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run explicitly as root on the VPS')
    results = []
    def check(name, ok):
        results.append(bool(ok))
        print(('PASS ' if ok else 'FAIL ') + name)
    master = json.loads(Path('/run/fortress/fortress_config.json').read_text())
    host = master.get('domain') or master['server_ip']
    port = int(master.get('sub_port', 8443))
    module = runpy.run_path('/usr/local/bin/fortress-sub.py', run_name='server_smoke_fixture')
    token = module['get_or_create_token']()
    context = ssl.create_default_context()
    ca = module['verified_private_ca']()
    if ca:
        context.load_verify_locations(cadata=ca)
    def request(path, method='GET', body=None):
        raw = socket.create_connection(('127.0.0.1', port), timeout=5)
        tls = context.wrap_socket(raw, server_hostname=host)
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.sock = tls
        try:
            conn.request(method, path, body=body, headers={'Host': host + ':' + str(port)})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()
    for name in ('adguard-home', 'fortress-core', 'fortress-sub', 'fortress-wstunnel', 'wg-quick@wg0', 'ssh'):
        result = subprocess.run(['systemctl', 'is-active', '--quiet', name])
        check(name + ' active', result.returncode == 0)
    cfg = yaml.safe_load(Path('/run/fortress/adguard/AdGuardHome.yaml').read_text())
    for section in ('querylog', 'statistics', 'log'):
        check('AdGuard ' + section + ' disabled', cfg.get(section, {}).get('enabled') is False)
    check('AdGuard file querylog disabled', cfg.get('querylog', {}).get('file_enabled') is False)
    check('AdGuard UI loopback only', cfg.get('http', {}).get('address') == '127.0.0.1:3000')
    check('AdGuard restricted DNS bindings', set(cfg.get('dns', {}).get('bind_hosts', [])) == {'127.0.0.1', '10.8.0.1'})
    check('AdGuard incoming DoT/DoQ disabled', cfg.get('tls', {}).get('port_dns_over_tls') == 0 and cfg.get('tls', {}).get('port_dns_over_quic') == 0)
    mount = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '--target', '/run/fortress/adguard']).strip()
    check('AdGuard working storage tmpfs', mount == b'tmpfs')
    status, headers, _ = request('/portal')
    check('Portal verified TLS and HTTP 200', status == 200)
    check('Portal no-referrer header', headers.get('Referrer-Policy') == 'no-referrer')
    check('Browser token GET rejected', request('/portal?token=' + token)[0] == 400)
    check('Invalid Unicode login rejected safely', request('/portal/login', 'POST', 'auth_credential=invalid%E2%98%83')[0] == 401)
    check('OTP alone cannot authenticate portal', request('/portal/login', 'POST', 'auth_credential=123456')[0] == 401)
    check('OTP subscription URL retired', request('/sub/123456')[0] == 302)
    for mode in ('full', 'traffic-only'):
        for core in ('1.11', '1.14'):
            status, _, body = request('/sub/' + token + '?mode=' + mode + '&core=' + core)
            profile = json.loads(body)
            prefix = mode + ' / ' + core
            check(prefix + ' authenticated HTTP 200', status == 200)
            rules = profile.get('route', {}).get('rules', [])
            check(prefix + ' DNS hijack is never unconditional', all(r.get('protocol') == 'dns' for r in rules if r.get('action') == 'hijack-dns'))
            if mode == 'traffic-only':
                check(prefix + ' no DNS hijack', not any(r.get('action') == 'hijack-dns' for r in rules))
            if core == '1.14':
                check(prefix + ' explicit TUN DNS mode', profile['inbounds'][0].get('dns_mode') == ('disabled' if mode == 'traffic-only' else 'hijack'))
            else:
                fd, path = tempfile.mkstemp(dir='/run/fortress', prefix='.smoke-profile-')
                try:
                    with os.fdopen(fd, 'w') as f:
                        json.dump(profile, f)
                    result = subprocess.run(['/usr/local/bin/sing-box', 'check', '-c', path], capture_output=True)
                    check(prefix + ' actual server-core schema check', result.returncode == 0)
                finally:
                    os.unlink(path)
    for transport in ('udp', 'tcp'):
        args = ['dig', '+time=5', '+tries=1', '@10.8.0.1', '-p', '5335', 'example.com', 'A']
        if transport == 'tcp':
            args.insert(1, '+tcp')
        result = subprocess.run(args, capture_output=True)
        check('Private DNS ' + transport + ' answers', result.returncode == 0 and b'status: NOERROR' in result.stdout and b'ANSWER: 0' not in result.stdout)
    durable = Path('/var/lib/fortress/subscription/sub_token').read_text().strip()
    check('Durable token matches loader without rotation', durable == token)
    print(f'SERVER SMOKE: {sum(results)}/{len(results)} passed. Secret values omitted.')
    return 0 if all(results) else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit('Server smoke checks failed (' + type(error).__name__ + '); private details omitted')
