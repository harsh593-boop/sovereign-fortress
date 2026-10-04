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
    check('AdGuard UI private WireGuard only', cfg.get('http', {}).get('address') == '10.8.0.1:3000')
    check('AdGuard restricted DNS bindings', set(cfg.get('dns', {}).get('bind_hosts', [])) == {'127.0.0.1', '10.8.0.1'})
    check('AdGuard incoming DoT/DoQ enabled privately', cfg.get('tls', {}).get('port_dns_over_tls') == 853 and cfg.get('tls', {}).get('port_dns_over_quic') == 853)
    mount = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '--target', '/run/fortress/adguard']).strip()
    check('AdGuard working storage tmpfs', mount == b'tmpfs')
    status, headers, _ = request('/portal')
    check('Portal verified TLS and HTTP 200', status == 200)
    check('Portal no-referrer header', headers.get('Referrer-Policy') == 'no-referrer')
    check('Browser token GET rejected', request('/portal?token=' + token)[0] == 400)
    check('Invalid Unicode login rejected safely', request('/portal/login', 'POST', 'auth_credential=invalid%E2%98%83')[0] == 401)
    check('OTP alone cannot authenticate portal', request('/portal/login', 'POST', 'auth_credential=123456')[0] == 401)
    check('OTP subscription URL retired', request('/sub/123456')[0] == 302)
    installed_version = subprocess.check_output(['/usr/local/bin/sing-box', 'version']).splitlines()[0]
    if installed_version not in (b'sing-box version 1.11.4', b'sing-box version 1.14.2'):
        raise RuntimeError('Unsupported installed core version')
    installed_core = '1.14' if installed_version == b'sing-box version 1.14.2' else '1.11'
    for mode in ('full', 'traffic-only'):
        for core in ('1.11', '1.14'):
            status, _, body = request('/sub/' + token + '?mode=' + mode + '&core=' + core)
            profile = json.loads(body)
            prefix = mode + ' / ' + core
            if mode == 'full' and core == '1.11':
                check(prefix + ' retired insecure legacy profile', status == 400)
                continue
            check(prefix + ' authenticated HTTP 200', status == 200)
            rules = profile.get('route', {}).get('rules', [])
            check(prefix + ' DNS hijack is never unconditional', all(r.get('protocol') == 'dns' for r in rules if r.get('action') == 'hijack-dns'))
            if mode == 'traffic-only':
                check(prefix + ' no DNS hijack', not any(r.get('action') == 'hijack-dns' for r in rules))
            if core == '1.14':
                check(prefix + ' explicit TUN DNS mode', profile['inbounds'][0].get('dns_mode') == ('disabled' if mode == 'traffic-only' else 'hijack'))
            if core == installed_core:
                fd, path = tempfile.mkstemp(dir='/run/fortress', prefix='.smoke-profile-')
                try:
                    with os.fdopen(fd, 'w') as f:
                        json.dump(profile, f)
                    result = subprocess.run(['/usr/local/bin/sing-box', 'check', '-c', path], capture_output=True)
                    check(prefix + ' actual installed-core schema check', result.returncode == 0)
                finally:
                    os.unlink(path)
    plain = subprocess.run(['dig', '+time=3', '+tries=1', '@10.8.0.1', '-p', '5335', 'example.com', 'A'], capture_output=True)
    check('Plain private DNS is disabled', plain.returncode != 0 or b'ANSWER: 0' in plain.stdout)
    dot = subprocess.run(['openssl', 's_client', '-brief', '-connect', '10.8.0.1:853', '-servername', host],
                         input='Q', text=True, capture_output=True, timeout=10)
    check('Private DNS-over-TLS handshake', dot.returncode == 0 and 'Protocol version: TLSv1.3' in (dot.stdout + dot.stderr))
    doh = subprocess.run(['curl', '--silent', '--show-error', '--max-time', '8', '--resolve', f'{host}:8445:10.8.0.1',
                          '--cacert', '/run/fortress/cert.pem', '-o', os.devnull,
                          '-w', '%{http_code}', f'https://{host}:8445/dns-query'], capture_output=True, text=True)
    check('Private DNS-over-HTTPS TLS endpoint responds', doh.returncode == 0 and doh.stdout in ('400','405'))
    check('Private DNS-over-QUIC listener configured', cfg.get('tls', {}).get('port_dns_over_quic') == 853)
    check('DNSCrypt remains explicitly disabled until provider config is staged', cfg.get('tls', {}).get('port_dnscrypt') == 0)
    durable = Path('/var/lib/fortress/subscription/sub_token').read_text().strip()
    check('Durable token matches loader without rotation', durable == token)
    print(f'SERVER SMOKE: {sum(results)}/{len(results)} passed. Secret values omitted.')
    return 0 if all(results) else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit('Server smoke checks failed (' + type(error).__name__ + '); private details omitted')
