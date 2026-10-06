#!/usr/bin/env python3
"""Explicit, backed-up remediation for an existing Fortress 1.11.4 deployment.

Run on the VPS, never on a client. Requires root, PyYAML, and reviewed local
subscription/initializer scripts. No downloads, SSH changes, OS upgrades,
credential rotation, or destructive firewall replacement. Backups remain
root-only on the VPS. Diagnostics never print configuration values or logs.
"""
import argparse
import copy
import glob
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tempfile
import time

STATE = Path('/var/lib/fortress/subscription')
RAM = Path('/run/fortress')
DISK = Path('/etc/fortress')
AGH = Path('/opt/AdGuardHome/AdGuardHome.yaml')
UNITS = ('adguard-home', 'fortress-core', 'fortress-sub', 'fortress-wstunnel')


def ensure_dnscrypt_config(user_uid, user_gid):
    persistent = DISK / 'dnscrypt.yaml'
    runtime = RAM / 'adguard' / 'dnscrypt.yaml'
    if not persistent.exists():
        domain = ""
        cfg_path = DISK / 'fortress_config.json'
        if cfg_path.exists():
            try:
                cfg = json.loads(cfg_path.read_text())
                d = cfg.get('domain', '')
                if d and not d.startswith('<'):
                    domain = d.strip()
                elif cfg.get('server_ip'):
                    domain = cfg.get('server_ip').strip()
            except Exception:
                pass
        provider_name = f"2.dnscrypt-cert.{domain}" if domain else "2.dnscrypt-cert.fortress"

        def gen_keys(alg):
            out = subprocess.check_output(['openssl', 'genpkey', '-algorithm', alg, '-text']).decode()
            m_priv = re.search(r'priv:\s*([0-9a-f:\s]+?)\s*pub:', out, re.I)
            priv_hex = re.sub(r'[^0-9a-fA-F]', '', m_priv.group(1)).upper()
            m_pub = re.search(r'pub:\s*([0-9a-f:\s]+)', out, re.I)
            pub_hex = re.sub(r'[^0-9a-fA-F]', '', m_pub.group(1))[:64].upper()
            return priv_hex, pub_hex

        priv_ed, pub_ed = gen_keys('ed25519')
        priv_x, pub_x = gen_keys('x25519')

        content = (
            f"provider_name: {provider_name}\n"
            f"public_key: {pub_ed}\n"
            f"private_key: {priv_ed}{pub_ed}\n"
            f"resolver_secret: {priv_x}\n"
            f"resolver_public: {pub_x}\n"
            f"es_version: 1\n"
            f"certificate_ttl: 0s\n"
        )
        atomic_file(persistent, content, mode=0o600, uid=0, gid=user_gid)

    runtime.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_file(runtime, persistent.read_bytes(), mode=0o600, uid=user_uid, gid=user_gid)


def harden_adguard(config):
    c = copy.deepcopy(config)
    c.setdefault('http', {})['address'] = '127.0.0.1:3000'
    c['http']['pprof'] = {'enabled': False, 'port': 6060}
    c.setdefault('querylog', {}).update(enabled=False, file_enabled=False, size_memory=0, interval='24h', dir_path='')
    c.setdefault('statistics', {}).update(enabled=False, interval='24h', dir_path='')
    c.setdefault('log', {}).update(enabled=False, file='', verbose=False)
    dns = c.setdefault('dns', {})
    for key in ('querylog_enabled', 'querylog_file_enabled', 'querylog_interval', 'querylog_size_memory', 'statistics_interval'):
        dns.pop(key, None)
    dns['upstream_dns'] = [
        'https://dns.quad9.net/dns-query',
        'tls://dns.quad9.net',
        'https://cloudflare-dns.com/dns-query',
        'quic://dns.adguard-dns.com'
    ]
    dns['bootstrap_dns'] = ['9.9.9.9', '1.1.1.1']
    dns['upstream_mode'] = 'parallel'
    dns.update(bind_hosts=['0.0.0.0'], port=5335,
               allowed_clients=[], anonymize_client_ip=True,
               ratelimit=100, ratelimit_whitelist=['127.0.0.1', '10.8.0.1'], refuse_any=True,
               cache_size=4194304, cache_ttl_min=300, cache_ttl_max=86400, cache_optimistic=True,
               handle_ddr=False, use_private_ptr_resolvers=False, serve_plain_dns=True)
    c.setdefault('tls', {}).update(enabled=True, port_https=8445, port_dns_over_tls=853,
                                   port_dns_over_quic=853, port_dnscrypt=5443,
                                   dnscrypt_config_file='/run/fortress/adguard/dnscrypt.yaml',
                                   allow_unencrypted_doh=False)
    c.setdefault('clients', {})['runtime_sources'] = {k: False for k in ('whois', 'arp', 'rdns', 'dhcp', 'hosts')}
    return c


def harden_core(config):
    c = copy.deepcopy(config)
    c['log'] = {'disabled': True}
    direct = next(o['tag'] for o in c.get('outbounds', []) if o.get('type') == 'direct')
    # Resolve domains before address policy, so a hostname resolving to OCI
    # metadata or a private service cannot bypass the IP deny rule.
    c['route'] = {'auto_detect_interface': True, 'rules': [
        {'ip_cidr': ['127.0.0.1/32', '10.8.0.1/32'], 'port': 5335, 'outbound': direct},
        {'action': 'resolve', 'strategy': 'ipv4_only'},
        {'ip_cidr': ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
                     '169.254.0.0/16', '100.64.0.0/10', '::1/128', 'fc00::/7', 'fe80::/10'], 'action': 'reject'},
        {'outbound': direct}]}
    return c


def command(args, *, timeout=40):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        operation = Path(args[0]).name + ((' ' + args[1]) if len(args) > 1 else '')
        raise RuntimeError('Command failed: ' + operation + '; private output suppressed')
    return result.stdout


def atomic_file(path, data, mode=0o640, uid=0, gid=0):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.fortress-reviewed-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode())
            f.flush()
            os.fsync(f.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def dropins():
    common = '\n[Service]\nLimitCORE=0\nPrivateTmp=true\nNoNewPrivileges=true\nStandardOutput=null\nStandardError=null\n'
    return {
        'adguard-home': '[Unit]\nRequires=fortress-init.service wg-quick@wg0.service\nAfter=fortress-init.service wg-quick@wg0.service\nRequiresMountsFor=/run/fortress\n' + common +
            'ExecStart=\nExecStart=/opt/AdGuardHome/AdGuardHome -c /run/fortress/adguard/AdGuardHome.yaml -w /run/fortress/adguard\nWorkingDirectory=/run/fortress/adguard\nReadWritePaths=\nReadWritePaths=/run/fortress/adguard\nReadOnlyPaths=/opt/AdGuardHome\nMemoryMax=256M\n',
        'fortress-core': '[Unit]\nRequires=fortress-init.service adguard-home.service\nAfter=fortress-init.service adguard-home.service\n' + common + 'MemoryMax=512M\n',
        'fortress-sub': '[Unit]\nRequires=fortress-init.service\nAfter=fortress-init.service\nRequiresMountsFor=/var/lib/fortress/subscription\n' + common +
            'ReadWritePaths=\nReadWritePaths=/run/fortress /var/lib/fortress/subscription\nMemoryMax=256M\n',
        'fortress-wstunnel': '[Unit]\nRequires=fortress-init.service wg-quick@wg0.service\nAfter=fortress-init.service wg-quick@wg0.service\n' + common,
        'wg-quick@wg0': '[Unit]\nRequires=fortress-init.service\nAfter=fortress-init.service\n',
        'fortress-init': '[Unit]\nBefore=adguard-home.service wg-quick@wg0.service fortress-core.service fortress-sub.service fortress-wstunnel.service\nRequiresMountsFor=/run/fortress /var/lib/fortress/subscription\n',
    }


def firewall_rules(uid):
    # These additive rules do not alter SSH accepts, default policies, or OCI
    # root-owned storage/DHCP traffic. Existing rules are preserved.
    return [
        ('INPUT', ['-i', 'wg0', '-d', '10.8.0.1', '-p', proto, '--dport', port, '-j', 'ACCEPT'])
        for proto in ('tcp', 'udp')
        for port in ('5335', '853', '5443', '8445')
    ] + [
        ('INPUT', ['-p', proto, '--dport', port, '-j', 'ACCEPT'])
        for proto in ('tcp', 'udp')
        for port in ('853', '5443')
    ] + [
        ('INPUT', ['-p', 'tcp', '--dport', '8445', '-j', 'ACCEPT'])
    ] + [('OUTPUT', ['-m', 'owner', '--uid-owner', str(uid), '-d', '169.254.0.0/16', '-j', 'REJECT']),
         ('FORWARD', ['-i', 'wg0', '-d', '169.254.0.0/16', '-j', 'REJECT'])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='explicitly authorize changes')
    parser.add_argument('--subscription-script', default='fortress-sub.py',
                        help='path to updated fortress-sub.py (default: fortress-sub.py)')
    parser.add_argument('--initializer-script', default='fortress-init.sh',
                        help='path to updated fortress-init.sh (default: fortress-init.sh)')
    args = parser.parse_args()
    if not args.apply:
        print('No changes made. Use --apply only after review and backup planning.')
        return 0
    if os.geteuid() != 0:
        raise SystemExit('Requires root')
    import yaml  # Already required on the audited host; no implicit install.
    user = pwd.getpwnam('fortress')
    for path in (RAM,):
        if command(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(path)]).strip() != b'tmpfs':
            raise SystemExit('Expected runtime tmpfs is missing')
    version = command(['/usr/local/bin/sing-box', 'version']).splitlines()[0]
    if not version.startswith(b'sing-box version 1.'):
        raise SystemExit(f'Remediation supports sing-box 1.x (found: {version.decode(errors="replace")})')
    for name in ('key.pem', 'cert.pem', 'ca.crt', 'wg0.conf', 'fortress_config.json', 'config.json.template'):
        if not (DISK / name).is_file():
            raise SystemExit('A required persistent runtime file is missing; no changes made')
    subscription = Path(args.subscription_script).read_bytes()
    initializer = Path(args.initializer_script).read_bytes()
    compile(subscription, 'reviewed-subscription', 'exec')
    command(['bash', '-n', args.initializer_script])
    agh = harden_adguard(yaml.safe_load(AGH.read_text()))
    core = harden_core(json.loads((RAM / 'config.json').read_text()))
    # Private staging stays on tmpfs; engine errors never reach the terminal.
    staged = RAM / '.reviewed-server.json'
    atomic_file(staged, json.dumps(core), mode=0o600)
    try:
        command(['/usr/local/bin/sing-box', 'check', '-c', str(staged)])
    finally:
        staged.unlink(missing_ok=True)
    backup = Path('/root/fortress-backups') / time.strftime('%Y%m%d-%H%M%S')
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(backup.parent, 0o700)
    os.chmod(backup, 0o700)
    targets = [AGH, RAM / 'adguard' / 'AdGuardHome.yaml', RAM / 'config.json', DISK / 'config.json.template',
               DISK / 'fortress_config.json', RAM / 'fortress_config.json',
               DISK / 'dnscrypt.yaml', RAM / 'adguard' / 'dnscrypt.yaml',
               Path('/usr/local/bin/fortress-sub.py'), Path('/usr/local/bin/fortress-init.sh'),
               Path('/etc/iptables/rules.v4')]
    for name in dropins():
        targets.append(Path('/etc/systemd/system') / (name + '.service.d') / '90-fortress-reviewed.conf')
    permission_targets = [DISK, RAM, DISK / 'key.pem', DISK / 'ca.key', DISK / 'wg0.conf',
                          DISK / 'fortress_config.json', DISK / 'totp_secret', DISK / 'dnscrypt.yaml',
                          RAM / 'key.pem', RAM / 'fortress_config.json', RAM / 'totp_secret',
                          RAM / 'adguard' / 'dnscrypt.yaml',
                          Path('/opt/AdGuardHome/AdGuardHome'), Path('/usr/local/bin/sing-box'),
                          Path('/usr/local/bin/wstunnel')]
    permissions = []
    for path in permission_targets:
        if path.exists():
            stat = path.stat()
            permissions.append({'path': str(path), 'mode': stat.st_mode & 0o777,
                                'uid': stat.st_uid, 'gid': stat.st_gid})
    atomic_file(backup / 'permissions.json', json.dumps(permissions), mode=0o600)
    metadata = []
    for path in targets:
        record = {'path': str(path), 'present': path.exists()}
        if path.exists():
            stat = path.stat()
            record.update(mode=stat.st_mode & 0o777, uid=stat.st_uid, gid=stat.st_gid)
            dest = backup / str(path).lstrip('/')
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(path, dest)
            os.chmod(dest, 0o600)
        metadata.append(record)
    atomic_file(backup / 'manifest.json', json.dumps(metadata, indent=2), mode=0o600)
    atomic_file(backup / 'firewall.v4', command(['iptables-save']), mode=0o600)
    print('Root-only backup created:', backup)
    print('Backups contain private configuration, not query logs; do not publish them.')
    # The snapshot is a file-level rollback, not a provider/VM snapshot.
    try:
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(STATE, user.pw_uid, user.pw_gid)
        os.chmod(STATE, 0o700)
        if not (STATE / 'sub_token').exists():
            token_source = RAM / 'sub_token' if (RAM / 'sub_token').exists() else DISK / 'sub_token'
            atomic_file(STATE / 'sub_token', token_source.read_bytes(), mode=0o600, uid=user.pw_uid, gid=user.pw_gid)
        work = RAM / 'adguard'
        work.mkdir(exist_ok=True, mode=0o700)
        os.chown(work, user.pw_uid, user.pw_gid)
        os.chmod(work, 0o700)
        # Stop before writing: AGH writes its configuration during shutdown.
        command(['systemctl', 'stop', 'adguard-home'])
        ensure_dnscrypt_config(user.pw_uid, user.pw_gid)
        subprocess.run(['chattr', '-i', str(AGH)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        atomic_file(AGH, yaml.safe_dump(agh, sort_keys=False), gid=user.pw_gid)
        # This AdGuard release rewrites config on startup: only RAM is writable.
        atomic_file(work / 'AdGuardHome.yaml', yaml.safe_dump(agh, sort_keys=False),
                    mode=0o600, uid=user.pw_uid, gid=user.pw_gid)
        atomic_file(DISK / 'config.json.template', json.dumps(core, indent=2), gid=user.pw_gid)
        atomic_file(RAM / 'config.json', json.dumps(core, indent=2), gid=user.pw_gid)
        # Retire SSH-seed distribution, without touching the SSH PAM account file.
        for path, mode in ((DISK / 'fortress_config.json', 0o600), (RAM / 'fortress_config.json', 0o640)):
            master = json.loads(path.read_text())
            master.pop('totp_secret', None)
            master.setdefault('portal_totp_required', False)
            atomic_file(path, json.dumps(master, indent=2), mode=mode, gid=user.pw_gid)
        atomic_file('/usr/local/bin/fortress-sub.py', subscription, mode=0o755)
        atomic_file('/usr/local/bin/fortress-init.sh', initializer, mode=0o755)
        for name, data in dropins().items():
            path = Path('/etc/systemd/system') / (name + '.service.d') / '90-fortress-reviewed.conf'
            path.parent.mkdir(exist_ok=True, mode=0o755)
            atomic_file(path, data, mode=0o644)
        for chain, rule in firewall_rules(user.pw_uid):
            exists = subprocess.run(['iptables', '-C', chain, *rule], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
            if not exists:
                command(['iptables', '-I', chain, '1', *rule])
        rules_path = Path('/etc/iptables/rules.v4')
        rules_path.parent.mkdir(exist_ok=True, mode=0o755)
        atomic_file(rules_path, command(['iptables-save']), mode=0o600)
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'restart', 'adguard-home', 'fortress-core', 'fortress-sub', 'fortress-wstunnel'], timeout=90)
        time.sleep(4)
        for unit in UNITS:
            command(['systemctl', 'is-active', '--quiet', unit])
        # Encrypted upstream/bootstrap startup can exceed a three-second probe.
        # Retry within a bound; never accept SERVFAIL or an empty answer as healthy.
        dns_healthy = False
        for attempt in range(4):
            result = subprocess.run(['dig', '+tcp', '+time=8', '+tries=1', '@10.8.0.1', '-p', '5335', 'example.com', 'A'],
                                    capture_output=True, timeout=12)
            if result.returncode == 0 and b'status: NOERROR' in result.stdout and b'ANSWER: 0' not in result.stdout:
                dns_healthy = True
                break
            time.sleep(2)
        if not dns_healthy:
            raise RuntimeError('Private resolver failed bounded DNS response health checks')
        # Apply root-only ownership after services are successfully healthy.
        os.chown(DISK, 0, user.pw_gid)
        os.chmod(DISK, 0o750)
        for name in ('key.pem', 'ca.key', 'wg0.conf', 'fortress_config.json', 'config.json.template', 'totp_secret', 'dnscrypt.yaml'):
            p = DISK / name
            if p.exists():
                os.chown(p, 0, user.pw_gid)
                os.chmod(p, 0o600)
        os.chown(RAM, 0, user.pw_gid)
        os.chmod(RAM, 0o750)
        for name in ('key.pem', 'fortress_config.json', 'config.json'):
            p = RAM / name
            if p.exists():
                os.chown(p, 0, user.pw_gid)
                os.chmod(p, 0o640)
        legacy_seed = RAM / 'totp_secret'
        if legacy_seed.exists():
            os.chown(legacy_seed, 0, 0)
            os.chmod(legacy_seed, 0o600)
        for binary in ('/opt/AdGuardHome/AdGuardHome', '/usr/local/bin/sing-box', '/usr/local/bin/wstunnel'):
            os.chown(binary, 0, 0)
        # Old application query/statistics files on tmpfs are no longer needed.
        for pattern in ('/opt/AdGuardHome/data/querylog*', '/opt/AdGuardHome/data/stats.db*'):
            for name in glob.glob(pattern):
                p = Path(name)
                if p.is_file() and not p.is_symlink():
                    p.unlink()
        print('Remediation applied; services active. SSH, OS, endpoint credentials and global routing unchanged.')
        print('Subscription SHA256:', hashlib.sha256(subscription).hexdigest())
    except Exception as failure:
        # Exception type and our own command label are safe; raw file/command
        # errors can contain private paths or values and remain suppressed.
        label = str(failure) if isinstance(failure, RuntimeError) else type(failure).__name__
        print('Failure category:', label)
        for unit in UNITS:
            status = subprocess.run(['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'SubState',
                                     '-p', 'Result', '-p', 'ExecMainStatus'], capture_output=True, text=True)
            print('Failed-stage service state:', unit, status.stdout.replace('\n', ' '))
        # Restore files and IPv4 rules; never expose failed command output.
        for record in metadata:
            p = Path(record['path'])
            if record['present']:
                atomic_file(p, (backup / str(p).lstrip('/')).read_bytes(), record['mode'], record['uid'], record['gid'])
            elif p.exists():
                p.unlink()
        for record in permissions:
            p = Path(record['path'])
            if p.exists():
                os.chown(p, record['uid'], record['gid'])
                os.chmod(p, record['mode'])
        with open(backup / 'firewall.v4', 'rb') as f:
            subprocess.run(['iptables-restore'], stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'daemon-reload'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'restart', *UNITS], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise SystemExit('Remediation failed; file/firewall rollback attempted. Inspect service health through a private console.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
