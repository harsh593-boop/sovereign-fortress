#!/usr/bin/env python3
"""Explicit file-backed Sing-box 1.11.4 -> 1.14.2 application migration.

Not an OS upgrade or VM snapshot substitute. No SSH, firewall or credentials
are changed. Stage a checksum-verified official candidate first. Run as root
on the VPS with --apply. Candidate config is validated before replacing files;
failed service checks restore the old binary and private configs. Perform
transport checks immediately; --rollback-backup provides an explicit restore.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


def current_server_config(original):
    config = copy.deepcopy(original)
    dns = config.setdefault('dns', {})
    servers = dns.get('servers', [])
    if len(servers) != 1:
        raise ValueError('Custom multi-resolver server policy requires review')
    old = servers[0]
    if 'type' in old:
        new = old
    else:
        address = old.get('address', '')
        parsed = urlsplit(address if '://' in address else 'udp://' + address)
        if parsed.scheme not in ('udp', 'tcp') or parsed.hostname not in ('127.0.0.1', '10.8.0.1'):
            raise ValueError('Expected private AdGuard DNS transport')
        new = {'type': parsed.scheme, 'tag': old.get('tag', 'server-adguard'),
               'server': parsed.hostname, 'server_port': parsed.port or 53}
        # Typed DNS already uses a direct dialer by default. The current core
        # rejects a detour to an otherwise empty direct outbound at startup.
        direct_tags = {o.get('tag') for o in config.get('outbounds', []) if o.get('type') == 'direct'}
        if old.get('detour') and old['detour'] not in direct_tags:
            new['detour'] = old['detour']
    for rule in dns.get('rules', []):
        if rule.get('outbound') != 'any' or rule.get('server') != new['tag'] or set(rule) != {'outbound', 'server'}:
            raise ValueError('Custom legacy DNS rule requires explicit migration')
    dns['servers'] = [new]
    dns.pop('rules', None)
    config.setdefault('route', {})['default_domain_resolver'] = new['tag']
    special = {o['tag'] for o in config.get('outbounds', []) if o.get('type') == 'block'}
    if any(o.get('type') == 'wireguard' for o in config.get('outbounds', [])):
        raise ValueError('Server WireGuard outbound needs separate endpoint migration')
    config['outbounds'] = [o for o in config.get('outbounds', []) if o.get('type') != 'block']
    for rule in config['route'].get('rules', []):
        if rule.get('outbound') in special:
            rule.pop('outbound')
            rule['action'] = 'reject'
    sniff = []
    for inbound in config.get('inbounds', []):
        if inbound.pop('sniff', False):
            sniff.append(inbound['tag'])
        for field in ('sniff_timeout', 'sniff_override_destination', 'domain_strategy'):
            if field in inbound:
                raise ValueError('Custom deprecated inbound policy requires review')
        reality = inbound.get('tls', {}).get('reality', {})
        if reality.get('enabled'):
            # Pin the resolver path explicitly, never use cloud metadata DNS.
            reality['handshake'].pop('domain_strategy', None)
            reality['handshake']['domain_resolver'] = new['tag']
    if sniff:
        config['route'].setdefault('rules', []).insert(0, {'inbound': sniff, 'action': 'sniff'})
    config['log'] = {'disabled': True}
    return config


def run(command, timeout=45):
    result = subprocess.run(command, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed: ' + Path(command[0]).name + '; private output omitted')
    return result.stdout


def publish(path, data, mode, uid=0, gid=0):
    path = Path(path)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.core-upgrade-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chown(temp, uid, gid)
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def restore_backup(directory):
    backup = Path(directory).resolve()
    if backup.parent != Path('/root/fortress-backups') or not backup.name.startswith('core-'):
        raise ValueError('Unexpected rollback directory')
    records = json.loads((backup / 'manifest.json').read_text())
    expected = {'/usr/local/bin/sing-box', '/run/fortress/config.json', '/etc/fortress/config.json.template'}
    if {record['path'] for record in records} != expected:
        raise ValueError('Unexpected rollback manifest')
    for record in records:
        if Path(record['backup_name']).name != record['backup_name']:
            raise ValueError('Unexpected backup file name')
        publish(record['path'], (backup / record['backup_name']).read_bytes(),
                record['mode'], record['uid'], record['gid'])
    run(['systemctl', 'restart', 'fortress-core'])
    time.sleep(2)
    run(['systemctl', 'is-active', '--quiet', 'fortress-core'])
    print('Core file rollback completed; service active. Re-run transport checks.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate')
    parser.add_argument('--candidate-sha256', help='expected executable hash from verified archive extraction')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--rollback-backup', help='explicitly restore a root-only core backup')
    args = parser.parse_args()
    if args.rollback_backup:
        if os.geteuid() != 0:
            raise SystemExit('Rollback requires root')
        restore_backup(args.rollback_backup)
        return 0
    if not args.apply:
        print('No changes made; --apply requires a staged official candidate and recovery planning.')
        return 0
    if os.geteuid() != 0: raise SystemExit('Run as root on the VPS')
    if not args.candidate or not args.candidate_sha256:
        raise SystemExit('Provide an independently checksum-verified candidate')
    candidate = Path(args.candidate)
    data = candidate.read_bytes()
    if hashlib.sha256(data).hexdigest() != args.candidate_sha256:
        raise SystemExit('Candidate binary checksum mismatch')
    if run([str(candidate), 'version']).splitlines()[0] != b'sing-box version 1.14.2':
        raise SystemExit('Expected exact candidate version 1.14.2')
    binary = Path('/usr/local/bin/sing-box')
    if run([str(binary), 'version']).splitlines()[0] not in (b'sing-box version 1.11.4', b'sing-box version 1.14.2'):
        raise SystemExit('Unexpected existing server version')
    active = Path('/run/fortress/config.json')
    template = Path('/etc/fortress/config.json.template')
    converted = current_server_config(json.loads(active.read_text()))
    fd, staged = tempfile.mkstemp(dir=active.parent, prefix='.candidate-server-')
    try:
        with os.fdopen(fd, 'w') as f:json.dump(converted, f)
        run([str(candidate), 'check', '-c', staged])
    finally:
        Path(staged).unlink(missing_ok=True)
    backup = Path('/root/fortress-backups') / ('core-' + time.strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(backup.parent, 0o700)
    metadata=[]
    for path in (binary, active, template):
        stat=path.stat()
        name=path.name if path != active else 'active-config.json'
        shutil.copyfile(path, backup / name)
        os.chmod(backup / name, 0o600)
        metadata.append((path, name, stat.st_mode & 0o777, stat.st_uid, stat.st_gid))
    manifest = [{'path': str(p), 'backup_name': name, 'mode': mode, 'uid': uid, 'gid': gid}
                for p, name, mode, uid, gid in metadata]
    publish(backup / 'manifest.json', json.dumps(manifest).encode(), 0o600)
    print('Private file-level rollback backup:', backup)
    try:
        publish(binary, data, 0o755)
        payload=json.dumps(converted,indent=2).encode()
        for path in (active, template):
            stat=path.stat()
            publish(path, payload, stat.st_mode & 0o777, stat.st_uid, stat.st_gid)
        run(['systemctl','restart','fortress-core'])
        time.sleep(3)
        run(['systemctl','is-active','--quiet','fortress-core'])
        # Caller must run authenticated transport probes before declaring success.
        print('Core 1.14.2 is active; transport verification is required, not assumed.')
    except Exception:
        for path,name,mode,uid,gid in metadata:
            publish(path,(backup/name).read_bytes(),mode,uid,gid)
        subprocess.run(['systemctl','restart','fortress-core'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        raise SystemExit('Upgrade failed; file rollback attempted, inspect private service health.')
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit('Core migration failed ('+type(error).__name__+'); private diagnostics suppressed')
