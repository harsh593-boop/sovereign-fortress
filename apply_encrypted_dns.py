#!/usr/bin/env python3
"""Migrate the existing server to private encrypted DNS listeners.

The public Internet never receives DNS listeners. AdGuard binds encrypted DNS
only to loopback/private WireGuard addresses; private plain DNS is disabled.
The core and generated Full-Tunnel profiles use DoT. DNSCrypt is intentionally
not enabled until a verified DNSCrypt provider config/stamp is provisioned.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
AGH_PATH=Path('/opt/AdGuardHome/AdGuardHome.yaml')
AGH_RUNTIME=Path('/run/fortress/adguard/AdGuardHome.yaml')
CORE_PATH=Path('/run/fortress/config.json')
CORE_TEMPLATE=Path('/etc/fortress/config.json.template')
CERT=Path('/run/fortress/cert.pem')
KEY=Path('/run/fortress/key.pem')
DOMAIN='fortress-portal.duckdns.org'


def run(args,check=True):
 r=subprocess.run(args,capture_output=True,text=True)
 if check and r.returncode: raise RuntimeError('command failed: '+args[0])
 return r

def atomic(path,data,mode=0o640,uid=0,gid=0):
 fd,tmp=tempfile.mkstemp(dir=str(Path(path).parent),prefix='.encrypted-dns-')
 try:
  with os.fdopen(fd,'wb') as f:f.write(data if isinstance(data,bytes) else data.encode());f.flush();os.fsync(f.fileno())
  os.chown(tmp,uid,gid);os.chmod(tmp,mode);os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)

def transform_agh(c):
 c=copy.deepcopy(c)
 c.setdefault('http',{})['address']='10.8.0.1:3000'
 c['http']['pprof']={'enabled':False,'port':6060}
 c.setdefault('users',[])
 c.setdefault('querylog',{}).update(enabled=False,file_enabled=False,size_memory=0,interval='24h',dir_path='')
 c.setdefault('statistics',{}).update(enabled=False,interval='24h',dir_path='')
 c.setdefault('log',{}).update(enabled=False,file='',verbose=False)
 dns=c.setdefault('dns',{})
 dns.update(bind_hosts=['127.0.0.1','10.8.0.1'],port=5335,
            allowed_clients=['127.0.0.0/8','10.8.0.0/24'],anonymize_client_ip=True,
            ratelimit=100,ratelimit_whitelist=['127.0.0.1','10.8.0.1'],refuse_any=True,
            serve_plain_dns=False,handle_ddr=False,use_private_ptr_resolvers=False)
 c['tls'].update(enabled=True,server_name=DOMAIN,force_https=True,port_https=8445,
                 port_dns_over_tls=853,port_dns_over_quic=853,port_dnscrypt=0,
                 allow_unencrypted_doh=False,certificate_path=str(CERT),private_key_path=str(KEY))
 return c

def transform_core(c):
 c=copy.deepcopy(c)
 dns=c.setdefault('dns',{})
 servers=dns.get('servers',[])
 if not servers: raise ValueError('core has no DNS server')
 s=servers[0]
 s.update(type='tls',server='127.0.0.1',server_port=853,tls={'server_name':DOMAIN})
 s.pop('address',None);s.pop('detour',None)
 dns.pop('rules',None)
 c.setdefault('route',{})['default_domain_resolver']=s.get('tag','server-adguard')
 c['log']={'disabled':True}
 return c

def main():
 import argparse
 p=argparse.ArgumentParser();p.add_argument('--apply',action='store_true');args=p.parse_args()
 if not args.apply: print('No changes made; use --apply after private backup/recovery review.');return 0
 if os.geteuid()!=0:raise SystemExit('root required')
 if not CERT.is_file() or not KEY.is_file():raise SystemExit('active TLS certificate/key missing')
 # A public/LE certificate may not be signed by the private CA; validate the
 # active leaf SAN directly instead.
 san=subprocess.check_output(['openssl','x509','-in',str(CERT),'-noout','-ext','subjectAltName'],text=True)
 if 'DNS:'+DOMAIN not in san:raise SystemExit('active certificate does not cover configured DuckDNS name')
 import yaml
 agh=transform_agh(yaml.safe_load(AGH_PATH.read_text()))
 core=transform_core(json.loads(CORE_PATH.read_text()))
 fd,staged=tempfile.mkstemp(dir='/run/fortress',prefix='.encrypted-core-')
 try:
  with os.fdopen(fd,'w') as f:json.dump(core,f)
  if run(['/usr/local/bin/sing-box','check','-c',staged],False).returncode:raise SystemExit('encrypted core config rejected')
 finally:Path(staged).unlink(missing_ok=True)
 backup=Path('/root/fortress-backups')/('encrypted-dns-'+time.strftime('%Y%m%d-%H%M%S'));backup.mkdir(parents=True,mode=0o700)
 for pth in (AGH_PATH,AGH_RUNTIME,CORE_PATH,CORE_TEMPLATE):
  shutil.copyfile(pth,backup/pth.name);os.chmod(backup/pth.name,0o600)
 print('Private encrypted-DNS backup:',backup)
 try:
  # Keep AdGuard writable runtime config synchronized with persistent template.
  atomic(AGH_PATH,yaml.safe_dump(agh,sort_keys=False),0o640,0,997)
  atomic(AGH_RUNTIME,yaml.safe_dump(agh,sort_keys=False),0o600,997,997)
  payload=json.dumps(core,indent=2).encode()
  atomic(CORE_PATH,payload,0o600,997,997);atomic(CORE_TEMPLATE,payload,0o600,0,997)
  run(['systemctl','restart','adguard-home']);run(['systemctl','restart','fortress-core'])
  deadline=time.time()+30
  while time.time()<deadline:
   states=[run(['systemctl','is-active','--quiet',unit],False).returncode==0 for unit in ('adguard-home','fortress-core')]
   if all(states):break
   time.sleep(1)
  if not all(states):raise RuntimeError('services did not become active within bounded startup window')
  # Plain DNS must fail; TLS must complete on the private interface.
  plain=run(['dig','@10.8.0.1','-p','5335','+time=3','+tries=1','example.com','A'],False)
  if plain.returncode==0 and 'ANSWER:' in plain.stdout:raise RuntimeError('plain DNS still answered')
  run(['openssl','s_client','-connect','10.8.0.1:853','-servername',DOMAIN,'-brief'],False)
  print('Encrypted private DNS applied: plain 5335 disabled, DoT/DoQ 853 enabled, DoH 8445 enabled; DNSCrypt remains staged.')
 except Exception:
  atomic(AGH_PATH,(backup/AGH_PATH.name).read_bytes(),0o640,0,997)
  atomic(AGH_RUNTIME,(backup/AGH_RUNTIME.name).read_bytes(),0o600,997,997)
  atomic(CORE_PATH,(backup/CORE_PATH.name).read_bytes(),0o600,997,997)
  atomic(CORE_TEMPLATE,(backup/CORE_TEMPLATE.name).read_bytes(),0o600,0,997)
  run(['systemctl','restart','adguard-home'],False);run(['systemctl','restart','fortress-core'],False)
  raise
 return 0

if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as e:raise SystemExit('Encrypted DNS migration failed ('+type(e).__name__+'); rollback attempted')
