"""Offline encrypted-DNS migration policy tests."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('encrypted_dns_fixture',ROOT/'apply_encrypted_dns.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class EncryptedDnsTests(unittest.TestCase):
    def base(self):
        return {'http':{'address':'127.0.0.1:3000'},'dns':{'bind_hosts':['127.0.0.1','10.8.0.1'],'port':5335,'serve_plain_dns':True},
                'tls':{'enabled':False,'port_https':0,'port_dns_over_tls':0,'port_dns_over_quic':0}}
    def test_private_encryption_and_plain_dns_off(self):
        c=m.transform_agh(self.base())
        self.assertFalse(c['dns']['serve_plain_dns'])
        self.assertEqual(c['tls']['port_dns_over_tls'],853)
        self.assertEqual(c['tls']['port_dns_over_quic'],853)
        self.assertEqual(c['tls']['port_https'],8445)
        self.assertEqual(c['http']['address'],'10.8.0.1:3000')
        self.assertEqual(c['tls']['port_dnscrypt'],0)
    def test_core_uses_dot_without_empty_direct_detour(self):
        c={'dns':{'servers':[{'tag':'adguard','type':'udp','server':'127.0.0.1','server_port':5335,'detour':'direct'}]},'route':{},'outbounds':[{'type':'direct','tag':'direct'}]}
        result=m.transform_core(c);s=result['dns']['servers'][0]
        self.assertEqual(s['type'],'tls');self.assertEqual(s['server_port'],853)
        self.assertNotIn('detour',s);self.assertEqual(s['tls']['server_name'],m.DOMAIN)
    def test_dnscrypt_stays_disabled_without_verified_provider_config(self):
        self.assertEqual(m.transform_agh(self.base())['tls']['port_dnscrypt'],0)
if __name__=='__main__':unittest.main()
