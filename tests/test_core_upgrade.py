"""Pure migration checks; no VPS, credentials, or service access."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('upgrade_fixture',ROOT/'upgrade_server_core.py')
upgrade=importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class CoreUpgradeTests(unittest.TestCase):
    def fixture(self):
        return {'dns':{'servers':[{'tag':'adguard','address':'127.0.0.1:5335','detour':'direct'}],
                       'rules':[{'outbound':'any','server':'adguard'}]},
                'inbounds':[{'tag':'in','type':'vless','users':[{'uuid':'synthetic-identity'}],
                             'tls':{'reality':{'enabled':True,'private_key':'synthetic-private',
                                              'handshake':{'server':'example.test','server_port':443}}}}],
                'outbounds':[{'type':'direct','tag':'direct'},{'type':'block','tag':'block'}],
                'route':{'rules':[{'ip_cidr':['::1/128'],'outbound':'block'}]}}

    def test_typed_dns_and_explicit_reality_resolver_preserve_auth(self):
        old=self.fixture()
        new=upgrade.current_server_config(old)
        self.assertEqual(new['dns']['servers'][0]['type'],'udp')
        self.assertEqual(new['dns']['servers'][0]['server_port'],5335)
        self.assertNotIn('detour',new['dns']['servers'][0])
        self.assertNotIn('rules',new['dns'])
        self.assertEqual(new['route']['default_domain_resolver'],'adguard')
        reality=new['inbounds'][0]['tls']['reality']
        self.assertEqual(reality['handshake']['domain_resolver'],'adguard')
        self.assertEqual(reality['private_key'],'synthetic-private')
        self.assertEqual(new['inbounds'][0]['users'],old['inbounds'][0]['users'])
        self.assertNotIn('type',old['dns']['servers'][0])
        self.assertEqual(upgrade.current_server_config(new),new)

    def test_deprecated_block_migrates_to_reject(self):
        new=upgrade.current_server_config(self.fixture())
        self.assertFalse(any(x['type']=='block' for x in new['outbounds']))
        self.assertEqual(new['route']['rules'][0]['action'],'reject')

    def test_unknown_operator_dns_policy_fails_closed(self):
        old=self.fixture()
        old['dns']['rules'].append({'domain':['example.test'],'server':'adguard'})
        with self.assertRaises(ValueError):upgrade.current_server_config(old)

    def test_non_private_resolver_is_not_silently_converted(self):
        old=self.fixture();old['dns']['servers'][0]['address']='1.1.1.1'
        with self.assertRaises(ValueError):upgrade.current_server_config(old)


if __name__=='__main__':unittest.main()
