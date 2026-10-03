"""Pure offline checks for existing-server migration; no remote operations."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('remediation_fixture', ROOT / 'apply_server_remediation.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class RemediationTests(unittest.TestCase):
    def test_adguard_uses_actual_root_level_privacy_keys(self):
        original = {'dns': {'upstream_dns': ['tls://dns.quad9.net'], 'querylog_enabled': False},
                    'querylog': {'enabled': True, 'file_enabled': True}, 'statistics': {'enabled': True}}
        result = migration.harden_adguard(original)
        self.assertFalse(result['querylog']['enabled'])
        self.assertFalse(result['querylog']['file_enabled'])
        self.assertFalse(result['statistics']['enabled'])
        self.assertNotIn('querylog_enabled', result['dns'])
        self.assertEqual(result['http']['address'], '127.0.0.1:3000')
        self.assertEqual(result['dns']['allowed_clients'], ['127.0.0.0/8', '10.8.0.0/24'])
        self.assertTrue(original['querylog']['enabled'])
        self.assertEqual(migration.harden_adguard(result), result)

    def test_plaintext_upstream_requires_review_not_silent_downgrade(self):
        with self.assertRaises(ValueError):
            migration.harden_adguard({'dns': {'upstream_dns': ['1.1.1.1']}})

    def test_private_dns_exception_precedes_private_destination_denial(self):
        cfg = {'inbounds': [], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
        result = migration.harden_core(cfg)
        rules = result['route']['rules']
        self.assertEqual(rules[0]['port'], 5335)
        self.assertEqual(rules[1]['action'], 'resolve')
        self.assertEqual(rules[2]['action'], 'reject')
        self.assertIn('169.254.0.0/16', rules[2]['ip_cidr'])
        self.assertIn('::1/128', rules[2]['ip_cidr'])
        self.assertEqual(migration.harden_core(result), result)

    def test_service_state_path_is_writable_but_code_path_is_not(self):
        drops = migration.dropins()
        self.assertIn('ReadWritePaths=/run/fortress /var/lib/fortress/subscription', drops['fortress-sub'])
        self.assertIn('ReadOnlyPaths=/opt/AdGuardHome', drops['adguard-home'])
        self.assertIn('-c /run/fortress/adguard/AdGuardHome.yaml', drops['adguard-home'])
        self.assertIn('StandardOutput=null', drops['adguard-home'])
        self.assertIn('LimitCORE=0', drops['fortress-core'])

    def test_firewall_rules_do_not_replace_ssh_or_global_policies(self):
        rules = migration.firewall_rules(997)
        self.assertEqual(len(rules), 4)
        self.assertFalse(any('--dport' in rule and '22' in rule for _, rule in rules))
        self.assertTrue(any(chain == 'OUTPUT' and '--uid-owner' in rule for chain, rule in rules))


if __name__ == '__main__':
    unittest.main()
