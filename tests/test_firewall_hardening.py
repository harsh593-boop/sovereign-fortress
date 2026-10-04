"""Offline firewall policy tests; no command execution."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fw_fixture',ROOT/'apply_firewall_hardening.py')
fw=importlib.util.module_from_spec(spec);spec.loader.exec_module(fw)

class FirewallPolicyTests(unittest.TestCase):
    def test_private_dns_is_scoped_to_wireguard(self):
        self.assertEqual(fw.PRIVATE_DNS_TCP,(5335,853,8445))
        self.assertEqual(fw.PRIVATE_DNS_UDP,(5335,853,8445))

    def test_public_services_are_explicit_not_default(self):
        self.assertIn(22,fw.SERVICE_TCP)
        self.assertIn(443,fw.SERVICE_TCP)
        self.assertNotIn(53,fw.SERVICE_TCP)
        self.assertNotIn(53,fw.SERVICE_UDP)

    def test_policy_targets_fail_closed_input_and_forward_but_not_output(self):
        source=(ROOT/'apply_firewall_hardening.py').read_text()
        self.assertIn("iptables', '-P', 'INPUT', 'DROP",source)
        self.assertIn("iptables', '-P', 'FORWARD', 'DROP",source)
        self.assertIn("iptables', '-P', 'OUTPUT', 'ACCEPT",source)
        self.assertIn('FORTRESS_FORWARD',source)
        self.assertIn('169.254.0.0/16',source)

if __name__=='__main__':unittest.main()
