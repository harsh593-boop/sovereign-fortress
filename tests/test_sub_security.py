"""Offline security regressions; never reads deployment configuration or keys."""
import base64
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

os.environ['FORTRESS_SUB_OFFLINE_TEST'] = '1'
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sub_security_fixture', ROOT / 'fortress-sub.py')
sub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sub)


class SubscriptionSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ram = self.root / 'runtime'
        self.disk = self.root / 'state'
        self.ram.mkdir()
        self.disk.mkdir()
        self.patches = [patch.object(sub, 'TOKEN_RAM', str(self.ram / 'sub_token')),
                        patch.object(sub, 'TOKEN_DISK', str(self.disk / 'sub_token')),
                        patch.object(sub, 'RAM_DIR', str(self.ram)),
                        patch.object(sub, 'DISK_DIR', str(self.disk))]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_rotation_persists_atomically_with_private_permissions(self):
        value = 'ft' + '_sec_' + ('a' * 32)
        sub.save_token(value)
        self.assertEqual(Path(sub.TOKEN_DISK).read_text(), value)
        self.assertEqual(Path(sub.TOKEN_RAM).read_text(), value)
        self.assertEqual(Path(sub.TOKEN_DISK).stat().st_mode & 0o777, 0o600)

    def test_persistent_rotation_wins_over_stale_boot_runtime(self):
        disk = 'ft' + '_sec_' + ('b' * 32)
        ram = 'ft' + '_sec_' + ('a' * 32)
        Path(sub.TOKEN_DISK).write_text(disk)
        Path(sub.TOKEN_RAM).write_text(ram)
        self.assertEqual(sub.get_or_create_token(), disk)

    def test_corrupt_durable_state_cannot_resurrect_revoked_ram_token(self):
        Path(sub.TOKEN_DISK).write_text('corrupt fixture')
        Path(sub.TOKEN_RAM).write_text('ft' + '_sec_' + ('a' * 32))
        with self.assertRaises(RuntimeError):
            sub.get_or_create_token()

    def test_failed_persistence_is_not_silently_reported_as_success(self):
        with patch.object(sub, 'TOKEN_DISK', str(self.root / 'missing' / 'sub_token')):
            with self.assertRaises(OSError):
                sub.save_token('ft' + '_sec_' + ('c' * 32))

    def test_token_validation_rejects_controls_and_overlong_input(self):
        self.assertFalse(sub._is_valid_subscription_token('ft_sec_' + 'x' * 32 + '\n'))
        self.assertFalse(sub._is_valid_subscription_token('ft_sec_' + 'x' * 1000))

    def test_session_has_nonce_and_rejects_future_signed_timestamp(self):
        with patch.object(sub.time, 'time', return_value=1000):
            cookie = sub.create_session_cookie()
            self.assertTrue(sub.verify_session_cookie(cookie))
            self.assertNotEqual(cookie, sub.create_session_cookie())
        with patch.object(sub.time, 'time', return_value=900):
            self.assertFalse(sub.verify_session_cookie(cookie))

    def test_unicode_auth_input_is_rejected_without_exception(self):
        self.assertFalse(sub.safe_compare('invalid\u2603', 'ascii-fixture'))

    def test_csrf_is_bound_to_session_and_not_constant(self):
        a = sub.create_session_cookie()
        b = sub.create_session_cookie()
        self.assertNotEqual(sub.session_csrf_token(a), sub.session_csrf_token(b))
        self.assertNotEqual(sub.session_csrf_token(a), '1')

    def test_full_hijack_is_matched_only_to_dns_after_sniffing(self):
        cfg = sub.get_singbox_json_config('full', core='1.11')
        rules = cfg['route']['rules']
        hijack = [r for r in rules if r.get('action') == 'hijack-dns']
        self.assertEqual(hijack, [{'protocol': 'dns', 'action': 'hijack-dns'}])
        self.assertTrue(any(r.get('action') == 'sniff' for r in rules))

    def test_modern_config_uses_typed_dns_endpoints_and_reject_actions(self):
        cfg = sub.get_singbox_json_config('full', core='1.14')
        dns = cfg['dns']['servers'][0]
        self.assertEqual(dns['type'], 'tcp')
        self.assertEqual(dns['server'], '10.8.0.1')
        self.assertEqual(dns['detour'], 'proxy')
        self.assertNotIn('address', dns)
        self.assertFalse(any(o.get('type') in ('block', 'wireguard') for o in cfg['outbounds']))
        self.assertTrue(any(r.get('action') == 'reject' for r in cfg['route']['rules']))
        self.assertEqual(cfg['inbounds'][0]['dns_mode'], 'hijack')

    def test_modern_traffic_only_disables_tun_native_dns_changes(self):
        cfg = sub.get_singbox_json_config('traffic-only', core='1.14')
        self.assertEqual(cfg['inbounds'][0]['dns_mode'], 'disabled')
        self.assertFalse(any(r.get('action') == 'hijack-dns' for r in cfg['route']['rules']))
        self.assertFalse(any(r.get('process_name') and 'cloudflared.exe' in r['process_name'] for r in cfg['route']['rules']))

    def test_stale_private_ca_does_not_override_public_certificate_trust(self):
        (self.ram / 'ca.crt').write_text('-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----')
        (self.ram / 'cert.pem').write_text('synthetic leaf')
        with patch.object(sub.subprocess, 'run') as verify:
            verify.return_value.returncode = 1
            config = sub.get_singbox_json_config('full')
        for outbound in config['outbounds']:
            self.assertNotIn('certificate', outbound.get('tls', {}))
            self.assertNotEqual(outbound.get('tls', {}).get('insecure'), True)

    def test_typo_in_mode_cannot_silently_change_dns_policy(self):
        with self.assertRaises(ValueError):
            sub.get_singbox_json_config(mode='traffic-onl')

    def test_unknown_core_version_is_rejected(self):
        with self.assertRaises(ValueError):
            sub.get_singbox_json_config(core='unsupported')

    def test_shadowsocks_2022_uri_uses_percent_encoded_not_base64_userinfo(self):
        from urllib.parse import urlsplit, unquote
        with patch.object(sub, 'SS_PASSWORD', 'fixture+/='):
            uri = urlsplit(sub.get_protocol_links()[4])
            self.assertEqual(uri.username, '2022-blake3-aes-256-gcm')
            self.assertEqual(unquote(uri.password), 'fixture+/=')
            self.assertIn('%2F', uri.password)


if __name__ == '__main__':
    unittest.main()
