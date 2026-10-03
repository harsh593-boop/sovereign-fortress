"""Offline regression tests for the subscription profile generator.

The environment flag prevents loading any local runtime or persistent config,
so this test never reads deployment credentials.
"""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
os.environ["FORTRESS_SUB_OFFLINE_TEST"] = "1"
spec = importlib.util.spec_from_file_location("fortress_sub_offline", ROOT / "fortress-sub.py")
fortress_sub = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fortress_sub)


class ProfileRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fortress_sub.SERVER_IP = "198.51.100.10"
        fortress_sub.DNS_PORT = 5335
        fortress_sub.DOMAIN = ""

    def test_full_mode_uses_remote_dns_and_blocks_ipv6(self):
        config = fortress_sub.get_singbox_json_config("full")
        dns_server = config["dns"]["servers"][0]
        self.assertEqual(dns_server["address"], "tcp://10.8.0.1:5335")
        self.assertEqual(dns_server["detour"], "proxy")
        self.assertNotIn("127.0.0.1", dns_server["address"])
        tun = config["inbounds"][0]
        self.assertTrue(tun["strict_route"])
        self.assertNotIn("10.0.0.0/8", tun["route_exclude_address"])
        self.assertEqual(config["route"]["rules"][0]["ip_cidr"], ["::/0"])
        self.assertEqual(config["route"]["rules"][0]["outbound"], "block-ipv6")

    def test_traffic_only_keeps_private_direct_exceptions(self):
        config = fortress_sub.get_singbox_json_config("traffic-only")
        tun = config["inbounds"][0]
        self.assertFalse(tun["strict_route"])
        self.assertIn("10.0.0.0/8", tun["route_exclude_address"])
        self.assertIn("172.16.0.0/12", tun["route_exclude_address"])
        self.assertIn("192.168.0.0/16", tun["route_exclude_address"])
        self.assertEqual(config["route"]["rules"][0]["outbound"], "block-ipv6")
        self.assertTrue(any(rule.get("protocol") == "dns" and rule.get("outbound") == "direct"
                            for rule in config["route"]["rules"]))

    def test_hiddify_nested_url_is_encoded(self):
        link = fortress_sub.build_hiddify_link(
            "https://example.test:8443/sub/demo?mode=traffic-only",
            "Sovereign Fortress (Traffic-Only)",
        )
        self.assertTrue(link.startswith("hiddify://import/https%3A%2F%2F"))
        self.assertNotIn("?mode=", link)
        self.assertIn("#Sovereign%20Fortress%20%28Traffic-Only%29", link)

    def test_example_profiles_have_explicit_ipv6_block(self):
        for name in ("fortress-full-tunnel.example.json", "fortress-traffic-only.example.json"):
            with self.subTest(name=name):
                profile = json.loads((ROOT / name).read_text(encoding="utf-8"))
                self.assertTrue(any(o.get("tag") == "block-ipv6" for o in profile["outbounds"]))
                self.assertTrue(any(r.get("outbound") == "block-ipv6" for r in profile["route"]["rules"]))

    def test_example_wireguard_outbounds_use_current_peer_schema(self):
        for name in ("fortress-full-tunnel.example.json", "fortress-traffic-only.example.json"):
            with self.subTest(name=name):
                profile = json.loads((ROOT / name).read_text(encoding="utf-8"))
                wireguard = [o for o in profile["outbounds"] if o.get("type") == "wireguard"]
                self.assertTrue(wireguard)
                for outbound in wireguard:
                    self.assertIn("peers", outbound)
                    self.assertNotIn("peer_public_key", outbound)
                    self.assertNotIn("server_port", outbound)

    def test_full_example_never_sends_plaintext_dns_to_public_endpoint(self):
        profile = json.loads((ROOT / "fortress-full-tunnel.example.json").read_text(encoding="utf-8"))
        self.assertEqual(profile["dns"]["servers"][0]["address"], "tcp://10.8.0.1:5335")
        self.assertEqual(profile["dns"]["servers"][0]["detour"], "proxy")

    def test_dashboard_never_contains_ssh_enrollment_secret(self):
        secret = "SHOULD_NOT_BE_IN_HTML_123"
        html = fortress_sub.render_dashboard_page("sample-token", secret)
        self.assertNotIn(secret, html)
        self.assertNotIn("otpauth://", html)
        self.assertNotIn("cdnjs.cloudflare.com", html)

    def test_dashboard_falls_back_to_configured_server_ip(self):
        original_domain = fortress_sub.DOMAIN
        try:
            fortress_sub.DOMAIN = ""
            html = fortress_sub.render_dashboard_page("sample-token", "")
        finally:
            fortress_sub.DOMAIN = original_domain
        self.assertIn("https://198.51.100.10:8443/sub/sample-token?mode=full", html)
        self.assertNotIn("https://www.microsoft.com:8443/sub/", html)

    def test_configured_token_is_used_when_runtime_state_is_absent(self):
        original_paths = fortress_sub.TOKEN_RAM, fortress_sub.TOKEN_DISK
        original_dirs = fortress_sub.RAM_DIR, fortress_sub.DISK_DIR
        original_token = fortress_sub.CONFIG.get("token")
        with tempfile.TemporaryDirectory() as directory:
            runtime_dir = Path(directory) / "runtime"
            disk_dir = Path(directory) / "disk"
            runtime_dir.mkdir()
            disk_dir.mkdir()
            runtime = runtime_dir / "sub_token"
            fortress_sub.RAM_DIR = str(runtime_dir)
            fortress_sub.DISK_DIR = str(disk_dir)
            fortress_sub.TOKEN_RAM = str(runtime)
            fortress_sub.TOKEN_DISK = str(disk_dir / "sub_token")
            fortress_sub.CONFIG["token"] = "ft_sec_" + ("a" * 32)
            try:
                self.assertEqual(fortress_sub.get_or_create_token(), fortress_sub.CONFIG["token"])
                self.assertEqual(runtime.read_text(encoding="utf-8"), fortress_sub.CONFIG["token"])
            finally:
                fortress_sub.TOKEN_RAM, fortress_sub.TOKEN_DISK = original_paths
                fortress_sub.RAM_DIR, fortress_sub.DISK_DIR = original_dirs
                if original_token is None:
                    fortress_sub.CONFIG.pop("token", None)
                else:
                    fortress_sub.CONFIG["token"] = original_token

    def test_portal_privacy_text_does_not_claim_absolute_zero_logs(self):
        self.assertNotIn("Zero-Log Architecture Guarantee", fortress_sub.PRIVACY_CONTENT_HTML)
        self.assertIn("does not make an absolute zero-log", fortress_sub.PRIVACY_CONTENT_HTML)

    def test_generated_transport_never_disables_tls_verification(self):
        config = fortress_sub.get_singbox_json_config("full")
        for outbound in config["outbounds"]:
            self.assertNotEqual(outbound.get("tls", {}).get("insecure"), True)


if __name__ == "__main__":
    unittest.main()
