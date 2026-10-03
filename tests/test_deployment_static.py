"""Static regression checks for deployment safety invariants.

These checks do not execute the installer, access a server, or inspect local
credentials. They protect the script-level guarantees that can be verified
without root or a live deployment.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeploymentScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = (ROOT / "deploy_server.sh").read_text(encoding="utf-8")

    def test_published_token_and_runtime_token_share_one_source(self):
        self.assertIn('"token": "${SUB_TOKEN}"', self.script)
        self.assertIn("printf '%s\\n' \"$SUB_TOKEN\" > \"$STATE_DIR/sub_token\"", self.script)
        self.assertIn("cp \"$STATE_DIR/sub_token\" \"$RAM_DIR/sub_token\"", self.script)

    def test_endpoint_domain_is_persisted_explicitly(self):
        self.assertIn('"domain": "${DOMAIN}"', self.script)
        self.assertIn('"dns_port": 5335', self.script)

    def test_adguard_privacy_settings_and_tmpfs_are_verified(self):
        self.assertIn("querylog:\n  enabled: false\n  file_enabled: false", self.script)
        self.assertIn("statistics:\n  enabled: false", self.script)
        self.assertNotIn("querylog_enabled:", self.script)
        self.assertIn('findmnt -n -o FSTYPE --target "$AGH_DATA_DIR"', self.script)

    def test_service_output_is_not_forwarded_to_journald(self):
        self.assertGreaterEqual(self.script.count("StandardOutput=null"), 4)
        self.assertGreaterEqual(self.script.count("StandardError=null"), 4)
        self.assertIn("Storage=volatile", self.script)
        self.assertIn("ForwardToSyslog=no", self.script)

    def test_unpinned_subscription_download_is_rejected(self):
        self.assertIn("refusing an unpinned remote download", self.script)

    def test_installer_does_not_print_tokens_or_enrollment_seeds(self):
        for line in self.script.splitlines():
            if line.startswith('echo '):
                self.assertNotIn('${SUB_TOKEN}', line)
                self.assertNotIn('${TOTP_SECRET_VAL}', line)

    def test_initializer_preserves_root_wireguard_and_never_changes_ssh(self):
        init = (ROOT / 'fortress-init.sh').read_text()
        self.assertIn('findmnt -n -o FSTYPE', init)
        self.assertIn('install -m 0600 -o root -g root', init)
        self.assertNotIn('google_authenticator', init)
        self.assertNotIn('chown -R', init)

    def test_ssh_policy_is_opt_in(self):
        self.assertIn('FORTRESS_CONFIGURE_SSH_2FA:-0', self.script)


if __name__ == "__main__":
    unittest.main()
