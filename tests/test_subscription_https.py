"""Local HTTPS integration tests with synthetic credentials/certificates only."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from unittest.mock import patch

os.environ['FORTRESS_SUB_OFFLINE_TEST'] = '1'
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('https_fixture', ROOT / 'fortress-sub.py')
sub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sub)


class HTTPSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(cls.directory / 'fixture.key'),
                        '-out', str(cls.directory / 'fixture.crt'), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=IP:127.0.0.1', '-days', '1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(cls.directory / 'fixture.crt', cls.directory / 'fixture.key')
        cls.client_context = ssl.create_default_context(cafile=str(cls.directory / 'fixture.crt'))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.token = 'ft' + '_sec_' + ('a' * 32)
        sub.FAILED_ATTEMPTS.clear()
        patches = [patch.object(sub, 'TOKEN_DISK', str(self.directory / 'durable-token')),
                   patch.object(sub, 'TOKEN_RAM', str(self.directory / 'runtime-token')),
                   patch.object(sub, 'SERVER_IP', '127.0.0.1'), patch.object(sub, 'DOMAIN', ''),
                   patch.object(sub, 'get_totp_secret', return_value=None)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        sub.save_token(self.token)
        self.server = sub.AutoDetectServer(('127.0.0.1', 0), sub.FortressSubHandler, self.server_context)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port,
                                                 context=self.client_context, timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self):
        status, headers, _ = self.request('POST', '/portal/login', urllib.parse.urlencode({'auth_credential': self.token}))
        self.assertEqual(status, 302)
        self.assertIn('Secure', headers['Set-Cookie'])
        return headers['Set-Cookie'].split(';', 1)[0]

    def test_stalled_tls_client_does_not_block_other_clients(self):
        stalled = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
        try:
            status, headers, _ = self.request('GET', '/portal')
            self.assertEqual(status, 200)
            self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
            self.assertEqual(headers['X-Frame-Options'], 'DENY')
        finally:
            stalled.close()

    def test_unicode_login_returns_401_not_handler_exception(self):
        status, _, _ = self.request('POST', '/portal/login', urllib.parse.urlencode({'auth_credential': 'invalid\u2603'}))
        self.assertEqual(status, 401)

    def test_browser_token_query_is_rejected(self):
        status, _, _ = self.request('GET', '/portal?token=' + self.token)
        self.assertEqual(status, 400)

    def test_rotation_requires_session_bound_csrf_and_revokes_session(self):
        cookie = self.login()
        status, _, _ = self.request('POST', '/portal/rotate-token', headers={'Cookie': cookie, 'X-Fortress-CSRF': '1'})
        self.assertEqual(status, 403)
        csrf = sub.session_csrf_token(cookie.split('=', 1)[1])
        status, _, body = self.request('POST', '/portal/rotate-token', headers={'Cookie': cookie, 'X-Fortress-CSRF': csrf})
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(result['url'].startswith('https://'))
        self.assertEqual(Path(sub.TOKEN_DISK).read_text(), result['token'])
        self.assertFalse(sub.verify_session_cookie(cookie.split('=', 1)[1]))
        status, _, _ = self.request('GET', '/sub/' + self.token)
        self.assertEqual(status, 302)

    def test_otp_alone_cannot_authenticate_or_export_profiles(self):
        with patch.object(sub, 'verify_totp', return_value=True):
            status, _, _ = self.request('GET', '/sub/123456')
            self.assertEqual(status, 302)
            status, _, _ = self.request('POST', '/portal/login', 'auth_credential=123456')
            self.assertEqual(status, 401)

    def test_enrolled_portal_second_factor_requires_token_and_code(self):
        with patch.object(sub, 'PORTAL_TOTP_REQUIRED', True), patch.object(sub, 'verify_totp', return_value=False):
            status, _, _ = self.request('POST', '/portal/login', 'auth_credential=' + self.token)
            self.assertEqual(status, 401)
        with patch.object(sub, 'PORTAL_TOTP_REQUIRED', True), patch.object(sub, 'verify_totp', return_value=True):
            status, _, _ = self.request('POST', '/portal/login', 'auth_credential=' + self.token + '&totp_code=123456')
            self.assertEqual(status, 302)

    def test_cross_origin_login_and_unknown_host_are_rejected(self):
        status, _, _ = self.request('POST', '/portal/login', headers={'Origin': 'https://other.invalid'})
        self.assertEqual(status, 403)
        status, _, _ = self.request('GET', '/portal', headers={'Host': 'other.invalid'})
        self.assertEqual(status, 421)

    def test_subscriptions_default_to_modern_but_allow_explicit_legacy(self):
        for core in ('1.11', '1.14'):
            status, _, body = self.request('GET', '/sub/' + self.token + '?core=' + core)
            if core == '1.11':
                self.assertEqual(status, 400)
                continue
            self.assertEqual(status, 200)
            config = json.loads(body)
            dns = config['dns']['servers'][0]
            self.assertEqual(dns['type'], 'tls')
            self.assertEqual(dns['server_port'], 853)
        status, _, _ = self.request('GET', '/sub/' + self.token + '?core=unknown')
        self.assertEqual(status, 400)


if __name__ == '__main__':
    unittest.main()
