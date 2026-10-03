"""Offline Windows-client regressions; standard library and synthetic data only.

No real config, certificates, keys, network, Windows store, or DPAPI calls.
Run: python3 -m unittest discover -s tests -p test_windows_client.py -v
"""

import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (ROOT / "SovereignFortressApp.pyw").read_text(encoding="utf-8")


def load_app(config=None):
    """Load GUI methods with a stub Tk and a strictly synthetic config reader."""
    from client_paths import client_config_path
    config_path = str(client_config_path())
    tkinter = types.ModuleType("tkinter")
    tkinter.Tk = object
    tkinter.ttk = mock.Mock()
    tkinter.messagebox = mock.Mock()
    namespace = {"__file__": str(ROOT / "SovereignFortressApp.pyw"),
                 "__name__": "offline_windows_client"}

    def synthetic_open(path, *args, **kwargs):
        if path != config_path:
            raise AssertionError("App attempted an unexpected file read")
        return io.StringIO(json.dumps(config or {}))

    with mock.patch.dict(sys.modules, {"tkinter": tkinter, "qrcode": None,
                                      "PIL": None}), \
            mock.patch("os.path.exists", side_effect=lambda path: path == config_path), \
            mock.patch("builtins.open", side_effect=synthetic_open):
        exec(compile(APP_SOURCE, namespace["__file__"], "exec"), namespace)
    return types.SimpleNamespace(**namespace)


spec = importlib.util.spec_from_file_location("offline_fortress_vault", ROOT / "fortress_vault.py")
vault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vault)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.app = load_app({"server_ip": "192.0.2.10", "domain": "vpn.example.invalid"})
        self.gui = object.__new__(self.app.SovereignApp)

    def test_udp_is_unverified_without_any_socket_probe(self):
        with mock.patch.object(self.app.socket, "socket") as socket_call, \
                mock.patch.object(self.app.socket, "create_connection") as connection:
            self.assertIsNone(self.gui._measure_latency("192.0.2.10", 9444, "udp"))
        socket_call.assert_not_called()
        connection.assert_not_called()

    def test_udp_status_never_claims_active_or_online(self):
        label = mock.Mock()
        self.gui.latency_labels = {"synthetic-udp": label}
        self.gui.after = lambda delay, callback: callback()
        self.app.PROTOCOLS[:] = [{"name": "synthetic-udp", "proto": "udp", "port_num": 9444}]
        self.gui._probe_worker()
        text = label.config.call_args.kwargs["text"]
        self.assertIn("UNVERIFIED", text)
        self.assertNotIn("ONLINE", text)
        self.assertNotIn("ACTIVE", text)

    def test_tcp_connect_uses_requested_port_monotonic_and_closes(self):
        connection = mock.MagicMock()
        with mock.patch.object(self.app.socket, "create_connection", return_value=connection) as connect, \
                mock.patch.object(self.app.time, "monotonic", side_effect=[10.0, 10.025]):
            self.assertAlmostEqual(self.gui._measure_latency("192.0.2.10", 10443, "tcp"), 25)
        connect.assert_called_once_with(("192.0.2.10", 10443), timeout=3.5)
        connection.__exit__.assert_called_once()

    def test_tcp_failure_returns_none_after_bounded_retry(self):
        with mock.patch.object(self.app.socket, "create_connection", side_effect=OSError), \
                mock.patch.object(self.app.time, "sleep") as sleep:
            self.assertIsNone(self.gui._measure_latency("192.0.2.10", 443, "tcp"))
        sleep.assert_called_once_with(0.2)

    def test_protocol_credentials_query_values_and_ipv6_round_trip(self):
        synthetic = "test:@/?#&=+% ü"
        app = load_app({"server_ip": "2001:db8::10", "domain": "vpn.example.invalid",
                        "uuid": synthetic, "hy2_password": synthetic,
                        "ss_password": synthetic, "salamander_password": synthetic,
                        "reality_pubkey": synthetic, "reality_shortid": synthetic,
                        "pin_sha256": "unused-spki-fixture", "cert_sha256": synthetic, "token": synthetic})
        links = {item["name"]: urlsplit(item["link"]) for item in app.PROTOCOLS}
        for name, parsed in links.items():
            if name in ("auto-fastest", "Native WireGuard"):
                continue
            self.assertEqual(parsed.hostname, "2001:db8::10")
        reality = links["Fortress-Reality-TCP"]
        self.assertEqual(unquote(reality.username), synthetic)
        self.assertEqual(parse_qs(reality.query)["pbk"], [synthetic])
        self.assertEqual(parse_qs(reality.query)["sid"], [synthetic])
        for name in ("Fortress-Hysteria2-Salamander", "Fortress-Hysteria2-Standard"):
            parsed = links[name]
            self.assertEqual(unquote(parsed.username), synthetic)
            query = parse_qs(parsed.query)
            self.assertEqual(query["sni"], ["vpn.example.invalid"])
            self.assertEqual(query["pinSHA256"], [synthetic])
        self.assertEqual(parse_qs(links["Fortress-Hysteria2-Salamander"].query)["obfs-password"], [synthetic])
        tuic = links["Fortress-TUIC5"]
        self.assertEqual(unquote(tuic.username), synthetic)
        self.assertEqual(unquote(tuic.password), synthetic)
        self.assertEqual(parse_qs(tuic.query)["sni"], ["vpn.example.invalid"])
        shadowsocks = links["Fortress-Shadowsocks2022"]
        self.assertEqual(shadowsocks.username, "2022-blake3-aes-256-gcm")
        self.assertEqual(unquote(shadowsocks.password), synthetic)
        self.assertEqual(parse_qs(links["WireGuard over TCP (WSTunnel)"].query)["sni"], ["vpn.example.invalid"])
        self.assertEqual(unquote(urlsplit(app.SUB_URL).path.removeprefix("/sub/")), synthetic)

    def test_tls_name_falls_back_to_configured_ip(self):
        app = load_app({"server_ip": "192.0.2.20", "domain": ""})
        for item in app.PROTOCOLS:
            if item["name"] in ("Fortress-Hysteria2-Standard", "Fortress-TUIC5"):
                self.assertEqual(parse_qs(urlsplit(item["link"]).query)["sni"], ["192.0.2.20"])
        self.assertNotIn("www.microsoft.com", APP_SOURCE)

    def test_vault_nonzero_exit_never_displays_success(self):
        for operation in ("lock_vault", "unlock_vault", "panic_shred"):
            with self.subTest(operation=operation), \
                    mock.patch.object(self.app.os.path, "exists", return_value=True), \
                    mock.patch.object(self.app.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                self.app.messagebox.reset_mock()
                self.app.messagebox.askyesno.return_value = True
                getattr(self.gui, operation)()
                self.app.messagebox.showerror.assert_called_once()
                self.app.messagebox.showinfo.assert_not_called()
                self.app.messagebox.showwarning.assert_not_called()

    def test_vault_timeout_or_launch_failure_is_not_success(self):
        for error in (OSError("synthetic failure"), subprocess.TimeoutExpired("synthetic", 120)):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(self.app.os.path, "exists", return_value=True), \
                    mock.patch.object(self.app.subprocess, "run", side_effect=error):
                self.app.messagebox.reset_mock()
                self.gui.lock_vault()
                self.app.messagebox.showerror.assert_called_once()
                self.app.messagebox.showinfo.assert_not_called()

    def test_vault_success_and_missing_helper(self):
        with mock.patch.object(self.app.os.path, "exists", return_value=True), \
                mock.patch.object(self.app.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.gui.lock_vault()
            self.app.messagebox.showinfo.assert_called_once()
            self.assertEqual(run.call_args.args[0][-1], "lock")
            self.assertIn("SSD", self.app.messagebox.showinfo.call_args.args[1])
        self.app.messagebox.reset_mock()
        with mock.patch.object(self.app.os.path, "exists", return_value=False), \
                mock.patch.object(self.app.subprocess, "run") as run:
            self.gui.unlock_vault()
            run.assert_not_called()
            self.app.messagebox.showerror.assert_called_once()

    def test_trust_decline_does_not_launch_anything(self):
        self.app.messagebox.askyesno.return_value = False
        with mock.patch.object(self.app.os.path, "exists", return_value=True), \
                mock.patch.object(self.app.subprocess, "Popen") as launch:
            self.gui.trust_root_ca()
            launch.assert_not_called()
        prompt = self.app.messagebox.askyesno.call_args.args[1]
        self.assertIn("ANY website", prompt)
        self.assertIn("independent trusted channel", prompt)

    def test_trust_acceptance_launches_only_verification_helper(self):
        self.app.messagebox.askyesno.return_value = True
        self.gui.trust_root_ca.__globals__["APP_DIR"] = "synthetic folder & name"
        with mock.patch.object(self.app.os.path, "exists", return_value=True), \
                mock.patch.object(self.app.subprocess, "Popen") as launch:
            self.gui.trust_root_ca()
        self.assertEqual(launch.call_args.args[0], ["cmd.exe", "/d", "/c", "Trust-Certificate.bat"])
        self.assertEqual(launch.call_args.kwargs["cwd"], "synthetic folder & name")
        self.app.messagebox.showinfo.assert_not_called()

    def test_missing_trust_helper_never_uses_unverified_fallback(self):
        with mock.patch.object(self.app.os.path, "exists", side_effect=[True, False]), \
                mock.patch.object(self.app.subprocess, "Popen") as launch:
            self.gui.trust_root_ca()
            launch.assert_not_called()
        self.app.messagebox.showerror.assert_called_once()


class VaultFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic.txt"
        self.enc_path = Path(str(self.path) + ".enc")
        self.raw = b"synthetic vault test bytes\x00\xff"
        self.enc = b"encrypted:" + self.raw
        for patcher in (
            mock.patch.object(vault, "get_target_files", return_value=[str(self.path)]),
            mock.patch.object(vault, "dpapi_protect", side_effect=lambda data: b"encrypted:" + data),
            mock.patch.object(vault, "dpapi_unprotect", side_effect=lambda data: data.removeprefix(b"encrypted:")),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_no_temps(self):
        self.assertEqual(list(Path(self.temp.name).glob(".fortress-vault-*.tmp")), [])

    def test_lock_unlock_round_trip(self):
        self.path.write_bytes(self.raw)
        self.assertTrue(vault.lock_vault())
        self.assertFalse(self.path.exists())
        self.assertEqual(self.enc_path.read_bytes(), self.enc)
        self.assertTrue(vault.unlock_vault())
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertFalse(self.enc_path.exists())
        self.assert_no_temps()

    def test_empty_file_round_trip(self):
        self.path.write_bytes(b"")
        self.assertTrue(vault.lock_vault())
        self.assertTrue(vault.unlock_vault())
        self.assertEqual(self.path.read_bytes(), b"")

    def test_both_copies_conflict_never_overwritten(self):
        self.path.write_bytes(self.raw)
        self.enc_path.write_bytes(b"older synthetic ciphertext")
        self.assertFalse(vault.lock_vault())
        self.assertFalse(vault.unlock_vault())
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertEqual(self.enc_path.read_bytes(), b"older synthetic ciphertext")

    def test_protect_and_round_trip_failures_preserve_plaintext(self):
        self.path.write_bytes(self.raw)
        for patcher in (
            mock.patch.object(vault, "dpapi_protect", side_effect=OSError),
            mock.patch.object(vault, "dpapi_protect", return_value=b""),
            mock.patch.object(vault, "dpapi_unprotect", return_value=b"wrong synthetic output"),
        ):
            with patcher:
                self.assertFalse(vault.lock_vault())
            self.assertEqual(self.path.read_bytes(), self.raw)
            self.assertFalse(self.enc_path.exists())

    def test_decryption_failure_preserves_ciphertext(self):
        self.enc_path.write_bytes(self.enc)
        with mock.patch.object(vault, "dpapi_unprotect", side_effect=OSError):
            self.assertFalse(vault.unlock_vault())
        self.assertEqual(self.enc_path.read_bytes(), self.enc)
        self.assertFalse(self.path.exists())

    def test_fsync_failure_does_not_publish_or_delete_either_source(self):
        for lock in (True, False):
            source = self.path if lock else self.enc_path
            destination = self.enc_path if lock else self.path
            source.write_bytes(self.raw if lock else self.enc)
            with mock.patch.object(vault.os, "fsync", side_effect=OSError):
                self.assertFalse(vault.lock_vault() if lock else vault.unlock_vault())
            self.assertTrue(source.exists())
            self.assertFalse(destination.exists())
            source.unlink()
            self.assert_no_temps()

    def test_publication_failure_keeps_source(self):
        self.path.write_bytes(self.raw)
        with mock.patch.object(vault.os, "link", side_effect=OSError):
            self.assertFalse(vault.lock_vault())
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertFalse(self.enc_path.exists())
        self.assert_no_temps()

    def test_racing_destination_is_not_clobbered(self):
        real_link = os.link
        self.path.write_bytes(self.raw)

        def race(source, destination):
            Path(destination).write_bytes(b"racing synthetic ciphertext")
            return real_link(source, destination)

        with mock.patch.object(vault.os, "link", side_effect=race):
            self.assertFalse(vault.lock_vault())
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertEqual(self.enc_path.read_bytes(), b"racing synthetic ciphertext")
        self.assert_no_temps()

    def test_source_changed_during_conversion_is_not_deleted(self):
        self.path.write_bytes(self.raw)
        real_publish = vault._publish_new

        def concurrent_edit(destination, data):
            real_publish(destination, data)
            self.path.write_bytes(b"new synthetic edits")

        with mock.patch.object(vault, "_publish_new", side_effect=concurrent_edit):
            self.assertFalse(vault.lock_vault())
        self.assertEqual(self.path.read_bytes(), b"new synthetic edits")
        self.assertEqual(self.enc_path.read_bytes(), self.enc)

    def test_written_output_mismatch_never_deletes_source(self):
        self.path.write_bytes(self.raw)
        real_open = open

        def corrupt_read(path, mode="r", *args, **kwargs):
            if os.path.basename(path).startswith(".fortress-vault-") and mode == "rb":
                return io.BytesIO(b"corrupt synthetic disk read")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=corrupt_read):
            self.assertFalse(vault.lock_vault())
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertFalse(self.enc_path.exists())
        self.assert_no_temps()

    def test_source_removal_failure_leaves_two_complete_copies(self):
        for lock in (True, False):
            self.path.unlink(missing_ok=True)
            self.enc_path.unlink(missing_ok=True)
            source = self.path if lock else self.enc_path
            source.write_bytes(self.raw if lock else self.enc)
            with mock.patch.object(vault.os, "remove", side_effect=PermissionError):
                self.assertFalse(vault.lock_vault() if lock else vault.unlock_vault())
            self.assertEqual(self.path.read_bytes(), self.raw)
            self.assertEqual(self.enc_path.read_bytes(), self.enc)
            self.assert_no_temps()

    def test_partial_failure_continues_but_returns_failure(self):
        second = Path(self.temp.name) / "second-synthetic.txt"
        self.path.write_bytes(self.raw)
        self.enc_path.write_bytes(b"conflict")
        second.write_bytes(self.raw)
        with mock.patch.object(vault, "get_target_files", return_value=[str(self.path), str(second)]):
            self.assertFalse(vault.lock_vault())
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertFalse(second.exists())
        self.assertEqual(Path(str(second) + ".enc").read_bytes(), self.enc)

    def test_symlink_source_is_rejected(self):
        target = Path(self.temp.name) / "synthetic-target.txt"
        target.write_bytes(self.raw)
        try:
            self.path.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable")
        self.assertFalse(vault.lock_vault())
        self.assertEqual(target.read_bytes(), self.raw)
        self.assertFalse(self.enc_path.exists())

    def test_panic_failure_returns_failure_and_abort_does_not_touch_files(self):
        self.path.write_bytes(self.raw)
        with mock.patch("builtins.input", return_value="cancel"), \
                mock.patch.object(vault, "secure_shred") as shred:
            self.assertFalse(vault.panic_shred_local())
            shred.assert_not_called()
        with mock.patch("builtins.input", return_value="VAPORIZE"), \
                mock.patch.object(vault, "__file__", str(Path(self.temp.name) / "vault.py")), \
                mock.patch.object(vault, "secure_shred", side_effect=PermissionError):
            self.assertFalse(vault.panic_shred_local())
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_shred_failure_is_not_swallowed(self):
        self.path.write_bytes(self.raw)
        with mock.patch.object(vault.os, "fsync", side_effect=OSError):
            with self.assertRaises(OSError):
                vault.secure_shred(str(self.path))
        self.assertTrue(self.path.exists())


class NativeApiContractTests(unittest.TestCase):
    def test_pointer_safe_windows_signatures(self):
        crypt32, kernel32 = mock.Mock(), mock.Mock()
        with mock.patch.object(vault.os, "name", "nt"), \
                mock.patch.object(vault.ctypes, "WinDLL", create=True,
                                  side_effect=[crypt32, kernel32]) as loader:
            protect, unprotect, free = vault._dpapi_functions()
        self.assertEqual(loader.call_args_list,
                         [mock.call("crypt32", use_last_error=True),
                          mock.call("kernel32", use_last_error=True)])
        self.assertEqual(protect.argtypes[1], vault.wintypes.LPCWSTR)
        self.assertEqual(unprotect.argtypes[1], ctypes.POINTER(vault.wintypes.LPWSTR))
        self.assertEqual(free.argtypes, [ctypes.c_void_p])
        self.assertEqual(free.restype, ctypes.c_void_p)
        self.assertEqual(ctypes.sizeof(vault.DATA_BLOB._fields_[0][1]), 4)

    def test_dpapi_copies_output_and_frees_native_buffer(self):
        buffers = []

        def native(in_ptr, description, entropy_ptr, reserved, prompt, flags, out_ptr):
            self.assertEqual(flags, 1)
            self.assertEqual(ctypes.cast(in_ptr, ctypes.POINTER(vault.DATA_BLOB)).contents.cbData, 4)
            buf = ctypes.create_string_buffer(b"synthetic output")
            buffers.append(buf)
            out = ctypes.cast(out_ptr, ctypes.POINTER(vault.DATA_BLOB)).contents
            out.cbData = len(b"synthetic output")
            out.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
            return 1

        free = mock.Mock()
        with mock.patch.object(vault, "_dpapi_functions", return_value=(native, native, free)):
            self.assertEqual(vault.dpapi_protect(b"test", entropy=b"synthetic"), b"synthetic output")
            self.assertEqual(vault.dpapi_unprotect(b"test", entropy=b"synthetic"), b"synthetic output")
        self.assertEqual(free.call_count, 2)
        self.assertIsInstance(free.call_args.args[0], ctypes.c_void_p)

    def test_native_output_is_freed_even_if_copy_raises(self):
        buffer = ctypes.create_string_buffer(b"synthetic")

        def native(*args):
            output = ctypes.cast(args[-1], ctypes.POINTER(vault.DATA_BLOB)).contents
            output.cbData = 9
            output.pbData = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
            return 1

        free = mock.Mock()
        with mock.patch.object(vault, "_dpapi_functions", return_value=(native, native, free)), \
                mock.patch.object(vault.ctypes, "string_at", side_effect=OSError):
            with self.assertRaises(OSError):
                vault.dpapi_protect(b"synthetic")
        free.assert_called_once()

    def test_legacy_fallback_only_for_default_entropy_and_error_propagates(self):
        native = mock.Mock(return_value=0)
        with mock.patch.object(vault, "_dpapi_functions", return_value=(native, native, mock.Mock())), \
                mock.patch.object(vault.ctypes, "get_last_error", return_value=13, create=True), \
                mock.patch.object(vault.ctypes, "WinError", side_effect=lambda error: OSError(error), create=True):
            with self.assertRaises(OSError):
                vault.dpapi_unprotect(b"synthetic")
            self.assertEqual(native.call_count, 2)
            self.assertIsNone(native.call_args.args[2])
            native.reset_mock()
            with self.assertRaises(OSError):
                vault.dpapi_unprotect(b"synthetic", entropy=b"explicit entropy")
            self.assertEqual(native.call_count, 1)
            self.assertIsNotNone(native.call_args.args[2])

    def test_cli_exit_status_reflects_operation(self):
        with mock.patch.object(vault.os, "name", "nt"), \
                mock.patch.object(vault, "lock_vault", return_value=False), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(vault.main(["lock"]), 1)
        with mock.patch.object(vault.os, "name", "nt"), \
                mock.patch.object(vault, "unlock_vault", return_value=True):
            self.assertEqual(vault.main(["unlock"]), 0)
        with mock.patch.object(vault.os, "name", "posix"), \
                mock.patch.object(vault, "get_target_files") as targets, \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(vault.main(["lock"]), 1)
            targets.assert_not_called()


class PrivateClientPathsTests(unittest.TestCase):
    def test_default_config_is_not_inside_public_repository(self):
        from client_paths import client_config_path
        with mock.patch.dict(os.environ, {'LOCALAPPDATA': str(Path(tempfile.gettempdir()) / 'synthetic-appdata')}, clear=True):
            self.assertNotIn(str(ROOT), str(client_config_path()))

    def test_powershell_wrappers_use_checked_vault_without_wildcards(self):
        for name in ('Protect-FortressVault.ps1', 'Shred-Fortress.ps1'):
            source = (ROOT / name).read_text()
            self.assertIn('fortress_vault.py', source)
            self.assertIn('exit $LASTEXITCODE', source)
            self.assertNotIn('ssh-key-*', source)
            self.assertNotIn('Get-ChildItem', source)
            self.assertNotIn('WriteAllBytes', source)

    def test_vault_does_not_discover_or_delete_unrelated_ssh_keys(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(vault.glob, 'glob') as search:
            files = vault.get_target_files()
        search.assert_not_called()
        self.assertFalse(any('Downloads' in name for name in files))


class BatchSafetyTests(unittest.TestCase):
    def test_trust_requires_verified_fingerprint_and_explicit_confirmation(self):
        source = (ROOT / "Trust-Certificate.bat").read_text(encoding="utf-8")
        self.assertIn("INDEPENDENT trusted channel", source)
        self.assertIn("$cert.RawData", source)
        self.assertIn("SHA256]::Create()", source)
        self.assertIn("$expected -cne $fingerprint", source)
        self.assertIn("-cne 'TRUST'", source)
        self.assertLess(source.index("$expected -cne $fingerprint"), source.index("$store.Add($cert)"))
        self.assertLess(source.index("-cne 'TRUST'"), source.index("$store.Add($cert)"))
        self.assertIn("'Root', 'CurrentUser'", source)
        self.assertNotIn("LocalMachine", source)
        self.assertNotIn("Import-Certificate", source)  # Add the exact verified in-memory certificate.
        self.assertIn("$ErrorActionPreference = 'Stop'", source)
        self.assertIn("exit /b %RESULT%", source)
        self.assertNotIn("100%", source)

    def test_wstunnel_uses_json_endpoint_and_preserves_tls_verification(self):
        source = (ROOT / "start-wstunnel.bat").read_text(encoding="utf-8")
        self.assertIn("ConvertFrom-Json", source)
        self.assertIn("$cfg.domain", source)
        self.assertIn("$cfg.server_ip", source)
        self.assertIn("[Uri]::CheckHostName", source)
        self.assertIn("$endpoint = 'wss://' + $uriHost + ':8080'", source)
        self.assertIn("& $binary client --tls-verify-certificate -L", source)
        self.assertIn("$env:LOCALAPPDATA", source)
        self.assertIn("Get-Content -LiteralPath $cfgPath", source)
        self.assertNotIn("findstr", source.lower())
        self.assertNotIn("www.microsoft.com", source)
        self.assertNotIn("--tls-sni-override", source)
        self.assertNotIn("--tls-verify-certificate=false", source)
        self.assertNotIn("--tls-verify-certificate false", source)
        self.assertIn("$hash -cne $expected", source)
        self.assertIn("exit $LASTEXITCODE", source)
        self.assertIn("exit /b %RESULT%", source)
        self.assertNotIn("$_.Exception.Message", source)  # JSON parse errors can expose credentials.


if __name__ == "__main__":
    unittest.main()
