"""Offline regression tests for the privacy scanner.

All sensitive-looking values in this module are assembled at runtime.  The
fixtures are synthetic and are never printed; tests assert on locations and
redacted diagnostics instead of exposing match text.
"""

from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))
import check_repo_privacy  # noqa: E402


def git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "privacy-test",
            "GIT_AUTHOR_EMAIL": "privacy-test@example.invalid",
            "GIT_COMMITTER_NAME": "privacy-test",
            "GIT_COMMITTER_EMAIL": "privacy-test@example.invalid",
        },
    )


class PrivacyScannerTests(unittest.TestCase):
    def make_repository(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="privacy-scan-"))
        git(directory, "init")
        return directory

    def test_scans_ignored_worktree_files(self) -> None:
        repository = self.make_repository()
        self.addCleanup(lambda: __import__("shutil").rmtree(repository, ignore_errors=True))
        (repository / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        synthetic_token = "ft" + "_sec_" + ("a" * 32)
        (repository / "ignored.txt").write_text(synthetic_token, encoding="utf-8")

        findings = check_repo_privacy.scan_repository(repository, include_history=False)

        self.assertTrue(any(f.path == "ignored.txt" and f.source == "worktree" for f in findings))

    def test_scans_all_git_blobs_not_only_current_files(self) -> None:
        repository = self.make_repository()
        self.addCleanup(lambda: __import__("shutil").rmtree(repository, ignore_errors=True))
        (repository / "history.txt").write_text("safe initial content\n", encoding="utf-8")
        git(repository, "add", ".")
        git(repository, "commit", "-m", "initial")

        synthetic_totp = "A" * 32
        (repository / "history.txt").write_text(synthetic_totp, encoding="utf-8")
        git(repository, "add", "history.txt")
        git(repository, "commit", "-m", "fixture")
        (repository / "history.txt").write_text("safe current content\n", encoding="utf-8")

        findings = check_repo_privacy.scan_repository(repository)

        self.assertTrue(any(f.source == "git blob" and f.reason == "TOTP secret format" for f in findings))

    def test_configured_values_are_detected_without_being_reported(self) -> None:
        repository = self.make_repository()
        self.addCleanup(lambda: __import__("shutil").rmtree(repository, ignore_errors=True))
        configured = "unit-test-value-" + ("z" * 18)
        (repository / "fortress_config.json").write_text(
            '{"token": "' + configured + '"}', encoding="utf-8"
        )
        (repository / "notes.txt").write_text("copied value: " + configured, encoding="utf-8")

        findings = check_repo_privacy.scan_repository(repository, include_history=False)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check_repo_privacy._print_report(findings)

        self.assertTrue(findings)
        self.assertNotIn(configured, output.getvalue())
        self.assertIn("redacted", output.getvalue().lower())

    def test_private_key_and_github_tokens_are_detected_in_ordinary_text(self) -> None:
        repository = self.make_repository()
        self.addCleanup(lambda: __import__('shutil').rmtree(repository, ignore_errors=True))
        marker = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----'
        token = 'gh' + 'p_' + ('a' * 36)
        (repository / 'notes.txt').write_text(marker + '\n' + token)
        findings = check_repo_privacy.scan_repository(repository, include_history=False)
        self.assertTrue(any(f.reason == 'Private key PEM marker' for f in findings))
        self.assertTrue(any(f.reason == 'GitHub token format' for f in findings))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            check_repo_privacy._print_report(findings)
        self.assertNotIn(token, output.getvalue())
        self.assertNotIn(marker, output.getvalue())

    def test_large_object_batch_completes_without_pipe_deadlock(self) -> None:
        repository = self.make_repository()
        self.addCleanup(lambda: __import__('shutil').rmtree(repository, ignore_errors=True))
        # Unique blobs exceed the Git request pipe capacity. No secret fixtures.
        for index in range(2200):
            (repository / f'fixture-{index}.txt').write_text(f'safe fixture {index}\n')
        git(repository, 'add', '.')
        git(repository, 'commit', '-m', 'many synthetic blobs')
        result = subprocess.run([sys.executable, str(REPOSITORY / 'check_repo_privacy.py'),
                                 '--root', str(repository)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0)

    def test_missing_root_is_not_reported_as_a_clean_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            findings = check_repo_privacy.scan_repository(Path(directory) / 'missing')
        self.assertTrue(any(f.source == 'scan' for f in findings))

    def test_failed_git_history_scan_is_not_reported_as_clean(self) -> None:
        from unittest.mock import patch
        repository = self.make_repository()
        self.addCleanup(lambda: __import__('shutil').rmtree(repository, ignore_errors=True))
        with patch.object(check_repo_privacy, '_history_object_ids', side_effect=check_repo_privacy.ScanFailure('fixture')):
            findings = check_repo_privacy.scan_repository(repository)
        self.assertTrue(any(f.path == '[Git history]' and f.source == 'scan' for f in findings))

    def test_clean_repository_passes_without_unqualified_claims(self) -> None:
        repository = self.make_repository()
        self.addCleanup(lambda: __import__("shutil").rmtree(repository, ignore_errors=True))
        (repository / "README.md").write_text("local test fixture\n", encoding="utf-8")

        self.assertEqual(check_repo_privacy.scan_repository(repository), [])


if __name__ == "__main__":
    unittest.main()
