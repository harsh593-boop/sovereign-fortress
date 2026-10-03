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

    def test_clean_repository_passes_without_unqualified_claims(self) -> None:
        repository = self.make_repository()
        self.addCleanup(lambda: __import__("shutil").rmtree(repository, ignore_errors=True))
        (repository / "README.md").write_text("local test fixture\n", encoding="utf-8")

        self.assertEqual(check_repo_privacy.scan_repository(repository), [])


if __name__ == "__main__":
    unittest.main()
