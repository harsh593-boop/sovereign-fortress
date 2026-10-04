#!/usr/bin/env python3
"""Offline privacy and secret scanner for the Sovereign Fortress repository.

The scanner deliberately reports *where* a match was found, but never reports
the matching text.  It checks the complete working tree (including ignored and
untracked files) and every blob reachable from the local Git object database.
It is a detection aid, not proof that a deployment is anonymous or log-free.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Iterator, Sequence


# These patterns are intentionally generic.  Local deployment values are
# loaded at scan time and are never included in a violation or log message.
GENERIC_FORBIDDEN_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"[C-Zc-z]:\\[Uu]sers\\[A-Za-z0-9_.-]+", "Personal Windows user path"),
    (r"/home/[A-Za-z0-9_.-]+", "Personal Linux home path"),
    (r"\bft_sec_[0-9a-fA-F]{32}\b", "Subscription token format"),
    (r"\bft_sec_[A-Za-z0-9_-]{32}\b", "Subscription token format"),
    (r"\b[A-Z2-7]{32}\b", "TOTP secret format"),
    (r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----", "Private key PEM marker"),
    (r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,255}\b", "GitHub token format"),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b", "GitHub fine-grained token format"),
)

SENSITIVE_CONFIG_KEYS = frozenset(
    {
        "server_ip",
        "token",
        "totp_secret",
        "uuid",
        "reality_pubkey",
        "reality_shortid",
        "hy2_password",
        "salamander_password",
        "ss_password",
        "wg_server_pub",
        "wg_client_priv",
        "wg_server_priv",
        "nextdns_id",
        "ssh_key_path",
        "campus_domain",
    }
)

FORBIDDEN_FILE_PATTERNS: tuple[str, ...] = (
    r"\.key$",
    r"\.crt$",
    r"\.pem$",
    r"\.p12$",
    r"\.pfx$",
    r"\.enc$",
    r"\.url$",
    r"\.exe$",
    r"\.bin$",
    r"\.dll$",
    r"^fortress_config\.json$",
    r"^client_profiles\.txt$",
    r"^fortress_dashboard\.html$",
    r"^qr_codes/",
    r"^\.agents/",
)

# Documentation and test fixtures use these values as examples.  They do not
# match the generic token/TOTP patterns above, and are not used as a blanket
# line-level bypass (a line containing an example must still be scanned).
ALLOWED_EXAMPLES = frozenset(
    {
        "<YOUR_TOTP_SECRET>",
        "<YOUR_SUBSCRIPTION_TOKEN>",
        "<YOUR_SERVER_IP>",
        "<YOUR_UUID>",
        "<YOUR_REALITY_PUBLIC_KEY>",
        "<YOUR_REALITY_SHORT_ID>",
        "<YOUR_HYSTERIA2_PASSWORD>",
        "<YOUR_SALAMANDER_PASSWORD>",
        "<YOUR_SHADOWSOCKS_PASSWORD>",
        "<YOUR_NEXTDNS_ID>",
    }
)

WHITELISTED_IPS = frozenset(
    {
        "0.0.0.0",
        "127.0.0.1",
        "127.0.0.0",
        "127.0.0.53",
        "10.8.0.1",
        "10.8.0.2",
        "10.66.66.1",
        "10.66.66.2",
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
        "45.90.28.0",
        "45.90.30.0",
        "94.140.14.14",
        "94.140.15.15",
        "208.67.222.222",
        "208.67.220.220",
        "76.76.2.0",
        "76.76.10.0",
        "10.0.0.0",
        "172.16.0.0",
        "192.168.0.0",
        "169.254.0.0",
        "169.254.169.254",
        "172.19.0.1",
        "162.159.36.1",
        "198.51.100.1",
        "198.51.100.2",
        "198.51.100.3",
        "198.51.100.4",
        "198.51.100.5",
        "192.0.2.1",
        "203.0.113.1",
    }
)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class Violation:
    """A safe-to-print finding; it intentionally contains no matched value."""

    path: str
    line: int
    reason: str
    source: str


def _relative_path(root: Path, path: Path) -> str:
    """Return a stable repository-relative path without exposing host paths."""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return "[outside-repository]"


def _iter_worktree_files(root: Path) -> Iterator[Path]:
    """Yield regular files, including ignored/untracked files, but not .git or bytecode."""

    def traversal_error(error):
        raise ScanFailure("Working tree could not be traversed") from error

    # Prune before descending. rglob followed by filtering still enters Git's
    # object directories, which background packing can remove while we scan.
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False, onerror=traversal_error):
        base = Path(directory)
        directories[:] = [name for name in directories
                          if name not in ('.git', '__pycache__') and not (base / name).is_symlink()]
        for name in files:
            path = base / name
            if name == '.git' or path.suffix == '.pyc' or path.is_symlink():
                continue
            try:
                if path.is_file():
                    yield path
            except OSError as error:
                raise ScanFailure("Working tree metadata could not be read") from error


def _configured_values(root: Path, environ: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """Return regexes for local values without ever exposing those values."""

    values: list[tuple[str, str]] = []
    config_path = root / "fortress_config.json"
    if config_path.is_file():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            config = {}

        def walk(value: object, key: str | None = None) -> None:
            if isinstance(value, dict):
                for child_key, child_value in value.items():
                    walk(child_value, str(child_key))
            elif key in SENSITIVE_CONFIG_KEYS and isinstance(value, str):
                cleaned = value.strip()
                if len(cleaned) >= 5 and not cleaned.startswith("<"):
                    values.append((re.escape(cleaned), f"Local configured value ({key})"))

        walk(config)

    env = os.environ if environ is None else environ
    for item in env.get("FORTRESS_SECRETS_BLACKLIST", "").split(","):
        if len(item.strip()) >= 5:
            values.append((re.escape(item.strip()), "CI-provided sensitive value"))
    return values


def _patterns(root: Path, environ: dict[str, str] | None = None) -> list[tuple[re.Pattern[str], str]]:
    result = [(re.compile(pattern), description) for pattern, description in GENERIC_FORBIDDEN_PATTERNS]
    result.extend((re.compile(pattern), description) for pattern, description in _configured_values(root, environ))
    return result


def _is_public_ip(value: str) -> bool:
    if value in WHITELISTED_IPS:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def _scan_text(
    text: str,
    path: str,
    source: str,
    patterns: Sequence[tuple[re.Pattern[str], str]],
) -> list[Violation]:
    findings: list[Violation] = []
    seen: set[tuple[str, int, str]] = set()
    lines = text.splitlines() or [text]

    for line_number, line in enumerate(lines, 1):
        # Placeholder markers are safe examples, not a reason to skip a line.
        for pattern, description in patterns:
            if pattern.search(line):
                key = (path, line_number, description)
                if key not in seen:
                    seen.add(key)
                    findings.append(Violation(path, line_number, description, source))

        for ip in IP_PATTERN.findall(line):
            if _is_public_ip(ip):
                key = (path, line_number, "Non-whitelisted public IP")
                if key not in seen:
                    seen.add(key)
                    findings.append(Violation(path, line_number, "Non-whitelisted public IP", source))
    return findings


def _path_is_forbidden(path: str) -> bool:
    return any(re.search(pattern, path, re.IGNORECASE) for pattern in FORBIDDEN_FILE_PATTERNS)


class ScanFailure(RuntimeError):
    """Safe diagnostic for a scan that could not complete."""


def _git_output(root: Path, args: Sequence[str]) -> list[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ScanFailure("Git metadata could not be scanned") from error
    return result.stdout.splitlines()


def _tracked_paths(root: Path) -> list[str]:
    return _git_output(root, ["ls-files"])


def _history_object_ids(root: Path) -> list[str]:
    """Enumerate all local Git objects; output is metadata only."""

    try:
        result = subprocess.run(
            ["git", "cat-file", "--batch-all-objects", "--batch-check"],
            cwd=root,
            input="",
            check=True,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ScanFailure("Git objects could not be enumerated") from error
    object_ids: list[str] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] == "blob":
            object_ids.append(fields[0])
    return object_ids


def _iter_git_blobs(root: Path) -> Iterator[tuple[str, bytes]]:
    """Read blob contents through Git's batch protocol without echoing them."""

    object_ids = _history_object_ids(root)
    if not object_ids:
        return
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            cwd=root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert process.stdin is not None and process.stdout is not None
        for object_id in object_ids:
            # Interleave requests and responses. Sending every ID first can
            # deadlock once both pipe buffers fill in a larger repository.
            process.stdin.write((object_id + "\n").encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline()
            if not header:
                raise ScanFailure("Git blob stream ended early")
            fields = header.split()
            if len(fields) < 3 or fields[1] != b"blob":
                raise ScanFailure("Git blob protocol could not be verified")
            size = int(fields[2])
            content = process.stdout.read(size)
            process.stdout.read(1)  # batch protocol's trailing newline
            if len(content) != size:
                raise ScanFailure("Git blob content was truncated")
            yield object_id, content
        process.stdin.close()
        process.wait(timeout=30)
        if process.returncode:
            raise ScanFailure("Git blob reader failed")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if process is not None and process.poll() is None:
            process.kill()
        raise ScanFailure("Git blob scan could not complete") from error
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            if process.poll() is None:
                process.kill()
            process.wait()


def scan_repository(
    repository: str | os.PathLike[str] | None = None,
    *,
    include_history: bool = True,
    environ: dict[str, str] | None = None,
) -> list[Violation]:
    """Scan the complete worktree and local Git blobs, returning safe findings."""

    root = Path(repository or Path(__file__).resolve().parent).resolve()
    if not root.is_dir():
        return [Violation("[repository]", 0, "Repository directory unavailable", "scan")]
    patterns = _patterns(root, environ)
    violations: list[Violation] = []
    seen: set[tuple[str, int, str, str]] = set()

    def add_all(items: Iterable[Violation]) -> None:
        for item in items:
            key = (item.path, item.line, item.reason, item.source)
            if key not in seen:
                seen.add(key)
                violations.append(item)

    try:
        tracked = _tracked_paths(root)
    except ScanFailure:
        tracked = []
        if include_history or (root / '.git').exists():
            add_all([Violation("[Git metadata]", 0, "Git metadata unavailable; scan incomplete", "scan")])
    for path in tracked:
        if _path_is_forbidden(path):
            add_all([Violation(path, 0, "Sensitive file tracked by Git", "path")])

    # Walk the filesystem instead of git ls-files: ignored credentials and
    # generated artifacts must be inspected before they can be published.
    try:
        for path in _iter_worktree_files(root):
            relative = _relative_path(root, path)
            if _path_is_forbidden(relative):
                add_all([Violation(relative, 0, "Sensitive artifact present in worktree", "path")])
            try:
                text = path.read_bytes().decode("utf-8", errors="replace")
            except OSError:
                add_all([Violation(relative, 0, "Unable to read worktree file", "worktree")])
                continue
            add_all(_scan_text(text, relative, "worktree", patterns))
    except ScanFailure:
        add_all([Violation("[worktree]", 0, "Worktree traversal unavailable; scan incomplete", "scan")])

    if include_history:
        try:
            for object_id, content in _iter_git_blobs(root):
                text = content.decode("utf-8", errors="replace")
                # Only object metadata is printed, never matching content.
                add_all(_scan_text(text, f"git blob {object_id[:12]}", "git blob", patterns))
        except ScanFailure:
            add_all([Violation("[Git history]", 0, "Git history unavailable; scan incomplete", "scan")])

    return violations


def _print_report(violations: Sequence[Violation]) -> None:
    if not violations:
        print("[+] Privacy scan passed: no prohibited values found in the worktree or local Git blobs.")
        return
    print("[!] Privacy scan found prohibited content (matching values are redacted):")
    for finding in violations:
        location = finding.path if finding.line == 0 else f"{finding.path}:{finding.line}"
        print(f"  - {location} -> {finding.reason} [{finding.source}]")
    print(f"[!] Scan failed with {len(violations)} finding(s). No matching content was printed.")


def scan_files(repository: str | os.PathLike[str] | None = None) -> int:
    """Compatibility entry point used by local hooks and the GitHub workflow."""

    violations = scan_repository(repository)
    _print_report(violations)
    return 1 if violations else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan worktree and Git blobs without printing matches")
    parser.add_argument("--root", default=None, help="repository root (defaults to this file's directory)")
    parser.add_argument("--no-history", action="store_true", help="skip Git object scanning")
    args = parser.parse_args(argv)
    violations = scan_repository(args.root, include_history=not args.no_history)
    if args.no_history:
        print("[i] Git history intentionally skipped; this is a worktree-only scan.")
    _print_report(violations)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
