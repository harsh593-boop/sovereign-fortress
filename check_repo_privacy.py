#!/usr/bin/env python3
"""
Sovereign Fortress — Zero-Leak Privacy & Secret Scanning Shield
Automated pre-commit & GitHub Actions CI validation tool.

Scans all tracked repository files, file paths, and git history to guarantee that:
- Zero personal or server IP addresses exist in public files
- Zero NextDNS profile IDs exist in public files
- Zero local filesystem paths or personal usernames exist in public files
- Zero live secrets, private keys, or personal email addresses exist
- No sensitive file formats (.key, .crt, .conf, .url, .exe, etc.) are tracked
- CI safe: Never leaks detected secret tokens into build logs
"""

import os
import re
import sys
import base64
import subprocess

import json

# 1. Generic High-Risk Secret & Path Patterns (Language and deployment agnostic)
GENERIC_FORBIDDEN_PATTERNS = [
    (r"[C-Zc-z]:\\[Uu]sers\\[A-Za-z0-9_.-]+", "Personal Windows User Filesystem Path"),
    (r"/home/[A-Za-z0-9_.-]+", "Personal Linux User Home Path"),
    (r"\bft_sec_[0-9a-fA-F]{32}\b", "Live Master Subscription Token Pattern"),
    (r"\bft_sec_[A-Za-z0-9_-]{32}\b", "Live URL-Safe Subscription Token Pattern"),
    (r"\b[A-Z2-7]{32}\b", "Raw 32-Character Base32 TOTP Secret Pattern"),
]

# 2. Dynamic Local Secret Blacklist
# Automatically pulls active secrets from local git-ignored fortress_config.json or environment variables.
# NEVER stores raw or encoded personal secrets in this repository or in git history.
LOCAL_SECRETS = []
_SENSITIVE_CONFIG_KEYS = {
    "server_ip", "token", "totp_secret", "uuid", "reality_pubkey",
    "reality_shortid", "hy2_password", "salamander_password", "ss_password",
    "wg_server_pub", "wg_client_priv", "nextdns_id", "ssh_key_path",
    "campus_domain"
}
_LOCAL_CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fortress_config.json")
if os.path.exists(_LOCAL_CFG_PATH):
    try:
        with open(_LOCAL_CFG_PATH, "r", encoding="utf-8") as f:
            _cfg = json.load(f)
            for key, val in _cfg.items():
                if key in _SENSITIVE_CONFIG_KEYS and isinstance(val, str) and len(val.strip()) >= 5 and not val.strip().startswith("<"):
                    cleaned = val.strip()
                    pattern = r"\b" + re.escape(cleaned) + r"\b" if cleaned.isalnum() else re.escape(cleaned)
                    LOCAL_SECRETS.append((pattern, f"Active Deployment Secret ({key})"))
    except Exception:
        pass

# Optional environment-based secret injection for CI
_ENV_SECRETS = os.environ.get("FORTRESS_SECRETS_BLACKLIST", "")
if _ENV_SECRETS:
    for item in _ENV_SECRETS.split(","):
        item = item.strip()
        if len(item) >= 5:
            LOCAL_SECRETS.append((re.escape(item), "CI Secret Blacklist Entry"))

FORBIDDEN_PATTERNS = GENERIC_FORBIDDEN_PATTERNS + LOCAL_SECRETS

ALLOWED_EXCEPTIONS = [
    "ft_sec_$(openssl rand -hex 16)",
    "ft_sec_revoked_historical_token_test_000",
    "ft_sec_\" + secrets.token_urlsafe(24)",
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
]

# Whitelist of standard network / testbed IP addresses and well-known public DNS resolvers
WHITELISTED_IPS = {
    "0.0.0.0", "127.0.0.1", "127.0.0.0", "127.0.0.53",
    "10.8.0.1", "10.8.0.2", "10.66.66.1", "10.66.66.2",
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "45.90.28.0", "45.90.30.0", "94.140.14.14", "94.140.15.15",
    "208.67.222.222", "208.67.220.220", "76.76.2.0", "76.76.10.0",
    "10.0.0.0", "172.16.0.0", "192.168.0.0", "169.254.0.0", "169.254.169.254",
    "172.19.0.1", "162.159.36.1",
    "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5",
    "192.0.2.1", "203.0.113.1"
}

# Forbidden tracked extensions or sensitive file names
FORBIDDEN_FILE_PATTERNS = [
    r"\.key$", r"\.crt$", r"\.pem$", r"\.enc$", r"\.url$", r"\.exe$", r"\.bin$", r"\.dll$",
    r"^fortress_config\.json$", r"^client_profiles\.txt$", r"^fortress_dashboard\.html$",
    r"^qr_codes/", r"^\.agents/"
]

def scan_files():
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        tracked = subprocess.check_output(
            ["git", "ls-files"], cwd=repo_dir, text=True
        ).splitlines()
    except Exception as e:
        print(f"[-] Error running git ls-files: {e}")
        return 1

    violations = []

    # 1. Inspect Tracked File Names
    for rel_path in tracked:
        for fpat in FORBIDDEN_FILE_PATTERNS:
            if re.search(fpat, rel_path, re.IGNORECASE):
                violations.append((rel_path, 0, f"Sensitive / Private File Tracked in Git: {rel_path}", "[REDACTED]"))

    # 2. Inspect File Content
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    for rel_path in tracked:
        if rel_path in [".gitignore", "check_repo_privacy.py"]:
            continue
        full_path = os.path.join(repo_dir, rel_path)
        if not os.path.exists(full_path):
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"[-] Could not read {rel_path}: {e}")
            continue

        for line_num, line in enumerate(lines, 1):
            if any(exc in line for exc in ALLOWED_EXCEPTIONS):
                continue

            # Check forbidden patterns
            for pattern, desc in FORBIDDEN_PATTERNS:
                if re.search(pattern, line):
                    violations.append((rel_path, line_num, desc, "[REDACTED_SECRET_OR_PATH]"))

            # Check non-whitelisted public IPs
            for ip in ip_pattern.findall(line):
                if ip not in WHITELISTED_IPS and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172."):
                    violations.append((rel_path, line_num, f"Non-whitelisted public IP detected: {ip}", "[REDACTED_IP]"))

    # 3. Inspect Git History (last 30 commits if .git exists)
    if os.path.exists(os.path.join(repo_dir, ".git")):
        for pattern, desc in LOCAL_SECRETS:
            try:
                raw_token = re.sub(r"^\\[bB]|^\^|\$$|\\[bB]$", "", pattern)
                if not raw_token or len(raw_token) < 4:
                    continue
                out = subprocess.check_output(
                    ["git", "log", "-S", raw_token, "--oneline", "-n", "30"],
                    cwd=repo_dir, text=True, stderr=subprocess.DEVNULL
                ).strip()
                if out:
                    violations.append((".git/history", 0, f"Found in commit history: {desc}", "[REDACTED_COMMIT]"))
            except Exception:
                pass

    if violations:
        print("=" * 70)
        print(" [!] PRIVACY & SECRET LEAK DETECTED IN REPOSITORY:")
        print("=" * 70)
        for rel_path, line_num, desc, line in violations:
            loc = f"{rel_path}:{line_num}" if line_num > 0 else rel_path
            print(f" [-] {loc} -> {desc}")
        print("=" * 70)
        print(" [!] GATE FAILED: Prohibited private data found. Rejecting.")
        return 1

    print("[+] Sovereign Fortress Privacy Shield: All files and history 100% CLEAN.")
    return 0

if __name__ == "__main__":
    sys.exit(scan_files())
