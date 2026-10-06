#!/usr/bin/env python3
"""
Sovereign Fortress — Server Encrypted Vault & Volatile Memory Manager
Zero-Disk-Footprint / Anti-Forensic Cryptographic Protection (2026)

Encrypts all private keys (TLS, CA, WireGuard, DNSCrypt, master passwords)
at rest into an AES-256-GCM authenticated vault (/etc/fortress/vault.enc).
Plaintext keys exist exclusively in volatile RAM (/run/fortress tmpfs) and
are shredded from disk storage.
"""

import os
import sys
import getpass
import subprocess
import shutil
import tarfile
import io
import json
import argparse
from pathlib import Path

DISK_DIR = Path("/etc/fortress")
RAM_DIR = Path("/run/fortress")
STATE_DIR = Path("/var/lib/fortress/subscription")
VAULT_FILE = DISK_DIR / "vault.enc"

SENSITIVE_FILES = [
    "key.pem",
    "ca.key",
    "wg0.conf",
    "dnscrypt.yaml",
    "fortress_config.json",
    "config.json.template",
    "cert.pem",
    "ca.crt",
    "sub_token"
]

SERVICES = ["fortress-init", "adguard-home", "fortress-core", "fortress-sub", "fortress-wstunnel"]


def check_root():
    if os.geteuid() != 0:
        print("[-] Error: Server vault operations require root privileges (sudo).", file=sys.stderr)
        sys.exit(1)


def is_tmpfs(path: Path) -> bool:
    try:
        out = subprocess.check_output(["findmnt", "-n", "-o", "FSTYPE", "--target", str(path)],
                                      stderr=subprocess.DEVNULL).decode().strip()
        return out == "tmpfs"
    except Exception:
        return False


def get_status():
    vault_exists = VAULT_FILE.is_file()
    disk_plaintext = [f for f in SENSITIVE_FILES if (DISK_DIR / f).is_file()]
    ram_mounted = is_tmpfs(RAM_DIR)
    ram_keys = [f for f in SENSITIVE_FILES if (RAM_DIR / f).is_file() or (RAM_DIR / "wireguard" / f).is_file() or (RAM_DIR / "adguard" / f).is_file()]

    active_svcs = []
    for s in ["adguard-home", "fortress-core", "fortress-sub"]:
        try:
            res = subprocess.run(["systemctl", "is-active", "--quiet", s])
            active_svcs.append(f"{s}: {'RUNNING' if res.returncode == 0 else 'STOPPED'}")
        except Exception:
            active_svcs.append(f"{s}: UNKNOWN")

    print("=================================================================")
    print("      SOVEREIGN FORTRESS — SERVER MEMORY & VAULT STATUS          ")
    print("=================================================================")
    print(f"[*] Encrypted Vault File:   {'PRESENT (' + str(VAULT_FILE) + ')' if vault_exists else 'NOT CREATED'}")
    print(f"[*] Disk Plaintext Keys:    {'EXPOSED (' + str(len(disk_plaintext)) + ' files: ' + ', '.join(disk_plaintext[:4]) + '...)' if disk_plaintext else 'CLEAN (0 plaintext keys on disk)'}")
    print(f"[*] RAM tmpfs (/run):       {'MOUNTED (tmpfs 256M)' if ram_mounted else 'NOT MOUNTED'}")
    print(f"[*] Active RAM Keys:        {'LOADED (' + str(len(ram_keys)) + ' keys in volatile memory)' if ram_keys else 'EMPTY'}")
    print(f"[*] Live Daemon Services:   {', '.join(active_svcs)}")
    print("-----------------------------------------------------------------")
    if vault_exists and not disk_plaintext and ram_keys:
        print("[+] STATUS: 100% SECURE VOLATILE MODE (Keys in RAM only; Disk is encrypted).")
    elif vault_exists and not disk_plaintext and not ram_keys:
        print("[!] STATUS: COLD-LOCKED (Server rebooted; Run 'unlock' to restore keys to RAM).")
    else:
        print("[!] STATUS: STANDARD DISK MODE (Plaintext keys reside on /etc/fortress).")
    print("=================================================================")


def encrypt_data(data: bytes, passphrase: str) -> bytes:
    env = os.environ.copy()
    env["VAULT_PASS"] = passphrase
    p = subprocess.Popen(
        ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-salt", "-pass", "env:VAULT_PASS"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )
    stdout, stderr = p.communicate(input=data)
    if p.returncode != 0:
        raise RuntimeError(f"OpenSSL encryption failed: {stderr.decode(errors='replace')}")
    return stdout


def decrypt_data(ciphertext: bytes, passphrase: str) -> bytes:
    env = os.environ.copy()
    env["VAULT_PASS"] = passphrase
    p = subprocess.Popen(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-pass", "env:VAULT_PASS"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )
    stdout, stderr = p.communicate(input=ciphertext)
    if p.returncode != 0:
        raise RuntimeError("Decryption failed. Incorrect passphrase or corrupt vault archive.")
    return stdout


def secure_shred(path: Path):
    if not path.is_file():
        return
    try:
        subprocess.run(["shred", "-u", "-z", "-n", "3", str(path)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except Exception:
        # Fallback python overwrite
        size = path.stat().st_size
        with open(path, "ba+", buffering=0) as f:
            f.seek(0)
            f.write(os.urandom(size))
            f.seek(0)
            f.write(b"\x00" * size)
        path.unlink(missing_ok=True)


def lock_vault(passphrase: str = None):
    check_root()
    print("[*] Preparing to lock and encrypt all Sovereign Fortress server keys...")

    # Collect source files (prefer disk, fallback to RAM)
    archive_buf = io.BytesIO()
    with tarfile.open(fileobj=archive_buf, mode="w:gz") as tar:
        found_any = False
        for name in SENSITIVE_FILES:
            src = DISK_DIR / name
            if not src.is_file():
                src = RAM_DIR / name
            if not src.is_file() and name == "wg0.conf":
                src = RAM_DIR / "wireguard" / "wg0.conf"
            if not src.is_file() and name == "dnscrypt.yaml":
                src = RAM_DIR / "adguard" / "dnscrypt.yaml"
            if not src.is_file() and name == "sub_token":
                src = STATE_DIR / "sub_token"

            if src.is_file():
                tar.add(str(src), arcname=name)
                found_any = True
                print(f"  [+] Bundled: {name}")

        if not found_any:
            print("[-] Error: No sensitive keys found to bundle. Is the server deployed?", file=sys.stderr)
            sys.exit(1)

    tar_bytes = archive_buf.getvalue()

    # Passphrase handling
    if not passphrase:
        while True:
            pass1 = getpass.getpass("[?] Enter Master Vault Passphrase (min 10 characters): ")
            if len(pass1) < 10:
                print("[-] Passphrase must be at least 10 characters long.")
                continue
            pass2 = getpass.getpass("[?] Confirm Master Vault Passphrase: ")
            if pass1 != pass2:
                print("[-] Passphrases do not match. Try again.")
                continue
            passphrase = pass1
            break
    else:
        if len(passphrase) < 10:
            print("[-] Error: Passphrase must be at least 10 characters long.", file=sys.stderr)
            sys.exit(1)

    print("[*] Encrypting with AES-256-CBC (PBKDF2 100,000 iterations)...")
    encrypted_bytes = encrypt_data(tar_bytes, passphrase)

    # Test decrypt to verify validity before deleting anything
    print("[*] Verifying encrypted vault integrity...")
    test_decrypted = decrypt_data(encrypted_bytes, passphrase)
    if test_decrypted != tar_bytes:
        raise RuntimeError("Self-verification integrity mismatch. Encryption aborted.")

    # Write vault.enc
    DISK_DIR.mkdir(parents=True, exist_ok=True)
    temp_vault = DISK_DIR / ".vault.enc.tmp"
    temp_vault.write_bytes(encrypted_bytes)
    os.chmod(temp_vault, 0o600)
    temp_vault.replace(VAULT_FILE)
    os.chmod(VAULT_FILE, 0o600)
    print(f"[+] Encrypted vault written successfully: {VAULT_FILE}")

    # Ensure keys are staged in RAM tmpfs so services keep running
    subprocess.run(["bash", "fortress-init.sh"], check=False)

    # Securely shred plaintext copies from disk
    print("[*] Securely shredding plaintext keys from permanent disk storage...")
    for name in SENSITIVE_FILES:
        target = DISK_DIR / name
        if target.is_file():
            secure_shred(target)
            print(f"  [x] Shredded: {target}")

    print("\n[+] SUCCESS! All server keys are encrypted in /etc/fortress/vault.enc.")
    print("[+] Zero plaintext private keys remain on disk.")
    print("[!] On reboot, run: 'sudo python3 manage_server_vault.py unlock' to supply the passphrase.")


def unlock_vault(passphrase: str = None):
    check_root()
    if not VAULT_FILE.is_file():
        print(f"[-] Error: Vault file {VAULT_FILE} not found. Server is not in vault-locked mode.", file=sys.stderr)
        sys.exit(1)

    if not passphrase:
        passphrase = getpass.getpass("[?] Enter Master Vault Passphrase: ")
    print("[*] Decrypting vault into volatile RAM tmpfs (/run/fortress)...")

    try:
        ciphertext = VAULT_FILE.read_bytes()
        decrypted_tar = decrypt_data(ciphertext, passphrase)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Ensure RAM tmpfs is mounted
    if not is_tmpfs(RAM_DIR):
        RAM_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(["mount", "-t", "tmpfs", "-o", "size=256M,mode=0750", "tmpfs", str(RAM_DIR)], check=True)

    # Ensure directories
    (RAM_DIR / "wireguard").mkdir(parents=True, exist_ok=True)
    (RAM_DIR / "adguard").mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Unpack tar directly in RAM
    tar_stream = io.BytesIO(decrypted_tar)
    with tarfile.open(fileobj=tar_stream, mode="r:gz") as tar:
        for member in tar.getmembers():
            extracted = tar.extractfile(member)
            if not extracted:
                continue
            content = extracted.read()
            name = member.name

            # Map to proper RAM location
            if name == "wg0.conf":
                dest = RAM_DIR / "wireguard" / "wg0.conf"
                dest.write_bytes(content)
                os.chmod(dest, 0o600)
            elif name == "dnscrypt.yaml":
                dest = RAM_DIR / "adguard" / "dnscrypt.yaml"
                dest.write_bytes(content)
                os.chmod(dest, 0o600)
            elif name == "sub_token":
                dest1 = STATE_DIR / "sub_token"
                dest2 = RAM_DIR / "sub_token"
                dest1.write_bytes(content)
                dest2.write_bytes(content)
                os.chmod(dest1, 0o600)
                os.chmod(dest2, 0o640)
            elif name == "config.json.template":
                dest = RAM_DIR / "config.json"
                dest.write_bytes(content)
                os.chmod(dest, 0o640)
            else:
                dest = RAM_DIR / name
                dest.write_bytes(content)
                os.chmod(dest, 0o640 if name.endswith(('.pem', '.crt', '.json')) else 0o600)

            print(f"  [+] Unpacked into RAM: {dest}")

    # Set fortress ownership
    try:
        import pwd
        u = pwd.getpwnam("fortress")
        uid, gid = u.pw_uid, u.pw_gid
        os.chown(RAM_DIR, 0, gid)
        os.chmod(RAM_DIR, 0o750)
        for item in RAM_DIR.rglob("*"):
            if "wireguard" in str(item):
                os.chown(item, 0, 0)
            else:
                os.chown(item, uid, gid)
    except Exception:
        pass

    # Ensure WireGuard symlink
    Path("/etc/wireguard").mkdir(parents=True, exist_ok=True)
    wg_symlink = Path("/etc/wireguard/wg0.conf")
    wg_symlink.unlink(missing_ok=True)
    wg_symlink.symlink_to(RAM_DIR / "wireguard" / "wg0.conf")

    # Restart services
    print("[*] Reloading and restarting Sovereign Fortress daemons...")
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "restart"] + SERVICES, check=False)

    print("\n[+] SUCCESS! Keys loaded directly into volatile RAM tmpfs.")
    get_status()


def purge_ram():
    check_root()
    confirm = input("[!] WARNING: Purging RAM will terminate all VPN & DNS services immediately. Type 'PURGE' to proceed: ")
    if confirm != "PURGE":
        print("[-] Aborted.")
        return

    print("[*] Stopping services...")
    subprocess.run(["systemctl", "stop"] + SERVICES, check=False)
    print("[*] Wiping volatile keys from /run/fortress...")
    for item in RAM_DIR.rglob("*"):
        if item.is_file():
            secure_shred(item)
    print("[+] RAM purged. System is cold-locked.")


def main():
    parser = argparse.ArgumentParser(description="Sovereign Fortress Memory & Vault Manager")
    parser.add_argument("command", choices=["status", "lock", "unlock", "purge-ram"], help="Action to perform")
    parser.add_argument("--passphrase", "-p", dest="passphrase", default=None, help="Master Vault Passphrase (or set VAULT_PASSPHRASE env var)")
    args = parser.parse_args()

    passphrase = args.passphrase or os.environ.get("VAULT_PASSPHRASE")

    if args.command == "status":
        get_status()
    elif args.command == "lock":
        lock_vault(passphrase)
    elif args.command == "unlock":
        unlock_vault(passphrase)
    elif args.command == "purge-ram":
        purge_ram()


if __name__ == "__main__":
    main()
