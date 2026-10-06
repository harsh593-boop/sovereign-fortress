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
LUKS_IMAGE = Path("/var/fortress.luks")
LUKS_NAME = "fortress-secure"
LUKS_DEV = Path(f"/dev/mapper/{LUKS_NAME}")
LUKS_MOUNT = Path("/var/fortress-storage")

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


def is_mounted(path: Path) -> bool:
    try:
        out = subprocess.check_output(["findmnt", "-n", "--target", str(path)],
                                      stderr=subprocess.DEVNULL).decode().strip()
        return bool(out)
    except Exception:
        return False


def is_luks_active() -> bool:
    try:
        res = subprocess.run(["cryptsetup", "status", LUKS_NAME],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return res.returncode == 0
    except Exception:
        return False


def get_status():
    luks_exists = LUKS_IMAGE.is_file()
    luks_active = is_luks_active()
    luks_mounted = is_mounted(LUKS_MOUNT)
    luks_cipher = "None"
    luks_size = "0 GB"
    if luks_exists:
        luks_size = f"{LUKS_IMAGE.stat().st_size / (1024**3):.1f} GB"
    if luks_active:
        try:
            c_info = subprocess.check_output(["cryptsetup", "status", LUKS_NAME], stderr=subprocess.DEVNULL).decode()
            for line in c_info.splitlines():
                if "cipher:" in line.lower():
                    luks_cipher = line.split(":", 1)[1].strip()
                elif "keysize:" in line.lower():
                    luks_cipher += f" ({line.split(':', 1)[1].strip()} bits)"
        except Exception:
            luks_cipher = "aes-xts-plain64 (512 bits)"

    vault_exists = VAULT_FILE.is_file() or (luks_mounted and (LUKS_MOUNT / "etc" / "vault.enc").is_file())
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
    print("      SOVEREIGN FORTRESS — SERVER MEMORY & STORAGE STATUS        ")
    print("=================================================================")
    if luks_exists:
        print(f"[*] LUKS2 Volume Image:     PRESENT ({LUKS_IMAGE}, {luks_size})")
        print(f"[*] LUKS2 Device Status:    {'ACTIVE (' + str(LUKS_DEV) + ', Cipher: ' + luks_cipher + ')' if luks_active else 'LOCKED / INACTIVE'}")
        print(f"[*] LUKS2 Mount Point:      {'MOUNTED (' + str(LUKS_MOUNT) + ')' if luks_mounted else 'UNMOUNTED'}")
    else:
        print(f"[*] LUKS2 Volume Image:     NOT INITIALIZED (Run 'setup-luks' to provision)")
    print(f"[*] Encrypted Vault File:   {'PRESENT' if vault_exists else 'NOT CREATED'}")
    print(f"[*] Disk Plaintext Keys:    {'EXPOSED (' + str(len(disk_plaintext)) + ' files: ' + ', '.join(disk_plaintext[:4]) + '...)' if disk_plaintext else 'CLEAN (0 plaintext keys on disk)'}")
    print(f"[*] RAM tmpfs (/run):       {'MOUNTED (tmpfs 256M)' if ram_mounted else 'NOT MOUNTED'}")
    print(f"[*] Active RAM Keys:        {'LOADED (' + str(len(ram_keys)) + ' keys in volatile memory)' if ram_keys else 'EMPTY'}")
    print(f"[*] Live Daemon Services:   {', '.join(active_svcs)}")
    print("-----------------------------------------------------------------")
    if luks_active and not disk_plaintext and ram_keys:
        print("[+] STATUS: MAXIMUM SOVEREIGN PROTECTION (LUKS2 512-bit + Volatile RAM Only).")
    elif vault_exists and not disk_plaintext and ram_keys:
        print("[+] STATUS: 100% SECURE VOLATILE MODE (Keys in RAM only; Disk is encrypted).")
    elif not ram_keys:
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
def setup_luks(passphrase: str = None, size_gb: int = 4):
    check_root()
    if LUKS_IMAGE.is_file():
        print(f"[*] LUKS image already exists: {LUKS_IMAGE}")
        if not is_luks_active():
            if not passphrase:
                passphrase = getpass.getpass("[?] Enter Master LUKS Passphrase: ")
            p = subprocess.Popen(
                [
                    "cryptsetup", "open",
                    "--type", "luks2",
                    str(LUKS_IMAGE),
                    LUKS_NAME,
                    "-"
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = p.communicate(input=passphrase.encode("utf-8"))
            if p.returncode != 0:
                raise RuntimeError(f"cryptsetup open failed: {stderr.decode(errors='replace')}")

        # Check if ext4 already exists
        needs_format = True
        try:
            blkid_out = subprocess.check_output(["blkid", str(LUKS_DEV)], stderr=subprocess.DEVNULL).decode()
            if "ext4" in blkid_out:
                needs_format = False
        except Exception:
            needs_format = True

        if needs_format:
            print(f"[*] Creating ext4 filesystem on {LUKS_DEV}...")
            subprocess.run(["mkfs.ext4", "-q", "-L", "fortress_crypt", str(LUKS_DEV)], check=True)

        if not is_mounted(LUKS_MOUNT):
            LUKS_MOUNT.mkdir(parents=True, exist_ok=True)
            os.chmod(LUKS_MOUNT, 0o700)
            print(f"[*] Mounting {LUKS_DEV} at {LUKS_MOUNT}...")
            subprocess.run(["mount", str(LUKS_DEV), str(LUKS_MOUNT)], check=True)

        (LUKS_MOUNT / "adguard").mkdir(parents=True, exist_ok=True)
        (LUKS_MOUNT / "backups").mkdir(parents=True, exist_ok=True)
        (LUKS_MOUNT / "etc").mkdir(parents=True, exist_ok=True)
        if VAULT_FILE.is_file():
            shutil.copy2(VAULT_FILE, LUKS_MOUNT / "etc" / "vault.enc")
        print(f"[+] LUKS2 storage initialized and mounted at {LUKS_MOUNT}.")
        get_status()
        return

    if not passphrase:
        while True:
            pass1 = getpass.getpass("[?] Enter Master LUKS Passphrase (min 10 characters): ")
            if len(pass1) < 10:
                print("[-] Passphrase must be at least 10 characters long.")
                continue
            pass2 = getpass.getpass("[?] Confirm Master LUKS Passphrase: ")
            if pass1 != pass2:
                print("[-] Passphrases do not match. Try again.")
                continue
            passphrase = pass1
            break
    else:
        if len(passphrase) < 10:
            print("[-] Error: Passphrase must be at least 10 characters long.", file=sys.stderr)
            sys.exit(1)

    print(f"[*] Allocating {size_gb}GB container file at {LUKS_IMAGE}...")
    subprocess.run(["fallocate", "-l", f"{size_gb}G", str(LUKS_IMAGE)], check=True)
    os.chmod(LUKS_IMAGE, 0o600)

    print("[*] Formatting LUKS2 volume (AES-XTS-Plain64 512-bit, PBKDF Argon2id)...")
    p = subprocess.Popen(
        [
            "cryptsetup", "luksFormat",
            "--type", "luks2",
            "--cipher", "aes-xts-plain64",
            "--key-size", "512",
            "--hash", "sha512",
            "--pbkdf", "argon2id",
            "--batch-mode",
            str(LUKS_IMAGE),
            "-"
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = p.communicate(input=passphrase.encode("utf-8"))
    if p.returncode != 0:
        LUKS_IMAGE.unlink(missing_ok=True)
        raise RuntimeError(f"cryptsetup luksFormat failed: {stderr.decode(errors='replace')}")

    print("[+] LUKS2 container formatted successfully.")
    print(f"[*] Opening LUKS2 container {LUKS_IMAGE} -> {LUKS_NAME}...")
    p_open = subprocess.Popen(
        [
            "cryptsetup", "open",
            "--type", "luks2",
            str(LUKS_IMAGE),
            LUKS_NAME,
            "-"
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = p_open.communicate(input=passphrase.encode("utf-8"))
    if p_open.returncode != 0:
        raise RuntimeError(f"cryptsetup open failed: {stderr.decode(errors='replace')}")

    print(f"[*] Creating ext4 filesystem on {LUKS_DEV}...")
    subprocess.run(["mkfs.ext4", "-q", "-L", "fortress_crypt", str(LUKS_DEV)], check=True)

    LUKS_MOUNT.mkdir(parents=True, exist_ok=True)
    os.chmod(LUKS_MOUNT, 0o700)
    print(f"[*] Mounting {LUKS_DEV} at {LUKS_MOUNT}...")
    subprocess.run(["mount", str(LUKS_DEV), str(LUKS_MOUNT)], check=True)

    (LUKS_MOUNT / "adguard").mkdir(parents=True, exist_ok=True)
    (LUKS_MOUNT / "backups").mkdir(parents=True, exist_ok=True)
    (LUKS_MOUNT / "etc").mkdir(parents=True, exist_ok=True)
    if VAULT_FILE.is_file():
        shutil.copy2(VAULT_FILE, LUKS_MOUNT / "etc" / "vault.enc")
    print(f"[+] LUKS2 storage initialized and mounted at {LUKS_MOUNT}.")
    get_status()


def open_luks(passphrase: str = None):
    check_root()
    if not LUKS_IMAGE.is_file():
        print(f"[-] LUKS image not found: {LUKS_IMAGE}", file=sys.stderr)
        return False

    if is_luks_active():
        print(f"[*] LUKS device is already active at {LUKS_DEV}")
    else:
        if not passphrase:
            passphrase = getpass.getpass("[?] Enter Master LUKS Passphrase: ")
        print(f"[*] Opening LUKS2 container {LUKS_IMAGE} -> {LUKS_NAME}...")
        p = subprocess.Popen(
            [
                "cryptsetup", "open",
                "--type", "luks2",
                str(LUKS_IMAGE),
                LUKS_NAME,
                "-"
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate(input=passphrase.encode("utf-8"))
        if p.returncode != 0:
            raise RuntimeError(f"cryptsetup open failed: {stderr.decode(errors='replace')}")
        print(f"[+] LUKS2 device opened at {LUKS_DEV}.")

    if not is_mounted(LUKS_MOUNT):
        try:
            blkid_out = subprocess.check_output(["blkid", str(LUKS_DEV)], stderr=subprocess.DEVNULL).decode()
            if "ext4" in blkid_out:
                LUKS_MOUNT.mkdir(parents=True, exist_ok=True)
                os.chmod(LUKS_MOUNT, 0o700)
                print(f"[*] Mounting {LUKS_DEV} at {LUKS_MOUNT}...")
                subprocess.run(["mount", str(LUKS_DEV), str(LUKS_MOUNT)], check=True)
                print(f"[+] Mounted at {LUKS_MOUNT}.")
        except Exception:
            pass
    return True


def close_luks():
    check_root()
    if is_mounted(LUKS_MOUNT):
        print(f"[*] Unmounting {LUKS_MOUNT}...")
        subprocess.run(["umount", str(LUKS_MOUNT)], check=False)
    if is_luks_active():
        print(f"[*] Closing LUKS device {LUKS_NAME}...")
        subprocess.run(["cryptsetup", "close", LUKS_NAME], check=False)
        print(f"[+] LUKS device {LUKS_NAME} closed and locked.")


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
    if not passphrase:
        passphrase = getpass.getpass("[?] Enter Master Passphrase: ")

    # Open LUKS container if present
    if LUKS_IMAGE.is_file():
        open_luks(passphrase)

    vault_path = VAULT_FILE
    if not vault_path.is_file() and is_mounted(LUKS_MOUNT) and (LUKS_MOUNT / "etc" / "vault.enc").is_file():
        vault_path = LUKS_MOUNT / "etc" / "vault.enc"

    if not vault_path.is_file():
        print(f"[-] Error: Vault file {VAULT_FILE} not found. Server is not in vault-locked mode.", file=sys.stderr)
        sys.exit(1)

    print("[*] Decrypting vault into volatile RAM tmpfs (/run/fortress)...")

    try:
        ciphertext = vault_path.read_bytes()
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


def purge_ram(force: bool = False):
    check_root()
    if not force:
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

    if LUKS_IMAGE.is_file():
        close_luks()

    print("[+] RAM purged. System is cold-locked.")


def main():
    parser = argparse.ArgumentParser(description="Sovereign Fortress Memory & Storage Manager")
    parser.add_argument("command", choices=["status", "lock", "unlock", "purge-ram", "setup-luks", "open-luks", "close-luks"], help="Action to perform")
    parser.add_argument("--passphrase", "-p", dest="passphrase", default=None, help="Master Passphrase (or set VAULT_PASSPHRASE env var)")
    parser.add_argument("--size", "-s", dest="size", type=int, default=4, help="Size of LUKS container in GB (default: 4)")
    parser.add_argument("--force", "-f", action="store_true", help="Force action without interactive confirmation")
    args = parser.parse_args()

    passphrase = args.passphrase or os.environ.get("VAULT_PASSPHRASE")

    if args.command == "status":
        get_status()
    elif args.command == "lock":
        lock_vault(passphrase)
    elif args.command == "unlock":
        unlock_vault(passphrase)
    elif args.command == "purge-ram":
        purge_ram(args.force)
    elif args.command == "setup-luks":
        setup_luks(passphrase, args.size)
    elif args.command == "open-luks":
        open_luks(passphrase)
    elif args.command == "close-luks":
        close_luks()


if __name__ == "__main__":
    main()
