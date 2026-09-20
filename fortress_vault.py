"""
Sovereign Fortress — Windows DPAPI Client Key & Config Vault (2026)
Cryptographically protects keys and configs at rest using Windows DPAPI.
"""

import os
import sys
import glob
import ctypes
from ctypes import wintypes
import secrets
import hashlib

class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

def get_vault_entropy(custom_pass: str = None) -> bytes:
    if custom_pass:
        return hashlib.sha256(custom_pass.encode("utf-8")).digest()
    user = os.environ.get("USERNAME", "DefaultUser")
    comp = os.environ.get("COMPUTERNAME", "DefaultHost")
    seed = f"{user}:{comp}:SovereignFortressVault2026"
    return hashlib.sha256(seed.encode("utf-8")).digest()

def dpapi_protect(data: bytes, entropy: bytes = None, description: str = "SovereignFortressKey") -> bytes:
    if entropy is None:
        entropy = get_vault_entropy()
    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    ent_blob = DATA_BLOB(len(entropy), ctypes.cast(ctypes.create_string_buffer(entropy, len(entropy)), ctypes.POINTER(ctypes.c_byte)))
    # CryptProtectData with current user scope and secondary entropy
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(in_blob), description, ctypes.byref(ent_blob), None, None, 0, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    buf = (ctypes.c_byte * out_blob.cbData)()
    ctypes.memmove(buf, out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return bytes(buf)

def dpapi_unprotect(data: bytes, entropy: bytes = None) -> bytes:
    if entropy is None:
        entropy = get_vault_entropy()
    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    ent_blob = DATA_BLOB(len(entropy), ctypes.cast(ctypes.create_string_buffer(entropy, len(entropy)), ctypes.POINTER(ctypes.c_byte)))
    # 1. Try with secondary entropy
    if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, ctypes.byref(ent_blob), None, None, 0, ctypes.byref(out_blob)):
        buf = (ctypes.c_byte * out_blob.cbData)()
        ctypes.memmove(buf, out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return bytes(buf)
    # 2. Backwards-compatible fallback with null entropy
    if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        buf = (ctypes.c_byte * out_blob.cbData)()
        ctypes.memmove(buf, out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return bytes(buf)
    raise ctypes.WinError()

def get_target_files():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "fortress-wireguard.conf"),
        os.path.join(base_dir, "fortress-wireguard-tcp.conf"),
        os.path.join(base_dir, "client_profiles.txt"),
        os.path.join(base_dir, "fortress_config.json"),
        os.path.join(base_dir, "fortress-full-tunnel.json"),
        os.path.join(base_dir, "fortress-traffic-only.json")
    ]
    # Dynamically find ssh keys in Downloads
    user_home = os.path.expanduser("~")
    downloads_dir = os.path.join(user_home, "Downloads")
    if os.path.exists(downloads_dir):
        for key_file in glob.glob(os.path.join(downloads_dir, "ssh-key-*.key*")):
            if not key_file.endswith(".enc"):
                candidates.append(key_file)
            elif key_file.endswith(".enc"):
                base_name = key_file[:-4]
                if base_name not in candidates:
                    candidates.append(base_name)
    return list(dict.fromkeys(candidates))

def secure_shred(file_path: str):
    if not os.path.exists(file_path):
        return
    try:
        size = os.path.getsize(file_path)
        if size > 0:
            with open(file_path, "wb") as f:
                # Pass 1: Cryptographic random bytes
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
            with open(file_path, "wb") as f:
                # Pass 2: Inverted 0xFF bytes
                f.write(b"\xff" * size)
                f.flush()
                os.fsync(f.fileno())
            with open(file_path, "wb") as f:
                # Pass 3: Zero bytes
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
        os.remove(file_path)
        print(f" [X] Multi-pass overwritten and removed: {os.path.basename(file_path)}")
    except Exception as e:
        print(f" [-] Error shredding {file_path}: {e}")

def lock_vault():
    print("=" * 60)
    print("   LOCKING SOVEREIGN FORTRESS VAULT (WINDOWS DPAPI)   ")
    print("=" * 60)
    print("[*] Encrypting sensitive configuration files and private keys at rest...")
    count = 0
    for path in get_target_files():
        enc_path = path + ".enc"
        if os.path.exists(path):
            with open(path, "rb") as f:
                raw = f.read()
            enc = dpapi_protect(raw)
            with open(enc_path, "wb") as f:
                f.write(enc)
            secure_shred(path)
            print(f" [+] Encrypted and wiped: {os.path.basename(path)} -> {os.path.basename(enc_path)}")
            count += 1
        elif os.path.exists(enc_path):
            print(f" [=] Already locked: {os.path.basename(enc_path)}")
    print(f"\n[OK] Vault Locked! {count} file(s) encrypted with Windows user-bound DPAPI (CryptProtectData).")

def unlock_vault():
    print("=" * 60)
    print("   UNLOCKING SOVEREIGN FORTRESS VAULT (WINDOWS DPAPI)   ")
    print("=" * 60)
    print("[*] Decrypting sensitive configuration files for active session...")
    count = 0
    for path in get_target_files():
        enc_path = path + ".enc"
        if os.path.exists(enc_path):
            with open(enc_path, "rb") as f:
                enc = f.read()
            try:
                dec = dpapi_unprotect(enc)
                with open(path, "wb") as f:
                    f.write(dec)
                os.remove(enc_path)
                print(f" [+] Decrypted and restored: {os.path.basename(path)}")
                count += 1
            except Exception as e:
                print(f" [-] Failed to decrypt {os.path.basename(enc_path)}: {e}")
        elif os.path.exists(path):
            print(f" [=] Already unlocked: {os.path.basename(path)}")
    print(f"\n[OK] Vault Unlocked! {count} file(s) restored into active workspace for VPN client operation.\nTip: Lock vault when VPN session is complete to prevent plaintext storage.")

def panic_shred_local():
    print("=" * 60)
    print("   SOVEREIGN FORTRESS: LOCAL CLIENT EMERGENCY PANIC   ")
    print("=" * 60)
    print("[!] WARNING: This will permanently overwrite and delete all VPN configurations,")
    print("    private keys, QR codes, and SSH credentials from this computer.")
    confirm = input("Type 'VAPORIZE' to proceed: ").strip()
    if confirm != "VAPORIZE":
        print("[-] Panic aborted. No files were touched.")
        return

    all_files = []
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for base in get_target_files():
        all_files.append(base)
        all_files.append(base + ".enc")
    
    qr_dir = os.path.join(base_dir, "qr_codes")
    if os.path.exists(qr_dir):
        for fname in os.listdir(qr_dir):
            all_files.append(os.path.join(qr_dir, fname))

    print("\n[*] Commencing Multi-Pass Overwrite & Cryptographic Key Erasure...")
    for f in all_files:
        secure_shred(f)
    print("\n[OK] CREDENTIAL ERASURE COMPLETE. All local configurations and keys overwritten and removed.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fortress_vault.py [lock|unlock|shred]")
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    if cmd == "lock":
        lock_vault()
    elif cmd == "unlock":
        unlock_vault()
    elif cmd == "shred":
        panic_shred_local()
    else:
        print(f"[-] Unknown command: {cmd}")
        sys.exit(1)
