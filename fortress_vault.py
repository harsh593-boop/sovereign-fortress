"""
Sovereign Fortress — Windows DPAPI Client Key & Config Vault (2026)
Cryptographically protects keys and configs at rest using Windows DPAPI.
Deletion/overwrite cannot guarantee erasure on SSDs, snapshots, or backups.
"""

import os
import sys
import glob
import ctypes
from ctypes import wintypes
import secrets
import hashlib
import tempfile


class DATA_BLOB(ctypes.Structure):
    # DWORD is always 32-bit, including on 64-bit Windows.
    _fields_ = [('cbData', ctypes.c_uint32),
                ('pbData', ctypes.POINTER(ctypes.c_ubyte))]


def get_vault_entropy(custom_pass: str = None) -> bytes:
    if custom_pass:
        return hashlib.sha256(custom_pass.encode("utf-8")).digest()
    user = os.environ.get("USERNAME", "DefaultUser")
    comp = os.environ.get("COMPUTERNAME", "DefaultHost")
    seed = f"{user}:{comp}:SovereignFortressVault2026"
    return hashlib.sha256(seed.encode("utf-8")).digest()


def _dpapi_functions():
    if os.name != "nt":
        raise OSError("Windows DPAPI is available only on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    blob_ptr = ctypes.POINTER(DATA_BLOB)
    protect = crypt32.CryptProtectData
    protect.argtypes = [blob_ptr, wintypes.LPCWSTR, blob_ptr, ctypes.c_void_p,
                        ctypes.c_void_p, wintypes.DWORD, blob_ptr]
    protect.restype = wintypes.BOOL
    unprotect = crypt32.CryptUnprotectData
    unprotect.argtypes = [blob_ptr, ctypes.POINTER(wintypes.LPWSTR), blob_ptr,
                          ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob_ptr]
    unprotect.restype = wintypes.BOOL
    # Without these declarations LocalFree truncates pointers on Win64.
    free = kernel32.LocalFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p
    return protect, unprotect, free


def _make_blob(data):
    buffer = ctypes.create_string_buffer(data, max(1, len(data)))
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _dpapi_transform(data, entropy, description=None, decrypt=False,
                     allow_legacy=False):
    protect, unprotect, free = _dpapi_functions()
    # Retain the input buffers for the entire native call.
    in_blob, in_buffer = _make_blob(data)
    ent_blob, ent_buffer = _make_blob(entropy)
    attempts = [ctypes.byref(ent_blob)]
    if decrypt and allow_legacy:
        attempts.append(None)
    for entropy_ptr in attempts:
        out_blob = DATA_BLOB()
        try:
            func = unprotect if decrypt else protect
            ok = func(ctypes.byref(in_blob), None if decrypt else description,
                      entropy_ptr, None, None, 0x1, ctypes.byref(out_blob))
            # CRYPTPROTECT_UI_FORBIDDEN, current-user scope (not machine scope).
            if ok:
                if not out_blob.pbData and out_blob.cbData:
                    raise OSError("DPAPI returned an invalid output buffer")
                return ctypes.string_at(out_blob.pbData, out_blob.cbData)
            error = ctypes.get_last_error()
        finally:
            if out_blob.pbData:
                free(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
    raise ctypes.WinError(error)


def dpapi_protect(data: bytes, entropy: bytes = None,
                  description: str = "SovereignFortressKey") -> bytes:
    if entropy is None:
        entropy = get_vault_entropy()
    return _dpapi_transform(data, entropy, description=description)


def dpapi_unprotect(data: bytes, entropy: bytes = None) -> bytes:
    # Legacy no-entropy fallback applies only to the default vault format.
    allow_legacy = entropy is None
    if entropy is None:
        entropy = get_vault_entropy()
    return _dpapi_transform(data, entropy, decrypt=True, allow_legacy=allow_legacy)


def get_target_files():
    from client_paths import client_directory, client_config_path
    base_dir = str(client_directory())
    candidates = [str(client_config_path())] + [os.path.join(base_dir, name) for name in (
        "fortress-wireguard.conf", "fortress-wireguard-tcp.conf", "client_profiles.txt",
        "fortress-full-tunnel.json", "fortress-traffic-only.json")]
    # Never enumerate unrelated SSH keys in Downloads or shred them implicitly.
    explicit_key = os.environ.get('FORTRESS_VAULT_SSH_KEY')
    if explicit_key:
        candidates.append(os.path.abspath(os.path.expanduser(explicit_key)))
    return list(dict.fromkeys(candidates))


def _publish_new(path, data):
    """Flush a complete sibling file, then publish atomically without replacement."""
    fd, temp_path = tempfile.mkstemp(prefix=".fortress-vault-", suffix=".tmp",
                                     dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        with open(temp_path, "rb") as stream:
            if stream.read() != data:
                raise OSError("Vault output verification failed")
        # Same-volume hard link is atomic and fails if a destination appeared.
        # Unsupported filesystems fail safely; never fall back to an overwrite.
        os.link(temp_path, path)
    finally:
        os.unlink(temp_path)


def secure_shred(file_path: str):
    """Best-effort logical overwrite/delete, NOT guaranteed physical erasure."""
    if not os.path.lexists(file_path):
        return
    if os.path.islink(file_path) or not os.path.isfile(file_path):
        raise OSError("Refusing to overwrite a link or non-regular file")
    with open(file_path, "r+b") as stream:
        size = os.fstat(stream.fileno()).st_size
        for pattern in (None, b"\xff", b"\x00"):
            stream.seek(0)
            remaining = size
            while remaining:
                amount = min(remaining, 1024 * 1024)
                chunk = secrets.token_bytes(amount) if pattern is None else pattern * amount
                stream.write(chunk)
                remaining -= amount
            stream.flush()
            os.fsync(stream.fileno())
    os.remove(file_path)
    print(f" [X] Best-effort overwrite and removal: {os.path.basename(file_path)}")


def _convert_vault(lock):
    operation = "lock" if lock else "unlock"
    count = failures = 0
    for path in get_target_files():
        enc_path = path + ".enc"
        source, destination = (path, enc_path) if lock else (enc_path, path)
        try:
            if not os.path.lexists(source):
                continue
            if os.path.islink(source) or not os.path.isfile(source):
                raise OSError("Refusing a link or non-regular source")
            if os.path.lexists(destination):
                raise FileExistsError("Both plaintext and encrypted files exist; resolve manually")
            with open(source, "rb") as stream:
                source_stat = os.fstat(stream.fileno())
                data = stream.read()
            converted = dpapi_protect(data) if lock else dpapi_unprotect(data)
            if lock and (not converted or dpapi_unprotect(converted) != data):
                raise OSError("DPAPI round-trip verification failed")
            _publish_new(destination, converted)
            # Never overwrite the authoritative source as part of conversion.
            # Detect concurrent edits/replacements before deleting that source.
            if os.path.islink(source):
                raise OSError("Vault source was replaced with a link")
            with open(source, "rb") as stream:
                current_stat = os.fstat(stream.fileno())
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if (any(getattr(source_stat, field) != getattr(current_stat, field)
                        for field in fields) or stream.read() != data):
                    raise OSError("Vault source changed during conversion")
            # If deletion fails, keep both complete copies and report failure.
            os.remove(source)
            count += 1
            print(f" [+] {operation.capitalize()} completed: {os.path.basename(path)}")
        except Exception as exc:
            failures += 1
            print(f" [-] {operation.capitalize()} failed for {os.path.basename(path)} "
                  f"({type(exc).__name__}); recoverable copies retained where possible.")
    status = "FAILED" if failures else "OK"
    print(f"[{status}] Vault {operation}: {count} converted, {failures} failed.")
    if lock:
        print("Plaintext deletion does not erase SSD blocks, backups, or in-memory credentials.")
    return failures == 0


def lock_vault():
    return _convert_vault(lock=True)


def unlock_vault():
    return _convert_vault(lock=False)


def panic_shred_local():
    print("[!] Best-effort overwrite/delete of local configurations and keys.")
    print("[!] Cannot erase SSD remnants, snapshots, backups, or in-memory credentials.")
    if input("Type 'VAPORIZE' to proceed: ").strip() != "VAPORIZE":
        print("[-] Panic aborted. No files were touched.")
        return False
    all_files = []
    for base in get_target_files():
        all_files.extend((base, base + ".enc"))
    qr_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qr_codes")
    if os.path.isdir(qr_dir):
        all_files.extend(os.path.join(qr_dir, name) for name in os.listdir(qr_dir))
    failures = 0
    for path in dict.fromkeys(all_files):
        try:
            secure_shred(path)
        except Exception as exc:
            failures += 1
            print(f" [-] Removal failed for {os.path.basename(path)} ({type(exc).__name__})")
    print("[FAILED] Some files could not be removed." if failures else
          "[OK] Best-effort removal completed; physical erasure is not guaranteed.")
    return failures == 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    actions = {"lock": lock_vault, "unlock": unlock_vault, "shred": panic_shred_local}
    if len(argv) != 1 or argv[0].lower() not in actions:
        print("Usage: python fortress_vault.py [lock|unlock|shred]")
        return 1
    if os.name != "nt":
        print("[-] This vault requires Windows; no files were changed.")
        return 1
    try:
        return 0 if actions[argv[0].lower()]() else 1
    except Exception as exc:
        print(f"[-] Vault operation failed ({type(exc).__name__}).")
        return 1


if __name__ == "__main__":
    sys.exit(main())
