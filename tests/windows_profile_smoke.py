"""Explicit native Windows schema check of protected profiles; no TUN start."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from client_paths import client_directory
from fortress_vault import dpapi_unprotect


def main():
    if os.name != 'nt':
        raise SystemExit('Run with native Windows Python')
    root = client_directory()
    binary = root / 'tools' / 'sing-box-1.14.2' / 'sing-box.exe'
    for name in ('fortress-full-tunnel.json', 'fortress-traffic-only.json'):
        plain = dpapi_unprotect(Path(str(root / name) + '.enc').read_bytes())
        fd, path = tempfile.mkstemp(dir=root, prefix='.schema-check-', suffix='.json')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(plain)
            result = subprocess.run([str(binary), 'check', '-c', path], capture_output=True, timeout=20)
            if result.returncode:
                raise SystemExit('Native profile check failed; private diagnostics suppressed')
            print('PASS native Sing-box 1.14.2 schema:', name)
        finally:
            Path(path).unlink(missing_ok=True)
    print('No VPN process or TUN adapter was started.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
