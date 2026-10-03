"""Opt-in native Windows DPAPI smoke with synthetic data only."""
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fortress_vault as vault


def main():
    if os.name != 'nt':
        raise SystemExit('Run this opt-in smoke test on native Windows Python')
    for payload in (b'', b'synthetic-vault-fixture', bytes(range(256)) * 20):
        protected = vault.dpapi_protect(payload)
        assert protected and protected != payload
        assert vault.dpapi_unprotect(protected) == payload
    with tempfile.TemporaryDirectory(prefix='fortress-dpapi-smoke-') as directory:
        source = Path(directory) / 'fixture.json'
        original = b'{"fixture":true}'
        source.write_bytes(original)
        previous = vault.get_target_files
        vault.get_target_files = lambda: [str(source)]
        try:
            assert vault.lock_vault()
            assert not source.exists()
            assert Path(str(source) + '.enc').exists()
            assert vault.unlock_vault()
            assert source.read_bytes() == original
            assert not Path(str(source) + '.enc').exists()
        finally:
            vault.get_target_files = previous
    print('PASS native Windows DPAPI and NTFS synthetic vault round trip; no operator files touched')


if __name__ == '__main__':
    main()
