"""Opt-in native Windows GUI config load; prints booleans, never credentials."""
from pathlib import Path
import os
import runpy
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if os.name != 'nt':
    raise SystemExit('Run with native Windows Python')
module = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'SovereignFortressApp.pyw'),
                         run_name='gui_configuration_smoke')
configured = not module['SERVER_IP'].startswith('<')
no_ssh_seed = not bool(module['CONFIG'].get('totp_secret'))
encoded = 'https%3A%2F%2F' in module['HIDDIFY_DEEPLINK']
print('GUI loads protected client settings:', configured)
print('No SSH TOTP seed exported:', no_ssh_seed)
print('Hiddify nested URL encoded:', encoded)
raise SystemExit(0 if configured and no_ssh_seed and encoded else 1)
