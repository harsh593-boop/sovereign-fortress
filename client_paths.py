"""Keep deployment credentials outside the public source checkout."""
import os
from pathlib import Path


def client_directory():
    override = os.environ.get('FORTRESS_CLIENT_HOME')
    if override:
        return Path(override).expanduser().resolve()
    base = Path(os.environ['LOCALAPPDATA']) if os.environ.get('LOCALAPPDATA') else Path.home() / '.local' / 'share'
    return base / 'SovereignFortress'


def client_config_path():
    override = os.environ.get('FORTRESS_CLIENT_CONFIG')
    return Path(override).expanduser().resolve() if override else client_directory() / 'fortress_config.json'
