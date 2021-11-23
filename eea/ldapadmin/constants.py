from App.config import getConfiguration
cfg = getConfiguration()

# constant defined in env
NETWORK_NAME = getattr(cfg, 'environment', {}).get('NETWORK_NAME', 'EIONET')
