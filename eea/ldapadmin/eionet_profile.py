''' eionet LDAP connections '''
import os
import yaml
import requests

from App.config import getConfiguration

CONFIG = getConfiguration()
if hasattr(CONFIG, 'environment'):
    CONFIG.environment.update(os.environ)

LDAP_DISK_STORAGE = getattr(CONFIG,
                            'environment',
                            {}).get('LDAP_DISK_STORAGE', '')


def get_endpoints():
    """
    Reads config.yaml file if exists and returns list of configured endpoints
    """
    try:
        config_file = open(os.path.abspath(os.path.join(LDAP_DISK_STORAGE,
                                                        "config.yaml")), "r")
    except Exception:
        return []
    config = yaml.load(config_file)
    return config.get('endpoints', [])


def get_endpoint_data(endpoint, userid):
    """ Performs query to endpoint. May be slow or unsuccessful. """
    _ = endpoint
    req = requests.get(_['url'], params={'userid': userid},
                       auth=(_['user'], _['password']))
    if req.status_code == 200:
        return req.json()
    return {}
