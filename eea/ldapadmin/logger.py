import os
import logging

from App.config import getConfiguration

def init():
    names = ['nfp_nrc', 'orgs_editor', 'roles_editor', 'users_admin']

    CONFIG = getConfiguration()
    LDAP_ADMIN_LOGGING_PATH = getattr(CONFIG, 'environment', {}).\
                            get('LDAP_ADMIN_LOGGING_PATH', '')

    for name in names:
        LOG_FILENAME = os.path.join(LDAP_ADMIN_LOGGING_PATH, name + '.log')
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
        formatter = logging.Formatter('%(asctime)s: %(message)s',
                                      '%d/%b/%Y:%H:%M:%S %z')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
