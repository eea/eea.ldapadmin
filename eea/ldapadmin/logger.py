''' logger settings '''
import os
import logging

from eea.ldapadmin.constants import LDAP_DISK_STORAGE


def init():
    ''' configure logger for several objects '''
    names = ['nfp_nrc', 'orgs_editor', 'roles_editor', 'users_admin']

    for name in names:
        LOG_FILENAME = os.path.join(LDAP_DISK_STORAGE, '%s.log' % name)
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.WatchedFileHandler(LOG_FILENAME)
        formatter = logging.Formatter('%(asctime)s: %(message)s',
                                      '%d/%b/%Y:%H:%M:%S %z')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
