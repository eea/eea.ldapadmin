import logging
import os.path

from naaya.ldapdump import main


log = logging.getLogger(__name__)

def dump_ldap(ldap_logging_path):
    """ Perform a dump of an LDAP database according to the config file. """
    naaya_ldap_cfg = os.path.join(ldap_logging_path, 'config.yaml')
    if not os.path.exists(naaya_ldap_cfg):
        log.info("%s does not exist", naaya_ldap_cfg)
    else:
        return main.dump_ldap(naaya_ldap_cfg)
