"""
Module dedicated to specific logic related to role/organization leaders.
The two LDAP attributes that support this feature are `leaderMember` and
`alternateLeader`.

"""
import re
from eea.ldapadmin.nfp_nrc import EIONET_GROUPS


# Configurations
def naming(role_id):
    """ Based on the role, we have different namings for these memberships """
    role_id = role_id or ''
    if re.match('eionet-nfp-[mc]c-[^-]+', role_id):
        return {
            'leader': {'long': 'Officially Nominated',
                       'short': 'ON'},
            'alternate': {'long': 'Deputy',
                          'short': 'Dep'},
            'generic_pl': 'official representatives'
        }
    else:
        for eionet_group in EIONET_GROUPS:
            if re.match(eionet_group, role_id):
                return {
                    'leader': {'long': 'Primary Contact Point',
                               'short': 'PCP'},
                    'alternate': {'long': 'Alternate Contact Point',
                                  'short': 'ACP'},
                    'generic_pl': 'primary contact points'
                }
    return {
        'leader': {'long': 'Maintainer',
                   'short': 'Mn'},
        'alternate': {'long': 'Alternate Maintainer',
                      'short': 'AM'},
        'generic_pl': 'maintainers'
    }


def leaders_enabled(role_id):
    """
    Featured disabled by request for any non-NRC/NFP role

    """
    role_id = role_id or ''
    if re.match('eionet-nfp-[mc]c-[^-]+', role_id):
        return True
    if re.match('eionet-nrc-[^-]+-[mc]c-[^-]+', role_id):
        return True
    return False


def alternates_enabled(role_id):
    """
    Alternates are disabled (hidden) for nrc/nfp as a request by GAN (Milan)

    """
    role_id = role_id or ''
    if re.match('eionet-nfp-[mc]c-[^-]+', role_id):
        return False
    if re.match('eionet-nrc-[^-]+-[mc]c-[^-]+', role_id):
        return False
    return True
