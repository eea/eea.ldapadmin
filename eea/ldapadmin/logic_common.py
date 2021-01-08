''' some common logic '''
import six
from eea.ldapadmin.countries import get_country_options
from eea.ldapadmin import ldap_config


def _is_authenticated(request):
    ''' check if the user is authenticated '''
    return 'Authenticated' in request.AUTHENTICATED_USER.getRoles()


def logged_in_user(request):
    ''' return the id of the authenticated user '''
    user_id = ''

    if _is_authenticated(request):
        user = request.get('AUTHENTICATED_USER', '')

        if user:
            user_id = user.getId()

    return user_id


def orgs_in_country(context, country):
    """ return a dict of organisations in countrys """
    agent = _get_ldap_agent(context, secondary=True)
    orgs_by_id = agent.all_organisations()
    countries = dict(get_country_options(country=country))
    orgs = {}

    for org_id, info in six.iteritems(orgs_by_id):
        country_info = countries.get(info['country'])

        if country_info:
            orgs[org_id] = info

    return orgs


def nfp_for_country(context):
    """ Return country code for which the current user has NFP role
        or None otherwise"""
    user_id = context.REQUEST.AUTHENTICATED_USER.getId()

    if user_id:
        ldap_groups = get_ldap_user_groups(context, user_id)

        for group in ldap_groups:
            if ('eionet-nfp-mc-' in group[0] or
                'eionet-nfp-cc-' in group[0] or
                    'eionet-nfp-oc-' in group[0]):

                return group[0].rsplit('-', 1)[-1]
    return None


def get_ldap_user_groups(context, user_id):
    """ return the ldap roles the user is member of """
    agent = _get_ldap_agent(context, secondary=True)
    ldap_roles = sorted(agent.member_roles_info('user',
                                                user_id,
                                                ('description',)))

    return ldap_roles


def _get_ldap_agent(context, bind=True, secondary=False):
    ''' get the ldap agent '''
    agent = ldap_config.ldap_agent_with_config(context._config, bind,
                                               secondary=secondary)
    try:
        agent._author = logged_in_user(context.REQUEST)
    except AttributeError:
        agent._author = "System user"

    return agent
