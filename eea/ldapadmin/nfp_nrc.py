# pylint: disable=too-many-lines,super-init-not-called,too-many-statements
# pylint: disable=too-many-branches,too-many-locals,too-many-nested-blocks
# pylint: disable=too-many-public-methods,dangerous-default-value
# pylint: disable=global-statement,too-many-instance-attributes
''' Eionet directory management tools for users with NFP/Eionet Groups
    (former NRC) roles '''
import json
import logging
import operator
import re

import deform
import ldap
from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from AccessControl.unauthorized import Unauthorized
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from persistent.mapping import PersistentMapping
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.statusmessages.interfaces import IStatusMessage

from eea import usersdb
from eea.ldapadmin.countries import get_country
from eea.ldapadmin.users_admin import eionet_edit_users
from eea.ldapadmin import ldap_config
from eea.ldapadmin.ldap_config import _get_ldap_agent
from eea.ldapadmin import roles_leaders
from eea.ldapadmin.logic_common import _is_authenticated, logged_in_user
from eea.ldapadmin.ui_common import get_role_name, extend_crumbs
from eea.ldapadmin.ui_common import nfp_can_change_user
from eea.ldapadmin.ui_common import CommonTemplateLogic, TemplateRenderer
from eea.ldapadmin.ui_common import TemplateRendererNoWrap
log = logging.getLogger('nfp_nrc')

eionet_access_nfp_nrc = 'Eionet access NFP admin for NRC'

manage_add_nfp_nrc_html = PageTemplateFile('zpt/nfp_nrc/manage_add.zpt',
                                           globals())
manage_add_nfp_nrc_html.ldap_config_edit_macro = ldap_config.edit_macro
manage_add_nfp_nrc_html.config_defaults = lambda: ldap_config.defaults


def manage_add_nfp_nrc(parent, tool_id, REQUEST=None):
    """ Adds a new Eionet Groups Admin object """
    form = (REQUEST.form if REQUEST is not None else {})
    config = ldap_config.read_form(form)
    obj = NfpNrc(config)
    obj.title = form.get('title', tool_id)
    obj._setId(tool_id)
    parent._setObject(tool_id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')


user_info_edit_schema = usersdb.user_info_schema.clone()
user_info_edit_schema['postal_address'].widget = deform.widget.TextAreaWidget()
del user_info_edit_schema['first_name']
del user_info_edit_schema['last_name']


EXTRANET_REPORTER_ROLES = [
    'extranet-aqipr-h2k',
    'extranet-aqipr-utd',
    'extranet-aqipr-val',
    'extranet-birds-art12data',
    'extranet-bwd-data',
    'extranet-clrtap-reporter',
    'extranet-co2monitoring-reporter',
    'extranet-dwd-data',
    'extranet-emerald-reporter',
    'extranet-energycommunity',
    'extranet-eprtrlcp-data',
    'extranet-ets-art21reporter',
    'extranet-euregistry-reporter',
    'extranet-floods-data',
    'extranet-fqd-reporter',
    'extranet-habides-reporter',
    'extranet-habitats-art17data',
    'extranet-ias-reporter',
    'extranet-ied-ieddat',
    'extranet-inspire-reporter',
    'extranet-mcp-reporter',
    'extranet-mercury-reporter',
    'extranet-mmr-reporter',
    'extranet-msfdreporter-data',
    'extranet-natura2000-reporter',
    'extranet-necd-reporter',
    'extranet-nid-reporter',
    'extranet-noise-reporter',
    'extranet-res8-reporters',
    'extranet-uwwtd-data',
    'extranet-wfd-data'
]


EIONET_GROUPS = ["eionet-biodiversity1",
                 "eionet-biodiversity2",
                 "eionet-circulareconomy",
                 "eionet-climatecangeadaptation"
                 "eionet-clmatechangemitigation",
                 "eionet-communication",
                 "eionet-data",
                 "eionet-foodsystems",
                 "eionet-foresight",
                 "eionet-health",
                 "eionet-landsystems",
                 "eionet-mobility",
                 "eionet-soe",
                 ]


def code_to_name(country_code):
    ''' return country name from iso code '''
    return get_country(country_code)['name']


class SimplifiedRole(object):
    """
    A simple way of representing and addressing attributes
    of an NFP/Eionet Groups Role

    """

    def __init__(self, role_id, description):
        group = re.match(
            r'^eionet-(biodiversity1|biodiversity2|climatechange|health|'
            r'circulareconomy|foresight|soe|foodsystems|landsystems|mobility|'
            r'data|communication)(.*)-([^-]*)$',
            role_id, re.IGNORECASE)
        nfp = re.match(
            r'^eionet-nfp-(.*)(mc|cc|oc)-([^-]*)$',
            role_id, re.IGNORECASE)
        reportnet = re.match(
            r'^reportnet-awp-([^-]*)-reporter-([^-]*)$',
            role_id, re.IGNORECASE)
        extranet = re.match(
            r'^(extranet)-.*-([^-]*)$', role_id, re.IGNORECASE)
        match = group or nfp or reportnet or extranet

        if match:
            self.type = match.groups()[0].lower()
            self.country = match.groups()[-1].lower()
            self.role_id = role_id
            self.description = description
        else:
            raise ValueError("Not a valid NFP/Eionet Groups/Reporter role")

        if not self.country:
            raise ValueError("Not a valid NFP/Eionet Groups/Reporter role")

    def set_members_info(self, users=[], orgs=[], leaders=[], alternates=[]):
        ''' set members info '''
        self.users = users
        self.orgs = orgs
        self.leaders = leaders
        self.alternates = alternates

    def split(self, s):
        ''' split role id '''
        return self.role_id.split(s)


class SimplifiedRoleDict(dict):
    """
    A simple way of representing and addressing attributes
    of an NFP/Eionet Groups Role, json ready

    """

    def __init__(self, role_id, description):
        group = re.match(
            r'^eionet-(biodiversity1|biodiversity2|climatechange|health|'
            r'circulareconomy|foresight|soe|foodsystems|landsystems|mobility|'
            r'data|communication)(.*)-([^-]*)$',
            role_id, re.IGNORECASE)
        nfp = re.match(r'^eionet-nfp-(.*)(mc|cc|oc)-([^-]*)$', role_id,
                       re.IGNORECASE)
        reportnet = re.match(
            r'^reportnet-awp-([^-]*)-reporter-([^-]*)$',
            role_id, re.IGNORECASE)
        extranet = re.match(r'^(extranet)-.*-([^-]*)$', role_id, re.IGNORECASE)
        match = group or nfp or reportnet or extranet

        if match:
            self['type'] = match.groups()[0].lower()
            self['country'] = match.groups()[-1].lower()
            self['role_id'] = role_id
            self['description'] = description
        else:
            raise ValueError("Not a valid NFP/Groups/Reporter role")

        if not self['country']:
            raise ValueError("Not a valid NFP/Group/Reporter role")

    def set_members_info(self, users=[], orgs=[], leaders=[], alternates=[]):
        ''' set members info '''
        self['users'] = users
        self['orgs'] = orgs
        self['leaders'] = leaders
        self['alternates'] = alternates

    def split(self, s):
        ''' split role id '''
        return self['role_id'].split(s)


def get_nfps_for_country(agent, country_code):
    """ Returns a list of nfp role ids for the given country_code
    """

    out = []
    filterstr = "(objectClass=groupOfUniqueNames)"
    nfp_roles = agent.filter_roles("eionet-nfp-*-%s" % country_code,
                                   prefix_dn="cn=eionet-nfp,cn=eionet",
                                   filterstr=filterstr,
                                   attrlist=("description",))

    # pylint: disable=unused-variable
    for role_id, attrs in nfp_roles:
        out.append(role_id)

    return sorted(out)


def _get_roles_for_user(agent, user_id, prefix_dn, branch=""):
    ''' get a list of roles of user '''
    out = []
    filterstr = ("(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" %
                 agent._user_dn(user_id))
    if not branch:
        if "eionet-nfp" in prefix_dn:
            branch = "eionet-nfp-*-*"
        elif "reportnet-awp" in prefix_dn:
            branch = "reportnet-awp-*-reporter-*"
    roles = agent.filter_roles(
        branch, prefix_dn=prefix_dn,  # "cn=eionet-nrc,cn=eionet"
        filterstr=filterstr, attrlist=("description",))

    for role in roles:
        if re.match('.*-[a-z]{2}$', role[0]):
            try:
                role_obj = SimplifiedRole(role[0], role[1]['description'][0])
            except ValueError:
                continue
            else:
                out.append(role_obj)

    return sorted(out, key=operator.attrgetter('role_id'))


def get_nfp_roles(agent, user_id=None):
    """ Returns the nfp roles (as SimplifiedRole instances) for current user
    """

    return _get_roles_for_user(agent,
                               user_id,
                               prefix_dn="cn=eionet-nfp,cn=eionet")


def get_nrc_roles(agent, user_id):
    """ Returns the Eionet Grups (formerly called nrc) roles
        (as SimplifiedRole instances) for current user
    """

    out = []
    for role in EIONET_GROUPS:
        out.extend(_get_roles_for_user(
            agent, user_id,
            prefix_dn="cn=%s,cn=eionet" % role,
            branch=role))
    return sorted(out, key=operator.attrgetter('role_id'))


def get_awp_roles(agent, user_id):
    """ Returns the awp roles (as SimplifiedRole instances) for current user
    """

    return _get_roles_for_user(agent,
                               user_id,
                               prefix_dn="cn=reportnet-awp,cn=reportnet")


def get_top_role_dns(agent, dn_branch):
    ''' get the top role dns '''
    return sorted([x[0] for x in agent.conn.search_s(
        agent._role_dn(dn_branch),
        ldap.SCOPE_ONELEVEL,
        filterstr='(objectClass=groupOfUniqueNames)',
        attrlist=['id'])
    ])


def get_national_org(agent, user_id, role_id):
    """ Get the "canonical" national organisation for the given user_id

    It will return the organisation info only if the organisation is set to
    exist in the country for that role.
    """
    # test if the user is member of a national organisation
    # for that role
    country_code = role_id.split('-')[-1]

    if country_code == "eea":
        country_code = 'eu'
    user_orgs = agent._search_user_in_orgs(user_id)

    for org_id in user_orgs:
        org_info = agent.org_info(org_id)
        org_country = org_info.get("country")

        if org_country == country_code:
            return org_info
    return None


def role_members(agent, role_id):
    """ Return the member and organisations for the given role
    """
    members = agent.members_in_role(role_id)

    return {
        'users': dict((user_id, agent.user_info(user_id))
                      for user_id in members['users']),
        'orgs': dict((org_id, agent.org_info(org_id))
                     for org_id in members['orgs']),
    }


class NfpNrc(SimpleItem, PropertyManager):
    ''' Eionet NFP Admin '''
    meta_type = 'Eionet NFP Admin'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_nfp_admin.gif'

    manage_options = (
        {'label': 'Configure', 'action': 'manage_edit'},
        {'label': 'View', 'action': ''},
    ) + PropertyManager.manage_options + SimpleItem.manage_options

    _properties = (
        {'id': 'title', 'type': 'string', 'mode': 'w', 'label': 'Title'},
    )

    _render_template = TemplateRenderer(CommonTemplateLogic)
    _render_template_no_wrap = TemplateRendererNoWrap(CommonTemplateLogic)

    security.declareProtected(view_management_screens, 'manage_edit')
    manage_edit = PageTemplateFile('zpt/nfp_nrc/manage_edit.zpt', globals())
    manage_edit.ldap_config_edit_macro = ldap_config.edit_macro

    def __init__(self, config={}):
        super(NfpNrc, self).__init__()
        self._config = PersistentMapping(config)

    def _set_breadcrumbs(self, stack):
        ''' set the breadcrumbs '''
        self.REQUEST._nfp_nrc = stack

    def breadcrumbtrail(self):
        ''' create the breadcrumb trail '''
        crumbs_html = self.aq_parent.breadcrumbtrail(self.REQUEST)
        extra_crumbs = getattr(self.REQUEST, '_nfp_nrc', [])

        return extend_crumbs(crumbs_html, self.absolute_url(), extra_crumbs)

    security.declarePrivate('_allowed')

    def _allowed(self, agent, request, country_code):
        """
        Tests if logged in user is allowed to manage Eionet Groups members for
        `country` (whether he is an NFP member for country)

        """
        uid = logged_in_user(request)
        if not uid:
            return False
        filterstr = ("(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" %
                     agent._user_dn(uid))
        nfp_roles = agent.filter_roles("eionet-nfp-*-%s" % country_code,
                                       prefix_dn="cn=eionet-nfp,cn=eionet",
                                       filterstr=filterstr,
                                       attrlist=("description",))

        if not (bool(nfp_roles) or self.checkPermissionZopeManager()):
            msg = (
                u"You are not allowed to manage Eionet Groups members for %s"
                % code_to_name(country_code))
            IStatusMessage(request).add(msg, type='error')
            request.RESPONSE.redirect(self.absolute_url())

            return False
        return True

    security.declareProtected(view_management_screens, 'get_config')

    def get_config(self):
        ''' return the object's configuration '''
        return dict(self._config)

    security.declareProtected(view_management_screens, 'manage_edit_save')

    def manage_edit_save(self, REQUEST):
        """ save changes to configuration """
        self._config.update(ldap_config.read_form(REQUEST.form, edit=True))
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_edit')

    def _get_ldap_agent(self, bind=True, secondary=False):
        """ get the ldap agent """
        return _get_ldap_agent(self, bind, secondary)

    security.declareProtected(view, 'index_html')

    def index_html(self, REQUEST):
        """ view """

        if not _is_authenticated(REQUEST):
            return self._render_template('zpt/nfp_nrc/index.zpt')
        agent = self._get_ldap_agent()
        user_id = logged_in_user(REQUEST)
        nfps = get_nfp_roles(agent, user_id)
        options = {'nfps': nfps}

        return self._render_template('zpt/nfp_nrc/index.zpt', **options)

    def get_top_role_members(self, role_dn, country_code):
        """ get the members of the top role """
        agent = self._get_ldap_agent()
        has_problematic_users = False
        top_role_id = agent._role_id(role_dn)
        # the country filter should allow any number of items between
        # top_role_id and country_code (including zero)
        filter_country = "%s*-%s" % (top_role_id, country_code)
        roles = []

        for (dn, attr) in agent.conn.search_s(
                role_dn,
                ldap.SCOPE_SUBTREE,
                filterstr="(&(objectClass=groupOfUniqueNames)(cn=%s))"
                % filter_country, attrlist=['description']):

            role_id = agent._role_id(dn)

            try:
                description = attr.get('description', (b'',))[0].decode()
                role = SimplifiedRoleDict(role_id, description)
            except ValueError:
                continue
            else:
                members = agent.members_in_role(role_id)
                users = [agent.user_info(user_id) for user_id in
                         members['users']]

                for user in users:
                    user['ldap_org'] = get_national_org(agent,
                                                        user['id'],
                                                        role_id)

                    if not user['ldap_org']:
                        has_problematic_users = True
                    del user['createTimestamp']
                    del user['modifyTimestamp']
                orgs = [agent.org_info(org_id) for org_id in members['orgs']]
                leaders, alternates = agent.role_leaders(role_id)
                role.set_members_info(users, orgs, leaders, alternates)

                roles.append(role)

        if roles:
            return json.dumps(
                {'roles': sorted(roles, key=lambda k: k['role_id']),
                 'has_problematic_users': has_problematic_users,
                 'naming': roles_leaders.naming(roles[0]['role_id'])})
        return json.dumps(
            {'roles': [],
             'has_problematic_users': has_problematic_users,
             'naming': ''})

    security.declareProtected(eionet_access_nfp_nrc, 'nrcs')

    def nrcs(self, REQUEST):
        """ view Eionet Groups and members in these roles """

        if not _is_authenticated(REQUEST):
            pass

        country_code = REQUEST.form.get("nfp")
        country_name = code_to_name(country_code)
        agent = self._get_ldap_agent()

        if not self._allowed(agent, REQUEST, country_code):
            raise Unauthorized

        top_role_dns = [agent._role_dn(role_id) for role_id in EIONET_GROUPS]

        options = {'top_role_dns': top_role_dns,
                   'country': country_code,
                   'agent': agent,
                   'country_name': country_name or country_code,
                   }
        self._set_breadcrumbs([
            ("Browsing Eionet Groups in %s" % country_name, '#')])

        return self._render_template('zpt/nfp_nrc/nrcs.zpt', **options)

    security.declareProtected(eionet_access_nfp_nrc, 'awps')

    def awps(self, REQUEST):
        """ view awp roles and members in these roles """

        if not _is_authenticated(REQUEST):
            pass

        country_code = REQUEST.form.get("nfp", 'eea')
        country_name = code_to_name(country_code)
        agent = self._get_ldap_agent()

        if not self._allowed(agent, REQUEST, country_code):
            raise Unauthorized

        top_role_dns = get_top_role_dns(agent, 'reportnet-awp')

        options = {'top_role_dns': top_role_dns,
                   'country': country_code,
                   'country_name': country_name or country_code,
                   }
        self._set_breadcrumbs([("Browsing reporter roles in %s" % country_name,
                                '#')])

        return self._render_template('zpt/nfp_nrc/awps.zpt', **options)

    security.declareProtected(eionet_access_nfp_nrc, 'extranet_reporters')

    def extranet_reporters(self, REQUEST):
        """ view extranet reporter roles and members in these roles """

        if not _is_authenticated(REQUEST):
            raise Unauthorized

        country_code = REQUEST.form.get("nfp", 'eea')
        country_name = code_to_name(country_code)
        agent = self._get_ldap_agent()

        if not self._allowed(agent, REQUEST, country_code):
            raise Unauthorized

        try:
            extranet_reporter_roles = self.get_extranet_reporter_roles()
        except AttributeError:
            extranet_reporter_roles = EXTRANET_REPORTER_ROLES
        top_role_dns = [agent._role_dn(role)
                        for role in extranet_reporter_roles]

        options = {'top_role_dns': top_role_dns,
                   'country': country_code,
                   'country_name': country_name or country_code,
                   }
        self._set_breadcrumbs([("Browsing extranet reporter roles in %s" %
                                country_name, '#')])
        return self._render_template('zpt/nfp_nrc/extranet_reporters.zpt',
                                     **options)

    security.declareProtected(eionet_access_nfp_nrc, 'add_member_html')

    def add_member_html(self, REQUEST):
        """ view to add a member as"""

        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        country_name = code_to_name(country_code)
        agent = self._get_ldap_agent()
        role_name = agent.role_info(role_id)['description']

        if not self._allowed(agent, REQUEST, country_code):
            return None
        search_name = REQUEST.form.get('name', '')
        options = {
            'role_id': role_id,
            'role_name': role_name,
            'country': country_code,
            'country_name': country_name,
            'search_name': search_name,
            'search_results': None,
        }

        if search_name:
            search_results = agent.search_user(search_name, no_disabled=True)
            for user in search_results:
                if not nfp_can_change_user(self, user['uid'], no_org=False):
                    user['restricted'] = True
            options['search_results'] = {
                'users': search_results
            }

        if '-awp-' in role_id:
            self._set_breadcrumbs([("Browsing reporters in %s" % country_name,
                                    self.absolute_url() + '/awps?nfp=%s' %
                                    country_code), ("Add member", '#')])
        else:
            self._set_breadcrumbs([
                ("Browsing Eionet Groups in %s" % country_name,
                 self.absolute_url() + '/nrcs?nfp=%s' %
                 country_code),
                ("Add member", '#')])

        return self._render_template('zpt/nfp_nrc/add_member.zpt', **options)

    security.declareProtected(eionet_access_nfp_nrc, 'add_user')

    def add_user(self, REQUEST):
        """ Add user `user_id` to role `role_id`;

        This is used to add a user to an Eionet Groups role
        """

        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        user_id = REQUEST.form['user_id']
        agent = self._get_ldap_agent()

        if not self._allowed(agent, REQUEST, country_code):
            return None
        if not nfp_can_change_user(self, user_id, no_org=False):
            # This means somebody is manipulating the DOM in order to
            # add a user that belongs to an organisation from another
            # country (the button doesn't normally appear)
            return None

        with agent.new_action():
            role_id_list = agent.add_to_role(role_id, 'user', user_id)

        role_msg = get_role_name(agent, role_id)
        msg = "User %r added to role %s. \n" % (user_id, role_msg)

        # for Eionet Groups roles only, test if the added user is member of a
        # national organisation

        if self.is_eionet_group(role_id):
            if not get_national_org(agent, user_id, role_id):
                msg += (
                    "The user you want to add to an Eionet Group does not"
                    " have a mandatory reference to an organisation for "
                    "your country. Please corect!")

        IStatusMessage(REQUEST).add(msg, type='info')

        log.info("%s ADDED USER %r TO ROLE %r",
                 logged_in_user(REQUEST), user_id, role_id_list)

        if '-awp-' in role_id:
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/awps?nfp=%s#role_%s' %
                                             (country_code, role_id))

        return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                         '/nrcs?nfp=%s#role_%s' %
                                         (country_code, role_id))

    security.declareProtected(eionet_access_nfp_nrc, 'remove_members_html')

    def remove_members_html(self, REQUEST):
        """ Bulk-remove several members """

        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        country_name = code_to_name(country_code)
        agent = self._get_ldap_agent()
        role_name = get_role_name(agent, role_id)

        if not self._allowed(agent, REQUEST, country_code):
            return None
        options = {
            'role_id': role_id,
            'role_name': role_name,
            'country': country_code,
            'country_name': country_name,
            'role_members': role_members(agent, role_id),
        }

        if self.is_eionet_group(role_id):
            self._set_breadcrumbs([
                ("Browsing Eionet Groups in %s" % country_name,
                 self.absolute_url() + '/nrcs?nfp=%s' % country_code),
                ("Remove members", "#")])
        elif '-awp-' in role_id:
            self._set_breadcrumbs([("Browsing reporters in %s" % country_name,
                                    self.absolute_url() + '/awps?nfp=%s' %
                                    country_code),
                                   ("Remove members", "#")])

        return self._render_template('zpt/nfp_nrc/remove_members.zpt',
                                     **options)

    security.declareProtected(eionet_access_nfp_nrc, 'remove_members')

    def remove_members(self, REQUEST):
        """ Remove several members from a role """

        agent = self._get_ldap_agent()
        role_id = REQUEST.form['role_id']
        role_name = get_role_name(agent, role_id)
        country_code = role_id.rsplit('-', 1)[-1]

        if not self._allowed(agent, REQUEST, country_code):
            return None
        user_id_list = REQUEST.form.get('user_id_list', [])
        assert isinstance(user_id_list, list)

        if user_id_list:
            with agent.new_action():
                for user_id in user_id_list:
                    roles_id_list = agent.remove_from_role(role_id,
                                                           'user',
                                                           user_id)
                    log.info("%s REMOVED USER %s FROM ROLES %r",
                             logged_in_user(REQUEST), user_id, roles_id_list)

            msg = "Users %r removed from role %s" % (user_id_list, role_name)
            IStatusMessage(REQUEST).add(msg, type='info')

        if '-awp-' in role_id:
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/awps?nfp=%s#role_%s' %
                                             (country_code, role_id))

        return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                         '/nrcs?nfp=%s#role_%s' %
                                         (country_code, role_id))

    security.declareProtected(eionet_access_nfp_nrc, 'set_pcp')

    # pylint: disable=unused-variable
    def set_pcp(self, REQUEST):
        """ callback that saves the PCP """

        agent = self._get_ldap_agent()
        user_id = REQUEST.form['user_id']
        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]

        if not self._allowed(agent, REQUEST, country_code):
            return None
        if user_id not in agent.members_in_role(role_id)['users']:
            return None
        leaders, alternates = agent.role_leaders(role_id)
        REQUEST.RESPONSE.setHeader('Content-Type', 'application/json')

        if user_id in leaders:
            # then we have to unset it
            agent.unset_role_leader(role_id, user_id)

            return json.dumps({'pcp': ''})
        agent.set_role_leader(role_id, user_id)

        return json.dumps({'pcp': user_id})

    def checkPermissionEditUsers(self):
        """ Returns True if user has permission to edit users"""
        user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(eionet_edit_users, self))

    def checkPermissionZopeManager(self):
        """ Returns True if user has the manager role in Zope"""
        user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(view_management_screens, self))

    def is_eionet_group(self, role_id):
        """ Check if the role belongs to an Eionet Group branch """
        for role in EIONET_GROUPS:
            if role in role_id:
                return True

        return False
