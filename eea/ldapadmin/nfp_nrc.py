from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from AccessControl.unauthorized import Unauthorized
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from Products.Five.browser import BrowserView
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from copy import deepcopy
from datetime import datetime
from deform.widget import SelectWidget
from eea import usersdb
from eea.ldapadmin.constants import NETWORK_NAME
from eea.ldapadmin.countries import get_country
from eea.ldapadmin.countries import get_country_options
from eea.ldapadmin.help_messages import help_messages
from eea.ldapadmin.logic_common import _session_pop
from eea.ldapadmin.ui_common import NaayaViewPageTemplateFile
from eea.ldapadmin.users_admin import _is_authenticated
from eea.ldapadmin.users_admin import _send_email
from eea.ldapadmin.users_admin import eionet_edit_users
from eea.ldapadmin.users_admin import generate_password
from eea.ldapadmin.users_admin import generate_user_id
from eea.ldapadmin.users_admin import get_duplicates_by_name
from eea.ldapadmin.users_admin import _transliterate
from eea.ldapadmin.users_admin import user_info_add_schema
from eea.usersdb.db_agent import NameAlreadyExists, EmailAlreadyExists
from email.mime.text import MIMEText
from logic_common import _get_user_id
from persistent.mapping import PersistentMapping
from ui_common import CommonTemplateLogic
from ui_common import SessionMessages, TemplateRenderer  # load_template,
from ui_common import extend_crumbs, TemplateRendererNoWrap
from ui_common import get_role_name  # , roles_list_to_text
from unidecode import unidecode
import colander
import deform
import json
import ldap
import ldap_config
import logging
import operator
import re
import roles_leaders


log = logging.getLogger('nfp_nrc')

eionet_access_nfp_nrc = 'Eionet access NFP admin for NRC'

manage_add_nfp_nrc_html = PageTemplateFile('zpt/nfp_nrc/manage_add', globals())
manage_add_nfp_nrc_html.ldap_config_edit_macro = ldap_config.edit_macro
manage_add_nfp_nrc_html.config_defaults = lambda: ldap_config.defaults


def manage_add_nfp_nrc(parent, id, REQUEST=None):
    """ Adds a new Eionet NFP Admin object """
    form = (REQUEST.form if REQUEST is not None else {})
    config = ldap_config.read_form(form)
    obj = NfpNrc(config)
    obj.title = form.get('title', id)
    obj._setId(id)
    parent._setObject(id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')

SESSION_PREFIX = 'eea.ldapadmin.nfp_nrc'
SESSION_MESSAGES = SESSION_PREFIX + '.messages'
SESSION_FORM_DATA = SESSION_PREFIX + '.form_data'
SESSION_FORM_ERRORS = SESSION_PREFIX + '.form_errors'

user_info_edit_schema = usersdb.user_info_schema.clone()
user_info_edit_schema['postal_address'].widget = deform.widget.TextAreaWidget()
del user_info_edit_schema['first_name']
del user_info_edit_schema['last_name']


def _set_session_message(request, msg_type, msg):
    SessionMessages(request, SESSION_MESSAGES).add(msg_type, msg)


def logged_in_user(request):
    user_id = ''
    if _is_authenticated(request):
        user = request.get('AUTHENTICATED_USER', '')
        user_id = user.id

    return user_id


def code_to_name(country_code):
    return get_country(country_code)['name']


class SimplifiedRole(object):
    """
    A simple way of representing and addressing attributes
    of an NFP/NRC Role

    """

    def __init__(self, role_id, description):
        m = re.match(r'^eionet-(nfp|nrc)-(.*)(mc|cc)-([^-]*)$', role_id,
                     re.IGNORECASE)
        if m:
            self.type = m.groups()[0].lower()
            self.country = m.groups()[3].lower()
            self.role_id = role_id
            self.description = description
        else:
            raise ValueError("Not a valid NFP/NRC role")
        if not self.country or (self.type not in ('nfp', 'nrc')):
            raise ValueError("Not a valid NFP/NRC role")

    def set_members_info(self, users=[], orgs=[], leaders=[], alternates=[]):
        self.users = users
        self.orgs = orgs
        self.leaders = leaders
        self.alternates = alternates

    def split(self, s):
        return self.role_id.split(s)


def get_nfps_for_country(agent, country_code):
    """ Returns a list of nfp role ids for the given country_code
    """

    out = []
    filterstr = "(objectClass=groupOfUniqueNames)"
    nfp_roles = agent.filter_roles("eionet-nfp-*-%s" % country_code,
                                   prefix_dn="cn=eionet-nfp,cn=eionet",
                                   filterstr=filterstr,
                                   attrlist=("description",))

    for role_id, attrs in nfp_roles:
        out.append(role_id)

    return sorted(out)


def _get_roles_for_user(agent, user_id, prefix_dn):
    out = []
    filterstr = ("(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" %
                 agent._user_dn(user_id))
    branch = ""
    if "eionet-nfp" in prefix_dn:
        branch = "eionet-nfp-*-*"
    elif "eionet-nrc" in prefix_dn:
        branch = "eionet-nrc-*-*"
    roles = agent.filter_roles(
        branch, prefix_dn=prefix_dn,  # "cn=eionet-nrc,cn=eionet"
        filterstr=filterstr, attrlist=("description",))

    for nrc in roles:
        try:
            role = SimplifiedRole(nrc[0], nrc[1]['description'][0])
        except ValueError:
            continue
        else:
            out.append(role)

    return sorted(out, key=operator.attrgetter('role_id'))


def get_nfp_roles(agent, user_id=None):  # XXX: this was a request
    """ Returns the nfp roles (as SimplifiedRole instances) for current user
    """

    return _get_roles_for_user(agent,
                               user_id,
                               prefix_dn="cn=eionet-nfp,cn=eionet")


def get_nrc_roles(agent, user_id):
    """ Returns the nrc roles (as SimplifiedRole instances) for current user
    """

    return _get_roles_for_user(agent,
                               user_id,
                               prefix_dn="cn=eionet-nrc,cn=eionet")


def get_nrc_members(agent, country_code):
    """ Get the nrc members assigned to this country code
    """

    out = []

    top_nrc_role_dns = [x[0] for x in
                        agent.conn.search_s(
                            agent._role_dn('eionet-nrc'),
                            ldap.SCOPE_ONELEVEL,
                            filterstr='(objectClass=groupOfUniqueNames)',
                            attrlist=['id'])
                        ]

    for top_role_dn in top_nrc_role_dns:
        top_role_id = agent._role_id(top_role_dn)
        filter_country = "%s-*-%s" % (top_role_id, country_code)

        for (role_dn, attr) in agent.conn.search_s(
                top_role_dn,
                ldap.SCOPE_SUBTREE,
                filterstr="(&(objectClass=groupOfUniqueNames)(cn=%s))"
                % filter_country, attrlist=['description']):

            role_id = agent._role_id(role_dn)

            try:
                description = attr.get('description', ('',))[0]
                role = SimplifiedRole(role_id, description)
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
                orgs = [agent.org_info(org_id) for org_id in members['orgs']]
                leaders, alternates = agent.role_leaders(role_id)
                role.set_members_info(users, orgs, leaders, alternates)
                out.append(role)

    return sorted(out, key=operator.attrgetter('role_id'))


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
    meta_type = 'Eionet NFP Admin'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_nfp_admin.gif'
    session_messages = SESSION_MESSAGES

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
    manage_edit = PageTemplateFile('zpt/nfp_nrc/manage_edit', globals())
    manage_edit.ldap_config_edit_macro = ldap_config.edit_macro

    def __init__(self, config={}):
        super(NfpNrc, self).__init__()
        self._config = PersistentMapping(config)

    def _set_breadcrumbs(self, stack):
        self.REQUEST._nfp_nrc = stack

    def breadcrumbtrail(self):
        crumbs_html = self.aq_parent.breadcrumbtrail(self.REQUEST)
        extra_crumbs = getattr(self.REQUEST, '_nfp_nrc', [])
        return extend_crumbs(crumbs_html, self.absolute_url(), extra_crumbs)

    security.declarePrivate('_allowed')

    def _allowed(self, agent, request, country_code):
        """
        Tests if logged in user is allowed to manage NRC members for
        `country` (whether he is an NFP member for country)

        """
        uid = _get_user_id(request)
        filterstr = ("(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" %
                     agent._user_dn(uid))
        nfp_roles = agent.filter_roles("eionet-nfp-*-%s" % country_code,
                                       prefix_dn="cn=eionet-nfp,cn=eionet",
                                       filterstr=filterstr,
                                       attrlist=("description",))
        if not (bool(nfp_roles) or self.checkPermissionZopeManager()):
            _set_session_message(
                request, 'error',
                "You are not allowed to manage NRC members for %s"
                % code_to_name(country_code))
            request.RESPONSE.redirect(self.absolute_url())
            return False
        else:
            return True

    security.declareProtected(view_management_screens, 'get_config')

    def get_config(self):
        return dict(self._config)

    security.declareProtected(view_management_screens, 'manage_edit_save')

    def manage_edit_save(self, REQUEST):
        """ save changes to configuration """
        self._config.update(ldap_config.read_form(REQUEST.form, edit=True))
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_edit')

    def _get_ldap_agent(self, bind=True, secondary=False):
        agent = ldap_config.ldap_agent_with_config(self._config, bind)
        try:
            agent._author = logged_in_user(self.REQUEST)
        except AttributeError:
            agent._author = "System user"
        return agent

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

    security.declareProtected(eionet_access_nfp_nrc, 'nrcs')

    def nrcs(self, REQUEST):
        """ view nrcs and members in these roles """

        if not _is_authenticated(REQUEST):
            pass

        country_code = REQUEST.form.get("nfp")
        country_name = code_to_name(country_code)
        agent = self._get_ldap_agent()

        if not self._allowed(agent, REQUEST, country_code):
            return None

        roles = get_nrc_members(agent, country_code)
        has_problematic_users = False

        for role in roles:
            for user in role.users:
                if not user['ldap_org']:
                    has_problematic_users = True
                    break

        if has_problematic_users:
            msg = "There are problematic users with regards to their "\
                  "connection to a national organisation"
            _set_session_message(REQUEST, 'info', msg)

        options = {'roles': roles,
                   'country': country_code,
                   'country_name': country_name or country_code,
                   # naming is similar to all NRC roles
                   'naming': roles_leaders.naming(roles[0].role_id),
                   # 'has_problematic_users': has_problematic_users,
                   }
        self._set_breadcrumbs([("Browsing NRC-s in %s" % country_name, '#')])
        return self._render_template('zpt/nfp_nrc/nrcs.zpt', **options)

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
            options['search_results'] = {
                'users': agent.search_user(search_name, no_disabled=True)
            }

        self._set_breadcrumbs([("Browsing NRC-s in %s" % country_name,
                                self.absolute_url()+'/nrcs?nfp=%s' %
                                country_code), ("Add member", '#')])
        return self._render_template('zpt/nfp_nrc/add_member.zpt', **options)

    security.declareProtected(eionet_access_nfp_nrc, 'add_user')

    def add_user(self, REQUEST):
        """ Add user `user_id` to role `role_id`;

        This is used to add a user to an NRC role
        """

        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        user_id = REQUEST.form['user_id']
        agent = self._get_ldap_agent(bind=True)
        if not self._allowed(agent, REQUEST, country_code):
            return None

        with agent.new_action():
            role_id_list = agent.add_to_role(role_id, 'user', user_id)

        role_msg = get_role_name(agent, role_id)
        msg = "User %r added to role %s. \n" % (user_id, role_msg)

        # test if the user to be added is member of a national organisation
        if not get_national_org(agent, user_id, role_id):
            msg += ("The user you added as an NRC does not have a mandatory"
                    " reference to an organisation for your country. "
                    "Please corect!")

        _set_session_message(REQUEST, 'info', msg)

        log.info("%s ADDED USER %r TO ROLE %r",
                 logged_in_user(REQUEST), user_id, role_id_list)

        REQUEST.RESPONSE.redirect(self.absolute_url() +
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

        self._set_breadcrumbs([("Browsing NRC-s in %s" % country_name,
                                self.absolute_url()+'/nrcs?nfp=%s' %
                                country_code),
                              ("Remove members", "#")])
        return self._render_template('zpt/nfp_nrc/remove_members.zpt',
                                     **options)

    security.declareProtected(eionet_access_nfp_nrc, 'remove_members')

    def remove_members(self, REQUEST):
        """ Remove several members from a role """

        agent = self._get_ldap_agent(bind=True)
        role_id = REQUEST.form['role_id']
        role_name = get_role_name(agent, role_id)
        country_code = role_id.rsplit('-', 1)[-1]
        if not self._allowed(agent, REQUEST, country_code):
            return None
        user_id_list = REQUEST.form.get('user_id_list', [])
        assert type(user_id_list) is list

        if user_id_list:
            with agent.new_action():
                for user_id in user_id_list:
                    roles_id_list = agent.remove_from_role(role_id,
                                                           'user',
                                                           user_id)
                    log.info("%s REMOVED USER %s FROM ROLES %r",
                             logged_in_user(REQUEST), user_id, roles_id_list)

            msg = "Users %r removed from role %s" % (user_id_list, role_name)
            _set_session_message(REQUEST, 'info', msg)

        REQUEST.RESPONSE.redirect(self.absolute_url() +
                                  '/nrcs?nfp=%s#role_%s' %
                                  (country_code, role_id))

    security.declareProtected(eionet_access_nfp_nrc, 'edit_member')

    def edit_member(self, REQUEST):
        """ Update profile of a member of the NRC role """
        agent = self._get_ldap_agent()
        user_id = REQUEST.form['user_id']
        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        if not self._allowed(agent, REQUEST, country_code):
            return None
        elif user_id not in agent.members_in_role(role_id)['users']:
            return None
        errors = _session_pop(REQUEST, SESSION_FORM_ERRORS, {})
        user = agent.user_info(user_id)
        # message
        form_data = _session_pop(REQUEST, SESSION_FORM_DATA, None)
        if form_data is None:
            form_data = user
            form_data['user_id'] = user['uid']

        orgs = agent.all_organisations()
        orgs = [{'id': k, 'text': v['name'], 'ldap': True}
                for k, v in orgs.items()]

        user_orgs = list(agent.user_organisations(user_id))
        if not user_orgs:
            org = form_data['organisation']
            if org:
                orgs.append({'id': org, 'text': org, 'ldap': False})
        else:
            org = user_orgs[0]
            org_id = agent._org_id(org)
            form_data['organisation'] = org_id
        orgs.sort(lambda x, y: cmp(x['text'], y['text']))

        choices = [('', '-')]
        for org in orgs:
            if org['ldap']:
                label = u"%s (%s)" % (org['text'], org['id'])
            else:
                label = org['text']
            choices.append((org['id'], label))

        schema = user_info_edit_schema.clone()
        widget = deform.widget.SelectWidget(values=choices)
        schema['organisation'].widget = widget

        options = {
            'user': user,
            'form_data': form_data,
            'schema': schema,
            'errors': errors,
            'role_id': role_id,
        }
        self._set_breadcrumbs([(role_id,
                                '%s/nrcs?nfp=%s' % (self.absolute_url(),
                                                    country_code)),
                               (user_id, '#')])
        return self._render_template('zpt/nfp_nrc/edit_member.zpt', **options)

    security.declareProtected(eionet_access_nfp_nrc, 'edit_member_action')

    def edit_member_action(self, REQUEST):
        """ Edit a member: the action handler """

        agent = self._get_ldap_agent(bind=True)
        user_id = REQUEST.form['user_id']
        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        if not self._allowed(agent, REQUEST, country_code):
            return None
        elif user_id not in agent.members_in_role(role_id)['users']:
            return None
        user_form = deform.Form(user_info_edit_schema)

        try:
            new_info = user_form.validate(REQUEST.form.items())
        except deform.ValidationFailure, e:
            session = REQUEST.SESSION
            errors = {}
            for field_error in e.error.children:
                errors[field_error.node.name] = field_error.msg
            session[SESSION_FORM_ERRORS] = errors
            session[SESSION_FORM_DATA] = dict(REQUEST.form)
            msg = u"Please correct the errors below and try again."
            _set_session_message(REQUEST, 'error', msg)
        else:
            old_info = agent.user_info(user_id)

            # put these readonly-s back
            new_info.update(first_name=old_info['first_name'],
                            last_name=old_info['last_name'])

            new_org_id = new_info['organisation']
            new_org_id_valid = agent.org_exists(new_org_id)

            # make a check if user is changing the organisation
            user_orgs = [agent._org_id(org)
                         for org in list(agent.user_organisations(user_id))]

            with agent.new_action():
                if not (new_org_id in user_orgs):
                    self._remove_from_all_orgs(agent, user_id)
                    if new_org_id_valid:
                        self._add_to_org(agent, new_org_id, user_id)

                agent.set_user_info(user_id, new_info)
            when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _set_session_message(REQUEST, 'message',
                                 "Profile saved (%s)" % when)

            log.info("%s EDITED USER %s as member of %s",
                     logged_in_user(REQUEST), user_id, role_id)

        REQUEST.RESPONSE.redirect('%s/edit_member?user_id=%s&role_id=%s' %
                                  (self.absolute_url(), user_id, role_id))

    def _add_to_org(self, agent, org_id, user_id):
        try:
            agent.add_to_org(org_id, [user_id])
        except ldap.INSUFFICIENT_ACCESS:
            ids = self.aq_parent.objectIds(["Eionet Organisations Editor"])
            if ids:
                obj = self.aq_parent[ids[0]]
                org_agent = obj._get_ldap_agent(bind=True)
                org_agent.add_to_org(org_id, [user_id])
            else:
                raise

    def _remove_from_all_orgs(self, agent, user_id):
        orgs = agent.user_organisations(user_id)
        for org_dn in orgs:
            org_id = agent._org_id(org_dn)
            try:
                agent.remove_from_org(org_id, [user_id])
            except ldap.NO_SUCH_ATTRIBUTE:  # user is not in org
                pass
            except ldap.INSUFFICIENT_ACCESS:
                ids = self.aq_parent.objectIds(["Eionet Organisations Editor"])
                if ids:
                    obj = self.aq_parent[ids[0]]
                    org_agent = obj._get_ldap_agent(bind=True)
                    try:
                        org_agent.remove_from_org(org_id, [user_id])
                    except ldap.NO_SUCH_ATTRIBUTE:    # user is not in org
                        pass
                else:
                    raise

    security.declareProtected(eionet_access_nfp_nrc, 'set_pcp')

    def set_pcp(self, REQUEST):
        """ callback that saves the PCP """

        agent = self._get_ldap_agent()
        user_id = REQUEST.form['user_id']
        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        if not self._allowed(agent, REQUEST, country_code):
            return None
        elif user_id not in agent.members_in_role(role_id)['users']:
            return None
        agent = self._get_ldap_agent(bind=True)
        leaders, alternates = agent.role_leaders(role_id)
        REQUEST.RESPONSE.setHeader('Content-Type', 'application/json')
        if user_id in leaders:
            # then we have to unset it
            agent.unset_role_leader(role_id, user_id)
            return json.dumps({'pcp': ''})
        else:
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

    security.declarePrivate('_find_duplicates')

    def _find_duplicates(self, fname, lname, email):
        """ find similar users """
        duplicate_records = []

        agent = self._get_ldap_agent()
        duplicates_by_email = agent.search_user_by_email(email)
        duplicate_records.extend(duplicates_by_email)

        user_cn = unidecode(("%s %s" % (fname, lname)))
        # set of uids with similar corresponding names
        uids_by_name = set(map(agent._user_id,
                               get_duplicates_by_name(user_cn)))
        # set of uids with the same associated email
        uids_by_mail = set(user['uid'] for user in duplicates_by_email)
        uids_to_search = uids_by_name.difference(uids_by_mail)

        duplicate_records.extend(agent.search_users_by_uid(uids_to_search))
        return duplicate_records

    def find_duplicates(self, REQUEST):
        """ view """
        if self.REQUEST.AUTHENTICATED_USER.getUserName() == 'Anonymous User':
            raise Unauthorized
        fname = REQUEST.form.get('first_name', '')
        lname = REQUEST.form.get('last_name', '')
        email = REQUEST.form.get('email', '')

        # duplicate_records = []

        if fname and lname and email:
            duplicates_records = self._find_duplicates(fname, lname, email)

        options = {
            'is_authenticated': True,
            'users': dict([(d['uid'], d) for d in duplicates_records])
        }

        return self._render_template_no_wrap('zpt/users/find_duplicates.zpt',
                                             **options)


class CreateUser(BrowserView):
    """ A page to create a user

    Uses code from users_admin.py, but this should be merged/moved
    """
    index = NaayaViewPageTemplateFile('zpt/users/create.zpt')

    def _create_user(self, agent, user_info):
        """ Creates user in ldap using user_info (data already validated)
        """

        # remove id and password from user_info, so these will not
        # appear as properties on the user
        user_id = str(user_info.pop('id'))
        password = str(user_info.pop('password'))
        agent._update_full_name(user_info)
        agent.create_user(user_id, user_info)
        agent.set_user_password(user_id, None, password)

        if self.nfp_has_access():
            requester = logged_in_user(self.request)
            info = agent.user_info(requester)
            for to in [info['email'], "helpdesk@eionet.europa.eu"]:
                self._send_new_user_email(user_id, user_info, to)

        # put id and password back on user_info, for further processing
        # (mainly sending of email)
        user_info['id'] = user_id
        user_info['password'] = password
        return user_id

    def _send_new_user_email(self, user_id, user_info, to=None):
        """ Sends announcement email to helpdesk """

        addr_from = "no-reply@eea.europa.eu"
        addr_to = to or "helpdesk@eionet.europa.eu"

        message = MIMEText('')
        message['From'] = addr_from
        message['To'] = addr_to

        options = deepcopy(user_info)
        options['user_id'] = user_id
        agent = self.context._get_ldap_agent()

        requester = "System User"
        try:
            requester = logged_in_user(self.request)
            info = agent.user_info(requester)
        except:
            info = {'first_name': '', 'last_name': ''}

        options['author'] = u"%(firstname)s %(lastname)s (%(requester)s)" % {
            'firstname': info['first_name'],
            'lastname': info['last_name'],
            'requester': requester
        }

        body = self.context._render_template.render(
            "zpt/users/new_user_email.zpt",
            **options)

        message['Subject'] = "[Account created by NFP]"
        message.set_payload(body.encode('utf-8'), charset='utf-8')

        _send_email(addr_from, addr_to, message)

    def checkPermissionEditUsers(self):
        """ """
        user = self.request.AUTHENTICATED_USER
        return bool(user.has_permission(eionet_edit_users, self))

    def orgs_in_country(self, country):
        """ """
        agent = self.context._get_ldap_agent()
        orgs_by_id = agent.all_organisations()
        countries = dict(get_country_options(country=country))
        orgs = {}
        for org_id, info in orgs_by_id.iteritems():
            country_info = countries.get(info['country'])
            if country_info:
                orgs[org_id] = info
        return orgs

    def __call__(self):

        if not (self.checkPermissionEditUsers() or
                self.nfp_has_access()):
            raise Unauthorized

        nfp_country = self.nfp_for_country()
        form_data = dict(self.request.form)
        errors = {}
        if not form_data.get('password', ''):
            form_data['password'] = generate_password()

        schema = user_info_add_schema.clone()
        # hide user id, make password optional
        del schema['id']
        schema['password'].missing = None
        for children in schema.children:
            help_text = help_messages['create-user'].get(children.name, None)
            setattr(children, 'help_text', help_text)
        schema['destinationIndicator'].help_text = \
            ("Please indicate reason of account creation like e.g. "
             "NRC nomination, data reporter in Reportnet for directive XYZ, "
             "project XXXX cooperation ....")

        agent = self.context._get_ldap_agent()
        agent_orgs = self.orgs_in_country(nfp_country)

        orgs = [{'id': k, 'text': v['name'], 'ldap':True}
                for k, v in agent_orgs.items()]
        org = form_data.get('organisation')
        if org and not (org in agent_orgs):
            orgs.append({'id': org, 'text': org, 'ldap': False})
        orgs.sort(lambda x, y: cmp(x['text'], y['text']))
        choices = [('', '-')]
        for org in orgs:
            if org['ldap']:
                label = u"%s (%s)" % (org['text'], org['id'])
            else:
                label = org['text']
            choices.append((org['id'], label))

        widget = SelectWidget(values=choices)
        schema['organisation'].widget = widget

        if self.nfp_has_access():
            schema['organisation'].missing = colander.required

        if 'submit' in self.request.form:
            try:
                user_form = deform.Form(schema)
                user_info = user_form.validate(form_data.items())
                user_info['destinationIndicator'] = user_info[
                    'destinationIndicator'].replace('&', 'and')
                user_info['search_helper'] = _transliterate(
                    user_info['first_name'], user_info['last_name'],
                    user_info['full_name_native'], user_info['search_helper'])
            except deform.ValidationFailure, e:
                for field_error in e.error.children:
                    errors[field_error.node.name] = field_error.msg
                msg = u"Please correct the errors below and try again."
                _set_session_message(self.request, 'error', msg)
            else:
                agent = self.context._get_ldap_agent(bind=True)
                user_id = user_info['id'] = generate_user_id(
                    user_info['first_name'], user_info['last_name'],
                    agent, [])

                with agent.new_action():
                    try:
                        self._create_user(agent, user_info)
                    except NameAlreadyExists, e:
                        errors['id'] = 'This ID is alreay registered'
                    except EmailAlreadyExists, e:
                        errors['email'] = 'This email is alreay registered'
                    else:

                        new_org_id = form_data['organisation']
                        new_org_id_valid = agent.org_exists(new_org_id)

                        if new_org_id_valid:
                            self.context._add_to_org(agent,
                                                     new_org_id,
                                                     user_id)

                        send_confirmation = ('send_confirmation' in
                                             form_data.keys())
                        if send_confirmation:
                            self.send_confirmation_email(user_info)
                            self.send_password_reset_email(user_info)

                        # self._send_new_account_email_to_nfps(user_id)
                        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        msg = "User %s created (%s)" % (user_id, when)
                        _set_session_message(self.request, 'info', msg)

                        log.info("%s CREATED USER %s",
                                 logged_in_user(self.request),
                                 user_id)

                    if not errors:
                        return self.request.RESPONSE.redirect(
                            self.context.absolute_url())
                    else:
                        msg = u"Please correct the errors below and try again."
                        _set_session_message(self.request, 'error', msg)

        options = {
            'common': CommonTemplateLogic(self.context),
            'context': self.context,
            'errors': errors,
            'form_data': form_data,
            'nfp_access': self.nfp_has_access(),
            'schema': schema,
        }
        return self.index(**options)

    def send_confirmation_email(self, user_info):
        """ Sends confirmation email """
        addr_from = "no-reply@eea.europa.eu"
        addr_to = user_info['email']
        message = MIMEText('')
        message['From'] = addr_from
        message['To'] = addr_to

        body = self.confirmation_email(user_info['first_name'],
                                       user_info['id'])
        message['Subject'] = "%s Account `%s` Created" % (
            NETWORK_NAME, user_info['id'])
        message.set_payload(body.encode('utf-8'), charset='utf-8')
        _send_email(addr_from, addr_to, message)

    def confirmation_email(self, first_name, user_id, REQUEST=None):
        """ Returns body of confirmation email """
        if not self.checkPermissionEditUsers() and not self.nfp_has_access():
            raise Unauthorized
        options = {'first_name': first_name, 'user_id': user_id}
        options['site_title'] = self.context.unrestrictedTraverse('/').title
        return self.context._render_template.render(
            "zpt/users/email_account_created.zpt",
            **options)

    def send_password_reset_email(self, user_info):
        """ """
        pwreset_tool = self.context.restrictedTraverse('/').objectValues(
            'Eionet Password Reset Tool')[0]
        email = user_info['email']
        pwreset_tool.ask_for_password_reset(self.request, email=email)

    def nfp_has_access(self):
        """ """
        return bool(self.nfp_for_country())
        # and self.context.aq_parent.id == 'nfp-eionet'

    def nfp_for_country(self):
        """ Return country code for which the current user has NFP role
        or None otherwise"""
        user_id = self.request.AUTHENTICATED_USER.getId()
        if user_id:
            ldap_groups = self.get_ldap_user_groups(user_id)
            for group in ldap_groups:
                if 'eionet-nfp-cc-' in group[0]:
                    return group[0].replace('eionet-nfp-cc-', '')
                if 'eionet-nfp-mc-' in group[0]:
                    return group[0].replace('eionet-nfp-mc-', '')

    def get_ldap_user_groups(self, user_id):
        """ """
        try:
            from eea.usersdb.factories import agent_from_uf
        except ImportError:
            return []
        agent = agent_from_uf(self.context.restrictedTraverse("/acl_users"))
        ldap_roles = sorted(
            agent.member_roles_info('user', user_id, ('description',)))
        return ldap_roles
