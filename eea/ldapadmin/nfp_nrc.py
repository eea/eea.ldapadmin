#from App.class_init import InitializeClass
from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from datetime import datetime
from eea import usersdb
from eea.ldapadmin.countries import get_country
from logic_common import _get_user_id, _is_authenticated, _session_pop
from persistent.mapping import PersistentMapping
from ui_common import CommonTemplateLogic
from ui_common import SessionMessages, TemplateRenderer #load_template,
from ui_common import extend_crumbs, get_role_name, roles_list_to_text
import deform
import json
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
SESSION_FORM_ERRORS =  SESSION_PREFIX + '.form_errors'

user_info_edit_schema = usersdb.user_info_schema.clone()
user_info_edit_schema['postal_address'].widget = deform.widget.TextAreaWidget()
del user_info_edit_schema['first_name']
del user_info_edit_schema['last_name']

def _set_session_message(request, msg_type, msg):
    SessionMessages(request, SESSION_MESSAGES).add(msg_type, msg)

# def _is_authenticated(request):
#     return ('Authenticated' in request.AUTHENTICATED_USER.getRoles())

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


def get_nfp_roles(agent, request):
    out = []
    uid = _get_user_id(request)
    filterstr = ("(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" %
                   agent._user_dn(uid))
    nfp_roles = agent.filter_roles("eionet-nfp-*-*",
        prefix_dn="cn=eionet-nfp,cn=eionet",
        filterstr=filterstr,
        attrlist=("description",))

    for nfp in nfp_roles:
        try:
            role = SimplifiedRole(nfp[0], nfp[1]['description'][0])
        except ValueError:
            continue
        else:
            out.append(role)

    return sorted(out, key=operator.attrgetter('role_id'))


def get_nfps_for_country(agent, country_code):
    out = []
    filterstr = ("(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" %
                   agent._user_dn(uid))
    nfp_roles = agent.filter_roles("eionet-nfp-*-%s" % country_code,
        prefix_dn="cn=eionet-nfp,cn=eionet",
        filterstr=filterstr,
        attrlist=("description",))

    for nfp in nfp_roles:
        out.append(nfp[1]['id'])

    return sorted(out)


def get_nrc_roles(agent, user_id):
    out = []
    filterstr = ("(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))" %
                   agent._user_dn(user_id))
    roles = agent.filter_roles("eionet-nrc-*-*",
        prefix_dn="cn=eionet-nrc,cn=eionet",
        filterstr=filterstr,
        attrlist=("description",))

    for nrc in roles:
        try:
            role = SimplifiedRole(nrc[0], nrc[1]['description'][0])
        except ValueError:
            continue
        else:
            out.append(role)

    return sorted(out, key=operator.attrgetter('role_id'))


def get_nrc_members(agent, country_code):
    out = []
    for (role_id, attr) in agent.filter_roles("eionet-nrc-*-%s" % country_code,
                                           prefix_dn="cn=eionet-nrc,cn=eionet",
                                           attrlist=('description',)):
        try:
            description = attr.get('description', ('',))[0]
            role = SimplifiedRole(role_id, description)
        except ValueError:
            continue
        else:
            members = agent.members_in_role(role_id)
            users = [agent.user_info(user_id) for user_id in members['users']]
            for user in users:
                user['no_national_organisation'] = not has_national_org(
                    agent, user['id'], role_id)
            orgs = [agent.org_info(org_id) for org_id in members['orgs']]
            leaders, alternates = agent.role_leaders(role_id)
            role.set_members_info(users, orgs, leaders, alternates)
            out.append(role)

    return sorted(out, key=operator.attrgetter('role_id'))


def has_national_org(agent, user_id, role_id):
    # test if the user is member of a national organisation
    # for that role
    country_code = role_id.split('-')[-1]
    user_orgs = agent._search_user_in_orgs(user_id)
    has_national_org = False

    for org_id in user_orgs:
        org_info = agent.org_info(org_id)
        org_country = org_info.get("country")
        if org_country == country_code:
            has_national_org = True
            break

    return has_national_org


def role_members(agent, role_id):
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
        {'label':'Configure', 'action':'manage_edit'},
        {'label':'View', 'action':''},
    ) + PropertyManager.manage_options + SimpleItem.manage_options

    _properties = (
        {'id':'title', 'type': 'string', 'mode':'w', 'label': 'Title'},
    )

    _render_template = TemplateRenderer(CommonTemplateLogic)

    def _set_breadcrumbs(self, stack):
        self.REQUEST._nfp_nrc = stack

    def breadcrumbtrail(self):
        crumbs_html = self.aq_parent.breadcrumbtrail(self.REQUEST)
        extra_crumbs = getattr(self.REQUEST, '_nfp_nrc', [])
        return extend_crumbs(crumbs_html, self.absolute_url(), extra_crumbs)

    def __init__(self, config={}):
        super(NfpNrc, self).__init__()
        self._config = PersistentMapping(config)

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
        if not bool(nfp_roles):
            _set_session_message(request, 'error',
                    "You are not allowed to manage NRC members for %s" % code_to_name(country_code))
            request.RESPONSE.redirect(self.absolute_url())
            return False
        else:
            return True

    security.declareProtected(view_management_screens, 'get_config')
    def get_config(self):
        return dict(self._config)

    security.declareProtected(view_management_screens, 'manage_edit')
    manage_edit = PageTemplateFile('zpt/nfp_nrc/manage_edit', globals())
    manage_edit.ldap_config_edit_macro = ldap_config.edit_macro

    security.declareProtected(view_management_screens, 'manage_edit_save')
    def manage_edit_save(self, REQUEST):
        """ save changes to configuration """
        self._config.update(ldap_config.read_form(REQUEST.form, edit=True))
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_edit')

    def _get_ldap_agent(self, bind=False, secondary=False):
        agent = ldap_config.ldap_agent_with_config(self._config, bind)
        agent._author = logged_in_user(self.REQUEST)
        return agent

    security.declareProtected(view, 'index_html')
    def index_html(self, REQUEST):
        """ view """
        if not _is_authenticated(REQUEST):
            return self._render_template('zpt/nfp_nrc/index.zpt')
        agent = self._get_ldap_agent()
        nfps = get_nfp_roles(agent, REQUEST)
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
                if user.get('no_national_organisation'):
                    has_problematic_users = True
                    break

        if has_problematic_users:
            msg = "There are problematic users with regards to their "\
                  "connection to a national organisation"
            _set_session_message(REQUEST, 'info', msg)

        options = {'roles': roles,
                   'country': country_code,
                   'country_name': country_name,
                   # naming is similar to all NRC roles
                   'naming': roles_leaders.naming(roles[0].role_id),
                   'has_problematic_users': True,
                  }
        self._set_breadcrumbs([("Browsing NRC-s in %s" % country_name, '#')])
        return self._render_template('zpt/nfp_nrc/nrcs.zpt', **options)

    security.declareProtected(eionet_access_nfp_nrc, 'add_member_html')
    def add_member_html(self, REQUEST):
        """ view """
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
                'users': agent.search_user(search_name)
            }

        self._set_breadcrumbs([("Browsing NRC-s in %s" % country_name,
                                self.absolute_url()+'/nrcs?nfp=%s' % country_code),
                                ("Add member", '#')])
        return self._render_template('zpt/nfp_nrc/add_member.zpt', **options)

    security.declareProtected(eionet_access_nfp_nrc, 'add_user')
    def add_user(self, REQUEST):
        """ Add user `user_id` to role `role_id` """

        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        user_id = REQUEST.form['user_id']
        agent = self._get_ldap_agent(bind=True)
        if not self._allowed(agent, REQUEST, country_code):
            return None

        # test if the user to be added is member of a national organisation
        if not has_national_org(agent, user_id, role_id):
            msg = """
The user you would like to add as NRC does not have a sufficient reference to an
organisation for your country. Please add first as a member to one of your
national organisations and add after that as NRC."""
            _set_session_message(REQUEST, 'info', msg)
            url = REQUEST.get('HTTP_REFERER') or \
                self.absolute_url() + "/add_member_html?role_id=" + role_id
            return REQUEST.RESPONSE.redirect(url)

        role_id_list = agent.add_to_role(role_id, 'user', user_id)
        roles_msg = roles_list_to_text(agent, role_id_list)
        msg = "User %r added to roles %s." % (user_id, roles_msg)
        _set_session_message(REQUEST, 'info', msg)

        log.info("%s ADDED USER %r TO ROLE %r",
                      logged_in_user(REQUEST), user_id, role_id_list)

        REQUEST.RESPONSE.redirect(self.absolute_url() +
                                  '/nrcs?nfp=%s#role_%s' % (country_code, role_id))

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
                                self.absolute_url()+'/nrcs?nfp=%s' % country_code),
                              ("Remove members", "#")])
        return self._render_template('zpt/nfp_nrc/remove_members.zpt', **options)

    security.declareProtected(eionet_access_nfp_nrc, 'remove_members')
    def remove_members(self, REQUEST):
        """ Remove user several members from a role """
        agent = self._get_ldap_agent(bind=True)
        role_id = REQUEST.form['role_id']
        role_name = get_role_name(agent, role_id)
        country_code = role_id.rsplit('-', 1)[-1]
        if not self._allowed(agent, REQUEST, country_code):
            return None
        user_id_list = REQUEST.form.get('user_id_list', [])
        assert type(user_id_list) is list

        if user_id_list:
            for user_id in user_id_list:
                roles_id_list = agent.remove_from_role(role_id, 'user', user_id)
                log.info("%s REMOVED USER %s FROM ROLES %r",
                          logged_in_user(REQUEST), user_id, roles_id_list)

            msg = "Users %r removed from role %s" % (user_id_list, role_name)
            _set_session_message(REQUEST, 'info', msg)

        REQUEST.RESPONSE.redirect(self.absolute_url() +
                                  '/nrcs?nfp=%s#role_%s' % (country_code, role_id))

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
        #message
        form_data = _session_pop(REQUEST, SESSION_FORM_DATA, None)
        if form_data is None:
            form_data = user
            form_data['user_id'] = user['uid']
        options = {'user': user,
                   'form_data': form_data,
                   'schema': user_info_edit_schema,
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
        """ view """
        agent = self._get_ldap_agent()
        user_id = REQUEST.form['user_id']
        role_id = REQUEST.form['role_id']
        country_code = role_id.rsplit('-', 1)[-1]
        if not self._allowed(agent, REQUEST, country_code):
            return None
        elif user_id not in agent.members_in_role(role_id)['users']:
            return None
        user_form = deform.Form(user_info_edit_schema)
        user = agent.user_info(user_id)

        try:
            user_data = user_form.validate(REQUEST.form.items())
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
            agent = self._get_ldap_agent(bind=True, secondary=True)
            # put these readonly-s back
            user_data.update(first_name=user['first_name'],
                             last_name=user['last_name'])
            agent.set_user_info(user_id, user_data)
            when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _set_session_message(REQUEST, 'info', "Profile saved (%s)" % when)
            log.info("%s EDITED USER %s as member of %s",
                     logged_in_user(REQUEST), user_id, role_id)

        REQUEST.RESPONSE.redirect('%s/edit_member?user_id=%s&role_id=%s' %
                                  (self.absolute_url(), user_id, role_id))

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
