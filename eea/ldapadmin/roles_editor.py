from string import ascii_lowercase
import operator
import csv
import codecs
from StringIO import StringIO
import re
try:
    import json
except ImportError:
    import simplejson as json

from AccessControl import ClassSecurityInfo, Unauthorized
from AccessControl.Permissions import view, view_management_screens
from App.class_init import InitializeClass
from OFS.Folder import Folder
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from persistent.mapping import PersistentMapping
from persistent.list import PersistentList

from eea import usersdb
import ldap_config
from ui_common import load_template, SessionMessages, TemplateRenderer
from ui_common import get_role_name, roles_list_to_text
from import_export import generate_csv
from constants import NETWORK_NAME

import logging
log = logging.getLogger('roles_editor')

eionet_edit_roles = 'Eionet edit roles'

manage_add_roles_editor_html = PageTemplateFile('zpt/roles_manage_add',
                                                globals())
manage_add_roles_editor_html.ldap_config_edit_macro = ldap_config.edit_macro
manage_add_roles_editor_html.config_defaults = lambda: ldap_config.defaults


def manage_add_roles_editor(parent, id, REQUEST=None):
    """ Create a new RolesEditor object """
    form = (REQUEST.form if REQUEST is not None else {})
    config = ldap_config.read_form(form)
    obj = RolesEditor(config)
    obj.title = form.get('title', id)
    obj._setId(id)
    parent._setObject(id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')

def _is_authenticated(request):
    return ('Authenticated' in request.AUTHENTICATED_USER.getRoles())

def _role_parents(role_id):
    if role_id is None:
        return []
    parents = [role_id]
    while '-' in role_id:
        role_id = role_id.rsplit('-', 1)[0]
        parents.append(role_id)
    return reversed(parents)

SESSION_PREFIX = 'eea.ldapadmin.roles_editor'
SESSION_MESSAGES = SESSION_PREFIX + '.messages'
SESSION_FORM_DATA = SESSION_PREFIX + '.form_data'

def _set_session_message(request, msg_type, msg):
    SessionMessages(request, SESSION_MESSAGES).add(msg_type, msg)

def logged_in_user(request):
    user_id = ''
    if _is_authenticated(request):
        user = request.get('AUTHENTICATED_USER', '')
        user_id = str(user.id)

    return user_id

def filter_roles(agent, pattern):
    out = {}
    for (role_id, attr) in agent.filter_roles(pattern, attrlist=('description',)):
        members = agent.members_in_role(role_id)
        # TODO catch individual errors when showing useres
        out[role_id] = {
            'users': [agent.user_info(user_id)
                      for user_id in members['users']],
            'name': (attr.get('description') or [role_id])[0].decode(agent._encoding)
        }
    return out

def filter_result_html(agent, pattern, renderer):
    options = {
        'pattern': pattern,
        'results': filter_roles(agent, pattern),
    }
    return renderer.render('zpt/roles_filter_result.zpt', **options)

class CommonTemplateLogic(object):
    def __init__(self, context):
        self.context = context

    def _get_request(self):
        return self.context.REQUEST

    def base_url(self):
        return self.context.absolute_url()

    def message_boxes(self):
        return SessionMessages(self._get_request(), SESSION_MESSAGES).html()

    def is_authenticated(self):
        return _is_authenticated(self._get_request())

    def buttons_bar(self, current_page, role_id, members_in_role=0):
        user = self._get_request().AUTHENTICATED_USER

        options = {
            'current_page': current_page,
            'role_id': role_id,
            'common': self,
            'can_edit_roles': self.context.can_edit_roles(user),
            'can_edit_members': self.context.can_edit_members(role_id, user),
            'can_delete_role': self.context.can_delete_role(role_id, user),
            'members_in_role': members_in_role,
        }
        tr = self.context._render_template
        return tr.render('zpt/roles_buttons.zpt', **options)

    def search_roles_box(self, pattern=None):
        options = {
            'pattern': pattern,
            'predefined_filters': self.context._predefined_filters(),
        }
        tr = self.context._render_template
        return tr.render('zpt/roles_filter_form.zpt', **options)

    @property
    def macros(self):
        return load_template('zpt/macros.zpt').macros

    @property
    def network_name(self):
        """ E.g. EIONET, SINAnet etc. """
        return NETWORK_NAME

    @property
    def supports_mailing(self):
        """ bool, whether supports role mailing lists """
        return NETWORK_NAME == 'EIONET'

class RoleCreationError(Exception):
    def __init__(self, messages):
        self.messages = messages

import query

def role_members(agent, role_id, subroles=False):
    """
    Return members of specified role.
    If subroles is True return all members of specified role and its subroles.

    """
    from ldap import NO_SUCH_OBJECT

    users = {}
    try:
        if subroles:
            members = agent.members_in_role_and_subroles(role_id)
        else:
            members = agent.members_in_role(role_id)
        users = dict((user_id, agent.user_info(user_id))
                      for user_id in members['users'])
    except (NO_SUCH_OBJECT, usersdb.UserNotFound):
        pass

    return {
        'users': users
    }

class RolesEditor(Folder):
    meta_type = 'Eionet Roles Editor'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_roles_editor.gif'

    meta_types = (
        {'name': query.Query.meta_type, 'action': 'manage_add_query_html'},
    )

    manage_options = Folder.manage_options[:2] + (
        {'label':'Configure', 'action':'manage_edit'},
    ) + Folder.manage_options[2:]

    _render_template = TemplateRenderer(CommonTemplateLogic)

    def __init__(self, config={}):
        super(RolesEditor, self).__init__()
        self._config = PersistentMapping(config)

    security.declareProtected(view_management_screens, 'get_config')
    def get_config(self):
        return dict(self._config)

    security.declareProtected(view_management_screens, 'manage_edit')
    manage_edit = PageTemplateFile('zpt/roles_manage_edit', globals())
    manage_edit.ldap_config_edit_macro = ldap_config.edit_macro

    security.declareProtected(view_management_screens, 'manage_edit_save')
    def manage_edit_save(self, REQUEST):
        """ save changes to configuration """
        self._config.update(ldap_config.read_form(REQUEST.form, edit=True))
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_edit')

    def _get_ldap_agent(self, bind=False):
        return ldap_config.ldap_agent_with_config(self._config, bind)

    def _predefined_filters(self):
        return sorted(self.objectValues([query.Query.meta_type]),
                      key=operator.methodcaller('getId'))

    def _get_permitted_senders_info(self, mail_info):
        """ Returns permittedSender-s as {'patterns': [..], 'emails': [..]} """
        result = {'patterns': [], 'emails': []}
        for entity in mail_info['permittedSender']:
            if '*' in entity:
                result['patterns'].append(entity)
            elif '@' in entity:
                result['emails'].append(entity)
        return result

    security.declareProtected(view, 'index_html')
    def index_html(self, REQUEST):
        """ view """
        role_id = REQUEST.form.get('role_id', None)
        agent = self._get_ldap_agent()

        try:
            role_info = agent.role_info(role_id)
        except usersdb.RoleNotFound:
            REQUEST.RESPONSE.setStatus(404)
            options = {'message': "Role %s does not exist." % role_id}
            return self._render_template('zpt/generic_error.zpt', **options)

        subroles = agent.role_names_in_role(role_id)
        has_subroles = False
        for subrole_id in subroles:
            if agent.role_names_in_role(subrole_id):
                has_subroles = True

        user_infos = {} # shared user info-s storage

        mail_info = agent.mail_group_info(role_id)
        uinfo = agent.user_info
        for user in set(mail_info['owner'] + mail_info['permittedPerson']):
            try:
                user_infos[user] = uinfo(user)
            except usersdb.UserNotFound:
                user_infos[user] = {'id': user, 'deleted': True}
        role_owners = dict((x, user_infos[x]) for x in mail_info['owner'])
        persons = dict((x, user_infos[x]) for x in mail_info['permittedPerson'])
        permitted_senders = self._get_permitted_senders_info(mail_info)
        user = REQUEST.AUTHENTICATED_USER

        options = {
            'role_id': role_id,
            'role_name': get_role_name(agent, role_id),
            'role_info': role_info,
            'role_names': agent.role_names_in_role(role_id),
            'role_members': role_members(agent, role_id),
            'role_owners': role_owners,
            'permitted_persons': persons,
            'permitted_senders': permitted_senders,
            'can_edit': self.can_edit_roles(REQUEST.AUTHENTICATED_USER),
            'can_edit_members': self.can_edit_members(role_id, user),
            'can_delete_role': self.can_delete_role(role_id, user),
            'has_subroles': has_subroles,
            'agent': agent
        }

        self._set_breadcrumbs(self._role_parents_stack(role_id))
        return self._render_template('zpt/roles_browse.zpt', **options)

    def _filter_results(self, pattern, title=None):
        search_url = self.absolute_url() + '/filter'
        csv_url = self.absolute_url() + '/filter_users_csv'
        options = {
            'pattern': pattern,
            'title': title,
        }
        breadcrumbs = [('Search', search_url)]
        if pattern:
            agent = self._get_ldap_agent()
            results_html = filter_result_html(agent, pattern,
                                              self._render_template)
            options['results_html'] = results_html
            options['csv_link'] = csv_url + '?pattern=' + pattern
            pattern_url = search_url + '?pattern:utf8:ustring=' + pattern
            breadcrumbs += [(pattern, pattern_url)]

        self._set_breadcrumbs(breadcrumbs)
        return self._render_template('zpt/roles_filter.zpt', **options)

    security.declareProtected(view, 'filter')
    def filter(self, REQUEST):
        """ view """
        pattern = REQUEST.form.get('pattern', '')
        return self._filter_results(pattern)

    security.declareProtected(view, 'filter_users_csv')
    def filter_users_csv(self, REQUEST):
        """ view """
        if not _is_authenticated(REQUEST):
            return "You must be logged in to access this page.\n"

        pattern = REQUEST.form.get('pattern' '')
        agent = self._get_ldap_agent()

        output_file = StringIO()
        csv_file = csv.writer(output_file)
        csv_file.writerow(['Role', 'Name', 'User ID', 'Email', 'Tel/Fax',
                           'Organisation'])

        for role_id, role_data in filter_roles(agent, pattern).iteritems():
            for user_info in role_data['users']:
                row = []
                for field in ['role_id', 'full_name', 'id', 'email', 'tel/fax',
                              'organisation']:
                    if field == 'role_id':
                        value = role_id
                    elif field == 'tel/fax':
                        value = ', '.join(filter(None, [user_info['phone'],
                                                        user_info['fax']]))
                    else:
                        value = user_info[field]
                    row += [value]
                csv_file.writerow([v.encode('utf-8') for v in row])

        REQUEST.RESPONSE.setHeader('Content-Type', 'text/csv')
        filename = 'Eionet users in %s.csv' % pattern.replace('*', 'ANY')
        REQUEST.RESPONSE.setHeader("Content-Disposition",
                                   "attachment; filename=\"%s\"" % filename)
        return codecs.BOM_UTF8 + output_file.getvalue()

    security.declareProtected(view, 'can_edit_roles')
    def can_edit_roles(self, user):
        return bool(user.has_permission(eionet_edit_roles, self))

    security.declareProtected(view, 'can_edit_members')
    def can_edit_members(self, role_id, user):
        """
        This could have been done as a decorator, but unfortunatelly
        Zope Publisher fails to match url address to callable when the
        arguments have arbitrary number

        """
        if user.name == 'Anonymous User':
            return False
        if self.can_edit_roles(user):
            return True
        if not role_id:
            # top role - can_edit_roles check was sufficient for granting
            return False

        agent = self._get_ldap_agent()
        role_info = agent.role_info(role_id)
        return agent._user_dn(user.getId()) in role_info['owner']

    security.declareProtected(view, 'can_delete_role')
    def can_delete_role(self, role_id, user):
        """
        A role can also be deleted by owner if it does not contain any members
        or any subroles.

        """
        if user.name == 'Anonymous User':
            return False
        if self.can_edit_roles(user):
            return True
        if not role_id:
            # top role - can_edit_roles check was sufficient for granting
            return False
        agent = self._get_ldap_agent()
        role_info = agent.role_info(role_id)
        if agent._user_dn(user.getId()) not in role_info['owner']:
            return False
        # faster than members_in_role
        role_members = agent.members_in_role_and_subroles(role_id)
        if role_members['orgs'] or role_members['users']:
            return False
        return not agent.role_names_in_role(role_id)

    security.declareProtected(view, 'create_role_html')
    def create_role_html(self, REQUEST):
        """ view """
        parent_role_id = REQUEST.form['parent_role_id']
        if not self.can_edit_members(parent_role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to create roles in %s" %
                               parent_role_id)
        options = {
            'parent_id': parent_role_id,
        }
        session = REQUEST.SESSION
        if SESSION_FORM_DATA in session.keys():
            options['form_data'] = session[SESSION_FORM_DATA]
            del session[SESSION_FORM_DATA]

        self._set_breadcrumbs(self._role_parents_stack(parent_role_id) +
                              [("Create sub-role", '#')])
        return self._render_template('zpt/roles_create.zpt', **options)

    def _make_role(self, agent, slug, parent_role_id, description):
        assert isinstance(slug, basestring)
        if not slug:
            raise RoleCreationError(["Role name is required."])
        for ch in slug:
            if ch not in ascii_lowercase:
                msg = ("Invalid Role ID, it must contain only lowercase "
                       "latin letters.")
                if ch == '-':
                    msg += (" Only input the subrole extension, not the "
                            "complete id that contains dashes ('-').")
                raise RoleCreationError([msg])

        if parent_role_id is None:
            role_id = slug
        else:
            role_id = parent_role_id + '-' + slug

        try:
            agent.create_role(str(role_id), description)
        except ValueError, e:
            msg = unicode(e)
            if 'DN already exists' in msg:
                msg = 'Role "%s" already exists.' % slug
            raise RoleCreationError([msg])

        return role_id

    security.declareProtected(view, 'create_role')
    def create_role(self, REQUEST):
        """ add a role """
        user_id = logged_in_user(REQUEST)
        agent = self._get_ldap_agent(bind=True)
        slug = REQUEST.form['slug']
        description = REQUEST.form['description']
        parent_role_id = REQUEST.form.get('parent_role_id', '') or None
        if not self.can_edit_members(parent_role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to create roles in %s" %
                               parent_role_id)

        try:
            role_id = self._make_role(agent, slug, parent_role_id, description)
        except RoleCreationError, e:
            for msg in e.messages:
                _set_session_message(REQUEST, 'error', msg)
            REQUEST.RESPONSE.redirect(self.absolute_url() +
                                      '/create_role_html?parent_role_id=' +
                                      (parent_role_id or ''))
            form_data = {'slug': slug, 'description': description}
            REQUEST.SESSION[SESSION_FORM_DATA] = form_data
        else:
            msg = u'Created role %s' % role_id
            if description:
                msg += u' "%s"' % description
            _set_session_message(REQUEST, 'info', msg)

            log.info("%s CREATED ROLE %s", user_id, role_id)
            try:
                agent.add_role_owner(role_id, user_id)
            except Exception, e:
                msg = ("Can not set owner '%r' for role '%r': %r"
                       % (user_id, role_id, e.args))
                _set_session_message(REQUEST, 'error', msg)
            else:
                log.info("%s ADDED %s OWNER for ROLE %s" %
                         (user_id, user_id, role_id))

            REQUEST.RESPONSE.redirect(self.absolute_url() +
                                      '/?role_id=' + role_id)

    security.declareProtected(view, 'delete_role_html')
    def delete_role_html(self, REQUEST):
        """ view """
        role_id = REQUEST.form['role_id']
        if not self.can_delete_role(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized(("You are not allowed to delete role %s. "
                                "Owners can only delete empty roles") % role_id)
        agent = self._get_ldap_agent()

        to_remove = map(agent._role_id, agent._sub_roles(role_id))
        options = {
            'role_id': role_id,
            'roles_to_remove': to_remove,
        }

        self._set_breadcrumbs(self._role_parents_stack(role_id) +
                              [("Delete role", '#')])
        return self._render_template('zpt/roles_delete.zpt', **options)

    security.declareProtected(view, 'delete_role')
    def delete_role(self, REQUEST):
        """ remove a role and all its sub-roles """
        role_id = REQUEST.form['role_id']
        if not self.can_delete_role(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized(("You are not allowed to delete role %s. "
                                "Owners can only delete empty roles") % role_id)
        logged_in = logged_in_user(REQUEST)
        agent = self._get_ldap_agent(bind=True)
        # first remove users from role
        for user_id in agent.members_in_role_and_subroles(role_id)['users']:
            self._remove_user_from_role(user_id, role_id, logged_in)
        agent.delete_role(role_id)
        parent_role_id = '-'.join(role_id.split('-')[:-1])
        _set_session_message(REQUEST, 'info', "Removed role %s" % role_id)

        log.info("%s DELETED ROLE %s", logged_in, role_id)

        rel_url = '/?role_id=' + parent_role_id if parent_role_id else '/'
        REQUEST.RESPONSE.redirect(self.absolute_url() + rel_url)

    security.declareProtected(view, 'add_member_html')
    def add_member_html(self, REQUEST):
        """ view """
        role_id = REQUEST.form['role_id']
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)
        search_name = REQUEST.form.get('name', '')
        options = {
            'role_id': role_id,
            'search_name': search_name,
            'search_results': None,
        }
        if search_name:
            agent = self._get_ldap_agent()
            options['search_results'] = {
                'users': agent.search_user(search_name)
            }

        self._set_breadcrumbs(self._role_parents_stack(role_id) +
                              [("Add member", '#')])
        return self._render_template('zpt/roles_add_member.zpt', **options)

    security.declareProtected(view, 'add_user')
    def add_user(self, REQUEST):
        """ Add user `user_id` to role `role_id` """
        role_id = REQUEST.form['role_id']
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)
        user_id = REQUEST.form['user_id']
        agent = self._get_ldap_agent(bind=True)
        role_id_list = agent.add_to_role(role_id, 'user', user_id)
        roles_msg = roles_list_to_text(agent, role_id_list)
        msg = "User %r added to roles %s." % (user_id, roles_msg)
        _set_session_message(REQUEST, 'info', msg)
        log.info("%s ADDED USER %s to ROLE(S) %r",
                      logged_in_user(REQUEST), user_id, role_id_list)

        REQUEST.RESPONSE.redirect(self.absolute_url() + '/?role_id=' + role_id)

    security.declareProtected(view, 'remove_members_html')
    def remove_members_html(self, REQUEST):
        """ Bulk-remove several members """
        role_id = REQUEST.form['role_id']
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)
        agent = self._get_ldap_agent()
        options = {
            'role_id': role_id,
            'role_members': role_members(agent, role_id),
        }

        self._set_breadcrumbs(self._role_parents_stack(role_id) +
                              [("Remove members", "#")])
        return self._render_template('zpt/roles_remove_members.zpt', **options)

    security.declareProtected(view, 'remove_members')
    def remove_members(self, REQUEST):
        """ Remove user several members from a role """
        agent = self._get_ldap_agent(bind=True)
        role_id = REQUEST.form['role_id']
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)
        role_name = get_role_name(agent, role_id)
        user_id_list = REQUEST.form.get('user_id_list', [])
        assert type(user_id_list) is list

        if user_id_list:
            for user_id in user_id_list:
                roles_id_list = agent.remove_from_role(role_id, 'user', user_id)
                log.info("%s REMOVED USER %s FROM ROLES %r",
                          logged_in_user(REQUEST), user_id, roles_id_list)

            msg = "Users %r removed from role %r" % (user_id_list, role_name)
            _set_session_message(REQUEST, 'info', msg)

        REQUEST.RESPONSE.redirect(self.absolute_url()+'/?role_id='+role_id)

    security.declareProtected(view, 'remove_user_from_role_html')
    def remove_user_from_role_html(self, REQUEST):
        """ view """
        role_id = REQUEST.form['role_id']
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)
        user_id = REQUEST.form['user_id']
        agent = self._get_ldap_agent()
        user_roles = agent.list_member_roles('user', user_id)
        options = {
            'role_id': role_id,
            'user_id': user_id,
            'role_id_list': sorted(r for r in user_roles
                                   if agent.is_subrole(r, role_id)),
        }

        return self._render_template('zpt/roles_remove_user.zpt', **options)

    def _remove_user_from_role(self, user_id, role_id, logged_in):
        """
        Remove user_id from role_id. logged_in is required to log
        this action. Called by remove_user_from_role and delete_role

        """
        agent = self._get_ldap_agent(bind=True)
        role_id_list = agent.remove_from_role(role_id, 'user', user_id)
        log.info("%s REMOVED USER %r FROM ROLE(S) %r",
                 logged_in, user_id, role_id_list)
        return role_id_list

    security.declareProtected(view, 'remove_user_from_role')
    def remove_user_from_role(self, REQUEST):
        """ Remove a single user from the role """
        role_id = REQUEST.form['role_id']
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)
        user_id = REQUEST.form['user_id']
        logged_in = logged_in_user(REQUEST)

        role_id_list = self._remove_user_from_role(user_id, role_id, logged_in)

        roles_msg = ', '.join(repr(r) for r in role_id_list)
        msg = "User %r removed from roles %s." % (user_id, roles_msg)
        _set_session_message(REQUEST, 'info', msg)

        REQUEST.RESPONSE.redirect(self.absolute_url() +
                                  '/search_users?user_id=' + user_id)

    security.declareProtected(eionet_edit_roles, 'search_users')
    def search_users(self, REQUEST):
        """ view """
        search_name = REQUEST.form.get('name', '')
        user_id = REQUEST.form.get('user_id', None)
        options = {
            'search_name': search_name,
            'user_id': user_id,
        }

        if search_name:
            agent = self._get_ldap_agent()
            options['search_results'] = agent.search_user(search_name)

        if user_id is not None:
            agent = self._get_ldap_agent()
            options['user_roles'] = agent.list_member_roles('user', user_id)

        return self._render_template('zpt/roles_search_users.zpt', **options)

    security.declareProtected(view, 'export_members')
    def export_members(self, REQUEST):
        """ Exports csv of members in role given by role_id in QUERY_STRING """
        role_id = REQUEST.form.get('role_id', None)
        subroles = REQUEST.form.get('subroles', None) in [True, 'true', 'True']
        if not REQUEST.AUTHENTICATED_USER:
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)
        output = StringIO()
        if subroles:
            filename = "%s_all_members.csv" % str(role_id)
        else:
            filename = "%s_members.csv" % str(role_id)
        REQUEST.RESPONSE.setHeader('Content-Type', 'text/csv')
        REQUEST.RESPONSE.setHeader('Content-Disposition',
                           "attachment;filename=%s" % filename)
        header = ('Name', 'User ID', 'Email', 'Tel', 'Fax', 'Postal Address',
                  'Organisation')
        csv_writer = csv.writer(output)
        csv_writer.writerow(header)

        agent = self._get_ldap_agent()
        try:
            role_info = agent.role_info(role_id)
        except usersdb.RoleNotFound:
            REQUEST.RESPONSE.setStatus(404)
            options = {'message': "Role %s does not exist." % role_id}
            return self._render_template('zpt/generic_error.zpt', **options)

        members = role_members(agent, role_id, subroles)
        keys = sorted(members['users'].keys())

        for u_id in keys:
            usr = members['users'][u_id]
            row = [usr['full_name'], usr['id'], usr['email'],
                         usr['phone'], usr['fax'], usr['postal_address'],
                         usr['organisation']]
            csv_writer.writerow([value.encode('utf-8') for value in row])

        return codecs.BOM_UTF8 + output.getvalue()

    security.declareProtected(view, 'edit_owners')
    def edit_owners(self, REQUEST):
        """ Manage owners of a role """
        role_id = REQUEST.form.get('role_id')
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)
        agent = self._get_ldap_agent(bind=True)
        options = {'role_id': role_id,
                   'role_owners': {}}
        user_id_list = REQUEST.form.get('user_id_list', [])

        if REQUEST.REQUEST_METHOD == 'POST':
            action = REQUEST.form.get('action')
            if action == 'remove-owners':
                for owner in user_id_list:
                    try:
                        agent.remove_role_owner(role_id, owner)
                    except Exception, e:
                        t, msg = 'error', 'Error removing owner %s: %r' % (owner, e.args)
                    else:
                        t, msg = 'info', 'Successfully removed owner %r' % owner
                        log.info("%s REMOVED OWNER %r FOR ROLE %s",
                                  logged_in_user(REQUEST), owner, role_id)
                    _set_session_message(REQUEST, t, msg)
            elif action == 'search':
                search_name = REQUEST.form.get('name')
                options.update({'search_name': search_name,
                                'results': dict((x['id'], x) for x in
                                               agent.search_user(search_name))})
            elif action == 'add-owners':
                for owner in user_id_list:
                    try:
                        agent.add_role_owner(role_id, owner)
                    except Exception, e:
                        t, msg = 'error', 'Error adding owner %s: %r' % (owner, e.args)
                    else:
                        t, msg = 'info', 'Successfully added owner %r' % owner
                        log.info("%s ADDED OWNER %r FOR ROLE %s",
                                  logged_in_user(REQUEST), owner, role_id)
                    _set_session_message(REQUEST, t, msg)

        mailgroup_info = agent.mail_group_info(role_id)
        for owner in mailgroup_info['owner']:
            options['role_owners'][owner] = agent.user_info(owner)
        self._set_breadcrumbs(self._role_parents_stack(role_id) +
                              [("Manage owners", "#")])
        return self._render_template('zpt/roles_edit_owners.zpt', **options)

    security.declareProtected(view, 'edit_senders')
    def edit_senders(self, REQUEST, extra_opts={}):
        """ Manage mail group senders of a role """
        role_id = REQUEST.form.get('role_id')
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage senders in %s" %
                               role_id)
        agent = self._get_ldap_agent()
        data = agent.mail_group_info(role_id)
        data['emails'] = '\n'.join([e for e in data['permittedSender'] if '@' in e])
        options = {'role_id': role_id, 'data': data, 'user_info': {}}
        for user in data['permittedPerson']:
            try:
                options['user_info'][user] = agent.user_info(user)
            except usersdb.UserNotFound:
                options['user_info'][user] = {'id': user, 'deleted': True}

        self._set_breadcrumbs(self._role_parents_stack(role_id) +
                              [("Manage senders", "#")])
        options.update(extra_opts)
        return self._render_template('zpt/roles_edit_senders.zpt', **options)

    security.declareProtected(view, 'edit_senders_senders')
    def edit_senders_senders(self, REQUEST):
        """ Form actions for senders in Manage mail group senders of a role """
        role_id = REQUEST.form.get('role_id')
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage senders in %s" %
                               role_id)
        agent = self._get_ldap_agent(bind=True)
        if REQUEST.REQUEST_METHOD == 'POST':
            senders = REQUEST.form.get('senders', [])
            emails = REQUEST.form.get('emails', '').strip().lower()
            emails = re.split(r'[\s;,]+', emails)
            if '' in emails:
                emails.remove('')
            senders.extend(emails)
            role_info = agent.role_info(role_id)
            for existing in role_info['permittedSender']:
                if existing not in senders:
                    try:
                        agent.remove_permittedSender(role_id, existing)
                    except Exception, e:
                        t, msg = 'error', 'Error removing sender %s: %r' % (existing, e.args)
                    else:
                        t, msg = 'info', 'Successfully removed sender %r' % existing
                        log.info("%s REMOVED PERMITTEDSENDER %r FOR ROLE %s",
                                  logged_in_user(REQUEST), existing, role_id)
                    _set_session_message(REQUEST, t, msg)

            for sender in senders:
                if sender not in role_info['permittedSender']:
                    try:
                        agent.add_permittedSender(role_id, sender)
                    except Exception, e:
                        t, msg = 'error', 'Error adding sender %s: %r' % (sender, e.args)
                    else:
                        t, msg = 'info', 'Successfully added sender %r' % sender
                        log.info("%s ADDED PERMITTEDSENDER %r FOR ROLE %s",
                                  logged_in_user(REQUEST), sender, role_id)
                    _set_session_message(REQUEST, t, msg)

        return self.edit_senders(REQUEST)

    security.declareProtected(view, 'edit_senders_persons')
    def edit_senders_persons(self, REQUEST):
        """ Form actions for persons in Manage mail group senders of a role """
        role_id = REQUEST.form.get('role_id')
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            raise Unauthorized("You are not allowed to manage senders in %s" %
                               role_id)
        agent = self._get_ldap_agent(bind=True)
        if REQUEST.REQUEST_METHOD == 'POST':
            user_id_list = REQUEST.form.get('user_id_list', [])
            action = REQUEST.form.get('action')
            if action == 'remove-persons':
                for sender in user_id_list:
                    try:
                        agent.remove_permittedPerson(role_id, sender)
                    except Exception, e:
                        t, msg = 'error', 'Error removing sender %s: %r' % (sender, e.args)
                    else:
                        t, msg = 'info', 'Successfully removed sender %r' % sender
                        log.info("%s REMOVED PERMITTEDPERSON %r FOR ROLE %s",
                                  logged_in_user(REQUEST), sender, role_id)
                    _set_session_message(REQUEST, t, msg)
            elif action == 'search':
                search_name = REQUEST.form.get('name')
                extra_opts = {'search_name': search_name,
                              'results': dict((x['id'], x) for x in
                                               agent.search_user(search_name))}
                return self.edit_senders(REQUEST, extra_opts=extra_opts)
            elif action == 'add-persons':
                for sender in user_id_list:
                    try:
                        agent.add_permittedPerson(role_id, sender)
                    except Exception, e:
                        t, msg = 'error', 'Error adding sender %s: %r' % (sender, e.args)
                    else:
                        t, msg = 'info', 'Successfully added sender %r' % sender
                        log.info("%s ADDED PERMITTEDPERSON %r FOR ROLE %s",
                                  logged_in_user(REQUEST), sender, role_id)
                    _set_session_message(REQUEST, t, msg)
        return self.edit_senders(REQUEST)

    security.declareProtected(view, 'all_members')
    def all_members(self, REQUEST):
        """
        Lists all users of a specified role

        """
        role_id = REQUEST.form.get('role_id', None)
        if not REQUEST.AUTHENTICATED_USER:
            raise Unauthorized("You are not allowed to manage members in %s" %
                               role_id)

        agent = self._get_ldap_agent()
        try:
            role_info = agent.role_info(role_id)
        except usersdb.RoleNotFound:
            REQUEST.RESPONSE.setStatus(404)
            options = {'message': "Role %s does not exist." % role_id}
            return self._render_template('zpt/generic_error.zpt', **options)

        list =role_members(agent, role_id, True)
        users = {}
        for user_id in list['users']:
            try:
                users[user_id] = agent.user_info(user_id)
            except usersdb.UserNotFound:
                pass

        options = {
            'role_id': role_id,
            'list': users,
            'role_info': role_info,
            'role_members': role_members(agent, role_id),
            'can_edit': self.can_edit_roles(REQUEST.AUTHENTICATED_USER),
            'can_edit_members': self.can_edit_members(role_id,
                                             REQUEST.AUTHENTICATED_USER),
        }

        self._set_breadcrumbs(self._role_parents_stack(role_id) +
                              [("All members", "#")])
        return self._render_template('zpt/roles_all_members.zpt', **options)

    security.declareProtected(view, 'edit_role_name')
    def edit_role_name(self, REQUEST):
        """ Form actions for persons in Manage mail group senders of a role """
        role_id = REQUEST.form.get('role_id')
        if not self.can_edit_members(role_id, REQUEST.AUTHENTICATED_USER):
            return json.dumps({'error':
                        "You are not allowed to manage senders in %s" % role_id
                        })
        if REQUEST.REQUEST_METHOD == 'POST':
            description = REQUEST.form.get('role_name')
            agent = self._get_ldap_agent(bind=True)
            try:
                agent.set_role_description(role_id, description)
            except Exception, e:
                return json.dumps({'error': unicode(e)})
            else:
                log.info("%s SET DESCRIPTION %r FOR ROLE %s",
                                  logged_in_user(REQUEST), description, role_id)
                return json.dumps({'error': False})

    security.declareProtected(view_management_screens, 'manage_add_query_html')
    manage_add_query_html = query.manage_add_query_html

    security.declareProtected(view_management_screens, 'manage_add_query')
    manage_add_query = query.manage_add_query

    def _role_parents_stack(self, role_id):
        return [(role_id, self.absolute_url() + '/?role_id=%s' % role_id)
                for role_id in _role_parents(role_id)]

    def _set_breadcrumbs(self, stack):
        self.REQUEST._roles_editor_crumbs = stack

    def breadcrumbtrail(self):
        crumbs_html = self.aq_parent.breadcrumbtrail(self.REQUEST)
        extra_crumbs = getattr(self.REQUEST, '_roles_editor_crumbs', [])
        return extend_crumbs(crumbs_html, self.absolute_url(), extra_crumbs)


InitializeClass(RolesEditor)

def extend_crumbs(crumbs_html, editor_url, extra_crumbs):
    from lxml.html.soupparser import fromstring
    from lxml.html import tostring
    from lxml.builder import E

    crumbs = fromstring(crumbs_html).find('div[@class="breadcrumbtrail"]')

    roles_div = crumbs.find('div[@class="breadcrumbitemlast"]')
    roles_div.attrib['class'] = "breadcrumbitem"
    roles_link = E.a(roles_div.text, href=editor_url)
    roles_div.text = ""
    roles_div.append(roles_link)

    for title, href in extra_crumbs:
        a = E.a(title, {'href': href})
        div = E.div(a, {'class': 'breadcrumbitem'})
        crumbs.append(div)

    last_crumb = crumbs.xpath('div[@class="breadcrumbitem"]')[-1]
    last_crumb_text = last_crumb.find('a').text
    last_crumb.clear()
    last_crumb.attrib['class'] = "breadcrumbitemlast"
    last_crumb.text = last_crumb_text

    return tostring(crumbs)
