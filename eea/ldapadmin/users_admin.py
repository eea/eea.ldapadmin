from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from App.class_init import InitializeClass
from App.config import getConfiguration
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from datetime import datetime
from eea import usersdb
from eea.ldapadmin import eionet_profile
from eea.ldapadmin.constants import NETWORK_NAME
from eea.ldapadmin.help_messages import help_messages
from eea.ldapadmin.logic_common import _session_pop
from eea.usersdb import factories
from email.mime.text import MIMEText
from import_export import (excel_headers_to_object, generate_excel,
                           set_response_attachment)
from persistent.mapping import PersistentMapping
from ui_common import CommonTemplateLogic   # load_template,
from ui_common import SessionMessages, TemplateRenderer
from ui_common import extend_crumbs, TemplateRendererNoWrap
from unidecode import unidecode
from zope.component import getUtility
from zope.component.interfaces import ComponentLookupError
from zope.sendmail.interfaces import IMailDelivery
import deform
import colander
import jellyfish
import ldap
import ldap_config
import logging
import os
import random
import re
import sqlite3
import string
import xlrd

try:
    import simplejson as json
except ImportError:
    import json


log = logging.getLogger('users_admin')

user_info_add_schema = usersdb.user_info_schema.clone()
user_info_edit_schema = usersdb.user_info_schema.clone()

user_info_add_schema.children.insert(0, usersdb.schema._uid_node)
user_info_add_schema.children.insert(1, usersdb.schema._password_node)
user_info_add_schema['postal_address'].widget = deform.widget.TextAreaWidget()
user_info_edit_schema['postal_address'].widget = deform.widget.TextAreaWidget()

CONFIG = getConfiguration()
FORUM_URL = getattr(CONFIG, 'environment', {}).get('FORUM_URL', '')
TEMPLATE_COLUMNS = ["User ID*", "Password*", "First Name*", "Last Name*",
                    "E-mail*", "Job Title", "URL", "Postal Address",
                    "Telephone Number", "Mobile Telephone Number",
                    "Fax Number", "Organisation"]

password_letters = '23456789ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def generate_password():
    return ''.join(random.choice(password_letters) for n in range(8))


def generate_user_id(first_name, last_name, agent, id_list):
    min_first_length = min(first_name, 3)
    uid1 = last_name[:8-min_first_length]
    uid2 = first_name[:8-len(uid1)]
    base_uid = (uid1+uid2).lower()
    if not(list(agent.existing_usernames([base_uid]))
           or base_uid in id_list):
        return base_uid
    for i in range(8):
        for letter in string.lowercase:
            new_uid = base_uid[:8-i-1] + letter + base_uid[8-i:]
            if not(list(agent.existing_usernames([new_uid]))
                   or new_uid in id_list):
                return new_uid


def process_url(url):
    if url and not (url.startswith('http://') or url.startswith('https://')):
        return 'http://'+url
    return url

eionet_edit_users = 'Eionet edit users'

manage_add_users_admin_html = PageTemplateFile('zpt/users_manage_add',
                                               globals())
manage_add_users_admin_html.ldap_config_edit_macro = ldap_config.edit_macro
manage_add_users_admin_html.config_defaults = lambda: ldap_config.defaults


def manage_add_users_admin(parent, id, REQUEST=None):
    """ Create a new UsersAdmin object """
    if REQUEST is not None:
        form = REQUEST.form
    else:
        form = {}
    config = ldap_config.read_form(form)
    obj = UsersAdmin(config)
    obj.title = form.get('title', id)
    obj._setId(id)
    parent._setObject(id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')


def _is_authenticated(request):
    return ('Authenticated' in request.AUTHENTICATED_USER.getRoles())


def get_users_by_ldap_dump():
    LDAP_DISK_STORAGE = getattr(CONFIG, 'environment',
                                {}).get('LDAP_DISK_STORAGE', '')
    DB_FILE = os.path.join(LDAP_DISK_STORAGE, 'ldap_eionet_europa_eu.db')
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT a.dn as dn, a.value AS cn "
        "FROM ldapmapping a WHERE a.attr = 'cn' "
    )

    ldap_user_records = []
    for data in cursor.fetchall():
        ldap_user_records.append({'dn': data['dn'],
                                  'cn': unidecode(data['cn'])})
    return ldap_user_records


def get_duplicates_by_name(name):
    ldap_users = get_users_by_ldap_dump()

    records = []
    for user in ldap_users:
        distance = jellyfish.jaro_winkler(name, user['cn'])
        if distance >= UsersAdmin.similarity_level:
            records.append(user['dn'])

    return records

SESSION_PREFIX = 'eea.ldapadmin.users_admin'
SESSION_MESSAGES = SESSION_PREFIX + '.messages'
SESSION_FORM_DATA = SESSION_PREFIX + '.form_data'
SESSION_FORM_ERRORS = SESSION_PREFIX + '.form_errors'


def _set_session_message(request, msg_type, msg):
    SessionMessages(request, SESSION_MESSAGES).add(msg_type, msg)


def logged_in_user(request):
    user_id = ''
    if _is_authenticated(request):
        user = request.get('AUTHENTICATED_USER', '')
        user_id = user.id

    return user_id


# this class should be called UsersEditor, similar to OrganisationsEditor
# and RolesEditor. But the name UsersEditor is already used by the
# `eea.userseditor` package, which lets users edit their own profile info.
class UsersAdmin(SimpleItem, PropertyManager):
    meta_type = 'Eionet Users Admin'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_users_admin.gif'
    similarity_level = 0.939999
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

    def _set_breadcrumbs(self, stack):
        self.REQUEST._users_admin_crumbs = stack

    def breadcrumbtrail(self):
        crumbs_html = self.aq_parent.breadcrumbtrail(self.REQUEST)
        extra_crumbs = getattr(self.REQUEST, '_users_admin_crumbs', [])
        return extend_crumbs(crumbs_html, self.absolute_url(), extra_crumbs)

    def _user_bread(self, id, stack):
        """ Prepends a breadcrumb with link to main user page """
        stack.insert(0, (id, self.absolute_url() + "/edit_user?id=" + id))
        return stack

    def __init__(self, config={}):
        super(UsersAdmin, self).__init__()
        self._config = PersistentMapping(config)

    security.declareProtected(view_management_screens, 'get_config')

    def get_config(self):
        return dict(self._config)

    security.declareProtected(view_management_screens, 'manage_edit')
    manage_edit = PageTemplateFile('zpt/users_manage_edit', globals())
    manage_edit.ldap_config_edit_macro = ldap_config.edit_macro

    security.declareProtected(view_management_screens, 'manage_edit_save')

    def manage_edit_save(self, REQUEST):
        """ save changes to configuration """
        self._config.update(ldap_config.read_form(REQUEST.form, edit=True))
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_edit')

    def _get_ldap_agent(self, bind=False):
        agent = ldap_config.ldap_agent_with_config(self._config, bind)
        agent._author = logged_in_user(self.REQUEST)
        return agent

    security.declareProtected(view, 'can_edit_users')

    def can_edit_users(self, user):
        return bool(user.has_permission(eionet_edit_users, self))

    security.declareProtected(eionet_edit_users, 'index_html')

    def index_html(self, REQUEST):
        """ view """
        options = {
            'can_edit': self.can_edit_users(REQUEST.AUTHENTICATED_USER),
            'search_fields': usersdb.db_agent.ACCEPTED_SEARCH_FIELDS,
        }

        search_name = REQUEST.form.get('name', '')
        lookup = REQUEST.form.get('lookup', '')
        options.update({
            'search_name': search_name,
            'lookup': lookup,
        })

        if search_name:
            agent = self._get_ldap_agent()
            results = sorted(agent.search_user(search_name, lookup),
                             key=lambda x: x['full_name'])
            options['search_results'] = results
        return self._render_template('zpt/users_index.zpt', **options)

    security.declareProtected(eionet_edit_users, 'get_statistics')

    def get_statistics(self, REQUEST):
        """ view a simple table of how many users have been registered,
        for each year

        For reasons which are unclear, we need to use two agents:
        * one will be binded with the LDAP special user account. The account
          needs to have no limits on number of results return by LDAP server
        * the second agent is based on code in eea.userseditor/userdetails.py.
        It gets access to the createTimestamp attribute

        The problem is that the first user is not able to retrieve the
        createTimestamp for all users. For those which are retrieved it
        contains a longer string (has microseconds as well)
        """

        agent = self._get_ldap_agent(bind=True)
        unbound_agent = factories.agent_from_uf(
            self.restrictedTraverse("/acl_users"))

        msgid = agent.conn.search_ext(
            agent._user_dn_suffix,
            ldap.SCOPE_ONELEVEL,
            '(objectClass=organizationalPerson)',
            attrlist=['*', 'uid', 'createTimestamp', 'modifyTimestamp']
        )

        all_results = []

        for res_type, result, res_msgid, res_controls in agent.conn.allresults(
                msgid):
            for rdn, ldap_obj in result:
                created = ldap_obj.get('createTimestamp')
                if not created:
                    user_info = unbound_agent.user_info(
                        unbound_agent._user_id(rdn))
                    all_results.append((rdn, user_info))
                else:
                    all_results.append(
                        (rdn, agent._unpack_user_info(rdn, ldap_obj)))

        stats = {}
        for dn, rec in all_results:
            year = rec['createTimestamp'].year
            if year not in stats:
                stats[year] = 0
            stats[year] += 1

        options = {'stats': stats}

        return self._render_template('zpt/statistics.zpt', **options)

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

    security.declarePrivate('_create_user')

    def _create_user(self, agent, user_info):
        """
        Creates user in ldap using user_info (data already validated)

        """
        # remove id and password from user_info, so these will not
        # appear as properties on the user
        user_id = str(user_info.pop('id'))
        password = str(user_info.pop('password'))
        agent._update_full_name(user_info)
        agent.create_user(user_id, user_info)
        agent.set_user_password(user_id, None, password)
        # put id and password back on user_info, for further processing
        # (mainly sending of email)
        user_info['id'] = user_id
        user_info['password'] = password
        return user_id

    security.declareProtected(eionet_edit_users, 'confirmation_email')

    def confirmation_email(self, first_name, user_id, REQUEST=None):
        """ Returns body of confirmation email """
        options = {'first_name': first_name, 'user_id': user_id}
        options['site_title'] = self.unrestrictedTraverse('/').title
        return self._render_template.render(
            "zpt/users/email_registration_confirmation.zpt",
            **options)

    security.declareProtected(eionet_edit_users, 'create_user')

    def create_user(self, REQUEST):
        """ view """
        form_data = dict(REQUEST.form)
        errors = {}
        if not form_data.get('password', ''):
            form_data['password'] = generate_password()

        if 'submit' in REQUEST.form:
            try:
                user_form = deform.Form(user_info_add_schema)
                user_info = user_form.validate(form_data.items())

            except deform.ValidationFailure, e:
                for field_error in e.error.children:
                    errors[field_error.node.name] = field_error.msg
                msg = u"Please correct the errors below and try again."
                _set_session_message(REQUEST, 'error', msg)

            else:
                user_id = user_info['id']
                agent = self._get_ldap_agent(bind=True)
                self._create_user(agent, user_info)

                send_confirmation = 'send_confirmation' in form_data.keys()
                if send_confirmation:
                    self.send_confirmation_email(user_info)
                    self.send_password_reset_email(user_info)

                when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                msg = "User %s created (%s)" % (user_id, when)
                _set_session_message(REQUEST, 'info', msg)

                log.info("%s CREATED USER %s",
                         logged_in_user(REQUEST),
                         user_id)

                return REQUEST.RESPONSE.redirect(self.absolute_url())

        self._set_breadcrumbs([('Create User', '#')])
        for children in user_info_add_schema.children:
            help_text = help_messages['create-user'].get(children.name, None)
            setattr(children, 'help_text', help_text)

        options = {
            'form_data': form_data,
            'errors': errors,
            'schema': user_info_add_schema,
        }
        return self._render_template('zpt/users/create.zpt', **options)

    security.declareProtected(eionet_edit_users, 'find_duplicates')

    def find_duplicates(self, REQUEST):
        """ view """
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

    security.declareProtected(eionet_edit_users, 'edit_user')

    def edit_user(self, REQUEST):
        """
        View for editing profile information for a given user
        with id passed through GET

        """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent()
        errors = _session_pop(REQUEST, SESSION_FORM_ERRORS, {})
        user = agent.user_info(id)
        # message
        form_data = _session_pop(REQUEST, SESSION_FORM_DATA, None)
        if form_data is None:
            form_data = user
        options = {'user': user,
                   'form_data': form_data,
                   'schema': user_info_edit_schema,
                   'errors': errors,
                   'forum_url': FORUM_URL}
        self._set_breadcrumbs([(id, '#')])
        return self._render_template('zpt/users/edit.zpt', **options)

    security.declareProtected(eionet_edit_users, 'edit_user_action')

    def edit_user_action(self, REQUEST):
        """ view """
        id = REQUEST.form['id']

        user_form = deform.Form(user_info_edit_schema)

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
            agent = self._get_ldap_agent(bind=True)
            agent.set_user_info(id, user_data)
            when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _set_session_message(REQUEST, 'info', "Profile saved (%s)" % when)
            log.info("%s EDITED USER %s", logged_in_user(REQUEST), id)

        REQUEST.RESPONSE.redirect(self.absolute_url() + '/edit_user?id=' + id)

    security.declareProtected(eionet_edit_users, 'delete_user')

    def delete_user(self, REQUEST):
        """
        View that asks for confirmation of user deletion

        """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(id)
        options = {'user': user}
        self._set_breadcrumbs(self._user_bread(id, [("Delete User", '#')]))
        return self._render_template('zpt/users/delete.zpt', **options)

    security.declareProtected(eionet_edit_users, 'delete_user_action')

    def delete_user_action(self, REQUEST):
        """ Performing the delete action """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent(bind=True)
        agent.delete_user(id)

        _set_session_message(REQUEST, 'info',
                             'User "%s" has been deleted.' % id)

        log.info("%s DELETED USER %s", logged_in_user(REQUEST), id)

        REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

    security.declareProtected(eionet_edit_users, 'disable_user')

    def disable_user(self, REQUEST):
        """
        View that asks for confirmation of user disable

        """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(id)
        options = {'user': user}
        self._set_breadcrumbs(self._user_bread(id, [("Disable User", '#')]))
        return self._render_template('zpt/users/disable.zpt', **options)

    security.declareProtected(eionet_edit_users, 'disable_user_action')

    def disable_user_action(self, REQUEST):
        """ Performing the disable user action """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent(bind=True)
        agent.disable_user(id)

        _set_session_message(REQUEST, 'info',
                             'User "%s" has been disabled.' % id)

        log.info("%s DISABLED USER %s", logged_in_user(REQUEST), id)

        REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

    security.declareProtected(eionet_edit_users, 'enable_user')

    def enable_user(self, REQUEST):
        """
        View that asks for confirmation of user enable

        """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(id)
        options = {'user': user}
        self._set_breadcrumbs(self._user_bread(id, [("Enable User", '#')]))
        return self._render_template('zpt/users/enable.zpt', **options)

    security.declareProtected(eionet_edit_users, 'enable_user_action')

    def enable_user_action(self, REQUEST):
        """ Performing the enable user action """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent(bind=True)
        agent.enable_user(id)

        log.info("%s ENABLED USER %s", logged_in_user(REQUEST), id)

        user_info = agent.user_info(id)
        addr_from = "no-reply@eea.europa.eu"
        addr_to = user_info['email']

        email_password_body = self._render_template.render(
            "zpt/users/email_enabled_account.zpt", **user_info)

        message = MIMEText(email_password_body.encode('utf-8'),
                           _charset='utf-8')
        message['From'] = addr_from
        message['To'] = addr_to
        message['Subject'] = "%s Account - account enabled" % NETWORK_NAME
        try:
            mailer = getUtility(IMailDelivery, name="Mail")
            mailer.send(addr_from, [addr_to], message.as_string())
        except ComponentLookupError:
            mailer = getUtility(IMailDelivery, name="naaya-mail-delivery")
            mailer.send(addr_from, [addr_to], message.as_string())

        _set_session_message(REQUEST, 'info',
                             'Account enabled for "%s".' % id)

        REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

    security.declareProtected(eionet_edit_users, 'change_password')

    def change_password(self, REQUEST):
        """ View for changing user password """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(id)
        options = {'user': user, 'password': generate_password()}

        self._set_breadcrumbs(self._user_bread(id, [("Change Password", '#')]))
        return self._render_template('zpt/users/change_password.zpt',
                                     **options)

    security.declareProtected(eionet_edit_users, 'change_password_action')

    def change_password_action(self, REQUEST):
        """ Performing the delete action """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent(bind=True)
        password = str(REQUEST.form['password'])
        agent.set_user_password(id, None, password)

        user_info = agent.user_info(id)
        addr_from = "no-reply@eea.europa.eu"
        addr_to = user_info['email']
        email_password_body = self.email_password(user_info['first_name'],
                                                  password, 'change')
        message = MIMEText(email_password_body.encode('utf-8'),
                           _charset='utf-8')
        message['From'] = addr_from
        message['To'] = addr_to
        message['Subject'] = "%s Account - New password" % NETWORK_NAME
        try:
            mailer = getUtility(IMailDelivery, name="Mail")
            mailer.send(addr_from, [addr_to], message.as_string())
        except ComponentLookupError:
            mailer = getUtility(IMailDelivery, name="naaya-mail-delivery")
            mailer.send(addr_from, [addr_to], message)

        _set_session_message(REQUEST, 'info',
                             'Password changed for "%s".' % id)
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

    security.declareProtected(eionet_edit_users, 'bulk_check_username')

    def bulk_check_username(self, REQUEST):
        """ Bulk verify usernames for conformance """
        usernames = []
        form_data = REQUEST.form.get('usernames', None)
        if form_data:
            usernames = re.sub(r'[\s,]+', ' ', form_data).split(' ')
        options = {'usernames': usernames,
                   'valid': [], 'invalid': [], 'taken': []}
        if usernames:
            node = usersdb.schema._uid_node
            for user in usernames:
                try:
                    node.validator(node, user)
                except colander.Invalid:
                    options['invalid'].append(user)
                else:
                    options['valid'].append(user)
        if options['valid']:
            # search for availability
            agent = self._get_ldap_agent()
            existing = agent.existing_usernames(options['valid'])
            options['taken'] = list(existing)
            options['valid'] = list(set(options['valid']) -
                                    set(options['taken']))

        # sort lists
        for each_list in ('usernames', 'valid', 'taken'):
            options[each_list].sort()

        self._set_breadcrumbs([("Bulk Verify Usernames", '#')])
        return self._render_template('zpt/users/bulk_check_username.zpt',
                                     **options)

    security.declareProtected(eionet_edit_users, 'bulk_get_emails')

    def bulk_get_emails(self, REQUEST):
        """
        Return all email addresses
        """
        from ldap import NO_SUCH_OBJECT

        agent = self._get_ldap_agent()
        bulk_emails = []
        orgs = agent.all_organisations()

        for org_id, info in orgs.iteritems():
            members = agent.members_in_org(org_id)
            if members:
                for user_id in members:
                    try:
                        user_info = agent.user_info(user_id)
                        if user_info not in bulk_emails:
                            bulk_emails.append(str(user_info['email']))
                    except (NO_SUCH_OBJECT, usersdb.UserNotFound):
                        pass

        return json.dumps(bulk_emails)

    security.declareProtected(eionet_edit_users, 'bulk_check_email')

    def bulk_check_email(self, REQUEST):
        """ Bulk verify emails for conformance """
        # from ldap import NO_SUCH_OBJECT
        agent = self._get_ldap_agent()
        emails = []
        form_data = REQUEST.form.get('emails', None)
        if form_data:
            emails = re.sub(r'[\s,]+', ' ', form_data).split(' ')
        options = {'emails': emails,
                   'valid': [], 'invalid': [], 'taken': [], 'bulk_emails': []}
        if emails:
            node = user_info_add_schema['email']
            for email in emails:
                try:
                    node.validator(node, email)
                except colander.Invalid:
                    options['invalid'].append(email)
                else:
                    options['valid'].append(email)
        if options['valid']:
            # search for availability
            existing = agent.existing_emails(options['valid'])
            options['taken'] = list(existing)
            options['valid'] = list(set(options['valid']) -
                                    set(options['taken']))

        # sort lists
        for each_list in ('emails', 'valid', 'taken'):
            options[each_list].sort()

        self._set_breadcrumbs([("Bulk Verify Emails", '#')])
        return self._render_template('zpt/users/bulk_check_email.zpt',
                                     **options)

    security.declareProtected(eionet_edit_users, 'bulk_create_user')

    def bulk_create_user(self, REQUEST=None):
        """ upload view """
        return self._render_template('zpt/users/bulk_create.zpt')

    security.declareProtected(eionet_edit_users, 'download_template')

    def download_template(self, REQUEST):
        """ Force download of excel template """

        ret = generate_excel(TEMPLATE_COLUMNS, [[]])
        content_type = 'application/vnd.ms-excel'
        filename = 'create_users_template.xls'

        set_response_attachment(REQUEST.RESPONSE, filename, content_type,
                                len(ret))

        return ret

    security.declareProtected(eionet_edit_users, 'bulk_create_user_action')

    def bulk_create_user_action(self, data=None, REQUEST=None):
        """ view """
        errors = []
        file_errors = []
        successfully_imported = []

        try:
            wb = xlrd.open_workbook(file_contents=data.read())
            ws = wb.sheets()[0]
            header = ws.row_values(0)
            assert len(header) == len(TEMPLATE_COLUMNS)
            rows = []
            for i in range(ws.nrows)[1:]:
                rows.append(ws.row_values(i))

            users_data = []
            user_form = deform.Form(user_info_add_schema)
            agent = self._get_ldap_agent(bind=True)

            id_list = []
            for record_number, row in enumerate(rows):
                properties = {}
                for column, value in zip(header, row):
                    properties[column.lower()] = value
                row_data = excel_headers_to_object(properties)
                if not row_data['password']:
                    row_data['password'] = generate_password()
                if not row_data['id']:
                    row_data['id'] = generate_user_id(row_data['first_name'],
                                                      row_data['last_name'],
                                                      agent, id_list)
                id_list.append(row_data['id'])
                row_data['url'] = process_url(row_data['url'])
                try:
                    user_info = user_form.validate(row_data.items())
                    user_info['password'] = row_data['password']
                except deform.ValidationFailure, e:
                    for field_error in e.error.children:
                        errors.append('%s at row %d: %s' %
                                      (field_error.node.name, record_number+1,
                                       field_error.msg))
                else:
                    users_data.append(user_info)

        except xlrd.XLRDError:
            file_errors.append('Invalid Excel file')

        # cycled every object and stored them in users_data
        if not file_errors:
            emails = [x['email'] for x in users_data]
            usernames = [x['id'] for x in users_data]
            if len(emails) != len(set(emails)):
                for email in set(emails):
                    occourences = emails.count(email)
                    if occourences > 1:
                        errors.append('Duplicate email: %s appears %d times'
                                      % (email, occourences))
                        users_data = filter(lambda x: x['email'] != email,
                                            users_data)
            if len(usernames) != len(set(usernames)):
                for username in set(usernames):
                    occourences = usernames.count(username)
                    if occourences > 1:
                        errors.append('Duplicate user ID: %s appears %d times'
                                      % (username, occourences))
                        users_data = filter(lambda x: x['id'] != username,
                                            users_data)
            existing_emails = set(agent.existing_emails(list(set(emails))))
            existing_users = set(agent.existing_usernames(
                list(set(usernames))))
            if existing_emails:
                errors.append("The following emails are already in database"
                              + ": " + ', '.join(existing_emails))
                for email in existing_emails:
                    users_data = filter(lambda x: x['email'] != email,
                                        users_data)
            if existing_users:
                errors.append("The following user IDs are already registered"
                              + ": " + ', '.join(existing_users))
                for username in existing_users:
                    users_data = filter(lambda x: x['id'] != username,
                                        users_data)
            if users_data:
                # do the job for the users with no errors
                for user_info in users_data:
                    user_id = user_info['id']
                    try:
                        self._create_user(agent, user_info)
                    except Exception:
                        errors.append("Error creating %s user" % user_id)
                    else:
                        self.send_confirmation_email(user_info)
                        self.send_password_reset_email(user_info)
                        successfully_imported.append(user_id)

        errors.extend(file_errors)
        if errors:
            for err in errors:
                _set_session_message(REQUEST, 'error', err)
        if successfully_imported:
            _set_session_message(REQUEST, 'info',
                                 'User(s) %s successfully created.' %
                                 ', '.join(successfully_imported))
            logged_in = logged_in_user(REQUEST)
            for user_id in successfully_imported:
                log.info("%s CREATED USER %s", logged_in, user_id)
        else:
            _set_session_message(REQUEST, 'error', 'No user account created')
        self._set_breadcrumbs([("Create Accounts from File", '#')])
        return self._render_template('zpt/users/bulk_create.zpt')

    security.declareProtected(eionet_edit_users, 'eionet_profile')

    def eionet_profile(self, REQUEST):
        """ Renders eionet full profile page """
        uid = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(uid)
        options = {'user': user, 'services': eionet_profile.get_endpoints(),
                   'forum_url': FORUM_URL}
        return self._render_template('zpt/users/eionet_profile.zpt', **options)

    security.declareProtected(eionet_edit_users, 'eionet_profile')

    def get_endpoint(self, REQUEST):
        """ Returns call for a service """
        title = REQUEST.form['service']
        userid = REQUEST.form['userid']
        for service in eionet_profile.get_endpoints():
            if service['title'] == title:
                return json.dumps(eionet_profile.get_endpoint_data(service,
                                                                   userid))
        return json.dumps({})

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

    def send_password_reset_email(self, user_info):
        """ """
        pwreset_tool = self.restrictedTraverse('/')
        email = user_info['email']
        pwreset_tool.ask_for_password_reset(email=email)


InitializeClass(UsersAdmin)


def _send_email(addr_from, addr_to, message):
    try:
        mailer = getUtility(IMailDelivery, name="Mail")
        mailer.send(addr_from, [addr_to], message.as_string())
    except ComponentLookupError:
        mailer = getUtility(IMailDelivery, name="naaya-mail-delivery")
        mailer.send(addr_from, [addr_to], message)
