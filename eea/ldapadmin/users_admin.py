from datetime import datetime
import random
import re
import os
try:
    import simplejson as json
except ImportError:
    import json

from AccessControl import ClassSecurityInfo
from App.config import getConfiguration
from App.class_init import InitializeClass
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from OFS.SimpleItem import SimpleItem
from OFS.PropertyManager import PropertyManager
from AccessControl.Permissions import view, view_management_screens
from persistent.mapping import PersistentMapping
from zope.component import getUtility
from zope.component.interfaces import ComponentLookupError
from zope.sendmail.interfaces import IMailDelivery
from email.mime.text import MIMEText

import ldap_config
from ui_common import SessionMessages, TemplateRenderer, extend_crumbs
from import_export import UnicodeReader, csv_headers_to_object

import deform, colander
from eea import usersdb

from help_messages import help_messages
from constants import NETWORK_NAME

import logging
log = logging.getLogger('users_admin')

user_info_add_schema = usersdb.user_info_schema.clone()
user_info_edit_schema = usersdb.user_info_schema.clone()

user_info_add_schema.children.insert(0, usersdb.schema._uid_node)
user_info_add_schema.children.insert(1, usersdb.schema._password_node)
user_info_add_schema['postal_address'].widget = deform.widget.TextAreaWidget()
user_info_edit_schema['postal_address'].widget = deform.widget.TextAreaWidget()

CONFIG = getConfiguration()
FORUM_URL = getattr(CONFIG, 'environment', {}).get('FORUM_URL', '')

password_letters = '23456789ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def generate_password():
    return ''.join(random.choice(password_letters) for n in range(8))

def _session_pop(request, name, default):
    session = request.SESSION
    if name in session.keys():
        value = session[name]
        del session[name]
        return value
    else:
        return default

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

SESSION_PREFIX = 'eea.ldapadmin.users_admin'
SESSION_MESSAGES = SESSION_PREFIX + '.messages'
SESSION_FORM_DATA = SESSION_PREFIX + '.form_data'
SESSION_FORM_ERRORS =  SESSION_PREFIX + '.form_errors'

def _set_session_message(request, msg_type, msg):
    SessionMessages(request, SESSION_MESSAGES).add(msg_type, msg)

def logged_in_user(request):
    user_id = ''
    if _is_authenticated(request):
        user = request.get('AUTHENTICATED_USER', '')
        user_id = user.id

    return user_id

class CommonTemplateLogic(object):
    def __init__(self, context):
        self.context = context

    def base_url(self):
        return self.context.absolute_url()

    def message_boxes(self):
        return SessionMessages(self.context.REQUEST, SESSION_MESSAGES).html()

    def admin_menu(self):
        return self.context._render_template.render("zpt/users/admin_menu.zpt")

    @property
    def network_name(self):
        """ E.g. EIONET, SINAnet etc. """
        return NETWORK_NAME

# this class should be called UsersEditor, similar to OrganisationsEditor
# and RolesEditor. But the name UsersEditor is already used by the
# `eea.userseditor` package, which lets users edit their own profile info.
class UsersAdmin(SimpleItem, PropertyManager):
    meta_type = 'Eionet Users Admin'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_users_admin.gif'

    manage_options = (
        {'label':'Configure', 'action':'manage_edit'},
        {'label':'View', 'action':''},
    ) + PropertyManager.manage_options + SimpleItem.manage_options

    _properties = (
        {'id':'title', 'type': 'string', 'mode':'w', 'label': 'Title'},
    )

    _render_template = TemplateRenderer(CommonTemplateLogic)

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
        return ldap_config.ldap_agent_with_config(self._config, bind)

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

    security.declarePrivate('_create_user')
    def _create_user(self, agent, user_info):
        """
        Creates user in ldap using user_info (data already validated)

        """
        user_id = str(user_info.pop('id'))
        password = str(user_info.pop('password'))
        agent._update_full_name(user_info)
        agent.create_user(user_id, user_info)
        agent.set_user_password(user_id, None, password)

    security.declareProtected(eionet_edit_users, 'confirmation_email')
    def confirmation_email(self, first_name, user_id, REQUEST=None):
        """ Returns body of confirmation email """
        options = {'first_name': first_name, 'user_id': user_id}
        options['site_title'] = self.unrestrictedTraverse('/').title
        return self._render_template.render("zpt/users/email_registration_confirmation.zpt",
                                            **options)

    security.declarePrivate('email_password')
    def email_password(self, first_name, password, email_template='registration',
                       REQUEST=None):
        """ Returns body of confirmation email """
        options = {'first_name': first_name, 'password': password}
        options['site_title'] = self.unrestrictedTraverse('/').title
        return self._render_template.render("zpt/users/email_%s_password"
                                            ".zpt" % email_template, **options)

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

                addr_from = "no-reply@groupware.info-rac.org"
                addr_to = user_info['email']
                message = MIMEText('')
                message['From'] = addr_from
                message['To'] = addr_to

                if form_data.has_key('send_confirmation'):
                    body = self.confirmation_email(user_info['first_name'],
                                                   user_id)
                    message['Subject'] = "%s Account `%s` Created" % (NETWORK_NAME, user_id)
                    message.set_payload(body.encode('utf-8'), charset='utf-8')
                    try:
                        mailer = getUtility(IMailDelivery, name="Mail")
                        mailer.send(addr_from, [addr_to], message.as_string())
                    except ComponentLookupError:
                        mailer = getUtility(IMailDelivery, name="naaya-mail-delivery")
                        mailer.send(addr_from, [addr_to], message)

                email_password_body = self.email_password(user_info['first_name'],
                                                          form_data['password'])
                message['Subject'] = "%s Account password" % NETWORK_NAME
                message.set_payload(email_password_body.encode('utf-8'),
                                    charset='utf-8')
                try:
                    mailer = getUtility(IMailDelivery, name="Mail")
                    mailer.send(addr_from, [addr_to], message.as_string())
                except ComponentLookupError:
                    mailer = getUtility(IMailDelivery, name="naaya-mail-delivery")
                    mailer.send(addr_from, [addr_to], message)

                when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                msg = "User %s created (%s)" % (user_id, when)
                _set_session_message(REQUEST, 'info', msg)

                log.info("%s CREATED USER %s", logged_in_user(REQUEST), user_id)

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
        #message
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

    security.declareProtected(eionet_edit_users, 'change_password')
    def change_password(self, REQUEST):
        """ View for changing user password """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(id)
        options = {'user': user, 'password': generate_password()}

        self._set_breadcrumbs(self._user_bread(id, [("Change Password", '#')]))
        return self._render_template('zpt/users/change_password.zpt', **options)

    security.declareProtected(eionet_edit_users, 'change_password_action')
    def change_password_action(self, REQUEST):
        """ Performing the delete action """
        id = REQUEST.form['id']
        agent = self._get_ldap_agent(bind=True)
        password = str(REQUEST.form['password'])
        agent.set_user_password(id, None, password)

        user_info = agent.user_info(id)
        addr_from = "no-reply@groupware.info-rac.org"
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
                   'valid': [], 'invalid': [], 'taken':[]}
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
            options['valid'] = list(set(options['valid']) - set(options['taken']))

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

        for org_id, name in orgs.iteritems():
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
        from ldap import NO_SUCH_OBJECT
        agent = self._get_ldap_agent()
        emails = []
        form_data = REQUEST.form.get('emails', None)
        if form_data:
            emails = re.sub(r'[\s,]+', ' ', form_data).split(' ')
        options = {'emails': emails,
                   'valid': [], 'invalid': [], 'taken':[], 'bulk_emails': []}
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
            options['valid'] = list(set(options['valid']) - set(options['taken']))

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

    security.declareProtected(eionet_edit_users, 'download_csv_template')
    def download_csv_template(self, REQUEST):
        """ Force download of csv """
        REQUEST.RESPONSE.setHeader('Content-Disposition',
                                "attachment;filename=create_users_template.csv")
        path = os.path.join(os.path.dirname(__file__),
                            'www/create_users_template.csv')
        return open(path).read()

    security.declareProtected(eionet_edit_users, 'bulk_create_user_action')
    def bulk_create_user_action(self, data=None, REQUEST=None):
        """ view """
        errors = []
        successfully_imported = []
        try:
            reader = UnicodeReader(data)
            try:
                header = reader.next()
                assert isinstance(header, list)
                assert len(header) == 12
            except StopIteration:
                errors.append('Invalid CSV file')
                reader = []

            users_data = []
            user_form = deform.Form(user_info_add_schema)

            for record_number, row in enumerate(reader):
                try:
                    properties = {}
                    for column, value in zip(header, row):
                        properties[column.lower()] = value
                except UnicodeDecodeError, e:
                    raise
                except Exception, e:
                    msg = ('Error while importing from CSV, row ${record_number}: ${error}',
                           {'record_number': record_number+1, 'error': str(e)})
                    errors.append(msg)
                else:
                    # CSV Record read without errors
                    row_data = csv_headers_to_object(properties)
                    try:
                        user_info = user_form.validate(row_data.items())
                    except deform.ValidationFailure, e:
                        for field_error in e.error.children:
                            errors.append('%s at row %d: %s' %
                                          (field_error.node.name, record_number+1, field_error.msg))
                    else:
                        users_data.append(user_info)

            # cycled every object and stored them in users_data
            if not errors:
                agent = self._get_ldap_agent(bind=True)
                emails = [x['email'] for x in users_data]
                usernames = [x['id'] for x in users_data]
                if len(emails) != len(set(emails)):
                    for email in set(emails):
                        occourences = emails.count(email)
                        if occourences > 1:
                            errors.append('Duplicate email: %s appears %d times'
                                          % (email, occourences))
                if len(usernames) != len(set(usernames)):
                    for username in set(usernames):
                        occourences = usernames.count(username)
                        if occourences > 1:
                            errors.append('Duplicate user ID: %s appears %d times'
                                          % (username, occourences))
                existing_emails = list(agent.existing_emails(list(set(emails))))
                existing_users = list(agent.existing_usernames(list(set(usernames))))
                if existing_emails:
                    errors.append("The following emails are already in database"
                                  + ": " + ', '.join(existing_emails))
                if existing_users:
                    errors.append("The following user IDs are already registered"
                                  + ": " + ', '.join(existing_users))
                if not errors:
                    # Everything clean, do the job
                    for user_info in users_data:
                        try:
                            self._create_user(agent, user_info)
                        except Exception:
                            errors.append("Error creating %s user" % user_info['user_id'])
                        else:
                            successfully_imported.append(user_info['user_id'])

        except UnicodeDecodeError, e:
            errors.append('CSV file is not utf-8 encoded')

        if errors:
            for err in errors:
                _set_session_message(REQUEST, 'error', err)
        if successfully_imported:
            _set_session_message(REQUEST, 'info',
                '%s user(s) successfully created.' % len(successfully_imported))
            logged_in = logged_in_user(REQUEST)
            for user_id in successfully_imported:
                log.info("%s CREATED USER %s", logged_in, user_id)
        else:
            _set_session_message(REQUEST, 'error', 'No user account created')
        self._set_breadcrumbs([("Create Accounts from File", '#')])
        return self._render_template('zpt/users/bulk_create.zpt')

InitializeClass(UsersAdmin)
