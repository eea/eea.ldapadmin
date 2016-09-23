from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from AccessControl.unauthorized import Unauthorized
from App.class_init import InitializeClass
from App.config import getConfiguration
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from Products.Five.browser import BrowserView
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from copy import deepcopy
from countries import get_country_options
from datetime import datetime
from datetime import timedelta
from dateutil import parser
from deform.widget import SelectWidget
from eea import usersdb
from eea.ldapadmin import eionet_profile
from eea.ldapadmin.constants import NETWORK_NAME
from eea.ldapadmin.help_messages import help_messages
from eea.ldapadmin.logic_common import _session_pop
from eea.ldapadmin.ui_common import NaayaViewPageTemplateFile
from eea.usersdb import factories
from eea.usersdb.db_agent import NameAlreadyExists, EmailAlreadyExists
from eea.usersdb.db_agent import UserNotFound
from email.mime.text import MIMEText
from import_export import excel_headers_to_object
from import_export import generate_excel
from import_export import set_response_attachment
from naaya.ldapdump.interfaces import IDumpReader
from persistent.mapping import PersistentMapping
from ui_common import CommonTemplateLogic   # load_template,
from ui_common import SessionMessages, TemplateRenderer
from ui_common import extend_crumbs, TemplateRendererNoWrap
from unidecode import unidecode
from validate_email import validate_email, INCORRECT_EMAIL
from zope.component import getUtility
from zope.component.interfaces import ComponentLookupError
from zope.sendmail.interfaces import IMailDelivery
from transliterate import translit, get_available_language_codes
import colander
import deform
import jellyfish
import ldap
import ldap_config
import logging
import os
import random
import re
import requests
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
user_info_add_schema['search_helper'].widget = deform.widget.TextAreaWidget()
user_info_add_schema['department'].widget = deform.widget.TextAreaWidget()

CONFIG = getConfiguration()
FORUM_URL = getattr(CONFIG, 'environment', {}).get('FORUM_URL', '')

password_letters = '23456789ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def generate_password():
    return ''.join(random.choice(password_letters) for n in range(8))


def generate_user_id(first_name, last_name, agent, id_list):
    first_name = unidecode(first_name).replace(
        '-', '').replace("'", "").replace(" ", "")
    last_name = unidecode(last_name).replace(
        '-', '').replace("'", "").replace(" ", "")
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
    if not os.path.exists(DB_FILE):
        from naaya.ldapdump.interfaces import IDumpReader
        from zope.component import getUtility
        util = getUtility(IDumpReader)
        DB_FILE = util.db_path
        assert os.path.exists(DB_FILE)
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
        if user:
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
    title = "LDAP Users Administration"

    manage_options = (
        {'label': 'Configure', 'action': 'manage_edit'},
        {'label': 'View', 'action': ''},
    ) + PropertyManager.manage_options + SimpleItem.manage_options

    _properties = (
        {'id': 'title', 'type': 'string', 'mode': 'w', 'label': 'Title'},
    )

    _render_template = TemplateRenderer(CommonTemplateLogic)
    _render_template_no_wrap = TemplateRendererNoWrap(CommonTemplateLogic)

    def __init__(self, config={}):
        super(UsersAdmin, self).__init__()
        self._config = PersistentMapping(config)

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

    def _get_ldap_agent(self, bind=True):
        agent = ldap_config.ldap_agent_with_config(self._config, bind)
        if hasattr(self, 'REQUEST'):
            agent._author = logged_in_user(self.REQUEST)
        else:
            agent._author = 'System User'
        return agent

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

    security.declareProtected(view, 'can_edit_users')

    def can_edit_users(self):
        user = self.REQUEST.AUTHENTICATED_USER
        return bool(user.has_permission(eionet_edit_users, self))

    security.declarePublic('checkPermissionEditUsers')

    def checkPermissionEditUsers(self):
        """ """
        user = self.REQUEST.AUTHENTICATED_USER
        return bool(user.has_permission(eionet_edit_users, self))

    def index_html(self, REQUEST):
        """ view """
        if not self.checkPermissionEditUsers() and not self.nfp_has_access():
            raise Unauthorized
        options = {
            'can_edit': self.can_edit_users(),
            'search_fields': usersdb.db_agent.ACCEPTED_SEARCH_FIELDS,
        }

        search_name = REQUEST.form.get('name', '')
        lookup = REQUEST.form.get('lookup', '')
        options.update({
            'search_name': search_name,
            'lookup': lookup,
        })

        if search_name:
            agent = self._get_ldap_agent(bind=True)
            results = sorted(agent.search_user(search_name, lookup),
                             key=lambda x: x['full_name'])
            options['search_results'] = results

        for row in options.get('search_results', []):
            if row.get('status') in ['disabled']:
                row['email'] = "disabled - %s" % row['email']

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

    def _create_user(self, agent, user_info, send_helpdesk_email=False):
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
        if self.nfp_has_access() or send_helpdesk_email:
            self._send_new_user_email(
                user_id, user_info,
                source=(send_helpdesk_email and 'bulk' or 'nfp'))
        # put id and password back on user_info, for further processing
        # (mainly sending of email)
        user_info['id'] = user_id
        user_info['password'] = password
        return user_id

    def _send_new_user_email(self, user_id, user_info, source='nfp'):
        """ Sends announcement email to helpdesk """

        addr_from = "no-reply@eea.europa.eu"
        addr_to = "helpdesk@eionet.europa.eu"

        message = MIMEText('')
        message['From'] = addr_from
        message['To'] = addr_to

        options = deepcopy(user_info)
        options['user_id'] = user_id
        options['author'] = logged_in_user(self.REQUEST)

        body = self._render_template.render(
            "zpt/users/new_user_email.zpt",
            **options)

        if source == 'nfp':
            message['Subject'] = "[Account created by NFP]"
        else:
            message['Subject'] = "[New user created by batch import]"
        message.set_payload(body.encode('utf-8'), charset='utf-8')
        _send_email(addr_from, addr_to, message)

    def confirmation_email(self, first_name, user_id, REQUEST=None):
        """ Returns body of confirmation email """
        if not self.checkPermissionEditUsers() and not self.nfp_has_access():
            raise Unauthorized
        options = {'first_name': first_name, 'user_id': user_id}
        options['site_title'] = self.unrestrictedTraverse('/').title
        return self._render_template.render(
            "zpt/users/email_registration_confirmation.zpt",
            **options)

    def create_user(self, REQUEST):
        """ view """
        agent = self._get_ldap_agent()

        if not (self.checkPermissionEditUsers() or
                self.nfp_has_access()):
            raise Unauthorized

        nfp_country = self.nfp_for_country()
        form_data = dict(REQUEST.form)
        errors = {}
        if not form_data.get('password', ''):
            form_data['password'] = generate_password()

        def no_duplicate_id_validator(node, value):
            if list(agent.existing_usernames([value])):
                raise colander.Invalid(node, 'This username is taken')

        skip_email_validation_node = colander.SchemaNode(
            colander.Boolean(),
            title='',
            name='skip_email_validation',
            description='Skip extended email validation',
            widget=deform.widget.CheckboxWidget(),
        )

        schema = user_info_add_schema.clone()

        # add the "skip email validation" field if email fails validation
        email = form_data.get('email')
        if email:
            email = email.strip()
            validity_status = validate_email(email, verify=True, verbose=True)
            if validity_status is not True:
                email_node = schema['email']
                pos = schema.children.index(email_node)
                schema.children.insert(pos+1, skip_email_validation_node)

        # if the skip_email_validation field exists but is not activated,
        # add an extra validation to the form
        if not (form_data.get('edit-skip_email_validation') == 'on'):
            schema['email'].validator = colander.All(
                schema['email'].validator, check_valid_email)

        for children in schema.children:
            help_text = help_messages['create-user'].get(children.name, None)
            setattr(children, 'help_text', help_text)

        schema['id'].validator = colander.All(
            schema['id'].validator, no_duplicate_id_validator)

        if self.checkPermissionEditUsers():
            agent_orgs = agent.all_organisations()
        else:
            agent_orgs = self.orgs_in_country(nfp_country)

        orgs = [{'id': k, 'text': v['name'], 'ldap':True}
                for k, v in agent_orgs.items()]
        org = form_data.get('organisation')
        if org and not (org in agent_orgs):
            orgs.append({'id': org, 'text': org, 'ldap': False})
        orgs.sort(lambda x, y: cmp(x['text'], y['text']))
        choices = [('-', '-')]
        for org in orgs:
            if org['ldap']:
                label = u"%s (%s)" % (org['text'], org['id'])
            else:
                label = org['text']
            choices.append((org['id'], label))

        widget = SelectWidget(values=choices)
        schema['organisation'].widget = widget

        if 'submit' in REQUEST.form:
            try:
                user_form = deform.Form(schema)
                user_info = user_form.validate(form_data.items())
                user_info['search_helper'] = _transliterate(
                    user_info['first_name'], user_info['last_name'],
                    user_info['full_name_native'], user_info['search_helper'])
            except deform.ValidationFailure, e:
                for field_error in e.error.children:
                    errors[field_error.node.name] = field_error.msg
                msg = u"Please correct the errors below and try again."
                _set_session_message(REQUEST, 'error', msg)
            else:
                user_id = user_info['id']
                agent = self._get_ldap_agent(bind=True)
                with agent.new_action():
                    user_info.pop('skip_email_validation', None)
                    try:
                        self._create_user(agent, user_info)
                    except NameAlreadyExists, e:
                        errors['id'] = 'This ID is alreay registered'
                    except EmailAlreadyExists, e:
                        errors['email'] = 'This email is alreay registered'
                    else:
                        new_org_id = user_info['organisation']
                        new_org_id_valid = agent.org_exists(new_org_id)

                        if new_org_id_valid:
                            self._add_to_org(agent, new_org_id, user_id)

                        send_confirmation = 'send_confirmation' in \
                            form_data.keys()
                        if send_confirmation:
                            self.send_confirmation_email(user_info)
                            self.send_password_reset_email(user_info)

                        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        msg = "User %s created (%s)" % (user_id, when)
                        _set_session_message(REQUEST, 'info', msg)

                        log.info("%s CREATED USER %s",
                                 logged_in_user(REQUEST),
                                 user_id)

                if not errors:
                    return REQUEST.RESPONSE.redirect(self.absolute_url())
                else:
                    msg = u"Please correct the errors below and try again."
                    _set_session_message(REQUEST, 'error', msg)

        self._set_breadcrumbs([('Create User', '#')])
        options = {
            'form_data': form_data,
            'errors': errors,
            'schema': schema,
            'nfp_access': self.nfp_has_access()
        }
        return self._render_template('zpt/users/create.zpt', **options)

    def find_duplicates(self, REQUEST):
        """ view """
        if not self.checkPermissionEditUsers() and not self.nfp_has_access():
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

    def edit_user(self, REQUEST):
        """
        View for editing profile information for a given user
        with id passed through GET

        """
        user_id = REQUEST.form['id']
        agent = self._get_ldap_agent(bind=True)
        errors = _session_pop(REQUEST, SESSION_FORM_ERRORS, {})
        user = agent.user_info(user_id)
        if not (self.checkPermissionEditUsers() or
                self.nfp_has_edit_access(user=user)):
            raise Unauthorized
        # message
        form_data = _session_pop(REQUEST, SESSION_FORM_DATA, None)
        if form_data is None:
            form_data = user

        orgs = agent.all_organisations()
        orgs = [{'id': k, 'text': v['name'], 'ldap': True}
                for k, v in orgs.items()]
        user_orgs = list(agent.user_organisations(user_id))
        if not user_orgs:
            org = form_data.get('organisation')
            if org:
                orgs.append({'id': org, 'text': org, 'ldap': False})
        else:
            org = user_orgs[0]
            org_id = agent._org_id(org)
            form_data['organisation'] = org_id
        orgs.sort(lambda x, y: cmp(x['text'], y['text']))
        schema = user_info_edit_schema.clone()

        skip_email_validation_node = colander.SchemaNode(
            colander.Boolean(),
            title='',
            name='skip_email_validation',
            description='Skip extended email validation',
            widget=deform.widget.CheckboxWidget(),
        )

        # add the "skip email validation" field if email fails validation
        email = form_data.get('email')
        if email:
            email = email.strip()
            validity_status = validate_email(email, verify=True, verbose=True)
            if validity_status is not True:
                email_node = schema['email']
                pos = schema.children.index(email_node)
                schema.children.insert(pos+1, skip_email_validation_node)

        # if the skip_email_validation field exists but is not activated,
        # add an extra validation to the form
        if not (form_data.get('edit-skip_email_validation') == 'on'):
            schema['email'].validator = colander.All(
                schema['email'].validator, check_valid_email)

        choices = [('', '-')]
        for org in orgs:
            if org['ldap']:
                label = u"%s (%s)" % (org['text'], org['id'])
            else:
                label = org['text']
            choices.append((org['id'], label))
        widget = SelectWidget(values=choices)
        schema['organisation'].widget = widget

        # if 'disabled@' in form_data.get('email', ''):
        #     user_dn = agent._user_dn(user_id)
        #     form_data['email'] = "disabled - %s" % \
        #         agent.get_email_for_disabled_user_dn(user_dn)

        options = {'user': user,
                   'form_data': form_data,
                   'schema': schema,
                   'errors': errors,
                   'forum_url': FORUM_URL,
                   }
        self._set_breadcrumbs([(user_id, '#')])
        return self._render_template('zpt/users/edit.zpt', **options)

    security.declareProtected(eionet_edit_users, 'edit_user_action')

    def edit_user_action(self, REQUEST):
        """ view """
        user_id = REQUEST.form['id']

        schema = user_info_edit_schema.clone()
        # if the skip_email_validation field exists but is not activated,
        # add an extra validation to the form
        if not (REQUEST.form.get('edit-skip_email_validation') == 'on'):
            schema['email'].validator = colander.All(
                schema['email'].validator, check_valid_email)

        user_form = deform.Form(schema)

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
            agent = self._get_ldap_agent(bind=True)

            new_org_id = new_info['organisation']
            new_org_id_valid = agent.org_exists(new_org_id)

            # make a check if user is changing the organisation
            user_orgs = [agent._org_id(org)
                         for org in list(agent.user_organisations(user_id))]

            new_info['search_helper'] = _transliterate(
                new_info['first_name'], new_info['last_name'],
                new_info['full_name_native'], new_info['search_helper'])

            with agent.new_action():
                if not (new_org_id in user_orgs):
                    self._remove_from_all_orgs(agent, user_id)
                    if new_org_id_valid:
                        self._add_to_org(agent, new_org_id, user_id)

                agent.set_user_info(user_id, new_info)

            when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _set_session_message(
                REQUEST, 'info', "Profile saved (%s)" % when)

            log.info("%s EDITED USER %s as member of %s",
                     logged_in_user(REQUEST), user_id, new_org_id)

        REQUEST.RESPONSE.redirect(
            self.absolute_url() + '/edit_user?id=' + user_id)

    def _add_to_org(self, agent, org_id, user_id):
        try:
            agent.add_to_org(org_id, [user_id])
            log.info("USER %s ADDED %s as member of organisation %s",
                     logged_in_user(self.REQUEST), user_id, org_id)
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
        with agent.new_action():
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
        with agent.new_action():
            agent.disable_user(id)

        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _set_session_message(
            REQUEST, 'info', 'User "%s" has been disabled. (%s)' % (id, when))
        log.info("%s DISABLED USER %s", logged_in_user(REQUEST), id)
        return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

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
        restore_roles = REQUEST.form.get('restore_roles')
        agent = self._get_ldap_agent(bind=True)
        with agent.new_action():
            agent.enable_user(id, restore_roles=restore_roles)

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
            try:
                mailer.send(addr_from, [addr_to], message.as_string())
            except AssertionError:
                mailer.send(addr_from, [addr_to], message)

        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if restore_roles:
            extra = ', previous roles restored'
        else:
            extra = ', previous roles NOT restored'
        _set_session_message(REQUEST, 'info',
                             'Account enabled for "%s (%s)"%s.' % (id, when,
                                                                   extra))

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
        with agent.new_action:
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

        agent = self._get_ldap_agent(bind=True)
        emails = []
        form_data = REQUEST.form.get('emails', None)
        if form_data:
            emails = re.sub(r'[\s,]+', ' ', form_data).split(' ')

        duplicates = []
        singles = []
        for email in emails:
            if email.lower() not in [x.lower() for x in singles]:
                singles.append(email)
            else:
                duplicates.append(email)

        options = {
            'emails': sorted(singles),
            'valid': [],
            'invalid': [],
            'taken': [],
            'bulk_emails': [],
            'duplicates': sorted(duplicates),
        }

        node = user_info_add_schema['email']
        for email in emails:
            try:
                node.validator(node, email)
            except colander.Invalid:
                options['invalid'].append(email)
            else:
                options['valid'].append(email.lower())

        # search for availability
        if options['valid']:
            options['taken'] = sorted(agent.existing_emails(options['valid']))
            options['valid'] = sorted(set(options['valid']) -
                                      set(options['taken']))

        self._set_breadcrumbs([("Bulk Verify Emails", '#')])
        return self._render_template('zpt/users/bulk_check_email.zpt',
                                     **options)

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
        pwreset_tool = self.restrictedTraverse('/').objectValues(
            'Eionet Password Reset Tool')[0]
        email = user_info['email']
        pwreset_tool.ask_for_password_reset(email=email)

    def nfp_has_access(self):
        """ """
        return self.nfp_for_country() and self.aq_parent.id == 'nfp-eionet'

    def nfp_has_edit_access(self, user):
        """ """
        nfp_country = self.nfp_for_country()
        if self.aq_parent.id != 'nfp-eionet':
            return False
        if nfp_country:
            country_orgs = self.orgs_in_country(nfp_country)
            return user['organisation'] in country_orgs

    def orgs_in_country(self, country):
        """ """
        agent = self._get_ldap_agent()
        orgs_by_id = agent.all_organisations()
        countries = dict(get_country_options(country=country))
        orgs = {}
        for org_id, info in orgs_by_id.iteritems():
            country_info = countries.get(info['country'])
            if country_info:
                orgs[org_id] = info
        return orgs

    def nfp_for_country(self):
        """ Return country code for which the current user has NFP role
        or None otherwise"""
        user_id = self.REQUEST.AUTHENTICATED_USER.getId()
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
        agent = agent_from_uf(self.restrictedTraverse("/acl_users"))
        ldap_roles = sorted(agent.member_roles_info('user',
                                                    user_id,
                                                    ('description',)))
        return ldap_roles

InitializeClass(UsersAdmin)


def _send_email(addr_from, addr_to, message):
    try:
        mailer = getUtility(IMailDelivery, name="Mail")
        mailer.send(addr_from, [addr_to], message.as_string())
    except ComponentLookupError:
        mailer = getUtility(IMailDelivery, name="naaya-mail-delivery")
        try:
            mailer.send(addr_from, [addr_to], message.as_string())
        except AssertionError:
            mailer.send(addr_from, [addr_to], message)


class BulkUserImporter(BrowserView):
    """ A view to bulk import users from an xls file
    """
    buttons = ('download_template', 'bulk_create')
    TEMPLATE_COLUMNS = ["First Name*", "Last Name*",
                        "Full name (native language)",
                        "Search helper (ASCII characters only!)",
                        "E-mail*", "Job Title", "URL", "Postal Address",
                        "Telephone Number*", "Mobile Telephone Number",
                        "Fax Number", "Organisation*", "Department",
                        "Reason to create*"]

    def __call__(self):
        """ upload view """
        if not self.request.form:
            return self.index()
        else:
            for name in self.buttons:
                if name in self.request.form:
                    return getattr(self, name)()

    def index(self):
        self.context._set_breadcrumbs([("Create Accounts from File", '#')])
        return self.context._render_template('zpt/users/bulk_create.zpt')

    def download_template(self):
        """ Force download of excel template """

        ret = generate_excel(self.TEMPLATE_COLUMNS, [[]])
        content_type = 'application/vnd.ms-excel'
        filename = 'create_users_template.xls'

        set_response_attachment(
            self.request.RESPONSE, filename, content_type, len(ret))

        return ret

    def read_xls(self, data):
        agent = self.context._get_ldap_agent(bind=True)
        wb = xlrd.open_workbook(file_contents=data)
        ws = wb.sheets()[0]
        header = ws.row_values(0)
        if not (len(header) == len(self.TEMPLATE_COLUMNS)):
            raise ValueError("wrong number of columns")
        rows = []
        for i in range(ws.nrows)[1:]:
            rows.append(ws.row_values(i))

        result = []
        id_list = []
        for record_number, row in enumerate(rows):
            row = [x.strip() for x in row]
            properties = {}
            for column, value in zip(header, row):
                properties[column.lower()] = value

            row_data = excel_headers_to_object(properties)
            row_data['password'] = generate_password()
            row_data['id'] = generate_user_id(row_data['first_name'],
                                              row_data['last_name'],
                                              agent, id_list)
            id_list.append(row_data['id'])
            row_data['url'] = process_url(row_data['url'])
            result.append(row_data)

        return result

    def bulk_create(self):
        """ view """
        data = self.request.form.get('data').read()
        msgr = lambda level, msg: _set_session_message(self.request, level,
                                                       msg)

        try:
            rows = self.read_xls(data)
        except Exception, e:
            msgr('error', 'Invalid Excel file: %s' % e)
            log.exception("Exception while parsing bulk import users file")
            return self.index()

        agent = self.context._get_ldap_agent(bind=True)

        users_data = []
        errors = []
        successfully_imported = []

        user_form = deform.Form(user_info_add_schema)

        for record_number, row_data in enumerate(rows):
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

        emails = [x['email'] for x in users_data]
        usernames = [x['id'] for x in users_data]

        if len(emails) != len(set(emails)):
            for email in set(emails):
                count = emails.count(email)
                if count > 1:
                    errors.append('Duplicate email: %s appears %d times'
                                  % (email, count))
                    users_data = filter(lambda x: x['email'] != email.lower(),
                                        users_data)

        if len(usernames) != len(set(usernames)):
            for username in set(usernames):
                count = usernames.count(username)
                if count > 1:
                    errors.append('Duplicate user ID: %s appears %d times'
                                  % (username, count))
                    users_data = filter(lambda x: x['id'] != username,
                                        users_data)

        existing_emails = set(agent.existing_emails(list(set(emails))))
        existing_users = set(agent.existing_usernames(
            list(set(usernames))))

        if existing_emails:
            for email in existing_emails:
                errors.append("The following email is already in database: %s"
                              % email)
            for email in existing_emails:
                users_data = filter(lambda x: x['email'] != email.lower(),
                                    users_data)

        if existing_users:
            for user_id in existing_users:
                errors.append("The following user ID is already registered: %s"
                              % user_id)
            for username in existing_users:
                users_data = filter(lambda x: x['id'] != username, users_data)

        for user_info in users_data:
            user_info['search_helper'] = _transliterate(
                user_info['first_name'], user_info['last_name'],
                user_info['full_name_native'], user_info['search_helper'])
            user_id = user_info['id']
            try:
                self.context._create_user(agent, user_info,
                                          send_helpdesk_email=True)
            except Exception:
                errors.append("Error creating %s user" % user_id)
            else:

                new_org_id = user_info['organisation']
                new_org_id_valid = agent.org_exists(new_org_id)

                if new_org_id_valid:
                    self.context._add_to_org(agent, new_org_id, user_id)

                try:
                    self.context.send_confirmation_email(user_info)
                except Exception, e:
                    msgr('error', "Error sending confirmation email to %s"
                         % user_info['email'])
                try:
                    self.context.send_password_reset_email(user_info)
                except Exception, e:
                    msgr('error',
                         "Error: %s sending password reset email to %s"
                         % (e, user_info['email']))

                msg = u"%s %s (%s)" % \
                    (user_info['first_name'], user_info['last_name'], user_id)
                successfully_imported.append(msg)

        if errors:
            for err in errors:
                msgr('error', err)

        if successfully_imported:
            msgr('info',
                 'User(s) %s successfully created.' %
                 ', '.join(successfully_imported))
            logged_in = logged_in_user(self.request)
            for user_id in successfully_imported:
                log.info("%s CREATED USER %s", logged_in, user_id)
        else:
            msgr('error', 'No user account created')

        if 'location' in self.request.response.headers:
            del self.request.response.headers['location']
            self.request.response.headers['status'] = '200 OK'
        return self.context._render_template('zpt/users/bulk_create.zpt')


class ResetUser(BrowserView):
    """ A view to reset the roles of a user
    """

    index = NaayaViewPageTemplateFile('zpt/users/reset.zpt')

    def __call__(self):
        user_id = self.request.form.get('id')

        agent = self.context._get_ldap_agent(bind=True)
        if 'submit' in self.request.form:
            with agent.new_action():
                agent.reset_user_roles(user_id)
            _set_session_message(
                self.request, 'info',
                'Roles for user "%s" have been reseted (deleted).' % user_id)
            log.info("%s RESETED USER %s", logged_in_user(self.request),
                     user_id)
            url = self.context.absolute_url() + '/edit_user?id=' + user_id
            return self.request.RESPONSE.redirect(url)

        user = agent.user_info(user_id)
        options = {
            'common': CommonTemplateLogic(self.context),
            'context': self.context,
            'user': user,
        }
        return self.index(**options)


class MigrateDisabledEmails(BrowserView):

    def _get_metadata(self, metadata):
        if not metadata:
            metadata = "[]"
        metadata = json.loads(metadata)
        return metadata

    def __call__(self):
        agent = self.context._get_ldap_agent(bind=True)
        disabled_users = agent.get_disabled_users()

        for user_info in disabled_users:
            metadata = self._get_metadata(user_info['metadata'])
            email = agent._get_email_for_disabled_user(metadata)
            user_info['email'] = email
            agent.set_user_info(user_info['id'], user_info)
            log.info("Migrated disabled email info for user %s",
                     user_info['id'])

        return "done"


class AutomatedUserDisabler(BrowserView):
    """ A view that will automatically disable users
    """

    DISABLE_DELTA = timedelta(days=780)
    ONE_MONTH = timedelta(days=30)
    SERVICE_URL = "http://ldapmon.eea.europa.eu/export"
    LDAP_PREDISABLE_FIELDNAME = "employeeNumber"

    def get_login_statistics(self):
        data = requests.get(self.SERVICE_URL).json()
        return data

    def get_ldap_users(self):
        result = []
        reader = getUtility(IDumpReader)
        for dn, attrs in reader.get_dump():
            if not dn.startswith('uid='):
                continue
            if not attrs.get('mail'):   # probably a system user
                continue
            result.append(dict(
                disabled=attrs.get('employeeType', 'enabled') in ['disabled'],
                dn=dn,
                email=attrs['mail'],
                full_name=attrs['cn'],
                pending_disable=attrs.get(self.LDAP_PREDISABLE_FIELDNAME),
                username=attrs['uid'],
            ))

        return result

    def predisable_users(self, agent, users):
        for user in users:
            log.warn("User will be disabled the next check %s",
                     user['username'])
            self.send_predisable_notification_email(user)
            timestamp = datetime.now().isoformat()
            try:
                result = agent.conn.modify_s(
                    agent._user_dn(user['username']),
                    [(ldap.MOD_REPLACE, self.LDAP_PREDISABLE_FIELDNAME,
                      timestamp), ]
                )
            except ldap.NO_SUCH_OBJECT:
                log.info("Could not predisable user: %s", user['dn'])
                continue
            assert result[:2] == (ldap.RES_MODIFY, [])

    def disable_users(self, agent, users):
        for user in users:
            username = user.get('username') or user.get('id')
            if not username:
                continue
            log.warn("Disabling user %s", username)
            agent.disable_user(username)
            self.send_disable_notification_email(user)

    def remove_pending_users(self, agent, users):
        for user in users:
            log.warn("Removing predisable for user %s", user['username'])
            try:
                result = agent.conn.modify_s(
                    agent._user_dn(user['username']),
                    [(ldap.MOD_REPLACE, self.LDAP_PREDISABLE_FIELDNAME, ''), ]
                )
            except ldap.NO_SUCH_OBJECT:
                log.info("Could not remove predisable for user: %s",
                         user['dn'])
                continue
            assert result[:2] == (ldap.RES_MODIFY, [])

    def __call__(self):
        # call up the login service report
        # make a list of all users from ldap that are not disabled
        #       this list should have a "has been notified" value
        # construct a list of users that should be disabled
        #       also have a list of users that should be "predisabled"
        # predisable users
        # disable users
        # send emails that they are disabled
        # send emails to helpdesk that they have been disabled

        users_stats = self.get_login_statistics()
        all_ldap_users = self.get_ldap_users()

        agent = self.context.restrictedTraverse('ldap-roles')._get_ldap_agent(
            bind=True)

        now = datetime.now()
        users_to_disable = []
        users_to_predisable = []
        users_to_remove_pending = []

        # only use all_ldap_users to provide a list of users
        for user in all_ldap_users:
            if user['disabled']:
                continue
            username = user['username']
            try:
                user = agent.user_info(user['username'])
            except UserNotFound:
                continue
            user['username'] = username
            last_login = users_stats.get(username)
            if last_login:
                last_login = parser.parse(last_login)
                user['last_login'] = last_login

                # check if the user has logged during in the one month period
                pending_disable = user.get('pending_disable')
                if pending_disable:
                    pending_disable = parser.parse(pending_disable)
                    if last_login > pending_disable:
                        users_to_remove_pending.append(user)
                        continue

                if last_login + self.DISABLE_DELTA < now:
                    if pending_disable:
                        if (pending_disable + self.ONE_MONTH) < now:
                            # double check if everything is ok
                            if (last_login + self.DISABLE_DELTA +
                                    self.ONE_MONTH) < now:
                                users_to_disable.append(user)
                    else:
                        users_to_predisable.append(user)

        self.predisable_users(agent, users_to_predisable)
        self.disable_users(agent, users_to_disable)
        self.remove_pending_users(agent, users_to_remove_pending)

        self.send_admin_report_email(users_to_predisable, users_to_disable)

        return "Predisabled %s users, disabled % users" % (
            len(users_to_predisable), len(users_to_disable)
        )

    def send_disable_notification_email(self, user):
        addr_from = "no-reply@eea.europa.eu"
        addr_to = user['email']

        message = MIMEText('')
        message['From'] = addr_from
        message['To'] = addr_to

        options = deepcopy(user)
        options['site_title'] = self.context.unrestrictedTraverse('/').title

        body = self.context._render_template.render(
            "zpt/users/email_auto_disabled.zpt",
            **options)

        message['Subject'] = "[You have been automatically disabled]"
        message.set_payload(body.encode('utf-8'), charset='utf-8')
        _send_email(addr_from, addr_to, message)

    def send_predisable_notification_email(self, user):
        addr_from = "no-reply@eea.europa.eu"
        addr_to = user['email']

        message = MIMEText('')
        message['From'] = addr_from
        message['To'] = addr_to

        options = deepcopy(user)
        options['site_title'] = self.context.unrestrictedTraverse('/').title

        body = self.context._render_template.render(
            "zpt/users/email_auto_predisabled.zpt",
            **options)

        message['Subject'] = "[You will be automatically disabled]"
        message.set_payload(body.encode('utf-8'), charset='utf-8')
        _send_email(addr_from, addr_to, message)

    def send_admin_report_email(self, users_to_predisable, users_to_disable):
        addr_from = "no-reply@eea.europa.eu"
        addr_to = 'helpdesk@eea.europa.eu'

        message = MIMEText('')
        message['From'] = addr_from
        message['To'] = addr_to

        options = {}
        options['users_predisable'] = users_to_predisable
        options['users_disable'] = users_to_disable
        options['site_title'] = self.context.unrestrictedTraverse('/').title
        options['days'] = (self.DISABLE_DELTA + self.ONE_MONTH).days

        body = self.context._render_template.render(
            "zpt/users/email_report_autodisable.zpt",
            **options)

        message['Subject'] = "[Report on auto-disabled users]"
        message.set_payload(body.encode('utf-8'), charset='utf-8')
        _send_email(addr_from, addr_to, message)


def auto_disable_users():
    """ A script to automatically disable users

    Should be run as ``bin/zope-instance run /path/to/this/disable_users.py``
    """

    from AccessControl.SecurityManagement import newSecurityManager
    from AccessControl.SpecialUsers import system
    from Globals import DB
    from Testing.makerequest import makerequest
    from zope.component import getMultiAdapter
    import transaction

    app = DB.open().root()['Application']

    def spoofRequest(app):
        admin = app.acl_users.getUserById("admin")
        newSecurityManager(None, admin)

        return makerequest(app)

    app = spoofRequest(app)

    site = app['nfp-eionet']
    users = site['users']
    request = users.REQUEST
    system.id = u'SystemUser'
    request.AUTHENTICATED_USER = request['AUTHENTICATED_USER'] = system
    view = getMultiAdapter((users, request), name="auto_disable_users")
    view()

    transaction.commit()
    app._p_jar.sync()


def check_valid_email(node, value):
    validity_status = validate_email(value, verify=True, verbose=True)
    if validity_status is not True:
        if validity_status != INCORRECT_EMAIL:  # avoid a double error message
            raise colander.Invalid(
                node, 'This email is possibly invalid. %s' % validity_status)


def _transliterate(first_name, last_name, full_name_native, search_helper):
    vocab = set(first_name.split(' ') + last_name.split(' ') +
                full_name_native.split(' ') + search_helper.split(' '))
    langs = get_available_language_codes()
    ascii_values = []
    translate_table = {
        0xe4: ord('a'),
        0xc4: ord('A'),
        0xf6: ord('o'),
        0xd6: ord('O'),
        0xfc: ord('u'),
        0xdc: ord('U'),
        }

    for name in vocab:
        ascii_values.append(unidecode(name))
        for lang in langs:
            try:
                ascii_values.append(
                    str(translit(name, lang, reversed=True)))
            except UnicodeEncodeError:
                # if we encounter other characters = other languages
                # than German
                pass
        try:
            ascii_values.append(
                str(name.replace(u'\xdf', 'ss').translate(translate_table)))
        except UnicodeEncodeError:
            # if we encounter other characters = other languages than German
            pass
    return ' '.join(sorted(set(ascii_values))).strip()
