# pylint: disable=too-many-lines,super-init-not-called,too-many-statements
# pylint: disable=too-many-branches,too-many-locals,too-many-nested-blocks
# pylint: disable=too-many-public-methods,dangerous-default-value
# pylint: disable=global-statement,unused-variable
''' the user administration module '''
import logging
import functools
import os
import random
import re
import sqlite3
import string
from copy import deepcopy
from datetime import datetime
from email.mime.text import MIMEText

import six
from six.moves import map
from six.moves import range
from six.moves import zip
from zope.component import getUtility
import colander
import jellyfish
import xlrd
from unidecode import unidecode
from plone import api

import deform
from deform.widget import SelectWidget
import ldap
from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from AccessControl.unauthorized import Unauthorized
from App.class_init import InitializeClass
from App.config import getConfiguration
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from persistent.mapping import PersistentMapping
from Products.Five.browser import BrowserView
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.statusmessages.interfaces import IStatusMessage
from transliterate import get_available_language_codes, translit
from naaya.ldapdump.interfaces import IDumpReader
from eea import usersdb
from eea.usersdb.db_agent import (EmailAlreadyExists, NameAlreadyExists)
from eea.ldapadmin import eionet_profile
from eea.ldapadmin.constants import NETWORK_NAME
from eea.ldapadmin.help_messages import help_messages
from eea.ldapadmin.ui_common import NaayaViewPageTemplateFile
from eea.ldapadmin.ui_common import CommonTemplateLogic
from eea.ldapadmin.ui_common import TemplateRenderer, TemplateRendererNoWrap
from eea.ldapadmin.ui_common import extend_crumbs
from eea.ldapadmin.import_export import excel_headers_to_object
from eea.ldapadmin.import_export import generate_excel
from eea.ldapadmin.import_export import set_response_attachment
from eea.ldapadmin import ldap_config
from eea.ldapadmin.logic_common import logged_in_user
from eea.ldapadmin.ldap_config import _get_ldap_agent
from eea.ldapadmin.ui_common import orgs_in_country, nfp_for_country

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
if hasattr(CONFIG, 'environment'):
    CONFIG.environment.update(os.environ)
FORUM_URL = getattr(CONFIG, 'environment', {}).get('FORUM_URL', '')

password_letters = '23456789ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def generate_password():
    ''' generate a random password '''
    return ''.join(random.choice(password_letters) for n in range(8))


def generate_user_id(first_name, last_name, agent, id_list):
    ''' generate uid based on last and first name '''
    first_name = unidecode(first_name).replace(
        '-', '').replace("'", "").replace(" ", "")
    last_name = unidecode(last_name).replace(
        '-', '').replace("'", "").replace(" ", "")
    min_first_length = min(len(first_name), 3)
    uid1 = last_name[:8 - min_first_length]
    uid2 = first_name[:8 - len(uid1)]
    base_uid = (uid1 + uid2).lower()

    if not(list(agent.existing_usernames([base_uid])) or base_uid in id_list):
        return base_uid

    for i in range(8):
        for letter in string.ascii_lowercase:
            new_uid = base_uid[:8 - i - 1] + letter + base_uid[8 - i:]

            if not(list(agent.existing_usernames([new_uid])) or
                    new_uid in id_list):

                return new_uid
    return None


def process_url(url):
    ''' add url protocol if missing '''
    if url and not (url.startswith('http://') or url.startswith('https://')):
        return 'http://' + url

    return url


eionet_edit_users = 'Eionet edit users'

manage_add_users_admin_html = PageTemplateFile('zpt/users_manage_add.zpt',
                                               globals())
manage_add_users_admin_html.ldap_config_edit_macro = ldap_config.edit_macro
manage_add_users_admin_html.config_defaults = lambda: ldap_config.defaults


def manage_add_users_admin(parent, tool_id, REQUEST=None):
    """ Create a new UsersAdmin object """

    if REQUEST is not None:
        form = REQUEST.form
    else:
        form = {}
    config = ldap_config.read_form(form)
    obj = UsersAdmin(config)
    obj.title = form.get('title', tool_id)
    obj._setId(tool_id)
    parent._setObject(tool_id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')


def get_users_by_ldap_dump():
    ''' get users from the ldap dump cache '''
    LDAP_DISK_STORAGE = getattr(CONFIG, 'environment',
                                {}).get('LDAP_DISK_STORAGE', '')
    DB_FILE = os.path.join(LDAP_DISK_STORAGE, 'ldap_eionet_europa_eu.db')

    if not os.path.exists(DB_FILE):
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
    ''' return possibly duplicate users '''
    ldap_users = get_users_by_ldap_dump()

    records = []

    for user in ldap_users:
        distance = jellyfish.jaro_winkler(name, user['cn'])

        if distance >= UsersAdmin.similarity_level:
            records.append(user['dn'])

    return records


# this class should be called UsersEditor, similar to OrganisationsEditor
# and RolesEditor. But the name UsersEditor is already used by the
# `eea.userseditor` package, which lets users edit their own profile info.
class UsersAdmin(SimpleItem, PropertyManager):
    ''' The main user administration object '''
    meta_type = 'Eionet Users Admin'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_users_admin.gif'
    similarity_level = 0.939999
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
        ''' set breadcrumbs '''
        self.REQUEST._users_admin_crumbs = stack

    def breadcrumbtrail(self):
        ''' create the breadcrumb trail '''
        crumbs_html = self.aq_parent.breadcrumbtrail(self.REQUEST)
        extra_crumbs = getattr(self.REQUEST, '_users_admin_crumbs', [])

        return extend_crumbs(crumbs_html, self.absolute_url(), extra_crumbs)

    def _user_bread(self, uid, stack):
        """ Prepends a breadcrumb with link to main user page """
        stack.insert(0,
                     (uid, self.absolute_url() + "/edit_user?user_id=" + uid))

        return stack

    def _get_ldap_agent(self, bind=True, secondary=False):
        """ get the ldap agent """
        return _get_ldap_agent(self, bind, secondary)

    def checkPermissionZopeManager(self):
        """ Returns True if user has the manager role in Zope"""
        user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(view_management_screens, self))

    security.declareProtected(view_management_screens, 'get_config')

    def get_config(self):
        ''' return the object configuration '''
        return dict(self._config)

    security.declareProtected(view_management_screens, 'manage_edit')
    manage_edit = PageTemplateFile('zpt/users_manage_edit.zpt', globals())
    manage_edit.ldap_config_edit_macro = ldap_config.edit_macro

    security.declareProtected(view_management_screens, 'manage_edit_save')

    def manage_edit_save(self, REQUEST):
        """ save changes to configuration """
        self._config.update(ldap_config.read_form(REQUEST.form, edit=True))
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_edit')

    security.declareProtected(view, 'can_edit_users')

    def can_edit_users(self):
        ''' check permission to edit users '''
        user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(eionet_edit_users, self))

    security.declarePublic('checkPermissionEditUsers')

    def checkPermissionEditUsers(self):
        ''' check permission to edit users '''
        user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(eionet_edit_users, self))

    def index_html(self, REQUEST):
        """ view """

        if not self.checkPermissionEditUsers() and not nfp_for_country(self):
            raise Unauthorized
        options = {
            'can_edit': self.can_edit_users(),
            'search_fields': usersdb.db_agent.ACCEPTED_SEARCH_FIELDS,
        }

        search_name = REQUEST.form.get('name', '')
        lookup = REQUEST.form.get('lookup', '')

        base_url = self.portal_url()

        # if not REQUEST.ACTUAL_URL.endswith('/'):
        #     base_url += '/'

        options.update({
            'search_name': search_name,
            'lookup': lookup,
            'base_url': base_url + '/directory/user',
        })

        if search_name:
            agent = self._get_ldap_agent()
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
        """

        agent = self._get_ldap_agent()

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

        if nfp_for_country(self) or send_helpdesk_email:
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

        site = api.portal.get()
        if not self.checkPermissionEditUsers() and not nfp_for_country(self):
            raise Unauthorized
        options = {'first_name': first_name, 'user_id': user_id or 'USER_ID'}
        options['site_title'] = site.title

        return self._render_template.render(
            "zpt/users/email_registration_confirmation.zpt",
            **options)

    security.declarePublic('create_user')

    def create_user(self, REQUEST):
        """ view """
        agent = self._get_ldap_agent()

        permission_to_edit = self.checkPermissionEditUsers()
        nfp_country = nfp_for_country(self)

        if not (permission_to_edit or nfp_country):
            raise Unauthorized

        form_data = dict(REQUEST.form)
        errors = {}

        if not form_data.get('password', ''):
            form_data['password'] = generate_password()

        def no_duplicate_id_validator(node, value):
            ''' check if the user id is available '''
            if list(agent.existing_usernames([value])):
                raise colander.Invalid(node, 'This username is taken')

        schema = user_info_add_schema.clone()

        # no need to make the id mandatory, it will be generated if empty
        schema['id'].missing = None

        # if the user is an NFP and doesn't have explicit user editing
        # permission, hide the user id field with a hack
        # and add a help_text on the reasonToCreate field
        if not permission_to_edit:
            schema['id'].description = 'to_be_generated'
            schema['password'].missing = None

            schema['reasonToCreate'].help_text = (
                "Please indicate reason of account creation like e.g. "
                "Eionet Groups nomination, data reporter in Reportnet for "
                "directive XYZ, project XXXX cooperation ....")
        else:
            schema['id'].validator = colander.All(
                schema['id'].validator, no_duplicate_id_validator)

        for children in schema.children:
            help_text = help_messages['create-user'].get(children.name, None)
            setattr(children, 'help_text', help_text)

        if self.checkPermissionEditUsers():
            secondary_agent = self._get_ldap_agent(secondary=True)
            agent_orgs = secondary_agent.all_organisations()
        else:
            agent_orgs = orgs_in_country(self, nfp_country)

        orgs = [{'id': k, 'text': v['name'], 'text_native': v['name_native'],
                 'ldap':True}
                for k, v in agent_orgs.items()]
        org = form_data.get('organisation')

        if org and org not in agent_orgs:
            orgs.append({'id': org, 'text': org, 'text_native': '',
                         'ldap': False})

        comp = functools.cmp_to_key(
            lambda x, y: (x['text'] > y['text']) - (x['text'] < y['text']))
        orgs.sort(key=comp)

        choices = [('-', 'Please select organisation')]

        for org in orgs:
            if org['ldap']:
                if org['text_native']:
                    label = u"%s (%s, %s)" % (org['text'], org['text_native'],
                                              org['id'])
                else:
                    label = u"%s (%s)" % (org['text'], org['id'])
            else:
                label = org['text']
            choices.append((org['id'], label))

        widget = SelectWidget(values=choices)
        schema['organisation'].widget = widget
        msgs = IStatusMessage(REQUEST)

        if 'submit' in REQUEST.form:
            try:
                if form_data.get('organisation') == '-':
                    del form_data['organisation']
                user_form = deform.Form(schema)
                user_info = user_form.validate(list(form_data.items()))
                user_info['search_helper'] = _transliterate(
                    user_info['first_name'], user_info['last_name'],
                    user_info.get('full_name_native', ''),
                    user_info.get('search_helper', ''))
            except deform.ValidationFailure as e:
                for field_error in e.error.children:
                    errors[field_error.node.name] = field_error.msg
                msg = u"Please correct the errors below and try again."
                msgs.add(msg, type='error')
            else:
                user_id = user_info.get('id')
                if not user_id:
                    user_id = generate_user_id(user_info['first_name'],
                                               user_info['last_name'],
                                               agent,
                                               [])
                user_info['id'] = user_id
                agent = self._get_ldap_agent()
                with agent.new_action():
                    try:
                        self._create_user(agent, user_info)
                    except NameAlreadyExists:
                        errors['id'] = 'This ID is alreay registered'
                    except EmailAlreadyExists:
                        errors['email'] = 'This email is alreay registered'
                    else:
                        new_org_id = user_info['organisation']
                        new_org_id_valid = agent.org_exists(new_org_id)

                        if new_org_id_valid:
                            self._add_to_org(agent, new_org_id, user_id)

                        send_confirmation = 'send_confirmation' in \
                            list(form_data.keys())

                        if send_confirmation:
                            self.send_confirmation_email(user_info)
                            self.send_password_reset_email(user_info)

                        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        msg = "User %s created (%s)" % (user_id, when)
                        msgs.add(msg, type='info')

                        log.info("%s CREATED USER %s",
                                 logged_in_user(REQUEST),
                                 user_id)

                if not errors:
                    if not self.checkPermissionEditUsers():
                        return REQUEST.RESPONSE.redirect(
                            '/directory/user?uid=%s' % user_id)
                    return REQUEST.RESPONSE.redirect(self.absolute_url())
                msg = u"Please correct the errors below and try again."
                msgs.add(msg, type='error')

        self._set_breadcrumbs([('Create User', '#')])
        options = {
            'form_data': form_data,
            'errors': errors,
            'schema': schema
        }

        return self._render_template('zpt/users/create.zpt', **options)

    def find_duplicates(self, REQUEST):
        """ view """

        if not self.checkPermissionEditUsers() and not nfp_for_country(self):
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

    security.declareProtected(eionet_edit_users, 'edit_user_html')

    def edit_user_html(self, REQUEST, data=None, errors=None):
        """
        View for editing profile information for a given user
        with id passed through GET

        """
        user_id = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(user_id)

        if data:
            form_data = data
        else:
            form_data = user

        secondary_agent = self._get_ldap_agent(secondary=True)
        user_orgs = list(agent.user_organisations(user_id))

        nfp_country = nfp_for_country(self)
        if self.checkPermissionEditUsers():
            secondary_agent = self._get_ldap_agent(secondary=True)
            agent_orgs = secondary_agent.all_organisations()
        else:
            agent_orgs = orgs_in_country(self, nfp_country)
        orgs = [{'id': k, 'text': v['name'], 'text_native': v['name_native'],
                 'ldap': True} for k, v in agent_orgs.items()]

        if not user_orgs:
            org = form_data.get('organisation')

            if org:
                orgs.append(
                    {'id': org, 'text': org, 'text_native': '',
                     'ldap': False})
        else:
            org = user_orgs[0]
            org_id = agent._org_id(org)
            form_data['organisation'] = org_id

        comp = functools.cmp_to_key(
            lambda x, y: (x['text'] > y['text']) - (x['text'] < y['text']))
        orgs.sort(key=comp)

        schema = user_info_edit_schema.clone()

        choices = [('', '-')]

        for org in orgs:
            if org['ldap']:
                if org['text_native']:
                    label = u"%s (%s, %s)" % (org['text'], org['text_native'],
                                              org['id'])
                else:
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
                   'errors': errors or {},
                   'forum_url': FORUM_URL,
                   }
        self._set_breadcrumbs([(user_id, '#')])

        return self._render_template('zpt/users/edit.zpt', **options)

    security.declarePublic('edit_user')

    def edit_user(self, REQUEST):
        """ view """

        user_id = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user_orgs = agent._search_user_in_orgs(user_id)
        org_country = ''
        if user_orgs:
            org_country = user_orgs[0].split('_')[0]
        nfp_country = nfp_for_country(self)
        if not self.checkPermissionEditUsers() and (
                not nfp_country or nfp_country != org_country):
            # NFP's are only authorized to edit users with belonging to
            # an organisation from their country.
            raise Unauthorized
        if REQUEST.method == 'GET':
            return self.edit_user_html(REQUEST)

        schema = user_info_edit_schema.clone()
        user_form = deform.Form(schema)
        msgs = IStatusMessage(REQUEST)

        try:
            new_info = user_form.validate(list(REQUEST.form.items()))
        except deform.ValidationFailure as e:
            errors = {}

            for field_error in e.error.children:
                errors[field_error.node.name] = field_error.msg

            msg = u"Please correct the errors below and try again."
            msgs.add(msg, type='error')

            return self.edit_user_html(REQUEST, REQUEST.form, errors)
        else:

            new_org_id = new_info['organisation']
            new_org_id_valid = agent.org_exists(new_org_id)

            # make a check if user is changing the organisation
            user_orgs = [agent._org_id(org)
                         for org in list(agent.user_organisations(user_id))]

            new_info['search_helper'] = _transliterate(
                new_info['first_name'], new_info['last_name'],
                new_info.get('full_name_native', ''),
                new_info.get('search_helper', ''))

            with agent.new_action():
                if new_org_id not in user_orgs:
                    self._remove_from_all_orgs(agent, user_id)

                    if new_org_id_valid:
                        self._add_to_org(agent, new_org_id, user_id)

                agent.set_user_info(user_id, new_info)

            when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msgs.add("Profile saved (%s)" % when, type='info')

            log.info("%s EDITED USER %s as member of %s",
                     logged_in_user(REQUEST), user_id, new_org_id)

        return REQUEST.RESPONSE.redirect(
            self.absolute_url() + '/edit_user?id=' + user_id)

    def _add_to_org(self, agent, org_id, user_id):
        ''' add user to organisations '''
        try:
            agent.add_to_org(org_id, [user_id])
            log.info("USER %s ADDED %s as member of organisation %s",
                     logged_in_user(self.REQUEST), user_id, org_id)
        except ldap.INSUFFICIENT_ACCESS:
            ids = self.aq_parent.objectIds(["Eionet Organisations Editor"])

            if ids:
                obj = self.aq_parent[ids[0]]
                org_agent = obj._get_ldap_agent()
                org_agent.add_to_org(org_id, [user_id])
            else:
                raise

    def _remove_from_all_orgs(self, agent, user_id):
        ''' remove user from all orgs '''
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
                    org_agent = obj._get_ldap_agent()
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
        uid = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(uid)
        options = {'user': user}
        self._set_breadcrumbs(self._user_bread(uid, [("Delete User", '#')]))

        return self._render_template('zpt/users/delete.zpt', **options)

    security.declareProtected(eionet_edit_users, 'delete_user_action')

    def delete_user_action(self, REQUEST):
        """ Performing the delete action """
        uid = REQUEST.form['id']
        agent = self._get_ldap_agent()
        with agent.new_action():
            agent.delete_user(uid)

        IStatusMessage(REQUEST).add('User "%s" has been deleted.' % uid,
                                    type='info')

        log.info("%s DELETED USER %s", logged_in_user(REQUEST), uid)

        REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

    security.declareProtected(eionet_edit_users, 'disable_user')

    def disable_user(self, REQUEST):
        """
        View that asks for confirmation of user disable

        """
        uid = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(uid)
        options = {'user': user}
        self._set_breadcrumbs(self._user_bread(uid, [("Disable User", '#')]))

        return self._render_template('zpt/users/disable.zpt', **options)

    security.declareProtected(eionet_edit_users, 'disable_user_action')

    def disable_user_action(self, REQUEST):
        """ Performing the disable user action """
        uid = REQUEST.form['id']
        agent = self._get_ldap_agent()
        with agent.new_action():
            agent.disable_user(uid)

        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = 'User "%s" has been disabled. (%s)' % (uid, when)
        IStatusMessage(REQUEST).add(msg, type='info')
        log.info("%s DISABLED USER %s", logged_in_user(REQUEST), uid)

        return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

    security.declareProtected(eionet_edit_users, 'enable_user')

    def enable_user(self, REQUEST):
        """
        View that asks for confirmation of user enable

        """
        uid = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(uid)
        options = {'user': user}
        self._set_breadcrumbs(self._user_bread(uid, [("Enable User", '#')]))

        return self._render_template('zpt/users/enable.zpt', **options)

    security.declareProtected(eionet_edit_users, 'enable_user_action')

    def enable_user_action(self, REQUEST):
        """ Performing the enable user action """
        uid = REQUEST.form['id']
        restore_roles = REQUEST.form.get('restore_roles')
        agent = self._get_ldap_agent()
        with agent.new_action():
            agent.enable_user(uid, restore_roles=restore_roles)

        log.info("%s ENABLED USER %s", logged_in_user(REQUEST), uid)

        user_info = agent.user_info(uid)
        addr_from = "no-reply@eea.europa.eu"
        addr_to = user_info['email']

        email_password_body = self._render_template.render(
            "zpt/users/email_enabled_account.zpt", **user_info)

        message = MIMEText(email_password_body.encode('utf-8'),
                           _charset='utf-8')
        message['From'] = addr_from
        message['To'] = addr_to
        subject = "%s Account - account enabled" % NETWORK_NAME
        message['Subject'] = subject

        api.portal.send_email(recipient=[addr_to], sender=addr_from,
                              subject=subject, body=message)
        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if restore_roles:
            extra = ', previous roles restored'
        else:
            extra = ', previous roles NOT restored'
        msg = 'Account enabled for "%s (%s)"%s.' % (uid, when, extra)
        IStatusMessage(REQUEST).add(msg, type='info')

        return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

    security.declareProtected(eionet_edit_users, 'change_password')

    def change_password(self, REQUEST):
        """ View for changing user password """
        uid = REQUEST.form['id']
        agent = self._get_ldap_agent()
        user = agent.user_info(uid)
        options = {'user': user, 'password': generate_password()}

        self._set_breadcrumbs(self._user_bread(uid,
                                               [("Change Password", '#')]))

        return self._render_template('zpt/users/change_password.zpt',
                                     **options)

    security.declareProtected(eionet_edit_users, 'change_password_action')

    def change_password_action(self, REQUEST):
        """ Performing the delete action """
        uid = REQUEST.form['id']
        agent = self._get_ldap_agent()
        password = str(REQUEST.form['password'])
        with agent.new_action:
            agent.set_user_password(uid, None, password)

        user_info = agent.user_info(uid)
        addr_from = "no-reply@eea.europa.eu"
        addr_to = user_info['email']
        email_password_body = self.email_password(user_info['first_name'],
                                                  password, 'change')
        message = MIMEText(email_password_body.encode('utf-8'),
                           _charset='utf-8')
        message['From'] = addr_from
        message['To'] = addr_to
        subject = "%s Account - New password" % NETWORK_NAME
        message['Subject'] = subject

        api.portal.send_email(recipient=[addr_to], sender=addr_from,
                              subject=subject, body=message)
        IStatusMessage(REQUEST).add('Password changed for "%s".' % uid,
                                    type='info')

        return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

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
        secondary_agent = self._get_ldap_agent(secondary=True)
        orgs = secondary_agent.all_organisations()

        for org_id, info in six.iteritems(orgs):
            members = agent.members_in_org(org_id)

            if members:
                for user_id in members:
                    try:
                        user_info = agent.user_info(user_id)

                        if user_info['email'] not in bulk_emails:
                            bulk_emails.append(user_info['email'])
                    except (NO_SUCH_OBJECT, usersdb.UserNotFound):
                        pass
        return json.dumps(bulk_emails)

    security.declareProtected(eionet_edit_users, 'eionet_profile')

    def eionet_profile(self, REQUEST):
        """ Renders eionet full profile page """
        uid = REQUEST.form['user_id']
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
        """ send the password reset email """
        site = api.portal.get()
        pwreset_tool = site.objectValues('Eionet Password Reset Tool')[0]
        email = user_info['email']
        pwreset_tool.ask_for_password_reset(email=email, on_create=True)


InitializeClass(UsersAdmin)


def _send_email(addr_from, addr_to, message):
    ''' send an email '''
    api.portal.send_email(recipient=[addr_to], sender=addr_from,
                          subject=message.get('subject'), body=message)


class BulkUserImporter(BrowserView):
    """ A view to bulk import users from an xls file
    """
    buttons = ('download_template', 'bulk_create')
    TEMPLATE_COLUMNS = [
        "First Name*",
        "Last Name*",
        "Full name (native language)",
        "Search helper (ASCII characters only!)",
        "E-mail*",
        "Job Title",
        "URL",
        "Postal Address",
        "Telephone Number",
        "Mobile Telephone Number",
        "Fax Number",
        "Organisation*",
        "Department",
        "Reason to create*"]

    def __call__(self):
        """ upload view """

        if not self.request.form:
            return self.index()
        else:
            for name in self.buttons:
                if name in self.request.form:
                    return getattr(self, name)()
            return None

    def index(self):
        ''' main index page '''
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
        ''' process the uploaded excel file '''
        agent = self.context._get_ldap_agent()
        wb = xlrd.open_workbook(file_contents=data)
        ws = wb.sheets()[0]
        header = ws.row_values(0)

        if not len(header) == len(self.TEMPLATE_COLUMNS):
            raise ValueError("wrong number of columns")
        rows = []

        for i in range(ws.nrows)[1:]:
            rows.append(ws.row_values(i))

        result = []
        id_list = []

        for record_number, row in enumerate(rows):
            try:
                row = [x.strip() for x in row]
            except AttributeError:
                raise ValueError('Please format all cells as text!')
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
            if row_data['phone'] is None:
                row_data['phone'] = ''
            result.append(row_data)

        return result

    def bulk_create(self):
        """ view """
        data = self.request.form.get('data').read()

        msgs = IStatusMessage(self.request)
        try:
            rows = self.read_xls(data)
        except Exception as e:
            msgs.add('Invalid Excel file: %s' % e, type='error')
            log.exception("Exception while parsing bulk import users file")

            return self.index()

        agent = self.context._get_ldap_agent()

        users_data = []
        errors = []
        successfully_imported = []

        user_form = deform.Form(user_info_add_schema)

        for record_number, row_data in enumerate(rows):
            try:
                user_info = user_form.validate(list(row_data.items()))
                user_info['password'] = row_data['password']
            except deform.ValidationFailure as e:
                for field_error in e.error.children:
                    errors.append('%s at row %d: %s' %
                                  (field_error.node.name, record_number + 1,
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
                    users_data = [x for x in users_data
                                  if x['email'] != email.lower()]

        if len(usernames) != len(set(usernames)):
            for username in set(usernames):
                count = usernames.count(username)

                if count > 1:
                    errors.append('Duplicate user ID: %s appears %d times'
                                  % (username, count))
                    users_data = [x for x in users_data if x['id'] != username]

        existing_emails = set(agent.existing_emails(list(set(emails))))
        existing_users = set(agent.existing_usernames(
            list(set(usernames))))

        if existing_emails:
            for email in existing_emails:
                errors.append("The following email is already in database: %s"
                              % email)

            for email in existing_emails:
                users_data = [x for x in users_data
                              if x['email'] != email.lower()]

        if existing_users:
            for user_id in existing_users:
                errors.append("The following user ID is already registered: %s"
                              % user_id)

            for username in existing_users:
                users_data = [x for x in users_data if x['id'] != username]

        for user_info in users_data:
            user_info['search_helper'] = _transliterate(
                user_info['first_name'], user_info['last_name'],
                user_info.get('full_name_native', ''),
                user_info.get('search_helper', ''))
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
                except Exception:
                    msgs.add("Error sending confirmation email to %s"
                             % user_info['email'], type='error')
                try:
                    self.context.send_password_reset_email(user_info)
                except Exception as e:
                    msgs.add("Error: %s sending password reset email to %s"
                             % (e, user_info['email']), type='error')

                msg = u"%s %s (%s)" % \
                    (user_info['first_name'], user_info['last_name'], user_id)
                successfully_imported.append(msg)

        if errors:
            for err in errors:
                msgs.add(err, type='error')

        if successfully_imported:
            msg = 'User(s) %s successfully created.' % \
                ', '.join(successfully_imported)
            msgs.add(msg, type='info')
            logged_in = logged_in_user(self.request)

            for user_id in successfully_imported:
                log.info("%s CREATED USER %s", logged_in, user_id)
        else:
            msgs.add('No user account created', type='error')

        return self.context._render_template('zpt/users/bulk_create.zpt')


class ResetUser(BrowserView):
    """ A view to reset the roles of a user
    """

    index = NaayaViewPageTemplateFile('zpt/users/reset.zpt')

    def __call__(self):
        user_id = self.request.form.get('id')

        agent = self.context._get_ldap_agent()

        if 'submit' in self.request.form:
            with agent.new_action():
                agent.reset_user_roles(user_id)
            msg = 'Roles for user "%s" have been reset (deleted).' % user_id
            IStatusMessage(self.request).add(msg, type='info')
            log.info("%s RESETED USER %s", logged_in_user(self.request),
                     user_id)
            url = self.context.absolute_url() + '/edit_user?id=' + user_id

            return self.request.RESPONSE.redirect(url)

        user = agent.user_info(user_id)
        roles = []
        ldap_roles = agent.member_roles_info(
            'user', user_id, ('description', ))

        for (role_id, attrs) in ldap_roles:
            roles.append((role_id,
                          attrs.get('description', ('', ))[0]))
        options = {
            'common': CommonTemplateLogic(self.context),
            'context': self.context,
            'user': user,
            'roles': roles,
        }

        return self.index(**options)


class MigrateDisabledEmails(BrowserView):
    ''' restore the original email to disabled users '''

    def _get_metadata(self, metadata):
        ''' get metadata from json '''
        if not metadata:
            metadata = "[]"
        metadata = json.loads(metadata)

        return metadata

    def __call__(self):
        agent = self.context._get_ldap_agent()
        disabled_users = agent.get_disabled_users()

        for user_info in disabled_users:
            metadata = self._get_metadata(user_info['metadata'])
            email = agent._get_email_for_disabled_user(metadata)
            user_info['email'] = email
            agent.set_user_info(user_info['id'], user_info)
            log.info("Migrated disabled email info for user %s",
                     user_info['id'])

        return "done"


def _transliterate(first_name, last_name, full_name_native, search_helper):
    ''' transliterate unicode characters to ascii '''
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
