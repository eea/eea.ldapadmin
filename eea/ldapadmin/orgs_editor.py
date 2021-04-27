# pylint: disable=too-many-lines,super-init-not-called,too-many-statements
# pylint: disable=too-many-branches,too-many-locals,too-many-nested-blocks
# pylint: disable=too-many-public-methods,dangerous-default-value
# pylint: disable=global-statement,too-many-instance-attributes
''' Organisations editor '''
import codecs
import itertools
import logging
import operator
import re
from datetime import datetime
from io import BytesIO

import six
from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from AccessControl.Permissions import view, view_management_screens
from AccessControl.unauthorized import Unauthorized

import deform
import ldap
from ldap import NO_SUCH_OBJECT
from ldap import INVALID_DN_SYNTAX
import xlwt
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from persistent.mapping import PersistentMapping
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.statusmessages.interfaces import IStatusMessage
import eea.usersdb
from eea.ldapadmin.constants import USER_INFO_KEYS
from eea.ldapadmin.ui_common import (CommonTemplateLogic, TemplateRenderer,
                                     extend_crumbs, nfp_for_country,
                                     nfp_can_change_user)
from eea.ldapadmin.logic_common import logged_in_user, _is_authenticated
from eea.ldapadmin.logic_common import load_template
from eea.ldapadmin import ldap_config
from eea.ldapadmin.ldap_config import _get_ldap_agent
from .countries import get_country, get_country_options

log = logging.getLogger('orgs_editor')

eionet_edit_orgs = 'Eionet edit organisations'
eionet_edit_users = 'Eionet edit users'

manage_add_orgs_editor_html = PageTemplateFile('zpt/orgs_manage_add.zpt',
                                               globals())
manage_add_orgs_editor_html.ldap_config_edit_macro = ldap_config.edit_macro
manage_add_orgs_editor_html.config_defaults = lambda: ldap_config.defaults


def manage_add_orgs_editor(parent, tool_id, REQUEST=None):
    """ Adds a new Eionet Organisations Editor object """
    parent = parent.this()
    form = (REQUEST.form if REQUEST is not None else {})
    config = ldap_config.read_form(form)
    obj = OrganisationsEditor(config)
    tool_id = tool_id or 'orgeditor'
    obj.title = form.get('title', tool_id)
    obj._setId(tool_id)
    parent._setObject(tool_id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')


def get_template_macro(name):
    ''' get the template macro '''
    return load_template('zpt/orgs_macros.zpt').macros[name]


user_info_edit_schema = eea.usersdb.user_info_schema.clone()
user_info_edit_schema['postal_address'].widget = deform.widget.TextAreaWidget()
del user_info_edit_schema['first_name']
del user_info_edit_schema['last_name']


class OrganisationsEditor(SimpleItem, PropertyManager):
    ''' Organisations editor '''
    meta_type = 'Eionet Organisations Editor'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_organisations_editor.gif'
    manage_options = (
        {'label': 'Configure', 'action': 'manage_edit'},
        {'label': 'View', 'action': ''},
    ) + PropertyManager.manage_options + SimpleItem.manage_options

    _properties = (
        {'id': 'title', 'type': 'string', 'mode': 'w', 'label': 'Title'},
    )

    _render_template = TemplateRenderer(CommonTemplateLogic)

    def _set_breadcrumbs(self, stack):
        ''' set the breadcrumbs '''
        self.REQUEST._orgs_editor = stack

    def breadcrumbtrail(self):
        ''' create the breadcrumb trail '''
        crumbs_html = self.aq_parent.breadcrumbtrail(self.REQUEST)
        extra_crumbs = getattr(self.REQUEST, '_orgs_editor', [])

        return extend_crumbs(crumbs_html, self.absolute_url(), extra_crumbs)

    def __init__(self, config={}):
        super(OrganisationsEditor, self).__init__()
        self._config = PersistentMapping(config)

    security.declareProtected(view_management_screens, 'get_config')

    def get_config(self):
        ''' return the object's configuration '''
        return dict(self._config)

    security.declareProtected(view_management_screens, 'manage_edit')
    manage_edit = PageTemplateFile('zpt/orgs_manage_edit.zpt', globals())
    manage_edit.ldap_config_edit_macro = ldap_config.edit_macro

    security.declarePublic('checkPermissionView()')

    def checkPermissionView(self):
        ''' check permission to access object '''
        user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(view, self))

    security.declareProtected(view, 'can_edit_organisation')

    def can_edit_organisation(self):
        ''' check permission to edit organisation '''
        user = self.REQUEST.AUTHENTICATED_USER

        if user.has_permission(eionet_edit_orgs, self):
            return True
        nfp_country = self.nfp_for_country()

        if nfp_country:
            agent = self._get_ldap_agent()
            org_id = self.REQUEST.form.get('id')
            org_info = agent.org_info(org_id)

            if nfp_country == 'eea':
                return org_info['country'] in ['eu', 'int']
            return nfp_country == org_info['country']
        return False

    security.declarePublic('checkPermissionEditOrganisations()')

    def checkPermissionEditOrganisations(self):
        ''' check permission to edit organisations '''
        user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(eionet_edit_orgs, self))

    security.declarePublic('can_edit_organisations')

    def can_edit_organisations(self):
        ''' check if current user can edit organisations '''
        return bool(self.checkPermissionEditOrganisations() or
                    self.nfp_for_country())

    def nfp_for_country(self):
        ''' if the authenticated user is an NFP, return the two letter
        iso code of the country name '''
        return nfp_for_country(self)

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
        """ Index of organisations """
        country = REQUEST.get('country')
        nfp_country = self.nfp_for_country()

        if not (self.checkPermissionView() or nfp_country):
            raise Unauthorized
        agent = self._get_ldap_agent(secondary=True)
        orgs_by_id = agent.all_organisations()
        countries = dict(get_country_options(country))
        orgs = []

        for org_id, info in six.iteritems(orgs_by_id):
            country = countries.get(info['country'])

            if country:
                orgs.append({'id': org_id,
                             'name': info['name'],
                             'country': country['name'],
                             'country_pub_code': country['pub_code']})

        orgs.sort(key=operator.itemgetter('id'))
        options = {
            'sorted_organisations': orgs,
        }

        return self._render_template('zpt/orgs_index.zpt', **options)

    def export_organisations(self, REQUEST):
        """ Export of organisations """

        if not _is_authenticated(REQUEST):
            raise Unauthorized

        agent = self._get_ldap_agent()
        orgs_by_id = agent.all_organisations()

        if self.checkPermissionEditOrganisations():
            countries = dict(get_country_options())
            nfp_country = 'all'
        else:
            nfp_country = self.nfp_for_country()

            if not (self.checkPermissionView() or nfp_country):
                raise Unauthorized
            countries = dict(get_country_options(country=nfp_country))

        orgs = []

        for org_id, info in six.iteritems(orgs_by_id):
            country = countries.get(info['country'])

            if country:
                orgs.append({'id': org_id,
                             'name': info['name'],
                             'country': country['name'],
                             'country_pub_code': country['pub_code']})
        orgs.sort(key=operator.itemgetter('id'))

        for d in orgs:
            org_info = agent.org_info(d['id'])
            d.update(org_info)

        wb = xlwt.Workbook()
        org_sheet = wb.add_sheet("Organisations")
        users_sheet = wb.add_sheet("Members")

        style_header = xlwt.XFStyle()
        style_org_header = xlwt.XFStyle()
        style_normal = xlwt.XFStyle()

        normalfont = xlwt.Font()
        headerfont = xlwt.Font()
        headerfont.bold = True
        biggerheaderfont = xlwt.Font()
        biggerheaderfont.bold = True
        biggerheaderfont.height = int(biggerheaderfont.height * 1.3)

        style_header.font = headerfont
        style_normal.font = normalfont
        style_org_header.font = biggerheaderfont

        cols = [
            'id',
            'name',
            'locality',
            'postal_address',
            'fax',
            'email',
        ]

        for i, col in enumerate(cols):
            org_sheet.write(0, i, col.capitalize(), style_header)

        org_sheet.write(0, 6, "Members count", style_header)

        for i, row in enumerate(orgs):
            org_sheet.write(i + 2, 0, row['id'], style_normal)
            org_sheet.write(i + 2, 1, row['name'], style_normal)
            org_sheet.write(i + 2, 2, row['locality'], style_normal)
            org_sheet.write(i + 2, 3, row['postal_address'], style_normal)
            org_sheet.write(i + 2, 4, row['fax'], style_normal)
            org_sheet.write(i + 2, 5, row['email'], style_normal)
            members = agent.members_in_org(row['id'])
            org_sheet.write(i + 2, 6, len(members), style_normal)

        org_sheet.col(1).set_width(9000)
        org_sheet.col(2).set_width(5000)
        org_sheet.col(3).set_width(9000)
        org_sheet.col(4).set_width(4000)
        org_sheet.col(5).set_width(5000)

        row_counter = 0

        for org in orgs:
            org_id, org_name = org['id'], org['name']

            users_sheet.write(row_counter, 0, org_name, style_org_header)
            row = users_sheet.row(row_counter)
            row.height = int(row.height * 1.3)
            row_counter += 2

            org_members = []

            members = agent.members_in_org(org_id)

            for user_id in members:
                try:
                    org_members.append(agent.user_info(user_id))
                except (NO_SUCH_OBJECT, eea.usersdb.UserNotFound):
                    pass
            org_members.sort(key=operator.itemgetter('first_name'))

            cols = [
                'user id',
                'fullname',
                'email',
            ]

            for i, col in enumerate(cols):
                users_sheet.write(row_counter, i, col, style_header)

            for i, member in enumerate(org_members, 1):
                users_sheet.write(row_counter + i, 0, member['uid'])
                users_sheet.write(row_counter + i, 1, member['full_name'])
                users_sheet.write(row_counter + i, 2, member['email'])

            users_sheet.col(0).set_width(4000)
            users_sheet.col(1).set_width(6000)
            users_sheet.col(2).set_width(9000)

            row_counter += i + 2

        out = BytesIO()
        wb.save(out)
        out.seek(0)
        out = out.read()

        RESPONSE = REQUEST.RESPONSE

        RESPONSE.setHeader('Content-Type', "application/vnd.ms-excel")
        RESPONSE.setHeader('Content-Length', len(out))
        RESPONSE.setHeader('Pragma', 'public')
        RESPONSE.setHeader('Cache-Control', 'max-age=0')
        RESPONSE.addHeader("content-disposition",
                           "attachment; filename=%s-organisations.xls" %
                           nfp_country)

        return out

    def export_org(self, REQUEST):
        """ Export of one organisation """

        if not _is_authenticated(REQUEST):
            raise Unauthorized

        org_id = REQUEST.form['id']

        agent = self._get_ldap_agent()
        org_info = agent.org_info(org_id)
        wb = xlwt.Workbook()
        org_sheet = wb.add_sheet("Organisation Details")
        users_sheet = wb.add_sheet("Users")

        style_header = xlwt.XFStyle()
        style_normal = xlwt.XFStyle()
        normalfont = xlwt.Font()
        headerfont = xlwt.Font()
        headerfont.bold = True
        style_header.font = headerfont
        style_normal.font = normalfont

        cols = [
            'id',
            'name',
            'locality',
            'postal_address',
            'fax',
            'email',
        ]

        for i, col in enumerate(cols):
            org_sheet.write(0, i, col, style_header)
            org_sheet.write(2, i, org_info[col], style_normal)

        org_sheet.col(1).set_width(9000)
        org_sheet.col(2).set_width(5000)
        org_sheet.col(3).set_width(9000)
        org_sheet.col(4).set_width(4000)
        org_sheet.col(5).set_width(5000)

        org_members = []
        members = agent.members_in_org(org_id)

        for user_id in members:
            try:
                org_members.append(agent.user_info(user_id))
            except (NO_SUCH_OBJECT, eea.usersdb.UserNotFound):
                pass

        org_members.sort(key=operator.itemgetter('first_name'))

        cols = [
            'user id',
            'fullname',
            'email',
        ]

        for i, col in enumerate(cols):
            users_sheet.write(0, i, col, style_header)

        for i, member in enumerate(org_members, 2):
            users_sheet.write(i, 0, member['uid'])
            users_sheet.write(i, 1, member['full_name'])
            users_sheet.write(i, 2, member['email'])

        users_sheet.col(0).set_width(4000)
        users_sheet.col(1).set_width(6000)
        users_sheet.col(2).set_width(9000)

        out = BytesIO()
        wb.save(out)
        out.seek(0)
        out = out.read()

        RESPONSE = REQUEST.RESPONSE

        RESPONSE.setHeader('Content-Type', "application/vnd.ms-excel")
        RESPONSE.setHeader('Content-Length', len(out))
        RESPONSE.setHeader('Pragma', 'public')
        RESPONSE.setHeader('Cache-Control', 'max-age=0')
        RESPONSE.addHeader("content-disposition",
                           "attachment; filename=%s.xls" % org_id)

        return out

    security.declareProtected(view, 'organisation')

    def organisation(self, REQUEST):
        """ Index of an organisation """
        nfp_country = self.nfp_for_country()
        org_id = REQUEST.form.get('id')

        if not org_id:
            return REQUEST.RESPONSE.redirect(self.absolute_url())
        agent = self._get_ldap_agent()

        org_info = agent.org_info(org_id)

        if not (self.checkPermissionView() or
                nfp_country == org_info['country']):
            raise Unauthorized
        options = {
            'organisation': org_info,
            'country': get_country(org_info['country'])['name'],
        }
        self._set_breadcrumbs([('%s Organisation' % org_id, '#')])

        return self._render_template('zpt/orgs_view.zpt', **options)

    def create_organisation_html(self, REQUEST, data=None, errors=None):
        """ Page for adding an organisation """

        if not self.can_edit_organisations():
            msg = "You are not allowed to create an organisation"
            IStatusMessage(REQUEST).add(msg, 'error')

            return REQUEST.RESPONSE.redirect(self.absolute_url())

        nfp_country = self.nfp_for_country()

        if self.checkPermissionEditOrganisations():
            countries = get_country_options()
        else:
            countries = get_country_options(country=nfp_country)

        options = {
            'countries': countries,
            'form_macro': get_template_macro('org_form_fields'),
            'create_mode': True,
            'org_info': {},
            'errors': errors or {}
        }
        options['org_info'].update(data or {})

        self._set_breadcrumbs([('Create Organisation', '#')])

        return self._render_template('zpt/orgs_create.zpt', **options)

    def create_organisation(self, REQUEST):
        """ Create organisation """

        if not REQUEST.form:
            return self.create_organisation_html(REQUEST)

        msgs = IStatusMessage(REQUEST)

        if not self.can_edit_organisations():
            msg = ("You are not allowed to create an organisation")
            msgs.add(msg, type='error')

            return REQUEST.RESPONSE.redirect(self.absolute_url())

        org_id = REQUEST.form['id']
        org_info = {}

        for name in eea.usersdb.editable_org_fields:
            org_info[name] = REQUEST.form.get(name)

        errors = validate_org_info(org_id, org_info, create_mode=True)

        if errors:
            msg = "Organisation not created. Please correct the errors below."
            msgs.add(msg, type='error')

            for msg in itertools.chain(*list(errors.values())):
                msgs.add(msg, type='error')

            return self.create_organisation_html(REQUEST,
                                                 dict(org_info, id=org_id),
                                                 errors=errors)

        org_id = str(org_id)
        agent = self._get_ldap_agent()
        try:
            with agent.new_action():
                agent.create_org(org_id, org_info)
        except ldap.ALREADY_EXISTS:
            msg = "Organisation not created. Please correct the errors below."
            msgs.add(msg, type='error')
            msgs.add('Organisation ID exists already', type='error')

            return self.create_organisation_html(REQUEST,
                                                 dict(org_info, id=org_id))

        msg = 'Organisation "%s" created successfully.' % org_id
        msgs.add(msg, type='info')

        log.info("%s CREATED ORGANISATION %s", logged_in_user(REQUEST), org_id)

        return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                         '/organisation?id=' + org_id)

    def edit_organisation_html(self, REQUEST, data=None):
        """ Edit organisation data """

        org_id = REQUEST.form['id']

        if not self.can_edit_organisation():
            msg = "You are not allowed to edit this organisation"
            IStatusMessage(REQUEST).add(msg, type='error')
            REQUEST.RESPONSE.redirect(self.absolute_url() +
                                      '/organisation?id=' + org_id)

            return None

        nfp_country = self.nfp_for_country()

        if self.checkPermissionEditOrganisations():
            countries = get_country_options()
        else:
            countries = get_country_options(country=nfp_country)

        options = {
            'countries': countries,
            'form_macro': get_template_macro('org_form_fields'),
        }

        options['org_info'] = self._get_ldap_agent().org_info(org_id)
        options['org_info'].update(data or {})

        org_id = options['org_info']['id']
        self._set_breadcrumbs([
            (options['org_info']['id'],
             self.absolute_url() + '/organisation?id=%s' % org_id),
            ('Edit Organisation', '#')])

        return self._render_template('zpt/orgs_edit.zpt', **options)

    def edit_organisation(self, REQUEST):
        """ Save modifications in the organisation data """

        if REQUEST.method == 'GET':
            return self.edit_organisation_html(REQUEST)

        org_id = REQUEST.form['id']
        msgs = IStatusMessage(REQUEST)

        if not self.can_edit_organisation():
            msg = "You are not allowed to edit this organisation"
            msgs.add(msg, type='error')

            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/organisation?id=' + org_id)

        org_info = {}

        for name in eea.usersdb.editable_org_fields:
            org_info[name] = REQUEST.form.get(name)

        errors = validate_org_info(org_id, org_info)

        if errors:
            msg = "Organisation not modified. Please correct the errors below."
            msgs.add(msg, type='error')

            for msg in itertools.chain(*list(errors.values())):
                msgs.add(msg, type='error')

            return self.edit_organisation_html(REQUEST,
                                               dict(org_info, id=org_id))

        agent = self._get_ldap_agent()
        with agent.new_action():
            agent.set_org_info(org_id, org_info)

        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msgs.add("Organisation saved (%s)" % when, type='info')

        log.info("%s EDITED ORGANISATION %s", logged_in_user(REQUEST), org_id)

        return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                         '/organisation?id=' + org_id)

    def rename_organisation_html(self, REQUEST):
        """ Page for renaming an organisation """
        org_id = REQUEST.form['id']

        if not self.checkPermissionEditOrganisations():
            msg = "You are not allowed to change the ID of this organisation"
            IStatusMessage(REQUEST).add(msg, type='error')
            REQUEST.RESPONSE.redirect(self.absolute_url() +
                                      '/organisation?id=' + org_id)

            return None
        options = {
            'org_id': org_id,
        }
        self._set_breadcrumbs([
            (org_id, self.absolute_url() + '/organisation?id=%s' % org_id),
            ('Rename Organisation', '#')])

        return self._render_template('zpt/orgs_rename.zpt', **options)

    def rename_organisation(self, REQUEST):
        """ Save modifications in the organisation id """
        org_id = REQUEST.form['id']
        msgs = IStatusMessage(REQUEST)

        if not self.checkPermissionEditOrganisations():
            msg = "You are not allowed to change the ID of this organisation"
            msgs.add(msg, type='error')
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/organisation?id=' + org_id)

        new_org_id = REQUEST.form['new_id']

        if not re.match('^[a-z_]+$', new_org_id):
            msgs.add(VALIDATION_ERRORS['id'], type='error')

            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/organisation?id=' + org_id)

        if org_id == new_org_id:
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/organisation?id=' + org_id)

        agent = self._get_ldap_agent()

        try:
            with agent.new_action():
                agent.rename_org(org_id, new_org_id)
        except eea.usersdb.NameAlreadyExists:
            msg = ('Organisation "%s" could not be renamed because "%s" '
                   'already exists.' % (org_id, new_org_id))
            msgs.add(msg, type='error')
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/organisation?id=' + org_id)

        except eea.usersdb.OrgRenameError:
            msg = ('Renaming of "%s" failed mid-way. Some data may be '
                   'inconsistent. Please inform a system administrator.' %
                   org_id)
            msgs.add(msg, type='error')
            return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

        msg = ('Organisation "%s" renamed to "%s".' % (org_id, new_org_id))
        msgs.add(msg, type='info')

        log.info("%s RENAMED ORGANISATION %s TO %s",
                 logged_in_user(REQUEST), org_id, new_org_id)

        return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                         '/organisation?id=' + new_org_id)

    def delete_organisation_html(self, REQUEST):
        """ Delete organisation page """
        org_id = REQUEST.form['id']

        if not self.can_edit_organisation():
            msg = "You are not allowed to delete this organisation"
            IStatusMessage(REQUEST).add(msg, type='error')
            REQUEST.RESPONSE.redirect(self.absolute_url() +
                                      '/organisation?id=' + org_id)

            return None
        options = {
            'org_info': self._get_ldap_agent().org_info(org_id),
        }
        self._set_breadcrumbs([
            (options['org_info']['id'],
             self.absolute_url() + '/organisation?id=%s' % org_id),
            ('Delete Organisation', '#')])

        return self._render_template('zpt/orgs_delete.zpt', **options)

    def delete_organisation(self, REQUEST):
        """ Delete organisation """
        org_id = REQUEST.form['id']
        msgs = IStatusMessage(REQUEST)

        if not self.can_edit_organisation():
            msg = "You are not allowed to delete this organisation"
            msgs.add(msg, type='error')
            REQUEST.RESPONSE.redirect(self.absolute_url() +
                                      '/organisation?id=' + org_id)

            return None
        agent = self._get_ldap_agent()
        with agent.new_action():
            agent.delete_org(org_id)

        msgs.add('Organisation "%s" has been deleted.' % org_id, type='info')

        log.info("%s DELETED ORGANISATION %s", logged_in_user(REQUEST), org_id)

        return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

    security.declarePublic('members_html')

    def members_html(self, REQUEST):
        """ view """

        org_id = REQUEST.form.get('id')

        if not org_id:
            IStatusMessage(REQUEST).add("The organisation id is mandatory",
                                        type='error')

            return REQUEST.RESPONSE.redirect(self.absolute_url())
        agent = self._get_ldap_agent()

        org_members = []
        members = agent.members_in_org(org_id)

        for user_id in members:
            try:
                org_members.append(agent.user_info(user_id))
            except (NO_SUCH_OBJECT, INVALID_DN_SYNTAX,
                    eea.usersdb.UserNotFound):
                deleted_user_info = dict((prop, '') for prop in USER_INFO_KEYS)
                deleted_user_info['first_name'] = 'Former'
                deleted_user_info['last_name'] = 'Eionet member'
                deleted_user_info['full_name'] = 'Former Eionet member'
                deleted_user_info['uid'] = user_id
                deleted_user_info['id'] = user_id
                deleted_user_info['status'] = 'disabled'
                deleted_user_info['dn'] = agent._user_dn(user_id)
                org_members.append(deleted_user_info)

        org_members.sort(key=operator.itemgetter('first_name'))
        options = {
            'organisation': agent.org_info(org_id),
            'org_members': org_members,
        }
        self._set_breadcrumbs([
            (org_id, self.absolute_url() + '/organisation?id=%s' % org_id),
            ('Members', '#')])

        return self._render_template('zpt/orgs_members.zpt', **options)

    security.declareProtected(eionet_edit_orgs, 'demo_members')

    def demo_members(self, REQUEST):
        """ view """

        file_format = REQUEST.form.get('format', 'html')
        agent = self._get_ldap_agent()
        orgs_by_id = agent.all_organisations()

        orgs = []

        for org_id, info in six.iteritems(orgs_by_id):
            org_members = agent.members_in_org(org_id)
            members = []

            for user_id in org_members:
                try:
                    user_info = agent.user_info(user_id)
                    members.append(user_info)
                except (NO_SUCH_OBJECT, eea.usersdb.UserNotFound):
                    pass

            org = {
                'id': org_id,
                'name': info['name'],
                'country': info['country'],
                'members': members
            }
            orgs.append(org)

        orgs.sort(key=operator.itemgetter('name'))
        options = {
            'agent': agent,
            'orgs': orgs
        }

        if file_format == 'csv':
            import csv

            output = BytesIO()
            header = ('Organisation ID', 'Organisation name', 'Member ID',
                      'Member full name', 'Member email')

            REQUEST.RESPONSE.setHeader('Content-Type', 'text/csv')
            REQUEST.RESPONSE.setHeader('Content-Disposition',
                                       "attachment;filename=ldap_users.csv")

            csv_writer = csv.writer(output)
            csv_writer.writerow(header)

            rows = []

            for org in orgs:
                if not org['members']:
                    row = [org['id'], org['name'], 'NO MEMEBRS', '', '']
                    rows.append(row)
                else:
                    user_data = org['members'][0]
                    first_row = [org['id'], org['name'], user_data['id'],
                                 user_data['full_name'], user_data['email']]
                    rows.append(first_row)
                    org['members'].pop(0)

                    for user_data in org['members']:
                        row = ['', '', user_data['id'], user_data['full_name'],
                               user_data['email']]
                        rows.append(row)

            for item in rows:
                csv_writer.writerow([value.encode('utf-8') for value in item])

            return codecs.BOM_UTF8 + output.getvalue()

        return self._render_template('zpt/orgs_html_report.zpt', **options)

    def remove_members(self, REQUEST):
        """ view """
        org_id = REQUEST.form['id']
        msgs = IStatusMessage(REQUEST)

        if not self.can_edit_organisation():
            msg = "You are not allowed to remove members from this "\
                "organisation"
            msgs.add(msg, type='error')
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/members_html?id=' + org_id)

        user_id_list = REQUEST.form['user_id']

        assert isinstance(user_id_list, list)

        for user_id in user_id_list:
            assert isinstance(user_id, str)

        agent = self._get_ldap_agent()
        try:
            with agent.new_action():
                agent.remove_from_org(org_id, user_id_list)

            msg = 'Removed %d members from organisation "%s".' % \
                (len(user_id_list), org_id)
            msgs.add(msg, type='info')
            log.info("%s REMOVED MEMBERS %s FROM ORGANISATION %s",
                     logged_in_user(REQUEST), user_id_list, org_id)
        except (NO_SUCH_OBJECT, INVALID_DN_SYNTAX,
                eea.usersdb.UserNotFound):
            msg = ('Deleted users cannot be removed from orgsnisations yet '
                   '(will be implemented)')
            msgs.add(msg, type='error')

        return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                         '/members_html?id=' + org_id)

    security.declarePublic('add_members_html')

    def add_members_html(self, REQUEST):
        """ view """
        org_id = REQUEST.form['id']

        if not self.can_edit_organisation():
            msg = "You are not allowed to add members to this organisation"

            IStatusMessage(REQUEST).add(msg, type='error')
            REQUEST.RESPONSE.redirect(self.absolute_url() +
                                      '/members_html?id=' + org_id)

            return None
        search_query = REQUEST.form.get('search_query', u"")
        assert isinstance(search_query, six.text_type)

        if search_query:
            agent = self._get_ldap_agent()
            found_users = agent.search_user(search_query)
        else:
            found_users = []

        found_active = [user for user in found_users
                        if user.get('status') != 'disabled']
        if not self.checkPermissionEditOrganisations():
            # means the user is an NFP
            for user in found_active:
                if not nfp_can_change_user(self, user['id'], no_org=True):
                    user['restricted'] = True
        options = {
            'org_id': org_id,
            'search_query': search_query,
            'found_users': found_active,
            'found_inactive': len(found_active) != len(found_users)
        }
        self._set_breadcrumbs([
            (org_id, self.absolute_url() + '/organisation?id=%s' % org_id),
            ('Members',
             self.absolute_url() + '/members_html?id=%s' % org_id),
            ('Add Members', '#')])

        return self._render_template('zpt/orgs_add_members.zpt', **options)

    def add_members(self, REQUEST):
        """ view """
        org_id = REQUEST.form['id']

        if not self.can_edit_organisation():
            msg = "You are not allowed to add members to this organisation"
            IStatusMessage(REQUEST).add(msg, type='error')
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/members_html?id=' + org_id)

        user_id_list = REQUEST.form['user_id']
        agent = self._get_ldap_agent()

        if not self.checkPermissionEditOrganisations():
            # means the user is an NFP
            for user in user_id_list:
                if not nfp_can_change_user(self, user, no_org=True):
                    msg = ("User %s is member of an organisation from "
                           "another country" % user)
                IStatusMessage(REQUEST).add(msg, type='error')
                return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                                 '/members_html?id=' + org_id)

        assert isinstance(user_id_list, list)

        for user_id in user_id_list:
            assert isinstance(user_id, str)

        with agent.new_action():
            for user_id in user_id_list:
                old_info = agent.user_info(user_id)
                self._remove_from_all_orgs(agent, user_id)
                old_info['organisation'] = org_id
                agent.set_user_info(user_id, old_info)

            agent.add_to_org(org_id, user_id_list)

        msg = 'Added %d members to organisation "%s".' % (len(user_id_list),
                                                          org_id)
        IStatusMessage(REQUEST).add(msg, type='info')

        log.info("%s ADDED MEMBERS %s TO ORGANISATION %s",
                 logged_in_user(REQUEST), user_id_list, org_id)

        return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                         '/members_html?id=' + org_id)

    def can_edit_users(self, user=None):
        ''' check if authenticated user can edit users '''
        if user is None:
            user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(eionet_edit_users, self))

    def can_edit_members(self, user, org_id, member_id):
        """
        This could have been done as a decorator, but unfortunatelly
        Zope Publisher fails to match url address to callable when the
        arguments have arbitrary number

        """

        if user.getUserName() == 'Anonymous User':
            return False

        if self.can_edit_users(user):
            return True

        if not org_id:
            # top role - can_edit_users check was sufficient for granting

            return False

        agent = self._get_ldap_agent()
        org_members = agent.members_in_org(org_id)

        return member_id in org_members

    def _add_to_org(self, agent, org_id, user_id):
        ''' add user to org '''
        try:
            agent.add_to_org(org_id, [user_id])
        except ldap.INSUFFICIENT_ACCESS:
            ids = self.aq_parent.objectIds(["Eionet Organisations Editor"])

            if ids:
                obj = self.aq_parent[ids[0]]
                org_agent = obj._get_ldap_agent()
                org_agent.add_to_org(org_id, [user_id])
            else:
                raise

    def _remove_from_all_orgs(self, agent, user_id):
        ''' remove user from all organisations '''
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


InitializeClass(OrganisationsEditor)


id_re = re.compile(r'(^[a-z]{2}|int)_[a-z]+$')
phone_re = re.compile(r'^\+[\d ]+$')
postal_code_re = re.compile(r'^[a-zA-Z]{2}[a-zA-Z0-9\- ]+$')

_phone_help = ('Telephone numbers must be in international notation (they '
               'must start with a "+" followed by digits which may be '
               'separated using spaces).')
VALIDATION_ERRORS = {
    'id': ('Invalid organisation ID. Mandatory format xx_yyyy - '
           'It must start with a two letter lowercase country code, '
           'followed by an underscore ("_") and then any number '
           'of lowercase a-z letters (no accented characters - unlike the '
           'title, which can contain any characters).'),
    'name': "The organisation's name is mandatory",
    'phone': "Invalid telephone number. " + _phone_help,
    'fax': "Invalid fax number. " + _phone_help,
    'postal_code': ('Postal codes must be in international notation (they '
                    'must start with a two-letter country code followed by a '
                    'combination of digits, latin letters, dashes and '
                    'spaces).'
                    'Leave empty for international organisations.'),
    'country': "The country name is mandatory",
}


def validate_org_info(org_id, org_info, create_mode=False):
    ''' org info validation '''
    errors = {}

    if create_mode:
        if id_re.match(org_id) is None:
            errors['id'] = [VALIDATION_ERRORS['id']]

    name = org_info['name']

    if not name.strip():
        errors['name'] = [VALIDATION_ERRORS['name']]

    phone = org_info['phone']

    if phone and phone_re.match(phone) is None:
        errors['phone'] = [VALIDATION_ERRORS['phone']]

    fax = org_info['fax']

    if fax and phone_re.match(fax) is None:
        errors['fax'] = [VALIDATION_ERRORS['fax']]

    postal_code = org_info['postal_code']

    if postal_code and postal_code_re.match(postal_code) is None:
        errors['postal_code'] = [VALIDATION_ERRORS['postal_code']]

    country = org_info['country']

    if not country.strip():
        errors['country'] = [VALIDATION_ERRORS['country']]

    return errors
