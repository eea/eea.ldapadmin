''' test the organisations ui '''
from io import StringIO
import logging
import unittest
from unittest.mock import Mock, patch
import six
from plone.api.user import get_current
from eea import usersdb
from eea.ldapadmin.orgs_editor import OrganisationsEditor, CommonTemplateLogic
from eea.ldapadmin.orgs_editor import validate_org_info, VALIDATION_ERRORS
from eea.ldapadmin.countries import get_country
from eea.ldapadmin.ui_common import TemplateRenderer
from eea.ldapadmin.testing import INTEGRATION_TESTING
from eea.ldapadmin.testing import base_setup, parse_html, status_messages

org_info_fixture = {
    'name': u"Ye olde bridge club",
    'name_native': u"Ye olde bridge club",
    'phone': u"+45 555 2222",
    'fax': u"+45 555 9999",
    'url': u"http://bridge.example.com/",
    'postal_address': (u"13 Card games road\n"
                       u"K\xf8benhavn, Danmark\n"),
    'street': u"Card games road",
    'po_box': u"123456",
    'postal_code': u"DK 456789",
    'country': u"eu",
    #    'country': u"European Union organisation, EU",
    'locality': u"K\xf8benhavn",
    'email': 'bridge@example.com',
}

validation_errors_fixture = {
    'id': [u"invalid ID"],
    'phone': [u"invalid PHONE"],
    'fax': [u"invalid FAX"],
    'postal_code': [u"invalid POSTAL CODE"],
}


class StubbedOrganisationsEditor(OrganisationsEditor):
    ''' Stubbed organisations editor '''
    def __init__(self):
        super(StubbedOrganisationsEditor, self).__init__()
        self._render_template = TemplateRenderer(CommonTemplateLogic)
        self._render_template.wrap = lambda html: "<html>%s</html>" % html

    def absolute_url(self):
        ''' return URL '''
        return "URL"


class OrganisationsUITest(unittest.TestCase):
    ''' test the organisations ui '''

    layer = INTEGRATION_TESTING

    def setUp(self):
        self.ui = StubbedOrganisationsEditor()
        user = get_current()
        base_setup(self, user)
        self.ui.checkPermissionView = Mock(return_value=True)
        self.ui.checkPermissionEditOrganisations = Mock(return_value=True)
        self.ui.nfp_for_country = Mock(return_value=None)
        self.ui.get_country = Mock(return_value='European Union organisation')
        self.mock_agent.all_organisations.return_value = {}
        org_info = dict(org_info_fixture)
        org_info['id'] = 'eu_bridgeclub'
        self.mock_agent.org_info = Mock(return_value=org_info)
        self.mock_agent.member_roles_info = Mock(return_value=[])
        self.stream = StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.log = logging.getLogger('orgs_editor')
        self.log.setLevel(logging.INFO)

        for handler in self.log.handlers:
            self.log.removeHandler(handler)
        self.log.addHandler(self.handler)

    def tearDown(self):
        self.log = logging.getLogger('orgs_editor')
        self.log.removeHandler(self.handler)
        self.handler.close()

    def test_create_org_form(self):
        ''' test the creat org form '''
        page = parse_html(self.ui.create_organisation_html(self.request))

        def exists(xp):
            ''' check existence of element in page '''
            return len(page.xpath(xp)) > 0

        self.assertTrue(exists('//form//input[@name="id:utf8:ustring"]'))
        self.assertTrue(exists('//form//input[@name="name:utf8:ustring"]'))
        self.assertTrue(exists('//form//input[@name="url:utf8:ustring"]'))
        self.assertTrue(exists('//form//input[@name="phone:utf8:ustring"]'))
        self.assertTrue(exists('//form//input[@name="fax:utf8:ustring"]'))
        self.assertTrue(exists('//form//input[@name="street:utf8:ustring"]'))
        self.assertTrue(exists('//form//input[@name="po_box:utf8:ustring"]'))
        self.assertTrue(exists('//form//input'
                               '[@name="postal_code:utf8:ustring"]'))
        self.assertTrue(exists('//form//input[@name="locality:utf8:ustring"]'))
        self.assertTrue(exists('//form//select[@name="country:utf8:ustring"]'))
        self.assertTrue(exists('//form//textarea'
                               '[@name="postal_address:utf8:ustring"]'))

    @patch('eea.ldapadmin.orgs_editor.logged_in_user')
    def test_create_org_submit(self, logged_user):
        ''' test submit on create org '''
        logged_user.return_value = "John Doe"
        self.request.form = dict(org_info_fixture)
        self.request.form['id'] = 'eu_bridgeclub'

        self.ui.create_organisation(self.request)

        self.mock_agent.create_org.assert_called_once_with('eu_bridgeclub',
                                                           org_info_fixture)
        self.request.RESPONSE.redirect.assert_called_with(
            'URL/organisation?id=eu_bridgeclub')

        logmsg = "John Doe CREATED ORGANISATION eu_bridgeclub\n"
        self.assertEqual(self.stream.getvalue(), logmsg)

    def _verify_org_form_submit_error(self, page, org_info, errors):
        ''' verify org submit error '''
        err_msg = page.xpath('//div[@class="error-msg"]')
        self.assertEqual(set(err_div.text for err_div in err_msg), errors)

        form = page.xpath('//form')[0]

        for name, value in six.iteritems(org_info):
            if name == 'postal_address':
                continue

            if name != 'id':
                name += ':utf8:ustring'

            if name == 'country:utf8:ustring':
                form_input = form.xpath(
                    './/select[@name="%s"]/option[@value="denmark"]' % name)
                value = value.lower()
            else:
                form_input = form.xpath('.//input[@name="%s"]' % name)

            self.assertEqual(form_input[0].attrib['value'], value)
        form_input = form.xpath(
            './/textarea[@name="postal_address:utf8:ustring"]')
        self.assertEqual(form_input[0].text, org_info['postal_address'])

    @patch('eea.ldapadmin.orgs_editor.validate_org_info')
    def test_create_org_submit_invalid(self, mock_validator):
        ''' test fail on invalid org data '''
        self.request.form = dict(org_info_fixture, id='eu_bridgeclub')
        mock_validator.return_value = validation_errors_fixture

        self.ui.create_organisation(self.request)

        mock_validator.assert_called_once_with('eu_bridgeclub',
                                               org_info_fixture,
                                               create_mode=True)
        self.assertEqual(self.mock_agent.create_org.call_count, 0)

    def test_edit_org_form(self):
        ''' test edit org form '''
        self.request.form = {'id': 'eu_bridgeclub'}
        self.mock_agent.org_info.return_value = dict(org_info_fixture,
                                                     id='eu_bridgeclub')

        page = parse_html(self.ui.edit_organisation_html(self.request))

        self.mock_agent.org_info.assert_called_once_with('eu_bridgeclub')

        form = page.xpath('//form')[0]
        self.assertEqual(form.attrib['action'], 'URL/edit_organisation')
        self.assertEqual(
            form.xpath('//input[@name="id:utf8:ustring"]')[0].attrib['value'],
            'eu_bridgeclub')

        for name, value in six.iteritems(org_info_fixture):
            if name == 'postal_address':
                xp = '//textarea[@name="%s:utf8:ustring"]' % name
                frm_value = form.xpath(xp)[0].text
            elif name == 'country':
                xp = '//select[@name="%s:utf8:ustring"]/option' % name.lower()
                frm_value = form.xpath(xp)[1].text.strip()
                country_data = get_country(value)
                value = '%s, %s' % (country_data['name'],
                                    country_data['pub_code'].upper())
            else:
                xp = '//input[@name="%s:utf8:ustring"]' % name
                frm_value = form.xpath(xp)[0].attrib['value']
            self.assertEqual(frm_value, value)

    @patch('eea.ldapadmin.orgs_editor.logged_in_user')
    def test_edit_org_submit(self, logged_user):
        ''' test submit on edit org '''
        logged_user.return_value = "John Doe"
        self.request.form = dict(org_info_fixture, id='eu_bridgeclub')

        self.ui.edit_organisation(self.request)

        self.mock_agent.set_org_info.assert_called_once_with(
            'eu_bridgeclub', org_info_fixture)
        self.request.RESPONSE.redirect.assert_called_with(
            'URL/organisation?id=eu_bridgeclub')

        logmsg = "John Doe EDITED ORGANISATION eu_bridgeclub\n"
        self.assertEqual(self.stream.getvalue(), logmsg)

    @patch('eea.ldapadmin.orgs_editor.validate_org_info')
    def test_edit_org_submit_invalid(self, mock_validator):
        ''' test fail on invalid org edit data '''
        self.request.form = dict(org_info_fixture, id='eu_bridgeclub')
        self.request.form['id'] = 'eu_bridgeclub'
        mock_validator.return_value = validation_errors_fixture

        self.ui.edit_organisation(self.request)

        mock_validator.assert_called_once_with('eu_bridgeclub',
                                               org_info_fixture)
        self.assertEqual(self.mock_agent.set_org_info.call_count, 0)

    def test_rename_org_page(self):
        ''' test rename org page '''
        self.request.form = {'id': 'eu_bridgeclub'}
        self.mock_agent.org_info.return_value = dict(org_info_fixture,
                                                     id='eu_bridgeclub')

        page = parse_html(self.ui.rename_organisation_html(self.request))

        form = page.xpath('//form[@name="rename_organisation"]')[0]
        self.assertEqual(form.attrib['action'], 'URL/rename_organisation')
        org_id_input = form.xpath('//input[@name="id"]')[0]
        self.assertEqual(org_id_input.attrib['value'], 'eu_bridgeclub')

    @patch('eea.ldapadmin.orgs_editor.logged_in_user')
    def test_rename_org_submit(self, logged_user):
        ''' test rename organisation '''
        logged_user.return_value = "John Doe"
        self.request.form = {'id': 'eu_bridgeclub', 'new_id': 'tunnel_club'}

        self.ui.rename_organisation(self.request)

        self.mock_agent.rename_org.assert_called_once_with('eu_bridgeclub',
                                                           'tunnel_club')
        self.request.RESPONSE.redirect.assert_called_with(
            'URL/organisation?id=tunnel_club')

        msg = 'Organisation "eu_bridgeclub" renamed to "tunnel_club".'
        self.assertEqual(status_messages(self.request), {'info': msg})

        logmsg = "John Doe RENAMED ORGANISATION eu_bridgeclub TO tunnel_club\n"
        self.assertEqual(self.stream.getvalue(), logmsg)

    def test_rename_org_submit_fail(self):
        ''' test fail on org rename '''
        self.request.form = {'id': 'eu_bridgeclub', 'new_id': 'tunnel_club'}
        self.mock_agent.rename_org.side_effect = usersdb.NameAlreadyExists()

        self.ui.rename_organisation(self.request)

        self.mock_agent.rename_org.assert_called_once_with('eu_bridgeclub',
                                                           'tunnel_club')
        self.request.RESPONSE.redirect.assert_called_with(
            'URL/organisation?id=eu_bridgeclub')
        msg = ('Organisation "eu_bridgeclub" could not be renamed because '
               '"tunnel_club" already exists.')
        self.assertEqual(status_messages(self.request), {'error': msg})

    def test_rename_org_submit_crash(self):
        ''' test crash on org rename '''
        self.request.form = {'id': 'eu_bridgeclub', 'new_id': 'tunnel_club'}
        self.mock_agent.rename_org.side_effect = usersdb.OrgRenameError()

        self.ui.rename_organisation(self.request)

        self.mock_agent.rename_org.assert_called_once_with('eu_bridgeclub',
                                                           'tunnel_club')
        self.request.RESPONSE.redirect.assert_called_with('URL/')
        msg = ('Renaming of "eu_bridgeclub" failed mid-way. Some data may be '
               'inconsistent. Please inform a system administrator.')
        self.assertEqual(status_messages(self.request), {'error': msg})

    def test_delete_org_page(self):
        ''' test delete org page '''
        import re
        self.request.form = {'id': 'eu_bridgeclub'}
        self.mock_agent.org_info.return_value = dict(org_info_fixture,
                                                     id='eu_bridgeclub')

        page = parse_html(self.ui.delete_organisation_html(self.request))

        txt = page.xpath('//p[@class="confirm-delete"]')[0].text_content()
        self.assertEqual(re.sub(r'\s+', ' ', txt.strip()),
                         ("Are you sure you want to delete the organisation "
                          "Ye olde bridge club (eu_bridgeclub)?"))
        id_input = page.xpath('//form//input[@name="id"]')[0]
        self.assertEqual(id_input.attrib['value'], 'eu_bridgeclub')

    @patch('eea.ldapadmin.orgs_editor.logged_in_user')
    def test_delete_org_submit(self, logged_user):
        ''' test delete organisation '''
        logged_user.return_value = "John Doe"
        self.request.form = {'id': 'eu_bridgeclub'}

        self.ui.delete_organisation(self.request)

        self.mock_agent.delete_org.assert_called_once_with('eu_bridgeclub')
        self.request.RESPONSE.redirect.assert_called_with('URL/')

        logmsg = "John Doe DELETED ORGANISATION eu_bridgeclub\n"
        self.assertEqual(self.stream.getvalue(), logmsg)


class OrganisationsUIMembersTest(unittest.TestCase):
    ''' test the members ui '''

    layer = INTEGRATION_TESTING

    def setUp(self):
        self.ui = StubbedOrganisationsEditor()
        user = get_current()
        base_setup(self, user)
        self.mock_agent.user_organisations = Mock(return_value=[])
        self.REQUEST.AUTHENTICATED_USER.getId = Mock(return_value='')

        user_list = {
            'anne': {
                'id': 'anne', 'first_name': "Anne", 'last_name': "Tester",
                'status': ''},
            'jsmith': {
                'id': 'jsmith', 'first_name': "Joe", 'last_name': "Smith",
                'status': ''},
        }
        self.mock_agent.members_in_org.return_value = sorted(user_list.keys())
        self.mock_agent.user_info.side_effect = user_list.get
        self.mock_agent.org_info.return_value = dict(org_info_fixture,
                                                     id='eu_bridgeclub')

        self.stream = StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.log = logging.getLogger('orgs_editor')
        self.log.setLevel(logging.INFO)

        for handler in self.log.handlers:
            self.log.removeHandler(handler)
        self.log.addHandler(self.handler)

    def tearDown(self):
        self.log = logging.getLogger('orgs_editor')
        self.log.removeHandler(self.handler)
        self.handler.close()

    def test_enumerate_members(self):
        ''' test members listing '''
        self.request.form = {'id': 'eu_bridgeclub'}

        page = parse_html(self.ui.members_html(self.request))

        self.mock_agent.members_in_org.assert_called_once_with('eu_bridgeclub')
        self.mock_agent.user_info.assert_called_with('jsmith')

        form = page.xpath('//form')[0]
        self.assertEqual(form.attrib['action'],
                         'URL/remove_members')
        self.assertEqual(
            form.xpath('.//input[@name="id"]')[0].attrib['value'],
            'eu_bridgeclub')

        members_td = page.xpath(
            './/table[@class="account-datatable dataTable"]/tbody/tr/td')
        self.assertTrue("Anne Tester" in members_td[2].text_content())
        self.assertTrue("Joe Smith" in members_td[6].text_content())

        anne_checkbox = members_td[0].xpath('.//input')[0]
        self.assertEqual(anne_checkbox.attrib['name'], 'user_id:list')
        self.assertEqual(anne_checkbox.attrib['value'], 'anne')

        jsmith_checkbox = members_td[4].xpath('.//input')[0]
        self.assertEqual(jsmith_checkbox.attrib['name'], 'user_id:list')
        self.assertEqual(jsmith_checkbox.attrib['value'], 'jsmith')

    @patch('eea.ldapadmin.orgs_editor.logged_in_user')
    def test_remove_members_submit(self, logged_user):
        ''' test removal of members '''
        logged_user.return_value = "John Doe"
        self.request.form = {'id': 'eu_bridgeclub', 'user_id': ['jsmith']}

        self.ui.remove_members(self.request)

        self.mock_agent.remove_from_org.assert_called_once_with(
            'eu_bridgeclub', ['jsmith'])
        self.request.RESPONSE.redirect.assert_called_with(
            'URL/members_html?id=eu_bridgeclub')

        logmsg = ("John Doe REMOVED MEMBERS ['jsmith'] FROM ORGANISATION "
                  "eu_bridgeclub\n")
        self.assertEqual(self.stream.getvalue(), logmsg)

    def test_add_members_html(self):
        ''' test add_members_html '''
        self.request.form = {'id': 'eu_bridgeclub', 'search_query': u"smith"}
        self.mock_agent.search_user.return_value = [
            {'id': 'anne', 'first_name': "Anne", 'last_name': "Smith"},
            {'id': 'jsmith', 'first_name': "Joe", 'last_name': "Something"},
        ]

        page = parse_html(self.ui.add_members_html(self.request))

        form_search = page.xpath('//form[@name="search-users"]')[0]
        self.assertEqual(form_search.attrib['action'],
                         'URL/add_members_html')
        _xp = './/input[@name="search_query:utf8:ustring"]'
        self.assertEqual(form_search.xpath(_xp)[0].attrib['value'], u"smith")

        form_add_members = page.xpath('//form[@name="add-members"]')[0]
        self.assertEqual(form_add_members.attrib['action'],
                         'URL/add_members')

        self.mock_agent.search_user.assert_called_once_with(u'smith')
        results_li = form_add_members.xpath('.//ul/li')
        self.assertTrue("Anne Smith" in results_li[0].text_content())
        self.assertTrue("Joe Something" in results_li[1].text_content())

        anne_checkbox = results_li[0].xpath('.//input')[0]
        self.assertEqual(anne_checkbox.attrib['name'], 'user_id:list')
        self.assertEqual(anne_checkbox.attrib['value'], 'anne')

    def test_add_members_submit(self):
        ''' test addition of members '''
        self.request.form = {'id': 'eu_bridgeclub', 'user_id': ['jsmith']}

        self.ui.add_members(self.request)

        self.mock_agent.add_to_org.assert_called_once_with(
            'eu_bridgeclub', ['jsmith'])
        self.request.RESPONSE.redirect.assert_called_with(
            'URL/members_html?id=eu_bridgeclub')

        self.request.form = {'id': 'eu_bridgeclub'}
        page = parse_html(self.ui.members_html(self.request))
        self.assertTrue('Joe Smith' in page.text_content())


class OrganisationsValidationTest(unittest.TestCase):
    ''' validation tests '''
    def _test_bad_values(self, name, values, msg):
        ''' test bad values '''
        for bad_value in values:
            org_info = dict(org_info_fixture, **{name: bad_value})
            err = validate_org_info('myorg', org_info)
            self.assertEqual(err[name], [msg],
                             "Missed bad %s %r" % (name, bad_value))

    def _test_good_values(self, name, values):
        ''' test good values '''
        for ok_value in values:
            org_info = dict(org_info_fixture, **{name: ok_value})
            err = validate_org_info('myorg', org_info)
            self.assertTrue(name not in err,
                            "False positive %r %r" % (name, ok_value))

    def _test_phone(self, name, msg):
        ''' test phone number '''
        bad_values = ['asdf', '1234adsf', '555 1234', '+55 3123 asdf']
        self._test_bad_values(name, bad_values, msg)

        good_values = ['', '+40123456789', '+40 12 34 56 78 9']
        self._test_good_values(name, good_values)

    def test_phone_number(self):
        ''' test the phone number '''
        self._test_phone('phone', VALIDATION_ERRORS['phone'])

    def test_fax_number(self):
        ''' test the fax number '''
        self._test_phone('fax', VALIDATION_ERRORS['fax'])

    def test_postcode(self):
        ''' test the postcode '''
        bad_values = ['123 456', 'DK_1234 33', u'DK 123\xf8456']
        self._test_bad_values('postal_code', bad_values,
                              VALIDATION_ERRORS['postal_code'])
        self._test_good_values('postal_code', ['', 'DK 1Nu 456', 'ro31-23'])

    def test_id(self):
        ''' test the id '''
        for bad_id in ['', '123', 'asdf123', 'my(org)', u'my_\xf8rg']:
            err = validate_org_info(bad_id, dict(org_info_fixture),
                                    create_mode=True)
            self.assertEqual(err['id'], [VALIDATION_ERRORS['id']],
                             "Missed bad org_id %r" % (bad_id,))

        for ok_id in ['a', 'my_org', '_myorg', '_', 'yet_another___one']:
            err = validate_org_info(ok_id, dict(org_info_fixture))
            self.assertTrue('id' not in err,
                            "False positive org_id %r" % (ok_id,))
