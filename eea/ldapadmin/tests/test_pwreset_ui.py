import re
import unittest
import transaction
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from zope.component import getUtility
from plone.registry.interfaces import IRegistry
from Products.MailHost.interfaces import IMailHost
from plone.api.user import get_current
from plone.api import portal
from plone.testing.z2 import Browser
from eea.ldapadmin.testing import FUNCTIONAL_TESTING
from eea.ldapadmin.pwreset_tool import manage_add_pwreset_tool
from eea.ldapadmin.pwreset_tool import PasswordResetTool
import eea.usersdb


users = [
    {'id': 'teh-user', 'email': 'testpilot@example.com', 'status': ''},
]
mock_agent = Mock(spec=eea.usersdb.UsersDB)
filter_users = lambda email: [u for u in users if u['email'] == email]
mock_agent.search_user_by_email.side_effect = filter_users
PasswordResetTool._get_ldap_agent = Mock(return_value=mock_agent)

portal.send_email = Mock()


def extract_link_from_email(email, url_base):
    url_piece = url_base + '/confirm_email?token='
    match = re.search(re.escape(url_piece) + r'(?P<token>\S+)(?=\s)',
                      email['body'].get_payload())
    assert match is not None
    return match.group()


def parse_html(html):
    from lxml.html.soupparser import fromstring
    return fromstring(html)


def csstext(target, selector):
    from lxml.cssselect import CSSSelector
    return ' '.join(e.text_content() for e in
                    CSSSelector(selector)(target)).strip()


def decode_form(request):
    form = {}
    source = request.POST or request.GET
    for name in source:
        value = source[name]
        if name.endswith(':utf8:ustring'):
            value = value.decode('utf-8')
            name = name[:-(len(':utf8:ustring'))]
        form[name] = value
    return form


class BrowseTest(unittest.TestCase):

    layer = FUNCTIONAL_TESTING

    def setUp(self):
        app = self.layer['app']
        self.portal = self.layer['portal']
        manage_add_pwreset_tool(self.portal, 'pwreset')
        transaction.commit()
        self.app_url = self.portal.pwreset.absolute_url()
        self.request = self.layer['portal'].REQUEST
        self.browser = Browser(app)
        self.browser.handleErrors = False  # Don't get HTTP 500 pages

        self.portal.error_log._ignored_exceptions = ()

        def raising(self, info):
            import traceback
            traceback.print_tb(info[2])
            print(info[1])

        from Products.SiteErrorLog.SiteErrorLog import SiteErrorLog
        SiteErrorLog.raising = raising

        self.mailhost = getUtility(IMailHost)
        registry = getUtility(IRegistry)
        registry["plone.email_from_address"] = "user-directory@plone.org"
        registry["plone.email_from_name"] = u"Plone test site"

        request = self.layer['portal'].REQUEST
        user = get_current()
        request.AUTHENTICATED_USER = user
        self.portal.pwreset.REQUEST = self.portal.pwreset.request = request
        self.mock_agent = self.portal.pwreset._get_ldap_agent()

    def tearDown(self):
        mock_agent.set_user_password.reset_mock()
        portal.send_email.reset_mock()

    def assert_invalid_token_response(self, page):
        self.assertEqual(csstext(page, 'div.error'),
                         "Error\n        Password reset link is invalid, "
                         "perhaps it has expired. Please try again.")
        self.assertFalse(self.mock_agent.set_user_password.called)

    def test_welcome_page(self):
        br = self.browser
        br.open(self.app_url)
        page = parse_html(br.contents)

        self.assertEqual(csstext(page, 'h1'), "Reset Eionet account password")

    def test_reset_password(self):
        br = self.browser
        br.open(self.app_url)
        form = br.getForm('identify')
        input = form.getControl(name='email:utf8:ustring')
        input.value = 'testpilot@example.com'
        form.submit('Reset password')
        page = parse_html(br.contents)

        self.assertTrue("message has been sent" in csstext(page, 'p'))

        self.assertEqual(len(self.portal.pwreset._tokens), 1)

        self.assertEqual(portal.send_email.call_count, 1)
        email = portal.send_email.call_args[1]
        self.assertEqual(email['recipient'], ["testpilot@example.com"])
        link = extract_link_from_email(email,
                                       self.portal.pwreset.absolute_url())
        token = list(self.portal.pwreset._tokens.keys())[0]
        self.assertEqual(link.rsplit('=', 1)[-1], token)

        link = '%s/confirm_email?token=%s' % (
            self.portal.pwreset.absolute_url(), token)
        br.open(link)
        page = parse_html(br.contents)

        self.assertEqual(csstext(page, 'p tt'), 'teh-user')

        # first should fail with non matching passwords
        form = br.getForm('new-password')
        input = form.getControl(name='password:utf8:ustring')
        input.value = 'NeWpAsS'
        input = form.getControl(name='password-confirm:utf8:ustring')
        input.value = 'newpass'
        form.submit('Save new password')
        page = parse_html(br.contents)

        self.assertEqual(csstext(page, 'div.error'),
                         "Error\n        Passwords do not match.")
        form = br.getForm('new-password')
        input = form.getControl(name='password:utf8:ustring')
        input.value = 'NeWpAsS'
        input = form.getControl(name='password-confirm:utf8:ustring')
        input.value = 'NeWpAsS'
        form.submit('Save new password')
        page = parse_html(br.contents)

        self.mock_agent.set_user_password.assert_called_once_with(
            'teh-user', None, "NeWpAsS")
        self.assertTrue("successfully reset" in csstext(page, 'p'))

    def test_enter_bad_email(self):
        br = self.browser
        br.open(self.app_url)
        form = br.getForm('identify')
        input = form.getControl(name='email:utf8:ustring')
        input.value = 'badtestpilot@example.com'
        form.submit('Reset password')
        page = parse_html(br.contents)

        self.assertEqual(csstext(page, 'div.error'),
                         "Error\n        Email address not found in database.")
        self.assertEqual(portal.send_email.call_count, 0)
        self.assertEqual(len(self.portal.pwreset._tokens), 0)

    def test_invalid_token_in_link(self):
        token = "bogus-token"
        link = '%s/confirm_email?token=%s' % (
            self.portal.pwreset.absolute_url(), token)
        br = self.browser
        br.open(link)
        page = parse_html(br.contents)

        self.assert_invalid_token_response(page)

    @patch('eea.ldapadmin.pwreset_tool.datetime')
    def test_token_expiry(self, mock_datetime):
        t0 = datetime.utcnow()
        mock_datetime.utcnow.return_value = t0
        br = self.browser
        br.open(self.app_url)
        form = br.getForm('identify')
        input = form.getControl(name='email:utf8:ustring')
        input.value = 'testpilot@example.com'
        form.submit('Reset password')
        token = list(self.portal.pwreset._tokens.keys())[0]
        mock_datetime.utcnow.return_value = t0 + timedelta(days=1, minutes=1)
        link = '%s/confirm_email?token=%s' % (
            self.portal.pwreset.absolute_url(), token)
        br.open(link)
        page = parse_html(br.contents)

        self.assert_invalid_token_response(page)

    @patch('eea.ldapadmin.pwreset_tool.datetime')
    def test_token_expiry_in_form(self, mock_datetime):
        t0 = datetime.utcnow()
        mock_datetime.utcnow.return_value = t0
        br = self.browser
        br.open(self.app_url)
        form = br.getForm('identify')
        input = form.getControl(name='email:utf8:ustring')
        input.value = 'testpilot@example.com'
        form.submit('Reset password')
        token = list(self.portal.pwreset._tokens.keys())[0]
        link = '%s/confirm_email?token=%s' % (
            self.portal.pwreset.absolute_url(), token)
        br.open(link)
        mock_datetime.utcnow.return_value = t0 + timedelta(days=1, minutes=1)
        page = parse_html(br.contents)
        form = br.getForm('new-password')
        input = form.getControl(name='password:utf8:ustring')
        input.value = 'NeWpAsS'
        input = form.getControl(name='password-confirm:utf8:ustring')
        input.value = 'NeWpAsS'
        form.submit('Save new password')
        page = parse_html(br.contents)

        self.assert_invalid_token_response(page)

    def test_no_token_reuse(self):
        br = self.browser
        br.open(self.app_url)
        form = br.getForm('identify')
        input = form.getControl(name='email:utf8:ustring')
        input.value = 'testpilot@example.com'
        form.submit('Reset password')
        token = list(self.portal.pwreset._tokens.keys())[0]
        link = '%s/confirm_email?token=%s' % (
            self.portal.pwreset.absolute_url(), token)
        br.open(link)
        form = br.getForm('new-password')
        input = form.getControl(name='password:utf8:ustring')
        input.value = 'NeWpAsS'
        input = form.getControl(name='password-confirm:utf8:ustring')
        input.value = 'NeWpAsS'
        form.submit('Save new password')

        self.assertFalse(token in self.portal.pwreset._tokens)

    @patch('eea.ldapadmin.ui_common.CommonTemplateLogic.network_name')
    def test_network_name_customization(self, mock_network_name):
        mock_network_name.return_value = 'SINAnet'
        br = self.browser
        br.open(self.app_url)
        page = parse_html(br.contents)

        self.assertEqual(csstext(page, 'h1'), "Reset SINAnet account password")
