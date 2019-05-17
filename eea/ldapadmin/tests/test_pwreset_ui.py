import unittest
import re
from datetime import datetime, timedelta
from zope.component import getGlobalSiteManager
from zope.sendmail.interfaces import IMailDelivery
from mock import Mock, patch
from webob import Response
from webob.exc import HTTPNotFound, HTTPSeeOther
from webob.dec import wsgify
from eea.ldapadmin.pwreset_tool import PasswordResetTool, CommonTemplateLogic
from eea.ldapadmin.ui_common import TemplateRenderer
import eea.usersdb


def stubbed_renderer():
    renderer = TemplateRenderer(CommonTemplateLogic)
    renderer.wrap = lambda html: "<html>%s</html>" % html
    return renderer


class StubbedPasswordResetTool(PasswordResetTool):
    def __init__(self):
        super(StubbedPasswordResetTool, self).__init__()
        self._render_template = stubbed_renderer()

    def absolute_url(self):
        return "http://test"


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


class WsgiApp(object):
    def __init__(self, ui):
        self.ui = ui
        self.session = {}

    @wsgify
    def __call__(self, request):
        request.SESSION = self.session
        request.RESPONSE = Mock()
        request.form = decode_form(request)
        try:
            name = request.path[1:] or 'index_html'
            method = getattr(self.ui, name)
        except AttributeError:
            return HTTPNotFound()
        else:
            self.ui.REQUEST = request
            body = method(request)

            if request.RESPONSE.redirect.called:
                url = request.RESPONSE.redirect.call_args[0][0]
                return HTTPSeeOther(location=url)

            else:
                return Response(body)


def parse_email(mimetext):
    from email.parser import Parser
    return Parser().parsestr(mimetext)


def csstext(target, selector):
    from lxml.cssselect import CSSSelector
    return ' '.join(e.text_content() for e in
                    CSSSelector(selector)(target)).strip()


def parse_html(html):
    from lxml.html.soupparser import fromstring
    return fromstring(html)


def extract_link_from_email(email, url_base):
    url_piece = url_base + '/confirm_email?token='
    match = re.search(re.escape(url_piece) + r'(?P<token>\S+)(?=\s)',
                      email.get_payload())
    assert match is not None
    return match.group()


class BrowseTest(unittest.TestCase):
    def setUp(self):
        self.ui = StubbedPasswordResetTool()
        self.mock_agent = Mock(spec=eea.usersdb.UsersDB)
        self.ui._get_ldap_agent = Mock(return_value=self.mock_agent)

        users = [
            {'id': 'teh-user', 'email': 'testpilot@example.com'},
        ]
        filter_users = lambda email: [u for u in users if u['email'] == email]
        self.mock_agent.search_user_by_email.side_effect = filter_users

        self.mail = []
        self.mail_delivery = Mock()
        self.mail_delivery.send = lambda afrom, ato, msg: self.mail.append(msg)

        gsm = getGlobalSiteManager()
        gsm.registerUtility(self.mail_delivery, IMailDelivery, "Mail")

        app = WsgiApp(self.ui)

        import wsgi_intercept.mechanize_intercept
        wsgi_intercept.add_wsgi_intercept('test', 80, lambda: app)
        self.browser = wsgi_intercept.mechanize_intercept.Browser()

    def tearDown(self):
        import wsgi_intercept
        wsgi_intercept.remove_wsgi_intercept('test', 80)

        gsm = getGlobalSiteManager()
        gsm.unregisterUtility(self.mail_delivery, IMailDelivery, "Mail")

    def test_welcome_page(self):
        br = self.browser
        page = parse_html(br.open('http://test/').read())

        self.assertEqual(csstext(page, 'h1'), "Reset EIONET account password")

    def test_enter_email(self):
        br = self.browser
        br.open('http://test/')
        br.select_form(name='identify')
        br['email:utf8:ustring'] = "testpilot@example.com"
        page = parse_html(br.submit().read())

        self.assertTrue("message has been sent" in csstext(page, 'p'))

        self.assertEqual(len(self.ui._tokens), 1)
        token = self.ui._tokens.keys()[0]

        self.assertEqual(len(self.mail), 1)
        email = parse_email(self.mail[0])
        self.assertEqual(email['to'], "testpilot@example.com")
        link = extract_link_from_email(email, 'http://test')
        self.assertEqual(link.rsplit('=', 1)[-1], token)

    def test_enter_bad_email(self):
        br = self.browser
        br.open('http://test/')
        br.select_form(name='identify')
        br['email:utf8:ustring'] = "badtestpilot@example.com"
        page = parse_html(br.submit().read())

        self.assertEqual(csstext(page, 'div.error-msg'),
                         "Email address not found in database.")
        self.assertEqual(len(self.ui._tokens), 0)
        self.assertEqual(len(self.mail), 0)

    def test_enter_new_password(self):
        token = self.ui._new_token('teh-user')
        link = 'http://test/confirm_email?token=' + token
        br = self.browser
        page = parse_html(br.open(link).read())

        self.assertEqual(csstext(page, 'p tt'), 'teh-user')

        br.select_form(name='new-password')
        br['password:utf8:ustring'] = "NeWpAsS"
        br['password-confirm:utf8:ustring'] = "NeWpAsS"
        page = parse_html(br.submit().read())

        self.mock_agent.set_user_password.assert_called_once_with(
            'teh-user', None, "NeWpAsS")
        self.assertTrue("successfully reset" in csstext(page, 'p'))

    def test_new_passwords_do_not_match(self):
        token = self.ui._new_token('teh-user')
        link = 'http://test/confirm_email?token=' + token
        br = self.browser
        br.open(link)
        br.select_form(name='new-password')
        br['password:utf8:ustring'] = "NeWpAsS"
        br['password-confirm:utf8:ustring'] = "blah"
        page = parse_html(br.submit().read())

        self.assertEqual(csstext(page, 'div.error-msg'),
                         "Passwords do not match.")

        # make sure the new form still works
        br.select_form(name='new-password')
        br['password:utf8:ustring'] = "NeWpAsS"
        br['password-confirm:utf8:ustring'] = "NeWpAsS"
        page = parse_html(br.submit().read())
        self.assertTrue("successfully reset" in csstext(page, 'p'))

    def assert_invalid_token_response(self, page):
        self.assertEqual(csstext(page, 'div.error-msg'),
                         "Password reset link is invalid, perhaps it has "
                         "expired. Please try again.")
        self.assertFalse(self.mock_agent.set_user_password.called)

    def test_invalid_token_in_link(self):
        token = "bogus-token"
        link = 'http://test/confirm_email?token=' + token
        br = self.browser
        page = parse_html(br.open(link).read())

        self.assert_invalid_token_response(page)

    def test_invalid_token_from_form(self):
        token = self.ui._new_token('teh-user')
        link = 'http://test/confirm_email?token=' + token
        br = self.browser
        br.open(link)
        br.select_form(name='new-password')
        br['password:utf8:ustring'] = "NeWpAsS"
        br['password-confirm:utf8:ustring'] = "NeWpAsS"
        del self.ui._tokens[token]
        page = parse_html(br.submit().read())

        self.assert_invalid_token_response(page)

    @patch('eea.ldapadmin.pwreset_tool.datetime')
    def test_token_expiry(self, mock_datetime):
        t0 = datetime(2011, 05, 02, 13, 30, 22)
        mock_datetime.utcnow.return_value = t0
        token = self.ui._new_token('teh-user')
        link = 'http://test/confirm_email?token=' + token

        mock_datetime.utcnow.return_value = t0 + timedelta(days=1, minutes=1)
        br = self.browser
        page = parse_html(br.open(link).read())

        self.assert_invalid_token_response(page)

    @patch('eea.ldapadmin.pwreset_tool.datetime')
    def test_token_expiry_in_form(self, mock_datetime):
        t0 = datetime(2011, 05, 02, 13, 30, 22)
        mock_datetime.utcnow.return_value = t0
        token = self.ui._new_token('teh-user')
        link = 'http://test/confirm_email?token=' + token

        br = self.browser
        br.open(link)
        br.select_form(name='new-password')
        br['password:utf8:ustring'] = "NeWpAsS"
        br['password-confirm:utf8:ustring'] = "NeWpAsS"

        mock_datetime.utcnow.return_value = t0 + timedelta(days=1, minutes=1)
        page = parse_html(br.submit().read())

        self.assert_invalid_token_response(page)

    def test_no_token_reuse(self):
        br = self.browser
        br.open('http://test/')
        br.select_form(name='identify')
        br['email:utf8:ustring'] = "testpilot@example.com"
        br.submit()
        email = parse_email(self.mail[0])
        link = extract_link_from_email(email, 'http://test')
        token = link.rsplit('=')[-1]

        self.assertTrue(token in self.ui._tokens)

        parse_html(br.open(link).read())
        br.select_form(name='new-password')
        br['password:utf8:ustring'] = "NeWpAsS"
        br['password-confirm:utf8:ustring'] = "NeWpAsS"
        br.submit()

        self.assertFalse(token in self.ui._tokens)

    def test_successful_workflow(self):
        br = self.browser
        br.open('http://test/')
        br.select_form(name='identify')
        br['email:utf8:ustring'] = "testpilot@example.com"
        br.submit()

        email = parse_email(self.mail[0])
        link = extract_link_from_email(email, 'http://test')
        page = parse_html(br.open(link).read())
        br.select_form(name='new-password')
        br['password:utf8:ustring'] = "NeWpAsS"
        br['password-confirm:utf8:ustring'] = "NeWpAsS"
        page = parse_html(br.submit().read())

        self.mock_agent.set_user_password.assert_called_once_with(
            'teh-user', None, "NeWpAsS")
        self.assertTrue("successfully reset" in csstext(page, 'p'))

    @patch('eea.ldapadmin.pwreset_tool.NETWORK_NAME', 'SINAnet')
    def test_network_name_customization(self):
        br = self.browser
        page = parse_html(br.open('http://test/').read())

        self.assertEqual(csstext(page, 'h1'), "Reset SINAnet account password")
