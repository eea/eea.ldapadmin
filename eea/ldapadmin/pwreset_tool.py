from __future__ import print_function
import base64
import hashlib
import logging
import random
from collections import namedtuple
from datetime import datetime, timedelta
from email.mime.text import MIMEText

from zope.component import getUtility
from zope.sendmail.interfaces import IMailDelivery

from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from App.class_init import InitializeClass
from eea.ldapadmin import ldap_config, query
from eea.ldapadmin.constants import NETWORK_NAME
from eea.ldapadmin.ui_common import (CommonTemplateLogic, TemplateRenderer,
                                     load_template)
from eea.ldapadmin.users_admin import eionet_edit_users
from ldap import CONSTRAINT_VIOLATION, NO_SUCH_OBJECT, SCOPE_BASE
from OFS.SimpleItem import SimpleItem
from persistent.mapping import PersistentMapping
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.statusmessages.interfaces import IStatusMessage
import six

log = logging.getLogger(__name__)

manage_add_pwreset_tool_html = PageTemplateFile('zpt/pwreset_manage_add.zpt',
                                                globals())
manage_add_pwreset_tool_html.ldap_config_edit_macro = ldap_config.edit_macro
manage_add_pwreset_tool_html.config_defaults = lambda: ldap_config.defaults


def manage_add_pwreset_tool(parent, id, REQUEST=None):
    """ Create a new PasswordResetTool object """
    form = (REQUEST is not None and REQUEST.form or {})
    config = ldap_config.read_form(form)
    obj = PasswordResetTool(config)
    obj.title = form.get('title', id)
    obj._setId(id)
    parent._setObject(id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')


def _role_parents(role_id):
    if role_id is None:
        return []
    parents = [role_id]

    while '-' in role_id:
        role_id = role_id.rsplit('-', 1)[0]
        parents.append(role_id)

    return reversed(parents)


TokenData = namedtuple('TokenData', 'user_id timestamp')


def random_token():
    bits = hashlib.sha1((str(datetime.now()) +
                         str(random.random())).encode()).digest()

    return base64.urlsafe_b64encode(bits).replace(b'-', b'')[:20]


class PasswordResetTool(SimpleItem):
    meta_type = 'Eionet Password Reset Tool'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_password_reset_tool.gif'

    manage_options = (
        {'label': 'Configure', 'action': 'manage_edit'},
        {'label': 'View', 'action': ''},
    ) + SimpleItem.manage_options

    _render_template = TemplateRenderer(CommonTemplateLogic)

    def __init__(self, config={}):
        super(PasswordResetTool, self).__init__()
        self._config = PersistentMapping(config)
        self._tokens = PersistentMapping()

    security.declareProtected(view_management_screens, 'get_config')

    def get_config(self):
        return dict(self._config)

    security.declareProtected(view_management_screens, 'manage_edit')
    manage_edit = PageTemplateFile('zpt/pwreset_manage_edit.zpt', globals())
    manage_edit.ldap_config_edit_macro = ldap_config.edit_macro

    security.declareProtected(view_management_screens, 'manage_edit_save')

    def manage_edit_save(self, REQUEST):
        """ save changes to configuration """
        form = REQUEST.form
        new_config = ldap_config.read_form(form, edit=True)

        new_config['legacy_ldap_server'] = form.get('legacy_ldap_server', '')
        new_config['legacy_admin_dn'] = form.get('legacy_admin_dn', '')
        new_config['legacy_admin_pw'] = form.get('legacy_admin_pw', '')

        if not new_config['legacy_admin_pw']:
            del new_config['legacy_admin_pw']  # don't overwrite

        self._config.update(new_config)
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_edit')

    def _get_ldap_agent(self, bind=True):
        return ldap_config.ldap_agent_with_config(self._config, bind)

    def _predefined_filters(self):
        return sorted(self.objectValues([query.Query.meta_type]),
                      key=lambda ob: ob.getId())

    security.declareProtected(view, 'index_html')

    def index_html(self, REQUEST):
        """ view """
        email = REQUEST.get('email', '')
        options = {'email': email}

        return self._render_template('zpt/pwreset_index.zpt', **options)

    def _new_token(self, user_id):
        token = random_token().decode()
        self._tokens[token] = TokenData(user_id, datetime.utcnow())

        self._p_changed = True
        return token

    def _send_token_email(self, addr_to, token, user_info):
        addr_from = "no-reply@eionet.europa.eu"
        email_template = load_template('zpt/pwreset_token_email.zpt')
        expiration_time = datetime.utcnow() + timedelta(days=1)
        options = {
            'token_url': self.absolute_url() + "/confirm_email?token=" + token,
            'user_info': user_info,
            'context': self,
            'network_name': NETWORK_NAME,
            'expiration_time': expiration_time.strftime("%Y-%m-%d %H:%M:%S")
        }
        print(options['token_url'])
        message = MIMEText(email_template(**options),)
        message['From'] = addr_from
        message['To'] = addr_to
        subject = "%s account password recovery" % NETWORK_NAME
        message['Subject'] = subject

        try:
            from plone import api
            api.portal.send_email(recipient=[addr_to], sender=addr_from,
                                  subject=subject, body=message)
        except ImportError:
            mailer = getUtility(IMailDelivery, name="naaya-mail-delivery")
            try:
                mailer.send(addr_from, [addr_to], message.as_string())
            except AssertionError:
                mailer.send(addr_from, [addr_to], message)

    security.declareProtected(view, 'ask_for_password_reset')

    def ask_for_password_reset(self, REQUEST=None, email=None,
                               on_create=False):
        """ view """

        if REQUEST is None:
            REQUEST = self.REQUEST

        if not email:
            email = REQUEST.form['email']

        agent = self._get_ldap_agent()
        users = agent.search_user_by_email(email)   # , no_disabled=True)
        msgs = IStatusMessage(REQUEST)

        if users:
            # some people have multiple accounts; send mail for each account.

            for user_info in users:
                if user_info['status'] == 'disabled':
                    msg = u"This email: %s belongs to a disabled account" % \
                        user_info['email']
                    msgs.add(msg, type='error')
                    location = (
                        self.absolute_url() +
                        '/messages_html?msg=email-disabled')
                else:
                    token = self._new_token(user_info['id'])
                    log.info(
                        "Sending password recovery email to user %r at %r.",
                        user_info['id'], email)
                    self._send_token_email(email, token, user_info)

                    location = (self.absolute_url() +
                                '/messages_html?msg=email-sent')

        else:
            log.info("Requested password recovery with invalid email %r.",
                     email)
            msg = u"Email address not found in database."
            msgs.add(msg, type='error')
            location = self.absolute_url() + '/'

        if REQUEST and not on_create:
            REQUEST.RESPONSE.redirect(location)

    security.declareProtected(view, 'messages_html')

    def messages_html(self, REQUEST):
        """ view """
        options = {
            'message-name': REQUEST.form['msg'],
        }

        return self._render_template('zpt/pwreset_message.zpt', **options)

    def _say_token_expired(self, REQUEST):
        msgs = IStatusMessage(REQUEST)
        msg = (u"Password reset link is invalid, perhaps it has "
               u"expired. Please try again.")
        msgs.add(msg, type='error')
        location = self.absolute_url() + '/'
        REQUEST.RESPONSE.redirect(location)

    def _expire_tokens(self):
        expired = []
        cutoff_time = datetime.utcnow() - timedelta(days=1)

        for token, token_data in six.iteritems(self._tokens):
            if token_data.timestamp < cutoff_time:
                expired.append(token)

        for token in expired:
            log.info('Token %r expired.', token)
            del self._tokens[token]
            self._p_changed = True

    security.declareProtected(view, 'confirm_email')

    def confirm_email(self, REQUEST):
        """ view """

        token = REQUEST.form['token']
        self._expire_tokens()
        token_data = self._tokens.get(token, None)

        if token_data is None:
            return self._say_token_expired(REQUEST)

        options = {
            'token': token,
            'user_id': token_data.user_id,
        }

        return self._render_template('zpt/pwreset_new_password.zpt', **options)

    def reset_password(self, REQUEST):
        """ view """

        token = REQUEST.form['token']
        self._expire_tokens()
        token_data = self._tokens.get(token, None)

        if token_data is None:
            return self._say_token_expired(REQUEST)

        new_password = REQUEST.form['password']
        msgs = IStatusMessage(REQUEST)

        if new_password != REQUEST.form['password-confirm']:
            msgs.add("Passwords do not match.", type='error')
            location = self.absolute_url() + '/confirm_email?token=' + token

        else:
            log.info("Restting password for user %r with token %r",
                     token_data.user_id, token)
            agent = self._get_ldap_agent(bind=True)
            try:
                agent.set_user_password(token_data.user_id, None, new_password)
            except CONSTRAINT_VIOLATION as e:
                message = ''

                if e.args[0]['info'] in [
                        'Password fails quality checking policy']:
                    try:
                        defaultppolicy = agent.conn.search_s(
                            'cn=defaultppolicy,ou=pwpolicies,o=EIONET,'
                            'l=Europe',
                            SCOPE_BASE)
                        p_length = defaultppolicy[0][1]['pwdMinLength'][0]
                        message = '%s (min. %s characters)' % (
                            e.args[0]['info'], p_length)
                    except NO_SUCH_OBJECT:
                        message = e.args[0]['info']
                else:
                    message = e.args[0]['info']

                msgs.add(message, type='error')
                location = '%s/confirm_email?token=%s' % (self.absolute_url(),
                                                          token)
            else:
                del self._tokens[token]
                location = (self.absolute_url() +
                            '/messages_html?msg=password-reset')
                self._p_changed = True

        REQUEST.RESPONSE.redirect(location)

    security.declareProtected(view, 'can_edit_users')

    def can_edit_users(self):
        user = self.REQUEST.AUTHENTICATED_USER

        return bool(user.has_permission(eionet_edit_users, self))


InitializeClass(PasswordResetTool)
