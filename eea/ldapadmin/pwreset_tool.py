import logging
from datetime import datetime, timedelta
from collections import namedtuple
from email.mime.text import MIMEText

from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from App.class_init import InitializeClass
from OFS.SimpleItem import SimpleItem
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from persistent.mapping import PersistentMapping
from zope.component import getUtility
from zope.component.interfaces import ComponentLookupError
from zope.sendmail.interfaces import IMailDelivery

from eea import usersdb
import ldap_config
from ui_common import load_template, SessionMessages, TemplateRenderer
from constants import NETWORK_NAME

log = logging.getLogger(__name__)

manage_add_pwreset_tool_html = PageTemplateFile('zpt/pwreset_manage_add',
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

SESSION_PREFIX = 'eea.ldapadmin.pwreset_tool'
SESSION_MESSAGES = SESSION_PREFIX + '.messages'
SESSION_FORM_DATA = SESSION_PREFIX + '.form_data'

def _set_session_message(request, msg_type, msg):
    SessionMessages(request, SESSION_MESSAGES).add(msg_type, msg)

class CommonTemplateLogic(object):
    def __init__(self, context):
        self.context = context

    def _get_request(self):
        return self.context.REQUEST

    def base_url(self):
        return self.context.absolute_url()

    def message_boxes(self):
        return SessionMessages(self._get_request(), SESSION_MESSAGES).html()

    @property
    def network_name(self):
        return NETWORK_NAME

TokenData = namedtuple('TokenData', 'user_id timestamp')

def random_token():
    import base64, hashlib, random
    bits = hashlib.sha1(str(datetime.now()) + str(random.random())).digest()
    return base64.urlsafe_b64encode(bits)[:20]


class PasswordResetTool(SimpleItem):
    meta_type = 'Eionet Password Reset Tool'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_password_reset_tool.gif'

    manage_options = (
        {'label':'Configure', 'action':'manage_edit'},
        {'label':'View', 'action':''},
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
    manage_edit = PageTemplateFile('zpt/pwreset_manage_edit', globals())
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
            del new_config['legacy_admin_pw'] # don't overwrite

        self._config.update(new_config)
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/manage_edit')

    def _get_ldap_agent(self, bind=False):
        return ldap_config.ldap_agent_with_config(self._config, bind)

    def _predefined_filters(self):
        return sorted(self.objectValues([query.Query.meta_type]),
                      key=lambda ob: ob.getId())

    security.declareProtected(view, 'index_html')
    def index_html(self, REQUEST):
        """ view """
        options = {}
        return self._render_template('zpt/pwreset_index.zpt', **options)

    def _new_token(self, user_id):
        token = random_token()
        self._tokens[token] = TokenData(user_id, datetime.utcnow())
        return token

    def _send_token_email(self, addr_to, token, user_info):
        addr_from = "no-reply@groupware.info-rac.org"
        email_template = load_template('zpt/pwreset_token_email.zpt')
        options = {
            'token_url': self.absolute_url() + "/confirm_email?token=" + token,
            'user_info': user_info,
            'context': self,
            'network_name': NETWORK_NAME
        }
        message = MIMEText(email_template(**options).encode('utf-8'),
                           _charset='utf-8')
        message['From'] = addr_from
        message['To'] = addr_to
        message['Subject'] = "%s account password recovery" % NETWORK_NAME

        try:
            mailer = getUtility(IMailDelivery, name="Mail")
            mailer.send(addr_from, [addr_to], message.as_string())
        except ComponentLookupError:
            mailer = getUtility(IMailDelivery, name="naaya-mail-delivery")
            mailer.send(addr_from, [addr_to], message)

    security.declareProtected(view, 'ask_for_password_reset')
    def ask_for_password_reset(self, REQUEST):
        """ view """
        email = REQUEST.form['email']
        agent = self._get_ldap_agent()
        users = agent.search_user_by_email(email)

        if users:
            # some people have multiple accounts; send mail for each account.
            for user_info in users:
                token = self._new_token(user_info['id'])
                log.info("Sending password recovery email to user %r at %r.",
                         user_info['id'], email)
                self._send_token_email(email, token, user_info)
            location = self.absolute_url() + '/messages_html?msg=email-sent'

        else:
            log.info("Requested password recovery with invalid email %r.",
                     email)
            msg = "Email address not found in database."
            _set_session_message(REQUEST, 'error', msg)
            location = self.absolute_url() + '/'

        REQUEST.RESPONSE.redirect(location)

    security.declareProtected(view, 'messages_html')
    def messages_html(self, REQUEST):
        """ view """
        options = {
            'message-name': REQUEST.form['msg'],
        }
        return self._render_template('zpt/pwreset_message.zpt', **options)

    def _say_token_expired(self, REQUEST):
        msg = ("Password reset link is invalid, perhaps it has "
               "expired. Please try again.")
        _set_session_message(REQUEST, 'error', msg)
        location = self.absolute_url() + '/'
        REQUEST.RESPONSE.redirect(location)

    def _expire_tokens(self):
        expired = []
        cutoff_time = datetime.utcnow() - timedelta(days=1)
        for token, token_data in self._tokens.iteritems():
            if token_data.timestamp < cutoff_time:
                expired.append(token)
        for token in expired:
            log.info('Token %r expired.', token)
            del self._tokens[token]

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
        if new_password != REQUEST.form['password-confirm']:
            _set_session_message(REQUEST, 'error', "Passwords do not match.")
            location = self.absolute_url() + '/confirm_email?token=' + token

        else:
            log.info("Restting password for user %r with token %r",
                     token_data.user_id, token)
            agent = self._get_ldap_agent(bind=True)
            agent.set_user_password(token_data.user_id, None, new_password)
            del self._tokens[token]
            location = (self.absolute_url() +
                        '/messages_html?msg=password-reset')

        REQUEST.RESPONSE.redirect(location)

InitializeClass(PasswordResetTool)
