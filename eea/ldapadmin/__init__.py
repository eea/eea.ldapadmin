import importlib
import logging
log = logging.getLogger('LDAPUserFolder')


def patched_connect(self, bind_dn='', bind_pwd=''):
    """ initialize an ldap server connection """
    import ldap
    from AccessControl.SecurityManagement import getSecurityManager
    from Products.LDAPUserFolder.LDAPUser import LDAPUser
    from Products.LDAPUserFolder.SharedResource import getResource
    conn = None
    conn_string = ''

    if bind_dn != '':
        user_dn = bind_dn
        user_pwd = bind_pwd or '~'
    elif self.binduid_usage == 1:
        user_dn = self.bind_dn
        user_pwd = self.bind_pwd
    else:
        user = getSecurityManager().getUser()
        if isinstance(user, LDAPUser):
            user_dn = user.getUserDN()
            user_pwd = user._getPassword()
            if not user_pwd or user_pwd == 'undef':
                # This user object did not result from a login
                user_dn = user_pwd = ''
        else:
            user_dn = user_pwd = ''

    conn = getResource('%s-connection' % self._hash, str, ())
    if not isinstance(conn._type(), str):
        try:
            conn.simple_bind_s(user_dn, user_pwd)
            conn.search_s(self.u_base, self.BASE, '(objectClass=*)')
            return conn
        except (AttributeError,
                ldap.SERVER_DOWN,
                ldap.NO_SUCH_OBJECT,
                ldap.TIMEOUT,
                ldap.INVALID_CREDENTIALS
                ), e:
            log.debug('LDAPDEBUG bind error %s' % e)
            pass

    e = None

    for server in self._servers:
        conn_string = self._createConnectionString(server)

        try:
            newconn = self._connect(conn_string,
                                    user_dn,
                                    user_pwd,
                                    conn_timeout=server['conn_timeout'],
                                    op_timeout=server['op_timeout']
                                    )
            return newconn
        except (ldap.SERVER_DOWN,
                ldap.TIMEOUT,
                ldap.INVALID_CREDENTIALS
                ), e:
            log.debug('LDAPDEBUG connect error %s' % e)
            continue

    # If we get here it means either there are no servers defined or we
    # tried them all. Try to produce a meaningful message and raise
    # an exception.
    if len(self._servers) == 0:
        log.critical('No servers defined')
    else:
        if e is not None:
            msg_supplement = str(e)
        else:
            msg_supplement = 'n/a'

        err_msg = 'Failure connecting, last attempted server: %s (%s)' % (
            conn_string, msg_supplement)
        log.critical(err_msg, exc_info=1)

    if e is not None:
        raise e

    return None


def initialize(context):
    import roles_editor
    import orgs_editor
    import pwreset_tool
    import users_admin
    import api_tool
    import dashboard
    import nfp_nrc
    import logger
    import countries

    countries.load_countries()
    logger.init()

    context.registerClass(roles_editor.RolesEditor, constructors=(
        ('manage_add_roles_editor_html',
         roles_editor.manage_add_roles_editor_html),
        ('manage_add_roles_editor', roles_editor.manage_add_roles_editor),
    ))

    context.registerClass(orgs_editor.OrganisationsEditor, constructors=(
        ('manage_add_orgs_editor_html',
         orgs_editor.manage_add_orgs_editor_html),
        ('manage_add_orgs_editor', orgs_editor.manage_add_orgs_editor),
    ))

    context.registerClass(pwreset_tool.PasswordResetTool, constructors=(
        ('manage_add_pwreset_tool_html',
         pwreset_tool.manage_add_pwreset_tool_html),
        ('manage_add_pwreset_tool', pwreset_tool.manage_add_pwreset_tool),
    ))

    context.registerClass(users_admin.UsersAdmin, constructors=(
        ('manage_add_users_admin_html',
         users_admin.manage_add_users_admin_html),
        ('manage_add_users_admin', users_admin.manage_add_users_admin),
    ))

    context.registerClass(nfp_nrc.NfpNrc, constructors=(
        ('manage_add_nfp_nrc_html',
         nfp_nrc.manage_add_nfp_nrc_html),
        ('manage_add_nfp_nrc', nfp_nrc.manage_add_nfp_nrc),
    ))

    context.registerClass(api_tool.ApiTool, constructors=(
        ('manage_add_api_tool', api_tool.manage_add_api_tool),
    ))

    context.registerClass(dashboard.Dashboard, constructors=(
        ('manage_add_ldap_admin_html',
         dashboard.manage_add_ldap_admin_html),
        ('manage_add_ldap_admin', dashboard.manage_add_ldap_admin),
    ))

    mod = importlib.import_module('Products.LDAPUserFolder.LDAPDelegate')
    delegate = mod.LDAPDelegate
    delegate.old_connect = delegate.connect
    delegate.connect = patched_connect
    log.info('Patched LDAPDelegate.connect to log errors')
