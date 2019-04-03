from eea.usersdb import UsersDB
from ui_common import load_template


defaults = {
    'admin_dn': "cn=Eionet Administrator,o=EIONET,l=Europe",
    'admin_pw': "",
    'ldap_server': "ldap2.eionet.europa.eu",
    'users_rdn': 'uid',
    'users_dn': "ou=Users,o=EIONET,l=Europe",
    'orgs_dn': "ou=Organisations,o=EIONET,l=Europe",
    'roles_dn': "ou=Roles,o=EIONET,l=Europe",
    'secondary_admin_dn': "cn=Accounts Browser,o=EIONET,l=Europe",
    'secondary_admin_pw': "",
}


def read_form(form, edit=False):
    config = dict((name, form.get(name, default))
                  for name, default in defaults.iteritems())

    if edit:
        if not config['admin_pw'].strip():
            del config['admin_pw']

        if not config['secondary_admin_pw'].strip():
            del config['secondary_admin_pw']

    return config


def ldap_agent_with_config(config, bind=False, secondary=False):
    db = UsersDB(ldap_server=config.get('ldap_server', defaults['ldap_server']),
                 # next is for bwd compat with objects created with v1.0.0
                 users_rdn=config.get('users_rdn', defaults['users_rdn']),
                 users_dn=config.get('users_dn', defaults['users_dn']),
                 orgs_dn=config.get('orgs_dn', defaults['orgs_dn']),
                 roles_dn=config.get('roles_dn', defaults['roles_dn']))

    if bind:
        if secondary:
            db.perform_bind(config['secondary_admin_dn'],
                            config['secondary_admin_pw'])
        else:
            db.perform_bind(config.get('admin_dn', config.get('browser_dn')),
                            config.get('admin_pw', config.get('browser_pw')))
        legacy_ldap_server = config.get('legacy_ldap_server', None)

        if legacy_ldap_server:
            from eea.userseditor.users_editor import (
                CircaUsersDB, CIRCA_USERS_DN_SUFFIX, DualLDAPProxy)
            legacy_db = CircaUsersDB(ldap_server=legacy_ldap_server,
                                     users_dn=CIRCA_USERS_DN_SUFFIX,
                                     encoding="ISO-8859-1")
            legacy_db.perform_bind(config['legacy_admin_dn'],
                                   config['legacy_admin_pw'])

            db = DualLDAPProxy(db, legacy_db)

    return db


edit_macro = load_template('zpt/ldap_config.zpt').macros['edit']
