from ui_common import load_template
from eea.usersdb import UsersDB

defaults = {
    'admin_dn': "uid=_admin,ou=Users,o=EIONET,l=Europe",
    'admin_pw': "",
    'ldap_server': "ldap2.eionet.europa.eu",
    'users_rdn': 'uid',
    'users_dn': "ou=Users,o=EIONET,l=Europe",
    'orgs_dn': "ou=Organisations,o=EIONET,l=Europe",
    'roles_dn': "ou=Roles,o=EIONET,l=Europe",
}

def read_form(form, edit=False):
    config = dict((name, form.get(name, default))
                  for name, default in defaults.iteritems())
    if edit:
        if not config['admin_pw']:
            del config['admin_pw']
    return config

def ldap_agent_with_config(config, bind=False):
    db = UsersDB(ldap_server=config['ldap_server'],
                 # next is for bwd compat with objects created with v1.0.0
                 users_rdn=config.get('users_rdn', defaults['users_rdn']),
                 users_dn=config['users_dn'],
                 orgs_dn=config['orgs_dn'],
                 roles_dn=config['roles_dn'])

    if bind:
        db.perform_bind(config['admin_dn'], config['admin_pw'])

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
