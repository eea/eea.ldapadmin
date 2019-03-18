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

    context.registerClass(roles_editor.RolesEditor,
                          permission='Add Eionet Roles Editors',
                          constructors=(
                              ('manage_add_roles_editor_html',
                               roles_editor.manage_add_roles_editor_html),
                              ('manage_add_roles_editor',
                               roles_editor.manage_add_roles_editor),
                          ))

    context.registerClass(orgs_editor.OrganisationsEditor,
                          permission='Add Eionet Organisations Editors',
                          constructors=(
                              ('manage_add_orgs_editor_html',
                               orgs_editor.manage_add_orgs_editor_html),
                              ('manage_add_orgs_editor',
                               orgs_editor.manage_add_orgs_editor),
                          ))

    context.registerClass(pwreset_tool.PasswordResetTool,
                          permission="Add Eionet Password Reset Tools",
                          constructors=(
                              ('manage_add_pwreset_tool_html',
                               pwreset_tool.manage_add_pwreset_tool_html),
                              ('manage_add_pwreset_tool',
                               pwreset_tool.manage_add_pwreset_tool),
                          ))

    context.registerClass(users_admin.UsersAdmin,
                          permission="Add Eionet Users Admins",
                          constructors=(
                              ('manage_add_users_admin_html',
                               users_admin.manage_add_users_admin_html),
                              ('manage_add_users_admin',
                               users_admin.manage_add_users_admin),
                          ))

    context.registerClass(nfp_nrc.NfpNrc,
                          permission="Add Eionet NFP Admins",
                          constructors=(
                              ('manage_add_nfp_nrc_html',
                               nfp_nrc.manage_add_nfp_nrc_html),
                              ('manage_add_nfp_nrc',
                               nfp_nrc.manage_add_nfp_nrc),
                          ))

    context.registerClass(api_tool.ApiTool,
                          permission="Add Eionet Api Tools",
                          constructors=(
                              ('manage_add_api_tool',
                               api_tool.manage_add_api_tool),
                          ))

    context.registerClass(dashboard.Dashboard,
                          permission='Add Eionet Roles Editors',
                          constructors=(
                              ('manage_add_ldap_admin_html',
                               dashboard.manage_add_ldap_admin_html),
                              ('manage_add_ldap_admin',
                               dashboard.manage_add_ldap_admin),
                          ))
