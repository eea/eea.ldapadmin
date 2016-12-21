def initialize(context):
    import roles_editor, orgs_editor, pwreset_tool, users_admin, \
        api_tool, dashboard
    import nfp_nrc, logger
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
