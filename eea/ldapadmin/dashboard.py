import operator
import os

from AccessControl import ClassSecurityInfo, getSecurityManager
from AccessControl.Permissions import view  # , view_management_screens
from App.config import getConfiguration
from OFS.Folder import Folder
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from ui_common import CommonTemplateLogic, TemplateRenderer

KNOWN_TYPES = {'Eionet Roles Editor': {
    'description': ('Browse Roles and Roles\' Members in LDAP'
                    '<br /><i>[system administration]</i>')
},
    'Eionet Organisations Editor': {
    'description': ('Browse organisations'
                    '<br /><i>[system administration]</i>')
},
    'Eionet Password Reset Tool': {
    'description': ('Reset EIONET account password'
                    '<br /><i>[available to any user]</i>')
},
    'Eionet Users Admin': {
    'description': ('Manage User Accounts'
                    '<br /><i>[system administration]</i>')
},
    'Eionet Users Editor': {
    'description': ('Manage your profile information'
                    '<br /><i>[available to any user]</i>')
},
    'Eionet NFP Admin': {
    'description': ('NFP Administration - Editing NRC Members'
                    '<br /><i>[nfps and system administration]</i>')
},
    'My Profile Overview': {
    'description': ('Overview on my memberships in interest groups,'
                    ' Roles and Subscriptions'
                    '<br /><i>[available to any user]</i>')
},
    'Eionet User Details': {
    'description': ('Eionet User page (User Directory)'
                    '<br /><i>[available to any user]</i>')
}
}

# Permission
eionet_access_ldap_explorer = 'Eionet access LDAP explorer'

CONFIG = getConfiguration()
CONFIG.environment.update(os.environ)

FORUM_URL = getattr(CONFIG, 'environment', {}).get('FORUM_URL', '')

manage_add_ldap_admin_html = PageTemplateFile('zpt/ldapadmin_manage_add.zpt',
                                              globals())


class FakeTool(object):
    """
    Some tools we want to include in LDAP Explorer are not objects in
    database. Fake/mock them to use the same pattern in logic and
    templates.

    """

    def __init__(self, meta_type, title, icon, absolute_url):
        self.meta_type = meta_type
        self.title = title
        self.icon = icon
        self.absolute_url = absolute_url


FAKES = [
    ('My Profile Overview', 'My Profile Overview',
     '++resource++eea.ldapadmin-www/profile_overview.png',
     FORUM_URL + '/profile_overview')
]


def manage_add_ldap_admin(parent, id, REQUEST=None):
    """ Create a new Dashboard object """

    if REQUEST is not None:
        form = REQUEST.form
    else:
        form = {}
    obj = Dashboard()
    obj.title = form.get('title', id)
    obj._setId(id)
    parent._setObject(id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')


class Dashboard(Folder):
    """
    The ldapadmin dashboard acts as container for the ldapadmin tools
    (organisation editor, users admin, roles editor, etc.).
    The tools should be created inside the dashboard folder so they can be
    rendered and linked in the dashboard template (some style will be applied
    in connection with their meta type)

    """

    meta_type = 'Eionet LDAP Explorer'
    icon = '++resource++eea.ldapadmin-www/ldap_dashboard.gif'
    security = ClassSecurityInfo()

    _render_template = TemplateRenderer(CommonTemplateLogic)

    def checkDashboardPermission(self):
        return getSecurityManager().checkPermission(
            eionet_access_ldap_explorer, self)

    security.declareProtected(view, 'get_slug')

    def get_slug(self, tool):
        """
        Returns a given slug for the `tool`, based on meta type,
        useful for referencing static files

        """

        return tool.meta_type.lower().replace(' ', '_')

    def get_tool_info(self, tool):
        """
        Returns meta properties of this tool as defined at the top of this
        module

        """

        return KNOWN_TYPES[tool.meta_type]

    security.declareProtected(view, 'index_html')

    def index_html(self, REQUEST):
        """ Dashboard page """
        tools = self.objectValues(KNOWN_TYPES.keys())

        for fake in FAKES:
            tools.append(FakeTool(*fake))
        tools.sort(key=operator.attrgetter('title'))

        return self._render_template("zpt/dashboard.zpt", **{'tools': tools})
