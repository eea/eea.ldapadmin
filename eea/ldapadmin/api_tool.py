""" This module provides support for calling various methods via http.
"""

import logging

from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view, view_management_screens
from App.class_init import InitializeClass
from OFS.SimpleItem import SimpleItem

from eea.ldapadmin.constants import LDAP_DISK_STORAGE
from countries import update_countries
from ldapdump import dump_ldap

log = logging.getLogger(__name__)


def manage_add_api_tool(parent, REQUEST=None):
    """ Create a new ApiTool object """
    id = 'api_tool'
    title = 'Api Tool'

    obj = ApiTool(id, title)
    parent._setObject(id, obj)

    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')


class ApiTool(SimpleItem):
    """ ApiTool class
    """

    meta_type = 'Eionet Api Tool'
    security = ClassSecurityInfo()
    icon = '++resource++eea.ldapadmin-www/eionet_password_reset_tool.gif'

    manage_options = (
        SimpleItem.manage_options
    )

    def __init__(self, id, title):
        super(ApiTool, self).__init__()
        self.id = id
        self.title = title

    security.declareProtected(view_management_screens, 'update_countries')
    def update_countries(self, REQUEST=None, RESPONSE=None):
        """ Wrapper for update_countries.
        """
        update_countries()
        return 'FINISHED update_countries @ {}/'.format(
            self.absolute_url()
        )

    security.declareProtected(view_management_screens, 'dump_ldap')
    def dump_ldap(self, REQUEST=None, RESPONSE=None):
        """ """
        dump_ldap(LDAP_DISK_STORAGE)
        return 'FINISHED dump_ldap @ {}/ to {}'.format(
            self.absolute_url(),
            LDAP_DISK_STORAGE
        )

    security.declareProtected(view, 'index_html')
    def index_html(self, REQUEST=None, RESPONSE=None):
        """ view """
        RESPONSE.setStatus(404)
        return RESPONSE

InitializeClass(ApiTool)
