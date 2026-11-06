''' URLs of the account tools, found by meta_type '''
from Acquisition import aq_base

USER_DETAILS = 'Eionet User Details'
USERS_ADMIN = 'Eionet Users Admin'
ORGS_EDITOR = 'Eionet Organisations Editor'

# Paths on the Eionet portal, used when no tool of that type is found
DEFAULT_PATHS = {
    USER_DETAILS: 'user',
    USERS_ADMIN: 'eionet-account-tools/users',
    ORGS_EDITOR: 'eionet-account-tools/organisations',
}

MAX_DEPTH = 3
_cache = {}


def _portal(context):
    ''' the Plone site, or the Zope root outside Plone '''
    portal_url = getattr(context, 'portal_url', None)
    if hasattr(portal_url, 'getPortalObject'):
        return portal_url.getPortalObject()
    return context.getPhysicalRoot()


def _find(folder, meta_type, depth=1):
    ''' path of the first tool of meta_type, breadth first '''
    children = [ob for ob in folder.objectValues()
                if not ob.getId().startswith(('portal_', 'acl_users'))]
    for ob in children:
        if getattr(aq_base(ob), 'meta_type', None) == meta_type:
            return ob.getId()
    if depth == MAX_DEPTH:
        return None
    for ob in children:
        if getattr(aq_base(ob), 'isPrincipiaFolderish', False):
            path = _find(ob, meta_type, depth + 1)
            if path:
                return ob.getId() + '/' + path
    return None


def tool_url(context, meta_type):
    ''' absolute URL of the first tool of meta_type in the portal '''
    portal = _portal(context)
    key = (portal.getPhysicalPath(), meta_type)
    if key not in _cache:
        path = _find(portal, meta_type)
        if path is None:
            return '%s/%s' % (portal.absolute_url(), DEFAULT_PATHS[meta_type])
        _cache[key] = path
    return '%s/%s' % (portal.absolute_url(), _cache[key])
