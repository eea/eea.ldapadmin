from Products.Five import BrowserView
from eea.usersdb import factories
from zope.interface import Interface, Attribute, implements


class IActionDetails(Interface):
    """ A view that presents details about user changelog actions
    """

    action_title = Attribute("Human readable title for this action")
    author       = Attribute("Author of changes, in html format")
    details      = Attribute("Action details in html format")


class BaseActionDetails(BrowserView):
    """ Generic implementation of IActionDetails
    """

    implements(IActionDetails)

    @property
    def action_title(self):
        raise NotImplementedError

    def details(self, entry):
        self.entry = entry
        return self.index()

    def author(self, entry):
        if entry['author'] == 'unknown user':
            return entry['author']

        user_info = self._get_ldap_agent().user_info(entry['author'])
        return u"%s (%s)" % (user_info['full_name'], entry['author'])

    def _get_ldap_agent(self):
        return factories.agent_from_uf(self.context.restrictedTraverse("/acl_users"))


class BaseRoleDetails(BaseActionDetails):

    def details(self, entry):
        roles = [x['role'] for x in entry['data']]
        self.roles = self.merge(roles)
        return self.index()


class BaseOrganisationDetails(object):

    @property
    def organisation(self):
        for entry in self.entry['data']:
            org = entry.get('organisation')
            if org:
                return self._get_ldap_agent().org_info(org)['name']

        return ""

