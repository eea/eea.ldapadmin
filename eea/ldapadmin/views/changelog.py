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

        user_info = self.base._get_ldap_agent().user_info(entry['author'])
        return u"%s (%s)" % (user_info['full_name'], entry['author'])

    def _get_ldap_agent(self):
        return factories.agent_from_uf(self.context.restrictedTraverse("/acl_users"))

class EditedOrg(BaseActionDetails):
    """
    """

    action_title = "Edited organisation"


class CreatedOrg(BaseActionDetails):
    """
    """

    action_title = "Created organisation"


class RenamedOrg(BaseActionDetails):
    """
    """

    action_title = "Renamed organisation"


class AddedMemberToOrg(BaseActionDetails):
    """
    """

    action_title = "Added member to organisation"

    def member(self):
        return [x['member'] for x in self.context['data']]


class AddedPendingMemberToOrg(BaseActionDetails):
    """
    """

    action_title = "Added pending member to organisation"

    def member(self):
        return "tibi"


class RemovedMemberFromOrg(BaseActionDetails):
    """
    """

    action_title = "Removed member from organisation"


class RemovedPendingMemberFromOrg(BaseActionDetails):
    """
    """

    action_title = "Removed pending member from organisation"
