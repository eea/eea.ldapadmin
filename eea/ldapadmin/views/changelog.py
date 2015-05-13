from DateTime.DateTime import DateTime
from Products.Five import BrowserView
from eea.usersdb import factories
from zope.component import getMultiAdapter
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
        return [x['member'] for x in self.context['data']]


class RemovedMemberFromOrg(BaseActionDetails):
    """
    """

    action_title = "Removed member from organisation"

    def member(self):
        return [x['member'] for x in self.context['data']]


class RemovedPendingMemberFromOrg(BaseActionDetails):
    """
    """

    action_title = "Removed pending member from organisation"

    def member(self):
        return [x['member'] for x in self.context['data']]


class OrganisationChangelog(BrowserView):
    """ Changelog for an organisation

    Context is an instance of OrganisationsEditor
    """

    def entries(self):
        org_id = self.request.form.get('id')
        agent = self.context._get_ldap_agent()
        org_dn = agent._org_dn(org_id)


        log_entries = list(reversed(agent._get_metadata(org_dn)))

        for entry in log_entries:
            date = DateTime(entry['timestamp']).toZone("CET")
            entry['timestamp'] = date.ISO()
            view = getMultiAdapter((entry, self.request),
                                    name="details_" + entry['action'])
            view.base = self.context
            entry['view'] = view

        output = []
        for entry in log_entries:
            if output:
                last_entry = output[-1]
                check = ['author', 'action', 'timestamp']
                flag = True
                for k in check:
                    if last_entry[k] != entry[k]:
                        flag = False
                        break
                if flag:
                    last_entry['data'].append(entry['data'])
                else:
                    entry['data'] = [entry['data']]
                    output.append(entry)
            else:
                entry['data'] = [entry['data']]
                output.append(entry)

        return output
