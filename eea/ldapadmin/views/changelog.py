from zope.component import getMultiAdapter
from zope.interface import Attribute, Interface, implements

from DateTime.DateTime import DateTime
from eea.usersdb import factories
from eea.usersdb.db_agent import UserNotFound
from Products.Five import BrowserView
from Products.LDAPUserFolder.LDAPUserFolder import LDAPUserFolder


class IActionDetails(Interface):
    """ A view that presents details about user changelog actions
    """

    action_title = Attribute("Human readable title for this action")
    author = Attribute("Author of changes, in html format")
    details = Attribute("Action details in html format")


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

        try:
            user_info = self.base._get_ldap_agent().user_info(entry['author'])
        except UserNotFound:
            return entry['author']

        return u"%s (%s)" % (user_info['full_name'], entry['author'])

    def author_email(self, entry):
        if entry['author'] == 'unknown user':
            return ''

        try:
            user_info = self.base._get_ldap_agent().user_info(entry['author'])
        except UserNotFound:
            return ''

        return user_info['email']


    def _get_ldap_agent(self):
        # without the leading slash, since it will match the root acl
        user_folder = self.context.restrictedTraverse("acl_users")
        # Plone compatibility

        if not isinstance(user_folder, LDAPUserFolder):
            user_folder = self.context.restrictedTraverse(
                "acl_users/ldap-plugin/acl_users")

        return factories.agent_from_uf(user_folder)


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

    def old_name(self):
        return self.context['data'][0]['old_name']


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
