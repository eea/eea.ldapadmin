''' changelog '''
from zope.component import getMultiAdapter
from zope.interface import Attribute, Interface, implementer

from DateTime.DateTime import DateTime
from eea.usersdb import factories
from eea.usersdb.db_agent import UserNotFound
from eea.ldapadmin.ldap_config import _get_ldap_agent
from Products.Five import BrowserView


class IActionDetails(Interface):
    """ A view that presents details about user changelog actions
    """

    action_title = Attribute("Human readable title for this action")
    author = Attribute("Author of changes, in html format")
    details = Attribute("Action details in html format")


@implementer(IActionDetails)
class BaseActionDetails(BrowserView):
    """ Generic implementation of IActionDetails
    """

    @property
    def action_title(self):
        ''' not implemented '''
        raise NotImplementedError

    def details(self, entry):
        ''' return the index page with details of entry '''
        self.entry = entry

        return self.index()

    def author(self, entry):
        ''' return author of entry '''
        if entry['author'] == 'unknown user':
            return entry['author']

        try:
            user_info = _get_ldap_agent(self.base).user_info(entry['author'])
        except UserNotFound:
            return entry['author']

        return u"%s (%s)" % (user_info['full_name'], entry['author'])

    def author_email(self, entry):
        ''' return author's email '''
        if entry['author'] == 'unknown user':
            return ''

        try:
            agent = _get_ldap_agent(self.base)
            user_info = agent.user_info(entry['author'])
        except UserNotFound:
            return ''

        return user_info['email']

    def _get_ldap_agent(self):
        ''' get the ldap agent '''
        # without the leading slash, since it will match the root acl
        user_folder = self.context.restrictedTraverse("acl_users")
        # Plone compatibility
        # import pdb; pdb.set_trace() # removed ldapuserfolder
        # if not isinstance(user_folder, LDAPUserFolder):
        # user_folder = self.context.restrictedTraverse(
        #     "acl_users/ldap-plugin/acl_users")

        return factories.agent_from_uf(user_folder)


class EditedOrg(BaseActionDetails):
    """ edited organisation
    """

    action_title = "Edited organisation"


class CreatedOrg(BaseActionDetails):
    """ created organisation
    """

    action_title = "Created organisation"


class RenamedOrg(BaseActionDetails):
    """ renamed organisation
    """

    action_title = "Renamed organisation"

    def old_name(self):
        ''' return old name '''
        return self.context['data'][0]['old_name']


class AddedMemberToOrg(BaseActionDetails):
    """ added member to organisation
    """

    action_title = "Added member to organisation"

    def member(self):
        ''' return members '''
        return [x['member'] for x in self.context['data']]


class AddedPendingMemberToOrg(BaseActionDetails):
    """ added pending member
    """

    action_title = "Added pending member to organisation"

    def member(self):
        ''' return members '''
        return [x['member'] for x in self.context['data']]


class RemovedMemberFromOrg(BaseActionDetails):
    """ removed member
    """

    action_title = "Removed member from organisation"

    def member(self):
        ''' return members '''
        return [x['member'] for x in self.context['data']]


class RemovedPendingMemberFromOrg(BaseActionDetails):
    """ removed pending member
    """

    action_title = "Removed pending member from organisation"

    def member(self):
        ''' return members '''
        return [x['member'] for x in self.context['data']]


class OrganisationChangelog(BrowserView):
    """ Changelog for an organisation

    Context is an instance of OrganisationsEditor
    """

    def entries(self):
        ''' get changelog entries '''
        org_id = self.request.form.get('id').encode()
        agent = _get_ldap_agent(self.context)
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
