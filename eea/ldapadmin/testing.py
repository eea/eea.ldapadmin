""" testing  """
from mock import Mock
from lxml.html.soupparser import fromstring
from Products.statusmessages.interfaces import IStatusMessage
from plone.app.testing import (PLONE_FIXTURE, FunctionalTesting,
                               IntegrationTesting, PloneSandboxLayer)
from plone.app.contenttypes.testing import PLONE_APP_CONTENTTYPES_FIXTURE


class Fixture(PloneSandboxLayer):
    """ Fixture """

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        """ Set up Zope """
        # Load ZCML
        import eea.ldapadmin
        import plone.dexterity
        import plone.app.textfield

        # needed for Dexterity FTI
        self.loadZCML(package=plone.dexterity)

        # needed for DublinCore behavior
        self.loadZCML(package=plone.app.dexterity)

        # needed to support RichText in testpage
        self.loadZCML(package=plone.app.textfield)

        self.loadZCML(package=eea.ldapadmin)


class FunctionalFixture(PloneSandboxLayer):
    """ Fixture """

    defaultBases = (PLONE_APP_CONTENTTYPES_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        """ Set up Zope """
        # Load ZCML
        import eea.ldapadmin
        import plone.dexterity
        import plone.app.textfield

        # needed for Dexterity FTI
        self.loadZCML(package=plone.dexterity)

        # needed for DublinCore behavior
        self.loadZCML(package=plone.app.dexterity)

        # needed to support RichText in testpage
        self.loadZCML(package=plone.app.textfield)

        self.loadZCML(package=eea.ldapadmin)


FIXTURE = Fixture()
FUNCTIONAL_FIXTURE = FunctionalFixture()
INTEGRATION_TESTING = IntegrationTesting(
    bases=(FIXTURE,),
    name='eea.ldapadmin:Integration',
)
FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FUNCTIONAL_FIXTURE,),
    name='eea.ldapadmin:Functional',
)


def base_setup(context, user):
    """ create request based on the PloneSandboxLayer """
    context.mock_agent = Mock()
    context.mock_agent.new_action = Mock
    context.mock_agent.new_action.__enter__ = Mock(
        return_value=context.mock_agent.new_action)
    context.mock_agent.new_action.__exit__ = Mock(
        return_value=None)
    context.mock_agent._encoding = 'utf-8'
    context.mock_agent.role_leaders = Mock(return_value=([], []))
    context.mock_agent.role_infos_in_role.return_value = {}
    context.ui._get_ldap_agent = Mock(return_value=context.mock_agent)
    context.ui.can_delete_role = Mock(return_value=True)
    context.ui.can_edit_members = Mock(return_value=True)
    context.ui.can_edit_organisation = Mock(return_value=True)
    context.ui.can_edit_organisations = Mock(return_value=True)
    context.ui.checkPermissionEditOrganisations = Mock(return_value=True)
    context.ui.getPhysicalRoot = Mock(return_value=context.layer['app'])

    context.request = context.REQUEST = context.ui.REQUEST = context.layer[
        'portal'].REQUEST
    context.request.method = 'POST'
    context.request.RESPONSE.redirect = Mock()
    context.request.RESPONSE.setStatus = Mock()
    context.REQUEST.AUTHENTICATED_USER = user
    user.getRoles = Mock(return_value=['Authenticated'])


def parse_html(html):
    ''' return parsed html '''
    return fromstring(html)


def status_messages(request):
    ''' get status messages '''
    messages = {}
    for message in IStatusMessage(request).show():
        messages[message.type] = message.message
    return messages
