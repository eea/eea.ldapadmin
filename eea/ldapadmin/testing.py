""" testing  """
from plone.app.testing import (PLONE_FIXTURE, FunctionalTesting,
                               IntegrationTesting, PloneSandboxLayer)


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


FIXTURE = Fixture()
INTEGRATION_TESTING = IntegrationTesting(
    bases=(FIXTURE,),
    name='eea.ldapadmin:Integration',
)
FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FIXTURE,),
    name='eea.ldapadmin:Functional',
)
