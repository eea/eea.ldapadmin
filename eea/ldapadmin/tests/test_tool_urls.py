''' test finding the account tools by meta_type '''
import unittest
from OFS.Application import Application
from OFS.Folder import Folder
from OFS.SimpleItem import SimpleItem
from Testing.makerequest import makerequest
from eea.ldapadmin import tool_urls


class Tool(SimpleItem):
    ''' a tool with a given meta_type '''

    def __init__(self, tool_id, meta_type):
        self.id = tool_id
        self.meta_type = meta_type


class ToolUrlsTest(unittest.TestCase):
    ''' tool_url '''

    def setUp(self):
        tool_urls._cache.clear()
        self.root = makerequest(Application())
        self.root._setObject('tools', Folder('tools'))
        self.root.tools._setObject('dash', Folder('dash'))
        self.root.tools.dash._setObject(
            'members', Tool('members', tool_urls.USERS_ADMIN))
        self.root._setObject('people', Folder('people'))
        self.root.people._setObject(
            'person', Tool('person', tool_urls.USER_DETAILS))
        self.context = self.root.tools.dash.members

    def test_found(self):
        self.assertEqual(
            tool_urls.tool_url(self.context, tool_urls.USER_DETAILS),
            self.root.absolute_url() + '/people/person')
        self.assertEqual(
            tool_urls.tool_url(self.context, tool_urls.USERS_ADMIN),
            self.root.absolute_url() + '/tools/dash/members')

    def test_default_path(self):
        self.assertEqual(
            tool_urls.tool_url(self.context, tool_urls.ORGS_EDITOR),
            self.root.absolute_url() + '/' +
            tool_urls.DEFAULT_PATHS[tool_urls.ORGS_EDITOR])

    def test_cached(self):
        tool_urls.tool_url(self.context, tool_urls.USER_DETAILS)
        self.root.people._delObject('person')
        self.assertTrue(tool_urls.tool_url(
            self.context, tool_urls.USER_DETAILS).endswith('/people/person'))
