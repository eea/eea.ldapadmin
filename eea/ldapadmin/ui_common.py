''' common ui methods '''
import six
from zope.component import getMultiAdapter
from Acquisition import Implicit
from eea.ldapadmin.constants import NETWORK_NAME
from eea.ldapadmin import roles_leaders
from eea.ldapadmin.countries import get_country, get_country_options
from eea.ldapadmin.logic_common import logged_in_user, _is_authenticated
from eea.ldapadmin.logic_common import load_template
from eea.ldapadmin.ldap_config import _get_ldap_agent
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from Products.PageTemplates.PageTemplateFile import PageTemplateFile


def get_role_name(agent, role_id):
    """
    Get role's name if exists else keep the role ID
    """

    return agent.role_info(role_id)['description'] or repr(role_id)


def roles_list_to_text(agent, roles):
    """
    Returns formatted text with roles' names or IDs for messages in forms
    """

    return ', '.join(get_role_name(agent, role_id) for role_id in roles)


def extend_crumbs(crumbs_html, editor_url, extra_crumbs):
    ''' Extend the breadcrumb '''
    from lxml.html.soupparser import fromstring
    from lxml.html import tostring
    from lxml.builder import E

    crumbs = fromstring(crumbs_html).find('div[@class="breadcrumbtrail"]')

    roles_div = crumbs.find('div[@class="breadcrumbitemlast"]')
    roles_div.attrib['class'] = "breadcrumbitem"
    roles_link = E.a(roles_div.text, href=editor_url)
    roles_div.text = ""
    roles_div.append(roles_link)

    for title, href in extra_crumbs:
        a = E.a(title, {'href': href})
        div = E.div(a, {'class': 'breadcrumbitem'})
        crumbs.append(div)

    last_crumb = crumbs.xpath('div[@class="breadcrumbitem"]')[-1]
    last_crumb_text = last_crumb.find('a').text
    last_crumb.clear()
    last_crumb.attrib['class'] = "breadcrumbitemlast"
    last_crumb.text = last_crumb_text

    return tostring(crumbs)


plone5_wrapper = PageTemplateFile('zpt/plone5_wrapper.zpt', globals())


class TemplateRenderer(Implicit):
    ''' the Template renderer '''
    def __init__(self, common_factory=lambda ctx: {}):
        self.common_factory = common_factory

    def render(self, template_name, **options):
        ''' render a given template '''
        context = self.aq_parent
        template = load_template(template_name, context)

        namespace = template.__self__._pt_get_context(
            context, context.REQUEST, options)

        namespace['common'] = self.common_factory(context)
        namespace['browserview'] = self.browserview

        if hasattr(template, 'pt_render'):
            return template.pt_render(namespace)
        return template.__self__.render(**namespace)

    def browserview(self, context, name):
        ''' return a named adapter '''
        return getMultiAdapter((context, self.aq_parent.REQUEST), name=name)

    def wrap(self, body_html):
        ''' wrap html in template context '''
        context = self.aq_parent
        main_template = self.aq_parent.restrictedTraverse(
            'main_template')
        main_page_macro = main_template.macros['master']

        tmpl = plone5_wrapper.__of__(context)

        return tmpl(main_page_macro=main_page_macro, body_html=body_html)

    def __call__(self, template_name, **options):
        if 'context' not in options:
            options['context'] = self.aq_parent
        options['request'] = self.REQUEST

        return self.wrap(self.render(template_name, **options))


class TemplateRendererNoWrap(Implicit):
    ''' Template renderer with no wrap '''
    def __init__(self, common_factory=lambda ctx: {}):
        self.common_factory = common_factory

    def render(self, name, **options):
        ''' render template '''
        context = self.aq_parent
        template = load_template(name)
        options['context'] = self.aq_parent
        options['request'] = self.aq_parent.REQUEST

        namespace = template._pt_get_context(context, context.REQUEST, options)
        namespace['common'] = self.common_factory(context)

        if hasattr(template, 'pt_render'):
            return template.pt_render(namespace)
        return template.render(**namespace)

    def __call__(self, name, **options):
        return self.render(name, **options)


class CommonTemplateLogic(object):
    ''' Common template logic '''
    def __init__(self, context):
        self.context = context

    def base_url(self):
        ''' return the absolute url of the context '''
        return self.context.absolute_url()

    def site_url(self):
        ''' return the absolute orl of the root '''
        return self.context.unrestrictedTraverse("/").absolute_url()

    def _get_request(self):
        ''' get request '''
        return self.context.REQUEST

    def admin_menu(self):
        ''' render the admin menu '''
        return self.context._render_template.render("zpt/users/admin_menu.zpt")

    def checkPermissionEditOrganisations(self):
        ''' check permission to edit organisations '''
        return self.context.checkPermissionEditOrganisations()

    def can_edit_organisations(self):
        ''' check permission to edit organisations as defined by the context'''
        return self.context.can_edit_organisations()

    def can_edit_organisation(self):
        ''' check permission to edit organisation as defined by the context'''
        return self.context.can_edit_organisation()

    def full_edit_permission(self):
        ''' check permission to edit users '''
        return self.context.checkPermissionEditUsers()

    def is_authenticated(self):
        ''' check if user is authenticated '''
        return _is_authenticated(self._get_request())

    def user_id(self):
        ''' return the user id '''
        return logged_in_user(self._get_request())

    def readonly_alert(self):
        ''' return a readonly alert message '''
        return self.context._render_template.render(
            "zpt/nfp_nrc/readonly_alert.zpt")

    def buttons_bar(self, current_page, role_id, members_in_role=0):
        ''' render the roles buttons bar '''
        user = self._get_request().AUTHENTICATED_USER

        options = {
            'current_page': current_page,
            'role_id': role_id,
            'common': self,
            'can_edit_roles': self.context.can_edit_roles(user),
            'can_edit_members': self.context.can_edit_members(role_id, user),
            'can_edit_extended_roles':
                self.context.can_edit_extended_roles(user),
            'can_delete_role': self.context.can_delete_role(role_id, user),
            'members_in_role': members_in_role,
            'leaders_enabled': roles_leaders.leaders_enabled(role_id),
        }
        tr = self.context._render_template

        return tr.render('zpt/roles_buttons.zpt', **options)

    def search_roles_box(self, pattern=None):
        ''' render the roles fitlering form '''
        options = {
            'pattern': pattern,
            'predefined_filters': self.context._predefined_filters(),
        }
        tr = self.context._render_template

        return tr.render('zpt/roles_filter_form.zpt', **options)

    @property
    def macros(self):
        ''' return the template macros '''
        return load_template('zpt/macros.zpt', self.context).macros

    @property
    def network_name(self):
        """ E.g. EIONET, SINAnet etc. """

        return NETWORK_NAME

    @property
    def supports_mailing(self):
        """ bool, whether supports role mailing lists """

        return NETWORK_NAME == 'Eionet'

#    @property
    def can_edit_users(self):
        ''' check permission to edit users '''
        return self.context.can_edit_users()

    def code_to_name(self, country_code):
        ''' return country name from iso code '''
        return get_country(country_code)['name']


class NaayaViewPageTemplateFile(ViewPageTemplateFile):
    """ A ViewPageTemplateFile that wraps its response in the main macro
    """

    def __call__(self, __instance, *args, **keywords):

        s = super(NaayaViewPageTemplateFile, self).__call__(__instance,
                                                            *args, **keywords)

        renderer = TemplateRenderer()
        try:
            renderer = renderer.__of__(__instance.context)
        except TypeError:  # this happens in case instance is a browser view
            renderer = renderer.__of__(__instance.aq_chain[1])
        result = renderer.wrap(s)

        return result


def orgs_in_country(context, country):
    """ return a dict of organisations in countrys """
    agent = _get_ldap_agent(context, secondary=True)
    orgs_by_id = agent.all_organisations()
    countries = dict(get_country_options(country=country))
    orgs = {}

    for org_id, info in six.iteritems(orgs_by_id):
        country_info = countries.get(info['country'])

        if country_info:
            orgs[org_id] = info

    return orgs


def nfp_for_country(context):
    """ Return country code for which the current user has NFP role
        or None otherwise"""
    user_id = context.REQUEST.AUTHENTICATED_USER.getId()

    if user_id:
        ldap_groups = get_ldap_user_groups(context, user_id)

        for group in ldap_groups:
            if ('eionet-nfp-mc-' in group[0] or
                'eionet-nfp-cc-' in group[0] or
                    'eionet-nfp-oc-' in group[0]):

                return group[0].rsplit('-', 1)[-1]
    return None


def nfp_can_change_user(context, uid, no_org=False):
    """ check if the authenticated user is an nfp and can edit a user
    (NFPs can only
     - edit users that are members of an organisation from their country
     - add users to such an organisation if they are not
    member of any org or if their org is from the country of the NFP)

    the 'no_org' parameter should decide what happens if the user is not
    member of an organisation: such a user cannot be edited by the NFP,
    but can be added to an org """
    try:
        # when called with CommonTemplateLogic as context
        context = context.context
    except AttributeError:
        pass
    nfp_country = nfp_for_country(context)
    if not nfp_country:
        return False
    agent = context._get_ldap_agent()
    user_orgs = agent.orgs_for_user(uid)
    same_country = False
    if user_orgs:
        for org in user_orgs:
            org_country = agent.org_country(org[0])
            if org_country == nfp_country:
                # if any of the user's orgs is the same with the
                # NFP's country, permision is True
                same_country = True
                break
        else:
            return False
    if same_country:
        return True
    # if the user doesn't have an organisation set, NFPs can add
    # them to any organisation from their country - there is no way
    # to bind users to a country
    return no_org


def get_ldap_user_groups(context, user_id):
    """ return the ldap roles the user is member of """
    agent = _get_ldap_agent(context, secondary=True)
    ldap_roles = sorted(agent.member_roles_info('user',
                                                user_id,
                                                ('description',)))

    return ldap_roles
