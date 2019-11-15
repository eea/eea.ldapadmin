from zope.component import getMultiAdapter

from Acquisition import Implicit
from constants import NETWORK_NAME
from eea.ldapadmin import roles_leaders
from eea.ldapadmin.countries import get_country
from logic_common import _get_user_id, _is_authenticated
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from z3c.pt.pagetemplate import PageTemplateFile as ChameleonTemplate


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


def load_template(name, context=None, _memo={}):
    if name not in _memo:
        tpl = ChameleonTemplate(name)

        if context is not None:
            bound = tpl.bind(context)
            _memo[name] = bound
        else:
            _memo[name] = tpl

    return _memo[name]


zope2_wrapper = PageTemplateFile('zpt/zope2_wrapper.zpt', globals())
plone5_wrapper = PageTemplateFile('zpt/plone5_wrapper.zpt', globals())


class TemplateRenderer(Implicit):
    def __init__(self, common_factory=lambda ctx: {}):
        self.common_factory = common_factory

    def render(self, template_name, **options):
        context = self.aq_parent
        template = load_template(template_name, context)

        try:
            namespace = template.pt_getContext((), options)
        except AttributeError:      # Plone5 compatibility
            namespace = template.im_self._pt_get_context(
                context, context.REQUEST, options)

        namespace['common'] = self.common_factory(context)
        namespace['browserview'] = self.browserview

        if hasattr(template, 'pt_render'):
            return template.pt_render(namespace)
        else:
            return template.im_self.render(**namespace)

    def browserview(self, context, name):
        return getMultiAdapter((context, self.aq_parent.REQUEST), name=name)

    def wrap(self, body_html):
        context = self.aq_parent
        plone = False
        # Naaya groupware integration. If present, use the standard template
        # of the current site
        macro = self.aq_parent.restrictedTraverse('/').get('gw_macro')

        if macro:
            try:
                layout = self.aq_parent.getLayoutTool().getCurrentSkin()
                main_template = layout.getTemplateById('standard_template')
            except:
                main_template = self.aq_parent.restrictedTraverse(
                    'standard_template.pt')
            main_page_macro = main_template.macros['page']
        else:
            main_template = self.aq_parent.restrictedTraverse(
                'main_template')
            plone = True
            main_page_macro = main_template.macros['master']

        if plone:
            tmpl = plone5_wrapper.__of__(context)
        else:
            tmpl = zope2_wrapper.__of__(context)

        return tmpl(main_page_macro=main_page_macro, body_html=body_html)

    def __call__(self, template_name, **options):
        if 'context' not in options:
            options['context'] = self.aq_parent
        options['request'] = self.REQUEST

        return self.wrap(self.render(template_name, **options))


class TemplateRendererNoWrap(Implicit):
    def __init__(self, common_factory=lambda ctx: {}):
        self.common_factory = common_factory

    def render(self, name, **options):
        context = self.aq_parent
        template = load_template(name)
        options['context'] = self.aq_parent
        options['request'] = self.aq_parent.REQUEST

        if hasattr(template, 'pt_getContext'):
            namespace = template.pt_getContext((), options)
        else:
            namespace = template._pt_get_context(
                context, self.aq_parent.REQUEST, options)
        namespace['common'] = self.common_factory(context)

        if hasattr(template, 'pt_render'):
            return template.pt_render(namespace)
        else:
            return template.render(**namespace)


    def __call__(self, name, **options):
        return self.render(name, **options)


class CommonTemplateLogic(object):
    def __init__(self, context):
        self.context = context

    def base_url(self):
        return self.context.absolute_url()

    def site_url(self):
        return self.context.unrestrictedTraverse("/").absolute_url()

    def _get_request(self):
        return self.context.REQUEST

    def admin_menu(self):
        return self.context._render_template.render("zpt/users/admin_menu.zpt")

    def checkPermissionEditOrganisations(self):
        return self.context.checkPermissionEditOrganisations()

    def can_edit_organisations(self):
        return self.context.can_edit_organisations()

    def can_edit_organisation(self):
        return self.context.can_edit_organisation()

    def full_edit_permission(self):
        return self.context.checkPermissionEditUsers()

    def is_authenticated(self):
        return _is_authenticated(self._get_request())

    def user_id(self):
        return _get_user_id(self._get_request())

    def readonly_alert(self):
        return self.context._render_template.render(
            "zpt/nfp_nrc/readonly_alert.zpt")

    def buttons_bar(self, current_page, role_id, members_in_role=0):
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
        options = {
            'pattern': pattern,
            'predefined_filters': self.context._predefined_filters(),
        }
        tr = self.context._render_template

        return tr.render('zpt/roles_filter_form.zpt', **options)

    @property
    def macros(self):
        return load_template('zpt/macros.zpt', self.context).macros

    @property
    def network_name(self):
        """ E.g. EIONET, SINAnet etc. """

        return NETWORK_NAME

    @property
    def supports_mailing(self):
        """ bool, whether supports role mailing lists """

        return NETWORK_NAME == 'Eionet'

    @property
    def can_edit_users(self):
        return self.context.can_edit_users()

    def code_to_name(self, country_code):
        return get_country(country_code)['name']


def network_name(self):
    """ E.g. EIONET, SINAnet etc. """

    return NETWORK_NAME


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
