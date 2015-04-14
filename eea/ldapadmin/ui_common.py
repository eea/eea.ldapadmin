from Acquisition import Implicit
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from Products.PageTemplates.PageTemplateFile import PageTemplateFile as \
    Z2Template
from constants import NETWORK_NAME
from eea.ldapadmin import roles_leaders
from logic_common import _get_user_id, _is_authenticated
from persistent.list import PersistentList
from persistent.mapping import PersistentMapping
from zope.pagetemplate.pagetemplatefile import PageTemplateFile as Z3Template


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


def load_template(name, _memo={}):
    if name not in _memo:
        _memo[name] = Z3Template(name, globals())
    return _memo[name]


class SessionMessages(object):
    def __init__(self, request, name):
        self.request = request
        self.name = name

    def add(self, msg_type, msg):
        session = self.request.SESSION
        if self.name not in session.keys():
            session[self.name] = PersistentMapping()
        messages = session[self.name]
        if msg_type not in messages:
            messages[msg_type] = PersistentList()
        messages[msg_type].append(msg)

    def html(self):
        session = self.request.SESSION
        if self.name in session.keys():
            messages = dict(session[self.name])
            del session[self.name]
        else:
            messages = {}
        tmpl = load_template('zpt/session_messages.zpt')
        return tmpl(messages=messages)

zope2_wrapper = Z2Template('zpt/zope2_wrapper.zpt', globals())


class TemplateRenderer(Implicit):
    def __init__(self, common_factory=lambda ctx: {}):
        self.common_factory = common_factory

    def render(self, name, **options):
        context = self.aq_parent
        template = load_template(name)
        namespace = template.pt_getContext((), options)
        namespace['common'] = self.common_factory(context)
        return template.pt_render(namespace)

    def wrap(self, body_html):
        context = self.aq_parent
        zope2_tmpl = zope2_wrapper.__of__(context)
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
        else:
            main_template = self.aq_parent.restrictedTraverse(
                'standard_template.pt')
        main_page_macro = main_template.macros['page']
        return zope2_tmpl(main_page_macro=main_page_macro, body_html=body_html)

    def __call__(self, name, **options):
        if 'context' not in options:
            options['context'] = self.aq_parent
        options['request'] = self.REQUEST
        return self.wrap(self.render(name, **options))


class TemplateRendererNoWrap(Implicit):
    def __init__(self, common_factory=lambda ctx: {}):
        self.common_factory = common_factory

    def render(self, name, **options):
        context = self.aq_parent
        template = load_template(name)
        options['context'] = self.aq_parent
        options['request'] = self.aq_parent.REQUEST

        namespace = template.pt_getContext((), options)
        namespace['common'] = self.common_factory(context)
        return template.pt_render(namespace)

    def __call__(self, name, **options):
        return self.render(name, **options)


class CommonTemplateLogic(object):
    def __init__(self, context):
        self.context = context

    def base_url(self):
        return self.context.absolute_url()

    def site_url(self):
        return self.context.unrestrictedTraverse("/").absolute_url()

    def message_boxes(self):
        return SessionMessages(self._get_request(),
                               self.context.session_messages).html()

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
        return load_template('zpt/macros.zpt').macros

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
        return ('Manager' in
                self.context.REQUEST.AUTHENTICATED_USER.getRoles())


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
