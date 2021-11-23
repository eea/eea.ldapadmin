from Acquisition import Implicit
from zope.pagetemplate.pagetemplatefile import PageTemplateFile as Z3Template
from persistent.list import PersistentList
from persistent.mapping import PersistentMapping
from Products.PageTemplates.PageTemplateFile import PageTemplateFile\
                                                 as Z2Template

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
        return zope2_tmpl(body_html=body_html)

    def __call__(self, name, **options):
        return self.wrap(self.render(name, **options))
