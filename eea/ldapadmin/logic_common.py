''' some common logic '''
from z3c.pt.pagetemplate import PageTemplateFile as ChameleonTemplate


def _is_authenticated(request):
    ''' check if the user is authenticated '''
    return 'Authenticated' in request.AUTHENTICATED_USER.getRoles()


def logged_in_user(request):
    ''' return the id of the authenticated user '''
    user_id = ''

    if _is_authenticated(request):
        user_id = request.AUTHENTICATED_USER.getId()

    return user_id


# pylint: disable=dangerous-default-value
def load_template(name, context=None, _memo={}):
    ''' load the main template '''
    if name not in _memo:
        tpl = ChameleonTemplate(name)

        if context is not None:
            bound = tpl.bind(context)
            _memo[name] = bound
        else:
            _memo[name] = tpl

    return _memo[name]
