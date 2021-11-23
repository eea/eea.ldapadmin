
def _get_user_password(request):
    return request.AUTHENTICATED_USER.__

def _get_user_id(request):
    return request.AUTHENTICATED_USER.getId()

def _is_authenticated(request):
    return ('Authenticated' in request.AUTHENTICATED_USER.getRoles())
