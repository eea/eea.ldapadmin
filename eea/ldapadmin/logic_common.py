''' some common logic '''


def _get_user_id(request):
    ''' return the id of the authenticated user '''
    return request.AUTHENTICATED_USER.getId()


def _is_authenticated(request):
    ''' check if the user is authenticated '''
    return 'Authenticated' in request.AUTHENTICATED_USER.getRoles()
