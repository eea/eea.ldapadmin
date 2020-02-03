from email.message import Message


def _get_user_password(request):
    return request.AUTHENTICATED_USER.__


def _get_user_id(request):
    return request.AUTHENTICATED_USER.getId()


def _is_authenticated(request):
    return ('Authenticated' in request.AUTHENTICATED_USER.getRoles())


def _session_pop(request, name, default):
    session = request.SESSION
    if name in session.keys():
        value = session[name]
        del session[name]
        return value
    else:
        return default


def _create_plain_message(body_bytes):
    message = Message()
    message.set_payload(body_bytes)
    return message
