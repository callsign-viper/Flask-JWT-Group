from functools import wraps

import jwt
from flask import current_app, request, _request_ctx_stack, abort

# from helper import _decode_jwt


def jwt_required(group=None):
    """

    :param group: must be list
    :return:
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header_name = current_app.config['JWT_HEADER_NAME']
            jwt_header = request.headers.get(header_name, None)
            secret_key = current_app.config['JWT_SECRET_KEY']
            algorithm = current_app.config['JWT_ALGORITHM']

            if not jwt_header:
                abort(400)

            # if type(group) is not list:
            #     abort(400)

            decoded_token = jwt.decode(jwt_header.split()[1], key=secret_key, algorithms=algorithm)

            if 'iat' not in decoded_token:
                abort(422)
            if 'nbf' not in decoded_token:
                abort(422)
            if 'exp' not in decoded_token:
                abort(422)
            if 'jti' not in decoded_token:
                abort(422)
            if 'identity' not in decoded_token:
                abort(422)
            if 'type' not in decoded_token or decoded_token['type'] != 'access':
                abort(422)
            if decoded_token['group'] not in group:
                abort(422)

            _request_ctx_stack.top.jwt = decoded_token

            return fn(*args, **kwargs)
        return wrapper
    return decorator
