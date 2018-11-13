from functools import wraps

import jwt
from flask import request, _request_ctx_stack, abort

from flask_jwt_group.config import config
from flask_jwt_group.exceptions import NoAuthorizationHeaderError, InvalidAuthorizationHeaderError


def _get_encoded_token_from_request(configs):
    header_name = configs.header_name
    header_prefix = configs.header_prefix

    jwt_header = request.headers.get(header_name, None)

    if not jwt_header:
        raise NoAuthorizationHeaderError

    parts = jwt_header.split()

    if not header_prefix:
        # header prefix is empty('')
        if len(parts) != 1:
            # JWT header includes prefix
            raise InvalidAuthorizationHeaderError
        token = parts[0]
    else:
        if parts[0] != header_prefix or len(parts) != 2:
            raise InvalidAuthorizationHeaderError

        token = parts[1]

    return token


def _decode_token_and_access_control(token, configs, token_type, expected_groups):
    decoded_token = jwt.decode(
        token,
        key=configs._secret_key,
        algorithm=configs.algorithm
    )

    if 'iat' not in decoded_token:
        abort(422)
    if 'nbf' not in decoded_token:
        abort(422)
    if 'exp' not in decoded_token:
        abort(422)
    if 'jti' not in decoded_token:
        abort(422)
    if configs.identity_key not in decoded_token:
        abort(422)
    if configs.group_key not in decoded_token or decoded_token['group'] not in expected_groups:
        abort(422)
    if 'type' not in decoded_token or decoded_token['type'] != token_type:
        abort(422)

    return decoded_token


def jwt_required(*expected_groups):
    """
    This decorator to protect Flask Api Resource

    :param expected_groups: Groups required for authentication (variable argument)
    :return:
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            configs = config

            try:
                encoded_token = _get_encoded_token_from_request(configs)

            except NoAuthorizationHeaderError:
                abort(400)

            except InvalidAuthorizationHeaderError:
                abort(422)

            else:
                _request_ctx_stack.top.jwt = _decode_token_and_access_control(
                    encoded_token,
                    configs,
                    'access',
                    expected_groups
                )

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def jwt_optional(*expected_groups):
    """
    This decorator to protect Flask Api Resource

    :param expected_groups: Groups required for authentication (variable argument)
    :return:
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            configs = config

            try:
                encoded_token = _get_encoded_token_from_request(configs)

            except (NoAuthorizationHeaderError, InvalidAuthorizationHeaderError):
                pass

            else:
                _request_ctx_stack.top.jwt = _decode_token_and_access_control(
                    encoded_token,
                    configs,
                    'access',
                    expected_groups
                )

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def jwt_refresh_token_required(*expected_groups):
    """
    This decorator to protect Flask Api Resource

    :param expected_groups: Groups required for authentication (variable argument)
    :return:
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            configs = config

            encoded_token = _get_encoded_token_from_request(configs)

            _request_ctx_stack.top.jwt = _decode_token_and_access_control(
                encoded_token,
                configs,
                'refresh',
                expected_groups
            )

            return fn(*args, **kwargs)
        return wrapper
    return decorator
