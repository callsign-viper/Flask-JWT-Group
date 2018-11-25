from uuid import uuid4

import jwt
from flask import current_app

from flask_jwt_group import jwt_identity, jwt_group, raw_jwt_claims
from flask_jwt_group.config import config
from flask_jwt_group.view_decorator import _decode_token_and_access_control


def _create_token(identity, group=None, token_type='access', expires=None):
    now = config.jwt_timezone
    jti = str(uuid4())
    exp = config.access_token_expires if not expires else expires

    token = {
        'iat': now,
        'nbf': now,
        'exp': now + exp,
        'jti': jti,
        # default: 'identity'
        config.identity_key: identity,
        # default: 'group'
        config.group_key: group,
        'type': token_type,
    }

    return jwt.encode(token, key=config._secret_key, algorithm=config.algorithm).decode('utf-8')


def create_access_token(identity, group=None, expires=None):
    return _create_token(identity, group=group, expires=expires)


def create_refresh_token(identity, group=None, expires=None):
    return _create_token(identity, group=group, token_type='refresh', expires=expires)


def get_jwt_identity():
    return str(jwt_identity)


def get_jwt_group():
    return str(jwt_group)


def _get_jwt_manager():
    try:
        return current_app.extensions['flask-jwt-group']
    except KeyError:
        raise RuntimeError("You must initialize JWT manager with Flask app instance before using this function")
