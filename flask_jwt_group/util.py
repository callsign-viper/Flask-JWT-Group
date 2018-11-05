from datetime import datetime
from uuid import uuid4

import jwt
from flask import current_app


def _create_token(identity, group=None, token_type='access', expires=None):
    configs = current_app.config
    now = datetime.utcnow()
    jti = str(uuid4())
    exp = configs['JWT_ACCESS_TOKEN_EXPIRES'] if not expires else expires

    token = {
        'iat': now,
        'nbf': now,
        'exp': now + exp,
        'jti': jti,
        # default: 'identity'
        configs['JWT_IDENTITY_KEY']: identity,
        # default: 'group'
        configs['JWT_GROUP_KEY']: group,
        'type': token_type,
    }

    return jwt.encode(token, key=configs['JWT_SECRET_KEY'], algorithm=configs['JWT_ALGORITHM']).decode('utf-8')


def create_access_token(identity, group=None, expires=None):
    return _create_token(identity, group=group, expires=expires)


def create_refresh_token(identity, group=None, expires=None):
    return _create_token(identity, group=group, token_type='refresh', expires=expires)
