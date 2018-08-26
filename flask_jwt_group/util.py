from datetime import datetime
from uuid import uuid4

import jwt
from flask import current_app


def _create_token(identity, group=None, type='access'):
    now = datetime.utcnow()
    jti = str(uuid4())
    configs = current_app.config

    token = {
        'iat': now,
        'nbf': now,
        'exp': now + configs['JWT_ACCESS_TOKEN_EXPIRES'],
        'jti': jti,
        configs['JWT_IDENTITY_KEY']: identity,
        # default: 'identity'
        configs['JWT_GROUP_KEY']: group,
        # default: 'group'
        'type': type,
    }

    return jwt.encode(token, key=configs['JWT_SECRET_KEY'], algorithm=configs['JWT_ALGORITHM']).decode('utf-8')


def create_access_token(identity, group=None):
    return _create_token(identity, group)


def create_refresh_token(identity, group=None):
    return _create_token(identity, group, 'refresh')
