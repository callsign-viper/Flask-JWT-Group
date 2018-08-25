import datetime
import uuid

import jwt
from flask import current_app


def create_access_token(identity, group=None):
    now = datetime.datetime.utcnow()
    jti = str(uuid.uuid4())
    configs = current_app.config
    token = {
        'iat': now,
        'nbf': now,
        'exp': now + configs['JWT_ACCESS_TOKEN_EXPIRES'],
        'jti': jti,
        configs['JWT_IDENTITY_KEY']: identity,
        'type': 'access',
        configs['JWT_GROUP_KEY']: group
    }

    return jwt.encode(token, key=configs['JWT_SECRET_KEY'], algorithm=configs['JWT_ALGORITHM']).decode('utf-8')

