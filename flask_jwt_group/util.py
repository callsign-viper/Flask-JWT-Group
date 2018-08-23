import datetime
import uuid

import jwt
from flask import current_app


def create_access_token(identity, group=None):
    now = datetime.datetime.utcnow()
    jti = str(uuid.uuid4())
    secret = current_app.config['JWT_SECRET_KEY']
    algorithm = current_app.config['JWT_ALGORITHM']
    token = {
        'iat': now,
        'nbf': now,
        'exp': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        'jti': jti,
        'identity': identity,
        'type': 'access',
        'group': group
    }

    return jwt.encode(token, secret, algorithm=algorithm).decode('utf-8')
