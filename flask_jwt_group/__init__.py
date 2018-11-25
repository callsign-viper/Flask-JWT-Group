from flask import _request_ctx_stack, _app_ctx_stack, current_app
from werkzeug.local import LocalProxy

from flask_jwt_group.config import config

raw_jwt_claims = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'jwt', {}))
jwt_identity = LocalProxy(lambda: raw_jwt_claims.get(config.identity_key, None))
jwt_group = LocalProxy(lambda: raw_jwt_claims.get(config.group_key, None))