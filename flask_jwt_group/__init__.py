from flask import current_app, _request_ctx_stack
from werkzeug.local import LocalProxy

raw_jwt_claims = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'jwt', {}))
jwt_identity = LocalProxy(lambda: raw_jwt_claims.get(current_app.config[''], None))
jwt_group = LocalProxy(lambda: raw_jwt_claims.get(current_app.config[''], None))
