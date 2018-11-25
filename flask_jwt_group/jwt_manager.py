import datetime


class JWTManager:
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

        self.blacklist = {}

    def init_app(self, app):
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['flask-jwt-group'] = self

        self._set_default_config(app)
        self._set_error_handlers(app)

    @classmethod
    def _set_default_config(cls, app):
        app.config.setdefault('JWT_ALGORITHM', 'HS256')
        app.config.setdefault('JWT_TOKEN_LOCATION', ['headers'])
        app.config.setdefault('JWT_HEADER_NAME', 'Authorization')
        app.config.setdefault('JWT_HEADER_PREFIX', 'Bearer')
        app.config.setdefault('JWT_IDENTITY_KEY', 'identity')
        app.config.setdefault('JWT_TIMEZONE', datetime.datetime.utcnow)
        app.config.setdefault('JWT_GROUP_KEY', 'group')
        app.config.setdefault('JWT_SECRET_KEY', None)
        app.config.setdefault('JWT_BLACKLIST_ENABLED', False)
        app.config.setdefault('JWT_BLACKLIST_TARGETS', ['access', 'refresh'])

        # expires
        app.config.setdefault('JWT_ACCESS_TOKEN_EXPIRES', datetime.timedelta(minutes=15))
        app.config.setdefault('JWT_REFRESH_TOKEN_EXPIRES', datetime.timedelta(days=30))

    @classmethod
    def _set_error_handlers(cls, app):
        pass
