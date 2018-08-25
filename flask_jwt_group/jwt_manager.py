import datetime


_DEFAULT_SETTINGS = {
    'JWT_ALGORITHM': 'HS256',
    'JWT_TOKEN_LOCATION': ['headers'],
    'JWT_HEADER_NAME': 'Authorization',
    'JWT_HEADER_TYPE': 'Bearer',
    'JWT_IDENTITY_KEY': 'identity',
    'JWT_GROUP_KEY': 'group',
    
    # expires
    'JWT_ACCESS_TOKEN_EXPIRES': datetime.timedelta(minutes=15),
    'JWT_REFRESH_TOKEN_EXPIRES': datetime.timedelta(days=30),

    'JWT_SECRET_KEY': None
}


class JWTManager:
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        # Set default configuration
        for k, v in _DEFAULT_SETTINGS.items():
            app.config.setdefault(k, v)

    def _error_handlers(self, app):
        pass
