_DEFAULT_SETTINGS = {

}


class JWTManager:
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(app):
        for k, v in _DEFAULT_SETTINGS.items():
            app.config.setdefault(k, v)

        pass
