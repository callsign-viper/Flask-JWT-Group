from datetime import timedelta

from flask import current_app


class _Config:
    @property
    def algorithm(self):
        return current_app.config['JWT_ALGORITHM']

    @property
    def location(self):
        locations = current_app.config['JWT_TOKEN_LOCATION']
        if not isinstance(locations, list):
            locations = [locations]

        return locations

    @property
    def header_name(self):
        return current_app.config['JWT_HEADER_NAME']

    @property
    def header_prefix(self):
        return current_app.config['JWT_HEADER_PREFIX']

    @property
    def identity_key(self):
        return current_app.config['JWT_IDENTITY_KEY']

    @property
    def jwt_timezone(self):
        return current_app.config['JWT_TIMEZONE']()

    @property
    def group_key(self):
        group_key = current_app.config['JWT_GROUP_KEY']
        if not isinstance(group_key, str) or group_key is None:
            raise RuntimeError("group_key is not valid")

        return group_key

    @property
    def access_token_expires(self):
        exp = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        if not isinstance(exp, timedelta) or exp is None:
            raise RuntimeError("access token exp is not valid")

        return exp

    @property
    def refresh_token_expires(self):
        exp = current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
        if not isinstance(exp, timedelta) or exp is None:
            raise RuntimeError("refresh token exp is not valid")

        return exp

    @property
    def _secret_key(self):
        key = current_app.config['JWT_SECRET_KEY']
        if not key:
            raise RuntimeError("jwt-secret-key must be needed")

        return key


config = _Config()
