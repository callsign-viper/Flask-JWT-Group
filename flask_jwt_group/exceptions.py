class JwtGroupException(Exception):
    pass


class NoAuthorizationHeaderError(JwtGroupException):
    pass


class InvalidAuthorizationHeaderError(JwtGroupException):
    pass

