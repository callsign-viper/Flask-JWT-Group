from convertor import encode_jwt


def create_access_token(identity, group=None):
    return encode_jwt(identity, group)
