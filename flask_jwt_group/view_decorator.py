from functools import wraps


def jwt_required(group=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        
        return wrapper
    return decorator
