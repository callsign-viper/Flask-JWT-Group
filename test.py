import pytest
import jwt
from flask import Flask

from flask_jwt_group.jwt_manager import JWTManager
from flask_jwt_group.util import create_access_token
# from flask_jwt_group.helper import _decode_jwt
from flask_jwt_group.view_decorator import jwt_required


@pytest.fixture(scope="function")
def flask_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'iwanttogoodatprogramming'
    JWTManager(app)

    return app


def test_creation_success(flask_app):
    secret_key = flask_app.config['JWT_SECRET_KEY']
    algorithm = flask_app.config['JWT_ALGORITHM']

    with flask_app.test_request_context():
        token = create_access_token('flouie74', 'student')

    decoded = jwt.decode(token, key=secret_key, algorithms=algorithm)

    assert 'iat' in decoded
    assert 'nbf' in decoded
    assert 'exp' in decoded
    assert 'jti' in decoded
    assert 'identity' in decoded
    assert decoded['identity'] == 'flouie74'
    assert 'type' in decoded
    assert decoded['type'] == 'access'
    assert decoded['group'] == 'student'
