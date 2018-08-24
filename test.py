import pytest
import jwt
from flask import Flask

from flask_jwt_group.jwt_manager import JWTManager
from flask_jwt_group.util import create_access_token
from flask_jwt_group.view_decorator import jwt_required


@pytest.fixture(scope="function")
def flask_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'iwanttogoodatprogramming'
    JWTManager(app)

    @app.route('/required', methods=['GET'])
    @jwt_required(['student'])
    def required():
        return 'Be decorated by jwt_required', 200

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


def test_jwt_required(flask_app):
    test_client = flask_app.test_client()
    with flask_app.test_request_context():
        token = create_access_token('flouie74', 'student')
        different_groups_token = create_access_token('flouie74', 'teacher')

    # has valid token
    resp = test_client.get('/required', headers={'Authorization': 'Bearer {}'.format(token)})
    assert resp.status_code == 200
    assert resp.data.decode('utf-8') == 'Be decorated by jwt_required'

    # non exist token in header
    resp = test_client.get('/required', headers=None)
    assert resp.status_code == 400

    # has incorrect type token
    # resp = test_client.get('/required', headers=create_refresh_token())

    # has different groups token
    resp = test_client.get('/required', headers={'Authorization': 'Bearer {}'.format(different_groups_token)})
    assert resp.status_code == 422
