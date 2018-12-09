import pytest
import jwt
from flask import Flask, jsonify

from flask_jwt_group import jwt_identity, jwt_group
from flask_jwt_group.jwt_manager import JWTManager
from flask_jwt_group.util import (create_access_token, create_refresh_token,
                                  get_jwt_identity, get_jwt_group, _get_jwt_manager, add_current_token_to_blacklist)
from flask_jwt_group.view_decorator import jwt_required, jwt_optional, jwt_refresh_token_required


@pytest.fixture(scope="function")
def flask_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'iwanttogoodatprogramming'
    app.config['JWT_BLACKLIST_ENABLED'] = True
    JWTManager(app)

    @app.route('/required', methods=['GET'])
    @jwt_required('student', 'admin')
    def required():
        identity, group = str(jwt_identity), str(jwt_group)

        add_current_token_to_blacklist()

        return jsonify({
            'identity': identity,
            'group': group,
            'blacklist': _get_jwt_manager().access_blacklist
        }), 200

    @app.route('/optional', methods=['GET'])
    @jwt_optional('student', 'admin')
    def optional():
        identity, group = str(jwt_identity), str(jwt_group)

        if jwt_identity:
            add_current_token_to_blacklist()

        return jsonify({
            'identity': identity,
            'group': group,
            'identity_from_func': get_jwt_identity(),
            'group_from_func': get_jwt_group()
        })

    @app.route('/refresh-required', methods=['GET'])
    @jwt_refresh_token_required('student', 'admin')
    def refresh_required():
        identity, group = str(jwt_identity), str(jwt_group)

        add_current_token_to_blacklist()

        return jsonify({
            'identity': identity,
            'group': group,
            'blacklist': _get_jwt_manager().refresh_blacklist
        }), 200

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


def test_get_jwt_identity(flask_app):
    prefix = flask_app.config['JWT_HEADER_PREFIX']

    test_client = flask_app.test_client()
    with flask_app.test_request_context():
        token = create_access_token('flouie74', 'student')

    resp = test_client.get('/optional')
    assert resp.json['identity_from_func'] == 'None'
    resp = test_client.get('/optional', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    assert resp.json['identity_from_func'] == 'flouie74'


def test_get_jwt_group(flask_app):
    prefix = flask_app.config['JWT_HEADER_PREFIX']

    test_client = flask_app.test_client()
    with flask_app.test_request_context():
        token = create_access_token('flouie74', 'student')

    resp = test_client.get('/optional')
    assert resp.json['group_from_func'] == 'None'
    resp = test_client.get('/optional', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    assert resp.json['group_from_func'] == 'student'


def test_jwt_required(flask_app):
    prefix = flask_app.config['JWT_HEADER_PREFIX']

    test_client = flask_app.test_client()
    with flask_app.test_request_context():
        token = create_access_token('flouie74', 'student')
        different_groups_token = create_access_token('flouie74', 'teacher')

    # has valid token
    resp = test_client.get('/required', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    assert resp.status_code == 200
    assert resp.json['identity'] == 'flouie74'
    assert resp.json['group'] == 'student'

    # non exist token in header
    resp = test_client.get('/required', headers=None)
    assert resp.status_code == 400

    # has incorrect type token
    with flask_app.test_request_context():
        refresh_token = create_refresh_token('flouie74', 'teacher')
    resp = test_client.get('/required', headers={'Authorization': '{0} {1}'.format(prefix, refresh_token)})
    assert resp.status_code == 422

    # has different groups token
    resp = test_client.get('/required', headers={'Authorization': '{0} {1}'.format(prefix, different_groups_token)})
    assert resp.status_code == 422

    # token is in blacklist
    test_client.get('/required', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    resp = test_client.get('/required', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    assert resp.status_code == 403


def test_jwt_optional(flask_app):
    prefix = flask_app.config['JWT_HEADER_PREFIX']

    test_client = flask_app.test_client()
    with flask_app.test_request_context():
        token = create_access_token('flouie74', 'student')
        different_groups_token = create_access_token('flouie74', 'teacher')

    # no authorization header
    resp = test_client.get('/optional')
    assert resp.status_code == 200
    assert resp.json['identity'] == 'None'
    assert resp.json['group'] == 'None'

    # has valid token
    resp = test_client.get('/optional', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    assert resp.status_code == 200
    assert resp.json['identity'] == 'flouie74'
    assert resp.json['group'] == 'student'

    # non exist token in header
    resp = test_client.get('/required', headers=None)
    assert resp.status_code == 400

    # has incorrect type token
    with flask_app.test_request_context():
        refresh_token = create_refresh_token('flouie74', 'teacher')
    resp = test_client.get('/optional', headers={'Authorization': '{0} {1}'.format(prefix, refresh_token)})
    assert resp.status_code == 422

    # has different groups token
    resp = test_client.get('/optional', headers={'Authorization': '{0} {1}'.format(prefix, different_groups_token)})
    assert resp.status_code == 422

    # token is in blacklist
    test_client.get('/optional', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    resp = test_client.get('/optional', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    assert resp.status_code == 403


def test_jwt_refresh_required(flask_app):
    prefix = flask_app.config['JWT_HEADER_PREFIX']

    test_client = flask_app.test_client()
    with flask_app.test_request_context():
        token = create_refresh_token('flouie74', 'student')
        different_groups_token = create_refresh_token('flouie74', 'teacher')

    # has valid token
    resp = test_client.get('/refresh-required', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    assert resp.status_code == 200
    assert resp.json['identity'] == 'flouie74'
    assert resp.json['group'] == 'student'

    # non exist token in header
    resp = test_client.get('/refresh-required', headers=None)
    assert resp.status_code == 400

    # has incorrect type token
    with flask_app.test_request_context():
        access_token = create_access_token('flouie74', 'teacher')
    resp = test_client.get('/refresh-required', headers={'Authorization': '{0} {1}'.format(prefix, access_token)})
    assert resp.status_code == 422

    # has different groups token
    resp = test_client.get('/refresh-required',
                           headers={'Authorization': '{0} {1}'.format(prefix, different_groups_token)})
    assert resp.status_code == 422

    # token is in blacklist
    test_client.get('/refresh-required', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    resp = test_client.get('/refresh-required', headers={'Authorization': '{0} {1}'.format(prefix, token)})
    assert resp.status_code == 403


def test_add_token_to_blacklist(flask_app):
    test_client = flask_app.test_client()
    with flask_app.test_request_context():
        access_token = create_access_token('flouie74', 'student')
        refresh_token = create_refresh_token('flouie74', 'student')
        another_access_token = create_access_token('geni429', 'admin')
        another_refresh_token = create_refresh_token('geni429', 'admin')

    secret_key = flask_app.config['JWT_SECRET_KEY']
    algorithm = flask_app.config['JWT_ALGORITHM']
    prefix = flask_app.config['JWT_HEADER_PREFIX']

    decoded_access_token = jwt.decode(access_token, key=secret_key, algorithms=algorithm)
    decoded_another_access_token = jwt.decode(another_access_token, key=secret_key, algorithms=algorithm)
    decoded_refresh_token = jwt.decode(refresh_token, key=secret_key, algorithms=algorithm)
    decoded_another_refresh_token = jwt.decode(another_refresh_token, key=secret_key, algorithms=algorithm)

    # test access_blacklist
    resp = test_client.get('/required', headers={'Authorization': '{0} {1}'.format(prefix, access_token)})
    assert resp.status_code == 200
    assert resp.json['blacklist'] == {decoded_access_token['jti']: decoded_access_token['exp']}

    resp2 = test_client.get('/required', headers={'Authorization': '{0} {1}'.format(prefix, another_access_token)})
    assert resp.status_code == 200
    assert resp2.json['blacklist'] == {decoded_access_token['jti']: decoded_access_token['exp'],
                                       decoded_another_access_token['jti']: decoded_another_access_token['exp']}

    # test refresh_blacklist
    refresh_resp = test_client.get('/refresh-required',
                                   headers={'Authorization': '{0} {1}'.format(prefix, refresh_token)})
    assert refresh_resp.status_code == 200
    assert refresh_resp.json['blacklist'] == {decoded_refresh_token['jti']: decoded_refresh_token['exp']}

    refresh_resp2 = test_client.get('/refresh-required',
                                    headers={'Authorization': '{0} {1}'.format(prefix, another_refresh_token)})
    assert refresh_resp2.status_code == 200
    assert refresh_resp2.json['blacklist'] == {
        decoded_refresh_token['jti']: decoded_refresh_token['exp'],
        decoded_another_refresh_token['jti']: decoded_another_refresh_token['exp']
    }
