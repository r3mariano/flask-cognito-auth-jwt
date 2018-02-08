from flask import json, jsonify
from flask_jwt_extended import JWTManager, create_access_token, set_refresh_cookies, set_access_cookies


def setup_test_jwt(flask_app, user_id='test'):
    _setup_fake_auth(flask_app, user_id)
    flask_app.secret_key = 'super=secret'
    flask_app.config['JWT_TOKEN_LOCATION'] = 'cookies'
    # No CSRF plz
    flask_app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    return _setup_jwt_manager(flask_app)


def _setup_jwt_manager(flask_app):
    return JWTManager(flask_app)


def _setup_fake_auth(flask_app, user_id):
    @flask_app.route('/auth/fake_login', methods=['POST'])
    def login():
        response = jsonify('')
        access_token = create_access_token(user_id)
        set_access_cookies(response, access_token)
        return response


def setup_user(jwt_manager, client, claims=None):
    if claims is None:
        claims = {}

    @jwt_manager.user_claims_loader
    def user_claims_callback(identity):
        return claims

    response = client.post('/auth/fake_login')
    # data = json.loads(response.get_data(as_text=True))
    # return data['access_token']
    return response


def jwt_get(client, url, jwt, **kwargs):
    return _jwt_request('GET', client, url, jwt, **kwargs)


def jwt_post(client, url, jwt, **kwargs):
    return _jwt_request('POST', client, url, jwt, **kwargs)


def jwt_put(client, url, jwt, **kwargs):
    return _jwt_request('PUT', client, url, jwt, **kwargs)


def _jwt_request(req_method, client, url, jwt, header_name='Authorization', header_type='Bearer', **kwargs):
    # header_type = '{} {}'.format(header_type, jwt).strip()
    # response = json_request(client, url, headers={header_name: header_type}, method=req_method, **kwargs)
    response = json_request(client, url, method=req_method, **kwargs)
    return response


def json_request(client, url, method, **kwargs):
    if 'headers' not in kwargs:
        kwargs['headers'] = {}
    kwargs['headers']['Content-Type'] = 'application/json'

    if 'data' in kwargs:
        kwargs['data'] = json.dumps(kwargs['data'])

    return client.open(url, method=method, **kwargs)
