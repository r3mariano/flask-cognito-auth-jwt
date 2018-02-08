from re import split

from flask import request, Blueprint
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, set_access_cookies, \
    set_refresh_cookies, unset_jwt_cookies, get_jwt_claims, jwt_refresh_token_required

from app.auth.authenticators import authenticator
from app.auth.authenticators.base import AuthError, AuthenticatedUser
from app.auth.utils import build_response

auth = Blueprint('auth', __name__, url_prefix='/auth')

################
# JWT


def make_jwt_payload_from_user(user: AuthenticatedUser):
    return {
        'pm': [p for p in split(r',', user.permissions)]
    }


def init_jwt(flask_app):
    jwt_auth = JWTManager(flask_app)

    @jwt_auth.user_claims_loader
    def add_claims_to_token(user: AuthenticatedUser):
        return make_jwt_payload_from_user(user)

    @jwt_auth.user_identity_loader
    def add_claims_to_token(user: AuthenticatedUser):
        return user.id

    return jwt_auth


##########
# Helpers


def do_refresh(response, identity):
    access_token = create_access_token(identity=identity)
    set_access_cookies(response, access_token)
    return response


#########
# Routes


@auth.route('/test_protected')
@jwt_required
def protected():
    return 'heyyy'
    # return build_response(get_jwt_claims())


@auth.route('/test_hello')
def unprotected():
    return 'hello'


@auth.route('/login', methods=['POST'])
def login():
    form = request.get_json()
    my_authenticator = authenticator(auth)
    auth_user = my_authenticator.authenticate(form['username'], form['password'])
    if auth_user is None:
        return build_response({'message': 'Invalid username or password.'}), 401

    response = build_response({'message': 'ok'})
    access_token = create_access_token(identity=auth_user)
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, access_token)
    return response, 200


@auth.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    response = build_response({'message': 'ok'})
    response = do_refresh(response, get_jwt_identity())
    return response, 200


@auth.route('/logout', methods=['POST'])
@jwt_required
def logout():
    response = build_response('')
    unset_jwt_cookies(response)
    return response, 200


# TODO not good; users can just sign up.
@auth.route('/test-register', methods=['POST'])
def register():
    my_authenticator = authenticator(auth)
    form = request.get_json()
    try:
        my_authenticator.register(form['email'], form['password'])
        return 'OK'
    except AuthError:
        # TODO get message from AuthError
        return 'Fail', 401


@auth.route('/verify', methods=['POST'])
def verify():
    my_authenticator = authenticator(auth)
    form = request.get_json()
    try:
        my_authenticator.verify(form['email'], form['verify_code'])
        return 'OK'
    except AuthError:
        # TODO get message from AuthError
        return 'Fail', 401
