import unittest

from app.testing.jwt import setup_test_jwt, setup_user, jwt_get
from .controllers import auth
from flask import Flask, json


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask('test_app')
        self.app.register_blueprint(auth)
        self.client = self.app.test_client()
        self.jwt_manager = setup_test_jwt(self.app)

    def test_protected_endpoint(self):
        claims = {'some claim': 'some value'}
        access_token = setup_user(self.jwt_manager, self.client, claims=claims)
        response = jwt_get(self.client, '/auth/test_protected', access_token)
        assert response.status_code == 200
        # response_json = json.loads(response.data)
        # assert response_json == claims

    def test_protected_endpoint_no_auth(self):
        response = self.client.get('/auth/test_protected')
        assert response.status_code == 401

    def test_hello(self):
        response = self.client.get('/auth/test_hello')
        assert response.status_code == 200
