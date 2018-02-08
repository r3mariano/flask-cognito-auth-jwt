import pprint
import traceback
from typing import Optional

from botocore.exceptions import ClientError
from warrant import Cognito, UserObj

from app.auth.authenticators.base import Authenticator, AuthError, AuthenticatedUser


class CognitoAuthenticator(Authenticator):
    def build_cognito(self, **kwargs):
        return Cognito(self.app.config['COGNITO_POOL_ID'],
                       self.app.config['COGNITO_CLIENT_ID'],
                       user_pool_region=self.app.config['AWS_REGION'],
                       access_key=self.app.config['AWS_ACCESS_KEY'],
                       secret_key=self.app.config['AWS_SECRET_KEY'],
                       **kwargs)

    @staticmethod
    def user_obj_from_cognito(cognito: Cognito):
        return cognito.get_user(attr_map={
            'sub': 'id'
        })

    @staticmethod
    def auth_user_from_cognito(user_obj: UserObj):
        # Tokens I get from Cognito (so I can modify user info)
        # 'id_token': user_obj._metadata['id_token'],
        # 'access_token': user_obj._metadata['access_token'],
        # 'refresh_token': user_obj._metadata['refresh_token']
        auth_user = AuthenticatedUser()
        auth_user.id = user_obj._data.get('id')
        auth_user.username = user_obj.username
        auth_user.permissions = user_obj._data.get('permissions')
        return auth_user

    def authenticate(self, username: str, password: str) -> Optional[AuthenticatedUser]:
        user = self.build_cognito(username=username)
        try:
            user.authenticate(password)
            if self.app.config['TESTING']:
                pprint.PrettyPrinter().pprint(vars(user))
            user_object = self.user_obj_from_cognito(user)
            return self.auth_user_from_cognito(user_object)
        except ClientError:
            traceback.print_exc()
            return None

    def register(self, username: str, password: str):
        user = self.build_cognito()
        try:
            user.register(username, password, email=username,)
        except ClientError:
            if self.app.config['TESTING']:
                traceback.print_exc()
            # TODO exposes that we are using python?
            msg = traceback.format_exc().splitlines()[-1]
            raise AuthError(msg)

    def verify(self, username: str, verify_code: str):
        user = self.build_cognito()
        try:
            user.confirm_sign_up(verify_code, username=username,)
        except ClientError:
            if self.app.config['TESTING']:
                traceback.print_exc()
            # TODO exposes that we are using python?
            msg = traceback.format_exc().splitlines()[-1]
            raise AuthError(msg)
