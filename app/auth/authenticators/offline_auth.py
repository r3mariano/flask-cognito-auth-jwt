from typing import Optional

from app.auth.authenticators.base import Authenticator, AuthenticatedUser


class OfflineAuthenticator(Authenticator):
    def authenticate(self, username: str, password: str) -> Optional[AuthenticatedUser]:
        if username == 'x@x.x' and password == '123456':
            auth_user = AuthenticatedUser()
            auth_user.id = 'xxxx-xx-xxxx'
            auth_user.username = 'x@x.x'
            auth_user.permissions = 'p1,p2,p3'
            return auth_user

    def verify(self, username: str, verify_code: str):
        pass

    def register(self, username: str, password: str):
        pass
