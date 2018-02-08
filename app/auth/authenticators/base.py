from typing import Optional


class AuthError(Exception):
    def __init__(self, *args, **kwargs):
        pass


class AuthenticatedUser:
    id = ''
    username = ''
    permissions = ''


# TODO make authenticator a "service"
class Authenticator:
    def __init__(self, app):
        self.app = app

    def authenticate(self, username: str, password: str) -> Optional[AuthenticatedUser]:
        raise NotImplementedError('authenticate() not implemented')

    def register(self, username: str, password: str):
        raise NotImplementedError('register() not implemented')

    def verify(self, username: str, verify_code: str):
        raise NotImplementedError('verify() not implemented')
