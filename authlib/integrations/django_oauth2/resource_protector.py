import functools

from django.http import JsonResponse

from authlib.oauth2 import OAuth2Error
from authlib.oauth2 import ResourceProtector as _ResourceProtector
from authlib.oauth2.rfc6749 import MissingAuthorizationError
from authlib.oauth2.rfc6750 import BearerTokenValidator as _BearerTokenValidator

from .requests import DjangoJsonRequest
from .signals import token_authenticated


class ResourceProtector(_ResourceProtector):
    def acquire_token(self, request, scopes=None, **kwargs):
        """A method to acquire current valid token with the given scope.

        :param request: Django HTTP request instance
        :param scopes: a list of scope values
        :return: token object
        """
        pass

    def __call__(self, scopes=None, optional=False, **kwargs):
        claims = kwargs
        claims["scopes"] = scopes if not callable(scopes) else None

        def decorator(f):
            @functools.wraps(f)
            pass

        if callable(scopes):
            return decorator(scopes)
        return decorator


class BearerTokenValidator(_BearerTokenValidator):
    def __init__(self, token_model, realm=None, **extra_attributes):
        self.token_model = token_model
        super().__init__(realm, **extra_attributes)

    def authenticate_token(self, token_string):
        try:
            return self.token_model.objects.get(access_token=token_string)
        except self.token_model.DoesNotExist:
            return None


def return_error_response(error):
    pass
