import functools

from django.conf import settings
from django.http import JsonResponse

from authlib.oauth1 import ResourceProtector as _ResourceProtector
from authlib.oauth1.errors import OAuth1Error

from .nonce import exists_nonce_in_cache


class ResourceProtector(_ResourceProtector):
    def __init__(self, client_model, token_model):
        self.client_model = client_model
        self.token_model = token_model

        config = getattr(settings, "AUTHLIB_OAUTH1_PROVIDER", {})
        methods = config.get("signature_methods", [])
        if methods and isinstance(methods, (list, tuple)):
            self.SUPPORTED_SIGNATURE_METHODS = methods

        self._nonce_expires_in = config.get("nonce_expires_in", 86400)

    def get_client_by_id(self, client_id):
        try:
            return self.client_model.objects.get(client_id=client_id)
        except self.client_model.DoesNotExist:
            return None

    def get_token_credential(self, request):
        try:
            return self.token_model.objects.get(
                client_id=request.client_id, oauth_token=request.token
            )
        except self.token_model.DoesNotExist:
            return None

    def exists_nonce(self, nonce, request):
        return exists_nonce_in_cache(nonce, request, self._nonce_expires_in)

    def acquire_credential(self, request):
        pass

    def __call__(self, realm=None):
        def decorator(f):
            @functools.wraps(f)
            pass

        if callable(realm):
            return decorator(realm)
        return decorator
