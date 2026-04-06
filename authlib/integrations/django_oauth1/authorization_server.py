import logging

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse

from authlib.common.security import generate_token
from authlib.common.urls import url_encode
from authlib.oauth1 import AuthorizationServer as _AuthorizationServer
from authlib.oauth1 import OAuth1Request
from authlib.oauth1 import TemporaryCredential

from .nonce import exists_nonce_in_cache

log = logging.getLogger(__name__)


class BaseServer(_AuthorizationServer):
    def __init__(self, client_model, token_model, token_generator=None):
        self.client_model = client_model
        self.token_model = token_model

        if token_generator is None:

            def token_generator():
                return {
                    "oauth_token": generate_token(42),
                    "oauth_token_secret": generate_token(48),
                }

        self.token_generator = token_generator
        self._config = getattr(settings, "AUTHLIB_OAUTH1_PROVIDER", {})
        self._nonce_expires_in = self._config.get("nonce_expires_in", 86400)
        methods = self._config.get("signature_methods")
        if methods:
            self.SUPPORTED_SIGNATURE_METHODS = methods

    def get_client_by_id(self, client_id):
        try:
            return self.client_model.objects.get(client_id=client_id)
        except self.client_model.DoesNotExist:
            return None

    def exists_nonce(self, nonce, request):
        return exists_nonce_in_cache(nonce, request, self._nonce_expires_in)

    def create_token_credential(self, request):
        pass

    def check_authorization_request(self, request):
        pass

    def create_oauth1_request(self, request):
        pass

    def handle_response(self, status_code, payload, headers):
        resp = HttpResponse(url_encode(payload), status=status_code)
        for k, v in headers:
            resp[k] = v
        return resp


class CacheAuthorizationServer(BaseServer):
    def __init__(self, client_model, token_model, token_generator=None):
        super().__init__(client_model, token_model, token_generator)
        self._temporary_expires_in = self._config.get(
            "temporary_credential_expires_in", 86400
        )
        self._temporary_credential_key_prefix = self._config.get(
            "temporary_credential_key_prefix", "temporary_credential:"
        )

    def create_temporary_credential(self, request):
        pass

    def get_temporary_credential(self, request):
        pass

    def delete_temporary_credential(self, request):
        pass

    def create_authorization_verifier(self, request):
        pass
