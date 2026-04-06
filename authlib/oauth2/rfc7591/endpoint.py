import binascii
import os
import time

from joserfc import jwt
from joserfc.errors import JoseError

from authlib._joserfc_helpers import import_any_key
from authlib.common.security import generate_token
from authlib.consts import default_json_headers
from authlib.deprecate import deprecate

from ..rfc6749 import AccessDeniedError
from ..rfc6749 import InvalidRequestError
from .claims import ClientMetadataClaims
from .errors import InvalidClientMetadataError
from .errors import InvalidSoftwareStatementError
from .errors import UnapprovedSoftwareStatementError


class ClientRegistrationEndpoint:
    """The client registration endpoint is an OAuth 2.0 endpoint designed to
    allow a client to be registered with the authorization server.
    """

    ENDPOINT_NAME = "client_registration"

    #: Rewrite this value with a list to support ``software_statement``
    #: e.g. ``software_statement_alg_values_supported = ['RS256']``
    software_statement_alg_values_supported = None

    def __init__(self, server=None, claims_classes=None):
        self.server = server
        self.claims_classes = claims_classes or [ClientMetadataClaims]

    def __call__(self, request):
        return self.create_registration_response(request)

    def create_registration_response(self, request):
        pass

    def extract_client_metadata(self, request):
        pass

    def extract_software_statement(self, software_statement, request):
        pass

    def generate_client_info(self, request):
        # https://tools.ietf.org/html/rfc7591#section-3.2.1
        pass

    def generate_client_registration_info(self, client, request):
        """Generate ```registration_client_uri`` and ``registration_access_token``
        for RFC7592. This method returns ``None`` by default. Developers MAY rewrite
        this method to return registration information.
        """
        pass

    def create_endpoint_request(self, request):
        return self.server.create_json_request(request)

    def generate_client_id(self, request):
        """Generate ``client_id`` value. Developers MAY rewrite this method
        to use their own way to generate ``client_id``.
        """
        pass

    def generate_client_secret(self, request):
        """Generate ``client_secret`` value. Developers MAY rewrite this method
        to use their own way to generate ``client_secret``.
        """
        pass

    def get_server_metadata(self):
        """Return server metadata which includes supported grant types,
        response types and etc.
        """
        raise NotImplementedError()

    def authenticate_token(self, request):
        """Authenticate current credential who is requesting to register a client.
        Developers MUST implement this method in subclass::

            def authenticate_token(self, request):
                auth = request.headers.get("Authorization")
                return get_token_by_auth(auth)

        :return: token instance
        """
        raise NotImplementedError()

    def resolve_public_key(self, request):
        """Resolve a public key for decoding ``software_statement``. If
        ``enable_software_statement=True``, developers MUST implement this
        method in subclass::

            def resolve_public_key(self, request):
                return get_public_key_from_user(request.credential)

        :return: JWK or Key string
        """
        raise NotImplementedError()

    def save_client(self, client_info, client_metadata, request):
        """Save client into database. Developers MUST implement this method
        in subclass::

            def save_client(self, client_info, client_metadata, request):
                client = OAuthClient(
                    client_id=client_info['client_id'],
                    client_secret=client_info['client_secret'],
                    ...
                )
                client.save()
                return client
        """
        raise NotImplementedError()
