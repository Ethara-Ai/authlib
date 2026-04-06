from joserfc import jwt
from joserfc.errors import DecodeError
from joserfc.errors import JoseError
from joserfc.errors import UnsupportedAlgorithmError
from joserfc.jws import JWSRegistry

from authlib._joserfc_helpers import import_any_key

from ..rfc6749 import AuthorizationServer
from ..rfc6749 import ClientMixin
from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidRequestError
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request
from .errors import InvalidRequestObjectError
from .errors import InvalidRequestUriError
from .errors import RequestNotSupportedError
from .errors import RequestUriNotSupportedError


class JWTAuthenticationRequest:
    """Authorization server extension implementing the support
    for JWT secured authentication request, as defined in :rfc:`RFC9101 <9101>`.

    :param support_request: Whether to enable support for the ``request`` parameter.
    :param support_request_uri: Whether to enable support for the ``request_uri`` parameter.

    This extension is intended to be inherited and registered into the authorization server::

        class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
            def resolve_client_public_key(self, client: ClientMixin):
                return get_jwks_for_client(client)

            def get_request_object(self, request_uri: str):
                try:
                    return requests.get(request_uri).text
                except requests.Exception:
                    return None

            def get_server_metadata(self):
                return {
                    "issuer": ...,
                    "authorization_endpoint": ...,
                    "require_signed_request_object": ...,
                }

            def get_client_require_signed_request_object(self, client: ClientMixin):
                return client.require_signed_request_object


        authorization_server.register_extension(JWTAuthenticationRequest())
    """

    claims_validator = jwt.JWTClaimsRegistry(
        client_id={"essential": True},
    )

    def __init__(self, support_request: bool = True, support_request_uri: bool = True):
        self.support_request = support_request
        self.support_request_uri = support_request_uri

    def __call__(self, authorization_server: AuthorizationServer):
        authorization_server.register_hook(
            "before_get_authorization_grant", self.parse_authorization_request
        )

    def get_request_object_signing_algorithms(self, client):
        """Return the supported algorithms for verifying the ``request_object`` JWT signature.
        By default, this method will only return the recommended algorithms. If signed request
        object is not required, "none" algorithm will be included.

        Developers can override this method to customize the supported algorithms::

            def get_request_object_signing_algorithms(self, client):
                return ["RS256"]
        """
        pass

    def parse_authorization_request(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ):
        pass

    def _shoud_proceed_with_request_object(
        self,
        request: OAuth2Request,
        client: ClientMixin,
    ) -> bool:
        pass

    def _get_raw_request_object(self, request: OAuth2Request) -> str:
        pass

    def _decode_request_object(
        self, request, client: ClientMixin, raw_request_object: str
    ):
        pass

    def get_request_object(self, request_uri: str):
        """Download the request object at ``request_uri``.

        This method must be implemented if the ``request_uri`` parameter is supported::

            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def get_request_object(self, request_uri: str):
                    try:
                        return requests.get(request_uri).text
                    except requests.Exception:
                        return None
        """
        raise NotImplementedError()

    def resolve_client_public_key(self, client: ClientMixin):
        """Resolve the client public key for verifying the JWT signature.
        A client may have many public keys, in this case, we can retrieve it
        via ``kid`` value in headers. Developers MUST implement this method::

            from joserfc import KeySet


            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def resolve_client_public_key(self, client):
                    if client.jwks_uri:
                        data = requests.get(client.jwks_uri).json()
                        return KeySet.import_key_set(data)

                    return KeySet.import_key_set(client.jwks)
        """
        raise NotImplementedError()

    def get_server_metadata(self) -> dict:
        """Return server metadata which includes supported grant types,
        response types and etc.

        When the ``require_signed_request_object`` claim is :data:`True`,
        all clients require that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

            class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
                def get_server_metadata(self):
                    return {
                        "issuer": ...,
                        "authorization_endpoint": ...,
                        "require_signed_request_object": ...,
                        "request_object_signing_alg_values_supported": ["RS256", ...],
                    }

        """
        pass

    def get_client_require_signed_request_object(self, client: ClientMixin) -> bool:
        """Return the 'require_signed_request_object' client metadata.

        When :data:`True`, the client requires that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

           class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
               def get_client_require_signed_request_object(self, client):
                   return client.require_signed_request_object

        If not implemented, the value is considered as :data:`False`.
        """
        pass
