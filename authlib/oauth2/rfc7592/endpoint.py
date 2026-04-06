from joserfc.errors import JoseError

from authlib.consts import default_json_headers

from ..rfc6749 import AccessDeniedError
from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import UnauthorizedClientError
from ..rfc7591 import InvalidClientMetadataError
from ..rfc7591.claims import ClientMetadataClaims


class ClientConfigurationEndpoint:
    ENDPOINT_NAME = "client_configuration"

    def __init__(self, server=None, claims_classes=None):
        self.server = server
        self.claims_classes = claims_classes or [ClientMetadataClaims]

    def __call__(self, request):
        return self.create_configuration_response(request)

    def create_configuration_response(self, request):
        # This request is authenticated by the registration access token issued
        # to the client.
        pass

    def create_endpoint_request(self, request):
        return self.server.create_json_request(request)

    def create_read_client_response(self, client, request):
        pass

    def create_delete_client_response(self, client, request):
        pass

    def create_update_client_response(self, client, request):
        # The updated client metadata fields request MUST NOT include the
        # 'registration_access_token', 'registration_client_uri',
        # 'client_secret_expires_at', or 'client_id_issued_at' fields
        pass

    def extract_client_metadata(self, request):
        pass

    def introspect_client(self, client):
        pass

    def generate_client_registration_info(self, client, request):
        """Generate ```registration_client_uri`` and ``registration_access_token``
        for RFC7592. By default this method returns the values sent in the current
        request. Developers MUST rewrite this method to return different registration
        information.::

            def generate_client_registration_info(self, client, request):{
                access_token = request.headers['Authorization'].split(' ')[1]
                return {
                    'registration_client_uri': request.uri,
                    'registration_access_token': access_token,
                }

        :param client: the instance of OAuth client
        :param request: formatted request instance
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

    def authenticate_client(self, request):
        """Read a client from the request payload.
        Developers MUST implement this method in subclass::

            def authenticate_client(self, request):
                client_id = request.payload.data.get("client_id")
                return Client.get(client_id=client_id)

        :return: client instance
        """
        raise NotImplementedError()

    def revoke_access_token(self, token, request):
        """Revoke a token access in case an invalid client has been requested.
        Developers MUST implement this method in subclass::

            def revoke_access_token(self, token, request):
                token.revoked = True
                token.save()

        """
        raise NotImplementedError()

    def check_permission(self, client, request):
        """Checks whether the current client is allowed to be accessed, edited
        or deleted. Developers MUST implement it in subclass, e.g.::

            def check_permission(self, client, request):
                return client.editable

        :return: boolean
        """
        raise NotImplementedError()

    def delete_client(self, client, request):
        """Delete authorization code from database or cache. Developers MUST
        implement it in subclass, e.g.::

            def delete_client(self, client, request):
                client.delete()

        :param client: the instance of OAuth client
        :param request: formatted request instance
        """
        raise NotImplementedError()

    def update_client(self, client, client_metadata, request):
        """Update the client in the database. Developers MUST implement this method
        in subclass::

            def update_client(self, client, client_metadata, request):
                client.set_client_metadata(
                    {**client.client_metadata, **client_metadata}
                )
                client.save()
                return client

        :param client: the instance of OAuth client
        :param client_metadata: a dict of the client claims to update
        :param request: formatted request instance
        :return: client instance
        """
        raise NotImplementedError()

    def get_server_metadata(self):
        """Return server metadata which includes supported grant types,
        response types and etc.
        """
        raise NotImplementedError()
