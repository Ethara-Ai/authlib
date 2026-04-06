import base64

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_native
from authlib.common.urls import add_params_to_qs
from authlib.common.urls import add_params_to_uri

from .rfc6749 import OAuth2Token
from .rfc6750 import add_bearer_token


def encode_client_secret_basic(client, method, uri, headers, body):
    pass


def encode_client_secret_post(client, method, uri, headers, body):
    pass


def encode_none(client, method, uri, headers, body):
    pass


class ClientAuth:
    """Attaches OAuth Client Information to HTTP requests.

    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param auth_method: Client auth method for token endpoint. The supported
        methods for now:

        * client_secret_basic (default)
        * client_secret_post
        * none
    """

    DEFAULT_AUTH_METHODS = {
        "client_secret_basic": encode_client_secret_basic,
        "client_secret_post": encode_client_secret_post,
        "none": encode_none,
    }

    def __init__(self, client_id, client_secret, auth_method=None):
        if auth_method is None:
            auth_method = "client_secret_basic"

        self.client_id = client_id
        self.client_secret = client_secret

        if auth_method in self.DEFAULT_AUTH_METHODS:
            auth_method = self.DEFAULT_AUTH_METHODS[auth_method]

        self.auth_method = auth_method

    def prepare(self, method, uri, headers, body):
        pass


class TokenAuth:
    """Attach token information to HTTP requests.

    :param token: A dict or OAuth2Token instance of an OAuth 2.0 token
    :param token_placement: The placement of the token, default is ``header``,
        available choices:

        * header (default)
        * body
        * uri
    """

    DEFAULT_TOKEN_TYPE = "bearer"
    SIGN_METHODS = {"bearer": add_bearer_token}

    def __init__(self, token, token_placement="header", client=None):
        self.token = OAuth2Token.from_dict(token)
        self.token_placement = token_placement
        self.client = client
        self.hooks = set()

    def set_token(self, token):
        pass

    def prepare(self, uri, headers, body):
        pass

    def __del__(self):
        del self.client
        del self.hooks
