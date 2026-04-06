from urllib.request import parse_http_list
from urllib.request import parse_keqv_list

from authlib.common.urls import extract_params
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse

from .errors import DuplicatedOAuthProtocolParameterError
from .errors import InsecureTransportError
from .signature import SIGNATURE_TYPE_BODY
from .signature import SIGNATURE_TYPE_HEADER
from .signature import SIGNATURE_TYPE_QUERY
from .util import unescape


class OAuth1Request:
    def __init__(self, method, uri, body=None, headers=None):
        InsecureTransportError.check(uri)
        self.method = method
        self.uri = uri
        self.body = body
        self.headers = headers or {}

        # states namespaces
        self.client = None
        self.credential = None
        self.user = None

        self.query = urlparse.urlparse(uri).query
        self.query_params = url_decode(self.query)
        self.body_params = extract_params(body) or []

        self.auth_params, self.realm = _parse_authorization_header(headers)
        self.signature_type, self.oauth_params = _parse_oauth_params(
            self.query_params, self.body_params, self.auth_params
        )

        params = []
        params.extend(self.query_params)
        params.extend(self.body_params)
        params.extend(self.auth_params)
        self.params = params

    @property
    def client_id(self):
        pass

    @property
    def client_secret(self):
        pass

    @property
    def rsa_public_key(self):
        pass

    @property
    def timestamp(self):
        pass

    @property
    def redirect_uri(self):
        pass

    @property
    def signature(self):
        pass

    @property
    def signature_method(self):
        pass

    @property
    def token(self):
        pass

    @property
    def token_secret(self):
        pass


def _filter_oauth(params):
    pass


def _parse_authorization_header(headers):
    """Parse an OAuth authorization header into a list of 2-tuples."""
    pass


def _parse_oauth_params(query_params, body_params, auth_params):
    pass
