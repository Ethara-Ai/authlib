"""authlib.oauth2.rfc6749.authenticate_client.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Registry of client authentication methods, with 3 built-in methods:

1. client_secret_basic
2. client_secret_post
3. none

The "client_secret_basic" method is used a lot in examples of `RFC6749`_,
but the concept of naming are introduced in `RFC7591`_.

.. _`RFC6749`: https://tools.ietf.org/html/rfc6749
.. _`RFC7591`: https://tools.ietf.org/html/rfc7591
"""

import logging

from .errors import InvalidClientError
from .util import extract_basic_authorization

log = logging.getLogger(__name__)

__all__ = ["ClientAuthentication"]


class ClientAuthentication:
    def __init__(self, query_client):
        self.query_client = query_client
        self._methods = {
            "none": authenticate_none,
            "client_secret_basic": authenticate_client_secret_basic,
            "client_secret_post": authenticate_client_secret_post,
        }

    def register(self, method, func):
        self._methods[method] = func

    def authenticate(self, request, methods, endpoint):
        pass

    def __call__(self, request, methods, endpoint="token"):
        return self.authenticate(request, methods, endpoint)


def authenticate_client_secret_basic(query_client, request):
    """Authenticate client by ``client_secret_basic`` method. The client
    uses HTTP Basic for authentication.
    """
    pass


def authenticate_client_secret_post(query_client, request):
    """Authenticate client by ``client_secret_post`` method. The client
    uses POST parameters for authentication.
    """
    pass


def authenticate_none(query_client, request):
    """Authenticate public client by ``none`` method. The client
    does not have a client secret.
    """
    pass


def _validate_client(query_client, client_id, status_code=400):
    pass
