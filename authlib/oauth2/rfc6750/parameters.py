from authlib.common.urls import add_params_to_qs
from authlib.common.urls import add_params_to_uri


def add_to_uri(token, uri):
    """Add a Bearer Token to the request URI.
    Not recommended, use only if client can't use authorization header or body.

    http://www.example.com/path?access_token=h480djs93hd8
    """
    pass


def add_to_headers(token, headers=None):
    """Add a Bearer Token to the request URI.
    Recommended method of passing bearer tokens.

    Authorization: Bearer h480djs93hd8
    """
    pass


def add_to_body(token, body=None):
    """Add a Bearer Token to the request body.

    access_token=h480djs93hd8
    """
    pass


def add_bearer_token(token, uri, headers, body, placement="header"):
    pass
