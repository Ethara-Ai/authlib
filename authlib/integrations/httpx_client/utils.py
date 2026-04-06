from httpx import Request

HTTPX_CLIENT_KWARGS = [
    "headers",
    "cookies",
    "verify",
    "cert",
    "http1",
    "http2",
    "proxy",
    "mounts",
    "timeout",
    "follow_redirects",
    "limits",
    "max_redirects",
    "event_hooks",
    "base_url",
    "transport",
    "trust_env",
    "default_encoding",
]


def extract_client_kwargs(kwargs):
    pass


def build_request(url, headers, body, initial_request: Request) -> Request:
    """Make sure that all the data from initial request is passed to the updated object."""
    pass
