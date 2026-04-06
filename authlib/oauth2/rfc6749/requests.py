from collections import defaultdict

from authlib.deprecate import deprecate

from .errors import InsecureTransportError


class OAuth2Payload:
    @property
    def data(self):
        raise NotImplementedError()

    @property
    def datalist(self) -> defaultdict[str, list]:
        raise NotImplementedError()

    @property
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        pass

    @property
    def response_type(self) -> str:
        pass

    @property
    def grant_type(self) -> str:
        pass

    @property
    def redirect_uri(self):
        pass

    @property
    def scope(self) -> str:
        pass

    @property
    def state(self):
        pass


class BasicOAuth2Payload(OAuth2Payload):
    def __init__(self, payload):
        self._data = payload
        self._datalist = {key: [value] for key, value in payload.items()}

    @property
    def data(self):
        pass

    @property
    def datalist(self) -> defaultdict[str, list]:
        pass


class OAuth2Request(OAuth2Payload):
    def __init__(self, method: str, uri: str, body=None, headers=None):
        InsecureTransportError.check(uri)
        #: HTTP method
        self.method = method
        self.uri = uri
        #: HTTP headers
        self.headers = headers or {}

        # Store body for backward compatibility but issue deprecation warning if used
        if body is not None:
            deprecate(
                "'body' parameter in OAuth2Request is deprecated. "
                "Use the payload system instead.",
                version="1.8",
            )
        self._body = body

        self.payload = None

        self.client = None
        self.auth_method = None
        self.user = None
        self.authorization_code = None
        self.refresh_token = None
        self.credential = None
        self._scope = None

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def form(self):
        pass

    @property
    def data(self):
        pass

    @property
    def datalist(self) -> defaultdict[str, list]:
        pass

    @property
    def client_id(self) -> str:
        pass

    @property
    def response_type(self) -> str:
        pass

    @property
    def grant_type(self) -> str:
        pass

    @property
    def redirect_uri(self):
        pass

    @property
    def scope(self) -> str:
        pass

    @scope.setter
    def scope(self, value: str):
        pass

    @property
    def state(self):
        pass

    @property
    def body(self):
        pass


class JsonPayload:
    @property
    def data(self):
        raise NotImplementedError()


class JsonRequest:
    def __init__(self, method, uri, headers=None):
        self.method = method
        self.uri = uri
        self.headers = headers or {}
        self.payload = None

    @property
    def data(self):
        pass
