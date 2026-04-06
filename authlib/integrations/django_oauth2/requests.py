from collections import defaultdict

from django.http import HttpRequest
from django.utils.functional import cached_property

from authlib.common.encoding import json_loads
from authlib.oauth2.rfc6749 import JsonPayload
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import OAuth2Payload
from authlib.oauth2.rfc6749 import OAuth2Request


class DjangoOAuth2Payload(OAuth2Payload):
    def __init__(self, request: HttpRequest):
        self._request = request

    @cached_property
    def data(self):
        pass

    @cached_property
    def datalist(self):
        pass


class DjangoOAuth2Request(OAuth2Request):
    def __init__(self, request: HttpRequest):
        super().__init__(
            method=request.method,
            uri=request.build_absolute_uri(),
            headers=request.headers,
        )
        self.payload = DjangoOAuth2Payload(request)
        self._request = request

    @property
    def args(self):
        pass

    @property
    def form(self):
        pass


class DjangoJsonPayload(JsonPayload):
    def __init__(self, request: HttpRequest):
        self._request = request

    @cached_property
    def data(self):
        pass


class DjangoJsonRequest(JsonRequest):
    def __init__(self, request: HttpRequest):
        super().__init__(request.method, request.build_absolute_uri(), request.headers)
        self.payload = DjangoJsonPayload(request)
