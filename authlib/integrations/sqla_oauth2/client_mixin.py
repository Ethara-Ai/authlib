import secrets

from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text

from authlib.common.encoding import json_dumps
from authlib.common.encoding import json_loads
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749 import list_to_scope
from authlib.oauth2.rfc6749 import scope_to_list


class OAuth2ClientMixin(ClientMixin):
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120))
    client_id_issued_at = Column(Integer, nullable=False, default=0)
    client_secret_expires_at = Column(Integer, nullable=False, default=0)
    _client_metadata = Column("client_metadata", Text)

    @property
    def client_info(self):
        """Implementation for Client Info in OAuth 2.0 Dynamic Client
        Registration Protocol via `Section 3.2.1`_.

        .. _`Section 3.2.1`: https://tools.ietf.org/html/rfc7591#section-3.2.1
        """
        pass

    @property
    def client_metadata(self):
        pass

    def set_client_metadata(self, value):
        pass

    @property
    def redirect_uris(self):
        pass

    @property
    def token_endpoint_auth_method(self):
        pass

    @property
    def grant_types(self):
        pass

    @property
    def response_types(self):
        pass

    @property
    def client_name(self):
        pass

    @property
    def client_uri(self):
        pass

    @property
    def logo_uri(self):
        pass

    @property
    def scope(self):
        pass

    @property
    def contacts(self):
        pass

    @property
    def tos_uri(self):
        pass

    @property
    def policy_uri(self):
        pass

    @property
    def jwks_uri(self):
        pass

    @property
    def jwks(self):
        pass

    @property
    def software_id(self):
        pass

    @property
    def software_version(self):
        pass

    @property
    def id_token_signed_response_alg(self):
        pass

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        pass

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        pass

    def check_client_secret(self, client_secret):
        pass

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == "token":
            return self.token_endpoint_auth_method == method
        # TODO
        return True

    def check_response_type(self, response_type):
        pass

    def check_grant_type(self, grant_type):
        pass
