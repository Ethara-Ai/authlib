import logging
import warnings

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.oauth2.rfc6749 import AccessDeniedError
from authlib.oauth2.rfc6749 import ImplicitGrant
from authlib.oauth2.rfc6749 import InvalidScopeError
from authlib.oauth2.rfc6749 import OAuth2Error
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from authlib.oauth2.rfc6749.hooks import hooked

from ._legacy import LegacyMixin
from .util import create_half_hash
from .util import create_response_mode_response
from .util import is_openid_scope
from .util import validate_nonce
from .util import validate_request_prompt

log = logging.getLogger(__name__)


class OpenIDImplicitGrant(LegacyMixin, ImplicitGrant):
    RESPONSE_TYPES = {"id_token token", "id_token"}
    DEFAULT_RESPONSE_MODE = "fragment"

    def exists_nonce(self, nonce, request):
        """Check if the given nonce is existing in your database. Developers
        should implement this method in subclass, e.g.::

            def exists_nonce(self, nonce, request):
                exists = AuthorizationCode.query.filter_by(
                    client_id=request.payload.client_id, nonce=nonce
                ).first()
                return bool(exists)

        :param nonce: A string of "nonce" parameter in request
        :param request: OAuth2Request instance
        :return: Boolean
        """
        raise NotImplementedError()

    def generate_user_info(self, user, scope):
        """Provide user information for the given scope. Developers
        MUST implement this method in subclass, e.g.::

            from authlib.oidc.core import UserInfo


            def generate_user_info(self, user, scope):
                user_info = UserInfo(sub=user.id, name=user.name)
                if "email" in scope:
                    user_info["email"] = user.email
                return user_info

        :param user: user instance
        :param scope: scope of the token
        :return: ``authlib.oidc.core.UserInfo`` instance
        """
        raise NotImplementedError()

    def get_audiences(self, request):
        """Parse `aud` value for id_token, default value is client id. Developers
        MAY rewrite this method to provide a customized audience value.
        """
        client = request.client
        return [client.get_client_id()]

    def validate_authorization_request(self):
        pass

    @hooked
    def validate_consent_request(self):
        pass

    def create_authorization_response(self, redirect_uri, grant_user):
        pass

    def create_granted_params(self, grant_user):
        pass

    def process_implicit_token(self, token, code=None):
        pass

    def _compatible_resolve_jwt_config(self, grant, client):
        pass
