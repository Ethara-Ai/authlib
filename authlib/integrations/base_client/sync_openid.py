from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.oidc.core import CodeIDToken
from authlib.oidc.core import ImplicitIDToken
from authlib.oidc.core import UserInfo


class OpenIDMixin:
    def fetch_jwk_set(self, force=False):
        pass

    def userinfo(self, **kwargs):
        """Fetch user info from ``userinfo_endpoint``."""
        pass

    def parse_id_token(
        self, token, nonce, claims_options=None, claims_cls=None, leeway=120
    ):
        """Return an instance of UserInfo from token's ``id_token``."""
        pass

    def create_logout_url(
        self,
        post_logout_redirect_uri=None,
        id_token_hint=None,
        state=None,
        **kwargs,
    ):
        """Generate the end session URL for RP-Initiated Logout.

        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param state: Opaque value for maintaining state.
        :param kwargs: Extra parameters (client_id, logout_hint, ui_locales).
        :return: dict with 'url' and 'state' keys.
        """
        pass
