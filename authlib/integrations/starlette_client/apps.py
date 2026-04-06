from starlette.datastructures import URL
from starlette.responses import RedirectResponse

from ..base_client import BaseApp
from ..base_client import OAuthError
from ..base_client.async_app import AsyncOAuth1Mixin
from ..base_client.async_app import AsyncOAuth2Mixin
from ..base_client.async_openid import AsyncOpenIDMixin
from ..httpx_client import AsyncOAuth1Client
from ..httpx_client import AsyncOAuth2Client


class StarletteAppMixin:
    async def save_authorize_data(self, request, **kwargs):
        pass

    async def authorize_redirect(self, request, redirect_uri=None, **kwargs):
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: HTTP request instance from Starlette view.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        pass


class StarletteOAuth1App(StarletteAppMixin, AsyncOAuth1Mixin, BaseApp):
    client_cls = AsyncOAuth1Client

    async def authorize_access_token(self, request, **kwargs):
        pass


class StarletteOAuth2App(
    StarletteAppMixin, AsyncOAuth2Mixin, AsyncOpenIDMixin, BaseApp
):
    client_cls = AsyncOAuth2Client

    async def logout_redirect(
        self, request, post_logout_redirect_uri=None, id_token_hint=None, **kwargs
    ):
        """Create a HTTP Redirect for End Session Endpoint (RP-Initiated Logout).

        :param request: HTTP request instance from Starlette view.
        :param post_logout_redirect_uri: URI to redirect after logout.
        :param id_token_hint: ID Token previously issued to the RP.
        :param kwargs: Extra parameters (state, client_id, logout_hint, ui_locales).
        :return: A HTTP redirect response.
        """
        pass

    async def validate_logout_response(self, request):
        """Validate the state parameter from the logout callback.

        :param request: HTTP request instance from Starlette view.
        :return: The state data dict.
        :raises OAuthError: If state is missing or invalid.
        """
        pass

    async def authorize_access_token(self, request, **kwargs):
        pass
