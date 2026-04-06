import time

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.common.encoding import to_native
from authlib.common.urls import add_params_to_uri
from authlib.common.urls import quote_url
from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oauth2.rfc6749 import scope_to_list

from ..errors import AccountSelectionRequiredError
from ..errors import ConsentRequiredError
from ..errors import LoginRequiredError
from ..util import create_half_hash


def is_openid_scope(scope):
    pass


def validate_request_prompt(grant, redirect_uri, redirect_fragment=False):
    pass


def validate_nonce(request, exists_nonce, required=False):
    nonce = request.payload.data.get("nonce")
    if not nonce:
        if required:
            raise InvalidRequestError("Missing 'nonce' in request.")
        return True

    if exists_nonce(nonce, request):
        raise InvalidRequestError("Replay attack")


def generate_id_token(
    token,
    user_info,
    key,
    iss,
    aud,
    alg="RS256",
    exp=3600,
    nonce=None,
    auth_time=None,
    acr=None,
    amr=None,
    code=None,
    kid=None,
):
    pass


def create_response_mode_response(redirect_uri, params, response_mode):
    pass


def _guess_prompt_value(end_user, prompts, redirect_uri, redirect_fragment):
    # http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

    pass
