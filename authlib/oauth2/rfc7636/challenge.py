import hashlib
import re

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64encode

from ..rfc6749 import InvalidGrantError
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import OAuth2Request

CODE_VERIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9\-._~]{43,128}$")
CODE_CHALLENGE_PATTERN = re.compile(r"^[a-zA-Z0-9\-._~]{43,128}$")


def create_s256_code_challenge(code_verifier):
    """Create S256 code_challenge with the given code_verifier."""
    pass


def compare_plain_code_challenge(code_verifier, code_challenge):
    # If the "code_challenge_method" from Section 4.3 was "plain",
    # they are compared directly
    pass


def compare_s256_code_challenge(code_verifier, code_challenge):
    # BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
    pass


class CodeChallenge:
    """CodeChallenge extension to Authorization Code Grant. It is used to
    improve the security of Authorization Code flow for public clients by
    sending extra "code_challenge" and "code_verifier" to the authorization
    server.

    The AuthorizationCodeGrant SHOULD save the ``code_challenge`` and
    ``code_challenge_method`` into database when ``save_authorization_code``.
    Then register this extension via::

        server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    """

    #: defaults to "plain" if not present in the request
    DEFAULT_CODE_CHALLENGE_METHOD = "plain"
    #: supported ``code_challenge_method``
    SUPPORTED_CODE_CHALLENGE_METHOD = ["plain", "S256"]

    CODE_CHALLENGE_METHODS = {
        "plain": compare_plain_code_challenge,
        "S256": compare_s256_code_challenge,
    }

    def __init__(self, required=True):
        self.required = required

    def __call__(self, grant):
        grant.register_hook(
            "after_validate_authorization_request_payload",
            self.validate_code_challenge,
        )
        grant.register_hook(
            "after_validate_token_request",
            self.validate_code_verifier,
        )

    def validate_code_challenge(self, grant, redirect_uri):
        pass

    def validate_code_verifier(self, grant, result):
        pass

    def get_authorization_code_challenge(self, authorization_code):
        """Get "code_challenge" associated with this authorization code.
        Developers MAY re-implement it in subclass, the default logic::

            def get_authorization_code_challenge(self, authorization_code):
                return authorization_code.code_challenge

        :param authorization_code: the instance of authorization_code
        """
        pass

    def get_authorization_code_challenge_method(self, authorization_code):
        """Get "code_challenge_method" associated with this authorization code.
        Developers MAY re-implement it in subclass, the default logic::

            def get_authorization_code_challenge_method(self, authorization_code):
                return authorization_code.code_challenge_method

        :param authorization_code: the instance of authorization_code
        """
        pass
