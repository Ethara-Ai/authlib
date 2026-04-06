import functools
from contextlib import contextmanager

from flask import g
from flask import json
from flask import request as _req
from werkzeug.local import LocalProxy

from authlib.oauth2 import OAuth2Error
from authlib.oauth2 import ResourceProtector as _ResourceProtector
from authlib.oauth2.rfc6749 import MissingAuthorizationError

from .errors import raise_http_exception
from .requests import FlaskJsonRequest
from .signals import token_authenticated


class ResourceProtector(_ResourceProtector):
    """A protecting method for resource servers. Creating a ``require_oauth``
    decorator easily with ResourceProtector::

        from authlib.integrations.flask_oauth2 import ResourceProtector

        require_oauth = ResourceProtector()

        # add bearer token validator
        from authlib.oauth2.rfc6750 import BearerTokenValidator
        from project.models import Token


        class MyBearerTokenValidator(BearerTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()


        require_oauth.register_token_validator(MyBearerTokenValidator())

        # protect resource with require_oauth


        @app.route("/user")
        @require_oauth(["profile"])
        def user_profile():
            user = User.get(current_token.user_id)
            return jsonify(user.to_dict())

    """

    def raise_error_response(self, error):
        """Raise HTTPException for OAuth2Error. Developers can re-implement
        this method to customize the error response.

        :param error: OAuth2Error
        :raise: HTTPException
        """
        pass

    def acquire_token(self, scopes=None, **kwargs):
        """A method to acquire current valid token with the given scope.

        :param scopes: a list of scope values
        :return: token object
        """
        pass

    @contextmanager
    def acquire(self, scopes=None):
        """The with statement of ``require_oauth``. Instead of using a
        decorator, you can use a with statement instead::

            @app.route("/api/user")
            def user_api():
                with require_oauth.acquire("profile") as token:
                    user = User.get(token.user_id)
                    return jsonify(user.to_dict())
        """
        pass

    def __call__(self, scopes=None, optional=False, **kwargs):
        claims = kwargs
        claims["scopes"] = scopes if not callable(scopes) else None

        def decorator(f):
            @functools.wraps(f)
            pass

        if callable(scopes):
            return decorator(scopes)
        return decorator


def _get_current_token():
    pass


current_token = LocalProxy(_get_current_token)
