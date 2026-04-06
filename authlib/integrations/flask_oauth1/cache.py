from authlib.oauth1 import TemporaryCredential


def register_temporary_credential_hooks(
    authorization_server, cache, key_prefix="temporary_credential:"
):
    """Register temporary credential related hooks to authorization server.

    :param authorization_server: AuthorizationServer instance
    :param cache: Cache instance
    :param key_prefix: key prefix for temporary credential
    """
    pass


def create_exists_nonce_func(cache, key_prefix="nonce:", expires=86400):
    """Create an ``exists_nonce`` function that can be used in hooks and
    resource protector.

    :param cache: Cache instance
    :param key_prefix: key prefix for temporary credential
    :param expires: Expire time for nonce
    """
    pass


def register_nonce_hooks(
    authorization_server, cache, key_prefix="nonce:", expires=86400
):
    """Register nonce related hooks to authorization server.

    :param authorization_server: AuthorizationServer instance
    :param cache: Cache instance
    :param key_prefix: key prefix for temporary credential
    :param expires: Expire time for nonce
    """
    pass
