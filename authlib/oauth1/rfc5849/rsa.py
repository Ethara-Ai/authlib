from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from authlib.common.encoding import to_bytes


def sign_sha1(msg, rsa_private_key):
    pass


def verify_sha1(sig, msg, rsa_public_key):
    pass
