"""
Key Derivation Function (HKDF-SHA256, RFC 5869)
Transforms the raw Diffie-Hellman shared secret into cryptographically independent
symmetric keys: one for AES encryption and one for HMAC integrity.
"""
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

AES_KEY_INFO = b"cns-secure-messaging-aes-key-v1"
HMAC_KEY_INFO = b"cns-secure-messaging-hmac-key-v1"
KEY_LENGTH = 32 # 256 bits

def derive_session_keys(shared_secret: bytes, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derives (aes_key, hmac_key) from the raw DH shared secret.
    Salt is optional; if None, HKDF uses a block of zeros per RFC 5869.
    """
    if not isinstance(shared_secret, bytes):
        raise TypeError("shared_secret must be bytes")

    # 1. Derive AES-256 Key
    hkdf_aes = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        info=AES_KEY_INFO,
    )
    aes_key = hkdf_aes.derive(shared_secret)

    # 2. Derive HMAC-SHA256 Key
    hkdf_hmac = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        info=HMAC_KEY_INFO,
    )
    hmac_key = hkdf_hmac.derive(shared_secret)

    return aes_key, hmac_key

def get_key_fingerprint(key: bytes) -> str:
    """Returns a short SHA-256 fingerprint of a key for visual confirmation in UI."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key)
    return digest.finalize().hex()[:16]
