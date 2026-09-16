"""
Authentication Cryptography: Password Hashing & Verification
Implements PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salt.
Protects credentials against dictionary attacks, rainbow tables, and database leaks.
"""
import os
import hashlib
import hmac

PBKDF2_ITERATIONS = 100_000
SALT_SIZE_BYTES = 16
HASH_KEY_LENGTH = 32 # 256 bits

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """
    Hashes a plaintext password using PBKDF2-HMAC-SHA256.
    Returns: (password_hash_hex, salt_hex)
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    if salt is None:
        salt = os.urandom(SALT_SIZE_BYTES)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)

    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=HASH_KEY_LENGTH
    )
    return derived_key.hex(), salt.hex()

def verify_password(password: str, stored_hash_hex: str, stored_salt_hex: str) -> bool:
    """
    Verifies a password against the stored hash and salt using constant-time comparison.
    """
    salt = bytes.fromhex(stored_salt_hex)
    calculated_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=HASH_KEY_LENGTH
    ).hex()
    # Constant-time comparison prevents timing side-channel attacks
    return hmac.compare_digest(calculated_hash, stored_hash_hex)
