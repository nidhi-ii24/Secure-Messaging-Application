"""
Message Integrity and Authenticity: HMAC-SHA256
Implements Encrypt-then-MAC paradigm.
Computes a cryptographic authentication tag over IV, Ciphertext, Timestamp, and Sequence Number.
Detects any unauthorized modification or tampering during transmission.
"""
import hmac
import hashlib

def construct_canonical_data(iv_hex: str, ciphertext_hex: str, timestamp: str, seq_no: int) -> bytes:
    """
    Constructs a deterministic canonical byte sequence for HMAC calculation.
    Binding IV, Timestamp, and Sequence Number prevents IV manipulation and replay attacks.
    """
    canonical_str = f"{iv_hex}:{ciphertext_hex}:{timestamp}:{seq_no}"
    return canonical_str.encode('utf-8')

def calculate_hmac(iv_hex: str, ciphertext_hex: str, timestamp: str, seq_no: int, hmac_key: bytes) -> str:
    """
    Calculates HMAC-SHA256 over the canonical message representation.
    Returns: hexadecimal HMAC tag
    """
    if not isinstance(hmac_key, bytes) or len(hmac_key) != 32:
        raise ValueError("hmac_key must be 32 bytes (256 bits)")

    data_bytes = construct_canonical_data(iv_hex, ciphertext_hex, timestamp, seq_no)
    tag = hmac.new(hmac_key, data_bytes, hashlib.sha256).hexdigest()
    return tag

def verify_hmac(iv_hex: str, ciphertext_hex: str, timestamp: str, seq_no: int,
                received_hmac_hex: str, hmac_key: bytes) -> bool:
    """
    Verifies HMAC tag using constant-time comparison.
    Returns True if tag is authentic, False if tampered.
    """
    if not isinstance(hmac_key, bytes) or len(hmac_key) != 32:
        raise ValueError("hmac_key must be 32 bytes (256 bits)")

    expected_tag = calculate_hmac(iv_hex, ciphertext_hex, timestamp, seq_no, hmac_key)
    return hmac.compare_digest(expected_tag, received_hmac_hex)
