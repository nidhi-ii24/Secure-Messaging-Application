"""
Symmetric Confidentiality Engine: AES-256-CBC with PKCS#7 Padding
Provides end-to-end confidentiality. Each message is encrypted with a fresh random 16-byte IV.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

AES_BLOCK_SIZE_BITS = 128
IV_SIZE_BYTES = 16

def encrypt_message(plaintext: str, aes_key: bytes, iv: bytes = None) -> tuple[str, str]:
    """
    Encrypts a plaintext string using AES-256 in CBC mode with PKCS#7 padding.
    Returns: (ciphertext_hex, iv_hex)
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    if not isinstance(aes_key, bytes) or len(aes_key) != 32:
        raise ValueError("aes_key must be 32 bytes (256 bits)")

    if iv is None:
        iv = os.urandom(IV_SIZE_BYTES)
    elif len(iv) != IV_SIZE_BYTES:
        raise ValueError(f"IV must be exactly {IV_SIZE_BYTES} bytes")

    # 1. Apply PKCS#7 Padding
    padder = padding.PKCS7(AES_BLOCK_SIZE_BITS).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # 2. AES-256-CBC Encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext.hex(), iv.hex()

def decrypt_message(ciphertext_hex: str, iv_hex: str, aes_key: bytes) -> str:
    """
    Decrypts an AES-256-CBC ciphertext and removes PKCS#7 padding.
    Returns: plaintext string
    """
    if not isinstance(aes_key, bytes) or len(aes_key) != 32:
        raise ValueError("aes_key must be 32 bytes (256 bits)")

    ciphertext = bytes.fromhex(ciphertext_hex)
    iv = bytes.fromhex(iv_hex)

    if len(iv) != IV_SIZE_BYTES:
        raise ValueError(f"Invalid IV length: expected {IV_SIZE_BYTES} bytes")

    # 1. AES-256-CBC Decryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # 2. Remove PKCS#7 Padding
    unpadder = padding.PKCS7(AES_BLOCK_SIZE_BITS).unpadder()
    plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext_bytes.decode('utf-8')
