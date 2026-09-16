"""
Unit Tests for Cryptographic Modules
Validates mathematical correctness, key separation, confidentiality, integrity, and non-repudiation.
"""
import unittest
from crypto.auth import hash_password, verify_password
from crypto.dh import DiffieHellman
from crypto.kdf import derive_session_keys, get_key_fingerprint
from crypto.encryption import encrypt_message, decrypt_message
from crypto.integrity import calculate_hmac, verify_hmac
from crypto.signatures import generate_identity_keypair, sign_data, verify_signature

class TestCryptoSuite(unittest.TestCase):

    def test_01_password_hashing(self):
        """Verify PBKDF2 hashing with random salt and constant-time verification."""
        password = "SuperSecretPassword123!"
        hash_hex, salt_hex = hash_password(password)
        self.assertTrue(verify_password(password, hash_hex, salt_hex))
        self.assertFalse(verify_password("WrongPassword!", hash_hex, salt_hex))

    def test_02_diffie_hellman_exchange(self):
        """Verify Alice and Bob independently calculate identical shared secrets."""
        alice_dh = DiffieHellman()
        bob_dh = DiffieHellman()

        # Alice public -> Bob, Bob public -> Alice
        alice_shared = alice_dh.compute_shared_secret(bob_dh.get_public_hex())
        bob_shared = bob_dh.compute_shared_secret(alice_dh.get_public_hex())

        self.assertEqual(alice_shared, bob_shared)
        self.assertEqual(len(alice_shared), 256) # 2048-bit key = 256 bytes

    def test_03_hkdf_key_derivation(self):
        """Verify HKDF produces two distinct, cryptographically strong 256-bit keys."""
        alice_dh = DiffieHellman()
        bob_dh = DiffieHellman()
        shared_secret = alice_dh.compute_shared_secret(bob_dh.get_public_hex())

        aes_key, hmac_key = derive_session_keys(shared_secret)

        self.assertEqual(len(aes_key), 32)
        self.assertEqual(len(hmac_key), 32)
        self.assertNotEqual(aes_key, hmac_key) # Keys must be distinct!

        # Fingerprint test
        fp_aes = get_key_fingerprint(aes_key)
        fp_hmac = get_key_fingerprint(hmac_key)
        self.assertEqual(len(fp_aes), 16)
        self.assertNotEqual(fp_aes, fp_hmac)

    def test_04_aes_encryption_decryption(self):
        """Verify AES-256-CBC encrypt/decrypt round-trip with arbitrary text."""
        key = b"\x01" * 32
        secret_message = "Meet me at 5 PM. Bring the confidential documents!"

        ciphertext_hex, iv_hex = encrypt_message(secret_message, key)
        self.assertNotEqual(ciphertext_hex, secret_message)

        decrypted = decrypt_message(ciphertext_hex, iv_hex, key)
        self.assertEqual(decrypted, secret_message)

    def test_05_hmac_integrity_and_tampering(self):
        """Verify HMAC detects even a single bit modification."""
        key = b"\x02" * 32
        iv_hex = "00" * 16
        ciphertext_hex = "aabbccddeeff"
        timestamp = "2026-09-13T23:30:00"
        seq_no = 1

        tag = calculate_hmac(iv_hex, ciphertext_hex, timestamp, seq_no, key)
        self.assertTrue(verify_hmac(iv_hex, ciphertext_hex, timestamp, seq_no, tag, key))

        # Tampering: modify 1 character in ciphertext
        tampered_ciphertext = "fabccddeeff"
        self.assertFalse(verify_hmac(iv_hex, tampered_ciphertext, timestamp, seq_no, tag, key))

        # Tampering: modify sequence number
        self.assertFalse(verify_hmac(iv_hex, ciphertext_hex, timestamp, seq_no + 1, tag, key))

    def test_06_digital_signatures(self):
        """Verify RSA-2048 PSS signing, verification, and rejection of forgery."""
        priv_pem, pub_pem = generate_identity_keypair()
        data = "DH_PUBLIC_VALUE_A_HEX_1234567890"

        signature = sign_data(data, priv_pem)
        self.assertTrue(verify_signature(data, signature, pub_pem))

        # Forged data
        self.assertFalse(verify_signature(data + "_forged", signature, pub_pem))

        # Wrong key
        other_priv, other_pub = generate_identity_keypair()
        self.assertFalse(verify_signature(data, signature, other_pub))

if __name__ == "__main__":
    unittest.main()
