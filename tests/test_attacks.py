"""
Automated Security & Attack Detection Test Suite
Verifies resistance to:
1. Message Tampering (HMAC-SHA256 verification failure)
2. Replay Attacks (Message ID / Nonce deduplication)
3. Man-in-the-Middle Attacks (RSA Signature verification on DH Public Values)
4. Server Confidentiality / Zero Plaintext Leakage in SQLite
"""
import unittest
import uuid
import datetime
from crypto.dh import DiffieHellman
from crypto.kdf import derive_session_keys
from crypto.encryption import encrypt_message, decrypt_message
from crypto.integrity import calculate_hmac, verify_hmac
from crypto.signatures import generate_identity_keypair, sign_data, verify_signature
from database import init_db, record_and_verify_replay, get_db_connection, save_message

class TestAttackDefenses(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_01_tamper_detection_ciphertext(self):
        """Verify that altering 1 byte in the ciphertext fails HMAC verification."""
        aes_key = b"\x11" * 32
        hmac_key = b"\x22" * 32
        plaintext = "Transfer $1,000 to Charlie"

        c_hex, iv_hex = encrypt_message(plaintext, aes_key)
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        seq = 1
        tag = calculate_hmac(iv_hex, c_hex, ts, seq, hmac_key)

        # Confirm authentic packet passes
        self.assertTrue(verify_hmac(iv_hex, c_hex, ts, seq, tag, hmac_key))

        # Attacker flips a character in ciphertext
        tampered_c_hex = ("0" if c_hex[0] != "0" else "1") + c_hex[1:]
        self.assertFalse(verify_hmac(iv_hex, tampered_c_hex, ts, seq, tag, hmac_key))

    def test_02_tamper_detection_iv_and_metadata(self):
        """Verify that tampering with IV, timestamp, or sequence fails HMAC verification."""
        aes_key = b"\x11" * 32
        hmac_key = b"\x22" * 32
        plaintext = "Secure Status OK"

        c_hex, iv_hex = encrypt_message(plaintext, aes_key)
        ts = "2026-09-13T23:45:00"
        seq = 42
        tag = calculate_hmac(iv_hex, c_hex, ts, seq, hmac_key)

        # Altered IV
        tampered_iv = ("f" if iv_hex[0] != "f" else "e") + iv_hex[1:]
        self.assertFalse(verify_hmac(tampered_iv, c_hex, ts, seq, tag, hmac_key))

        # Altered Timestamp
        self.assertFalse(verify_hmac(iv_hex, c_hex, "2026-09-13T23:45:01", seq, tag, hmac_key))

        # Altered Sequence Number
        self.assertFalse(verify_hmac(iv_hex, c_hex, ts, seq + 1, tag, hmac_key))

    def test_03_replay_attack_detection(self):
        """Verify that replaying a message packet is caught and rejected."""
        msg_id = f"test-replay-{uuid.uuid4().hex}"
        seq = 99

        # First transmission: fresh
        is_replay_1 = record_and_verify_replay(msg_id, "alice", "bob", seq)
        self.assertFalse(is_replay_1, "First transmission must be accepted")

        # Second transmission with same message_id: replay attack!
        is_replay_2 = record_and_verify_replay(msg_id, "alice", "bob", seq)
        self.assertTrue(is_replay_2, "Duplicate transmission must be flagged as replay")

    def test_04_mitm_prevention_via_rsa_signatures(self):
        """Verify that an adversary attempting to substitute DH public keys is rejected."""
        alice_dh = DiffieHellman()
        eve_dh = DiffieHellman()

        alice_priv, alice_pub = generate_identity_keypair()
        eve_priv, eve_pub = generate_identity_keypair()

        # Alice signs her authentic public DH key
        alice_sig = sign_data(alice_dh.get_public_hex(), alice_priv)

        # Bob verifies genuine Alice packet -> PASSES
        self.assertTrue(verify_signature(alice_dh.get_public_hex(), alice_sig, alice_pub))

        # Eve substitutes Alice's public key with Eve's public key, keeping Alice's signature -> FAILS
        self.assertFalse(verify_signature(eve_dh.get_public_hex(), alice_sig, alice_pub))

        # Eve signs Eve's key with Eve's private key -> Bob checks against Alice's known public key -> FAILS
        eve_forged_sig = sign_data(eve_dh.get_public_hex(), eve_priv)
        self.assertFalse(verify_signature(eve_dh.get_public_hex(), eve_forged_sig, alice_pub))

    def test_05_server_zero_plaintext_leakage(self):
        """Assert that stored database records contain ONLY ciphertexts and metadata."""
        msg_id = f"test-leakage-{uuid.uuid4().hex}"
        plaintext = "TOP SECRET MILITARY INTELLIGENCE"
        key = b"\x99" * 32
        c_hex, iv_hex = encrypt_message(plaintext, key)
        tag = "dummy_hmac_tag"

        save_message(msg_id, "alice", "bob", c_hex, iv_hex, tag, "2026-09-13T23:50:00", 1)

        # Inspect database rows
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM messages WHERE message_id = ?", (msg_id,))
        row = dict(cursor.fetchone())
        conn.close()

        # Verify plaintext does NOT appear anywhere in the database row
        for field, value in row.items():
            self.assertNotIn(plaintext, str(value), f"Plaintext leaked in field '{field}'!")

if __name__ == "__main__":
    unittest.main()
