"""
Interactive Attack Demonstration Engine (Terminal Runner)
Simulates and explains the 4 core attacks for CNS Course viva & lab evaluation:
1. Eavesdropping / Packet Sniffing (HTTP vs TLS + E2EE)
2. Message Tampering & Bit Flipping (Caught by HMAC-SHA256)
3. Replay Attack (Prevented by Sequence Nonces & Timestamps)
4. Man-in-the-Middle Attack on Diffie-Hellman (Defeated by RSA Signatures)
"""
import sys
import uuid
import datetime
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from crypto.dh import DiffieHellman
from crypto.kdf import derive_session_keys, get_key_fingerprint
from crypto.encryption import encrypt_message, decrypt_message
from crypto.integrity import calculate_hmac, verify_hmac
from crypto.signatures import generate_identity_keypair, sign_data, verify_signature
from database import init_db, record_and_verify_replay

def print_banner(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def demo_1_eavesdropping():
    print_banner("ATTACK 1: EAVESDROPPING / PACKET INTERCEPTION")
    secret_text = "Transfer $10,000 from Alice to Bob (Confidential)"
    print(f"[*] Original Message: '{secret_text}'\n")

    # Insecure Plaintext HTTP Simulation
    print("[-] SCENARIO A: Insecure Plain HTTP (No E2EE)")
    insecure_packet = f"POST /messages/send HTTP/1.1\\r\\nHost: server.local\\r\\n\\r\\nmessage={secret_text}"
    print(f"    Network Sniffer (Wireshark) observes:")
    print(f"    >>> {insecure_packet}")
    print("    [!] VULNERABILITY: Plaintext exposed to anyone on the local network or ISP.\n")

    # Secure TLS + E2EE Simulation
    print("[+] SCENARIO B: TLS 1.3 Transport + AES-256-CBC E2EE (Our System)")
    session_key = b"\x55" * 32
    c_hex, iv_hex = encrypt_message(secret_text, session_key)
    secure_packet = f'{{"ciphertext": "{c_hex}", "iv": "{iv_hex}"}}'
    print(f"    Network Sniffer observes only encrypted TLS frame:")
    print(f"    >>> TLS Application Data: {secure_packet[:65]}... (hex)")
    print("    [PASS] PROTECTION: Zero plaintext leakage. Confidentiality guaranteed!")

def demo_2_message_tampering():
    print_banner("ATTACK 2: MESSAGE TAMPERING & BIT-FLIPPING (INTEGRITY TEST)")
    plaintext = "Pay $100 to Vendor"
    aes_key = b"\x33" * 32
    hmac_key = b"\x44" * 32

    # 1. Encrypt and Tag
    c_hex, iv_hex = encrypt_message(plaintext, aes_key)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    seq_no = 1
    authentic_tag = calculate_hmac(iv_hex, c_hex, ts, seq_no, hmac_key)

    print(f"[*] Sender creates message: '{plaintext}'")
    print(f"    Ciphertext: {c_hex}")
    print(f"    HMAC-SHA256 Tag: {authentic_tag}")

    # 2. Adversary Alters Ciphertext in Transit
    tampered_c_hex = ('1' if c_hex[0] != '1' else '2') + c_hex[1:]
    print(f"\n[!] Attacker intercepts and flips first character in ciphertext:")
    print(f"    Original: {c_hex[:16]}...")
    print(f"    Tampered: {tampered_c_hex[:16]}...")

    # 3. Recipient Verifies HMAC
    print("\n[*] Recipient verifies received packet before decrypting...")
    is_valid = verify_hmac(iv_hex, tampered_c_hex, ts, seq_no, authentic_tag, hmac_key)

    if not is_valid:
        print("    [BLOCKED] INTEGRITY CHECK FAILED!")
        print("    [!] Action: HMAC-SHA256 mismatch detected. Message safely discarded.")
        print("    [PASS] RESULT: Tampered data is NEVER passed to AES decryption.")
    else:
        print("    [FAIL] Vulnerability: Tamper was not detected.")

def demo_3_replay_attack():
    print_banner("ATTACK 3: REPLAY ATTACK (ANTI-REPLAY TEST)")
    init_db()
    msg_id = f"tx-{uuid.uuid4().hex[:8]}"
    seq_no = 205

    print(f"[*] Captured Legitimate Packet: MessageID = {msg_id}, Sequence = #{seq_no}")

    # Transmission 1
    first_attempt_replayed = record_and_verify_replay(msg_id, "alice", "bob", seq_no)
    print("\n[1] Alice transmits packet to Bob for the first time:")
    if not first_attempt_replayed:
        print("    [PASS] Server Status: ACCEPTED (Fresh message)")
        print("    [PASS] Recipient: Processed and displayed successfully.")
    else:
        print("    [FAIL] Error in first attempt.")

    # Transmission 2 (Adversary replays same packet)
    second_attempt_replayed = record_and_verify_replay(msg_id, "alice", "bob", seq_no)
    print("\n[2] Adversary re-sends captured packet across network:")
    if second_attempt_replayed:
        print("    [BLOCKED] Server Status: REPLAY_ATTACK_DETECTED (HTTP 409 Conflict)")
        print(f"    [!] Alert: Duplicate message ID '{msg_id}' already consumed.")
        print("    [PASS] DEFENSE: Replay attack thwarted by sequence & nonce tracking!")
    else:
        print("    [FAIL] Vulnerability: Replay was accepted.")

def demo_4_mitm_attack():
    print_banner("ATTACK 4: MAN-IN-THE-MIDDLE ATTACK ON DIFFIE-HELLMAN")

    # Honest parties
    alice = DiffieHellman()
    bob = DiffieHellman()

    # Adversary (Eve)
    eve_alice = DiffieHellman()
    eve_bob = DiffieHellman()

    print("[-] SCENARIO A: Unauthenticated Diffie-Hellman")
    print("    Alice sends Public A -> Eve intercepts -> Eve sends E_A to Bob")
    print("    Bob sends Public B   -> Eve intercepts -> Eve sends E_B to Alice")
    alice_s = alice.compute_shared_secret(eve_alice.get_public_hex())
    eve_alice_s = eve_alice.compute_shared_secret(alice.get_public_hex())
    bob_s = bob.compute_shared_secret(eve_bob.get_public_hex())
    eve_bob_s = eve_bob.compute_shared_secret(bob.get_public_hex())

    print(f"    Shared Secret (Alice-Eve): {get_key_fingerprint(alice_s)}")
    print(f"    Shared Secret (Bob-Eve):   {get_key_fingerprint(bob_s)}")
    print("    [!] VULNERABILITY: Eve can decrypt Alice's message, read it, and re-encrypt for Bob!\n")

    print("[+] SCENARIO B: Authenticated DH with RSA Digital Signatures (Our System)")
    alice_priv, alice_pub = generate_identity_keypair()
    # Alice signs her public DH key A
    alice_sig = sign_data(alice.get_public_hex(), alice_priv)
    print("    Alice signs Public A with her RSA-2048 private key.")

    # Eve tries to replace A with Eve's key E_A but cannot forge Alice's signature
    eve_substituted_key = eve_alice.get_public_hex()
    print("    Eve substitutes Public A with Eve's public key...")

    # Bob verifies Alice's signature
    bob_checks_eve_packet = verify_signature(eve_substituted_key, alice_sig, alice_pub)
    if not bob_checks_eve_packet:
        print("    [BLOCKED] Bob rejects Eve's substituted key: RSA Signature Verification Failed!")
        print("    [PASS] DEFENSE: MITM impossible without Alice's private signing key.")

def run_all():
    print("\n======================================================================")
    print("     CNS PROJECT: HYBRID CRYPTOGRAPHY & SECURITY DEMONSTRATION")
    print("======================================================================")
    demo_1_eavesdropping()
    demo_2_message_tampering()
    demo_3_replay_attack()
    demo_4_mitm_attack()
    print("\n======================================================================")
    print("     ALL 4 ATTACK SCENARIOS EVALUATED SUCCESSFULLY!")
    print("======================================================================\n")

if __name__ == "__main__":
    run_all()
