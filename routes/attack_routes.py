"""
Attack Simulation & Educational Demonstrations
Provides dedicated endpoints demonstrating the 4 core attacks:
1. Eavesdropping & Interception
2. Message Tampering (Integrity violation)
3. Replay Attack (Anti-replay violation)
4. Man-in-the-Middle (Unauthenticated DH vs Authenticated DH)
"""
import uuid
import datetime
from flask import Blueprint, request, jsonify
from crypto.dh import DiffieHellman
from crypto.kdf import derive_session_keys
from crypto.encryption import encrypt_message, decrypt_message
from crypto.integrity import calculate_hmac, verify_hmac
from crypto.signatures import generate_identity_keypair, sign_data, verify_signature

attack_bp = Blueprint('attacks', __name__)

@attack_bp.route('/api/attacks/eavesdrop', methods=['POST'])
def demo_eavesdrop():
    """
    Demonstrates Plaintext Interception vs E2EE Interception.
    """
    data = request.get_json() or {}
    message = data.get('message', 'Confidential financial transaction: Transfer $5,000 to Account #84920')

    # Simulate symmetric key
    key = b"\x42" * 32
    c_hex, iv_hex = encrypt_message(message, key)

    return jsonify({
        "insecure_http_sniff": {
            "protocol": "Plain HTTP (No E2EE)",
            "packet_payload": f"POST /send HTTP/1.1\\r\\nHost: server.com\\r\\n\\r\\nmessage={message}",
            "plaintext_exposed": True,
            "vulnerability": "Packet sniffing via Wireshark exposes confidential plaintext immediately."
        },
        "secure_e2ee_tls_sniff": {
            "protocol": "TLS 1.3 + Application-Layer AES-256-CBC",
            "packet_payload": f"{{\\\"ciphertext\\\": \\\"{c_hex[:32]}...\\\", \\\"iv\\\": \\\"{iv_hex}\\\"}}",
            "plaintext_exposed": False,
            "protection": "Intermediary and network sniffers only observe cryptographic ciphertext. Zero plaintext leakage."
        }
    }), 200

@attack_bp.route('/api/attacks/tamper', methods=['POST'])
def demo_tamper():
    """
    Demonstrates tampering with ciphertext and how HMAC-SHA256 catches it.
    """
    data = request.get_json() or {}
    plaintext = data.get('message', 'Authorize payment of $100 to Vendor')

    key = b"\x77" * 32
    hmac_key = b"\x88" * 32

    # 1. Honest encryption & HMAC
    c_hex, iv_hex = encrypt_message(plaintext, key)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    seq_no = 1
    valid_tag = calculate_hmac(iv_hex, c_hex, ts, seq_no, hmac_key)

    # 2. Malicious Tampering: Flip first hex character
    tampered_c_hex = ('1' if c_hex[0] != '1' else '2') + c_hex[1:]

    # 3. Recipient Verification
    is_valid_original = verify_hmac(iv_hex, c_hex, ts, seq_no, valid_tag, hmac_key)
    is_valid_tampered = verify_hmac(iv_hex, tampered_c_hex, ts, seq_no, valid_tag, hmac_key)

    tampered_decryption_error = None
    decrypted_tampered_text = None
    if not is_valid_tampered:
        # System halts here, but for demo we show what raw AES decrypting tampered data would yield
        try:
            decrypted_tampered_text = decrypt_message(tampered_c_hex, iv_hex, key)
        except Exception as e:
            tampered_decryption_error = f"AES Decryption/Padding Error: {str(e)}"

    return jsonify({
        "plaintext": plaintext,
        "authentic_packet": {
            "ciphertext": c_hex,
            "iv": iv_hex,
            "hmac_tag": valid_tag,
            "hmac_verified": is_valid_original
        },
        "tampered_packet": {
            "original_byte": c_hex[:4],
            "modified_byte": tampered_c_hex[:4],
            "tampered_ciphertext": tampered_c_hex,
            "expected_tag_for_tampered": calculate_hmac(iv_hex, tampered_c_hex, ts, seq_no, hmac_key),
            "received_tag": valid_tag,
            "hmac_verified": is_valid_tampered
        },
        "verdict": "REJECTED" if not is_valid_tampered else "ACCEPTED",
        "action": "Message safely dropped before decryption because HMAC tag did not match.",
        "tampered_decryption_result": decrypted_tampered_text,
        "tampered_decryption_error": tampered_decryption_error
    }), 200

@attack_bp.route('/api/attacks/replay', methods=['POST'])
def demo_replay():
    """
    Demonstrates Replay Attack detection.
    """
    data = request.get_json() or {}
    message_id = data.get('message_id', f"msg-{uuid.uuid4().hex[:8]}")
    seq_no = data.get('seq_no', 104)

    # First attempt: Fresh packet
    from database import record_and_verify_replay
    first_attempt_replayed = record_and_verify_replay(message_id, "alice", "bob", seq_no)

    # Second attempt: Same packet replayed by adversary
    second_attempt_replayed = record_and_verify_replay(message_id, "alice", "bob", seq_no)

    return jsonify({
        "message_id": message_id,
        "seq_no": seq_no,
        "first_transmission": {
            "status": "ACCEPTED",
            "is_replay": first_attempt_replayed,
            "result": "Message processed and displayed to recipient."
        },
        "second_transmission (adversary replay)": {
            "status": "REJECTED",
            "is_replay": second_attempt_replayed,
            "result": "Security alert: Replay detected! Duplicate message ID rejected."
        }
    }), 200

@attack_bp.route('/api/attacks/mitm', methods=['POST'])
def demo_mitm():
    """
    Demonstrates Man-in-the-Middle Attack on Diffie-Hellman:
    1. Unauthenticated DH: Eve intercepts and impersonates both parties.
    2. Authenticated DH with RSA Signatures: Eve cannot forge the signature.
    """
    # Honest parties
    alice_dh = DiffieHellman()
    bob_dh = DiffieHellman()

    # Adversary (Eve)
    eve_dh_alice = DiffieHellman()
    eve_dh_bob = DiffieHellman()

    # Scenario 1: Unauthenticated DH
    # Alice sends A -> Eve intercepts -> Eve sends E_A to Bob
    # Bob sends B -> Eve intercepts -> Eve sends E_B to Alice
    alice_secret_with_eve = alice_dh.compute_shared_secret(eve_dh_alice.get_public_hex())
    eve_secret_with_alice = eve_dh_alice.compute_shared_secret(alice_dh.get_public_hex())

    bob_secret_with_eve = bob_dh.compute_shared_secret(eve_dh_bob.get_public_hex())
    eve_secret_with_bob = eve_dh_bob.compute_shared_secret(bob_dh.get_public_hex())

    unauthenticated_mitm_success = (alice_secret_with_eve == eve_secret_with_alice) and (bob_secret_with_eve == eve_secret_with_bob)

    # Scenario 2: Authenticated DH with RSA Digital Signatures
    alice_priv, alice_pub = generate_identity_keypair()
    # Alice signs her public value A
    alice_signature = sign_data(alice_dh.get_public_hex(), alice_priv)

    # Eve tries to replace A with Eve's own public key E_A
    eve_tampered_public = eve_dh_alice.get_public_hex()

    # Bob verifies Alice's signature against the received public key
    # Test A: Genuine packet from Alice
    genuine_check = verify_signature(alice_dh.get_public_hex(), alice_signature, alice_pub)

    # Test B: Eve's substituted key with Alice's signature
    mitm_attack_check = verify_signature(eve_tampered_public, alice_signature, alice_pub)

    return jsonify({
        "unauthenticated_dh": {
            "vulnerability": "Alice and Bob establish keys with Eve without knowing it.",
            "mitm_achieved": unauthenticated_mitm_success,
            "explanation": "Diffie-Hellman alone provides secrecy against passive eavesdroppers, but NOT authentication against active attackers."
        },
        "authenticated_dh_with_rsa_signatures": {
            "genuine_packet_verified": genuine_check,
            "eve_tampered_packet_verified": mitm_attack_check,
            "mitm_prevented": not mitm_attack_check,
            "explanation": "Eve cannot forge Alice's RSA digital signature on the DH public value without Alice's private key. MITM fails!"
        }
    }), 200
