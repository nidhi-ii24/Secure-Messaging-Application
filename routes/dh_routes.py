"""
Diffie-Hellman Key Exchange Coordination Routes
Facilitates the exchange of public parameters (p, g, A, B) and RSA signatures.
The server acts purely as a public directory and message board;
it NEVER learns private keys (a, b) or the resulting shared secret.
"""
import uuid
from flask import Blueprint, request, jsonify, session
from database import (
    create_dh_session,
    update_dh_session_bob,
    get_dh_session,
    get_active_dh_session,
    get_latest_pending_session_for,
    get_user_by_username
)
from crypto.dh import DiffieHellman, RFC_3526_2048_PRIME, RFC_3526_GENERATOR
from crypto.kdf import derive_session_keys, get_key_fingerprint
from crypto.signatures import sign_data, verify_signature
from crypto.encryption import encrypt_message, decrypt_message
from crypto.integrity import calculate_hmac, verify_hmac

dh_bp = Blueprint('dh', __name__)

@dh_bp.route('/api/dh/initiate', methods=['POST'])
def initiate_session():
    current_user = request.headers.get('X-Sim-User') or session.get('username')
    if not current_user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    peer = (data.get('peer') or '').strip().lower()
    pub_a = data.get('pub_a')
    sig_a = data.get('sig_a')
    p_hex = data.get('p_hex')
    g = data.get('g', 2)

    if not peer or not pub_a:
        return jsonify({"success": False, "error": "Peer and Public Key A are required"}), 400

    peer_user = get_user_by_username(peer)
    if not peer_user:
        return jsonify({"success": False, "error": "Peer user not found"}), 404

    session_id = uuid.uuid4().hex[:12]

    # Verify Alice's signature on A if provided (defense against MITM)
    sig_valid = False
    sender_user = get_user_by_username(current_user)
    if sig_a and sender_user and sender_user.get('public_identity_key'):
        sig_valid = verify_signature(pub_a, sig_a, sender_user['public_identity_key'])

    create_dh_session(
        session_id=session_id,
        user1=current_user,
        user2=peer,
        dh_p=p_hex,
        dh_g=g,
        pub_a=pub_a,
        sig_a=sig_a
    )

    return jsonify({
        "success": True,
        "session_id": session_id,
        "status": "pending",
        "signature_valid": sig_valid,
        "message": f"DH Key Exchange initiated by {current_user} with {peer}."
    }), 201

@dh_bp.route('/api/dh/respond', methods=['POST'])
def respond_session():
    current_user = request.headers.get('X-Sim-User') or session.get('username')
    if not current_user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    session_id = data.get('session_id')
    pub_b = data.get('pub_b')
    sig_b = data.get('sig_b')

    if not session_id or not pub_b:
        return jsonify({"success": False, "error": "session_id and pub_b are required"}), 400

    dh_sess = get_dh_session(session_id)
    if not dh_sess:
        return jsonify({"success": False, "error": "Session not found"}), 404

    if dh_sess['user2'] != current_user:
        return jsonify({"success": False, "error": "You are not the designated recipient for this DH handshake"}), 403

    # Verify Bob's signature on B if provided
    sig_valid = False
    responder_user = get_user_by_username(current_user)
    if sig_b and responder_user and responder_user.get('public_identity_key'):
        sig_valid = verify_signature(pub_b, sig_b, responder_user['public_identity_key'])

    update_dh_session_bob(session_id, pub_b, sig_b)

    return jsonify({
        "success": True,
        "session_id": session_id,
        "status": "established",
        "signature_valid": sig_valid,
        "message": "DH handshake completed. Symmetric keys can now be derived."
    }), 200

@dh_bp.route('/api/dh/session/<session_id>', methods=['GET'])
def get_session_info(session_id):
    dh_sess = get_dh_session(session_id)
    if not dh_sess:
        return jsonify({"success": False, "error": "Session not found"}), 404
    return jsonify({"success": True, "session": dict(dh_sess)}), 200

@dh_bp.route('/api/dh/pending', methods=['GET'])
def check_pending():
    current_user = request.headers.get('X-Sim-User') or session.get('username')
    if not current_user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    pending = get_latest_pending_session_for(current_user)
    if pending:
        return jsonify({"has_pending": True, "session": dict(pending)}), 200
    return jsonify({"has_pending": False}), 200

@dh_bp.route('/api/dh/active/<peer>', methods=['GET'])
def check_active(peer):
    current_user = request.headers.get('X-Sim-User') or session.get('username')
    if not current_user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    active = get_active_dh_session(current_user, peer.strip().lower())
    if active:
        return jsonify({"has_active": True, "session": dict(active)}), 200
    return jsonify({"has_active": False}), 200

@dh_bp.route('/api/dh/reset', methods=['POST'])
def reset_session():
    current_user = request.headers.get('X-Sim-User') or session.get('username')
    data = request.get_json() or {}
    peer = (data.get('peer') or '').strip().lower()
    from database import clear_messages_and_sessions
    clear_messages_and_sessions(current_user, peer if peer else None)
    return jsonify({"success": True, "message": "Session reset successfully"}), 200

# ----------------- Educational Client-Side Crypto Helper -----------------
# This endpoint models the cryptographic computation done on a client's device,
# providing verifiable mathematical output for browser clients & automated test harnesses.
@dh_bp.route('/api/dh/client/keygen', methods=['POST'])
def client_keygen():
    dh = DiffieHellman()
    params = dh.get_parameters_dict()
    return jsonify({
        "p_hex": params["p_hex"],
        "g": params["g"],
        "private_hex": dh.get_private_hex(),
        "public_hex": params["public_key_hex"],
        "bit_length": params["bit_length"]
    }), 200

@dh_bp.route('/api/dh/client/compute', methods=['POST'])
def client_compute():
    data = request.get_json() or {}
    private_hex = data.get('private_hex')
    peer_public_hex = data.get('peer_public_hex')
    p_hex = data.get('p_hex')

    if not private_hex or not peer_public_hex:
        return jsonify({"error": "private_hex and peer_public_hex are required"}), 400

    p = int(p_hex, 16) if p_hex else RFC_3526_2048_PRIME
    private_int = int(private_hex, 16)
    peer_public_int = int(peer_public_hex, 16)

    # Compute S = (peer_pub)^my_priv mod p
    shared_int = pow(peer_public_int, private_int, p)
    byte_len = (p.bit_length() + 7) // 8
    shared_bytes = shared_int.to_bytes(byte_len, byteorder="big")

    # HKDF Derivation
    aes_key, hmac_key = derive_session_keys(shared_bytes)

    return jsonify({
        "shared_secret_hex": shared_bytes.hex(),
        "shared_secret_fingerprint": get_key_fingerprint(shared_bytes),
        "aes_key_hex": aes_key.hex(),
        "aes_key_fingerprint": get_key_fingerprint(aes_key),
        "hmac_key_hex": hmac_key.hex(),
        "hmac_key_fingerprint": get_key_fingerprint(hmac_key)
    }), 200

@dh_bp.route('/api/client/encrypt', methods=['POST'])
def client_encrypt():
    data = request.get_json() or {}
    plaintext = data.get('plaintext', '')
    aes_key_hex = data.get('aes_key_hex')
    hmac_key_hex = data.get('hmac_key_hex')
    timestamp = data.get('timestamp')
    seq_no = data.get('seq_no', 1)

    if not aes_key_hex or not hmac_key_hex:
        return jsonify({"error": "aes_key_hex and hmac_key_hex are required"}), 400

    aes_key = bytes.fromhex(aes_key_hex)
    hmac_key = bytes.fromhex(hmac_key_hex)

    # 1. AES-256-CBC Encryption
    ciphertext_hex, iv_hex = encrypt_message(plaintext, aes_key)

    # 2. Encrypt-then-MAC (HMAC-SHA256)
    hmac_tag = calculate_hmac(iv_hex, ciphertext_hex, timestamp, seq_no, hmac_key)

    return jsonify({
        "ciphertext_hex": ciphertext_hex,
        "iv_hex": iv_hex,
        "hmac_tag": hmac_tag
    }), 200

@dh_bp.route('/api/client/decrypt', methods=['POST'])
def client_decrypt():
    data = request.get_json() or {}
    ciphertext_hex = data.get('ciphertext_hex')
    iv_hex = data.get('iv_hex')
    hmac_tag = data.get('hmac_tag')
    timestamp = data.get('timestamp')
    seq_no = data.get('seq_no', 1)
    aes_key_hex = data.get('aes_key_hex')
    hmac_key_hex = data.get('hmac_key_hex')

    if not aes_key_hex or not hmac_key_hex or not ciphertext_hex or not iv_hex:
        return jsonify({"error": "Missing decryption parameters"}), 400

    aes_key = bytes.fromhex(aes_key_hex)
    hmac_key = bytes.fromhex(hmac_key_hex)

    # 1. Verify HMAC First (Crucial security step!)
    hmac_valid = verify_hmac(iv_hex, ciphertext_hex, timestamp, seq_no, hmac_tag, hmac_key)
    if not hmac_valid:
        return jsonify({
            "hmac_valid": False,
            "error": "HMAC Verification Failed! Message integrity compromised or tampered."
        }), 200

    # 2. Decrypt AES-256-CBC
    try:
        plaintext = decrypt_message(ciphertext_hex, iv_hex, aes_key)
        return jsonify({
            "hmac_valid": True,
            "plaintext": plaintext
        }), 200
    except Exception as e:
        return jsonify({
            "hmac_valid": True,
            "error": f"Decryption failed: {str(e)}"
        }), 400

