"""
Encrypted Message Relay Routes
Provides message relay, anti-replay validation, and unread queue management.
The server stores and relays ONLY ciphertext, IV, HMAC, timestamp, and sequence number.
It CANNOT read any message content.
"""
import uuid
import datetime
from flask import Blueprint, request, jsonify, session
from database import (
    save_message,
    get_unread_messages,
    mark_messages_read,
    get_message_history,
    record_and_verify_replay,
    get_db_connection
)

msg_bp = Blueprint('messages', __name__)

@msg_bp.route('/api/messages/send', methods=['POST'])
def send_message():
    current_user = request.headers.get('X-Sim-User') or session.get('username')
    if not current_user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    receiver = (data.get('receiver') or '').strip().lower()
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')
    hmac_tag = data.get('hmac_tag')
    timestamp = data.get('timestamp') or datetime.datetime.now(datetime.timezone.utc).isoformat()
    seq_no = data.get('seq_no', 1)
    message_id = data.get('message_id') or str(uuid.uuid4())

    if not receiver or not ciphertext or not iv or not hmac_tag:
        return jsonify({"success": False, "error": "Missing encrypted payload fields"}), 400

    # 1. Anti-Replay Verification
    is_replayed = record_and_verify_replay(message_id, current_user, receiver, seq_no)
    if is_replayed:
        return jsonify({
            "success": False,
            "error": "REPLAY_ATTACK_DETECTED",
            "message": f"Security Alert: Replay attack detected! Message ID '{message_id}' or sequence #{seq_no} has already been processed."
        }), 409

    # 2. Store & Relay Encrypted Packet
    save_message(
        message_id=message_id,
        sender=current_user,
        receiver=receiver,
        ciphertext=ciphertext,
        iv=iv,
        hmac_tag=hmac_tag,
        timestamp=timestamp,
        seq_no=seq_no
    )

    return jsonify({
        "success": True,
        "message_id": message_id,
        "status": "relayed",
        "info": "Encrypted message accepted and queued for recipient."
    }), 201

@msg_bp.route('/api/messages/receive/<peer>', methods=['GET'])
def receive_messages(peer):
    current_user = request.headers.get('X-Sim-User') or session.get('username')
    if not current_user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    peer = peer.strip().lower()
    unread = get_unread_messages(current_user)
    # Filter messages from this specific peer
    peer_messages = [m for m in unread if m['sender'] == peer]

    # Mark returned messages as read
    if peer_messages:
        ids_to_mark = [m['message_id'] for m in peer_messages]
        mark_messages_read(ids_to_mark)

    return jsonify({
        "success": True,
        "messages": peer_messages
    }), 200

@msg_bp.route('/api/messages/history/<peer>', methods=['GET'])
def message_history(peer):
    current_user = request.headers.get('X-Sim-User') or session.get('username')
    if not current_user:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    peer = peer.strip().lower()
    history = get_message_history(current_user, peer)
    return jsonify({
        "success": True,
        "history": history
    }), 200

@msg_bp.route('/api/server/relay-log', methods=['GET'])
def server_relay_log():
    """
    Teacher/Examiner Inspection Endpoint:
    Reveals the server's raw database contents to prove that ZERO plaintext
    is known to or stored by the relay server.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT message_id, sender, receiver, ciphertext, iv, hmac_tag, timestamp, seq_no, created_at
    FROM messages ORDER BY id DESC LIMIT 50
    """)
    rows = cursor.fetchall()
    conn.close()

    return jsonify({
        "description": "Server-side relay log. Notice all messages are encrypted hex strings. Plaintext is inaccessible to server.",
        "count": len(rows),
        "packets": [dict(r) for r in rows]
    }), 200
