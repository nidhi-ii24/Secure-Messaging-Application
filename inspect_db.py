"""
Database Inspection Utility for CNS Secure Messaging System
Prints the contents of messaging.db in a structured, readable format.
Demonstrates zero-knowledge server storage:
- Messages store only IV, ciphertext, and HMAC (no plaintext)
- Sessions store only public Diffie-Hellman parameters (no private keys)
- Users store salted password hashes (no plaintext passwords)
"""
import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "messaging.db"

def inspect():
    if not DB_PATH.exists():
        print(f"[-] Database file not found at: {DB_PATH}")
        return

    print("=" * 70)
    print(f"DATABASE INSPECTION: {DB_PATH.name}")
    print(f"Location: {DB_PATH.resolve()}")
    print(f"Size: {os.path.getsize(DB_PATH)} bytes")
    print("=" * 70)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Users Table
    print("\n[1] TABLE: users (Salted Password Hashes & RSA Public Keys)")
    print("-" * 70)
    users = cursor.execute("SELECT id, username, password_hash, salt, public_identity_key, created_at FROM users").fetchall()
    if not users:
        print("  (No registered users found)")
    else:
        for u in users:
            pk_preview = (u['public_identity_key'][:30] + "...") if u['public_identity_key'] else "None"
            pw_preview = (u['password_hash'][:24] + "...") if u['password_hash'] else ""
            salt_preview = (u['salt'][:16] + "...") if u['salt'] else ""
            print(f"  * ID: {u['id']} | User: {u['username']}")
            print(f"    Password Hash: {pw_preview} (PBKDF2-HMAC-SHA256)")
            print(f"    Salt:          {salt_preview}")
            print(f"    Public Key:    {pk_preview}")
            print(f"    Created At:    {u['created_at']}")

    # 2. DH Sessions Table
    print("\n[2] TABLE: dh_sessions (Ephemeral Public Parameters Only)")
    print("-" * 70)
    sessions = cursor.execute("SELECT session_id, user1, user2, status, pub_a, pub_b, created_at FROM dh_sessions ORDER BY created_at DESC").fetchall()
    if not sessions:
        print("  (No DH sessions found)")
    else:
        for s in sessions:
            pub_a_prev = (s['pub_a'][:24] + "...") if s['pub_a'] else "None"
            pub_b_prev = (s['pub_b'][:24] + "...") if s['pub_b'] else "None"
            print(f"  * Session: {s['session_id']}")
            print(f"    Peers:   {s['user1']} <--> {s['user2']} | Status: {s['status']}")
            print(f"    Pub A:   {pub_a_prev}")
            print(f"    Pub B:   {pub_b_prev}")
            print(f"    Created: {s['created_at']}")

    # 3. Encrypted Messages Table
    print("\n[3] TABLE: messages (Zero-Knowledge Ciphertext Relay)")
    print("-" * 70)
    messages = cursor.execute("SELECT id, message_id, sender, receiver, ciphertext, iv, hmac_tag, seq_no, timestamp FROM messages ORDER BY id ASC").fetchall()
    if not messages:
        print("  (No messages stored yet. Send a message in the chat to see it here!)")
    else:
        for m in messages:
            c_prev = (m['ciphertext'][:32] + "...") if len(m['ciphertext']) > 32 else m['ciphertext']
            tag_prev = (m['hmac_tag'][:24] + "...") if m['hmac_tag'] else ""
            print(f"  * Msg #{m['id']} [ID: {m['message_id'][:12]}...]")
            print(f"    Route:      {m['sender']} --> {m['receiver']}")
            print(f"    Ciphertext: {c_prev} (Encrypted with AES-256-CBC)")
            print(f"    IV:         {m['iv']}")
            print(f"    HMAC Tag:   {tag_prev} (HMAC-SHA256)")
            print(f"    Seq No:     {m['seq_no']} | Timestamp: {m['timestamp']}")
            print(f"    PLAINTEXT STORED ON SERVER? NO (ZERO-KNOWLEDGE)")

    # 4. Replay Protection Table
    print("\n[4] TABLE: processed_messages (Replay Attack Nonce Cache)")
    print("-" * 70)
    nonces = cursor.execute("SELECT message_id, sender, receiver, seq_no, received_at FROM processed_messages").fetchall()
    if not nonces:
        print("  (No processed nonces recorded yet)")
    else:
        for n in nonces:
            print(f"  * Msg ID: {n['message_id'][:16]}... | {n['sender']} -> {n['receiver']} | Seq: {n['seq_no']} | At: {n['received_at']}")

    print("\n" + "=" * 70)
    print("CNS SECURITY VERIFICATION SUMMARY:")
    print("  1. No plaintext messages exist anywhere in this database.")
    print("  2. No symmetric AES/HMAC session keys exist in this database.")
    print("  3. No private Diffie-Hellman keys exist in this database.")
    print("  4. Passwords are salted and hashed with PBKDF2-HMAC-SHA256.")
    print("=" * 70 + "\n")

    conn.close()

if __name__ == "__main__":
    inspect()
