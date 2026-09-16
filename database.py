"""
SQLite Database Layer for CNS Secure Messaging System
Stores user credentials, public keys, active DH parameters, and encrypted message relays.
Plaintext messages and symmetric keys are NEVER stored.
"""
import sqlite3
import os
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent / "messaging.db"

def get_db_connection(db_path=None):
    if db_path is None:
        db_path = DB_FILE
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path=None):
    if db_path is None:
        db_path = DB_FILE
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Table 1: Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        public_identity_key TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Table 2: Diffie-Hellman Sessions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dh_sessions (
        session_id TEXT PRIMARY KEY,
        user1 TEXT NOT NULL,
        user2 TEXT NOT NULL,
        dh_p TEXT NOT NULL,
        dh_g INTEGER NOT NULL,
        pub_a TEXT,
        pub_b TEXT,
        sig_a TEXT,
        sig_b TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Table 3: Encrypted Messages (Server Relay & Storage)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT UNIQUE NOT NULL,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        hmac_tag TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        seq_no INTEGER NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Table 4: Seen Nonces / Message IDs for Replay Protection
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS processed_messages (
        message_id TEXT PRIMARY KEY,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        seq_no INTEGER NOT NULL,
        received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

# ----------------- User Helpers -----------------
def create_user(username, password_hash, salt, public_identity_key=None, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, public_identity_key) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, public_identity_key)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user_by_username(username, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_users(db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, public_identity_key, created_at FROM users ORDER BY username ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- DH Session Helpers -----------------
def create_dh_session(session_id, user1, user2, dh_p, dh_g, pub_a, sig_a=None, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    # Mark old sessions between these two users as superseded to prevent desync
    cursor.execute("""
    UPDATE dh_sessions SET status = 'superseded'
    WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)
    """, (user1, user2, user2, user1))

    cursor.execute("""
    INSERT INTO dh_sessions (session_id, user1, user2, dh_p, dh_g, pub_a, sig_a, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
    """, (session_id, user1, user2, dh_p, dh_g, pub_a, sig_a))
    conn.commit()
    conn.close()

def clear_messages_and_sessions(user1=None, user2=None, db_path=None):
    """Clears messages and sessions for a fresh demonstration."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if user1 and user2:
        cursor.execute("DELETE FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)", (user1, user2, user2, user1))
        cursor.execute("DELETE FROM dh_sessions WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)", (user1, user2, user2, user1))
        cursor.execute("DELETE FROM processed_messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)", (user1, user2, user2, user1))
    else:
        cursor.execute("DELETE FROM messages")
        cursor.execute("DELETE FROM dh_sessions")
        cursor.execute("DELETE FROM processed_messages")
    conn.commit()
    conn.close()

def update_dh_session_bob(session_id, pub_b, sig_b=None, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE dh_sessions
    SET pub_b = ?, sig_b = ?, status = 'established'
    WHERE session_id = ?
    """, (pub_b, sig_b, session_id))
    conn.commit()
    conn.close()

def get_dh_session(session_id, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dh_sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_active_dh_session(user1, user2, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM dh_sessions
    WHERE ((user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?))
    AND status = 'established'
    ORDER BY created_at DESC LIMIT 1
    """, (user1, user2, user2, user1))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_latest_pending_session_for(user2, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM dh_sessions
    WHERE user2 = ? AND status = 'pending'
    ORDER BY created_at DESC LIMIT 1
    """, (user2,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# ----------------- Message Relay Helpers -----------------
def record_and_verify_replay(message_id, sender, receiver, seq_no, db_path=None):
    """
    Checks if message_id or sequence number has already been processed.
    Returns True if replay attack detected, False if fresh.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT message_id FROM processed_messages WHERE message_id = ?", (message_id,))
    if cursor.fetchone() is not None:
        conn.close()
        return True # Replayed!

    # Record message as processed
    try:
        cursor.execute(
            "INSERT INTO processed_messages (message_id, sender, receiver, seq_no) VALUES (?, ?, ?, ?)",
            (message_id, sender, receiver, seq_no)
        )
        conn.commit()
        return False
    except sqlite3.IntegrityError:
        return True
    finally:
        conn.close()

def save_message(message_id, sender, receiver, ciphertext, iv, hmac_tag, timestamp, seq_no, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO messages (message_id, sender, receiver, ciphertext, iv, hmac_tag, timestamp, seq_no)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (message_id, sender, receiver, ciphertext, iv, hmac_tag, timestamp, seq_no))
    conn.commit()
    conn.close()

def get_unread_messages(receiver, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM messages
    WHERE receiver = ? AND is_read = 0
    ORDER BY seq_no ASC, created_at ASC
    """, (receiver,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def mark_messages_read(message_ids, db_path=None):
    if not message_ids:
        return
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    placeholders = ",".join("?" * len(message_ids))
    cursor.execute(f"UPDATE messages SET is_read = 1 WHERE message_id IN ({placeholders})", message_ids)
    conn.commit()
    conn.close()

def get_message_history(user1, user2, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM messages
    WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
    ORDER BY id ASC
    """, (user1, user2, user2, user1))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

if __name__ == "__main__":
    init_db()
    print("[+] Database initialized successfully.")
