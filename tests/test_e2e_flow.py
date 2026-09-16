"""
Full End-to-End Simulation Test: Alice & Bob Complete Exchange
Validates:
1. Diffie-Hellman Handshake Initiation & Response
2. Shared Secret & HKDF Key Equivalence
3. AES-256-CBC Encrypt-then-MAC Message Relay
4. Bob Decryption & Integrity Confirmation
5. Tamper Detection & Rejection
"""
import unittest
import json
import uuid
from app import app
from database import init_db

client = app.test_client()

def post(path, data, user):
    response = client.post(
        path,
        data=json.dumps(data),
        headers={'Content-Type': 'application/json', 'X-Sim-User': user}
    )
    return json.loads(response.data.decode('utf-8'))

def get(path, user):
    response = client.get(
        path,
        headers={'X-Sim-User': user}
    )
    return json.loads(response.data.decode('utf-8'))

class TestE2EFlow(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_complete_exchange(self):
        # 1. Register users
        post('/api/auth/register', {'username': 'alice', 'password': 'password123'}, 'alice')
        post('/api/auth/register', {'username': 'bob', 'password': 'password123'}, 'bob')

        # 2. Alice Keygen & Handshake Initiate
        a_keys = post('/api/dh/client/keygen', {}, 'alice')
        sess = post('/api/dh/initiate', {
            'peer': 'bob',
            'p_hex': a_keys['p_hex'],
            'g': a_keys['g'],
            'pub_a': a_keys['public_hex']
        }, 'alice')
        sess_id = sess['session_id']

        # 3. Bob detects pending handshake and responds
        pending = get('/api/dh/pending', 'bob')
        self.assertTrue(pending['has_pending'])
        b_keys = post('/api/dh/client/keygen', {}, 'bob')
        b_derived = post('/api/dh/client/compute', {
            'private_hex': b_keys['private_hex'],
            'peer_public_hex': pending['session']['pub_a'],
            'p_hex': a_keys['p_hex']
        }, 'bob')
        post('/api/dh/respond', {'session_id': sess_id, 'pub_b': b_keys['public_hex']}, 'bob')

        # 4. Alice finalizes
        sess_info = get(f'/api/dh/session/{sess_id}', 'alice')
        self.assertEqual(sess_info['session']['status'], 'established')
        a_derived = post('/api/dh/client/compute', {
            'private_hex': a_keys['private_hex'],
            'peer_public_hex': sess_info['session']['pub_b'],
            'p_hex': a_keys['p_hex']
        }, 'alice')

        # Assert identical keys
        self.assertEqual(a_derived['shared_secret_hex'], b_derived['shared_secret_hex'])
        self.assertEqual(a_derived['aes_key_hex'], b_derived['aes_key_hex'])
        self.assertEqual(a_derived['hmac_key_hex'], b_derived['hmac_key_hex'])
        print("\n[+] Handshake SUCCESS: Alice and Bob have IDENTICAL 256-bit AES and HMAC keys!")

        # 5. Alice encrypts and sends message
        plaintext = "The secret meeting is at 5 PM."
        ts = "2026-09-16T21:45:00"
        seq_no = 1
        msg_id = f"test-e2e-{uuid.uuid4().hex[:8]}"

        enc = post('/api/client/encrypt', {
            'plaintext': plaintext,
            'aes_key_hex': a_derived['aes_key_hex'],
            'hmac_key_hex': a_derived['hmac_key_hex'],
            'timestamp': ts,
            'seq_no': seq_no
        }, 'alice')

        send_res = post('/api/messages/send', {
            'message_id': msg_id,
            'receiver': 'bob',
            'ciphertext': enc['ciphertext_hex'],
            'iv': enc['iv_hex'],
            'hmac_tag': enc['hmac_tag'],
            'timestamp': ts,
            'seq_no': seq_no
        }, 'alice')
        self.assertTrue(send_res['success'])

        # 6. Bob receives and decrypts
        msgs = get('/api/messages/receive/alice', 'bob')
        self.assertGreater(len(msgs['messages']), 0)
        pkt = msgs['messages'][-1]

        dec = post('/api/client/decrypt', {
            'ciphertext_hex': pkt['ciphertext'],
            'iv_hex': pkt['iv'],
            'hmac_tag': pkt['hmac_tag'],
            'timestamp': pkt['timestamp'],
            'seq_no': pkt['seq_no'],
            'aes_key_hex': b_derived['aes_key_hex'],
            'hmac_key_hex': b_derived['hmac_key_hex']
        }, 'bob')

        self.assertTrue(dec['hmac_valid'])
        self.assertEqual(dec['plaintext'], plaintext)
        print(f"[+] Message Delivery & Decryption SUCCESS: Bob decrypted '{dec['plaintext']}'!")

        # 7. Tamper Detection Test
        tampered_c = ('0' if pkt['ciphertext'][0] != '0' else '1') + pkt['ciphertext'][1:]
        dec_tamper = post('/api/client/decrypt', {
            'ciphertext_hex': tampered_c,
            'iv_hex': pkt['iv'],
            'hmac_tag': pkt['hmac_tag'],
            'timestamp': pkt['timestamp'],
            'seq_no': pkt['seq_no'],
            'aes_key_hex': b_derived['aes_key_hex'],
            'hmac_key_hex': b_derived['hmac_key_hex']
        }, 'bob')

        self.assertFalse(dec_tamper['hmac_valid'])
        print("[+] Tamper Detection SUCCESS: Bob rejected tampered message with HMAC failure!")

if __name__ == "__main__":
    unittest.main()
