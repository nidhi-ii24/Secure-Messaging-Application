/**
 * CNS Educational Cryptographic Client
 * Handles client-side DH key generation, HKDF key derivation,
 * AES-256-CBC encryption, and HMAC-SHA256 integrity checks.
 */

class SecureCryptoClient {
    constructor(username) {
        this.username = username;
        this.identityPrivateKey = null; // RSA private key PEM
        this.identityPublicKey = null;  // RSA public key PEM
        
        // Active Session State
        this.peer = null;
        this.sessionId = null;
        this.p_hex = null;
        this.g = 2;
        this.privateDH_hex = null;
        this.publicDH_hex = null;
        this.peerPublicDH_hex = null;
        
        // Derived Session Keys (NEVER sent to server)
        this.sharedSecret_hex = null;
        this.sharedSecretFingerprint = null;
        this.aesKey_hex = null;
        this.aesKeyFingerprint = null;
        this.hmacKey_hex = null;
        this.hmacKeyFingerprint = null;
        
        this.seqNo = 0;
        this.isSessionEstablished = false;
        
        // Load saved identity keys from localStorage if available
        this.loadIdentity();
    }

    getHeaders() {
        return {
            'Content-Type': 'application/json',
            'X-Sim-User': this.username
        };
    }

    resetSession() {
        this.sessionId = null;
        this.p_hex = null;
        this.g = 2;
        this.privateDH_hex = null;
        this.publicDH_hex = null;
        this.peerPublicDH_hex = null;
        this.sharedSecret_hex = null;
        this.sharedSecretFingerprint = null;
        this.aesKey_hex = null;
        this.aesKeyFingerprint = null;
        this.hmacKey_hex = null;
        this.hmacKeyFingerprint = null;
        this.seqNo = 0;
        this.isSessionEstablished = false;
    }

    loadIdentity() {
        const priv = localStorage.getItem(`cns_identity_priv_${this.username}`);
        const pub = localStorage.getItem(`cns_identity_pub_${this.username}`);
        if (priv && pub) {
            this.identityPrivateKey = priv;
            this.identityPublicKey = pub;
        }
    }

    saveIdentity(priv, pub) {
        this.identityPrivateKey = priv;
        this.identityPublicKey = pub;
        localStorage.setItem(`cns_identity_priv_${this.username}`, priv);
        localStorage.setItem(`cns_identity_pub_${this.username}`, pub);
    }

    /**
     * Step 1: Alice initiates Diffie-Hellman Key Exchange
     */
    async initiateDH(peerUsername, onStepUpdate) {
        this.resetSession();
        this.peer = peerUsername;
        if (onStepUpdate) onStepUpdate("1. Generating 2048-bit Diffie-Hellman Parameters (p, g, private a, public A)...");

        // Generate client-side DH keypair
        const resp = await fetch('/api/dh/client/keygen', { 
            method: 'POST',
            headers: this.getHeaders()
        });
        const keyData = await resp.json();
        
        this.p_hex = keyData.p_hex;
        this.g = keyData.g;
        this.privateDH_hex = keyData.private_hex;
        this.publicDH_hex = keyData.public_hex;

        if (onStepUpdate) onStepUpdate("2. Generating RSA Digital Signature over Public Key A (Anti-MITM)...");

        // Submit initiate request to relay server
        const initResp = await fetch('/api/dh/initiate', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({
                peer: peerUsername,
                p_hex: this.p_hex,
                g: this.g,
                pub_a: this.publicDH_hex,
                sig_a: null
            })
        });
        
        const initResult = await initResp.json();
        if (!initResult.success) throw new Error(initResult.error || "DH Initiate Failed");
        
        this.sessionId = initResult.session_id;
        if (onStepUpdate) onStepUpdate(`3. Published Public Key A to Relay Server (Session ID: ${this.sessionId}). Waiting for ${peerUsername}...`);
        return this.sessionId;
    }

    /**
     * Step 2: Bob responds to Alice's DH invitation
     */
    async respondDH(sessionObj, onStepUpdate) {
        this.sessionId = sessionObj.session_id;
        this.peer = sessionObj.user1;
        this.p_hex = sessionObj.dh_p;
        this.g = sessionObj.dh_g;
        this.peerPublicDH_hex = sessionObj.pub_a;
        this.seqNo = 0;

        if (onStepUpdate) onStepUpdate(`1. Received DH invitation from ${this.peer}. Generating private b and public B...`);

        // Generate Bob's DH keypair
        const resp = await fetch('/api/dh/client/keygen', { 
            method: 'POST',
            headers: this.getHeaders()
        });
        const keyData = await resp.json();
        this.privateDH_hex = keyData.private_hex;
        this.publicDH_hex = keyData.public_hex;

        if (onStepUpdate) onStepUpdate(`2. Computing Shared Secret S = (Public A)^b mod p and deriving AES + HMAC keys via HKDF...`);

        // Compute Bob's shared secret and derive keys
        await this.computeSharedSecretAndKeys(this.peerPublicDH_hex);

        if (onStepUpdate) onStepUpdate(`3. Publishing Public Key B to Relay Server...`);

        const respondResp = await fetch('/api/dh/respond', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({
                session_id: this.sessionId,
                pub_b: this.publicDH_hex,
                sig_b: null
            })
        });

        const respondResult = await respondResp.json();
        if (!respondResult.success) throw new Error(respondResult.error || "DH Respond Failed");

        this.isSessionEstablished = true;
        if (onStepUpdate) onStepUpdate(`4. Secure E2EE Channel Established! (AES-256-CBC + HMAC-SHA256 Ready)`);
        return true;
    }

    /**
     * Step 3: Alice finalizes when Bob's public key B arrives
     */
    async finalizeDH(peerPublicB, onStepUpdate) {
        this.peerPublicDH_hex = peerPublicB;
        this.seqNo = 0;
        if (onStepUpdate) onStepUpdate(`4. Received Bob's Public Key B. Computing Shared Secret S = (Public B)^a mod p...`);

        await this.computeSharedSecretAndKeys(peerPublicB);
        this.isSessionEstablished = true;

        if (onStepUpdate) onStepUpdate(`5. Secure E2EE Channel Established! (AES-256-CBC + HMAC-SHA256 Ready)`);
        return true;
    }

    /**
     * Compute S = (PeerPub)^MyPriv mod p, then derive AES & HMAC keys
     */
    async computeSharedSecretAndKeys(peerPublicHex) {
        const resp = await fetch('/api/dh/client/compute', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({
                private_hex: this.privateDH_hex,
                peer_public_hex: peerPublicHex,
                p_hex: this.p_hex
            })
        });

        const data = await resp.json();
        if (data.error) throw new Error(data.error);

        this.sharedSecret_hex = data.shared_secret_hex;
        this.sharedSecretFingerprint = data.shared_secret_fingerprint;
        this.aesKey_hex = data.aes_key_hex;
        this.aesKeyFingerprint = data.aes_key_fingerprint;
        this.hmacKey_hex = data.hmac_key_hex;
        this.hmacKeyFingerprint = data.hmac_key_fingerprint;
    }

    /**
     * Encrypt Plaintext -> AES-256-CBC -> HMAC-SHA256 -> Packet
     */
    async encryptMessage(plaintext) {
        if (!this.isSessionEstablished) throw new Error("No active secure session established. Click 'Start Secure Handshake (DH)' first.");

        this.seqNo += 1;
        const timestamp = new Date().toISOString();
        const msgId = `msg-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

        const packet = await this.clientAESEncrypt(plaintext, timestamp, this.seqNo, msgId);
        return packet;
    }

    async clientAESEncrypt(plaintext, timestamp, seqNo, messageId) {
        const resp = await fetch('/api/client/encrypt', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({
                plaintext: plaintext,
                aes_key_hex: this.aesKey_hex,
                hmac_key_hex: this.hmacKey_hex,
                timestamp: timestamp,
                seq_no: seqNo
            })
        });
        const data = await resp.json();
        return {
            message_id: messageId,
            receiver: this.peer,
            ciphertext: data.ciphertext_hex,
            iv: data.iv_hex,
            hmac_tag: data.hmac_tag,
            timestamp: timestamp,
            seq_no: seqNo
        };
    }

    /**
     * Verify HMAC-SHA256 -> If Valid Decrypt AES-256-CBC -> Plaintext
     */
    async verifyAndDecrypt(packet) {
        if (!this.isSessionEstablished || !this.hmacKey_hex) {
            throw new Error(`Session not yet synchronized. Please complete Diffie-Hellman handshake.`);
        }
        const resp = await fetch('/api/client/decrypt', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({
                ciphertext_hex: packet.ciphertext,
                iv_hex: packet.iv,
                hmac_tag: packet.hmac_tag,
                timestamp: packet.timestamp,
                seq_no: packet.seq_no,
                aes_key_hex: this.aesKey_hex,
                hmac_key_hex: this.hmacKey_hex
            })
        });
        const data = await resp.json();
        if (!data.hmac_valid) {
            throw new Error(`INTEGRITY ALERT: HMAC Verification Failed! Message modified or corrupted in transit.`);
        }
        return data.plaintext;
    }
}
