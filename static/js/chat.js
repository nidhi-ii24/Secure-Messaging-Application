/**
 * Real-Time Chat & Cryptographic Pipeline Inspector
 */

let currentUser = null;
let currentPeer = null;
let cryptoClient = null;
let pollTimer = null;
let simulateTamper = false;

function getHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    if (currentUser) {
        headers['X-Sim-User'] = currentUser;
    }
    return headers;
}

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Detect if running inside iframe or standalone
    if (window.self !== window.top || new URLSearchParams(window.location.search).get('embedded') === '1') {
        document.body.classList.add('is-embedded');
        const nav = document.querySelector('nav.navbar');
        if (nav) nav.style.display = 'none';
    }

    // 2. Check Login Status / Simulation User Parameter
    const urlParams = new URLSearchParams(window.location.search);
    const userParam = urlParams.get('user');

    if (userParam) {
        currentUser = userParam.trim().toLowerCase();
        try {
            await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUser, password: 'password123' })
            });
        } catch (e) {}
        try {
            await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUser, password: 'password123' })
            });
        } catch (e) {}
    } else {
        const meResp = await fetch('/api/auth/me');
        const meData = await meResp.json();
        if (!meData.logged_in) {
            window.location.href = '/login';
            return;
        }
        currentUser = meData.username;
    }

    const displayUserEl = document.getElementById('display-username');
    if (displayUserEl) displayUserEl.innerText = currentUser;

    cryptoClient = new SecureCryptoClient(currentUser);

    // 3. Load Peers
    await loadPeers();

    // 4. Setup Events & Cross-Frame Messages
    setupEvents();
    setupCrossFrameSync();

    // 5. Start Polling Loop
    startPolling();
});

function setupCrossFrameSync() {
    window.addEventListener('message', async (event) => {
        if (!event.data || !event.data.type) return;
        
        if (event.data.type === 'DH_INITIATED' && event.data.peer === currentUser) {
            // Other user started handshake targeting us!
            await checkPendingHandshake();
        } else if (event.data.type === 'DH_RESPONDED' && event.data.peer === currentUser) {
            // Other user responded to our handshake!
            await checkFinalizeHandshake();
        } else if (event.data.type === 'NEW_MESSAGE' && event.data.to === currentUser) {
            // New message arrived!
            await receiveMessagesFromPeer();
        } else if (event.data.type === 'RESET_CHAT') {
            onLocalReset();
        }
    });
}

async function loadPeers() {
    const resp = await fetch('/api/auth/users', { headers: getHeaders() });
    const data = await resp.json();
    const peerSelect = document.getElementById('peer-select');
    peerSelect.innerHTML = '<option value="">-- Select Communication Peer --</option>';

    const urlParams = new URLSearchParams(window.location.search);
    const preferredPeer = urlParams.get('peer');

    if (data.users && data.users.length > 0) {
        data.users.forEach(u => {
            const opt = document.createElement('option');
            opt.value = u.username;
            opt.innerText = u.username;
            if (preferredPeer && preferredPeer.toLowerCase() === u.username.toLowerCase()) {
                opt.selected = true;
            }
            peerSelect.appendChild(opt);
        });
    }

    if (peerSelect.value) {
        onPeerChanged(peerSelect.value);
    } else if (preferredPeer) {
        const opt = document.createElement('option');
        opt.value = preferredPeer.toLowerCase();
        opt.innerText = preferredPeer.toLowerCase();
        opt.selected = true;
        peerSelect.appendChild(opt);
        onPeerChanged(opt.value);
    }
}

function setupEvents() {
    const peerSelect = document.getElementById('peer-select');
    peerSelect.addEventListener('change', (e) => onPeerChanged(e.target.value));

    const btnStartDH = document.getElementById('btn-start-dh');
    if (btnStartDH) {
        btnStartDH.addEventListener('click', (e) => {
            e.preventDefault();
            initiateHandshake();
        });
    }

    const btnReset = document.getElementById('btn-reset-chat');
    if (btnReset) {
        btnReset.addEventListener('click', (e) => {
            e.preventDefault();
            resetChat();
        });
    }

    const chatForm = document.getElementById('chat-form');
    if (chatForm) {
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            sendMessage();
        });
    }

    const tamperCheckbox = document.getElementById('tamper-checkbox');
    if (tamperCheckbox) {
        tamperCheckbox.addEventListener('change', (e) => {
            simulateTamper = e.target.checked;
        });
    }

    const logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            await fetch('/api/auth/logout', { 
                method: 'POST',
                headers: getHeaders()
            });
            window.location.href = '/login';
        });
    }
}

async function onPeerChanged(peer) {
    if (!peer) {
        currentPeer = null;
        updateSessionBadge(false, "No Peer Selected");
        return;
    }
    currentPeer = peer;
    const peerHeaderEl = document.getElementById('chat-peer-name');
    if (peerHeaderEl) peerHeaderEl.innerText = currentPeer;
    document.getElementById('messages-container').innerHTML = '';

    // Check if established DH session exists on server
    const activeResp = await fetch(`/api/dh/active/${currentPeer}`, {
        headers: getHeaders()
    });
    const activeData = await activeResp.json();
    
    if (activeData.has_active) {
        const sess = activeData.session;
        cryptoClient.sessionId = sess.session_id;
        cryptoClient.p_hex = sess.dh_p;
        cryptoClient.g = sess.dh_g;
        cryptoClient.peer = currentPeer;

        const peerPub = (currentUser === sess.user1) ? sess.pub_b : sess.pub_a;
        if (peerPub && cryptoClient.privateDH_hex) {
            await cryptoClient.computeSharedSecretAndKeys(peerPub);
            cryptoClient.isSessionEstablished = true;
            updateSessionBadge(true, "🔒 Active E2EE Session (AES-256 + HMAC)");
            updateInspector();
        } else {
            updateSessionBadge(false, "Ready: Click 'Start Secure Handshake (DH)'");
        }
    } else {
        updateSessionBadge(false, "No Secure Session Established");
    }

    loadHistory();
}

async function initiateHandshake() {
    if (!currentPeer) {
        alert("Please select a peer first!");
        return;
    }

    const logDiv = document.getElementById('dh-pipeline-log');
    logDiv.innerHTML = '';

    function logStep(msg) {
        const p = document.createElement('div');
        p.className = 'pipeline-step-msg';
        p.innerText = msg;
        logDiv.appendChild(p);
        logDiv.scrollTop = logDiv.scrollHeight;
    }

    try {
        logStep(`[*] Starting Diffie-Hellman Key Exchange with ${currentPeer}...`);
        await cryptoClient.initiateDH(currentPeer, logStep);
        updateSessionBadge(false, "⏳ Waiting for Peer Public Key B...");
        updateInspector();

        // Broadcast to other iframe so peer completes handshake immediately
        try {
            window.parent.postMessage({ type: 'DH_INITIATED', from: currentUser, peer: currentPeer }, '*');
        } catch(e) {}
    } catch (err) {
        logStep(`❌ Error: ${err.message}`);
        alert(err.message);
    }
}

async function checkPendingHandshake() {
    if (!currentUser) return;
    const pendingResp = await fetch('/api/dh/pending', { headers: getHeaders() });
    const pendingData = await pendingResp.json();

    if (pendingData.has_pending) {
        const sess = pendingData.session;
        // If pending session is directed to us and has not been responded to yet
        if (sess.user2 === currentUser && sess.status === 'pending' && cryptoClient.sessionId !== sess.session_id) {
            const logDiv = document.getElementById('dh-pipeline-log');
            logDiv.innerHTML = '';
            function logStep(msg) {
                const p = document.createElement('div');
                p.className = 'pipeline-step-msg';
                p.innerText = msg;
                logDiv.appendChild(p);
                logDiv.scrollTop = logDiv.scrollHeight;
            }

            currentPeer = sess.user1;
            document.getElementById('peer-select').value = currentPeer;

            logStep(`[*] Received DH Key Exchange request from ${currentPeer}! Generating response...`);
            await cryptoClient.respondDH(sess, logStep);
            updateSessionBadge(true, "🔒 Active E2EE Session (AES-256 + HMAC)");
            updateInspector();

            // Broadcast back to initiator to finalize immediately
            try {
                window.parent.postMessage({ type: 'DH_RESPONDED', from: currentUser, peer: currentPeer, sessionId: sess.session_id }, '*');
            } catch(e) {}
        }
    }
}

async function checkFinalizeHandshake() {
    if (cryptoClient.sessionId && !cryptoClient.isSessionEstablished && currentPeer) {
        const sessResp = await fetch(`/api/dh/session/${cryptoClient.sessionId}`, {
            headers: getHeaders()
        });
        const sessData = await sessResp.json();
        if (sessData.success && sessData.session.status === 'established' && sessData.session.pub_b) {
            const logDiv = document.getElementById('dh-pipeline-log');
            function logStep(msg) {
                const p = document.createElement('div');
                p.className = 'pipeline-step-msg';
                p.innerText = msg;
                logDiv.appendChild(p);
                logDiv.scrollTop = logDiv.scrollHeight;
            }
            await cryptoClient.finalizeDH(sessData.session.pub_b, logStep);
            updateSessionBadge(true, "🔒 Active E2EE Session (AES-256 + HMAC)");
            updateInspector();
        }
    }
}

async function receiveMessagesFromPeer() {
    if (!currentPeer || !cryptoClient.isSessionEstablished) return;
    const msgResp = await fetch(`/api/messages/receive/${currentPeer}`, {
        headers: getHeaders()
    });
    const msgData = await msgResp.json();
    if (msgData.success && msgData.messages.length > 0) {
        for (const pkt of msgData.messages) {
            await handleIncomingMessage(pkt);
        }
    }
}

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
        if (!currentUser) return;
        // 1. Check for incoming DH requests
        await checkPendingHandshake();
        // 2. Check if peer responded to our DH request
        await checkFinalizeHandshake();
        // 3. Check for incoming messages
        await receiveMessagesFromPeer();
    }, 1000);
}

async function sendMessage() {
    const input = document.getElementById('message-input');
    const text = input.value.trim();
    if (!text) return;

    if (!cryptoClient.isSessionEstablished) {
        alert("Please click 'Start Secure Handshake (DH)' first to establish symmetric keys!");
        return;
    }

    try {
        // 1. Client-Side AES-256-CBC Encrypt + HMAC-SHA256
        const packet = await cryptoClient.encryptMessage(text);

        // Optional Simulation: Tamper with ciphertext in transit
        if (simulateTamper) {
            packet.ciphertext = ('1' === packet.ciphertext[0] ? '2' : '1') + packet.ciphertext.substring(1);
            console.warn("⚠️ SIMULATING ADVERSARY TAMPERING: Modified byte in ciphertext before sending!");
        }

        // 2. Relay Encrypted Packet to Server
        const sendResp = await fetch('/api/messages/send', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify(packet)
        });
        const sendData = await sendResp.json();

        if (sendData.success) {
            appendMessageToUI(currentUser, text, packet, true);
            input.value = '';
            updateInspectorPacket(packet, true);

            // Notify recipient frame to fetch immediately
            try {
                window.parent.postMessage({ type: 'NEW_MESSAGE', from: currentUser, to: currentPeer }, '*');
            } catch(e) {}
        } else {
            alert(`Send Error: ${sendData.message || sendData.error}`);
        }
    } catch (err) {
        alert(err.message);
    }
}

async function handleIncomingMessage(pkt) {
    try {
        const decryptedPlaintext = await cryptoClient.verifyAndDecrypt(pkt);
        appendMessageToUI(pkt.sender, decryptedPlaintext, pkt, false);
        updateInspectorPacket(pkt, false, true);
    } catch (err) {
        appendTamperedMessageAlert(pkt.sender, pkt, err.message);
        updateInspectorPacket(pkt, false, false);
    }
}

function appendMessageToUI(sender, text, pkt, isSelf) {
    const container = document.getElementById('messages-container');
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${isSelf ? 'message-sent' : 'message-received'}`;

    bubble.innerHTML = `
        <div style="font-weight: 700; font-size: 0.8rem; margin-bottom: 0.2rem;">${sender}</div>
        <div>${escapeHtml(text)}</div>
        <div class="message-meta">
            <span>🔒 AES-256 | HMAC ✓</span>
            <span>Seq: #${pkt.seq_no} | ${new Date(pkt.timestamp).toLocaleTimeString()}</span>
        </div>
    `;

    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
}

function appendTamperedMessageAlert(sender, pkt, errMsg) {
    const container = document.getElementById('messages-container');
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    bubble.style.backgroundColor = 'rgba(239, 68, 68, 0.2)';
    bubble.style.border = '1px solid #ef4444';
    bubble.style.color = '#fca5a5';

    bubble.innerHTML = `
        <div style="font-weight: 700; color: #ef4444;">❌ TAMPER ATTACK DETECTED (${sender})</div>
        <div style="font-size: 0.85rem; margin: 0.3rem 0;">${escapeHtml(errMsg)}</div>
        <div style="font-family: var(--font-mono); font-size: 0.7rem; color: #cbd5e1; word-break: break-all;">
            Ciphertext: ${pkt.ciphertext.substring(0, 32)}...<br>
            HMAC Tag: ${pkt.hmac_tag.substring(0, 24)}...
        </div>
        <div class="message-meta">
            <span style="color: #ef4444;">Status: Message Discarded by Client</span>
            <span>Seq: #${pkt.seq_no}</span>
        </div>
    `;

    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
}

async function loadHistory() {
    if (!currentPeer) return;
    const resp = await fetch(`/api/messages/history/${currentPeer}`, {
        headers: getHeaders()
    });
    const data = await resp.json();
    if (!data.success) return;

    for (const pkt of data.history) {
        if (cryptoClient.isSessionEstablished) {
            try {
                const text = await cryptoClient.verifyAndDecrypt(pkt);
                appendMessageToUI(pkt.sender, text, pkt, pkt.sender === currentUser);
            } catch (e) {
                appendEncryptedRawMessage(pkt);
            }
        } else {
            appendEncryptedRawMessage(pkt);
        }
    }
}

function appendEncryptedRawMessage(pkt) {
    const container = document.getElementById('messages-container');
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${pkt.sender === currentUser ? 'message-sent' : 'message-received'}`;
    bubble.style.opacity = '0.75';
    bubble.innerHTML = `
        <div style="font-weight: 700; font-size: 0.8rem;">${pkt.sender} (Relay Ciphertext)</div>
        <div style="font-family: var(--font-mono); font-size: 0.75rem; word-break: break-all;">${pkt.ciphertext.substring(0, 48)}...</div>
        <div class="message-meta">
            <span>Encrypted in Transit</span>
            <span>#${pkt.seq_no}</span>
        </div>
    `;
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
}

async function resetChat() {
    if (!confirm("Clear message history and reset cryptographic session for a clean demo?")) return;
    
    await fetch('/api/dh/reset', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ peer: currentPeer })
    });

    onLocalReset();

    // Broadcast reset to peer frame
    try {
        window.parent.postMessage({ type: 'RESET_CHAT' }, '*');
    } catch(e) {}
}

function onLocalReset() {
    cryptoClient.resetSession();
    document.getElementById('messages-container').innerHTML = `
        <div style="text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: 2rem;">
            Session reset. Click <strong>"Start Secure Handshake (DH)"</strong> to establish a fresh cryptographic session.
        </div>
    `;
    document.getElementById('dh-pipeline-log').innerHTML = '<span style="color: var(--text-muted);">Ready for new handshake.</span>';
    updateSessionBadge(false, "No Secure Session Established");
    updateInspector();
    
    // Clear last packet view
    const setSafe = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val;
    };
    setSafe('insp-last-iv', '-');
    setSafe('insp-last-c', '-');
    setSafe('insp-last-hmac', '-');
    setSafe('insp-last-status', '-');
}

function updateSessionBadge(isSecure, text) {
    const badge = document.getElementById('session-badge');
    if (!badge) return;
    badge.className = isSecure ? 'badge badge-success' : 'badge badge-warning';
    badge.innerText = text;
}

function updateInspector() {
    const setSafe = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val;
    };
    setSafe('insp-user', currentUser || '-');
    setSafe('insp-peer', currentPeer || '-');
    setSafe('insp-p', cryptoClient.p_hex ? `${cryptoClient.p_hex.substring(0, 24)}... (2048-bit MODP)` : '-');
    setSafe('insp-g', cryptoClient.g || '2');
    setSafe('insp-my-pub', cryptoClient.publicDH_hex ? `${cryptoClient.publicDH_hex.substring(0, 24)}...` : '-');
    setSafe('insp-peer-pub', cryptoClient.peerPublicDH_hex ? `${cryptoClient.peerPublicDH_hex.substring(0, 24)}...` : '-');
    setSafe('insp-secret-fp', cryptoClient.sharedSecretFingerprint || '(Handshake Pending)');
    setSafe('insp-aes-fp', cryptoClient.aesKeyFingerprint || '(Handshake Pending)');
    setSafe('insp-hmac-fp', cryptoClient.hmacKeyFingerprint || '(Handshake Pending)');
}

function updateInspectorPacket(pkt, isSent, verified = true) {
    const setSafe = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val;
    };
    setSafe('insp-last-iv', pkt.iv);
    setSafe('insp-last-c', `${pkt.ciphertext.substring(0, 40)}...`);
    setSafe('insp-last-hmac', pkt.hmac_tag);
    const statusSpan = document.getElementById('insp-last-status');
    if (statusSpan) {
        if (isSent) {
            statusSpan.innerText = 'Delivered to Relay';
            statusSpan.style.color = '#38bdf8';
        } else if (verified) {
            statusSpan.innerText = 'Verified & Decrypted ✓';
            statusSpan.style.color = '#22c55e';
        } else {
            statusSpan.innerText = 'INTEGRITY FAILED ❌';
            statusSpan.style.color = '#ef4444';
        }
    }
}

function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
