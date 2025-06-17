let currentUser = null;

function base64ToArrayBuffer(base64) {
    try {
        const binaryString = atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        throw new Error('Invalid Base64 string');
    }
}

function arrayBufferToBase64(buffer) {
    try {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    } catch (error) {
        throw new Error('Failed to convert buffer to Base64');
    }
}

async function hashData(data) {
    try {
        const msgBuffer = new TextEncoder().encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        return arrayBufferToBase64(hashBuffer);
    } catch (error) {
        throw new Error('Hashing failed: ' + error.message);
    }
}

function showStatus(elementId, message, type) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.className = type;
    } else {
        console.error(`Element #${elementId} not found`);
    }
}

function showVoteReceipt(receipt) {
    const receiptElement = document.getElementById('voteReceipt');
    if (receiptElement) {
        receiptElement.textContent = `Receipt ID: ${receipt.receiptID}, Timestamp: ${new Date(receipt.timestamp).toLocaleString()}, Block Hash: ${receipt.blockHash}`;
    } else {
        console.log('Receipt:', receipt);
    }
}

function clearAuthForm() {
    const form = document.getElementById('authForm');
    if (form) {
        form.reset();
    }
}

function clearSelection() {
    const form = document.getElementById('ballotSection');
    if (form) {
        form.querySelectorAll('input[name="vote"]').forEach(input => input.checked = false);
    }
}

async function generateKeyPair() {
    const keySize = parseInt(document.getElementById('keySizeSelect').value);
    try {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: keySize,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: 'SHA-256'
            },
            true,
            ['sign', 'verify']
        );

        const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKeyB64 = arrayBufferToBase64(privateKey);
        const publicKeyB64 = arrayBufferToBase64(publicKey);

        document.getElementById('privateKeyOutput').textContent = `Private Key (save securely):\n${privateKeyB64}`;
        document.getElementById('publicKeyOutput').textContent = `Public Key:\n${publicKeyB64}`;
        showStatus('voteStatus', 'Key pair generated successfully!', 'success');
    } catch (error) {
        console.error('Key generation error:', error);
        showStatus('voteStatus', `Error: ${error.message}`, 'error');
    }
}

async function register() {
    const name = document.getElementById('nameInput').value;
    const email = document.getElementById('emailInputReg').value;
    const password = document.getElementById('passwordInputReg').value;
    const voterID = document.getElementById('voterIDInput').value;
    const publicKey = document.getElementById('publicKeyOutput').textContent.replace('Public Key:\n', '');

    if (!name || !email || !password || !voterID || !publicKey) {
        showStatus('voteStatus', 'Please fill all fields and generate a key pair.', 'error');
        return;
    }

    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password, voterID, publicKey })
        });
        if (!response.ok) throw new Error(await response.text());
        showStatus('voteStatus', 'Registration successful! Request a certificate next.', 'success');
    } catch (error) {
        console.error('Registration error:', error);
        showStatus('voteStatus', `Error: ${error.message}`, 'error');
    }
}

async function requestCertificate() {
    const voterID = document.getElementById('voterIDInput').value;
    if (!voterID) {
        showStatus('voteStatus', 'Please enter your Voter ID.', 'error');
        return;
    }

    try {
        const response = await fetch('/api/request-certificate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voterID })
        });
        if (!response.ok) throw new Error(await response.text());
        showStatus('voteStatus', 'Certificate request submitted!', 'success');
    } catch (error) {
        console.error('Certificate request error:', error);
        showStatus('voteStatus', `Error: ${error.message}`, 'error');
    }
}

async function authenticate() {
    const email = document.getElementById('emailInput').value;
    const password = document.getElementById('passwordInput').value;
    const privateKeyB64 = document.getElementById('privateKeyInput').value;

    if (!email || !password || !privateKeyB64) {
        showStatus('voteStatus', 'Please provide email, password, and private key.', 'error');
        return;
    }

    try {
        // Login to get voterID and token
        const loginResponse = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        if (!loginResponse.ok) throw new Error(await loginResponse.text());
        const { token, voterID } = await loginResponse.json();

        // Get authentication challenge
        const challengeResponse = await fetch(`/api/auth-challenge/${voterID}`);
        if (!challengeResponse.ok) throw new Error(await challengeResponse.text());
        const { challenge } = await challengeResponse.json();

        // Sign the challenge
        const privateKeyObj = await crypto.subtle.importKey(
            'pkcs8',
            base64ToArrayBuffer(privateKeyB64),
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const signature = await crypto.subtle.sign(
            { name: 'RSASSA-PKCS1-v1_5' },
            privateKeyObj,
            new TextEncoder().encode(challenge)
        );
        const signatureB64 = arrayBufferToBase64(signature);

        // Authenticate with signature
        const authResponse = await fetch('/api/authenticate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voterID, signature: signatureB64 })
        });
        if (!authResponse.ok) throw new Error(await authResponse.text());
        const authData = await authResponse.json();

        currentUser = { voterID, token: authData.token };
        showStatus('voteStatus', 'Authentication successful!', 'success');

        const authSection = document.getElementById('authSection');
        const ballotSection = document.getElementById('ballotSection');
        if (authSection && ballotSection) {
            authSection.style.display = 'none';
            ballotSection.style.display = 'block';
        }
    } catch (error) {
        console.error('Authentication error:', error);
        showStatus('voteStatus', `Error: ${error.message}`, 'error');
    }
}

async function castVote() {
    if (!currentUser || !currentUser.voterID || !currentUser.token) {
        showStatus('voteStatus', 'Please authenticate first.', 'error');
        return;
    }

    const selectedVote = document.querySelector('input[name="vote"]:checked');
    if (!selectedVote) {
        showStatus('voteStatus', 'Please select a candidate.', 'error');
        return;
    }

    const privateKeyInput = document.getElementById('privateKeyInput');
    if (!privateKeyInput || !privateKeyInput.value) {
        showStatus('voteStatus', 'Please provide a private key.', 'error');
        return;
    }
    const privateKey = privateKeyInput.value;

    try {
        const privateKeyObj = await crypto.subtle.importKey(
            'pkcs8',
            base64ToArrayBuffer(privateKey),
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const voteData = {
            candidate: selectedVote.value,
            timestamp: new Date().toISOString(),
            voterIDHash: await hashData(currentUser.voterID)
        };

        const publicKeyResponse = await fetch(`/api/public-key/${currentUser.voterID}`);
        if (!publicKeyResponse.ok) {
            const errorText = await publicKeyResponse.text();
            throw new Error(`Failed to fetch public key: ${errorText}`);
        }
        const publicKeyText = await publicKeyResponse.text();
        if (!publicKeyText) {
            throw new Error('Empty public key response');
        }
        let publicKeyData;
        try {
            publicKeyData = JSON.parse(publicKeyText);
        } catch (e) {
            throw new Error(`Invalid JSON in public key response: ${publicKeyText}`);
        }
        const { publicKey: publicKeyB64 } = publicKeyData;

        const publicKey = await crypto.subtle.importKey(
            'spki',
            base64ToArrayBuffer(publicKeyB64),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );
        const encryptedVote = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            new TextEncoder().encode(JSON.stringify(voteData))
        );
        const encryptedVoteB64 = arrayBufferToBase64(encryptedVote);

        const signature = await crypto.subtle.sign(
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            privateKeyObj,
            base64ToArrayBuffer(encryptedVoteB64)
        );
        const signatureB64 = arrayBufferToBase64(signature);

        const response = await fetch('/api/cast-vote', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentUser.token}`
            },
            body: JSON.stringify({ encryptedVote: encryptedVoteB64, signature: signatureB64 })
        });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Vote submission failed: ${errorText}`);
        }
        const responseText = await response.text();
        if (!responseText) {
            throw new Error('Empty vote submission response');
        }
        let responseData;
        try {
            responseData = JSON.parse(responseText);
        } catch (e) {
            throw new Error(`Invalid JSON in vote submission response: ${responseText}`);
        }
        const { receipt } = responseData;

        showVoteReceipt(receipt);
        showStatus('voteStatus', 'Vote cast successfully!', 'success');

        setTimeout(() => {
            const ballotSection = document.getElementById('ballotSection');
            const authSection = document.getElementById('authSection');
            if (ballotSection && authSection) {
                ballotSection.style.display = 'none';
                authSection.style.display = 'block';
                clearAuthForm();
            } else {
                showStatus('voteStatus', 'UI reset failed: Elements not found.', 'error');
            }
        }, 5000);
    } catch (error) {
        console.error('Vote casting error:', error);
        showStatus('voteStatus', `Error: ${error.message}`, 'error');
    }
}

async function refreshLedger() {
    try {
        const response = await fetch('/api/ledger');
        if (!response.ok) throw new Error(await response.text());
        const ledger = await response.json();
        const totalEntries = document.getElementById('totalEntries');
        const latestBlockHash = document.getElementById('latestBlockHash');
        if (totalEntries && latestBlockHash) {
            totalEntries.textContent = ledger.length;
            latestBlockHash.textContent = ledger.length > 0 ? ledger[ledger.length - 1].hash : 'N/A';
        }
    } catch (error) {
        console.error('Ledger refresh error:', error);
        showStatus('voteStatus', `Error: ${error.message}`, 'error');
    }
}

async function exportLedger() {
    try {
        const response = await fetch('/api/ledger');
        if (!response.ok) throw new Error(await response.text());
        const ledger = await response.json();
        const blob = new Blob([JSON.stringify(ledger, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'ledger.json';
        a.click();
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Ledger export error:', error);
        showStatus('voteStatus', `Error: ${error.message}`, 'error');
    }
}

async function verifyVote() {
    const receiptID = document.getElementById('receiptIDInput').value;
    if (!receiptID) {
        showStatus('verificationResults', 'Please enter a receipt ID.', 'error');
        return;
    }

    try {
        const response = await fetch(`/api/verify-vote/${receiptID}`);
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        showStatus('verificationResults', `Vote verified: ${JSON.stringify(data, null, 2)}`, 'success');
    } catch (error) {
        console.error('Vote verification error:', error);
        showStatus('verificationResults', `Error: ${error.message}`, 'error');
    }
}

async function verifySignatures() {
    try {
        const response = await fetch('/api/verify-election');
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        showStatus('verificationResults', `Valid votes: ${data.validVotes}, Invalid votes: ${data.invalidVotes}`, 'success');
    } catch (error) {
        console.error('Signature verification error:', error);
        showStatus('verificationResults', `Error: ${error.message}`, 'error');
    }
}

async function verifyBlockchain() {
    try {
        const response = await fetch('/api/verify-blockchain');
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        showStatus('verificationResults', `Valid blocks: ${data.validBlocks}, Invalid blocks: ${data.invalidBlocks}`, 'success');
    } catch (error) {
        console.error('Blockchain verification error:', error);
        showStatus('verificationResults', `Error: ${error.message}`, 'error');
    }
}

// Attach event listeners
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('registrationForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        register();
    });
    document.getElementById('authForm')?.addEventListener('submit', (e) => {
        e.preventDefault();
        authenticate();
    });
    document.getElementById('ballotSection')?.addEventListener('submit', (e) => {
        e.preventDefault();
        castVote();
    });
});
