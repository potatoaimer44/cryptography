let adminToken = null;

function showAdminStatus(message, type) {
    const element = document.getElementById('adminStatus');
    if (element) {
        element.textContent = message;
        element.className = type;
    } else {
        console.error('Admin status element not found');
    }
}

async function adminLogin() {
    const email = document.getElementById('adminEmailInput').value;
    const password = document.getElementById('adminPasswordInput').value;
    if (!email || !password) {
        showAdminStatus('Please provide email and password.', 'error');
        return;
    }

    try {
        const response = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        adminToken = data.token;
        showAdminStatus('Login successful!', 'success');

        const loginSection = document.getElementById('adminLoginSection');
        const panelSection = document.getElementById('adminPanelSection');
        if (loginSection && panelSection) {
            loginSection.style.display = 'none';
            panelSection.style.display = 'block';
        }
        fetchAdminStats();
        fetchPendingCertificates();
    } catch (error) {
        console.error('Admin login error:', error);
        showAdminStatus(`Error: ${error.message}`, 'error');
    }
}

async function fetchAdminStats() {
    try {
        const response = await fetch('/api/admin/stats', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        document.getElementById('registeredVoters').textContent = data.totalVoters;
        document.getElementById('votesCast').textContent = data.totalVotes;
        document.getElementById('activeCertificates').textContent = data.activeCerts;
        document.getElementById('revokedCertificates').textContent = data.revokedCerts;
    } catch (error) {
        console.error('Admin stats error:', error);
        showAdminStatus(`Error: ${error.message}`, 'error');
    }
}

async function fetchPendingCertificates() {
    try {
        const response = await fetch('/api/admin/pending-certificates', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        if (!response.ok) throw new Error(await response.text());
        const certificates = await response.json();
        const container = document.getElementById('pendingCertificates');
        container.innerHTML = '<h4>Pending Certificate Requests:</h4>';
        certificates.forEach(cert => {
            const div = document.createElement('div');
            div.innerHTML = `<input type="checkbox" value="${cert.voter_id}"> ${cert.name} (Voter ID: ${cert.voter_id}, Requested: ${new Date(cert.request_date).toLocaleString()})`;
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Pending certificates error:', error);
        showAdminStatus(`Error: ${error.message}`, 'error');
    }
}

async function approveCertificates() {
    const checkboxes = document.querySelectorAll('#pendingCertificates input:checked');
    const voterIDs = Array.from(checkboxes).map(cb => cb.value);
    if (voterIDs.length === 0) {
        showAdminStatus('Please select at least one certificate.', 'error');
        return;
    }

    try {
        for (const voterID of voterIDs) {
            const response = await fetch('/api/admin/approve-certificate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${adminToken}`
                },
                body: JSON.stringify({ voterID })
            });
            if (!response.ok) throw new Error(await response.text());
        }
        showAdminStatus('Certificates approved!', 'success');
        fetchPendingCertificates();
        fetchAdminStats();
    } catch (error) {
        console.error('Certificate approval error:', error);
        showAdminStatus(`Error: ${error.message}`, 'error');
    }
}

async function rejectCertificates() {
    const checkboxes = document.querySelectorAll('#pendingCertificates input:checked');
    const voterIDs = Array.from(checkboxes).map(cb => cb.value);
    if (voterIDs.length === 0) {
        showAdminStatus('Please select at least one certificate.', 'error');
        return;
    }

    try {
        for (const voterID of voterIDs) {
            const response = await fetch('/api/admin/reject-certificate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${adminToken}`
                },
                body: JSON.stringify({ voterID })
            });
            if (!response.ok) throw new Error(await response.text());
        }
        showAdminStatus('Certificates rejected!', 'success');
        fetchPendingCertificates();
        fetchAdminStats();
    } catch (error) {
        console.error('Certificate rejection error:', error);
        showAdminStatus(`Error: ${error.message}`, 'error');
    }
}

async function revokeCertificate() {
    const voterID = document.getElementById('revokeVoterID').value;
    if (!voterID) {
        showAdminStatus('Please enter a Voter ID.', 'error');
        return;
    }

    try {
        const response = await fetch('/api/admin/revoke-certificate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${adminToken}`
                },
                body: JSON.stringify({ voterID })
            });
            if (!response.ok) throw new Error(await response.text());
            showAdminStatus('Certificate revoked!', 'success');
            fetchAdminStats();
        } catch (error) {
            console.error('Certificate revocation error:', error);
            showAdminStatus(`Error: ${error.message}`, 'error');
        }
    }
    
    async function tallyVotes() {
        try {
            const response = await fetch('/api/admin/tally-votes', {
                headers: { 'Authorization': `Bearer ${adminToken}` }
            });
            if (!response.ok) throw new Error(await response.text());
            const results = await response.json();
            const resultsDiv = document.getElementById('tallyResults');
            resultsDiv.innerHTML = '<h4>Election Results:</h4>';
            for (const [candidate, count] of Object.entries(results)) {
                resultsDiv.innerHTML += `<p>${candidate}: ${count} votes</p>`;
            }
            showAdminStatus('Votes tallied!', 'success');
        } catch (error) {
            console.error('Vote tally error:', error);
            showAdminStatus(`Error: ${error.message}`, 'error');
        }
    }
    
    async function publishResults() {
        try {
            const response = await fetch('/api/admin/publish-results', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${adminToken}`
                }
            });
            if (!response.ok) throw new Error(await response.text());
            showAdminStatus('Results published!', 'success');
        } catch (error) {
            console.error('Publish results error:', error);
            showAdminStatus(`Error: ${error.message}`, 'error');
        }
    }
    
    function adminLogout() {
        adminToken = null;
        document.getElementById('adminLoginForm').reset();
        document.getElementById('adminLoginSection').style.display = 'block';
        document.getElementById('adminPanelSection').style.display = 'none';
        showAdminStatus('Logged out successfully.', 'success');
    }
    
    // Attach event listeners
    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('adminLoginForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            adminLogin();
        });
    });
