let adminToken = null;

// Utility to show status messages
function showStatus(elementId, message, type) {
    const statusClass = `status-${type}`;
    const statusHTML = `<div class="${statusClass}">${message}</div>`;
    document.getElementById(elementId).innerHTML = statusHTML;
}

// Admin login
async function adminLogin() {
    const email = document.getElementById('adminEmail').value;
    const password = document.getElementById('adminPassword').value;

    if (!email || !password) {
        showStatus('loginStatus', 'Please enter email and password.', 'error');
        return;
    }

    try {
        const response = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        if (!response.ok) throw new Error(await response.text());
        const { token } = await response.json();
        adminToken = token;
        document.getElementById('loginSection').style.display = 'none';
        document.getElementById('adminSection').style.display = 'block';
        fetchStats();
        refreshPendingCertificates();
        showStatus('adminStatus', 'Logged in successfully.', 'success');
    } catch (error) {
        showStatus('loginStatus', `Error: ${error.message}`, 'error');
    }
}

// Fetch election stats
async function fetchStats() {
    try {
        const response = await fetch('/api/admin/stats', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        if (!response.ok) throw new Error(await response.text());
        const stats = await response.json();
        document.getElementById('totalVoters').textContent = stats.totalVoters;
        document.getElementById('totalVotes').textContent = stats.totalVotes;
        document.getElementById('activeCerts').textContent = stats.activeCerts;
        document.getElementById('revokedCerts').textContent = stats.revokedCerts;
    } catch (error) {
        showStatus('adminStatus', `Error fetching stats: ${error.message}`, 'error');
    }
}

// Refresh pending certificate requests
async function refreshPendingCertificates() {
    try {
        const response = await fetch('/api/admin/pending-certificates', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        if (!response.ok) throw new Error(await response.text());
        const requests = await response.json();
        const certList = document.getElementById('certificateList');
        certList.innerHTML = requests.length ? requests.map(req => `
            <div class="certificate-entry">
                <input type="checkbox" value="${req.voter_id}" class="cert-checkbox">
                <span><strong>Name:</strong> ${req.name}</span>
                <span><strong>Voter ID:</strong> ${req.voter_id}</span>
                <span><strong>Request Date:</strong> ${new Date(req.request_date).toLocaleString()}</span>
            </div>
        `).join('') : '<p>No pending certificate requests.</p>';
    } catch (error) {
        showStatus('adminStatus', `Error fetching certificates: ${error.message}`, 'error');
    }
}

// Approve selected certificates
async function approveCertificates() {
    const selected = Array.from(document.querySelectorAll('.cert-checkbox:checked')).map(cb => cb.value);
    if (!selected.length) {
        showStatus('adminStatus', 'Please select at least one certificate.', 'error');
        return;
    }

    try {
        for (const voterID of selected) {
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
        refreshPendingCertificates();
        fetchStats();
        showStatus('adminStatus', 'Selected certificates approved.', 'success');
    } catch (error) {
        showStatus('adminStatus', `Error approving certificates: ${error.message}`, 'error');
    }
}

// Reject selected certificates
async function rejectCertificates() {
    const selected = Array.from(document.querySelectorAll('.cert-checkbox:checked')).map(cb => cb.value);
    if (!selected.length) {
        showStatus('adminStatus', 'Please select at least one certificate.', 'error');
        return;
    }

    try {
        for (const voterID of selected) {
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
        refreshPendingCertificates();
        fetchStats();
        showStatus('adminStatus', 'Selected certificates rejected.', 'success');
    } catch (error) {
        showStatus('adminStatus', `Error rejecting certificates: ${error.message}`, 'error');
    }
}

// Revoke certificate
async function revokeCertificate() {
    const voterID = document.getElementById('revokeVoterID').value;
    if (!voterID) {
        showStatus('adminStatus', 'Please enter a Voter ID.', 'error');
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
        document.getElementById('revokeVoterID').value = '';
        fetchStats();
        showStatus('adminStatus', 'Certificate revoked.', 'success');
    } catch (error) {
        showStatus('adminStatus', `Error revoking certificate: ${error.message}`, 'error');
    }
}

// Tally votes
async function tallyVotes() {
    try {
        const response = await fetch('/api/admin/tally-votes', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        if (!response.ok) throw new Error(await response.text());
        const results = await response.json();
        const resultsHTML = `
            <div class="status-box status-info">
                <h4>📊 Election Results</h4>
                ${Object.entries(results).map(([candidate, count]) => `<p><strong>${candidate}:</strong> ${count} votes</p>`).join('')}
            </div>
        `;
        document.getElementById('adminStatus').innerHTML = resultsHTML;
    } catch (error) {
        showStatus('adminStatus', `Error tallying votes: ${error.message}`, 'error');
    }
}

// Publish results
async function publishResults() {
    try {
        const response = await fetch('/api/admin/publish-results', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        if (!response.ok) throw new Error(await response.text());
        showStatus('adminStatus', 'Election results published to ledger.', 'success');
    } catch (error) {
        showStatus('adminStatus', `Error publishing results: ${error.message}`, 'error');
    }
}

// Logout
function logout() {
    adminToken = null;
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('adminSection').style.display = 'none';
    document.getElementById('adminEmail').value = '';
    document.getElementById('adminPassword').value = '';
    showStatus('loginStatus', 'Logged out successfully.', 'success');
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('adminSection').style.display = 'none';
    console.log('Admin Panel initialized');
});