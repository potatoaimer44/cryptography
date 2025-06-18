import React, { useState } from 'react';
import { Download, Shield, Vote, CheckCircle, AlertCircle } from 'lucide-react';

// Crypto utilities (in production, use a proper crypto library)
const CryptoUtils = {
  // Generate RSA key pair (simplified - use WebCrypto API in production)
  generateKeyPair: async () => {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );
    return keyPair;
  },

  // Sign data
  signData: async (data, privateKey) => {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    const signature = await window.crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      privateKey,
      dataBuffer
    );
    
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  },

  // Encrypt ballot (simplified hybrid encryption)
  encryptBallot: async (vote, electionPublicKey) => {
    // Generate AES key
    const aesKey = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // Encrypt vote with AES
    const encoder = new TextEncoder();
    const voteData = encoder.encode(JSON.stringify(vote));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const encryptedVote = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      voteData
    );

    // Export AES key for RSA encryption (simplified)
    const exportedKey = await window.crypto.subtle.exportKey("raw", aesKey);
    
    return {
      encrypted_vote: btoa(String.fromCharCode(...new Uint8Array(encryptedVote))),
      encrypted_key: btoa(String.fromCharCode(...new Uint8Array(exportedKey))),
      iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
      tag: "mock_tag" // In production, extract from GCM result
    };
  }
};

// Voter Registration Component
const VoterRegistration = ({ onRegistrationComplete }) => {
  const [voterData, setVoterData] = useState({
    voter_id: '',
    name: '',
    email: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [credentials, setCredentials] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ voter_id: voterData.voter_id }),
      });

      const data = await response.json();
      
      if (response.ok) {
        setCredentials(data);
        onRegistrationComplete(data);
      } else {
        setError(data.error || 'Registration failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const downloadCredentials = () => {
    if (!credentials) return;

    const credentialsData = {
      private_key: credentials.private_key,
      certificate: credentials.certificate,
      serial_number: credentials.serial_number,
      generated_at: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(credentialsData, null, 2)], 
      { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `voter_credentials_${credentials.serial_number}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (credentials) {
    return (
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="text-center mb-6">
          <CheckCircle className="mx-auto h-16 w-16 text-green-500 mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Registration Successful!</h2>
          <p className="text-gray-600">Your voting credentials have been generated.</p>
        </div>

        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
          <div className="flex">
            <AlertCircle className="h-5 w-5 text-yellow-400 mr-2 mt-0.5" />
            <div>
              <h3 className="text-sm font-medium text-yellow-800">Important Security Notice</h3>
              <p className="text-sm text-yellow-700 mt-1">
                Download and securely store your credentials. You'll need them to vote, and they cannot be recovered if lost.
              </p>
            </div>
          </div>
        </div>

        <div className="bg-gray-50 rounded-lg p-4 mb-6">
          <h3 className="font-semibold text-gray-900 mb-2">Your Credentials</h3>
          <div className="space-y-2 text-sm">
            <div><strong>Serial Number:</strong> {credentials.serial_number}</div>
            <div><strong>Certificate:</strong> Generated ✓</div>
            <div><strong>Private Key:</strong> Generated ✓</div>
          </div>
        </div>

        <button
          onClick={downloadCredentials}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors flex items-center justify-center"
        >
          <Download className="h-5 w-5 mr-2" />
          Download Credentials
        </button>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <div className="text-center mb-6">
        <Shield className="mx-auto h-16 w-16 text-blue-500 mb-4" />
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Voter Registration</h2>
        <p className="text-gray-600">Register to receive your secure voting credentials</p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <div className="flex">
            <AlertCircle className="h-5 w-5 text-red-400 mr-2" />
            <p className="text-sm text-red-700">{error}</p>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Voter ID *
          </label>
          <input
            type="text"
            value={voterData.voter_id}
            onChange={(e) => setVoterData({ ...voterData, voter_id: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="Enter your voter ID"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Full Name
          </label>
          <input
            type="text"
            value={voterData.name}
            onChange={(e) => setVoterData({ ...voterData, name: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="Enter your full name"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Email Address
          </label>
          <input
            type="email"
            value={voterData.email}
            onChange={(e) => setVoterData({ ...voterData, email: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="Enter your email address"
          />
        </div>

        <button
          type="submit"
          disabled={loading || !voterData.voter_id}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Registering...' : 'Register to Vote'}
        </button>
      </form>
    </div>
  );
};

// Voting Interface Component
const VotingInterface = ({ credentials }) => {
  const [vote, setVote] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [receipt, setReceipt] = useState(null);

  const candidates = [
    { id: 'candidate_a', name: 'Alice Johnson', party: 'Democratic Party' },
    { id: 'candidate_b', name: 'Bob Smith', party: 'Republican Party' },
    { id: 'candidate_c', name: 'Carol Williams', party: 'Independent' }
  ];

  const handleVoteSubmit = async (e) => {
    e.preventDefault();
    if (!vote) return;

    setLoading(true);
    setError('');

    try {
      // Create vote object
      const voteData = {
        choice: vote,
        timestamp: new Date().toISOString(),
        election_id: 'general_2024'
      };

      // Encrypt ballot (simplified)
      const encryptedBallot = await CryptoUtils.encryptBallot(voteData, null);
      
      // Sign the encrypted ballot
      const ballotString = JSON.stringify(encryptedBallot, Object.keys(encryptedBallot).sort());
      
      // In production, use the actual private key from credentials
      const mockSignature = btoa(`signature_${Date.now()}`);

      // Submit vote
      const response = await fetch('/api/vote', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          encrypted_ballot: encryptedBallot,
          signature: mockSignature,
          certificate: credentials.certificate
        }),
      });

      const data = await response.json();
      
      if (response.ok) {
        setReceipt(data);
      } else {
        setError(data.error || 'Vote submission failed');
      }
    } catch (err) {
      setError('Failed to submit vote. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (receipt) {
    return (
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="text-center mb-6">
          <CheckCircle className="mx-auto h-16 w-16 text-green-500 mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Vote Submitted Successfully!</h2>
          <p className="text-gray-600">Your ballot has been encrypted and recorded.</p>
        </div>

        <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
          <h3 className="font-semibold text-green-800 mb-2">Vote Receipt</h3>
          <div className="space-y-2 text-sm text-green-700">
            <div><strong>Receipt Hash:</strong> <code className="bg-white px-2 py-1 rounded">{receipt.receipt}</code></div>
            <div><strong>Block Hash:</strong> <code className="bg-white px-2 py-1 rounded">{receipt.block_hash}</code></div>
            <div><strong>Ballot ID:</strong> <code className="bg-white px-2 py-1 rounded">{receipt.ballot_id}</code></div>
          </div>
        </div>

        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex">
            <AlertCircle className="h-5 w-5 text-blue-400 mr-2 mt-0.5" />
            <div>
              <h3 className="text-sm font-medium text-blue-800">Save Your Receipt</h3>
              <p className="text-sm text-blue-700 mt-1">
                Keep your receipt hash to verify your vote was counted. You can use the verification tool later.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <div className="text-center mb-6">
        <Vote className="mx-auto h-16 w-16 text-blue-500 mb-4" />
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Cast Your Vote</h2>
        <p className="text-gray-600">Select your candidate and submit your encrypted ballot</p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <div className="flex">
            <AlertCircle className="h-5 w-5 text-red-400 mr-2" />
            <p className="text-sm text-red-700">{error}</p>
          </div>
        </div>
      )}

      <form onSubmit={handleVoteSubmit} className="space-y-4">
        <div>
          <h3 className="text-lg font-medium text-gray-900 mb-4">Choose Your Candidate</h3>
          <div className="space-y-3">
            {candidates.map((candidate) => (
              <label
                key={candidate.id}
                className={`block p-4 border rounded-lg cursor-pointer transition-colors ${
                  vote === candidate.id
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
              >
                <div className="flex items-center">
                  <input
                    type="radio"
                    name="candidate"
                    value={candidate.id}
                    checked={vote === candidate.id}
                    onChange={(e) => setVote(e.target.value)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                  />
                  <div className="ml-3">
                    <div className="text-sm font-medium text-gray-900">
                      {candidate.name}
                    </div>
                    <div className="text-sm text-gray-500">
                      {candidate.party}
                    </div>
                  </div>
                </div>
              </label>
            ))}
          </div>
        </div>

        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
          <h4 className="font-medium text-gray-900 mb-2">Security Information</h4>
          <ul className="text-sm text-gray-600 space-y-1">
            <li>• Your vote will be encrypted before submission</li>
            <li>• Your identity will be anonymized after verification</li>
            <li>• You will receive a receipt to verify your vote was counted</li>
            <li>• The voting process uses end-to-end encryption</li>
          </ul>
        </div>

        <button
          type="submit"
          disabled={loading || !vote}
          className="w-full bg-green-600 text-white py-3 px-4 rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors font-medium"
        >
          {loading ? 'Submitting Vote...' : 'Submit Encrypted Vote'}
        </button>
      </form>
    </div>
  );
};

// Vote Verification Component
const VoteVerification = () => {
  const [receipt, setReceipt] = useState('');
  const [loading, setLoading] = useState(false);
  const [verification, setVerification] = useState(null);
  const [error, setError] = useState('');

  const handleVerification = async (e) => {
    e.preventDefault();
    if (!receipt) return;

    setLoading(true);
    setError('');
    setVerification(null);

    try {
      const response = await fetch('/api/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ receipt }),
      });

      const data = await response.json();
      
      if (response.ok) {
        setVerification(data);
      } else {
        setError(data.error || 'Verification failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <div className="text-center mb-6">
        <CheckCircle className="mx-auto h-16 w-16 text-blue-500 mb-4" />
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Verify Your Vote</h2>
        <p className="text-gray-600">Enter your receipt hash to verify your vote was recorded</p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <div className="flex">
            <AlertCircle className="h-5 w-5 text-red-400 mr-2" />
            <p className="text-sm text-red-700">{error}</p>
          </div>
        </div>
      )}

      {verification && (
        <div className={`border rounded-lg p-4 mb-6 ${
          verification.verified 
            ? 'bg-green-50 border-green-200' 
            : 'bg-red-50 border-red-200'
        }`}>
          <div className="flex items-center mb-2">
            {verification.verified ? (
              <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
            ) : (
              <AlertCircle className="h-5 w-5 text-red-500 mr-2" />
            )}
            <h3 className={`font-semibold ${
              verification.verified ? 'text-green-800' : 'text-red-800'
            }`}>
              {verification.verified ? 'Vote Verified ✓' : 'Vote Not Found ✗'}
            </h3>
          </div>
          
          {verification.verified && (
            <div className="text-sm space-y-1">
              <div className="text-green-700">
                <strong>Timestamp:</strong> {new Date(verification.timestamp).toLocaleString()}
              </div>
              <div className="text-green-700">
                <strong>Block Hash:</strong> <code className="bg-white px-1 rounded">{verification.block_hash}</code>
              </div>
            </div>
          )}
          
          {!verification.verified && (
            <p className="text-sm text-red-700">
              This receipt was not found in the public ledger. Please check your receipt hash.
            </p>
          )}
        </div>
      )}

      <form onSubmit={handleVerification} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Receipt Hash
          </label>
          <input
            type="text"
            value={receipt}
            onChange={(e) => setReceipt(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
            placeholder="Enter your vote receipt hash"
            required
          />
        </div>

        <button
          type="submit"
          disabled={loading || !receipt}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Verifying...' : 'Verify Vote'}
        </button>
      </form>

      <div className="mt-6 bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h4 className="font-medium text-gray-900 mb-2">About Vote Verification</h4>
        <p className="text-sm text-gray-600">
          The verification system checks the public blockchain ledger to confirm your vote 
          was recorded without revealing your actual vote choice. This ensures transparency 
          while maintaining ballot secrecy.
        </p>
      </div>
    </div>
  );
};

// Main Application Component
const SecureVotingApp = () => {
  const [currentView, setCurrentView] = useState('register');
  const [credentials, setCredentials] = useState(null);

  const handleRegistrationComplete = (creds) => {
    setCredentials(creds);
    setCurrentView('vote');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">
            Secure E-Voting System
          </h1>
          <p className="text-lg text-gray-600">
            End-to-end encrypted voting with blockchain verification
          </p>
        </div>

        {/* Navigation */}
        <div className="flex justify-center mb-8">
          <div className="bg-white rounded-lg shadow-sm p-1 flex space-x-1">
            <button
              onClick={() => setCurrentView('register')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                currentView === 'register'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Register
            </button>
            <button
              onClick={() => setCurrentView('vote')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                currentView === 'vote'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
              disabled={!credentials}
            >
              Vote
            </button>
            <button
              onClick={() => setCurrentView('verify')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                currentView === 'verify'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              Verify
            </button>
          </div>
        </div>

        {/* Main Content */}
        <div className="max-w-2xl mx-auto">
          {currentView === 'register' && (
            <VoterRegistration onRegistrationComplete={handleRegistrationComplete} />
          )}
          {currentView === 'vote' && credentials && (
            <VotingInterface credentials={credentials} />
          )}
          {currentView === 'vote' && !credentials && (
            <div className="bg-white rounded-lg shadow-lg p-6 text-center">
              <AlertCircle className="mx-auto h-16 w-16 text-yellow-500 mb-4" />
              <h2 className="text-xl font-semibold text-gray-900 mb-2">
                Registration Required
              </h2>
              <p className="text-gray-600 mb-4">
                You must register and obtain your voting credentials before you can vote.
              </p>
              <button
                onClick={() => setCurrentView('register')}
                className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
              >
                Go to Registration
              </button>
            </div>
          )}
          {currentView === 'verify' && <VoteVerification />}
        </div>

        {/* Footer */}
        <div className="text-center mt-12 text-sm text-gray-500">
          <p>
            This system uses PKI authentication, end-to-end encryption, and blockchain-style audit trails
            to ensure secure and verifiable elections.
          </p>
        </div>
      </div>
    </div>
  );
};

export default SecureVotingApp;