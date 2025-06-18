const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');

const app = express();
const port = process.env.PORT || 3001;

// Serve static files from the React build
app.use(express.static(path.join(__dirname, 'build')));

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// Database connection
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'db',
  database: process.env.DB_NAME || 'evoting',
  password: process.env.DB_PASSWORD || 'your_password',
  port: process.env.DB_PORT || 5432,
});

// JWT secret (store in environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Utility functions
const generateHashedId = (voterId) => {
  return crypto.createHash('sha256').update(voterId + Date.now().toString()).digest('hex');
};

const generateCertSerial = () => {
  return crypto.randomBytes(16).toString('hex');
};

const generateBallotId = () => {
  return crypto.randomBytes(32).toString('hex');
};

const calculateBlockHash = (encryptedData, prevHash, nonce) => {
  return crypto
    .createHash('sha256')
    .update(encryptedData + (prevHash || '') + nonce.toString())
    .digest('hex');
};

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// API Endpoints

// Voter Registration
app.post('/api/register', async (req, res) => {
  const { voter_id } = req.body;

  if (!voter_id) {
    return res.status(400).json({ error: 'Voter ID is required' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const hashedId = generateHashedId(voter_id);
    const certSerial = generateCertSerial();

    // Generate mock key pair (in production, use proper PKI infrastructure)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    // Store voter
    await client.query(
      'INSERT INTO voters (hashed_id, cert_serial) VALUES ($1, $2) RETURNING *',
      [hashedId, certSerial]
    );

    // Log registration
    await client.query(
      'INSERT INTO audit_log (event_type, user_id, event_data, ip_address) VALUES ($1, $2, $3, $4)',
      [
        'registration',
        hashedId,
        JSON.stringify({ voter_id: voter_id }),
        req.ip,
      ]
    );

    await client.query('COMMIT');

    // Generate JWT
    const token = jwt.sign({ hashed_id: hashedId }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      private_key: privateKey,
      certificate: publicKey,
      serial_number: certSerial,
      token,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  } finally {
    client.release();
  }
});

// Vote Submission
app.post('/api/vote', authenticateToken, async (req, res) => {
  const { encrypted_ballot, signature, certificate } = req.body;
  const hashedId = req.user.hashed_id;

  if (!encrypted_ballot || !signature || !certificate) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const electionId = 'general_2024'; // Hardcoded for demo; dynamically fetch in production
    const ballotId = generateBallotId();

    // Validate vote submission
    const validationResult = await client.query(
      'SELECT validate_vote_submission($1, $2, $3) AS valid',
      [electionId, hashedId, ballotId]
    );

    if (!validationResult.rows[0].valid) {
      throw new Error('Invalid vote submission');
    }

    // Get previous block hash
    const prevBlock = await client.query(
      'SELECT block_hash FROM ballots ORDER BY id DESC LIMIT 1'
    );
    const prevHash = prevBlock.rows.length ? prevBlock.rows[0].block_hash : null;

    // Calculate block hash
    const nonce = Math.floor(Math.random() * 1000000);
    const encryptedData = JSON.stringify(encrypted_ballot);
    const blockHash = calculateBlockHash(encryptedData, prevHash, nonce);

    // Store ballot
    const ballotResult = await client.query(
      `INSERT INTO ballots (ballot_id, election_id, encrypted_data, signature, block_hash, prev_hash, nonce)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [ballotId, electionId, encryptedData, signature, blockHash, prevHash, nonce]
    );

    // Log vote
    await client.query(
      'INSERT INTO audit_log (event_type, user_id, event_data, ip_address) VALUES ($1, $2, $3, $4)',
      [
        'vote',
        hashedId,
        JSON.stringify({ ballot_id: ballotId, election_id: electionId }),
        req.ip,
      ]
    );

    await client.query('COMMIT');

    res.json({
      receipt: crypto.createHash('sha256').update(ballotId).digest('hex'),
      block_hash: blockHash,
      ballot_id: ballotId,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Vote submission error:', err);
    res.status(500).json({ error: 'Vote submission failed' });
  } finally {
    client.release();
  }
});

// Vote Verification
app.post('/api/verify', async (req, res) => {
  const { receipt } = req.body;

  if (!receipt) {
    return res.status(400).json({ error: 'Receipt hash is required' });
  }

  try {
    // Find ballot by receipt hash
    const ballotResult = await pool.query(
      `SELECT b.*, pl.timestamp
       FROM ballots b
       JOIN public_ledger pl ON b.block_hash = pl.block_hash
       WHERE b.ballot_id = (
         SELECT ballot_id FROM ballots
         WHERE encode(sha256(ballot_id::bytea), 'hex') = $1
       )`,
      [receipt]
    );

    if (!ballotResult.rows.length) {
      return res.json({ verified: false });
    }

    const ballot = ballotResult.rows[0];

    res.json({
      verified: true,
      timestamp: ballot.timestamp,
      block_hash: ballot.block_hash,
    });
  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Catch-all route to serve React's index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Error handling
process.on('unhandledRejection', (err) => {
  console.error('Unhandled promise rejection:', err);
});