const { Pool } = require('pg');
const faker = require('faker');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Use the same DB config as in server.js
const pool = new Pool({
  user: 'postgres',
  host: 'db', // changed from 'localhost'
  database: 'evoting',
  password: 'password',
  port: 5432,
});

async function insertTestData() {
  try {
    console.log('Inserting 500 test voters, votes, and ledger entries...');
    for (let i = 1; i <= 500; i++) {
      // --- VOTER ---
      const voter_id = `VOTER_${i.toString().padStart(4, '0')}`;
      const name = faker.name.findName();
      const email = `testuser${i}@example.com`;
      const password = await bcrypt.hash('password123', 10);
      const public_key = `-----BEGIN PUBLIC KEY-----\n${faker.random.alphaNumeric(128)}\n-----END PUBLIC KEY-----`;
      const certificate_status = 'approved';
      const certificate = `CERTIFICATE_${i}`;
      const has_voted = true;
      const challenge = null;
      const is_admin = false;
      const citizenship_image_path = null;
      const citizenship_image_status = 'approved';

      await pool.query(
        `INSERT INTO voters (voter_id, name, email, password, public_key, certificate_status, certificate, has_voted, challenge, is_admin, citizenship_image_path, citizenship_image_status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT (voter_id) DO NOTHING`,
        [voter_id, name, email, password, public_key, certificate_status, certificate, has_voted, challenge, is_admin, citizenship_image_path, citizenship_image_status]
      );

      // --- VOTE ---
      const vote_id = `VOTE_${i.toString().padStart(4, '0')}`;
      // Pick a candidate at random
      const candidateList = ['candidate1', 'candidate2', 'candidate3'];
      const candidate = candidateList[Math.floor(Math.random() * candidateList.length)];
      // Simulate the real encrypted_vote: base64-encoded JSON with candidate field
      const voteData = {
        candidate,
        timestamp: timestamp.toISOString ? timestamp.toISOString() : new Date(timestamp).toISOString(),
        voterIDHash: crypto.createHash('sha256').update(voter_id).digest('base64')
      };
      const encrypted_vote = Buffer.from(JSON.stringify(voteData)).toString('base64');
      const timestamp = new Date(Date.now() - faker.random.number({min:0,max:1000000000}));
      const aes_key = crypto.randomBytes(32).toString('base64');
      const iv = crypto.randomBytes(12).toString('base64');

      await pool.query(
        `INSERT INTO votes (vote_id, voter_id, encrypted_vote, timestamp, aes_key, iv)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (vote_id) DO NOTHING`,
        [vote_id, voter_id, encrypted_vote, timestamp, aes_key, iv]
      );

      // --- LEDGER ---
      const block_id = i; // sequential
      const type = null;
      const data = null;
      const previous_hash = i === 1 ? '0' : crypto.createHash('sha256').update(`block_${i-1}`).digest('hex');
      const hash = crypto.createHash('sha256').update(`${vote_id}${encrypted_vote}${timestamp}${previous_hash}`).digest('hex');

      await pool.query(
        `INSERT INTO ledger (block_id, vote_id, type, data, hash, previous_hash, timestamp)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (block_id) DO NOTHING`,
        [block_id, vote_id, type, data, hash, previous_hash, timestamp]
      );

      if (i % 50 === 0) console.log(`Inserted ${i} records...`);
    }
    console.log('Done!');
  } catch (err) {
    console.error('Error inserting test data:', err);
  } finally {
    await pool.end();
  }
}

insertTestData(); 