const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const forge = require('node-forge');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs'); // For directory creation
const multer = require('multer'); // For file uploads

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', express.static(path.join(__dirname, 'public/admin')));

const pool = new Pool({
    user: 'postgres',
    host: 'db',
    database: 'evoting',
    password: 'password',
    port: 5432
});

const JWT_SECRET = crypto.randomBytes(32).toString('hex');

const caKeyPair = forge.pki.rsa.generateKeyPair(2048);
const caCert = forge.pki.createCertificate();
caCert.publicKey = caKeyPair.publicKey;
caCert.serialNumber = '01';
caCert.validity.notBefore = new Date();
caCert.validity.notAfter = new Date();
caCert.validity.notAfter.setFullYear(caCert.validity.notBefore.getFullYear() + 10);
caCert.setSubject([{ name: 'commonName', value: 'Election CA' }]);
caCert.setIssuer([{ name: 'commonName', value: 'Election CA' }]);
caCert.sign(caKeyPair.privateKey, forge.md.sha256.create());

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send('Access denied');
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Invalid token');
        req.user = user;
        next();
    });
};

const authenticateAdmin = (req, res, next) => {
    authenticateToken(req, res, () => {
        if (!req.user.is_admin) return res.status(403).send('Admin access required');
        next();
    });
};

// --- Multer Configuration for Document Uploads ---
const userDocumentStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Documents will be stored in a subfolder named after the voterID
        // voterID should be available from the authenticateToken middleware
        const voterID = req.user ? req.user.voterID : null;
        if (!voterID) {
            return cb(new Error('Voter ID not found for upload destination.'), null);
        }
        const dir = path.join(__dirname, 'uploads/user_documents', voterID);
        // Create directory if it doesn't exist
        fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        // Sanitize documentType from body, default to 'other_document'
        const documentType = req.body.documentType ? req.body.documentType.replace(/[^a-z0-9_]/gi, '_') : 'other_document';
        const timestamp = Date.now();
        // Original extension
        const extension = path.extname(file.originalname);
        // New filename: voterID_documentType_timestamp.ext
        const voterID = req.user ? req.user.voterID : 'unknownVoter';
        cb(null, `${voterID}_${documentType}_${timestamp}${extension}`);
    }
});

// Admin: Get a specific document file for viewing
app.get('/api/admin/document-file/:documentId', authenticateAdmin, async (req, res) => {
    try {
        const { documentId } = req.params;
        const docResult = await pool.query(
            'SELECT file_path, file_name, mime_type FROM user_documents WHERE id = $1',
            [documentId]
        );

        if (docResult.rows.length === 0) {
            return res.status(404).send('Document not found.');
        }

        const document = docResult.rows[0];
        const absoluteFilePath = path.resolve(document.file_path); // multer stores absolute path or path relative to project root. Resolve ensures it's absolute.

        // Check if file exists
        if (!fs.existsSync(absoluteFilePath)) {
            console.error(`File not found at path: ${absoluteFilePath} for document ID: ${documentId}`);
            return res.status(404).send('File not found on server.');
        }

        // Set appropriate headers for inline display or download
        // For inline display of PDFs/images:
        res.setHeader('Content-Type', document.mime_type || 'application/octet-stream');
        // res.setHeader('Content-Disposition', `inline; filename="${document.original_file_name || document.file_name}"`);

        // Forcing download:
        // res.setHeader('Content-Disposition', `attachment; filename="${document.original_file_name || document.file_name}"`);

        res.sendFile(absoluteFilePath, (err) => {
            if (err) {
                console.error('Error sending file:', err);
                // Avoid sending another response if headers already sent
                if (!res.headersSent) {
                    res.status(500).send('Error serving the document.');
                }
            }
        });

    } catch (error) {
        console.error('Error retrieving document file:', error);
        if (!res.headersSent) {
            res.status(500).send('Server error while retrieving document.');
        }
    }
});

// Admin: Verify (Approve/Reject) a Document
app.post('/api/admin/verify-document', authenticateAdmin, async (req, res) => {
    const { documentId, status, verificationNotes } = req.body; // status should be 'approved' or 'rejected'
    const adminVoterId = req.user.voterID; // Admin who is performing the action

    if (!documentId || !status || !['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ message: 'Document ID and a valid status (approved/rejected) are required.' });
    }

    try {
        const docResult = await pool.query('SELECT * FROM user_documents WHERE id = $1', [documentId]);
        if (docResult.rows.length === 0) {
            return res.status(404).json({ message: 'Document not found.' });
        }
        // Optional: Check if document is already verified
        // if (docResult.rows[0].verification_status !== 'pending') {
        //     return res.status(400).json({ message: `Document is already ${docResult.rows[0].verification_status}.` });
        // }

        await pool.query(
            `UPDATE user_documents
             SET verification_status = $1, verification_notes = $2, verified_by_admin_id = $3, verification_date = NOW()
             WHERE id = $4`,
            [status, verificationNotes || null, adminVoterId, documentId]
        );

        // Potentially, update voter's overall verification status or trigger other actions here
        // For example, if all required documents are approved, mark voter as 'verified_identity' in 'voters' table.
        // This depends on more complex application logic not yet defined.

        res.status(200).json({ message: `Document ${documentId} has been ${status}.` });
    } catch (error) {
        console.error(`Error verifying document ${documentId}:`, error);
        res.status(500).json({ message: 'Failed to update document verification status.' });
    }
});

// Admin: Get Pending Documents for Verification
app.get('/api/admin/pending-documents', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                ud.id,
                ud.voter_id,
                v.name as voter_name,
                v.email as voter_email,
                ud.document_type,
                ud.file_name,
                ud.original_file_name,
                ud.upload_date,
                ud.verification_status
            FROM user_documents ud
            JOIN voters v ON ud.voter_id = v.voter_id
            WHERE ud.verification_status = 'pending'
            ORDER BY ud.upload_date ASC
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching pending documents:', error);
        res.status(500).send(error.message);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const mimetype = allowedTypes.test(file.mimetype);
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());

    if (mimetype && extname) {
        return cb(null, true);
    }
    cb(new Error('File type not supported. Only JPEG, PNG, and PDF are allowed.'), false);
};

const uploadUserDocument = multer({
    storage: userDocumentStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB file size limit
    fileFilter: fileFilter
}).single('documentFile'); // 'documentFile' is the name attribute of the file input in the form

// --- End Multer Configuration ---

app.post('/api/register', async (req, res) => {
    const { name, email, password, voterID, publicKey } = req.body;
    try {
        const spkiDer = Buffer.from(publicKey, 'base64');
        const publicKeyPem = forge.pki.publicKeyToPem(forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(spkiDer.toString('binary'))));
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO voters (name, email, password, voter_id, public_key, certificate_status, is_admin) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (voter_id) DO NOTHING RETURNING *',
            [name, email, hashedPassword, voterID, publicKeyPem, 'pending', false]
        );
        if (result.rowCount === 0) return res.status(400).send('Voter ID or email already exists');
        res.status(201).send('Voter registered');
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM voters WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).send('Invalid email or password');
        const user = result.rows[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(401).send('Invalid email or password');
        const token = jwt.sign({ name: user.name, email: user.email, voterID: user.voter_id, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, voterID: user.voter_id, name: user.name, email: user.email });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM voters WHERE email = $1 AND is_admin = TRUE', [email]);
        if (result.rows.length === 0) return res.status(401).send('Invalid admin credentials');
        const admin = result.rows[0];
        const isValid = await bcrypt.compare(password, admin.password);
        if (!isValid) return res.status(401).send('Invalid admin credentials');
        const token = jwt.sign({ email: admin.email, voterID: admin.voter_id, is_admin: true }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/request-certificate', async (req, res) => {
    const { voterID } = req.body;
    try {
        const result = await pool.query(
            'UPDATE voters SET certificate_status = $1 WHERE voter_id = $2 AND certificate_status = $3 RETURNING *',
            ['requested', voterID, 'pending']
        );
        if (result.rowCount === 0) return res.status(400).send('Invalid voter or certificate already requested');
        await pool.query(
            'INSERT INTO certificate_requests (voter_id, request_date, status) VALUES ($1, $2, $3) ON CONFLICT (voter_id) DO NOTHING',
            [voterID, new Date(), 'pending']
        );
        res.send('Certificate request submitted');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/auth-challenge/:voterID', async (req, res) => {
    const { voterID } = req.params;
    try {
        const result = await pool.query('SELECT * FROM voters WHERE voter_id = $1', [voterID]);
        if (result.rows.length === 0) return res.status(404).send('Voter not found');
        if (result.rows[0].certificate_status !== 'approved') return res.status(400).send('Certificate not approved');
        if (result.rows[0].has_voted) return res.status(400).send('Already voted');
        const challenge = crypto.randomBytes(32).toString('hex');
        await pool.query('UPDATE voters SET challenge = $1 WHERE voter_id = $2', [challenge, voterID]);
        res.json({ challenge });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/authenticate', async (req, res) => {
    const { voterID, signature } = req.body;
    try {
        const result = await pool.query('SELECT * FROM voters WHERE voter_id = $1', [voterID]);
        if (result.rows.length === 0) return res.status(404).send('Voter not found');
        const { public_key, challenge } = result.rows[0];

        const publicKey = forge.pki.publicKeyFromPem(public_key);
        const md = forge.md.sha256.create();
        md.update(challenge);
        const verified = publicKey.verify(md.digest().bytes(), Buffer.from(signature, 'base64').toString('binary'));
        if (!verified) return res.status(401).send('Invalid signature');

        await pool.query('UPDATE voters SET challenge = NULL WHERE voter_id = $1', [voterID]);
        res.send('Authentication successful');
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/cast-vote', authenticateToken, async (req, res) => {
    const { encryptedVote, aesKey, iv } = req.body;
    const voterID = req.user.voterID;
    try {
        if (!encryptedVote || !aesKey || !iv) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const voterResult = await pool.query('SELECT * FROM voters WHERE voter_id = $1', [voterID]);
        if (voterResult.rows.length === 0) {
            return res.status(404).json({ error: 'Voter not found' });
        }
        if (voterResult.rows[0].has_voted) {
            return res.status(400).json({ error: 'Already voted' });
        }

        const voteID = `VOTE_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
        const blockID = (await pool.query('SELECT COALESCE(MAX(block_id), 0) + 1 AS next_id FROM ledger')).rows[0].next_id;
        const previousBlock = await pool.query('SELECT hash FROM ledger ORDER BY block_id DESC LIMIT 1');
        const previousHash = previousBlock.rows.length ? previousBlock.rows[0].hash : '0';
        const timestamp = new Date();
        const hash = crypto.createHash('sha256').update(JSON.stringify({ voteID, encryptedVote, timestamp, previousHash })).digest('base64');

        await pool.query(
            'INSERT INTO votes (vote_id, voter_id, encrypted_vote, timestamp, aes_key, iv) VALUES ($1, $2, $3, $4, $5, $6)',
            [voteID, voterID, encryptedVote, timestamp, aesKey, iv]
        );

        await pool.query(
            'INSERT INTO ledger (block_id, vote_id, hash, previous_hash, timestamp) VALUES ($1, $2, $3, $4, $5)',
            [blockID, voteID, hash, previousHash, timestamp]
        );

        await pool.query('UPDATE voters SET has_voted = TRUE WHERE voter_id = $1', [voterID]);

        const receipt = { receiptID: voteID, timestamp, blockHash: hash };
        res.json({ receipt });
    } catch (error) {
        console.error('Vote casting error:', error);
        res.status(500).json({ error: error.message || 'Internal server error' });
    }
});

app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const voters = await pool.query('SELECT COUNT(*) FROM voters WHERE is_admin = FALSE');
        const votes = await pool.query('SELECT COUNT(*) FROM votes');
        const activeCerts = await pool.query('SELECT COUNT(*) FROM voters WHERE certificate_status = $1 AND is_admin = FALSE', ['approved']);
        const revokedCerts = await pool.query('SELECT COUNT(*) FROM voters WHERE certificate_status = $1 AND is_admin = FALSE', ['revoked']);
        res.json({
            totalVoters: parseInt(voters.rows[0].count),
            totalVotes: parseInt(votes.rows[0].count),
            activeCerts: parseInt(activeCerts.rows[0].count),
            revokedCerts: parseInt(revokedCerts.rows[0].count)
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/admin/pending-certificates', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT v.name, v.voter_id, cr.request_date FROM voters v JOIN certificate_requests cr ON v.voter_id = cr.voter_id WHERE cr.status = $1', ['pending']);
        res.json(result.rows);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/approve-certificate', authenticateAdmin, async (req, res) => {
    const { voterID } = req.body;
    try {
        const voterResult = await pool.query('SELECT * FROM voters WHERE voter_id = $1 AND is_admin = FALSE', [voterID]);
        if (voterResult.rows.length === 0) return res.status(404).send('Voter not found');

        const publicKeyPem = voterResult.rows[0].public_key;
        let publicKey;
        try {
            publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
        } catch (error) {
            console.error('Invalid public key format for voter:', voterID, error);
            return res.status(400).send('Invalid public key format');
        }

        const cert = forge.pki.createCertificate();
        cert.publicKey = publicKey;
        cert.serialNumber = crypto.randomBytes(8).toString('hex');
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        cert.setSubject([{ name: 'commonName', value: voterResult.rows[0].name }, { name: 'emailAddress', value: voterResult.rows[0].email }]);
        cert.setIssuer(caCert.subject.attributes);
        cert.sign(caKeyPair.privateKey, forge.md.sha256.create());

        await pool.query(
            'UPDATE voters SET certificate_status = $1, certificate = $2 WHERE voter_id = $3',
            ['approved', forge.pki.certificateToPem(cert), voterID]
        );
        await pool.query('UPDATE certificate_requests SET status = $1 WHERE voter_id = $2', ['approved', voterID]);
        res.send('Certificate approved');
    } catch (error) {
        console.error('Certificate approval error:', error);
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/reject-certificate', authenticateAdmin, async (req, res) => {
    const { voterID } = req.body;
    try {
        await pool.query('UPDATE voters SET certificate_status = $1 WHERE voter_id = $2 AND is_admin = FALSE', ['rejected', voterID]);
        await pool.query('UPDATE certificate_requests SET status = $1 WHERE voter_id = $2', ['rejected', voterID]);
        res.send('Certificate rejected');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/revoke-certificate', authenticateAdmin, async (req, res) => {
    const { voterID } = req.body;
    try {
        await pool.query('UPDATE voters SET certificate_status = $1 WHERE voter_id = $2 AND is_admin = FALSE', ['revoked', voterID]);
        res.send('Certificate revoked');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/admin/tally-votes', authenticateAdmin, async (req, res) => {
    try {
        const votes = await pool.query('SELECT encrypted_vote, aes_key, iv FROM votes');
        const results = {};
        for (const vote of votes.rows) {
            try {
                const aesKey = await crypto.webcrypto.subtle.importKey(
                    "raw",
                    Buffer.from(vote.aes_key, 'base64'),
                    { name: "AES-GCM" },
                    false,
                    ["decrypt"]
                );
                const decrypted = await crypto.webcrypto.subtle.decrypt(
                    { name: "AES-GCM", iv: Buffer.from(vote.iv, 'base64') },
                    aesKey,
                    Buffer.from(vote.encrypted_vote, 'base64')
                );
                const voteData = JSON.parse(new TextDecoder().decode(decrypted));
                results[voteData.candidate] = (results[voteData.candidate] || 0) + 1;
            } catch (error) {
                console.error('Error decrypting vote:', error);
            }
        }
        res.json(results);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.post('/api/admin/publish-results', authenticateAdmin, async (req, res) => {
    try {
        const votes = await pool.query('SELECT encrypted_vote, aes_key, iv FROM votes');
        const results = {};
        for (const vote of votes.rows) {
            try {
                const aesKey = await crypto.webcrypto.subtle.importKey(
                    "raw",
                    Buffer.from(vote.aes_key, 'base64'),
                    { name: "AES-GCM" },
                    false,
                    ["decrypt"]
                );
                const decrypted = await crypto.webcrypto.subtle.decrypt(
                    { name: "AES-GCM", iv: Buffer.from(vote.iv, 'base64') },
                    aesKey,
                    Buffer.from(vote.encrypted_vote, 'base64')
                );
                const voteData = JSON.parse(new TextDecoder().decode(decrypted));
                results[voteData.candidate] = (results[voteData.candidate] || 0) + 1;
            } catch (error) {
                console.error('Error decrypting vote:', error);
            }
        }

        const blockID = (await pool.query('SELECT COALESCE(MAX(block_id), 0) + 1 AS next_id FROM ledger')).rows[0].next_id;
        const previousBlock = await pool.query('SELECT hash FROM ledger ORDER BY block_id DESC LIMIT 1');
        const previousHash = previousBlock.rows.length ? previousBlock.rows[0].hash : '0';
        const timestamp = new Date();
        const hash = crypto.createHash('sha256').update(JSON.stringify({ type: 'RESULTS', data: results, timestamp, previousHash })).digest('base64');

        await pool.query(
            'INSERT INTO ledger (block_id, type, data, hash, previous_hash, timestamp) VALUES ($1, $2, $3, $4, $5, $6)',
            [blockID, 'RESULTS', JSON.stringify(results), hash, previousHash, timestamp]
        );
        res.send('Results published');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Endpoint for User Document Upload
app.post('/api/user/upload-document', authenticateToken, (req, res) => {
    uploadUserDocument(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            // A Multer error occurred when uploading.
            console.error('Multer error:', err);
            return res.status(400).json({ message: `File upload error: ${err.message}` });
        } else if (err) {
            // An unknown error occurred when uploading.
            console.error('Unknown upload error:', err);
            return res.status(500).json({ message: `File upload error: ${err.message}` });
        }

        // Everything went fine with multer, file is uploaded.
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded.' });
        }

        const { voterID } = req.user; // From authenticateToken
        const { documentType } = req.body;
        const { path: filePath, filename: fileName, originalname: originalFileName, mimetype: mimeType } = req.file;


        if (!documentType) {
            // Should ideally be caught by client-side validation too
            // If file uploaded but type missing, we might want to delete the orphaned file
            fs.unlink(filePath, (unlinkErr) => {
                if (unlinkErr) console.error("Error deleting orphaned file:", unlinkErr);
            });
            return res.status(400).json({ message: 'Document type is required.' });
        }

        try {
            // Store document metadata in the database
            const dbResult = await pool.query(
                'INSERT INTO user_documents (voter_id, document_type, file_path, file_name, original_file_name, mime_type, verification_status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
                [voterID, documentType, filePath, fileName, originalFileName, mimeType, 'pending']
            );

            console.log(`Document metadata saved to DB for VoterID: ${voterID}, Type: ${documentType}, DB ID: ${dbResult.rows[0].id}`);

            res.status(200).json({
                message: 'Document uploaded successfully. Awaiting verification.',
                filename: fileName,
                docId: dbResult.rows[0].id
                // filePath: `/uploads/user_documents/${voterID}/${fileName}` // Client doesn't strictly need this back
            });

        } catch (dbError) {
            console.error('Database error after file upload:', dbError);
            // Attempt to delete the uploaded file if DB operation fails
            fs.unlink(filePath, (unlinkErr) => {
                if (unlinkErr) console.error("Error deleting file after DB error:", unlinkErr);
            });
            res.status(500).json({ message: 'Failed to record document information.' });
        }
    });
});


app.get('/api/ledger', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM ledger ORDER BY block_id');
        res.json(result.rows);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/verify-vote/:receiptID', async (req, res) => {
    const { receiptID } = req.params;
    try {
        const voteResult = await pool.query('SELECT * FROM votes WHERE vote_id = $1', [receiptID]);
        if (voteResult.rows.length === 0) return res.status(404).send('Vote not found');
        const ledgerResult = await pool.query('SELECT * FROM ledger WHERE vote_id = $1', [receiptID]);
        if (ledgerResult.rows.length === 0) return res.status(404).send('Ledger entry not found');
        res.json({ vote: voteResult.rows[0], ledgerEntry: ledgerResult.rows[0] });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/verify-election', async (req, res) => {
    try {
        const votes = await pool.query('SELECT encrypted_vote, aes_key, iv FROM votes');
        let validVotes = 0;
        let invalidVotes = 0;
        for (const vote of votes.rows) {
            try {
                const aesKey = await crypto.webcrypto.subtle.importKey(
                    "raw",
                    Buffer.from(vote.aes_key, 'base64'),
                    { name: "AES-GCM" },
                    false,
                    ["decrypt"]
                );
                const decrypted = await crypto.webcrypto.subtle.decrypt(
                    { name: "AES-GCM", iv: Buffer.from(vote.iv, 'base64') },
                    aesKey,
                    Buffer.from(vote.encrypted_vote, 'base64')
                );
                validVotes++;
            } catch (error) {
                invalidVotes++;
            }
        }
        res.json({ validVotes, invalidVotes });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/api/verify-blockchain', async (req, res) => {
    try {
        const ledger = await pool.query('SELECT * FROM ledger ORDER BY block_id');
        let validBlocks = 0;
        let invalidBlocks = 0;
        for (let i = 0; i < ledger.rows.length; i++) {
            const block = ledger.rows[i];
            const expectedHash = crypto.createHash('sha256').update(JSON.stringify({
                block_id: block.block_id,
                vote_id: block.vote_id,
                type: block.type,
                data: block.data,
                previous_hash: block.previous_hash,
                timestamp: block.timestamp
            })).digest('base64');
            const isValid = expectedHash === block.hash && (i === 0 || block.previous_hash === ledger.rows[i-1].hash);
            if (isValid) validBlocks++;
            else invalidBlocks++;
        }
        res.json({ validBlocks, invalidBlocks });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

async function initializeDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS voters (
                voter_id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT NOT NULL,
                certificate_status VARCHAR(20) NOT NULL,
                certificate TEXT,
                has_voted BOOLEAN DEFAULT FALSE,
                challenge TEXT,
                is_admin BOOLEAN DEFAULT FALSE
            );
            CREATE TABLE IF NOT EXISTS certificate_requests (
                voter_id VARCHAR(50) PRIMARY KEY REFERENCES voters(voter_id),
                request_date TIMESTAMP NOT NULL,
                status VARCHAR(20) NOT NULL
            );
            CREATE TABLE IF NOT EXISTS votes (
                vote_id VARCHAR(50) PRIMARY KEY,
                voter_id VARCHAR(50) REFERENCES voters(voter_id),
                encrypted_vote TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                aes_key TEXT,
                iv TEXT
            );
            CREATE TABLE IF NOT EXISTS ledger (
                block_id SERIAL PRIMARY KEY,
                vote_id VARCHAR(50),
                type VARCHAR(20),
                data JSONB,
                hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_documents (
                id SERIAL PRIMARY KEY,
                voter_id VARCHAR(50) REFERENCES voters(voter_id) ON DELETE CASCADE,
                document_type VARCHAR(50) NOT NULL,
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                original_file_name TEXT,
                mime_type VARCHAR(100),
                upload_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                verification_status VARCHAR(20) NOT NULL DEFAULT 'pending', -- e.g., pending, approved, rejected
                verified_by_admin_id VARCHAR(50) REFERENCES voters(voter_id) ON DELETE SET NULL, -- Assuming admins are also in voters table
                verification_date TIMESTAMP,
                verification_notes TEXT
            );
        `);

        const demoAdmin = await pool.query('SELECT * FROM voters WHERE email = $1', ['aayush@admin.com']);
        if (demoAdmin.rows.length === 0) {
            const keyPair = forge.pki.rsa.generateKeyPair(2048);
            const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
            const hashedPassword = await bcrypt.hash('adminadmin', 10);
            await pool.query(
                'INSERT INTO voters (voter_id, name, email, password, public_key, certificate_status, is_admin) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                ['ADMIN_001', 'Admin User', 'aayush@admin.com', hashedPassword, publicKeyPem, 'approved', true]
            );
            console.log('Demo admin account created');
        }
    } catch (error) {
        console.error('Database initialization error:', error);
        process.exit(1);
    }
}

initializeDatabase().then(() => {
    app.listen(3000, () => {
        console.log('Server running on port 3000');
    });
});