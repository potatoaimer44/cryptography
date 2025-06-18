-- Secure E-Voting System Database Schema
-- PostgreSQL implementation with blockchain-style audit trail

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Voters table with anonymized data
CREATE TABLE voters (
    id SERIAL PRIMARY KEY,
    hashed_id VARCHAR(64) UNIQUE NOT NULL,
    cert_serial VARCHAR(32) UNIQUE NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    CONSTRAINT voters_hashed_id_check CHECK (length(hashed_id) = 64),
    CONSTRAINT voters_cert_serial_check CHECK (length(cert_serial) > 0)
);

-- Ballots table with blockchain-style chaining
CREATE TABLE ballots (
    id SERIAL PRIMARY KEY,
    ballot_id VARCHAR(64) UNIQUE NOT NULL,
    election_id VARCHAR(64) NOT NULL,
    encrypted_data TEXT NOT NULL,
    signature TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    block_hash VARCHAR(64) NOT NULL,
    prev_hash VARCHAR(64),
    nonce INTEGER DEFAULT 0,
    
    -- Blockchain integrity constraints
    CONSTRAINT ballots_ballot_id_check CHECK (length(ballot_id) = 64),
    CONSTRAINT ballots_block_hash_check CHECK (length(block_hash) = 64),
    CONSTRAINT ballots_prev_hash_check CHECK (prev_hash IS NULL OR length(prev_hash) = 64),
    FOREIGN KEY (election_id) REFERENCES elections(election_id)
);

-- Public ledger view for transparency (no sensitive data)
CREATE TABLE public_ledger (
    id SERIAL PRIMARY KEY,
    block_hash VARCHAR(64) UNIQUE NOT NULL,
    prev_hash VARCHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ballot_count INTEGER DEFAULT 1,
    merkle_root VARCHAR(64),
    
    -- Foreign key to maintain chain integrity
    FOREIGN KEY (block_hash) REFERENCES ballots(block_hash)
);

-- Certificate Revocation List
CREATE TABLE certificate_revocation_list (
    id SERIAL PRIMARY KEY,
    cert_serial VARCHAR(32) NOT NULL,
    revocation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(100),
    revoked_by VARCHAR(100),
    
    -- Prevent duplicate revocations
    CONSTRAINT crl_unique_serial UNIQUE (cert_serial)
);

-- Elections table for managing multiple elections
CREATE TABLE elections (
    id SERIAL PRIMARY KEY,
    election_id VARCHAR(64) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    public_key TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'upcoming',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT elections_status_check CHECK (status IN ('upcoming', 'active', 'ended', 'tallied'))
);

-- Candidates table
CREATE TABLE candidates (
    id SERIAL PRIMARY KEY,
    election_id VARCHAR(64) NOT NULL,
    candidate_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    party VARCHAR(255),
    description TEXT,
    
    FOREIGN KEY (election_id) REFERENCES elections(election_id),
    CONSTRAINT candidates_unique_per_election UNIQUE (election_id, candidate_id)
);

-- Audit log for all system activities
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(64),
    ip_address INET,
    user_agent TEXT,
    event_data JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Index for performance
    CONSTRAINT audit_log_event_type_check CHECK (event_type IN ('registration', 'vote', 'verification', 'admin_action'))
);

-- HSM key storage simulation (encrypted keys)
CREATE TABLE secure_keys (
    id SERIAL PRIMARY KEY,
    key_id VARCHAR(64) UNIQUE NOT NULL,
    key_type VARCHAR(20) NOT NULL,
    encrypted_key TEXT NOT NULL,
    salt VARCHAR(32) NOT NULL,
    iv VARCHAR(32) NOT NULL,
    tag VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT secure_keys_type_check CHECK (key_type IN ('election_private', 'ca_private', 'signing'))
);

-- Tally results (only accessible after election ends)
CREATE TABLE tally_results (
    id SERIAL PRIMARY KEY,
    election_id VARCHAR(64) NOT NULL,
    candidate_id VARCHAR(64) NOT NULL,
    vote_count INTEGER NOT NULL DEFAULT 0,
    percentage DECIMAL(5,2),
    tallied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (election_id) REFERENCES elections(election_id),
    FOREIGN KEY (candidate_id) REFERENCES candidates(candidate_id),
    CONSTRAINT tally_unique_per_candidate UNIQUE (election_id, candidate_id)
);

-- Indexes for better performance
CREATE INDEX idx_voters_hashed_id ON voters(hashed_id);
CREATE INDEX idx_voters_cert_serial ON voters(cert_serial);
CREATE INDEX idx_ballots_ballot_id ON ballots(ballot_id);
CREATE INDEX idx_ballots_timestamp ON ballots(timestamp);
CREATE INDEX idx_ballots_block_hash ON ballots(block_hash);
CREATE INDEX idx_ballots_election_id ON ballots(election_id);
CREATE INDEX idx_public_ledger_timestamp ON public_ledger(timestamp);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_crl_cert_serial ON certificate_revocation_list(cert_serial);

-- Functions for blockchain integrity
CREATE OR REPLACE FUNCTION calculate_merkle_root(block_hashes TEXT[])
RETURNS VARCHAR(64) AS $$
DECLARE
    current_level TEXT[];
    next_level TEXT[];
    i INTEGER;
BEGIN
    current_level := block_hashes;
    
    WHILE array_length(current_level, 1) > 1 LOOP
        next_level := ARRAY[]::TEXT[];
        
        FOR i IN 1..array_length(current_level, 1) BY 2 LOOP
            IF i + 1 <= array_length(current_level, 1) THEN
                next_level := array_append(next_level, 
                    encode(digest(current_level[i] || current_level[i+1], 'sha256'), 'hex'));
            ELSE
                next_level := array_append(next_level, current_level[i]);
            END IF;
        END LOOP;
        
        current_level := next_level;
    END LOOP;
    
    RETURN current_level[1];
END;
$$ LANGUAGE plpgsql;

-- Function to verify blockchain integrity
CREATE OR REPLACE FUNCTION verify_blockchain_integrity()
RETURNS BOOLEAN AS $$
DECLARE
    ballot_record RECORD;
    expected_hash VARCHAR(64);
    prev_hash_check VARCHAR(64) := '0000000000000000000000000000000000000000000000000000000000000000';
BEGIN
    FOR ballot_record IN 
        SELECT * FROM ballots ORDER BY id ASC
    LOOP
        -- Verify previous hash chain
        IF ballot_record.prev_hash != prev_hash_check THEN
            RETURN FALSE;
        END IF;
        
        -- Calculate expected hash
        expected_hash := encode(digest(
            ballot_record.encrypted_data || ballot_record.prev_hash || ballot_record.nonce::TEXT, 'sha256'
        ), 'hex');
        
        -- Verify block hash
        IF ballot_record.block_hash != expected_hash THEN
            RETURN FALSE;
        END IF;
        
        prev_hash_check := ballot_record.block_hash;
    END LOOP;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update public ledger
CREATE OR REPLACE FUNCTION update_public_ledger()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public_ledger (block_hash, prev_hash, timestamp, ballot_count)
    VALUES (NEW.block_hash, NEW.prev_hash, NEW.timestamp, 1)
    ON CONFLICT (block_hash) DO NOTHING;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ballot_to_ledger_trigger
    AFTER INSERT ON ballots
    FOR EACH ROW
    EXECUTE FUNCTION update_public_ledger();

-- Trigger to update timestamps
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER voters_update_timestamp
    BEFORE UPDATE ON voters
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();

-- Views for different access levels

-- Public audit view (no sensitive data)
CREATE VIEW public_audit_trail AS
SELECT 
    pl.id,
    pl.block_hash,
    pl.prev_hash,
    pl.timestamp,
    pl.ballot_count,
    pl.merkle_root
FROM public_ledger pl
ORDER BY pl.timestamp ASC;

-- Election statistics view
CREATE VIEW election_statistics AS
SELECT 
    e.election_id,
    e.title,
    e.status,
    COUNT(b.id) as total_votes,
    e.start_date,
    e.end_date
FROM elections e
LEFT JOIN ballots b ON b.election_id = e.election_id
GROUP BY e.election_id, e.title, e.status, e.start_date, e.end_date;

-- Revoked certificates view
CREATE VIEW revoked_certificates AS
SELECT 
    crl.cert_serial,
    crl.revocation_date,
    crl.reason,
    v.hashed_id
FROM certificate_revocation_list crl
JOIN voters v ON v.cert_serial = crl.cert_serial;

-- Security policies and permissions

-- Create roles
CREATE ROLE evoting_admin;
CREATE ROLE evoting_app;
CREATE ROLE evoting_auditor;
CREATE ROLE evoting_public;

-- Grant permissions to admin
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO evoting_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO evoting_admin;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO evoting_admin;

-- Grant permissions to application
GRANT SELECT, INSERT, UPDATE ON voters TO evoting_app;
GRANT SELECT, INSERT ON ballots TO evoting_app;
GRANT SELECT, INSERT ON certificate_revocation_list TO evoting_app;
GRANT SELECT ON elections TO evoting_app;
GRANT SELECT ON candidates TO evoting_app;
GRANT INSERT ON audit_log TO evoting_app;
GRANT SELECT, INSERT, UPDATE ON secure_keys TO evoting_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO evoting_app;

-- Grant permissions to auditor (read-only)
GRANT SELECT ON public_ledger TO evoting_auditor;
GRANT SELECT ON public_audit_trail TO evoting_auditor;
GRANT SELECT ON election_statistics TO evoting_auditor;
GRANT SELECT ON audit_log TO evoting_auditor;

-- Grant permissions to public (very limited)
GRANT SELECT ON public_audit_trail TO evoting_public;
GRANT SELECT ON election_statistics TO evoting_public;

-- Row Level Security (RLS) policies
ALTER TABLE voters ENABLE ROW LEVEL SECURITY;
ALTER TABLE ballots ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Policy for voters table (users can only see their own data via hashed_id)
CREATE POLICY voter_self_access ON voters
    FOR ALL TO evoting_app
    USING (hashed_id = current_setting('app.current_voter_hash', true));

-- Policy for audit log (restrict sensitive operations)
CREATE POLICY audit_log_access ON audit_log
    FOR INSERT TO evoting_app
    WITH CHECK (true);

-- Sample data for testing
INSERT INTO elections (election_id, title, description, start_date, end_date, public_key, status)
VALUES 
    ('general_2024', 'General Election 2024', 'Presidential and Congressional Elections', 
     '2024-11-01 00:00:00-00', '2024-11-30 23:59:59-00', 
     'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...', 'active');

INSERT INTO candidates (election_id, candidate_id, name, party, description)
VALUES 
    ('general_2024', 'candidate_a', 'Alice Johnson', 'Democratic Party', 'Former Senator'),
    ('general_2024', 'candidate_b', 'Bob Smith', 'Republican Party', 'Business Leader'),
    ('general_2024', 'candidate_c', 'Carol Williams', 'Independent', 'Community Organizer');

-- Function to validate vote submission
CREATE OR REPLACE FUNCTION validate_vote_submission(
    p_election_id VARCHAR,
    p_voter_hashed_id VARCHAR,
    p_ballot_id VARCHAR
)
RETURNS BOOLEAN AS $$
DECLARE
    election_status VARCHAR;
    voter_exists BOOLEAN;
    ballot_exists BOOLEAN;
BEGIN
    -- Check if election exists and is active
    SELECT status INTO election_status 
    FROM elections 
    WHERE election_id = p_election_id;
    
    IF NOT FOUND OR election_status != 'active' THEN
        RETURN FALSE;
    END IF;
    
    -- Check if voter exists and is not revoked
    SELECT EXISTS (
        SELECT 1 
        FROM voters 
        WHERE hashed_id = p_voter_hashed_id 
        AND revoked = FALSE
    ) INTO voter_exists;
    
    IF NOT voter_exists THEN
        RETURN FALSE;
    END IF;
    
    -- Check if ballot_id is unique
    SELECT EXISTS (
        SELECT 1 
        FROM ballots 
        WHERE ballot_id = p_ballot_id
    ) INTO ballot_exists;
    
    IF ballot_exists THEN
        RETURN FALSE;
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Function to update tally results
CREATE OR REPLACE FUNCTION update_tally_results(p_election_id VARCHAR)
RETURNS VOID AS $$
BEGIN
    -- Clear existing tallies for the election
    DELETE FROM tally_results WHERE election_id = p_election_id;
    
    -- Insert new tally results
    INSERT INTO tally_results (election_id, candidate_id, vote_count)
    SELECT 
        b.election_id,
        c.candidate_id,
        COUNT(b.id) as vote_count
    FROM ballots b
    JOIN candidates c ON b.encrypted_data LIKE '%' || c.candidate_id || '%'
    WHERE b.election_id = p_election_id
    GROUP BY b.election_id, c.candidate_id;
    
    -- Update percentages
    UPDATE tally_results tr
    SET percentage = (
        SELECT (tr.vote_count::DECIMAL / NULLIF(COUNT(b.id), 0)) * 100
        FROM ballots b
        WHERE b.election_id = p_election_id
    )
    WHERE tr.election_id = p_election_id;
END;
$$ LANGUAGE plpgsql;