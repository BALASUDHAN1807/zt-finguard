-- Customer portal: profile, transfer methods and charges, self-protection, support tickets.
-- Idempotent: safe to run on every deploy.

-- ---------------------------------------------------------------- profile (auth owns identities)
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_status TEXT NOT NULL DEFAULT 'verified';
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;                      -- data: URL, PNG/JPEG <= 200 KB
ALTER TABLE users ADD COLUMN IF NOT EXISTS prefs JSONB NOT NULL DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS self_locked BOOLEAN NOT NULL DEFAULT false;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_email_key') THEN
    ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_kyc_check') THEN
    ALTER TABLE users ADD CONSTRAINT users_kyc_check CHECK (kyc_status IN ('pending','verified','rejected'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_avatar_size') THEN
    ALTER TABLE users ADD CONSTRAINT users_avatar_size CHECK (avatar IS NULL OR length(avatar) <= 280000);
  END IF;
END $$;
UPDATE users SET full_name = initcap(replace(username, '_', ' ')) WHERE full_name IS NULL;

ALTER TABLE known_devices ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- ---------------------------------------------------------------- accounts
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS account_type TEXT NOT NULL DEFAULT 'Savings';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS transfers_disabled BOOLEAN NOT NULL DEFAULT false;
UPDATE accounts SET account_type = 'Current' WHERE owner = 'meera' AND account_type = 'Savings';

-- ---------------------------------------------------------------- transfers
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS method TEXT NOT NULL DEFAULT 'internal';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS charges NUMERIC(10,2) NOT NULL DEFAULT 0;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS description TEXT;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'transactions_method_check') THEN
    ALTER TABLE transactions ADD CONSTRAINT transactions_method_check CHECK (method IN ('internal','imps','neft','rtgs'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'transactions_desc_len') THEN
    ALTER TABLE transactions ADD CONSTRAINT transactions_desc_len CHECK (description IS NULL OR length(description) <= 60);
  END IF;
END $$;

-- ---------------------------------------------------------------- support tickets (account service)
CREATE TABLE IF NOT EXISTS support_tickets (
    id          SERIAL PRIMARY KEY,
    owner       TEXT NOT NULL,
    category    TEXT NOT NULL CHECK (category IN ('general','fraud','access','device','recovery','investigation')),
    subject     TEXT NOT NULL CHECK (length(subject) BETWEEN 3 AND 120),
    body        TEXT NOT NULL CHECK (length(body) BETWEEN 3 AND 2000),
    tx_id       BIGINT,
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved','closed')),
    priority    TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('normal','high','urgent')),
    responses   JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS support_tickets_owner_idx ON support_tickets (owner, id DESC);

-- ---------------------------------------------------------------- least-privilege grants
GRANT UPDATE (full_name, email, email_verified, avatar, prefs, password_hash, password_changed_at, totp_secret,
              mobile, self_locked) ON users TO auth;
GRANT UPDATE (transfers_disabled) ON accounts TO account;
GRANT SELECT, INSERT, UPDATE ON support_tickets TO account;
GRANT USAGE ON SEQUENCE support_tickets_id_seq TO account;
GRANT INSERT (method, charges, description) ON transactions TO transaction;
