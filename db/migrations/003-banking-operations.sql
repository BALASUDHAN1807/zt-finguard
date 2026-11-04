-- Admin module 3: Banking & Transactions with a separate Operations role.
-- Idempotent; deploy.sh applies every file in db/migrations on each deployment.

-- 1. operations role (maker-checker banking staff, separate from security admins)
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('customer','teller','admin','operations'));

-- 2. account status (freeze) and daily limit
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS frozen_reason TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS frozen_by TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS frozen_at TIMESTAMPTZ;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS daily_limit NUMERIC(14,2) NOT NULL DEFAULT 100000;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS limit_updated_by TEXT;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_status_check') THEN
    ALTER TABLE accounts ADD CONSTRAINT accounts_status_check CHECK (status IN ('active','frozen'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_daily_limit_check') THEN
    ALTER TABLE accounts ADD CONSTRAINT accounts_daily_limit_check CHECK (daily_limit > 0 AND daily_limit <= 10000000);
  END IF;
END $$;

-- 3. transfer lifecycle: high-value transfers wait for approval; can be cancelled / rejected
ALTER TABLE transactions DROP CONSTRAINT IF EXISTS transactions_status_check;
ALTER TABLE transactions ADD CONSTRAINT transactions_status_check CHECK (status IN
  ('completed','denied','step_up_required','pending_approval','cancelled','rejected'));
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS decided_by TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS decided_at TIMESTAMPTZ;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS decision_note TEXT;
CREATE INDEX IF NOT EXISTS transactions_status_idx ON transactions (status, created_at DESC);

-- 4. saved payees
CREATE TABLE IF NOT EXISTS beneficiaries (
    id          SERIAL PRIMARY KEY,
    owner       TEXT NOT NULL,
    account_no  TEXT NOT NULL,
    nickname    TEXT NOT NULL CHECK (length(nickname) BETWEEN 1 AND 40),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner, account_no)
);

-- 5. least privilege for the new columns / table
GRANT UPDATE (status, frozen_reason, frozen_by, frozen_at, daily_limit, limit_updated_by) ON accounts TO account;
GRANT SELECT, INSERT, DELETE ON beneficiaries TO account;
GRANT USAGE ON SEQUENCE beneficiaries_id_seq TO account;
GRANT UPDATE (status, decided_by, decided_at, decision_note) ON transactions TO transaction;
