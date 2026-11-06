-- Teller portal: branch cash, counter transactions, dual-control approvals, identity verification.
-- Idempotent: safe to run on every deploy.

-- ---------------------------------------------------------------- staff identity
ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS branch TEXT;
UPDATE users SET employee_id = 'TLR-1001', branch = 'ZT-FinGuard Digital Branch, Chennai (ZTFG0000001)'
 WHERE username = 'teller' AND employee_id IS NULL;
UPDATE users SET employee_id = 'OPS-2001', branch = 'ZT-FinGuard Digital Branch, Chennai (ZTFG0000001)'
 WHERE username = 'ops' AND employee_id IS NULL;
UPDATE users SET employee_id = 'SEC-3001', branch = 'Head office - Security Operations'
 WHERE username = 'admin' AND employee_id IS NULL;

-- ---------------------------------------------------------------- branch cash vault
-- Deposits are vault -> customer, withdrawals customer -> vault, so every existing report,
-- statement and join keeps working. Customers can never send money to the vault online.
INSERT INTO accounts (user_id, owner, account_no, balance, account_type)
VALUES (0, '__branch_cash__', 'ZT0000000001', 900000000, 'Branch cash')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------- counter transactions
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS channel TEXT NOT NULL DEFAULT 'online';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'transfer';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS initiated_by TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS verification_id TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS approvals_required INT NOT NULL DEFAULT 1;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'transactions_channel_check') THEN
    ALTER TABLE transactions ADD CONSTRAINT transactions_channel_check CHECK (channel IN ('online','branch'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'transactions_kind_check') THEN
    ALTER TABLE transactions ADD CONSTRAINT transactions_kind_check CHECK (kind IN ('transfer','deposit','withdrawal'));
  END IF;
END $$;
ALTER TABLE transactions DROP CONSTRAINT IF EXISTS transactions_status_check;
ALTER TABLE transactions ADD CONSTRAINT transactions_status_check CHECK (status IN
  ('completed','denied','step_up_required','pending_approval','cancelled','rejected','on_hold','mfa_requested'));

-- dual control: one row per approval decision (who, role, when, remarks)
CREATE TABLE IF NOT EXISTS transaction_approvals (
    id          BIGSERIAL PRIMARY KEY,
    tx_id       BIGINT NOT NULL,
    approver    TEXT NOT NULL,
    role        TEXT NOT NULL,
    decision    TEXT NOT NULL CHECK (decision IN ('approve','reject','hold','request_mfa','customer_confirmed','release')),
    remarks     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS transaction_approvals_tx_idx ON transaction_approvals (tx_id, id);

-- ---------------------------------------------------------------- counter identity verification (auth)
CREATE TABLE IF NOT EXISTS identity_verifications (
    id          TEXT PRIMARY KEY,
    customer    TEXT NOT NULL,
    teller      TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    required    TEXT NOT NULL CHECK (required IN ('sms','sms+totp')),
    status      TEXT NOT NULL DEFAULT 'started' CHECK (status IN ('started','passed','failed','expired')),
    attempts    INT NOT NULL DEFAULT 0,
    checks      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_verifications_customer_idx ON identity_verifications (customer, created_at DESC);
CREATE INDEX IF NOT EXISTS identity_verifications_teller_idx ON identity_verifications (teller, created_at DESC);

-- support tickets can be opened by staff for a customer
ALTER TABLE support_tickets ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE support_tickets DROP CONSTRAINT IF EXISTS support_tickets_category_check;
ALTER TABLE support_tickets ADD CONSTRAINT support_tickets_category_check CHECK (category IN
  ('general','fraud','access','device','recovery','investigation','protection'));

-- ---------------------------------------------------------------- least-privilege grants
GRANT SELECT, INSERT, UPDATE ON identity_verifications TO auth;
GRANT SELECT, INSERT ON transaction_approvals TO transaction;
GRANT USAGE ON SEQUENCE transaction_approvals_id_seq TO transaction;
GRANT SELECT ON transaction_approvals TO account;
GRANT UPDATE (status, decided_by, decided_at, decision_note, approvals_required) ON transactions TO transaction;
