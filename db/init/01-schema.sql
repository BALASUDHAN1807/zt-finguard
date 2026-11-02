-- ZT-FinGuard database schema
--
-- Zero Trust at the data layer:
--   * every service has its OWN database role (no shared DB account)
--   * roles have NO passwords: they log in with their mTLS client certificate
--     (pg_hba.conf "cert" method; certificate CN must equal the role name)
--   * each role only gets the tables/columns it needs (least privilege)
--   * audit_log is append-only for the audit role (no UPDATE / DELETE)

CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('customer','teller','admin')),
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login_ip   TEXT,
    -- F19: customer-chosen inactivity timeout (capped by the admin maximum)
    idle_timeout_minutes INT NOT NULL DEFAULT 15 CHECK (idle_timeout_minutes BETWEEN 1 AND 1440),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- F21: device registry. A device is trusted only after verification.
CREATE TABLE known_devices (
    id          SERIAL PRIMARY KEY,
    user_id     INT NOT NULL REFERENCES users(id),
    fingerprint TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT 'Unknown device',
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','trusted','revoked')),
    first_ip    TEXT,
    last_ip     TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ,
    verified_by TEXT,
    UNIQUE (user_id, fingerprint)
);

-- Security settings an administrator controls (F19: maximum idle timeout).
CREATE TABLE security_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO security_settings (key, value, updated_by) VALUES ('max_idle_minutes', '30', 'system');

CREATE TABLE accounts (
    id          SERIAL PRIMARY KEY,
    user_id     INT UNIQUE NOT NULL,
    owner       TEXT UNIQUE NOT NULL,
    account_no  TEXT UNIQUE NOT NULL,
    balance     NUMERIC(14,2) NOT NULL CHECK (balance >= 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE transactions (
    id            BIGSERIAL PRIMARY KEY,
    from_account  TEXT NOT NULL,
    to_account    TEXT NOT NULL,
    amount        NUMERIC(14,2) NOT NULL CHECK (amount > 0),
    status        TEXT NOT NULL CHECK (status IN ('completed','denied','step_up_required')),
    risk_score    NUMERIC(5,4),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON transactions (from_account, created_at DESC);
CREATE INDEX ON transactions (to_account, created_at DESC);

CREATE TABLE risk_scores (
    id          BIGSERIAL PRIMARY KEY,
    subject     TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('login','transfer')),
    score       NUMERIC(5,4) NOT NULL,
    level       TEXT NOT NULL,
    reasons     JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    service     TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    decision    TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    risk        NUMERIC(5,4),
    details     JSONB NOT NULL DEFAULT '{}',
    prev_hash   CHAR(64) NOT NULL,
    hash        CHAR(64) NOT NULL UNIQUE
);
CREATE INDEX ON audit_log (ts DESC);

-- ---------- per-service roles (certificate login, no password) ----------
CREATE ROLE auth        LOGIN;
CREATE ROLE account     LOGIN;
CREATE ROLE transaction LOGIN;
CREATE ROLE audit       LOGIN;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO auth, account, transaction, audit;

-- auth: identities and devices only
GRANT SELECT, INSERT, UPDATE ON users TO auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON known_devices TO auth;
GRANT SELECT, UPDATE ON security_settings TO auth;
GRANT INSERT ON risk_scores TO auth;
GRANT USAGE ON SEQUENCE users_id_seq, known_devices_id_seq, risk_scores_id_seq TO auth;

-- account: open accounts and read balances / history
GRANT SELECT, INSERT ON accounts TO account;
GRANT SELECT ON transactions TO account;
GRANT USAGE ON SEQUENCE accounts_id_seq TO account;

-- transaction: move money (balance column only) and record transfers
GRANT SELECT ON accounts TO transaction;
GRANT UPDATE (balance) ON accounts TO transaction;
GRANT SELECT, INSERT ON transactions, risk_scores TO transaction;
GRANT USAGE ON SEQUENCE transactions_id_seq, risk_scores_id_seq TO transaction;

-- audit: append-only log
GRANT SELECT, INSERT ON audit_log TO audit;
GRANT SELECT ON risk_scores TO audit;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO audit;
