-- PART 5: AI risk decision history. Every scored login, transfer, counter transaction and
-- sensitive request keeps the full adaptive decision (engine scores, severity, action, explanation).
-- Idempotent: safe to run on every deploy.

ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS severity TEXT;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS action TEXT;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS components JSONB;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS explanation TEXT;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS model_version TEXT;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS ml_probability NUMERIC(5,4);
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS ref TEXT;

ALTER TABLE risk_scores DROP CONSTRAINT IF EXISTS risk_scores_kind_check;
ALTER TABLE risk_scores ADD CONSTRAINT risk_scores_kind_check
    CHECK (kind IN ('login','transfer','deposit','withdrawal','request'));

CREATE INDEX IF NOT EXISTS risk_scores_subject_idx ON risk_scores (subject, created_at DESC);
CREATE INDEX IF NOT EXISTS risk_scores_created_idx ON risk_scores (created_at DESC);

-- auth learns each customer's usual sign-in hours from their own login history
GRANT SELECT ON risk_scores TO auth;
