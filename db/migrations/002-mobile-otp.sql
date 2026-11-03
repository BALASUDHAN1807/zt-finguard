-- F22: mobile number for SMS OTP sign-in, for databases created before F22.
-- Idempotent: deploy.sh applies every file in db/migrations on each deployment
-- (fresh databases already get the column from db/init/01-schema.sql).
ALTER TABLE users ADD COLUMN IF NOT EXISTS mobile TEXT;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_mobile_key') THEN
    ALTER TABLE users ADD CONSTRAINT users_mobile_key UNIQUE (mobile);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_mobile_check') THEN
    ALTER TABLE users ADD CONSTRAINT users_mobile_check CHECK (mobile ~ '^[6-9][0-9]{9}$');
  END IF;
END $$;

-- demo users (same numbers as scripts/gen-secrets.sh)
UPDATE users u SET mobile = d.mobile
FROM (VALUES ('admin','9000000001'), ('teller','9000000002'), ('alice','9876500001'),
             ('bob','9876500002'), ('victim_demo','9876500003')) AS d(username, mobile)
WHERE u.username = d.username AND u.mobile IS NULL;
