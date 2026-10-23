ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_codes JSONB NOT NULL DEFAULT '[]';
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_attempts INTEGER NOT NULL DEFAULT 0 CHECK(login_attempts>=0);
ALTER TABLE users ADD COLUMN IF NOT EXISTS record_revision BIGINT NOT NULL DEFAULT 1 CHECK(record_revision>0);

CREATE OR REPLACE FUNCTION authentication_credential_revision() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 NEW.record_revision=OLD.record_revision+1;
 NEW.updated_at=clock_timestamp();
 IF NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN NEW.password_changed_at=NEW.updated_at;END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE TRIGGER authentication_credential_revision BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION authentication_credential_revision();
