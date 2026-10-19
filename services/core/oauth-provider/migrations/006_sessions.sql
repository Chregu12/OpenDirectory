CREATE TABLE IF NOT EXISTS oauth_sessions (
  id UUID PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject VARCHAR(255) NOT NULL,
  principal_type TEXT NOT NULL CHECK (principal_type IN ('user','application')),
  client_id VARCHAR(255) NOT NULL,
  auth_time BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS oauth_sessions_owner_idx ON oauth_sessions(issuer,subject,principal_type,created_at DESC);

CREATE TABLE IF NOT EXISTS oauth_session_refresh (
  token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  session_id UUID NOT NULL REFERENCES oauth_sessions(id),
  scope TEXT NOT NULL,
  claims_snapshot JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  replaced_by TEXT
);

CREATE INDEX IF NOT EXISTS oauth_session_refresh_session_idx ON oauth_session_refresh(session_id);

CREATE TABLE IF NOT EXISTS oauth_session_audit (
  id BIGSERIAL PRIMARY KEY,
  session_id UUID NOT NULL REFERENCES oauth_sessions(id),
  action TEXT NOT NULL,
  actor_subject VARCHAR(255) NOT NULL,
  actor_type TEXT NOT NULL,
  actor_client_id VARCHAR(255) NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION protect_oauth_session_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Session audit records are append-only';
END;
$$;

DROP TRIGGER IF EXISTS oauth_session_audit_immutable ON oauth_session_audit;
CREATE TRIGGER oauth_session_audit_immutable BEFORE UPDATE OR DELETE ON oauth_session_audit FOR EACH ROW EXECUTE FUNCTION protect_oauth_session_audit();

CREATE OR REPLACE FUNCTION guard_oauth_session_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF ROW(NEW.id,NEW.issuer,NEW.subject,NEW.principal_type,NEW.client_id,NEW.auth_time,NEW.expires_at,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.id,OLD.issuer,OLD.subject,OLD.principal_type,OLD.client_id,OLD.auth_time,OLD.expires_at,OLD.created_at) THEN
    RAISE EXCEPTION 'Session identity and absolute lifetime are immutable';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND ROW(NEW.revoked_at,NEW.revocation_reason) IS DISTINCT FROM ROW(OLD.revoked_at,OLD.revocation_reason) THEN
    RAISE EXCEPTION 'A revoked session cannot be reactivated';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS oauth_session_update_guard ON oauth_sessions;
CREATE TRIGGER oauth_session_update_guard BEFORE UPDATE ON oauth_sessions FOR EACH ROW EXECUTE FUNCTION guard_oauth_session_update();

CREATE OR REPLACE FUNCTION guard_oauth_refresh_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF ROW(NEW.token_hash,NEW.session_id,NEW.scope,NEW.claims_snapshot,NEW.expires_at)
    IS DISTINCT FROM ROW(OLD.token_hash,OLD.session_id,OLD.scope,OLD.claims_snapshot,OLD.expires_at) THEN
    RAISE EXCEPTION 'Refresh credential binding and grant are immutable';
  END IF;
  IF OLD.consumed_at IS NOT NULL AND ROW(NEW.consumed_at,NEW.replaced_by) IS DISTINCT FROM ROW(OLD.consumed_at,OLD.replaced_by) THEN
    RAISE EXCEPTION 'A consumed refresh credential cannot be reused';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS oauth_refresh_update_guard ON oauth_session_refresh;
CREATE TRIGGER oauth_refresh_update_guard BEFORE UPDATE ON oauth_session_refresh FOR EACH ROW EXECUTE FUNCTION guard_oauth_refresh_update();
