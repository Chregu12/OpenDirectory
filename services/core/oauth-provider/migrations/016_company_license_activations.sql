CREATE TABLE IF NOT EXISTS oauth_company_license_activations (
  id UUID PRIMARY KEY,
  session_id UUID NOT NULL REFERENCES oauth_sessions(id),
  binding JSONB NOT NULL CHECK (COALESCE((jsonb_typeof(binding)='object'
    AND binding ?& ARRAY['issuer','subject','sessionId','clientId','clientRevision','context','authTime','mfaRevision']
    AND binding-ARRAY['issuer','subject','sessionId','clientId','clientRevision','context','authTime','mfaRevision']='{}'::jsonb
    AND jsonb_typeof(binding->'context')='object' AND binding->'context' ?& ARRAY['userId','revision','linkRevision','rolesRevision']
    AND (binding->'context')-ARRAY['userId','revision','linkRevision','rolesRevision']='{}'::jsonb
    AND binding#>>'{context,rolesRevision}' ~ '^[a-f0-9]{64}$'
    AND binding#>>'{context,revision}' ~ '^[1-9][0-9]{0,18}$' AND binding#>>'{context,linkRevision}' ~ '^[1-9][0-9]{0,18}$'
    AND binding->>'mfaRevision' ~ '^[1-9][0-9]{0,18}$' AND binding->>'clientRevision' ~ '^[1-9][0-9]{0,18}$'),false)),
  tenant JSONB NOT NULL CHECK (COALESCE((jsonb_typeof(tenant)='object' AND tenant ?& ARRAY['id','version','generation']
    AND tenant-ARRAY['id','version','generation']='{}'::jsonb AND tenant->>'id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
    AND tenant->>'version' ~ '^[1-9][0-9]{0,18}$' AND tenant->>'generation' ~ '^[1-9][0-9]{0,18}$'),false)),
  reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 5 AND 500),
  duration_seconds INTEGER NOT NULL CHECK (duration_seconds IN (900,3600,7200,14400,28800,36000)),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CHECK (expires_at>created_at AND expires_at<=created_at+duration_seconds*interval '1 second')
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_company_license_one_activation ON oauth_company_license_activations(session_id) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS oauth_company_license_activation_audit (
  id BIGSERIAL PRIMARY KEY, activation_id UUID NOT NULL REFERENCES oauth_company_license_activations(id),
  action TEXT NOT NULL CHECK(action IN ('activated','revoked')), created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION guard_company_license_activation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE session oauth_sessions; factor oauth_mfa_factors; client oauth_clients;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Activation history is immutable'; END IF;
  IF TG_OP='UPDATE' THEN
    IF to_jsonb(NEW)-'revoked_at' IS DISTINCT FROM to_jsonb(OLD)-'revoked_at' OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
      OR abs(extract(epoch FROM NEW.revoked_at-clock_timestamp()))>5 THEN RAISE EXCEPTION 'Only activation revocation is permitted'; END IF;
    RETURN NEW;
  END IF;
  SELECT * INTO session FROM oauth_sessions WHERE id=NEW.session_id FOR SHARE;
  SELECT * INTO factor FROM oauth_mfa_factors WHERE user_id=(NEW.binding#>>'{context,userId}')::uuid FOR SHARE;
  SELECT * INTO client FROM oauth_clients WHERE id=NEW.binding->>'clientId' FOR SHARE;
  IF session.id IS NULL OR session.revoked_at IS NOT NULL OR session.principal_type<>'user' OR session.expires_at<=clock_timestamp()
    OR session.issuer IS DISTINCT FROM NEW.binding->>'issuer' OR session.subject IS DISTINCT FROM NEW.binding->>'subject'
    OR session.id::text IS DISTINCT FROM NEW.binding->>'sessionId' OR session.client_id IS DISTINCT FROM NEW.binding->>'clientId'
    OR session.auth_time IS DISTINCT FROM (NEW.binding->>'authTime')::bigint OR session.auth_time<extract(epoch FROM clock_timestamp())-300
    OR session.auth_time>extract(epoch FROM clock_timestamp())+5 OR NEW.expires_at>session.expires_at
    OR factor.user_id IS NULL OR NOT factor.enabled OR factor.revision::text IS DISTINCT FROM NEW.binding->>'mfaRevision'
    OR client.id IS NULL OR NOT client.enabled OR client.deleted_at IS NOT NULL OR client.revision::text IS DISTINCT FROM NEW.binding->>'clientRevision'
    OR abs(extract(epoch FROM NEW.created_at-clock_timestamp()))>5 THEN RAISE EXCEPTION 'Activation authority changed'; END IF;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS company_license_activation_guard ON oauth_company_license_activations;
CREATE TRIGGER company_license_activation_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth_company_license_activations FOR EACH ROW EXECUTE FUNCTION guard_company_license_activation();
CREATE OR REPLACE FUNCTION audit_company_license_activation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO oauth_company_license_activation_audit(activation_id,action) VALUES(NEW.id,CASE WHEN TG_OP='INSERT' THEN 'activated' ELSE 'revoked' END);
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS company_license_activation_audit ON oauth_company_license_activations;
CREATE TRIGGER company_license_activation_audit AFTER INSERT OR UPDATE ON oauth_company_license_activations FOR EACH ROW EXECUTE FUNCTION audit_company_license_activation();
DROP TRIGGER IF EXISTS company_license_activation_audit_guard ON oauth_company_license_activation_audit;
CREATE TRIGGER company_license_activation_audit_guard BEFORE UPDATE OR DELETE ON oauth_company_license_activation_audit FOR EACH ROW EXECUTE FUNCTION protect_oauth_session_audit();
