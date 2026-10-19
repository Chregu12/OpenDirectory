CREATE TABLE IF NOT EXISTS identity_role_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  role TEXT NOT NULL CHECK (role ~ '^[a-z][a-z-]{0,63}$'),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  CHECK (expires_at IS NULL OR expires_at > created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX IF NOT EXISTS identity_role_assignments_user ON identity_role_assignments(user_id,created_at,id);
CREATE INDEX IF NOT EXISTS identity_role_assignments_live ON identity_role_assignments(user_id,expires_at,id) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS identity_role_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assignment_id UUID NOT NULL,
  user_id UUID NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS identity_role_audit_user ON identity_role_audit(user_id,created_at,id);

CREATE OR REPLACE FUNCTION identity_role_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Role assignments are retained evidence' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
    PERFORM id FROM users WHERE id=NEW.user_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Canonical user required' USING ERRCODE='23503'; END IF;
    IF NEW.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'New assignment cannot be revoked' USING ERRCODE='23514'; END IF;
    NEW.created_at := clock_timestamp();
  ELSE
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.role IS DISTINCT FROM OLD.role
      OR NEW.reason IS DISTINCT FROM OLD.reason OR NEW.created_at IS DISTINCT FROM OLD.created_at
      OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
      RAISE EXCEPTION 'Only one-way role revocation is allowed' USING ERRCODE='23514';
    END IF;
    NEW.revoked_at := clock_timestamp();
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_guard ON identity_role_assignments;
CREATE TRIGGER identity_role_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_role_assignments FOR EACH ROW EXECUTE FUNCTION identity_role_guard();

CREATE OR REPLACE FUNCTION identity_role_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=NEW.user_id;
  INSERT INTO identity_role_audit(assignment_id,user_id,action,actor,details)
    VALUES(NEW.id,NEW.user_id,CASE WHEN TG_OP='INSERT' THEN 'granted' ELSE 'revoked' END,
      COALESCE(NULLIF(current_setting('opendirectory.actor',true),''),'database'),
      jsonb_build_object('role',NEW.role,'reason',NEW.reason,'expiresAt',NEW.expires_at,'revokedAt',NEW.revoked_at));
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS identity_role_changed ON identity_role_assignments;
CREATE TRIGGER identity_role_changed AFTER INSERT OR UPDATE ON identity_role_assignments FOR EACH ROW EXECUTE FUNCTION identity_role_changed();
DROP TRIGGER IF EXISTS identity_role_audit_guard ON identity_role_audit;
CREATE TRIGGER identity_role_audit_guard BEFORE UPDATE OR DELETE ON identity_role_audit FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();
