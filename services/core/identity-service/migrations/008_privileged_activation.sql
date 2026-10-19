CREATE TABLE IF NOT EXISTS identity_pim_eligibilities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  role TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
  max_duration_seconds INTEGER NOT NULL CHECK (max_duration_seconds BETWEEN 60 AND 28800),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS identity_pim_eligibilities_user ON identity_pim_eligibilities(user_id,created_at,id);
CREATE TABLE IF NOT EXISTS identity_pim_requests (
  id UUID PRIMARY KEY,
  eligibility_id UUID NOT NULL REFERENCES identity_pim_eligibilities(id),
  user_id UUID NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
  duration_seconds INTEGER NOT NULL CHECK (duration_seconds BETWEEN 60 AND 28800),
  request_authority JSONB NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','denied','cancelled','active','revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  deadline_at TIMESTAMPTZ NOT NULL CHECK (deadline_at>created_at),
  decided_at TIMESTAMPTZ,
  decision_authority JSONB
);
CREATE INDEX IF NOT EXISTS identity_pim_requests_user ON identity_pim_requests(user_id,created_at,id);
CREATE INDEX IF NOT EXISTS identity_pim_requests_eligibility ON identity_pim_requests(eligibility_id,state);
CREATE TABLE IF NOT EXISTS identity_pim_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id UUID NOT NULL,
  user_id UUID NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE identity_role_assignments ADD COLUMN IF NOT EXISTS activation_request_id UUID UNIQUE REFERENCES identity_pim_requests(id);

CREATE OR REPLACE FUNCTION identity_pim_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE eligibility identity_pim_eligibilities%ROWTYPE;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PIM evidence is retained' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
    PERFORM id FROM users WHERE id=NEW.user_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Canonical user required' USING ERRCODE='23503'; END IF;
    NEW.created_at := clock_timestamp();
    IF TG_TABLE_NAME='identity_pim_eligibilities' THEN
      IF NEW.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'New eligibility must not be revoked' USING ERRCODE='23514'; END IF;
    ELSE
      SELECT * INTO eligibility FROM identity_pim_eligibilities WHERE id=NEW.eligibility_id FOR UPDATE;
      IF NOT FOUND OR eligibility.user_id<>NEW.user_id OR eligibility.revoked_at IS NOT NULL OR eligibility.expires_at<=clock_timestamp()
        OR NEW.duration_seconds>eligibility.max_duration_seconds OR NEW.deadline_at>eligibility.expires_at
        OR NEW.state<>'pending' OR NEW.decided_at IS NOT NULL OR NEW.decision_authority IS NOT NULL
        OR NEW.request_authority->>'userId' IS DISTINCT FROM NEW.user_id::text THEN
        RAISE EXCEPTION 'A live owned eligibility and pending request are required' USING ERRCODE='23514';
      END IF;
    END IF;
  ELSIF TG_TABLE_NAME='identity_pim_eligibilities' THEN
    IF (to_jsonb(NEW)-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at') OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
      RAISE EXCEPTION 'Eligibility only permits one-way revocation' USING ERRCODE='23514';
    END IF;
    NEW.revoked_at := clock_timestamp();
  ELSE
    IF (to_jsonb(NEW)-ARRAY['state','decided_at','decision_authority']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','decided_at','decision_authority'])
      OR NOT ((OLD.state='pending' AND NEW.state IN ('approved','denied','cancelled'))
        OR (OLD.state='approved' AND NEW.state IN ('active','cancelled')) OR (OLD.state='active' AND NEW.state='revoked')) THEN
      RAISE EXCEPTION 'Invalid PIM transition or immutable-field change' USING ERRCODE='23514';
    END IF;
    IF OLD.state='pending' AND NEW.state IN ('approved','denied') THEN
      IF NEW.decision_authority IS NULL OR NEW.decision_authority->>'userId' IS NULL OR (NEW.decision_authority->>'userId')::uuid=NEW.user_id THEN
        RAISE EXCEPTION 'Independent canonical reviewer required' USING ERRCODE='23514';
      END IF;
      NEW.decided_at := clock_timestamp();
    ELSIF NEW.decided_at IS DISTINCT FROM OLD.decided_at OR NEW.decision_authority IS DISTINCT FROM OLD.decision_authority THEN
      RAISE EXCEPTION 'Decision authority is immutable' USING ERRCODE='23514';
    END IF;
    IF NEW.state='active' AND NOT EXISTS (SELECT 1 FROM identity_role_assignments WHERE activation_request_id=NEW.id AND revoked_at IS NULL) THEN
      RAISE EXCEPTION 'Canonical active assignment required' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_pim_guard ON identity_pim_eligibilities;
CREATE TRIGGER identity_pim_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_pim_eligibilities FOR EACH ROW EXECUTE FUNCTION identity_pim_guard();
DROP TRIGGER IF EXISTS identity_pim_guard ON identity_pim_requests;
CREATE TRIGGER identity_pim_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_pim_requests FOR EACH ROW EXECUTE FUNCTION identity_pim_guard();

CREATE OR REPLACE FUNCTION identity_pim_assignment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE request identity_pim_requests%ROWTYPE;
DECLARE eligibility identity_pim_eligibilities%ROWTYPE;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.activation_request_id IS DISTINCT FROM OLD.activation_request_id THEN RAISE EXCEPTION 'PIM assignment origin is immutable' USING ERRCODE='23514'; END IF;
  ELSIF NEW.activation_request_id IS NOT NULL THEN
    SELECT * INTO request FROM identity_pim_requests WHERE id=NEW.activation_request_id FOR UPDATE;
    SELECT * INTO eligibility FROM identity_pim_eligibilities WHERE id=request.eligibility_id FOR UPDATE;
    IF request.state IS DISTINCT FROM 'approved' OR request.user_id IS DISTINCT FROM NEW.user_id OR eligibility.role IS DISTINCT FROM NEW.role
      OR eligibility.revoked_at IS NOT NULL OR eligibility.expires_at<=clock_timestamp() OR request.deadline_at<=clock_timestamp()
      OR request.decided_at+interval '5 minutes'<=clock_timestamp() OR NEW.expires_at IS NULL
      OR NEW.expires_at>eligibility.expires_at OR NEW.expires_at>clock_timestamp()+request.duration_seconds*interval '1 second' THEN
      RAISE EXCEPTION 'Approved, bounded PIM activation required' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS identity_pim_assignment_guard ON identity_role_assignments;
CREATE TRIGGER identity_pim_assignment_guard BEFORE INSERT OR UPDATE ON identity_role_assignments FOR EACH ROW EXECUTE FUNCTION identity_pim_assignment_guard();

CREATE OR REPLACE FUNCTION identity_pim_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO identity_pim_audit(entity_id,user_id,action,actor,details)
    VALUES(NEW.id,NEW.user_id,TG_TABLE_NAME||':'||lower(TG_OP),COALESCE(NULLIF(current_setting('opendirectory.actor',true),''),'database'),to_jsonb(NEW));
  IF TG_TABLE_NAME='identity_pim_eligibilities' AND TG_OP='UPDATE' THEN
    UPDATE identity_role_assignments SET revoked_at=clock_timestamp()
      WHERE revoked_at IS NULL AND activation_request_id IN (SELECT id FROM identity_pim_requests WHERE eligibility_id=NEW.id);
    UPDATE identity_pim_requests SET state='cancelled' WHERE eligibility_id=NEW.id AND state IN ('pending','approved');
  END IF;
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS identity_pim_changed ON identity_pim_eligibilities;
CREATE TRIGGER identity_pim_changed AFTER INSERT OR UPDATE ON identity_pim_eligibilities FOR EACH ROW EXECUTE FUNCTION identity_pim_changed();
DROP TRIGGER IF EXISTS identity_pim_changed ON identity_pim_requests;
CREATE TRIGGER identity_pim_changed AFTER INSERT OR UPDATE ON identity_pim_requests FOR EACH ROW EXECUTE FUNCTION identity_pim_changed();
CREATE OR REPLACE FUNCTION identity_pim_assignment_revoked() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.activation_request_id IS NOT NULL AND NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL THEN
    UPDATE identity_pim_requests SET state='revoked' WHERE id=NEW.activation_request_id AND state='active';
  END IF;
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS identity_pim_assignment_revoked ON identity_role_assignments;
CREATE TRIGGER identity_pim_assignment_revoked AFTER UPDATE ON identity_role_assignments FOR EACH ROW EXECUTE FUNCTION identity_pim_assignment_revoked();
DROP TRIGGER IF EXISTS identity_pim_audit_guard ON identity_pim_audit;
CREATE TRIGGER identity_pim_audit_guard BEFORE UPDATE OR DELETE ON identity_pim_audit FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();
