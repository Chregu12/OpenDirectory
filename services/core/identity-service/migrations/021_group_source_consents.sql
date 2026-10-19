CREATE OR REPLACE FUNCTION identity_group_source_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
CREATE TABLE IF NOT EXISTS identity_group_source_grants (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),group_id UUID NOT NULL,issuer TEXT NOT NULL,client_id TEXT NOT NULL CHECK(client_id ~ '^[A-Za-z0-9._~-]{1,255}$'),
 client_revision BIGINT NOT NULL CHECK(client_revision>0),version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),created_by UUID NOT NULL,CHECK(client_id NOT IN('.','..')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT identity_group_source_now(),expires_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '30 days')
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_group_source_current ON identity_group_source_grants(issuer,client_id,group_id) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS identity_group_source_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),grant_id UUID NOT NULL REFERENCES identity_group_source_grants(id),action TEXT NOT NULL,actor JSONB NOT NULL,
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT identity_group_source_now()
);
CREATE OR REPLACE FUNCTION identity_group_source_administrator(actor UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM identity_role_assignments assignment JOIN identity_role_activation_policies policy ON policy.role=assignment.role
  LEFT JOIN identity_role_review_leases review ON review.target_kind='assignment' AND review.target_id=assignment.id
  LEFT JOIN identity_pim_requests request ON request.id=assignment.activation_request_id
  WHERE assignment.user_id=actor AND assignment.role='license-scope-administrator' AND assignment.revoked_at IS NULL
   AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp()) AND assignment.policy_version=policy.version
   AND (NOT policy.activation_required OR assignment.activation_request_id IS NOT NULL)
   AND (review.id IS NULL OR review.state<>'denied' AND (review.deadline_at IS NULL OR review.deadline_at>identity_role_review_now()))
   AND (assignment.activation_request_id IS NULL OR identity_role_review_eligible(request.eligibility_id)));
$$;
CREATE OR REPLACE FUNCTION identity_group_source_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;binding JSONB;actor UUID;action TEXT;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Source consents are retained evidence' USING ERRCODE='42501';END IF;
 IF NEW.client_id IN('.','..') THEN RAISE EXCEPTION 'Canonical source client identity required' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.group_source_actor',true),'')::jsonb;
 binding=NULLIF(current_setting('opendirectory.group_source_client',true),'')::jsonb;action=current_setting('opendirectory.group_source_action',true);
 IF proof IS NULL OR NOT identity_membership_review_fresh(proof) OR COALESCE(proof->>'userId','') !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' OR COALESCE(proof->>'clientId','') !~ '^[A-Za-z0-9._~-]{1,255}$'
  THEN RAISE EXCEPTION 'Fresh canonical source administrator required' USING ERRCODE='42501';END IF;
 actor=(proof->>'userId')::uuid;
 IF NOT identity_group_source_administrator(actor) OR NOT EXISTS(SELECT 1 FROM users JOIN identity_subject_links link ON link.user_id=users.id WHERE users.id=actor AND users.enabled
  AND users.authorization_revision::text=proof->>'revision' AND link.authorization_revision::text=proof->>'linkRevision' AND link.issuer=proof->>'issuer' AND link.subject=proof->>'subject')
  THEN RAISE EXCEPTION 'Current canonical source administrator required' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  PERFORM 1 FROM groups WHERE id=NEW.group_id FOR UPDATE;IF NOT FOUND THEN RAISE EXCEPTION 'Known canonical group required' USING ERRCODE='23503';END IF;
  IF action IS DISTINCT FROM 'create' OR NEW.version<>1 OR NEW.created_by<>actor OR NEW.issuer IS DISTINCT FROM proof->>'issuer' OR NEW.revoked_at IS NOT NULL
   OR binding IS NULL OR binding->>'clientId' IS DISTINCT FROM NEW.client_id OR binding->>'revision' IS DISTINCT FROM NEW.client_revision::text OR binding->'canReadGroupSources' IS DISTINCT FROM 'true'::jsonb
   OR binding->'enabled' IS DISTINCT FROM 'true'::jsonb OR NEW.client_id=proof->>'clientId'
   OR NEW.expires_at<=identity_group_source_now()+interval '60 seconds' OR NEW.expires_at>identity_group_source_now()+interval '30 days'
   THEN RAISE EXCEPTION 'Original bounded dedicated-client consent required' USING ERRCODE='23514';END IF;
  NEW.created_at=date_trunc('milliseconds',identity_group_source_now());
 ELSE
  IF action IS DISTINCT FROM 'revoke' OR (to_jsonb(NEW)-ARRAY['version','revoked_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','revoked_at'])
   OR NEW.version<>OLD.version+1 OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.issuer IS DISTINCT FROM proof->>'issuer'
   THEN RAISE EXCEPTION 'One-way exact source consent revocation required' USING ERRCODE='42501';END IF;
  NEW.revoked_at=date_trunc('milliseconds',identity_group_source_now());
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_group_source_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO identity_group_source_audit(grant_id,action,actor,reason,details) VALUES(NEW.id,CASE WHEN TG_OP='INSERT' THEN 'create' ELSE 'revoke' END,
  NULLIF(current_setting('opendirectory.group_source_actor',true),'')::jsonb,current_setting('opendirectory.group_source_reason',true),to_jsonb(NEW));RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_group_source_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.revoked_at IS NULL AND NEW.expires_at<=identity_group_source_now() THEN RAISE EXCEPTION 'Source consent expired before commit' USING ERRCODE='23514';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_group_source_guard ON identity_group_source_grants;
CREATE TRIGGER identity_group_source_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_group_source_grants FOR EACH ROW EXECUTE FUNCTION identity_group_source_guard();
DROP TRIGGER IF EXISTS identity_group_source_changed ON identity_group_source_grants;
CREATE TRIGGER identity_group_source_changed AFTER INSERT OR UPDATE ON identity_group_source_grants FOR EACH ROW EXECUTE FUNCTION identity_group_source_changed();
DROP TRIGGER IF EXISTS identity_group_source_commit_guard ON identity_group_source_grants;
CREATE CONSTRAINT TRIGGER identity_group_source_commit_guard AFTER INSERT OR UPDATE ON identity_group_source_grants DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_group_source_commit_guard();
DROP TRIGGER IF EXISTS identity_group_source_audit_guard ON identity_group_source_audit;
CREATE TRIGGER identity_group_source_audit_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_group_source_audit FOR EACH ROW EXECUTE FUNCTION identity_membership_evidence_guard();
