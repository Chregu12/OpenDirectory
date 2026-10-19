CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
CREATE TABLE IF NOT EXISTS identity_membership_origins (
 membership_id UUID PRIMARY KEY,group_id UUID NOT NULL,user_id UUID NOT NULL,created_by UUID,eligibility_revision BIGINT NOT NULL CHECK(eligibility_revision>0),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO identity_membership_origins(membership_id,group_id,user_id,eligibility_revision)
 SELECT membership.membership_id,membership.group_id,users.id,users.eligibility_revision FROM group_members membership JOIN users ON users.id::text=membership.user_id
 WHERE NOT EXISTS(SELECT 1 FROM identity_membership_origins WHERE membership_id=membership.membership_id);
CREATE TABLE IF NOT EXISTS identity_membership_review_policies (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),group_id UUID NOT NULL,issuer TEXT NOT NULL,version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2592000),window_seconds INTEGER NOT NULL CHECK(window_seconds BETWEEN 60 AND 604800 AND window_seconds<=interval_seconds),
 reviewer_user_ids UUID[] NOT NULL CHECK(cardinality(reviewer_user_ids) BETWEEN 1 AND 10),created_by UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT identity_membership_review_now(),retired_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_membership_active_policy ON identity_membership_review_policies(group_id) WHERE retired_at IS NULL;
CREATE TABLE IF NOT EXISTS identity_membership_review_leases (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),policy_id UUID NOT NULL REFERENCES identity_membership_review_policies(id),membership_id UUID NOT NULL UNIQUE REFERENCES identity_membership_origins(membership_id),
 version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),cycle BIGINT NOT NULL DEFAULT 1 CHECK(cycle>0),state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','denied')),
 initial_grace BOOLEAN NOT NULL,projected_active BOOLEAN NOT NULL,due_at TIMESTAMPTZ NOT NULL,deadline_at TIMESTAMPTZ NOT NULL CHECK(deadline_at>due_at),created_at TIMESTAMPTZ NOT NULL DEFAULT identity_membership_review_now()
);
CREATE TABLE IF NOT EXISTS identity_membership_review_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),policy_id UUID NOT NULL REFERENCES identity_membership_review_policies(id),review_id UUID REFERENCES identity_membership_review_leases(id),
 action TEXT NOT NULL,actor JSONB NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT identity_membership_review_now()
);
CREATE OR REPLACE FUNCTION identity_membership_review_allowed(identity UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id
  LEFT JOIN users ON users.id=origin.user_id WHERE lease.membership_id=identity AND (lease.state='denied' OR lease.deadline_at<=identity_membership_review_now()
   OR NOT(lease.initial_grace OR lease.cycle>1) OR users.id IS NULL OR NOT users.enabled OR users.eligibility_revision<>origin.eligibility_revision
   OR NOT EXISTS(SELECT 1 FROM group_members WHERE membership_id=identity)));
$$;
CREATE OR REPLACE FUNCTION identity_membership_review_independent(actor UUID,identity UUID,configurer UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM identity_membership_origins origin WHERE membership_id=identity AND actor<>origin.user_id AND actor IS DISTINCT FROM origin.created_by AND actor<>configurer
  AND NOT EXISTS(SELECT 1 FROM group_members WHERE group_id=origin.group_id AND user_id=actor::text));
$$;
CREATE OR REPLACE FUNCTION identity_membership_review_fresh(proof JSONB) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE(proof->'freshMfa'='true'::jsonb AND jsonb_typeof(proof->'authTime')='number' AND proof->>'authTime' ~ '^[0-9]{1,12}$'
  AND proof->>'factorRevision' ~ '^[1-9][0-9]{0,18}$' AND (proof->>'factorRevision')::numeric<=9223372036854775807
  AND (proof->>'authTime')::numeric BETWEEN floor(EXTRACT(epoch FROM clock_timestamp()))-300 AND floor(EXTRACT(epoch FROM clock_timestamp()))+5,false);
$$;
CREATE OR REPLACE FUNCTION identity_membership_origin_capture() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;policy identity_membership_review_policies;originator UUID;
BEGIN
 proof=NULLIF(current_setting('opendirectory.membership_proof',true),'')::jsonb;
 SELECT * INTO policy FROM identity_membership_review_policies WHERE group_id=NEW.group_id AND retired_at IS NULL;
 IF policy.id IS NULL AND EXISTS(SELECT 1 FROM identity_membership_review_policies WHERE group_id=NEW.group_id) THEN RAISE EXCEPTION 'Governed group requires a replacement review policy' USING ERRCODE='23514';END IF;
 IF proof IS NOT NULL THEN
  SELECT users.id INTO originator FROM users JOIN identity_subject_links link ON link.user_id=users.id WHERE users.id=(proof->>'userId')::uuid AND users.enabled AND link.issuer=proof->>'issuer' AND link.subject=proof->>'subject';
 END IF;
 IF policy.id IS NOT NULL AND (originator IS NULL OR proof->>'action' IS DISTINCT FROM 'add' OR proof->>'issuer' IS DISTINCT FROM policy.issuer OR NOT identity_membership_review_fresh(proof))
  THEN RAISE EXCEPTION 'Canonical fresh independent membership origin required' USING ERRCODE='42501';END IF;
 INSERT INTO identity_membership_origins(membership_id,group_id,user_id,created_by,eligibility_revision)
  SELECT NEW.membership_id,NEW.group_id,users.id,originator,users.eligibility_revision FROM users WHERE users.id::text=NEW.user_id;
 IF policy.id IS NOT NULL THEN
  INSERT INTO identity_membership_review_leases(policy_id,membership_id,initial_grace,projected_active,due_at,deadline_at)
   VALUES(policy.id,NEW.membership_id,false,false,identity_membership_review_now(),identity_membership_review_now()+interval '1 second');
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_membership_review_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;actor UUID;policy identity_membership_review_policies;origin identity_membership_origins;action TEXT;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Membership review history is retained' USING ERRCODE='42501';END IF;
 action=current_setting('opendirectory.membership_review_action',true);
 IF TG_TABLE_NAME='identity_membership_review_leases' AND TG_OP='UPDATE' AND action='refresh' THEN
  IF (to_jsonb(NEW)-'projected_active') IS DISTINCT FROM (to_jsonb(OLD)-'projected_active') OR NEW.projected_active IS DISTINCT FROM identity_membership_review_allowed(NEW.membership_id)
   THEN RAISE EXCEPTION 'Only actual effective state may be projected' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='identity_membership_review_leases' AND TG_OP='INSERT' THEN
  SELECT * INTO policy FROM identity_membership_review_policies WHERE id=NEW.policy_id;SELECT * INTO origin FROM identity_membership_origins WHERE membership_id=NEW.membership_id;
  IF pg_trigger_depth()<2 OR policy.retired_at IS NOT NULL OR policy.group_id IS DISTINCT FROM origin.group_id OR NEW.version<>1 OR NEW.cycle<>1 OR NEW.state<>'pending'
   OR NOT EXISTS(SELECT 1 FROM group_members WHERE membership_id=NEW.membership_id)
   OR NOT EXISTS(SELECT 1 FROM unnest(policy.reviewer_user_ids) reviewer WHERE identity_membership_review_independent(reviewer,NEW.membership_id,policy.created_by))
   THEN RAISE EXCEPTION 'Original independently reviewable membership capture required' USING ERRCODE='23514';END IF;
  NEW.due_at=date_trunc('milliseconds',identity_membership_review_now());NEW.deadline_at=NEW.due_at+policy.window_seconds*interval '1 second';
  NEW.projected_active=NEW.initial_grace AND EXISTS(SELECT 1 FROM users WHERE id=origin.user_id AND enabled AND eligibility_revision=origin.eligibility_revision);RETURN NEW;
 END IF;
 proof=NULLIF(current_setting('opendirectory.membership_proof',true),'')::jsonb;
 IF proof IS NULL OR NOT identity_membership_review_fresh(proof) OR COALESCE(proof->>'userId','') !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' OR COALESCE(proof->>'issuer','')='' THEN RAISE EXCEPTION 'Fresh canonical membership-review proof required' USING ERRCODE='42501';END IF;
 actor=(proof->>'userId')::uuid;
 IF TG_TABLE_NAME='identity_membership_review_policies' THEN
  PERFORM 1 FROM groups WHERE id=NEW.group_id FOR UPDATE;IF NOT FOUND THEN RAISE EXCEPTION 'Known canonical group required' USING ERRCODE='23503';END IF;
  IF TG_OP='INSERT' THEN
   IF action IS DISTINCT FROM 'create' OR NEW.created_by<>actor OR NEW.issuer IS DISTINCT FROM proof->>'issuer' OR NEW.version<>1 OR NEW.retired_at IS NOT NULL OR actor=ANY(NEW.reviewer_user_ids)
    OR array_position(NEW.reviewer_user_ids,NULL) IS NOT NULL OR cardinality(NEW.reviewer_user_ids)<>(SELECT count(DISTINCT reviewer) FROM unnest(NEW.reviewer_user_ids) reviewer)
    THEN RAISE EXCEPTION 'Independent original membership policy required' USING ERRCODE='23514';END IF;NEW.created_at=identity_membership_review_now();
  ELSE
   IF action IS DISTINCT FROM 'retire' OR (to_jsonb(NEW)-ARRAY['version','retired_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','retired_at']) OR NEW.version<>OLD.version+1 OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL
    THEN RAISE EXCEPTION 'One-way conditional policy retirement required' USING ERRCODE='42501';END IF;NEW.retired_at=identity_membership_review_now();
  END IF;
 ELSE
  SELECT * INTO policy FROM identity_membership_review_policies WHERE id=NEW.policy_id;SELECT * INTO origin FROM identity_membership_origins WHERE membership_id=NEW.membership_id;
  IF (to_jsonb(NEW)-ARRAY['version','cycle','state','due_at','deadline_at','projected_active']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','cycle','state','due_at','deadline_at','projected_active'])
   OR NEW.version<>OLD.version+1 OR OLD.state<>'pending' OR OLD.due_at>identity_membership_review_now() OR OLD.deadline_at<=identity_membership_review_now()
   OR proof->>'reviewedPolicyVersion' IS DISTINCT FROM policy.version::text OR proof->>'issuer' IS DISTINCT FROM policy.issuer OR NOT(actor=ANY(policy.reviewer_user_ids))
   OR NOT identity_membership_review_independent(actor,NEW.membership_id,policy.created_by) OR NOT EXISTS(SELECT 1 FROM group_members WHERE membership_id=NEW.membership_id)
   THEN RAISE EXCEPTION 'Current independent conditional membership review required' USING ERRCODE='42501';END IF;
  IF action='retain' THEN
   IF policy.retired_at IS NOT NULL OR origin.created_by IS NULL OR NEW.state<>'pending' OR NEW.cycle<>OLD.cycle+1
    OR NOT EXISTS(SELECT 1 FROM users WHERE id=origin.user_id AND enabled AND eligibility_revision=origin.eligibility_revision)
    THEN RAISE EXCEPTION 'Original live reviewed membership required; legacy origins need explicit reissue' USING ERRCODE='42501';END IF;
   NEW.due_at=date_trunc('milliseconds',identity_membership_review_now())+policy.interval_seconds*interval '1 second';NEW.deadline_at=NEW.due_at+policy.window_seconds*interval '1 second';NEW.projected_active=true;
  ELSIF action='deny' THEN
   IF NEW.state<>'denied' OR NEW.cycle<>OLD.cycle OR NEW.due_at<>OLD.due_at OR NEW.deadline_at<>OLD.deadline_at THEN RAISE EXCEPTION 'One-way membership denial required' USING ERRCODE='42501';END IF;NEW.projected_active=false;
  ELSE RAISE EXCEPTION 'Membership review decision required' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_membership_review_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy_id UUID;review_id UUID;group_identity UUID;action TEXT;
BEGIN
 IF TG_TABLE_NAME='identity_membership_review_policies' THEN
  policy_id=NEW.id;group_identity=NEW.group_id;action=CASE WHEN TG_OP='INSERT' THEN 'create' ELSE 'retire' END;
 ELSE
  policy_id=NEW.policy_id;review_id=NEW.id;SELECT group_id INTO group_identity FROM identity_membership_origins WHERE membership_id=NEW.membership_id;
  action=CASE WHEN TG_OP='INSERT' THEN 'capture' ELSE current_setting('opendirectory.membership_review_action',true) END;
  IF TG_OP='UPDATE' AND NEW.state='denied' THEN DELETE FROM group_members WHERE membership_id=NEW.membership_id;END IF;
 END IF;
 UPDATE groups SET updated_at=clock_timestamp() WHERE id=group_identity;
 INSERT INTO identity_membership_review_audit(policy_id,review_id,action,actor,reason,details) VALUES(policy_id,review_id,action,
  COALESCE(NULLIF(current_setting('opendirectory.membership_proof',true),'')::jsonb,'{}'::jsonb),COALESCE(NULLIF(current_setting('opendirectory.membership_reason',true),''),'Automatic actual membership-state projection'),to_jsonb(NEW));RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_membership_policy_capture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO identity_membership_review_leases(policy_id,membership_id,initial_grace,projected_active,due_at,deadline_at)
  SELECT NEW.id,membership_id,true,true,identity_membership_review_now(),identity_membership_review_now()+interval '1 second' FROM group_members WHERE group_id=NEW.group_id
  ON CONFLICT(membership_id) DO NOTHING;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_membership_review_refresh(group_identity UUID) RETURNS bigint LANGUAGE plpgsql VOLATILE AS $$
DECLARE revision BIGINT;previous_action TEXT;
BEGIN
 PERFORM 1 FROM groups WHERE id=group_identity FOR UPDATE;IF NOT FOUND THEN RETURN NULL;END IF;
 previous_action=current_setting('opendirectory.membership_review_action',true);PERFORM set_config('opendirectory.membership_review_action','refresh',true);
 UPDATE identity_membership_review_leases lease SET projected_active=identity_membership_review_allowed(lease.membership_id)
  FROM identity_membership_origins origin WHERE origin.membership_id=lease.membership_id AND origin.group_id=group_identity
   AND lease.projected_active IS DISTINCT FROM identity_membership_review_allowed(lease.membership_id);
 PERFORM set_config('opendirectory.membership_review_action',COALESCE(previous_action,''),true);SELECT groups.revision INTO revision FROM groups WHERE id=group_identity;RETURN revision;
END; $$;
CREATE OR REPLACE FUNCTION identity_membership_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Membership evidence requires its original transition' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS a_identity_membership_origin ON group_members;
CREATE TRIGGER a_identity_membership_origin AFTER INSERT ON group_members FOR EACH ROW EXECUTE FUNCTION identity_membership_origin_capture();
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['identity_membership_review_policies','identity_membership_review_leases'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_membership_review_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER identity_membership_review_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_membership_review_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_membership_review_changed ON %I',table_name);
  EXECUTE format('CREATE TRIGGER identity_membership_review_changed AFTER INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION identity_membership_review_changed()',table_name);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['identity_membership_origins','identity_membership_review_audit'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_membership_evidence_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER identity_membership_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_membership_evidence_guard()',table_name);
 END LOOP;
END; $$;
DROP TRIGGER IF EXISTS zz_identity_membership_policy_capture ON identity_membership_review_policies;
CREATE TRIGGER zz_identity_membership_policy_capture AFTER INSERT ON identity_membership_review_policies FOR EACH ROW EXECUTE FUNCTION identity_membership_policy_capture();
INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES('group-review-administrator',true,300),('group-reviewer',true,300),('group-review-reader',false,3600) ON CONFLICT(role) DO NOTHING;
INSERT INTO identity_role_activation_policies(role) VALUES('group-review-administrator'),('group-reviewer'),('group-review-reader') ON CONFLICT(role) DO NOTHING;
