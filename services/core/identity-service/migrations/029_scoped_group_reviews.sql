CREATE TABLE IF NOT EXISTS identity_directory_group_review_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),group_id UUID NOT NULL,root_id UUID NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('create','retire','retain','deny')),actor JSONB NOT NULL,
 scope_sha256 TEXT NOT NULL CHECK(scope_sha256 ~ '^[a-f0-9]{64}$'),details JSONB NOT NULL,
 transaction_id BIGINT NOT NULL DEFAULT txid_current(),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS identity_directory_group_review_events_target ON identity_directory_group_review_events(tenant_id,group_id,created_at);
CREATE TABLE IF NOT EXISTS identity_directory_group_review_outbox (
 id UUID PRIMARY KEY REFERENCES identity_directory_group_review_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action IN ('create','retire','retain','deny')),status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION identity_directory_group_policy_owned(identity UUID,owner UUID) RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$
 SELECT owner IS NULL OR EXISTS(SELECT 1 FROM identity_membership_review_policies setting WHERE setting.id=identity
  AND identity_tenant_id('group',setting.group_id)=owner AND identity_tenant_id('user',setting.created_by)=owner
  AND NOT EXISTS(SELECT 1 FROM unnest(setting.reviewer_user_ids) reviewer WHERE identity_tenant_id('user',reviewer) IS DISTINCT FROM owner));
$$;
CREATE OR REPLACE FUNCTION identity_directory_group_review_state(data JSONB) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT data||COALESCE((SELECT jsonb_object_agg(field,data->>field) FROM unnest(ARRAY['version','cycle','eligibility_revision']) field WHERE data ? field),'{}'::jsonb);
$$;
CREATE OR REPLACE FUNCTION identity_directory_group_review_sort(data JSONB) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(jsonb_agg(item ORDER BY item->>'id'),'[]'::jsonb) FROM jsonb_array_elements(data) item;
$$;
CREATE OR REPLACE FUNCTION identity_directory_group_review_snapshot(identity UUID) RETURNS jsonb LANGUAGE sql SECURITY DEFINER AS $$
 SELECT jsonb_build_object('group',identity_directory_group_row(identity),'members',identity_directory_group_members(identity),
  'policies',COALESCE((SELECT jsonb_agg(identity_directory_group_review_state(to_jsonb(setting)) ORDER BY setting.id)
   FROM (SELECT * FROM identity_membership_review_policies WHERE group_id=identity ORDER BY id LIMIT 10001) setting),'[]'::jsonb),
  'leases',COALESCE((SELECT jsonb_agg(identity_directory_group_review_state(to_jsonb(lease)) ORDER BY lease.id)
   FROM (SELECT lease.* FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id
    WHERE origin.group_id=identity ORDER BY lease.id LIMIT 10001) lease),'[]'::jsonb));
$$;
CREATE OR REPLACE FUNCTION identity_directory_group_review_actor(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE voter JSONB;
BEGIN
 PERFORM identity_directory_creation_actor(proof);
 IF NOT identity_membership_review_fresh(jsonb_build_object('freshMfa',true,'authTime',proof->'authTime','factorRevision',proof->'factorRevision'))
  THEN RAISE EXCEPTION 'Physical original membership-review MFA deadline required' USING ERRCODE='42501';END IF;
 FOR voter IN SELECT value FROM jsonb_array_elements(proof->'voters') LOOP
  IF voter->'tenant' IS DISTINCT FROM proof->'tenant' OR voter->'context'->>'userId'=proof->'context'->>'userId'
   OR voter->'validUntil' IS DISTINCT FROM proof->'validUntil' THEN RAISE EXCEPTION 'Exact independent owned reviewer authority required' USING ERRCODE='42501';END IF;
  PERFORM identity_directory_creation_actor(voter);
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_review_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;member_proof JSONB;admitted BOOLEAN;root_identity UUID;before_root JSONB;owner_role NAME;policy_version TEXT;
BEGIN
 proof=NULLIF(current_setting('opendirectory.group_review',true),'')::jsonb;
 IF proof IS NULL THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 SELECT pg_catalog.pg_get_userbyid(relowner) INTO owner_role FROM pg_catalog.pg_class WHERE oid=TG_RELID;
 IF owner_role IS NULL OR NOT pg_catalog.pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
  THEN RAISE EXCEPTION 'Actual database owner required for scoped group reviews' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME IN ('users','identity_subject_links','identity_membership_origins')
  THEN RAISE EXCEPTION 'Group reviews cannot mutate users, links or membership origins' USING ERRCODE='42501';END IF;
 admitted=COALESCE(current_setting('opendirectory.group_review_admitted',true)=proof->>'operationId',false);
 root_identity=NULLIF(current_setting('opendirectory.group_review_root',true),'')::uuid;
 IF TG_TABLE_NAME='groups' THEN
  IF TG_OP<>'UPDATE' OR NOT admitted OR pg_trigger_depth()<2 OR OLD.id::text IS DISTINCT FROM proof->>'groupId'
   OR to_jsonb(NEW)-'updated_at' IS DISTINCT FROM to_jsonb(OLD)-'updated_at'
   THEN RAISE EXCEPTION 'Only exact review-induced group version changes permitted' USING ERRCODE='23514';END IF;RETURN NEW;
 ELSIF TG_TABLE_NAME='group_members' THEN
  IF TG_OP<>'DELETE' OR NOT admitted OR proof->>'action'<>'deny' OR pg_trigger_depth()<2
   OR OLD.group_id::text IS DISTINCT FROM proof->>'groupId'
   OR NOT EXISTS(SELECT 1 FROM identity_membership_review_leases lease WHERE lease.id=root_identity AND lease.membership_id=OLD.membership_id AND lease.state='denied')
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'before'->'members') item WHERE item=to_jsonb(OLD))
   THEN RAISE EXCEPTION 'Only exact admitted review denial may remove its source' USING ERRCODE='23514';END IF;RETURN OLD;
 ELSIF TG_TABLE_NAME='identity_membership_review_leases' AND TG_OP='INSERT' AND admitted AND proof->>'action'='create' AND pg_trigger_depth()>1 THEN
  IF NEW.policy_id IS DISTINCT FROM root_identity OR NOT NEW.initial_grace OR NEW.version<>1 OR NEW.cycle<>1 OR NEW.state<>'pending'
   OR NOT EXISTS(SELECT 1 FROM identity_membership_origins origin WHERE origin.membership_id=NEW.membership_id AND origin.group_id=(proof->>'groupId')::uuid
    AND identity_tenant_id('user',origin.user_id)=(proof->'tenant'->>'id')::uuid)
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'before'->'members') item WHERE item->>'membership_id'=NEW.membership_id::text)
   THEN RAISE EXCEPTION 'Only actual owned policy membership captures permitted' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF admitted OR TG_OP='DELETE' OR identity_directory_group_review_snapshot((proof->>'groupId')::uuid) IS DISTINCT FROM proof->'before'
  OR identity_tenant_id('group',(proof->>'groupId')::uuid)::text IS DISTINCT FROM proof->'tenant'->>'id'
  THEN RAISE EXCEPTION 'One exact original group-review root transition required' USING ERRCODE='23514';END IF;
 PERFORM identity_directory_group_review_actor(proof);
 member_proof=NULLIF(current_setting('opendirectory.membership_proof',true),'')::jsonb;
 IF member_proof->>'issuer' IS DISTINCT FROM proof->>'issuer' OR member_proof->>'subject' IS DISTINCT FROM proof->>'subject'
  OR member_proof->>'userId' IS DISTINCT FROM proof->'context'->>'userId' OR member_proof->'authTime' IS DISTINCT FROM proof->'authTime'
  OR member_proof->'factorRevision' IS DISTINCT FROM proof->'factorRevision' OR NOT identity_membership_review_fresh(member_proof)
  OR member_proof->>'action' IS DISTINCT FROM proof->>'action'
  OR current_setting('opendirectory.membership_reason',true) IS DISTINCT FROM proof->'intent'->>'reason'
  THEN RAISE EXCEPTION 'Exact fresh original membership-review actor and intent required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_membership_review_policies' THEN
  IF NEW.group_id::text IS DISTINCT FROM proof->>'groupId' OR NEW.issuer IS DISTINCT FROM proof->>'issuer'
   THEN RAISE EXCEPTION 'Exact owned group-review policy required' USING ERRCODE='23514';END IF;
  IF TG_OP='INSERT' THEN
   IF proof->>'action'<>'create' OR proof->'rootId' IS DISTINCT FROM 'null'::jsonb OR NEW.version<>1 OR NEW.retired_at IS NOT NULL
    OR NEW.created_by::text IS DISTINCT FROM proof->'context'->>'userId' OR NEW.interval_seconds::text IS DISTINCT FROM proof->'intent'->>'intervalSeconds'
    OR NEW.window_seconds::text IS DISTINCT FROM proof->'intent'->>'windowSeconds' OR to_jsonb(NEW.reviewer_user_ids) IS DISTINCT FROM proof->'intent'->'reviewerUserIds'
    OR proof->'intent'->'acknowledgeEffects' IS DISTINCT FROM 'true'::jsonb
    OR EXISTS(SELECT 1 FROM group_members member LEFT JOIN identity_membership_origins origin ON origin.membership_id=member.membership_id
     WHERE member.group_id=NEW.group_id AND (origin.membership_id IS NULL OR origin.group_id IS DISTINCT FROM member.group_id
      OR origin.user_id::text IS DISTINCT FROM member.user_id OR identity_tenant_id('user',origin.user_id) IS DISTINCT FROM (proof->'tenant'->>'id')::uuid
      OR origin.created_by IS NOT NULL AND identity_tenant_id('user',origin.created_by) IS DISTINCT FROM (proof->'tenant'->>'id')::uuid))
    THEN RAISE EXCEPTION 'Exact independent policy creation intent required' USING ERRCODE='23514';END IF;
  ELSE
   SELECT item INTO before_root FROM jsonb_array_elements(proof->'before'->'policies') item WHERE item->>'id'=proof->>'rootId';
   IF proof->>'action'<>'retire' OR NEW.id::text IS DISTINCT FROM proof->>'rootId' OR identity_directory_group_review_state(to_jsonb(OLD)) IS DISTINCT FROM before_root
    OR to_jsonb(NEW)-ARRAY['version','retired_at'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['version','retired_at']
    OR NEW.version<>OLD.version+1 OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL
    OR proof->'intent'->>'expected' IS DISTINCT FROM '"od-membership-review-policy:'||OLD.id::text||':'||OLD.version::text||'"'
    OR proof->'intent'->'acknowledgeEffects' IS DISTINCT FROM 'true'::jsonb
    THEN RAISE EXCEPTION 'Exact conditional policy retirement required' USING ERRCODE='23514';END IF;
  END IF;
 ELSE
  SELECT item INTO before_root FROM jsonb_array_elements(proof->'before'->'leases') item WHERE item->>'id'=proof->>'rootId';
  SELECT version::text INTO policy_version FROM identity_membership_review_policies WHERE id=OLD.policy_id;
  IF TG_OP<>'UPDATE' OR proof->>'action' NOT IN ('retain','deny') OR NEW.id::text IS DISTINCT FROM proof->>'rootId'
   OR identity_directory_group_review_state(to_jsonb(OLD)) IS DISTINCT FROM before_root
   OR to_jsonb(NEW)-ARRAY['version','cycle','state'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['version','cycle','state']
   OR NEW.version<>OLD.version+1 OR NEW.cycle<>OLD.cycle+(CASE WHEN proof->>'action'='retain' THEN 1 ELSE 0 END)
   OR NEW.state IS DISTINCT FROM (CASE WHEN proof->>'action'='deny' THEN 'denied' ELSE 'pending' END)
   OR proof->'intent'->>'expected' IS DISTINCT FROM '"od-membership-review:'||OLD.id::text||':'||OLD.version::text||':'||policy_version||'"'
   OR proof->'intent'->>'decision' IS DISTINCT FROM proof->>'action' OR proof->'intent'->'acknowledgeScope' IS DISTINCT FROM 'true'::jsonb
   THEN RAISE EXCEPTION 'Exact conditional membership review decision required' USING ERRCODE='23514';END IF;
 END IF;
 PERFORM set_config('opendirectory.group_review_admitted',proof->>'operationId',true);PERFORM set_config('opendirectory.group_review_root',NEW.id::text,true);RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_review_validate(proof JSONB) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actual JSONB;root_state JSONB;before_root JSONB;policy_state JSONB;lease_state JSONB;old_lease JSONB;expected_policies JSONB;expected_leases JSONB;
 expected_members JSONB;root_identity TEXT;new_captures INTEGER;expected_captures INTEGER;group_identity UUID;action_name TEXT;
BEGIN
 PERFORM identity_directory_group_review_actor(proof);group_identity=(proof->>'groupId')::uuid;action_name=proof->>'action';
 root_identity=NULLIF(current_setting('opendirectory.group_review_root',true),'');actual=identity_directory_group_review_snapshot(group_identity);
 IF root_identity IS NULL OR action_name IS NULL OR action_name NOT IN ('create','retire','retain','deny')
  OR identity_tenant_id('group',group_identity)::text IS DISTINCT FROM proof->'tenant'->>'id' OR actual->'group'='null'::jsonb
  OR (actual->'group')-ARRAY['revision','updated_at'] IS DISTINCT FROM (proof->'before'->'group')-ARRAY['revision','updated_at']
  OR (actual->'group'->>'revision')::bigint<=(proof->'before'->'group'->>'revision')::bigint
  OR NOT EXISTS(SELECT 1 FROM identity_group_audit audit JOIN identity_group_outbox outbox ON outbox.group_id=audit.group_id AND outbox.revision=audit.revision
   WHERE audit.group_id=group_identity AND audit.revision=(actual->'group'->>'revision')::bigint AND audit.action='update'
   AND audit.actor=proof->>'subject' AND outbox.payload->'deleted'='false'::jsonb)
  THEN RAISE EXCEPTION 'Exact scoped group-review effects and core audit required' USING ERRCODE='23514';END IF;
 IF action_name IN ('create','retire') THEN
  SELECT item INTO root_state FROM jsonb_array_elements(actual->'policies') item WHERE item->>'id'=root_identity;
  IF root_state IS NULL OR NOT identity_directory_group_policy_owned(root_identity::uuid,(proof->'tenant'->>'id')::uuid)
   THEN RAISE EXCEPTION 'Current coherent owned review policy required' USING ERRCODE='23514';END IF;
  IF action_name='create' THEN
   IF root_state->>'group_id' IS DISTINCT FROM group_identity::text OR root_state->>'issuer' IS DISTINCT FROM proof->>'issuer'
    OR root_state->>'created_by' IS DISTINCT FROM proof->'context'->>'userId' OR root_state->>'version'<>'1' OR root_state->'retired_at' IS DISTINCT FROM 'null'::jsonb
    OR root_state->'reviewer_user_ids' IS DISTINCT FROM proof->'intent'->'reviewerUserIds'
    OR root_state->'interval_seconds' IS DISTINCT FROM proof->'intent'->'intervalSeconds' OR root_state->'window_seconds' IS DISTINCT FROM proof->'intent'->'windowSeconds'
    OR (root_state->>'created_at')::timestamptz<(proof->>'observedAt')::timestamptz-interval '1 millisecond'
    OR (root_state->>'created_at')::timestamptz>identity_membership_review_now()+interval '1 millisecond'
    OR jsonb_array_length(proof->'voters')<>jsonb_array_length(proof->'intent'->'reviewerUserIds')
    THEN RAISE EXCEPTION 'Exact new owned review policy content required' USING ERRCODE='23514';END IF;
   expected_policies=identity_directory_group_review_sort((proof->'before'->'policies')||jsonb_build_array(root_state));
   new_captures=0;
   FOR lease_state IN SELECT value FROM jsonb_array_elements(actual->'leases') LOOP
    SELECT item INTO old_lease FROM jsonb_array_elements(proof->'before'->'leases') item WHERE item->>'id'=lease_state->>'id';
    IF old_lease IS NOT NULL THEN IF lease_state IS DISTINCT FROM old_lease THEN RAISE EXCEPTION 'Policy creation cannot reset an old review lease' USING ERRCODE='23514';END IF;CONTINUE;END IF;
    IF lease_state->>'policy_id'<>root_identity OR lease_state->>'version'<>'1' OR lease_state->>'cycle'<>'1' OR lease_state->>'state'<>'pending'
     OR lease_state->'initial_grace' IS DISTINCT FROM 'true'::jsonb
     OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'before'->'members') item WHERE item->>'membership_id'=lease_state->>'membership_id')
     OR EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'before'->'leases') item WHERE item->>'membership_id'=lease_state->>'membership_id')
     OR (lease_state->>'deadline_at')::timestamptz-(lease_state->>'due_at')::timestamptz=(root_state->>'window_seconds')::integer*interval '1 second' IS NOT TRUE
     OR (lease_state->>'due_at')::timestamptz<(proof->>'observedAt')::timestamptz-interval '1 millisecond'
     OR (lease_state->>'due_at')::timestamptz>identity_membership_review_now()+interval '1 millisecond'
     OR lease_state->'projected_active' IS DISTINCT FROM to_jsonb(identity_membership_review_allowed((lease_state->>'membership_id')::uuid))
     OR NOT EXISTS(SELECT 1 FROM identity_membership_review_audit evidence WHERE evidence.policy_id=root_identity::uuid AND evidence.review_id=(lease_state->>'id')::uuid
      AND evidence.action='capture' AND evidence.actor->>'userId'=proof->'context'->>'userId' AND identity_directory_group_review_state(evidence.details)=lease_state)
     THEN RAISE EXCEPTION 'Only actual bounded original membership captures permitted' USING ERRCODE='23514';END IF;
    new_captures=new_captures+1;
   END LOOP;
   SELECT count(*) INTO expected_captures FROM jsonb_array_elements(proof->'before'->'members') member
    WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'before'->'leases') item WHERE item->>'membership_id'=member->>'membership_id');
   IF new_captures<>expected_captures OR jsonb_array_length(actual->'leases')<>jsonb_array_length(proof->'before'->'leases')+new_captures
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'before'->'leases') item WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(actual->'leases') current_lease WHERE current_lease=item))
    THEN RAISE EXCEPTION 'Complete current membership capture without historical reset required' USING ERRCODE='23514';END IF;
   expected_leases=actual->'leases';
  ELSE
   SELECT item INTO before_root FROM jsonb_array_elements(proof->'before'->'policies') item WHERE item->>'id'=root_identity;
   IF before_root IS NULL OR root_identity IS DISTINCT FROM proof->>'rootId'
    OR root_state-ARRAY['version','retired_at'] IS DISTINCT FROM before_root-ARRAY['version','retired_at']
    OR (root_state->>'version')::bigint<>(before_root->>'version')::bigint+1 OR before_root->'retired_at' IS DISTINCT FROM 'null'::jsonb
    OR root_state->'retired_at'='null'::jsonb OR (root_state->>'retired_at')::timestamptz<(proof->>'observedAt')::timestamptz-interval '1 millisecond'
    OR (root_state->>'retired_at')::timestamptz>identity_membership_review_now()+interval '1 millisecond'
    THEN RAISE EXCEPTION 'Exact one-way owned policy retirement required' USING ERRCODE='23514';END IF;
   SELECT identity_directory_group_review_sort(jsonb_agg(CASE WHEN item->>'id'=root_identity THEN root_state ELSE item END)) INTO expected_policies FROM jsonb_array_elements(proof->'before'->'policies') item;
   expected_leases=proof->'before'->'leases';
  END IF;
  expected_members=proof->'before'->'members';
 ELSE
  SELECT item INTO root_state FROM jsonb_array_elements(actual->'leases') item WHERE item->>'id'=root_identity;
  SELECT item INTO before_root FROM jsonb_array_elements(proof->'before'->'leases') item WHERE item->>'id'=root_identity;
  SELECT item INTO policy_state FROM jsonb_array_elements(actual->'policies') item WHERE item->>'id'=root_state->>'policy_id';
  IF root_state IS NULL OR before_root IS NULL OR root_identity IS DISTINCT FROM proof->>'rootId' OR policy_state IS NULL
   OR NOT identity_directory_group_policy_owned((policy_state->>'id')::uuid,(proof->'tenant'->>'id')::uuid)
   OR root_state-ARRAY['version','cycle','state','due_at','deadline_at','projected_active'] IS DISTINCT FROM before_root-ARRAY['version','cycle','state','due_at','deadline_at','projected_active']
   OR (root_state->>'version')::bigint<>(before_root->>'version')::bigint+1 OR before_root->>'state'<>'pending'
   OR (before_root->>'due_at')::timestamptz>identity_membership_review_now() OR (before_root->>'deadline_at')::timestamptz<=identity_membership_review_now()
   OR NOT identity_membership_review_independent((proof->'context'->>'userId')::uuid,(root_state->>'membership_id')::uuid,(policy_state->>'created_by')::uuid)
   THEN RAISE EXCEPTION 'Actual current independent owned review decision required' USING ERRCODE='23514';END IF;
  IF action_name='retain' THEN
   IF root_state->>'state'<>'pending' OR (root_state->>'cycle')::bigint<>(before_root->>'cycle')::bigint+1
    OR root_state->'projected_active' IS DISTINCT FROM 'true'::jsonb OR policy_state->'retired_at' IS DISTINCT FROM 'null'::jsonb
    OR NOT identity_membership_review_allowed((root_state->>'membership_id')::uuid)
    OR (root_state->>'due_at')::timestamptz<(proof->>'observedAt')::timestamptz+(policy_state->>'interval_seconds')::integer*interval '1 second'-interval '1 millisecond'
    OR (root_state->>'due_at')::timestamptz>identity_membership_review_now()+(policy_state->>'interval_seconds')::integer*interval '1 second'+interval '1 millisecond'
    OR (root_state->>'deadline_at')::timestamptz-(root_state->>'due_at')::timestamptz<>(policy_state->>'window_seconds')::integer*interval '1 second'
    THEN RAISE EXCEPTION 'Exact bounded independent retention required' USING ERRCODE='23514';END IF;
   expected_members=proof->'before'->'members';
  ELSE
   IF root_state->>'state'<>'denied' OR root_state->'cycle' IS DISTINCT FROM before_root->'cycle' OR root_state->'due_at' IS DISTINCT FROM before_root->'due_at'
    OR root_state->'deadline_at' IS DISTINCT FROM before_root->'deadline_at' OR root_state->'projected_active' IS DISTINCT FROM 'false'::jsonb
    THEN RAISE EXCEPTION 'Exact one-way review denial required' USING ERRCODE='23514';END IF;
   SELECT COALESCE(jsonb_agg(item ORDER BY item->>'membership_id'),'[]'::jsonb) INTO expected_members FROM jsonb_array_elements(proof->'before'->'members') item WHERE item->>'membership_id'<>root_state->>'membership_id';
  END IF;
  expected_policies=proof->'before'->'policies';
  SELECT identity_directory_group_review_sort(jsonb_agg(CASE WHEN item->>'id'=root_identity THEN root_state ELSE item END)) INTO expected_leases FROM jsonb_array_elements(proof->'before'->'leases') item;
 END IF;
 IF actual->'policies' IS DISTINCT FROM expected_policies OR actual->'leases' IS DISTINCT FROM expected_leases OR actual->'members' IS DISTINCT FROM expected_members
  OR NOT EXISTS(SELECT 1 FROM identity_membership_review_audit evidence WHERE evidence.action=action_name
   AND CASE WHEN action_name IN ('create','retire') THEN evidence.policy_id=root_identity::uuid AND evidence.review_id IS NULL ELSE evidence.review_id=root_identity::uuid END
   AND evidence.actor->>'issuer'=proof->>'issuer' AND evidence.actor->>'subject'=proof->>'subject' AND evidence.actor->>'userId'=proof->'context'->>'userId'
   AND evidence.reason=proof->'intent'->>'reason' AND identity_directory_group_review_state(evidence.details)=root_state)
  THEN RAISE EXCEPTION 'Exact group review state and mandatory original transition evidence required' USING ERRCODE='23514';END IF;
 RETURN actual;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_review_evidence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;event identity_directory_group_review_events%ROWTYPE;
BEGIN
 proof=NULLIF(current_setting('opendirectory.group_review',true),'')::jsonb;
 IF TG_OP<>'INSERT' OR proof IS NULL OR NEW.id::text IS DISTINCT FROM proof->>'operationId'
  OR current_setting('opendirectory.group_review_finishing',true) IS DISTINCT FROM proof->>'operationId'
  OR current_setting('opendirectory.group_review_admitted',true) IS DISTINCT FROM proof->>'operationId'
  OR NEW.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id' OR NEW.action IS DISTINCT FROM proof->>'action'
  THEN RAISE EXCEPTION 'Actual original group-review transition evidence required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_directory_group_review_events' THEN
  IF NEW.group_id::text IS DISTINCT FROM proof->>'groupId' OR NEW.root_id::text IS DISTINCT FROM current_setting('opendirectory.group_review_root',true)
   OR NEW.transaction_id<>txid_current() OR NEW.actor IS DISTINCT FROM jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId')
   OR NEW.scope_sha256 IS DISTINCT FROM encode(sha256(convert_to(proof::text,'UTF8')),'hex')
   THEN RAISE EXCEPTION 'Exact admitted group-review origin required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO event FROM identity_directory_group_review_events WHERE id=NEW.id;
  IF event.id IS NULL OR event.tenant_id<>NEW.tenant_id OR event.action<>NEW.action OR event.transaction_id<>txid_current()
   THEN RAISE EXCEPTION 'Exact group-review outbox origin required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_review_finish() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;actual JSONB;owner_role NAME;
BEGIN
 SELECT pg_catalog.pg_get_userbyid(relowner) INTO owner_role FROM pg_catalog.pg_class WHERE oid='groups'::regclass;
 IF owner_role IS NULL OR NOT pg_catalog.pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
  THEN RAISE EXCEPTION 'Actual database owner required for group-review finalization' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.group_review',true),'')::jsonb;
 IF proof IS NULL OR current_setting('opendirectory.group_review_admitted',true) IS DISTINCT FROM proof->>'operationId'
  THEN RAISE EXCEPTION 'Actual admitted group-review root required' USING ERRCODE='42501';END IF;
 actual=identity_directory_group_review_validate(proof);PERFORM set_config('opendirectory.group_review_finishing',proof->>'operationId',true);
 INSERT INTO identity_directory_group_review_events(id,tenant_id,group_id,root_id,action,actor,scope_sha256,details)
  VALUES((proof->>'operationId')::uuid,(proof->'tenant'->>'id')::uuid,(proof->>'groupId')::uuid,current_setting('opendirectory.group_review_root',true)::uuid,proof->>'action',
   jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId'),encode(sha256(convert_to(proof::text,'UTF8')),'hex'),
   jsonb_build_object('beforeSha256',encode(sha256(convert_to((proof->'before')::text,'UTF8')),'hex'),'afterSha256',encode(sha256(convert_to(actual::text,'UTF8')),'hex')));
 INSERT INTO identity_directory_group_review_outbox(id,tenant_id,action) VALUES((proof->>'operationId')::uuid,(proof->'tenant'->>'id')::uuid,proof->>'action');
 PERFORM set_config('opendirectory.group_review_finishing','',true);
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_review_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;group_identity UUID;event identity_directory_group_review_events%ROWTYPE;actual JSONB;membership_identity UUID;
BEGIN
 IF TG_TABLE_NAME='groups' THEN IF TG_OP='DELETE' THEN group_identity=OLD.id;ELSE group_identity=NEW.id;END IF;
 ELSIF TG_TABLE_NAME IN ('group_members','identity_membership_review_policies') THEN IF TG_OP='DELETE' THEN group_identity=OLD.group_id;ELSE group_identity=NEW.group_id;END IF;
 ELSE IF TG_OP='DELETE' THEN membership_identity=OLD.membership_id;ELSE membership_identity=NEW.membership_id;END IF;SELECT group_id INTO group_identity FROM identity_membership_origins WHERE membership_id=membership_identity;END IF;
 proof=NULLIF(current_setting('opendirectory.group_review',true),'')::jsonb;
 IF proof IS NULL THEN IF EXISTS(SELECT 1 FROM identity_directory_group_review_events WHERE group_id=group_identity AND transaction_id=txid_current()) THEN RAISE EXCEPTION 'Group-review scope cannot disappear before commit' USING ERRCODE='42501';END IF;RETURN NULL;END IF;
 SELECT evidence.* INTO event FROM identity_directory_group_review_events evidence WHERE evidence.id=(proof->>'operationId')::uuid AND evidence.group_id=group_identity
  AND evidence.tenant_id=(proof->'tenant'->>'id')::uuid AND evidence.action=proof->>'action' AND evidence.transaction_id=txid_current()
  AND evidence.scope_sha256=encode(sha256(convert_to(proof::text,'UTF8')),'hex');
 IF event.id IS NULL OR NOT EXISTS(SELECT 1 FROM identity_directory_group_review_outbox evidence WHERE evidence.id=event.id AND evidence.tenant_id=event.tenant_id AND evidence.action=event.action)
  THEN RAISE EXCEPTION 'Durable exact group-review receipt required' USING ERRCODE='23514';END IF;
 actual=identity_directory_group_review_validate(proof);
 IF event.details->>'afterSha256' IS DISTINCT FROM encode(sha256(convert_to(actual::text,'UTF8')),'hex')
  THEN RAISE EXCEPTION 'Group-review state cannot drift after confirmation' USING ERRCODE='23514';END IF;RETURN NULL;
END; $$;

DO $$ DECLARE relation TEXT;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['groups','group_members','identity_membership_review_policies','identity_membership_review_leases','users','identity_subject_links','identity_membership_origins'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_directory_group_review ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_directory_group_review BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_directory_group_review_guard()',relation);
  IF relation IN ('groups','group_members','identity_membership_review_policies','identity_membership_review_leases') THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_directory_group_review_commit ON %I',relation);
   EXECUTE format('CREATE CONSTRAINT TRIGGER identity_directory_group_review_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_directory_group_review_commit()',relation);
  END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['identity_directory_group_review_events','identity_directory_group_review_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_directory_group_review_evidence ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_directory_group_review_evidence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_directory_group_review_evidence()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_directory_group_policy_owned(uuid,uuid)','identity_directory_group_review_state(jsonb)','identity_directory_group_review_sort(jsonb)',
  'identity_directory_group_review_snapshot(uuid)','identity_directory_group_review_actor(jsonb)','identity_directory_group_review_guard()',
  'identity_directory_group_review_validate(jsonb)','identity_directory_group_review_evidence()','identity_directory_group_review_finish()','identity_directory_group_review_commit()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
