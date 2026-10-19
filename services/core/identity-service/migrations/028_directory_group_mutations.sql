CREATE TABLE IF NOT EXISTS identity_directory_group_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),group_id UUID NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('update','delete','member-add','member-remove')),actor JSONB NOT NULL,
 scope_sha256 TEXT NOT NULL CHECK(scope_sha256 ~ '^[a-f0-9]{64}$'),details JSONB NOT NULL,
 transaction_id BIGINT NOT NULL DEFAULT txid_current(),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS identity_directory_group_events_target ON identity_directory_group_events(tenant_id,group_id,created_at);
CREATE TABLE IF NOT EXISTS identity_directory_group_outbox (
 id UUID PRIMARY KEY REFERENCES identity_directory_group_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action IN ('update','delete','member-add','member-remove')),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION identity_directory_group_state(data JSONB) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT data || COALESCE((SELECT jsonb_object_agg(field,data->>field) FROM unnest(ARRAY['revision','tenant_generation']) field WHERE data ? field),'{}'::jsonb);
$$;
CREATE OR REPLACE FUNCTION identity_directory_group_members(identity UUID) RETURNS jsonb LANGUAGE sql SECURITY DEFINER AS $$
 SELECT COALESCE(jsonb_agg(to_jsonb(member) ORDER BY member.membership_id),'[]'::jsonb) FROM group_members member WHERE member.group_id=identity;
$$;
CREATE OR REPLACE FUNCTION identity_directory_group_row(identity UUID) RETURNS jsonb LANGUAGE sql SECURITY DEFINER AS $$
 SELECT identity_directory_group_state(to_jsonb(collection)) FROM groups collection WHERE collection.id=identity;
$$;

CREATE OR REPLACE FUNCTION identity_directory_group_validate(proof JSONB) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE group_identity UUID;member_identity UUID;action_name TEXT;before_state JSONB;actual JSONB;members JSONB;expected_members JSONB;member_state JSONB;governance JSONB;
BEGIN
 PERFORM identity_directory_creation_actor(proof);
 group_identity=(proof->'target'->>'id')::uuid;action_name=proof->'target'->>'action';before_state=proof->'target'->'before';
 IF identity_tenant_id('group',group_identity)::text IS DISTINCT FROM proof->'tenant'->>'id'
  OR action_name IS NULL OR action_name NOT IN ('update','delete','member-add','member-remove')
  OR before_state->>'id' IS DISTINCT FROM group_identity::text OR jsonb_typeof(proof->'target'->'beforeMembers') IS DISTINCT FROM 'array'
  THEN RAISE EXCEPTION 'Exact owned group mutation origin required' USING ERRCODE='23514';END IF;
 actual=identity_directory_group_row(group_identity);members=identity_directory_group_members(group_identity);
 IF action_name='delete' THEN
  IF actual IS NOT NULL OR members<>'[]'::jsonb OR proof->'target'->'expectedValues' IS DISTINCT FROM 'null'::jsonb
   OR NOT EXISTS(SELECT 1 FROM identity_tenant_retirements WHERE resource_kind='group' AND resource_id=group_identity AND tenant_id=(proof->'tenant'->>'id')::uuid)
   OR NOT EXISTS(SELECT 1 FROM identity_deleted_groups deleted JOIN identity_group_audit audit ON audit.group_id=deleted.group_id AND audit.revision=deleted.revision
    JOIN identity_group_outbox outbox ON outbox.group_id=deleted.group_id AND outbox.revision=deleted.revision
    WHERE deleted.group_id=group_identity AND deleted.revision>(before_state->>'revision')::bigint AND audit.action='delete'
    AND audit.actor=proof->>'subject' AND outbox.payload->'deleted'='true'::jsonb)
   THEN RAISE EXCEPTION 'Actual group deletion and retained negative evidence required' USING ERRCODE='23514';END IF;
 ELSE
  IF actual IS NULL OR actual-ARRAY['name','description','updated_at','revision'] IS DISTINCT FROM before_state-ARRAY['name','description','updated_at','revision']
   OR jsonb_build_object('name',actual->'name','description',actual->'description') IS DISTINCT FROM proof->'target'->'expectedValues'
   OR (actual->>'revision')::bigint<=(before_state->>'revision')::bigint
   OR NOT EXISTS(SELECT 1 FROM identity_group_audit audit JOIN identity_group_outbox outbox ON outbox.group_id=audit.group_id AND outbox.revision=audit.revision
    WHERE audit.group_id=group_identity AND audit.revision=(actual->>'revision')::bigint AND audit.action='update'
    AND audit.actor=proof->>'subject' AND outbox.payload->'deleted'='false'::jsonb)
   THEN RAISE EXCEPTION 'Exact group content, revision and core evidence required' USING ERRCODE='23514';END IF;
 END IF;
 IF action_name='update' THEN expected_members=proof->'target'->'beforeMembers';
 ELSIF action_name='delete' THEN expected_members='[]'::jsonb;
 ELSE
  IF proof->'target'->'member'->>'userId' IS NULL
   OR identity_tenant_id('user',(proof->'target'->'member'->>'userId')::uuid)::text IS DISTINCT FROM proof->'tenant'->>'id'
   OR NOT EXISTS(SELECT 1 FROM users account WHERE account.id=(proof->'target'->'member'->>'userId')::uuid
    AND account.eligibility_revision::text=proof->'target'->'member'->>'eligibilityRevision')
   THEN RAISE EXCEPTION 'Exact owned canonical membership recipient required' USING ERRCODE='23514';END IF;
  member_identity=CASE WHEN action_name='member-add' THEN NULLIF(current_setting('opendirectory.group_mutation_membership',true),'')::uuid ELSE (proof->'target'->'member'->>'id')::uuid END;
  SELECT to_jsonb(member) INTO member_state FROM group_members member WHERE member.membership_id=member_identity;
  IF action_name='member-add' THEN
   IF member_state IS NULL OR member_state->>'group_id' IS DISTINCT FROM group_identity::text
    OR member_state->>'user_id' IS DISTINCT FROM proof->'target'->'member'->>'userId'
    OR proof->'target'->'member'->'before' IS DISTINCT FROM 'null'::jsonb OR proof->'target'->'member'->'id' IS DISTINCT FROM 'null'::jsonb
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'target'->'beforeMembers') item WHERE item->>'user_id'=proof->'target'->'member'->>'userId')
    OR NOT EXISTS(SELECT 1 FROM identity_membership_origins origin WHERE origin.membership_id=member_identity
     AND origin.group_id=group_identity AND origin.user_id=(proof->'target'->'member'->>'userId')::uuid
     AND origin.created_by=(proof->'context'->>'userId')::uuid AND origin.eligibility_revision::text=proof->'target'->'member'->>'eligibilityRevision')
    THEN RAISE EXCEPTION 'Actual server-generated membership and original source capture required' USING ERRCODE='23514';END IF;
   governance=proof->'target'->'governance';
   IF governance IS DISTINCT FROM 'null'::jsonb THEN
    IF NOT EXISTS(SELECT 1 FROM identity_membership_review_leases lease JOIN identity_membership_review_policies policy ON policy.id=lease.policy_id
     WHERE lease.membership_id=member_identity AND policy.id=(governance->>'id')::uuid
     AND policy.group_id=group_identity AND policy.issuer=proof->>'issuer' AND policy.version::text=governance->>'version' AND policy.retired_at IS NULL
     AND NOT lease.initial_grace AND NOT lease.projected_active AND lease.version=1 AND lease.cycle=1 AND lease.state='pending'
     AND lease.deadline_at-lease.due_at=(governance->>'windowSeconds')::integer*interval '1 second'
     AND NOT identity_membership_review_allowed(lease.membership_id))
     THEN RAISE EXCEPTION 'Actual independent first approval must remain pending' USING ERRCODE='23514';END IF;
   ELSIF EXISTS(SELECT 1 FROM identity_membership_review_policies WHERE group_id=group_identity)
    OR EXISTS(SELECT 1 FROM identity_membership_review_leases WHERE membership_id=member_identity)
    THEN RAISE EXCEPTION 'Group governance cannot change inside membership admission' USING ERRCODE='23514';END IF;
   SELECT jsonb_agg(item ORDER BY item->>'membership_id') INTO expected_members
    FROM jsonb_array_elements((proof->'target'->'beforeMembers')||jsonb_build_array(member_state)) item;
  ELSE
   IF member_state IS NOT NULL OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'target'->'beforeMembers') item
    WHERE item=proof->'target'->'member'->'before' AND item->>'membership_id'=proof->'target'->'member'->>'id'
    AND item->>'user_id'=proof->'target'->'member'->>'userId')
    OR NOT EXISTS(SELECT 1 FROM identity_membership_origins origin WHERE origin.membership_id=(proof->'target'->'member'->>'id')::uuid
     AND origin.group_id=group_identity AND origin.user_id=(proof->'target'->'member'->>'userId')::uuid)
    THEN RAISE EXCEPTION 'Exact removed membership incarnation and retained origin required' USING ERRCODE='23514';END IF;
   SELECT COALESCE(jsonb_agg(item ORDER BY item->>'membership_id'),'[]'::jsonb) INTO expected_members
    FROM jsonb_array_elements(proof->'target'->'beforeMembers') item WHERE item->>'membership_id'<>proof->'target'->'member'->>'id';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM identity_group_audit audit WHERE audit.group_id=group_identity AND audit.revision=(actual->>'revision')::bigint
   AND audit.actor=proof->>'subject' AND audit.action=CASE WHEN action_name='member-add' THEN 'member-added' ELSE 'member-removed' END
   AND audit.details->>'userId'=proof->'target'->'member'->>'userId')
   THEN RAISE EXCEPTION 'Actual membership transition audit required' USING ERRCODE='23514';END IF;
 END IF;
 IF members IS DISTINCT FROM expected_members THEN RAISE EXCEPTION 'Only exact admitted membership changes may commit' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('group',actual,'members',members);
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_mutation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;group_identity UUID;action_name TEXT;admitted BOOLEAN;actual JSONB;owner_role NAME;
BEGIN
 proof=NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb;
 IF proof IS NULL THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 IF TG_TABLE_NAME='users' OR TG_OP='INSERT' AND TG_TABLE_NAME='groups' OR TG_OP='UPDATE' AND TG_TABLE_NAME='group_members'
  THEN RAISE EXCEPTION 'Group admission cannot mutate users, create groups or rewrite memberships' USING ERRCODE='42501';END IF;
 SELECT pg_catalog.pg_get_userbyid(relowner) INTO owner_role FROM pg_catalog.pg_class WHERE oid=TG_RELID;
 IF owner_role IS NULL OR NOT pg_catalog.pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
  THEN RAISE EXCEPTION 'Actual database owner required for original-actor group mutation' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='groups' THEN group_identity=OLD.id;ELSIF TG_OP='DELETE' THEN group_identity=OLD.group_id;ELSE group_identity=NEW.group_id;END IF;
 action_name=proof->'target'->>'action';admitted=COALESCE(current_setting('opendirectory.group_mutation_admitted',true)=proof->>'operationId',false);
 IF group_identity::text IS DISTINCT FROM proof->'target'->>'id' OR identity_tenant_id('group',group_identity)::text IS DISTINCT FROM proof->'tenant'->>'id'
  THEN RAISE EXCEPTION 'Exact owned group mutation target required' USING ERRCODE='23514';END IF;
 PERFORM identity_directory_creation_actor(proof);
 IF TG_TABLE_NAME='groups' AND TG_OP='UPDATE' AND admitted AND action_name IN ('member-add','member-remove') AND pg_trigger_depth()>1 THEN
  IF identity_directory_group_state(to_jsonb(NEW))-ARRAY['updated_at'] IS DISTINCT FROM identity_directory_group_state(to_jsonb(OLD))-ARRAY['updated_at']
   THEN RAISE EXCEPTION 'Only actual membership-induced group version updates permitted' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='group_members' AND TG_OP='DELETE' AND admitted AND action_name='delete' AND pg_trigger_depth()>1 THEN
  IF EXISTS(SELECT 1 FROM groups WHERE id=group_identity) OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'target'->'beforeMembers') item WHERE item=to_jsonb(OLD))
   THEN RAISE EXCEPTION 'Only actual group-delete membership cascade permitted' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 IF admitted OR identity_directory_group_row(group_identity) IS DISTINCT FROM proof->'target'->'before'
  OR identity_directory_group_members(group_identity) IS DISTINCT FROM proof->'target'->'beforeMembers'
  THEN RAISE EXCEPTION 'One exact locked group root transition required' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='groups' THEN
  IF (TG_OP='DELETE') IS DISTINCT FROM (action_name='delete') OR action_name NOT IN ('update','delete')
   THEN RAISE EXCEPTION 'Exact group operation required' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' AND (identity_directory_group_state(to_jsonb(NEW))-ARRAY['name','description','updated_at'] IS DISTINCT FROM (proof->'target'->'before')-ARRAY['name','description','updated_at']
   OR jsonb_build_object('name',NEW.name,'description',NEW.description) IS DISTINCT FROM proof->'target'->'expectedValues')
   THEN RAISE EXCEPTION 'Only exact requested group metadata may change' USING ERRCODE='23514';END IF;
 ELSE
  IF (TG_OP='INSERT') IS DISTINCT FROM (action_name='member-add') OR action_name NOT IN ('member-add','member-remove')
   THEN RAISE EXCEPTION 'Exact membership operation required' USING ERRCODE='23514';END IF;
  IF TG_OP='INSERT' THEN actual=to_jsonb(NEW);ELSE actual=to_jsonb(OLD);END IF;
  IF actual->>'user_id' IS DISTINCT FROM proof->'target'->'member'->>'userId'
   OR identity_tenant_id('user',(actual->>'user_id')::uuid)::text IS DISTINCT FROM proof->'tenant'->>'id'
   OR TG_OP='DELETE' AND (actual IS DISTINCT FROM proof->'target'->'member'->'before' OR actual->>'membership_id' IS DISTINCT FROM proof->'target'->'member'->>'id')
   OR TG_OP='INSERT' AND (proof->'target'->'member'->'id' IS DISTINCT FROM 'null'::jsonb OR proof->'target'->'member'->'before' IS DISTINCT FROM 'null'::jsonb)
   OR TG_OP='INSERT' AND actual-ARRAY['membership_id','group_id','user_id','added_at']<>'{}'::jsonb
   THEN RAISE EXCEPTION 'Exact owned membership incarnation required' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_TABLE_NAME='group_members' AND TG_OP='INSERT' THEN
  PERFORM set_config('opendirectory.group_mutation_admitting',proof->>'operationId',true);RETURN NEW;
 END IF;
 PERFORM set_config('opendirectory.group_mutation_admitted',proof->>'operationId',true);
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_membership_generation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;
BEGIN
 NEW.membership_id=gen_random_uuid();proof=NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb;
 IF proof IS NOT NULL THEN
  IF current_setting('opendirectory.group_mutation_admitting',true) IS DISTINCT FROM proof->>'operationId'
   OR NULLIF(current_setting('opendirectory.group_mutation_admitted',true),'') IS NOT NULL
   OR proof->'target'->>'action' IS DISTINCT FROM 'member-add' OR NEW.group_id::text IS DISTINCT FROM proof->'target'->>'id'
   OR NEW.user_id IS DISTINCT FROM proof->'target'->'member'->>'userId'
   OR EXISTS(SELECT 1 FROM identity_membership_origins WHERE membership_id=NEW.membership_id)
   THEN RAISE EXCEPTION 'Actual admitted fresh membership generation required' USING ERRCODE='23514';END IF;
  PERFORM identity_directory_creation_actor(proof);
  PERFORM set_config('opendirectory.group_mutation_membership',NEW.membership_id::text,true);
  PERFORM set_config('opendirectory.group_mutation_admitted',proof->>'operationId',true);
  PERFORM set_config('opendirectory.group_mutation_admitting','',true);
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_evidence_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;event identity_directory_group_events%ROWTYPE;
BEGIN
 proof=NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb;
 IF TG_OP<>'INSERT' OR proof IS NULL OR NEW.id::text IS DISTINCT FROM proof->>'operationId'
  OR current_setting('opendirectory.group_mutation_finishing',true) IS DISTINCT FROM proof->>'operationId'
  OR current_setting('opendirectory.group_mutation_admitted',true) IS DISTINCT FROM proof->>'operationId'
  OR NEW.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id' OR NEW.action IS DISTINCT FROM proof->'target'->>'action'
  THEN RAISE EXCEPTION 'Actual admitted group transition evidence required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_directory_group_events' THEN
  IF NEW.group_id::text IS DISTINCT FROM proof->'target'->>'id' OR NEW.transaction_id<>txid_current()
   OR NEW.actor IS DISTINCT FROM jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId')
   OR NEW.scope_sha256 IS DISTINCT FROM encode(sha256(convert_to(proof::text,'UTF8')),'hex')
   THEN RAISE EXCEPTION 'Exact original-actor group evidence required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO event FROM identity_directory_group_events WHERE id=NEW.id;
  IF event.id IS NULL OR event.tenant_id<>NEW.tenant_id OR event.action<>NEW.action OR event.transaction_id<>txid_current()
   THEN RAISE EXCEPTION 'Exact group outbox origin required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_finish() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;after_state JSONB;owner_role NAME;
BEGIN
 SELECT pg_catalog.pg_get_userbyid(relowner) INTO owner_role FROM pg_catalog.pg_class WHERE oid='groups'::regclass;
 IF owner_role IS NULL OR NOT pg_catalog.pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
  THEN RAISE EXCEPTION 'Actual database owner required for group finalization' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb;
 IF proof IS NULL OR current_setting('opendirectory.group_mutation_admitted',true) IS DISTINCT FROM proof->>'operationId'
  THEN RAISE EXCEPTION 'Actual admitted group transition required' USING ERRCODE='42501';END IF;
 after_state=identity_directory_group_validate(proof);PERFORM set_config('opendirectory.group_mutation_finishing',proof->>'operationId',true);
 INSERT INTO identity_directory_group_events(id,tenant_id,group_id,action,actor,scope_sha256,details)
  VALUES((proof->>'operationId')::uuid,(proof->'tenant'->>'id')::uuid,(proof->'target'->>'id')::uuid,proof->'target'->>'action',
   jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId'),encode(sha256(convert_to(proof::text,'UTF8')),'hex'),
   jsonb_build_object('beforeRevision',proof->'target'->'before'->>'revision','afterRevision',after_state->'group'->>'revision',
    'beforeSha256',encode(sha256(convert_to(jsonb_build_object('group',proof->'target'->'before','members',proof->'target'->'beforeMembers')::text,'UTF8')),'hex'),
    'afterSha256',encode(sha256(convert_to(after_state::text,'UTF8')),'hex')));
 INSERT INTO identity_directory_group_outbox(id,tenant_id,action) VALUES((proof->>'operationId')::uuid,(proof->'tenant'->>'id')::uuid,proof->'target'->>'action');
 PERFORM set_config('opendirectory.group_mutation_finishing','',true);
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_group_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;group_identity UUID;event identity_directory_group_events%ROWTYPE;actual JSONB;
BEGIN
 IF TG_TABLE_NAME='groups' THEN IF TG_OP='DELETE' THEN group_identity=OLD.id;ELSE group_identity=NEW.id;END IF;
 ELSIF TG_OP='DELETE' THEN group_identity=OLD.group_id;ELSE group_identity=NEW.group_id;END IF;
 proof=NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb;
 IF proof IS NULL THEN
  IF EXISTS(SELECT 1 FROM identity_directory_group_events WHERE group_id=group_identity AND transaction_id=txid_current())
   THEN RAISE EXCEPTION 'Group mutation scope cannot disappear before commit' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 SELECT evidence.* INTO event FROM identity_directory_group_events evidence WHERE evidence.id=(proof->>'operationId')::uuid AND evidence.group_id=group_identity
  AND evidence.tenant_id=(proof->'tenant'->>'id')::uuid AND evidence.action=proof->'target'->>'action' AND evidence.transaction_id=txid_current()
  AND evidence.scope_sha256=encode(sha256(convert_to(proof::text,'UTF8')),'hex');
 IF event.id IS NULL OR NOT EXISTS(SELECT 1 FROM identity_directory_group_outbox evidence WHERE evidence.id=event.id AND evidence.tenant_id=event.tenant_id AND evidence.action=event.action)
  THEN RAISE EXCEPTION 'Durable exact group mutation receipt required' USING ERRCODE='23514';END IF;
 actual=identity_directory_group_validate(proof);
 IF event.details->>'afterSha256' IS DISTINCT FROM encode(sha256(convert_to(actual::text,'UTF8')),'hex')
  THEN RAISE EXCEPTION 'Group content cannot drift after receiving confirmation' USING ERRCODE='23514';END IF;RETURN NULL;
END; $$;

DO $$ DECLARE relation TEXT;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['groups','group_members','users'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_directory_group_mutation ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_directory_group_mutation BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_directory_group_mutation_guard()',relation);
  IF relation<>'users' THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_directory_group_commit ON %I',relation);
   EXECUTE format('CREATE CONSTRAINT TRIGGER identity_directory_group_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_directory_group_commit()',relation);
  END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['identity_directory_group_events','identity_directory_group_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_directory_group_evidence_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_directory_group_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_directory_group_evidence_guard()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_directory_group_state(jsonb)','identity_directory_group_members(uuid)','identity_directory_group_row(uuid)',
  'identity_directory_group_validate(jsonb)','identity_directory_group_mutation_guard()','identity_directory_group_evidence_guard()',
  'identity_directory_group_finish()','identity_directory_group_commit()','identity_membership_generation()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
