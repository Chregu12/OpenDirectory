CREATE TABLE IF NOT EXISTS identity_company_offboarding_group_receipts (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,workflow_id UUID NOT NULL,user_id UUID NOT NULL,group_id UUID NOT NULL,membership_id UUID NOT NULL,
 before_group_revision BIGINT NOT NULL CHECK(before_group_revision>0),after_group_revision BIGINT NOT NULL CHECK(after_group_revision>before_group_revision),
 operation_id UUID NOT NULL UNIQUE REFERENCES identity_directory_group_events(id),actor_user_id UUID NOT NULL,correlation_id UUID NOT NULL,
 reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500 AND btrim(reason)=reason AND reason!~'[[:cntrl:]]'),name TEXT NOT NULL,
 eligibility_revision BIGINT NOT NULL CHECK(eligibility_revision>0),source JSONB NOT NULL,child_proof JSONB NOT NULL,child_after JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL DEFAULT txid_current(),
 FOREIGN KEY(tenant_id,workflow_id) REFERENCES identity_company_offboarding_receipts(tenant_id,workflow_id),
 UNIQUE(tenant_id,workflow_id,membership_id),CHECK(user_id<>actor_user_id AND isfinite(created_at) AND isfinite(valid_until) AND created_at<valid_until)
);
CREATE INDEX IF NOT EXISTS identity_company_offboarding_group_history ON identity_company_offboarding_group_receipts(tenant_id,workflow_id,user_id,created_at,id);
CREATE TABLE IF NOT EXISTS identity_company_offboarding_group_outbox (
 id UUID PRIMARY KEY REFERENCES identity_company_offboarding_group_receipts(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_offboarding_group_checks (
 transaction_id BIGINT PRIMARY KEY DEFAULT txid_current(),source JSONB NOT NULL
);

CREATE OR REPLACE FUNCTION identity_company_offboarding_groups_actor(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_company_offboarding_actor(proof);
 IF jsonb_typeof(proof) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(proof))<>18
  OR NOT proof ?& ARRAY['issuer','subject','context','tenant','rolesSnapshot','validUntil','tokenSha256','workflowId','userId','eligibilityRevision',
   'groupId','groupRevision','membershipId','operationId','receiptId','correlationId','reason','recovery']
  OR jsonb_typeof(proof->'tokenSha256') IS DISTINCT FROM 'string' OR proof->>'tokenSha256' !~ '^[a-f0-9]{64}$'
  OR jsonb_typeof(proof->'recovery') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(proof->'eligibilityRevision') IS DISTINCT FROM 'string' OR proof->>'eligibilityRevision' !~ '^[1-9][0-9]{0,18}$'
  OR jsonb_typeof(proof->'groupRevision') IS DISTINCT FROM 'string' OR proof->>'groupRevision' !~ '^[1-9][0-9]{0,18}$'
  OR (proof->>'groupRevision')::numeric>9223372036854775807 OR (proof->>'eligibilityRevision')::numeric>9223372036854775807
  OR jsonb_typeof(proof->'reason') IS DISTINCT FROM 'string' OR length(proof->>'reason') NOT BETWEEN 10 AND 500
  OR btrim(proof->>'reason') IS DISTINCT FROM proof->>'reason' OR proof->>'reason' ~ '[[:cntrl:]]'
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['workflowId','userId','groupId','membershipId','operationId','receiptId','correlationId']) field
   WHERE COALESCE(proof->>field,'') !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  THEN RAISE EXCEPTION 'Exact original bounded group cleanup source required' USING ERRCODE='23514';END IF;
 PERFORM identity_company_offboarding_validate((proof->'tenant'->>'id')::uuid,(proof->>'workflowId')::uuid,(proof->>'userId')::uuid);
 IF NOT EXISTS(SELECT 1 FROM identity_company_offboarding_receipts WHERE tenant_id=(proof->'tenant'->>'id')::uuid
  AND workflow_id=(proof->>'workflowId')::uuid AND user_id=(proof->>'userId')::uuid AND after_eligibility_revision::text=proof->>'eligibilityRevision')
  THEN RAISE EXCEPTION 'Original negative parent generation required' USING ERRCODE='23514';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_groups_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_offboarding_receiving();
 IF current_setting('session_replication_role')<>'origin' OR EXISTS(
  SELECT 1 FROM pg_class relation CROSS JOIN (VALUES('aaa_identity_company_offboarding_groups_fence',31),('aaa_identity_company_offboarding_groups_no_truncate',34)) expected(name,kind)
  WHERE relation.relnamespace=current_schema()::regnamespace AND relation.relkind IN('r','p') AND (left(relation.relname,9)='identity_' OR relation.relname IN('users','groups','group_members','ous'))
  AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O'
   AND NOT tgdeferrable AND tgfoid='identity_company_offboarding_groups_fence()'::regprocedure)
 ) OR EXISTS(
  SELECT 1 FROM unnest(ARRAY['identity_company_offboarding_group_receipts','identity_company_offboarding_group_outbox','identity_company_offboarding_group_checks']) relation(name)
  CROSS JOIN (VALUES('identity_company_offboarding_groups_guard',31,false,'identity_company_offboarding_groups_guard()'),
   ('identity_company_offboarding_groups_no_truncate',34,false,'identity_company_offboarding_groups_guard()'),
   ('identity_company_offboarding_groups_commit',29,true,'identity_company_offboarding_groups_commit()')) expected(name,kind,deferred,routine)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation.name) AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O'
   AND tgdeferrable=expected.deferred AND tginitdeferred=expected.deferred AND tgfoid=to_regprocedure(expected.routine))
 ) OR EXISTS(
  SELECT 1 FROM unnest(ARRAY['identity_company_offboarding_group_receipts','identity_company_offboarding_group_outbox','identity_company_offboarding_group_checks']) relation(name)
  CROSS JOIN (SELECT * FROM identity_license_user_source_hooks() UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence') hook
  CROSS JOIN (VALUES(false),(true)) truncation(enabled)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation.name)
   AND tgname=CASE WHEN truncation.enabled THEN regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate') ELSE hook.trigger_name END
   AND tgtype=CASE WHEN truncation.enabled THEN 34 ELSE 31 END AND tgenabled='O' AND NOT tgdeferrable AND tgfoid=to_regprocedure(hook.routine||'()'))
 ) OR EXISTS(
  SELECT 1 FROM (VALUES
   ('group_members','aaa_identity_directory_group_mutation',31,false,'identity_directory_group_mutation_guard()'),
   ('groups','aaa_identity_directory_group_mutation',31,false,'identity_directory_group_mutation_guard()'),
   ('groups','identity_directory_group_commit',29,true,'identity_directory_group_commit()'),
   ('group_members','identity_directory_group_commit',29,true,'identity_directory_group_commit()'),
   ('group_members','identity_member_change_record',13,false,'identity_member_changed()'),
   ('groups','identity_group_revision_guard',23,false,'identity_group_revision()'),
   ('groups','identity_group_change_record',29,false,'identity_group_record_change()'),
   ('identity_directory_group_events','identity_directory_group_evidence_guard',31,false,'identity_directory_group_evidence_guard()'),
   ('identity_directory_group_outbox','identity_directory_group_evidence_guard',31,false,'identity_directory_group_evidence_guard()')
  ) expected(relation,name,kind,deferred,routine)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(expected.relation) AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O'
   AND tgdeferrable=expected.deferred AND tginitdeferred=expected.deferred AND tgfoid=to_regprocedure(expected.routine))
 ) THEN RAISE EXCEPTION 'Complete company group cleanup receivers required' USING ERRCODE='55000';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_group_validate(identifier UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt identity_company_offboarding_group_receipts;event identity_directory_group_events;proof JSONB;expected_members JSONB;before_state JSONB;after_state JSONB;
BEGIN
 PERFORM identity_company_offboarding_groups_receiving();
 SELECT * INTO receipt FROM identity_company_offboarding_group_receipts WHERE id=identifier;
 IF receipt.id IS NULL THEN RAISE EXCEPTION 'Retained actual group cleanup receipt required' USING ERRCODE='23514';END IF;
 proof=receipt.child_proof;before_state=proof->'target'->'before';after_state=receipt.child_after->'group';
 PERFORM identity_company_offboarding_validate(receipt.tenant_id,receipt.workflow_id,receipt.user_id);
 SELECT * INTO event FROM identity_directory_group_events WHERE id=receipt.operation_id;
 SELECT COALESCE(jsonb_agg(member ORDER BY member->>'membership_id'),'[]'::jsonb) INTO expected_members
  FROM jsonb_array_elements(proof->'target'->'beforeMembers') member WHERE member->>'membership_id'<>receipt.membership_id::text;
 IF receipt.source->>'receiptId' IS DISTINCT FROM receipt.id::text OR receipt.source->>'operationId' IS DISTINCT FROM receipt.operation_id::text
  OR receipt.source->'recovery' IS DISTINCT FROM 'false'::jsonb OR receipt.source->'tenant'->>'id' IS DISTINCT FROM receipt.tenant_id::text
  OR receipt.source->>'workflowId' IS DISTINCT FROM receipt.workflow_id::text OR receipt.source->>'userId' IS DISTINCT FROM receipt.user_id::text
  OR receipt.source->>'groupId' IS DISTINCT FROM receipt.group_id::text OR receipt.source->>'membershipId' IS DISTINCT FROM receipt.membership_id::text
  OR receipt.source->>'groupRevision' IS DISTINCT FROM receipt.before_group_revision::text OR receipt.source->>'eligibilityRevision' IS DISTINCT FROM receipt.eligibility_revision::text
  OR receipt.source->'context'->>'userId' IS DISTINCT FROM receipt.actor_user_id::text OR receipt.source->>'correlationId' IS DISTINCT FROM receipt.correlation_id::text
  OR receipt.source->>'reason' IS DISTINCT FROM receipt.reason OR receipt.valid_until IS DISTINCT FROM to_timestamp((receipt.source->>'validUntil')::double precision)
  OR receipt.source->>'tokenSha256' !~ '^[a-f0-9]{64}$' OR receipt.name IS DISTINCT FROM before_state->>'name'
  OR NOT EXISTS(SELECT 1 FROM identity_company_offboarding_receipts WHERE tenant_id=receipt.tenant_id AND workflow_id=receipt.workflow_id
   AND user_id=receipt.user_id AND after_eligibility_revision=receipt.eligibility_revision)
  OR identity_tenant_id('group',receipt.group_id) IS DISTINCT FROM receipt.tenant_id
  OR proof->>'issuer' IS DISTINCT FROM receipt.source->>'issuer' OR proof->>'subject' IS DISTINCT FROM receipt.source->>'subject'
  OR proof->'context' IS DISTINCT FROM receipt.source->'context' OR proof->'tenant' IS DISTINCT FROM receipt.source->'tenant'
  OR proof->'rolesSnapshot' IS DISTINCT FROM receipt.source->'rolesSnapshot' OR (proof->>'validUntil')::numeric<(receipt.source->>'validUntil')::numeric
  OR proof->>'operationId' IS DISTINCT FROM receipt.operation_id::text OR proof->'target'->>'id' IS DISTINCT FROM receipt.group_id::text
  OR proof->'target'->>'action' IS DISTINCT FROM 'member-remove' OR proof->'target'->'member'->>'id' IS DISTINCT FROM receipt.membership_id::text
  OR proof->'target'->'member'->>'userId' IS DISTINCT FROM receipt.user_id::text OR proof->'target'->'member'->>'eligibilityRevision' IS DISTINCT FROM receipt.eligibility_revision::text
  OR before_state->>'id' IS DISTINCT FROM receipt.group_id::text OR before_state->>'revision' IS DISTINCT FROM receipt.before_group_revision::text
  OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(proof->'target'->'beforeMembers') member WHERE member=proof->'target'->'member'->'before'
   AND member->>'membership_id'=receipt.membership_id::text AND member->>'group_id'=receipt.group_id::text AND member->>'user_id'=receipt.user_id::text)
  OR NOT EXISTS(SELECT 1 FROM identity_membership_origins WHERE membership_id=receipt.membership_id AND group_id=receipt.group_id AND user_id=receipt.user_id)
  OR EXISTS(SELECT 1 FROM group_members WHERE membership_id=receipt.membership_id)
  OR after_state->>'revision' IS DISTINCT FROM receipt.after_group_revision::text
  OR after_state-ARRAY['revision','updated_at'] IS DISTINCT FROM before_state-ARRAY['revision','updated_at']
  OR proof->'target'->'expectedValues' IS DISTINCT FROM jsonb_build_object('name',before_state->'name','description',before_state->'description')
  OR receipt.child_after->'members' IS DISTINCT FROM expected_members
  OR event.id IS NULL OR event.tenant_id<>receipt.tenant_id OR event.group_id<>receipt.group_id OR event.action<>'member-remove' OR event.transaction_id<>receipt.transaction_id
  OR event.actor IS DISTINCT FROM jsonb_build_object('issuer',receipt.source->>'issuer','subject',receipt.source->>'subject','userId',receipt.actor_user_id)
  OR event.scope_sha256 IS DISTINCT FROM encode(sha256(convert_to(proof::text,'UTF8')),'hex')
  OR event.details IS DISTINCT FROM jsonb_build_object('beforeRevision',receipt.before_group_revision::text,'afterRevision',receipt.after_group_revision::text,
   'beforeSha256',encode(sha256(convert_to(jsonb_build_object('group',before_state,'members',proof->'target'->'beforeMembers')::text,'UTF8')),'hex'),
   'afterSha256',encode(sha256(convert_to(receipt.child_after::text,'UTF8')),'hex'))
  OR event.created_at>receipt.created_at OR NOT EXISTS(SELECT 1 FROM identity_directory_group_outbox WHERE id=event.id AND tenant_id=receipt.tenant_id AND action='member-remove' AND status='pending')
  OR NOT EXISTS(SELECT 1 FROM identity_group_audit audit JOIN identity_group_outbox outbox ON outbox.group_id=audit.group_id AND outbox.revision=audit.revision
   WHERE audit.group_id=receipt.group_id AND audit.revision=receipt.after_group_revision AND audit.action='member-removed' AND audit.actor=receipt.source->>'subject'
   AND audit.details=jsonb_build_object('userId',receipt.user_id) AND outbox.payload=jsonb_build_object('groupId',receipt.group_id,'revision',receipt.after_group_revision::text,'deleted',false))
  OR NOT EXISTS(SELECT 1 FROM identity_company_offboarding_group_outbox WHERE id=receipt.id AND tenant_id=receipt.tenant_id AND status='pending' AND created_at=receipt.created_at)
  THEN RAISE EXCEPTION 'Exact original GroupMutator effect, parent and pending cleanup outboxes required' USING ERRCODE='23514';END IF;
 IF receipt.transaction_id=txid_current() THEN
  IF receipt.source IS DISTINCT FROM NULLIF(current_setting('opendirectory.company_offboarding_groups',true),'')::jsonb
   OR receipt.child_proof IS DISTINCT FROM NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb
   OR receipt.child_after IS DISTINCT FROM identity_directory_group_validate(receipt.child_proof)
   THEN RAISE EXCEPTION 'Original live group cleanup source cannot change through commit' USING ERRCODE='23514';END IF;
  PERFORM identity_company_offboarding_groups_actor(receipt.source);
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_groups_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;receipt identity_company_offboarding_group_receipts;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_TABLE_NAME='identity_company_offboarding_group_checks' THEN
  IF TG_OP='DELETE' AND pg_trigger_depth()>1 AND OLD.transaction_id=txid_current() THEN RETURN OLD;END IF;
 END IF;
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM identity_company_offboarding_group_receipts) OR EXISTS(SELECT 1 FROM identity_company_offboarding_group_outbox)
   OR EXISTS(SELECT 1 FROM identity_company_offboarding_group_checks) OR NULLIF(current_setting('opendirectory.company_offboarding_groups',true),'') IS NOT NULL
   THEN RAISE EXCEPTION 'Company group cleanup evidence cannot be truncated' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 proof=NULLIF(current_setting('opendirectory.company_offboarding_groups',true),'')::jsonb;
 IF TG_OP<>'INSERT' OR proof IS NULL THEN RAISE EXCEPTION 'Company group cleanup evidence is immutable' USING ERRCODE='42501';END IF;
 PERFORM identity_company_offboarding_groups_actor(proof);
 IF TG_TABLE_NAME='identity_company_offboarding_group_checks' THEN
  IF NEW.transaction_id<>txid_current() OR NEW.source IS DISTINCT FROM proof THEN RAISE EXCEPTION 'Exact immutable original cleanup check required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='identity_company_offboarding_group_receipts' THEN
  IF proof->'recovery' IS DISTINCT FROM 'false'::jsonb OR NEW.source IS DISTINCT FROM proof OR NEW.transaction_id<>txid_current()
   OR NEW.id::text IS DISTINCT FROM proof->>'receiptId' OR NEW.operation_id::text IS DISTINCT FROM proof->>'operationId'
   OR NEW.child_proof IS DISTINCT FROM NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb
   OR NOT EXISTS(SELECT 1 FROM identity_company_offboarding_group_checks WHERE transaction_id=txid_current() AND source=proof)
   THEN RAISE EXCEPTION 'Original bound child cleanup receipt required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO receipt FROM identity_company_offboarding_group_receipts WHERE id=NEW.id;
  IF receipt.id IS NULL OR receipt.source IS DISTINCT FROM proof OR NEW.tenant_id<>receipt.tenant_id OR NEW.status<>'pending' OR NEW.created_at<>receipt.created_at
   THEN RAISE EXCEPTION 'Exact mandatory pending group cleanup outbox required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_groups_fence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;stored JSONB;child JSONB;data JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.company_offboarding_groups',true),'')::jsonb;
 SELECT source INTO stored FROM identity_company_offboarding_group_checks WHERE transaction_id=txid_current();
 IF stored IS NOT NULL AND proof IS DISTINCT FROM stored THEN RAISE EXCEPTION 'Original cleanup scope cannot disappear or change' USING ERRCODE='42501';END IF;
 IF proof IS NULL THEN
  PERFORM pg_advisory_xact_lock_shared(1948783475,1735549296);
  IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 PERFORM identity_authority_owner();PERFORM identity_company_offboarding_groups_actor(proof);
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Cleanup commands cannot truncate data' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_company_offboarding_group_checks' THEN
  IF TG_OP='INSERT' OR TG_OP='DELETE' AND pg_trigger_depth()>1 AND OLD.transaction_id=txid_current() THEN
   IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
  END IF;
 END IF;
 IF proof->'recovery'='true'::jsonb THEN RAISE EXCEPTION 'Retained cleanup recovery cannot have new effects' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' AND TG_TABLE_NAME IN('identity_company_offboarding_group_receipts','identity_company_offboarding_group_outbox') THEN RETURN NEW;END IF;
 child=NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb;
 IF stored IS NULL OR child->>'operationId' IS DISTINCT FROM proof->>'operationId' OR child->'target'->>'action' IS DISTINCT FROM 'member-remove'
  OR child->'target'->>'id' IS DISTINCT FROM proof->>'groupId' OR child->'target'->'before'->>'revision' IS DISTINCT FROM proof->>'groupRevision'
  OR child->'target'->'member'->>'id' IS DISTINCT FROM proof->>'membershipId' OR child->'target'->'member'->>'userId' IS DISTINCT FROM proof->>'userId'
  OR child->'target'->'member'->>'eligibilityRevision' IS DISTINCT FROM proof->>'eligibilityRevision'
  OR child->'context' IS DISTINCT FROM proof->'context' OR child->'tenant' IS DISTINCT FROM proof->'tenant'
  OR child->>'issuer' IS DISTINCT FROM proof->>'issuer' OR child->>'subject' IS DISTINCT FROM proof->>'subject' OR child->'rolesSnapshot' IS DISTINCT FROM proof->'rolesSnapshot'
  THEN RAISE EXCEPTION 'Only the bound original GroupMutator child may have effects' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='group_members' AND TG_OP='DELETE' AND to_jsonb(OLD)->>'membership_id'=proof->>'membershipId'
  AND to_jsonb(OLD)->>'group_id'=proof->>'groupId' AND to_jsonb(OLD)->>'user_id'=proof->>'userId' THEN RETURN OLD;END IF;
 IF TG_TABLE_NAME='groups' AND TG_OP='UPDATE' AND pg_trigger_depth()>1 AND to_jsonb(OLD)->>'id'=proof->>'groupId' THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  data=to_jsonb(NEW);
  IF TG_TABLE_NAME IN('identity_directory_group_events','identity_directory_group_outbox') AND data->>'id'=proof->>'operationId'
   AND data->>'tenant_id'=proof->'tenant'->>'id' AND data->>'action'='member-remove' THEN RETURN NEW;END IF;
  IF TG_TABLE_NAME IN('identity_group_audit','identity_group_outbox') AND pg_trigger_depth()>1 AND data->>'group_id'=proof->>'groupId'
   AND current_setting('opendirectory.group_mutation_admitted',true)=proof->>'operationId' THEN RETURN NEW;END IF;
 END IF;
 RAISE EXCEPTION 'Unrelated canonical effects cannot ride group cleanup' USING ERRCODE='42501';
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_groups_begin(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt identity_company_offboarding_group_receipts;
BEGIN
 PERFORM identity_company_offboarding_groups_receiving();PERFORM identity_company_offboarding_groups_actor(proof);
 IF NULLIF(current_setting('opendirectory.company_offboarding_groups',true),'') IS NOT NULL
  OR EXISTS(SELECT 1 FROM identity_company_offboarding_group_checks WHERE transaction_id=txid_current())
  OR EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid=1948783475::oid AND objid=1735549296::oid AND objsubid=2 AND mode='ShareLock' AND granted)
  THEN RAISE EXCEPTION 'One original cleanup child without earlier canonical effects required' USING ERRCODE='42501';END IF;
 PERFORM id FROM identity_tenants WHERE id=(proof->'tenant'->>'id')::uuid FOR SHARE;
 PERFORM id FROM users WHERE id IN((proof->'context'->>'userId')::uuid,(proof->>'userId')::uuid)
  AND identity_tenant_id('user',id)=(proof->'tenant'->>'id')::uuid ORDER BY id FOR UPDATE;
 PERFORM id FROM groups WHERE id=(proof->>'groupId')::uuid AND identity_tenant_id('group',id)=(proof->'tenant'->>'id')::uuid FOR UPDATE;
 IF proof->'recovery'='true'::jsonb THEN
  SELECT * INTO receipt FROM identity_company_offboarding_group_receipts WHERE id=(proof->>'receiptId')::uuid;
  IF receipt.id IS NULL OR receipt.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id' OR receipt.workflow_id::text IS DISTINCT FROM proof->>'workflowId'
   OR receipt.user_id::text IS DISTINCT FROM proof->>'userId' OR receipt.group_id::text IS DISTINCT FROM proof->>'groupId'
   OR receipt.membership_id::text IS DISTINCT FROM proof->>'membershipId' OR receipt.before_group_revision::text IS DISTINCT FROM proof->>'groupRevision'
   OR receipt.operation_id::text IS DISTINCT FROM proof->>'operationId' THEN RAISE EXCEPTION 'Exact retained original cleanup incarnation required' USING ERRCODE='23514';END IF;
  PERFORM identity_company_offboarding_group_validate(receipt.id);
 ELSE
  IF NOT EXISTS(SELECT 1 FROM groups collection JOIN group_members member ON member.group_id=collection.id
   WHERE collection.id=(proof->>'groupId')::uuid AND identity_tenant_id('group',collection.id)=(proof->'tenant'->>'id')::uuid
   AND collection.revision::text=proof->>'groupRevision' AND member.user_id=proof->>'userId' AND member.membership_id::text=proof->>'membershipId')
   THEN RAISE EXCEPTION 'Exact locked owned membership and group revision required' USING ERRCODE='23514';END IF;
 END IF;
 PERFORM set_config('opendirectory.company_offboarding_groups',proof::text,true);
 INSERT INTO identity_company_offboarding_group_checks(source) VALUES(proof);
 IF NOT EXISTS(SELECT 1 FROM identity_company_offboarding_group_checks WHERE transaction_id=txid_current() AND source=proof)
  THEN RAISE EXCEPTION 'Actual immutable deferred cleanup check required' USING ERRCODE='23514';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_groups_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;receipt identity_company_offboarding_group_receipts;
BEGIN
 IF TG_TABLE_NAME='identity_company_offboarding_group_checks' AND TG_OP<>'INSERT' THEN RETURN NULL;END IF;
 PERFORM identity_company_offboarding_groups_receiving();
 SELECT source INTO proof FROM identity_company_offboarding_group_checks WHERE transaction_id=txid_current();
 IF proof IS NULL THEN proof=NULLIF(current_setting('opendirectory.company_offboarding_groups',true),'')::jsonb;END IF;
 IF TG_TABLE_NAME='identity_company_offboarding_group_checks' THEN proof=NEW.source;END IF;
 IF proof IS DISTINCT FROM NULLIF(current_setting('opendirectory.company_offboarding_groups',true),'')::jsonb
  THEN RAISE EXCEPTION 'Immutable original cleanup source required at physical commit' USING ERRCODE='42501';END IF;
 PERFORM identity_company_offboarding_groups_actor(proof);
 SELECT * INTO receipt FROM identity_company_offboarding_group_receipts WHERE id=(proof->>'receiptId')::uuid;
 PERFORM identity_company_offboarding_group_validate((proof->>'receiptId')::uuid);
 IF receipt.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id' OR receipt.workflow_id::text IS DISTINCT FROM proof->>'workflowId'
  OR receipt.user_id::text IS DISTINCT FROM proof->>'userId' OR receipt.group_id::text IS DISTINCT FROM proof->>'groupId'
  OR receipt.membership_id::text IS DISTINCT FROM proof->>'membershipId' OR receipt.before_group_revision::text IS DISTINCT FROM proof->>'groupRevision'
  OR receipt.operation_id::text IS DISTINCT FROM proof->>'operationId'
  OR proof->'recovery'='false'::jsonb AND (receipt.transaction_id<>txid_current() OR receipt.source IS DISTINCT FROM proof)
  OR proof->'recovery'='true'::jsonb AND EXISTS(SELECT 1 FROM identity_directory_group_events WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'One exact original child or effect-free retained recovery required' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='identity_company_offboarding_group_checks' THEN DELETE FROM identity_company_offboarding_group_checks WHERE transaction_id=NEW.transaction_id;END IF;
 RETURN NULL;
END; $$;

DO $$ DECLARE relation TEXT;hook RECORD;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_offboarding_group_receipts','identity_company_offboarding_group_outbox','identity_company_offboarding_group_checks'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_offboarding_groups_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_company_offboarding_groups_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_groups_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_offboarding_groups_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_company_offboarding_groups_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_offboarding_groups_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_offboarding_groups_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_company_offboarding_groups_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_groups_commit()',relation);
  FOR hook IN SELECT * FROM identity_license_user_source_hooks() UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence' LOOP
   EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',hook.trigger_name,relation);
   EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,relation,hook.routine);
   EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation);
   EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation,hook.routine);
  END LOOP;
  EXECUTE format('REVOKE ALL ON TABLE %I FROM PUBLIC',relation);
 END LOOP;
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_company_offboarding_groups_fence ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_company_offboarding_groups_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_groups_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_company_offboarding_groups_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_company_offboarding_groups_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_offboarding_groups_fence()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_company_offboarding_groups_actor(jsonb)','identity_company_offboarding_groups_receiving()',
  'identity_company_offboarding_group_validate(uuid)','identity_company_offboarding_groups_guard()','identity_company_offboarding_groups_fence()',
  'identity_company_offboarding_groups_begin(jsonb)','identity_company_offboarding_groups_commit()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('ALTER FUNCTION %s RESET timezone',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
