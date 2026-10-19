ALTER TABLE identity_directory_ou_events DROP CONSTRAINT IF EXISTS identity_directory_ou_events_action_check;
ALTER TABLE identity_directory_ou_events ADD CONSTRAINT identity_directory_ou_events_action_check CHECK(action IN('update','delete','member-add','member-remove'));
ALTER TABLE identity_directory_ou_events DROP CONSTRAINT IF EXISTS identity_directory_ou_events_type_check;
ALTER TABLE identity_directory_ou_events ADD CONSTRAINT identity_directory_ou_events_type_check CHECK(type IN('organization-unit.updated','organization-unit.deleted','organization-unit.member.added','organization-unit.member.removed'));
CREATE INDEX IF NOT EXISTS identity_directory_ou_events_member ON identity_directory_ou_events((proof#>>'{target,member,id}')) WHERE action IN('member-add','member-remove');
CREATE TABLE IF NOT EXISTS identity_directory_ou_members (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),ou_id UUID NOT NULL REFERENCES ous(id) ON DELETE RESTRICT,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at TIMESTAMPTZ NOT NULL,UNIQUE(ou_id,user_id)
);
CREATE INDEX IF NOT EXISTS identity_directory_ou_members_page ON identity_directory_ou_members(tenant_id,ou_id,created_at,id);
CREATE INDEX IF NOT EXISTS identity_directory_ou_members_user ON identity_directory_ou_members(user_id,ou_id);
CREATE OR REPLACE FUNCTION identity_directory_ou_member_state(data identity_directory_ou_members) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN (data).id IS NULL THEN NULL ELSE to_jsonb(data) END;
$$;
CREATE OR REPLACE FUNCTION identity_directory_ou_member_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;member JSONB;expected JSONB;
BEGIN
 scope=identity_directory_ou_scope();member=scope->'proof'->'target'->'member';
 IF TG_OP='UPDATE' OR scope->>'action' NOT IN('member-add','member-remove') OR (TG_OP='INSERT') IS DISTINCT FROM (scope->>'action'='member-add')
  THEN RAISE EXCEPTION 'Only an exact membership admission or removal is allowed' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN data=to_jsonb(NEW);expected=jsonb_build_object('id',member->'id','tenant_id',scope->'tenant_id','ou_id',scope->'ou_id','user_id',member->'userId','created_at',scope->'created_at');
 ELSE data=to_jsonb(OLD);expected=member->'before';END IF;
 IF data IS DISTINCT FROM expected OR data->>'id' IS DISTINCT FROM member->>'id' OR data->>'ou_id' IS DISTINCT FROM scope->>'ou_id' OR data->>'tenant_id' IS DISTINCT FROM scope->>'tenant_id'
  OR data->>'user_id' IS DISTINCT FROM member->>'userId' OR identity_tenant_id('user',(data->>'user_id')::uuid)::text IS DISTINCT FROM scope->>'tenant_id'
  OR identity_tenant_id('ou',(data->>'ou_id')::uuid)::text IS DISTINCT FROM scope->>'tenant_id'
  OR NOT EXISTS(SELECT 1 FROM identity_directory_ou_events WHERE id=(scope->>'id')::uuid AND transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Exact owned membership incarnation and command required' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_membership_change(proof JSONB) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event identity_directory_ou_events;before_row ous;after_row ous;member JSONB;actual identity_directory_ou_members;users_locked INTEGER;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_directory_ou_receiving();PERFORM identity_directory_creation_actor(proof);PERFORM identity_directory_ou_lock((proof->'tenant'->>'id')::uuid);
 member=proof->'target'->'member';
 IF jsonb_typeof(member) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(member))<>3 OR NOT member ? 'before' OR member->>'id' IS NULL OR member->>'userId' IS NULL
  THEN RAISE EXCEPTION 'Exact server-bound membership target required' USING ERRCODE='23514';END IF;
 PERFORM id FROM users WHERE id IN((proof->'context'->>'userId')::uuid,(member->>'userId')::uuid) AND identity_tenant_id('user',id)=(proof->'tenant'->>'id')::uuid ORDER BY id FOR UPDATE;
 GET DIAGNOSTICS users_locked=ROW_COUNT;
 IF users_locked<>(CASE WHEN proof->'context'->>'userId'=member->>'userId' THEN 1 ELSE 2 END) THEN RAISE EXCEPTION 'Actual own operator and member required' USING ERRCODE='23514';END IF;
 SELECT * INTO before_row FROM ous WHERE id=(proof->'target'->>'id')::uuid AND identity_tenant_id('ou',id)=(proof->'tenant'->>'id')::uuid FOR UPDATE;
 IF before_row.id IS NULL OR identity_directory_ou_state(before_row) IS DISTINCT FROM proof->'target'->'before' OR proof->'target'->>'action' IS NULL OR proof->'target'->>'action' NOT IN('member-add','member-remove')
  OR identity_directory_creation_values('ou',to_jsonb(before_row)) IS DISTINCT FROM proof->'target'->'expectedValues'
  OR EXISTS(SELECT 1 FROM identity_directory_ou_events WHERE transaction_id=txid_current())
  OR EXISTS(SELECT 1 FROM identity_directory_ou_members WHERE ou_id=before_row.id AND (tenant_id<>(proof->'tenant'->>'id')::uuid OR identity_tenant_id('user',user_id) IS DISTINCT FROM tenant_id))
  THEN RAISE EXCEPTION 'Exact original owned OU membership command required' USING ERRCODE='23514';END IF;
 IF proof->'target'->>'action'='member-add' THEN
  IF member->'before' IS DISTINCT FROM 'null'::jsonb OR EXISTS(SELECT 1 FROM identity_directory_ou_members WHERE ou_id=before_row.id AND user_id=(member->>'userId')::uuid)
   OR EXISTS(SELECT 1 FROM identity_directory_ou_events history WHERE history.proof#>>'{target,member,id}'=member->>'id' AND history.action IN('member-add','member-remove'))
   OR (SELECT count(*) FROM identity_directory_ou_members WHERE ou_id=before_row.id)>=10000 THEN RAISE EXCEPTION 'New unique membership incarnation within capacity required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO actual FROM identity_directory_ou_members WHERE id=(member->>'id')::uuid AND ou_id=before_row.id AND tenant_id=(proof->'tenant'->>'id')::uuid FOR UPDATE;
  IF actual.id IS NULL OR actual.user_id::text IS DISTINCT FROM member->>'userId' OR identity_directory_ou_member_state(actual) IS DISTINCT FROM member->'before'
   THEN RAISE EXCEPTION 'Exact current membership removal required' USING ERRCODE='23514';END IF;
 END IF;
 event.id=(proof->>'operationId')::uuid;event.tenant_id=(proof->'tenant'->>'id')::uuid;event.ou_id=before_row.id;event.action=proof->'target'->>'action';
 event.type=CASE WHEN event.action='member-add' THEN 'organization-unit.member.added' ELSE 'organization-unit.member.removed' END;event.version=1;event.correlation_id=event.id;
 event.actor=jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId');event.proof=proof;
 event.before_state=identity_directory_ou_state(before_row);event.created_at=clock_timestamp();event.valid_until=to_timestamp((proof->>'validUntil')::double precision);event.transaction_id=txid_current();
 after_row=before_row;after_row.revision=before_row.revision+1;after_row.updated_at=event.created_at;event.after_state=identity_directory_ou_state(after_row);
 PERFORM set_config('opendirectory.ou_mutation',to_jsonb(event)::text,true);INSERT INTO identity_directory_ou_events SELECT event.*;
 UPDATE ous SET revision=after_row.revision,updated_at=after_row.updated_at WHERE id=event.ou_id;
 IF event.action='member-add' THEN INSERT INTO identity_directory_ou_members VALUES((member->>'id')::uuid,event.tenant_id,event.ou_id,(member->>'userId')::uuid,event.created_at);
 ELSE DELETE FROM identity_directory_ou_members WHERE id=(member->>'id')::uuid;END IF;
 INSERT INTO identity_directory_ou_outbox VALUES(event.id,event.tenant_id,'pending',event.created_at);RETURN event.id;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_ou_fence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;retirement identity_tenant_events;creation identity_directory_ou_creations;creation_proof JSONB;
BEGIN
 SELECT * INTO creation FROM identity_directory_ou_creations WHERE transaction_id=txid_current();creation_proof=NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb;
 IF creation.ou_id IS NOT NULL OR creation_proof->'resource'->>'kind'='ou' THEN
  PERFORM identity_authority_owner();
  IF NULLIF(current_setting('opendirectory.ou_mutation',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_directory_ou_events WHERE transaction_id=txid_current())
   THEN RAISE EXCEPTION 'OU creation cannot ride a different OU command' USING ERRCODE='42501';END IF;
  IF creation.ou_id IS NOT NULL AND creation_proof IS DISTINCT FROM creation.proof THEN RAISE EXCEPTION 'Original OU creation scope cannot disappear' USING ERRCODE='42501';END IF;
  PERFORM identity_directory_creation_actor(creation_proof);
  IF TG_OP<>'INSERT' THEN
   IF TG_TABLE_NAME='ous' THEN RAISE EXCEPTION 'Original new-OU content cannot be replaced' USING ERRCODE='23514';END IF;
   RAISE EXCEPTION 'Only original new-OU creation effects allowed' USING ERRCODE='42501';
  END IF;data=to_jsonb(NEW);
  IF TG_TABLE_NAME='ous' THEN
   IF NEW.id::text IS DISTINCT FROM creation_proof->'resource'->>'id' OR identity_directory_creation_values('ou',data) IS DISTINCT FROM creation_proof->'resource'->'values'
    THEN RAISE EXCEPTION 'Only the original new OU may be created' USING ERRCODE='23514';END IF;
  ELSIF TG_TABLE_NAME='identity_directory_ou_creations' THEN
   IF NEW.ou_id::text IS DISTINCT FROM creation_proof->'resource'->>'id' OR NEW.tenant_id::text IS DISTINCT FROM creation_proof->'tenant'->>'id' OR NEW.proof IS DISTINCT FROM creation_proof
    THEN RAISE EXCEPTION 'Original new-OU receipt required' USING ERRCODE='42501';END IF;
  ELSIF TG_TABLE_NAME='identity_tenant_ownership' THEN
   IF NEW.resource_kind<>'ou' OR NEW.resource_id::text IS DISTINCT FROM creation_proof->'resource'->>'id' OR NEW.tenant_id::text IS DISTINCT FROM creation_proof->'tenant'->>'id'
    OR NEW.reason<>'Original-token-bound new-resource creation' THEN RAISE EXCEPTION 'Only original new-OU ownership allowed' USING ERRCODE='42501';END IF;
  ELSIF TG_TABLE_NAME='identity_tenant_events' THEN
   IF pg_trigger_depth()<2 OR NEW.tenant_id::text IS DISTINCT FROM creation_proof->'tenant'->>'id' OR NEW.action<>'resource-created'
    OR NEW.details->>'kind'<>'ou' OR NEW.details->>'resourceId' IS DISTINCT FROM creation_proof->'resource'->>'id' THEN RAISE EXCEPTION 'Only actual new-OU event fanout allowed' USING ERRCODE='42501';END IF;
  ELSIF TG_TABLE_NAME='identity_tenant_outbox' THEN
   SELECT * INTO retirement FROM identity_tenant_events WHERE id=NEW.id;
   IF pg_trigger_depth()<2 OR NEW.tenant_id::text IS DISTINCT FROM creation_proof->'tenant'->>'id' OR NEW.action<>'resource-created' OR retirement.id IS NULL
    OR retirement.tenant_id<>NEW.tenant_id OR retirement.action<>NEW.action OR retirement.details->>'kind'<>'ou' OR retirement.details->>'resourceId' IS DISTINCT FROM creation_proof->'resource'->>'id'
    THEN RAISE EXCEPTION 'Only actual new-OU outbox fanout allowed' USING ERRCODE='42501';END IF;
  ELSE RAISE EXCEPTION 'Unrelated effects cannot ride OU creation' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF NULLIF(current_setting('opendirectory.ou_mutation',true),'') IS NULL AND NOT EXISTS(SELECT 1 FROM identity_directory_ou_events WHERE transaction_id=txid_current()) THEN
  IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 scope=identity_directory_ou_scope();IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'OU commands cannot truncate data' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='ous' THEN
  IF TG_OP NOT IN('UPDATE','DELETE') OR (TG_OP='DELETE') IS DISTINCT FROM (scope->>'action'='delete')
   OR OLD.id::text IS DISTINCT FROM scope->>'ou_id' OR identity_tenant_id('ou',OLD.id)::text IS DISTINCT FROM scope->>'tenant_id'
   OR identity_directory_ou_state(OLD) IS DISTINCT FROM scope->'before_state'
   OR TG_OP='UPDATE' AND identity_directory_ou_state(NEW) IS DISTINCT FROM scope->'after_state'
   OR NOT EXISTS(SELECT 1 FROM identity_directory_ou_events WHERE id=(scope->>'id')::uuid)
   OR TG_OP='DELETE' AND (EXISTS(SELECT 1 FROM ous WHERE parent_id=OLD.id) OR EXISTS(SELECT 1 FROM identity_directory_ou_members WHERE ou_id=OLD.id))
   THEN RAISE EXCEPTION 'Only the exact owned OU transition without dependants is allowed' USING ERRCODE='23514';END IF;
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 IF TG_TABLE_NAME='identity_directory_ou_members' THEN
  IF TG_OP='UPDATE' OR scope->>'action' NOT IN('member-add','member-remove') OR (TG_OP='INSERT') IS DISTINCT FROM (scope->>'action'='member-add')
   THEN RAISE EXCEPTION 'Only exact original membership effects allowed' USING ERRCODE='42501';END IF;
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Unrelated effects cannot ride an OU command' USING ERRCODE='42501';END IF;data=to_jsonb(NEW);
 IF TG_TABLE_NAME IN('identity_directory_ou_events','identity_directory_ou_outbox') THEN RETURN NEW;END IF;
 IF scope->>'action'<>'delete' OR pg_trigger_depth()<2 OR data->>'tenant_id' IS DISTINCT FROM scope->>'tenant_id'
  THEN RAISE EXCEPTION 'Only actual OU retirement fanout is allowed' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_tenant_retirements' THEN
  IF NEW.resource_kind<>'ou' OR NEW.resource_id::text IS DISTINCT FROM scope->>'ou_id' THEN RAISE EXCEPTION 'Exact OU retirement required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='identity_tenant_events' THEN
  IF NEW.action<>'resource-retired' OR NEW.details IS DISTINCT FROM jsonb_build_object('kind','ou','resourceId',scope->'ou_id')
   OR NEW.actor IS DISTINCT FROM jsonb_build_object('databaseRole',session_user) THEN RAISE EXCEPTION 'Exact OU retirement event required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='identity_tenant_outbox' THEN
  SELECT * INTO retirement FROM identity_tenant_events WHERE id=NEW.id;
  IF NEW.action<>'resource-retired' OR retirement.tenant_id<>NEW.tenant_id OR retirement.action<>NEW.action
   OR retirement.details IS DISTINCT FROM jsonb_build_object('kind','ou','resourceId',scope->'ou_id') THEN RAISE EXCEPTION 'Actual OU retirement outbox required' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'Unrelated effects cannot ride an OU command' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;
BEGIN
 PERFORM identity_authority_owner();
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_directory_ou_fence' AND tgtype=31 AND tgenabled='O' AND tgfoid='identity_directory_ou_fence()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_directory_ou_no_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='identity_directory_ou_fence()'::regprocedure)
   THEN RAISE EXCEPTION 'OU receiving fence unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['identity_directory_ou_events','identity_directory_ou_outbox'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_directory_ou_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='identity_directory_ou_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'OU evidence receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='ous'::regclass AND tgname='zzz_identity_directory_ou_revision' AND tgtype=23 AND tgenabled='O' AND tgfoid='identity_directory_ou_revision()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='ous'::regclass AND tgname='identity_directory_ou_creation_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_directory_ou_creation_commit()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_directory_ou_events'::regclass AND tgname='identity_directory_ou_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_directory_ou_commit()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_directory_ou_creations'::regclass AND tgname='identity_directory_ou_creation_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='identity_directory_ou_creation_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_directory_ou_creations'::regclass AND tgname='identity_directory_ou_creation_receipt_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_directory_ou_creation_commit()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='ous'::regclass AND tgname='aaa_identity_directory_creation' AND tgtype=7 AND tgenabled='O' AND tgfoid='identity_directory_creation_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='ous'::regclass AND tgname='identity_directory_creation_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_directory_creation_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_directory_ou_members'::regclass AND tgname='identity_directory_ou_member_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='identity_directory_ou_member_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_directory_ou_members'::regclass AND tgname='identity_directory_ou_member_commit' AND tgtype=29 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_directory_ou_member_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Deferred OU receiving and revision required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;event identity_directory_ou_events;actual JSONB;member JSONB;linked JSONB;
BEGIN
 PERFORM identity_directory_ou_receiving();scope=identity_directory_ou_scope();SELECT * INTO event FROM identity_directory_ou_events WHERE id=NEW.id;
 SELECT identity_directory_ou_state(unit) INTO actual FROM ous unit WHERE id=event.ou_id;
 IF event.id IS NULL OR scope IS DISTINCT FROM to_jsonb(event) OR event.transaction_id<>txid_current() OR event.proof->'target'->'before' IS DISTINCT FROM event.before_state
  OR event.id::text IS DISTINCT FROM event.proof->>'operationId' OR event.tenant_id::text IS DISTINCT FROM event.proof->'tenant'->>'id' OR event.ou_id::text IS DISTINCT FROM event.proof->'target'->>'id'
  OR event.action IS DISTINCT FROM event.proof->'target'->>'action' OR event.correlation_id<>event.id OR event.version<>1
  OR event.type IS DISTINCT FROM (CASE event.action WHEN 'update' THEN 'organization-unit.updated' WHEN 'delete' THEN 'organization-unit.deleted' WHEN 'member-add' THEN 'organization-unit.member.added' WHEN 'member-remove' THEN 'organization-unit.member.removed' END)
  OR event.actor IS DISTINCT FROM jsonb_build_object('issuer',event.proof->>'issuer','subject',event.proof->>'subject','userId',event.proof->'context'->>'userId')
  OR event.valid_until IS DISTINCT FROM to_timestamp((event.proof->>'validUntil')::double precision)
  OR event.action IN('update','member-add','member-remove') AND (event.after_state IS NULL OR event.after_state->>'revision' IS DISTINCT FROM ((event.before_state->>'revision')::bigint+1)::text
   OR event.after_state-ARRAY['name','description','parent_id','revision','updated_at'] IS DISTINCT FROM event.before_state-ARRAY['name','description','parent_id','revision','updated_at']
   OR identity_directory_creation_values('ou',event.after_state) IS DISTINCT FROM event.proof->'target'->'expectedValues'
   OR (event.after_state->>'updated_at')::timestamptz IS DISTINCT FROM event.created_at)
  OR event.action='delete' AND event.proof->'target'->'expectedValues' IS DISTINCT FROM 'null'::jsonb
  OR actual IS DISTINCT FROM event.after_state OR event.tenant_id<>identity_tenant_id('ou',event.ou_id)
  OR NOT EXISTS(SELECT 1 FROM identity_directory_ou_outbox WHERE id=event.id AND tenant_id=event.tenant_id AND status='pending' AND created_at=event.created_at)
  OR event.action='delete' AND (actual IS NOT NULL OR NOT EXISTS(SELECT 1 FROM identity_tenant_retirements WHERE resource_kind='ou' AND resource_id=event.ou_id AND tenant_id=event.tenant_id)
   OR NOT EXISTS(SELECT 1 FROM identity_tenant_events retired JOIN identity_tenant_outbox outbox USING(id) WHERE retired.tenant_id=event.tenant_id AND retired.action='resource-retired' AND retired.details=jsonb_build_object('kind','ou','resourceId',event.ou_id)
    AND outbox.tenant_id=event.tenant_id AND outbox.action=retired.action))
  OR NOT identity_directory_ou_tree_valid(event.tenant_id) THEN RAISE EXCEPTION 'Exact OU effect, coherent tree and retained receipts required' USING ERRCODE='23514';END IF;
 IF event.action IN('member-add','member-remove') THEN
  member=event.proof->'target'->'member';SELECT identity_directory_ou_member_state(link) INTO linked FROM identity_directory_ou_members link WHERE id=(member->>'id')::uuid;
  IF identity_directory_creation_values('ou',event.before_state) IS DISTINCT FROM event.proof->'target'->'expectedValues'
   OR identity_tenant_id('user',(member->>'userId')::uuid) IS DISTINCT FROM event.tenant_id
   OR event.action='member-add' AND (member->'before' IS DISTINCT FROM 'null'::jsonb OR linked IS DISTINCT FROM jsonb_build_object('id',member->'id','tenant_id',event.tenant_id,'ou_id',event.ou_id,'user_id',member->'userId','created_at',event.created_at))
   OR event.action='member-remove' AND (linked IS NOT NULL OR member->'before'->>'id' IS DISTINCT FROM member->>'id' OR member->'before'->>'ou_id' IS DISTINCT FROM event.ou_id::text OR member->'before'->>'tenant_id' IS DISTINCT FROM event.tenant_id::text OR member->'before'->>'user_id' IS DISTINCT FROM member->>'userId')
   THEN RAISE EXCEPTION 'Exact membership incarnation and final effect required' USING ERRCODE='23514';END IF;
 END IF;
 PERFORM identity_directory_creation_actor(event.proof);IF event.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original OU assurance expired' USING ERRCODE='28000';END IF;RETURN NULL;
END; $$;


CREATE OR REPLACE FUNCTION identity_directory_ou_member_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;member JSONB;
BEGIN
 PERFORM identity_directory_ou_receiving();scope=identity_directory_ou_scope();member=scope->'proof'->'target'->'member';
 IF TG_OP='DELETE' THEN data=identity_directory_ou_member_state(OLD);ELSE data=identity_directory_ou_member_state(NEW);END IF;
 IF TG_OP='UPDATE' OR scope->>'action' NOT IN('member-add','member-remove') OR data->>'id' IS DISTINCT FROM member->>'id'
  OR data->>'user_id' IS DISTINCT FROM member->>'userId' OR data->>'ou_id' IS DISTINCT FROM scope->>'ou_id' OR data->>'tenant_id' IS DISTINCT FROM scope->>'tenant_id'
  OR (TG_OP='INSERT') IS DISTINCT FROM (scope->>'action'='member-add')
  THEN RAISE EXCEPTION 'Original exact membership command required through commit' USING ERRCODE='42501';END IF;
 PERFORM identity_directory_creation_actor(scope->'proof');RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS identity_directory_ou_member_guard ON identity_directory_ou_members;
CREATE TRIGGER identity_directory_ou_member_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_directory_ou_members FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_member_guard();
DROP TRIGGER IF EXISTS identity_directory_ou_member_commit ON identity_directory_ou_members;
CREATE CONSTRAINT TRIGGER identity_directory_ou_member_commit AFTER INSERT OR UPDATE OR DELETE ON identity_directory_ou_members DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_member_commit();
DO $$ DECLARE guard TEXT;routine TEXT;BEGIN
 FOR guard,routine IN SELECT * FROM (VALUES ('identity_authority_stage','identity_authority_stage_no_effects'),('identity_authority_seal','identity_authority_namespace_no_effects'),('identity_authority_checkpoint','identity_authority_checkpoint_no_effects'),('identity_authority_source_set','identity_authority_source_set_no_effects'),('identity_organization','identity_organization_no_effects'),('identity_company_registration','identity_company_registration_fence'),('identity_company_review','identity_company_review_no_effects'),('identity_company_activation','identity_company_activation_fence')) guards(name,routine) LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS %I ON identity_directory_ou_members','aaa_'||guard||CASE WHEN guard IN('identity_company_registration','identity_company_activation') THEN '_fence' ELSE '_no_effects' END);
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON identity_directory_ou_members FOR EACH ROW EXECUTE FUNCTION %s()','aaa_'||guard||CASE WHEN guard IN('identity_company_registration','identity_company_activation') THEN '_fence' ELSE '_no_effects' END,routine);
  EXECUTE format('DROP TRIGGER IF EXISTS %I ON identity_directory_ou_members','aaa_'||guard||'_no_truncate');EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON identity_directory_ou_members FOR EACH STATEMENT EXECUTE FUNCTION %s()','aaa_'||guard||'_no_truncate',routine);
 END LOOP;
 DROP TRIGGER IF EXISTS aaa_identity_directory_ou_fence ON identity_directory_ou_members;
 CREATE TRIGGER aaa_identity_directory_ou_fence BEFORE INSERT OR UPDATE OR DELETE ON identity_directory_ou_members FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_fence();
 DROP TRIGGER IF EXISTS aaa_identity_directory_ou_no_truncate ON identity_directory_ou_members;
 CREATE TRIGGER aaa_identity_directory_ou_no_truncate BEFORE TRUNCATE ON identity_directory_ou_members FOR EACH STATEMENT EXECUTE FUNCTION identity_directory_ou_fence();
 FOREACH routine IN ARRAY ARRAY['identity_directory_ou_member_state(identity_directory_ou_members)','identity_directory_ou_member_guard()','identity_directory_ou_membership_change(jsonb)','identity_directory_ou_fence()','identity_directory_ou_receiving()','identity_directory_ou_commit()','identity_directory_ou_member_commit()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
