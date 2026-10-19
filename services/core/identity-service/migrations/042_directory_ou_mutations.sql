ALTER TABLE ous ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0);
ALTER FUNCTION identity_subject_link_role_state(uuid) SET timezone TO 'UTC';
CREATE TABLE IF NOT EXISTS identity_directory_ou_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),ou_id UUID NOT NULL,
 action TEXT NOT NULL CHECK(action IN('update','delete')),type TEXT NOT NULL CHECK(type IN('organization-unit.updated','organization-unit.deleted')),
 version INTEGER NOT NULL CHECK(version=1),correlation_id UUID NOT NULL,actor JSONB NOT NULL,proof JSONB NOT NULL,
 before_state JSONB NOT NULL,after_state JSONB,created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,
 transaction_id BIGINT NOT NULL UNIQUE,CHECK(valid_until>created_at)
);
CREATE INDEX IF NOT EXISTS identity_directory_ou_events_target ON identity_directory_ou_events(tenant_id,ou_id,created_at);
CREATE TABLE IF NOT EXISTS identity_directory_ou_outbox (
 id UUID PRIMARY KEY REFERENCES identity_directory_ou_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_directory_ou_creations (
 ou_id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),proof JSONB NOT NULL,
 valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL UNIQUE
);
CREATE OR REPLACE FUNCTION identity_directory_ou_state(data ous) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN (data).id IS NULL THEN NULL ELSE to_jsonb(data)||jsonb_build_object('revision',(data).revision::text) END;
$$;
CREATE OR REPLACE FUNCTION identity_directory_ou_lock(tenant UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_authority_owner();PERFORM pg_advisory_xact_lock(hashtextextended('opendirectory.ou-tree:'||tenant::text,0));
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_tree_valid(tenant UUID) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
 WITH RECURSIVE units AS (SELECT id,parent_id FROM ous WHERE identity_tenant_id('ou',id)=tenant),
 branches AS (
  SELECT id,ARRAY[id] AS path FROM units WHERE parent_id IS NULL
  UNION ALL SELECT child.id,branches.path||child.id FROM units child JOIN branches ON child.parent_id=branches.id
   WHERE cardinality(branches.path)<256 AND NOT child.id=ANY(branches.path)
 ) SELECT (SELECT count(*) FROM units)<=10000 AND NOT EXISTS(SELECT 1 FROM units WHERE id NOT IN(SELECT id FROM branches))
  AND NOT EXISTS(SELECT 1 FROM ous child JOIN units parent ON child.parent_id=parent.id WHERE identity_tenant_id('ou',child.id) IS DISTINCT FROM tenant);
$$;
CREATE OR REPLACE FUNCTION identity_directory_ou_scope() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;retained identity_directory_ou_events;
BEGIN
 PERFORM identity_authority_owner();scope=NULLIF(current_setting('opendirectory.ou_mutation',true),'')::jsonb;
 SELECT * INTO retained FROM identity_directory_ou_events WHERE transaction_id=txid_current();
 IF scope IS NULL OR scope->>'valid_until' IS NULL OR (scope->>'transaction_id')::bigint IS DISTINCT FROM txid_current() OR (scope->>'valid_until')::timestamptz<=clock_timestamp()
  OR retained.id IS NOT NULL AND to_jsonb(retained) IS DISTINCT FROM scope THEN RAISE EXCEPTION 'Exact current OU command required' USING ERRCODE='42501';END IF;
 PERFORM identity_directory_creation_actor(scope->'proof');RETURN scope;
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
   OR TG_OP='DELETE' AND EXISTS(SELECT 1 FROM ous WHERE parent_id=OLD.id)
   THEN RAISE EXCEPTION 'Only the exact owned OU transition without dependants is allowed' USING ERRCODE='23514';END IF;
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
CREATE OR REPLACE FUNCTION identity_directory_ou_creation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;
BEGIN
 PERFORM identity_authority_owner();proof=NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb;
 IF TG_OP<>'INSERT' OR proof IS NULL OR proof->'resource'->>'kind' IS DISTINCT FROM 'ou' OR NEW.ou_id::text IS DISTINCT FROM proof->'resource'->>'id'
  OR NEW.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id' OR NEW.proof IS DISTINCT FROM proof OR NEW.transaction_id<>txid_current()
  OR NEW.valid_until IS DISTINCT FROM to_timestamp((proof->>'validUntil')::double precision) THEN RAISE EXCEPTION 'Exact immutable original OU creation receipt required' USING ERRCODE='42501';END IF;
 PERFORM identity_directory_creation_actor(proof);RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;expected JSONB;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'OU command evidence is immutable' USING ERRCODE='42501';END IF;scope=identity_directory_ou_scope();
 expected=CASE WHEN TG_TABLE_NAME='identity_directory_ou_events' THEN scope ELSE jsonb_build_object('id',scope->'id','tenant_id',scope->'tenant_id','status','pending','created_at',scope->'created_at') END;
 IF to_jsonb(NEW) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact OU command evidence required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;creation JSONB;
BEGIN
 scope=NULLIF(current_setting('opendirectory.ou_mutation',true),'')::jsonb;
 IF scope IS NOT NULL THEN
  scope=identity_directory_ou_scope();
  IF TG_OP<>'UPDATE' OR identity_directory_ou_state(NEW) IS DISTINCT FROM scope->'after_state' OR NEW.revision<>OLD.revision+1
   THEN RAISE EXCEPTION 'Exact OU revision required' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 THEN RAISE EXCEPTION 'Initial OU revision must be one' USING ERRCODE='23514';END IF;
  creation=NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb;
  IF creation IS NOT NULL THEN PERFORM identity_directory_ou_lock((creation->'tenant'->>'id')::uuid);END IF;
 ELSE
  IF NEW.revision<>OLD.revision THEN RAISE EXCEPTION 'OU revisions are server-owned' USING ERRCODE='42501';END IF;
  NEW.revision=OLD.revision+1;NEW.updated_at=clock_timestamp();
 END IF;RETURN NEW;
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
  THEN RAISE EXCEPTION 'Deferred OU receiving and revision required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_creation_admit(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_directory_ou_receiving();PERFORM identity_directory_creation_actor(proof);
 IF proof->'resource'->>'kind' IS DISTINCT FROM 'ou' THEN RAISE EXCEPTION 'Only original OU creation can be admitted' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM ous WHERE id=(proof->'resource'->>'id')::uuid)
  OR EXISTS(SELECT 1 FROM identity_tenant_ownership WHERE resource_kind='ou' AND resource_id=(proof->'resource'->>'id')::uuid)
  THEN RAISE EXCEPTION 'Only an original new OU namespace can be admitted' USING ERRCODE='23514';END IF;
 INSERT INTO identity_directory_ou_creations VALUES((proof->'resource'->>'id')::uuid,(proof->'tenant'->>'id')::uuid,proof,to_timestamp((proof->>'validUntil')::double precision),txid_current());
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_change(proof JSONB) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event identity_directory_ou_events;before_row ous;after_row ous;values JSONB;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_directory_ou_receiving();PERFORM identity_directory_creation_actor(proof);
 PERFORM identity_directory_ou_lock((proof->'tenant'->>'id')::uuid);
 SELECT * INTO before_row FROM ous WHERE id=(proof->'target'->>'id')::uuid FOR UPDATE;
 IF before_row.id IS NULL OR identity_tenant_id('ou',before_row.id)::text IS DISTINCT FROM proof->'tenant'->>'id'
  OR identity_directory_ou_state(before_row) IS DISTINCT FROM proof->'target'->'before'
  OR proof->'target'->>'action' IS NULL OR proof->'target'->>'action' NOT IN('update','delete')
  OR EXISTS(SELECT 1 FROM identity_directory_ou_events WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Exact original owned OU mutation required' USING ERRCODE='23514';END IF;
 event.id=(proof->>'operationId')::uuid;event.tenant_id=(proof->'tenant'->>'id')::uuid;event.ou_id=before_row.id;event.action=proof->'target'->>'action';
 event.type=CASE WHEN event.action='update' THEN 'organization-unit.updated' ELSE 'organization-unit.deleted' END;event.version=1;event.correlation_id=event.id;
 event.actor=jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId');event.proof=proof;
 event.before_state=identity_directory_ou_state(before_row);event.created_at=clock_timestamp();event.valid_until=to_timestamp((proof->>'validUntil')::double precision);event.transaction_id=txid_current();
 IF event.action='update' THEN
  values=proof->'target'->'expectedValues';
  IF jsonb_typeof(values) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(values))<>3
   OR jsonb_typeof(values->'name') IS DISTINCT FROM 'string' OR length(btrim(values->>'name')) NOT BETWEEN 1 AND 255 OR values->>'name'<>btrim(values->>'name') OR values->>'name' ~ '[[:cntrl:]]'
   OR values->'description'<>'null'::jsonb AND (jsonb_typeof(values->'description') IS DISTINCT FROM 'string' OR length(values->>'description')>2000 OR regexp_replace(values->>'description',E'[\n\r\t]','','g') ~ '[[:cntrl:]]')
   OR NOT values ? 'description' OR NOT values ? 'parentId' THEN RAISE EXCEPTION 'Exact bounded OU values required' USING ERRCODE='23514';END IF;
  after_row=before_row;after_row.name=values->>'name';after_row.description=values->>'description';after_row.parent_id=(values->>'parentId')::uuid;after_row.revision=before_row.revision+1;after_row.updated_at=event.created_at;
  IF after_row.parent_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM ous WHERE id=after_row.parent_id AND identity_tenant_id('ou',id)=event.tenant_id)
   THEN RAISE EXCEPTION 'Actual own OU parent required' USING ERRCODE='23514';END IF;event.after_state=identity_directory_ou_state(after_row);
 ELSE
  IF proof->'target'->'expectedValues' IS DISTINCT FROM 'null'::jsonb OR EXISTS(SELECT 1 FROM ous WHERE parent_id=before_row.id)
   THEN RAISE EXCEPTION 'OU with active dependants cannot be deleted' USING ERRCODE='23514';END IF;
 END IF;
 PERFORM set_config('opendirectory.ou_mutation',to_jsonb(event)::text,true);
 INSERT INTO identity_directory_ou_events SELECT event.*;
 IF event.action='update' THEN UPDATE ous SET name=after_row.name,description=after_row.description,parent_id=after_row.parent_id,revision=after_row.revision,updated_at=after_row.updated_at WHERE id=event.ou_id;
 ELSE DELETE FROM ous WHERE id=event.ou_id;END IF;
 INSERT INTO identity_directory_ou_outbox VALUES(event.id,event.tenant_id,'pending',event.created_at);RETURN event.id;
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;event identity_directory_ou_events;actual JSONB;
BEGIN
 PERFORM identity_directory_ou_receiving();scope=identity_directory_ou_scope();SELECT * INTO event FROM identity_directory_ou_events WHERE id=NEW.id;
 SELECT identity_directory_ou_state(unit) INTO actual FROM ous unit WHERE id=event.ou_id;
 IF event.id IS NULL OR scope IS DISTINCT FROM to_jsonb(event) OR event.transaction_id<>txid_current() OR event.proof->'target'->'before' IS DISTINCT FROM event.before_state
  OR event.id::text IS DISTINCT FROM event.proof->>'operationId' OR event.tenant_id::text IS DISTINCT FROM event.proof->'tenant'->>'id' OR event.ou_id::text IS DISTINCT FROM event.proof->'target'->>'id'
  OR event.action IS DISTINCT FROM event.proof->'target'->>'action' OR event.correlation_id<>event.id OR event.version<>1
  OR event.type IS DISTINCT FROM (CASE WHEN event.action='update' THEN 'organization-unit.updated' ELSE 'organization-unit.deleted' END)
  OR event.actor IS DISTINCT FROM jsonb_build_object('issuer',event.proof->>'issuer','subject',event.proof->>'subject','userId',event.proof->'context'->>'userId')
  OR event.valid_until IS DISTINCT FROM to_timestamp((event.proof->>'validUntil')::double precision)
  OR event.action='update' AND (event.after_state IS NULL OR event.after_state->>'revision' IS DISTINCT FROM ((event.before_state->>'revision')::bigint+1)::text
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
 PERFORM identity_directory_creation_actor(event.proof);IF event.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original OU assurance expired' USING ERRCODE='28000';END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_directory_ou_creation_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;creation identity_directory_ou_creations;identifier UUID;actual ous;
BEGIN
 IF TG_TABLE_NAME='ous' THEN identifier=NEW.id;ELSE identifier=NEW.ou_id;END IF;SELECT * INTO creation FROM identity_directory_ou_creations WHERE ou_id=identifier;
 proof=NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb;
 IF proof IS NULL AND creation.ou_id IS NULL THEN RETURN NULL;END IF;
 PERFORM identity_directory_ou_receiving();PERFORM identity_directory_creation_actor(proof);
 SELECT * INTO actual FROM ous WHERE id=identifier;
 IF creation.ou_id IS NULL OR proof IS DISTINCT FROM creation.proof OR creation.transaction_id<>txid_current() OR creation.valid_until<=clock_timestamp()
  OR proof->'resource'->>'kind' IS DISTINCT FROM 'ou' OR proof->'resource'->>'id' IS DISTINCT FROM identifier::text OR actual.id IS NULL OR actual.revision<>1 OR actual.updated_at IS NOT NULL OR actual.created_at<>transaction_timestamp()
  OR identity_directory_creation_values('ou',to_jsonb(actual)) IS DISTINCT FROM proof->'resource'->'values' OR identity_tenant_id('ou',identifier)<>creation.tenant_id
  OR NOT EXISTS(SELECT 1 FROM identity_tenant_ownership ownership JOIN identity_tenant_events event ON event.tenant_id=ownership.tenant_id AND event.action='resource-created'
   JOIN identity_tenant_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=event.tenant_id AND outbox.action=event.action
   WHERE ownership.resource_kind='ou' AND ownership.resource_id=identifier AND ownership.tenant_id=creation.tenant_id AND ownership.reason='Original-token-bound new-resource creation'
   AND event.details->>'kind'='ou' AND event.details->>'resourceId'=identifier::text AND event.details->>'generation'=ownership.generation::text
   AND event.details->>'contentSha256'=encode(sha256(convert_to((proof->'resource'->'values')::text,'UTF8')),'hex')
   AND event.actor=jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId'))
  OR NOT identity_directory_ou_tree_valid((proof->'tenant'->>'id')::uuid)
  THEN RAISE EXCEPTION 'Actual coherent owned OU creation required' USING ERRCODE='23514';END IF;
 PERFORM identity_directory_creation_actor(proof);IF creation.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original OU creation assurance expired' USING ERRCODE='28000';END IF;RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS zzz_identity_directory_ou_revision ON ous;
CREATE TRIGGER zzz_identity_directory_ou_revision BEFORE INSERT OR UPDATE ON ous FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_revision();
DROP TRIGGER IF EXISTS identity_directory_ou_creation_commit ON ous;
CREATE CONSTRAINT TRIGGER identity_directory_ou_creation_commit AFTER INSERT ON ous DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_creation_commit();
DROP TRIGGER IF EXISTS identity_directory_ou_commit ON identity_directory_ou_events;
CREATE CONSTRAINT TRIGGER identity_directory_ou_commit AFTER INSERT ON identity_directory_ou_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_commit();
DROP TRIGGER IF EXISTS identity_directory_ou_creation_receipt_commit ON identity_directory_ou_creations;
CREATE CONSTRAINT TRIGGER identity_directory_ou_creation_receipt_commit AFTER INSERT ON identity_directory_ou_creations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_creation_commit();
DROP TRIGGER IF EXISTS identity_directory_ou_creation_guard ON identity_directory_ou_creations;
CREATE TRIGGER identity_directory_ou_creation_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_directory_ou_creations FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_creation_guard();
DO $$ DECLARE relation TEXT;routine TEXT;guard TEXT;BEGIN
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_directory_ou_fence ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_directory_ou_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_directory_ou_no_truncate ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_directory_ou_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_directory_ou_fence()',relation);
  IF relation IN('identity_directory_ou_events','identity_directory_ou_outbox','identity_directory_ou_creations') THEN
   IF relation<>'identity_directory_ou_creations' THEN EXECUTE format('DROP TRIGGER IF EXISTS identity_directory_ou_guard ON %I',relation);EXECUTE format('CREATE TRIGGER identity_directory_ou_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_directory_ou_guard()',relation);END IF;
   FOR guard,routine IN SELECT * FROM (VALUES ('identity_authority_stage','identity_authority_stage_no_effects'),('identity_authority_seal','identity_authority_namespace_no_effects'),('identity_authority_checkpoint','identity_authority_checkpoint_no_effects'),('identity_authority_source_set','identity_authority_source_set_no_effects'),('identity_organization','identity_organization_no_effects'),('identity_company_registration','identity_company_registration_fence'),('identity_company_review','identity_company_review_no_effects'),('identity_company_activation','identity_company_activation_fence')) guards(name,routine) LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||CASE WHEN guard IN('identity_company_registration','identity_company_activation') THEN '_fence' ELSE '_no_effects' END,relation);
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()','aaa_'||guard||CASE WHEN guard IN('identity_company_registration','identity_company_activation') THEN '_fence' ELSE '_no_effects' END,relation,routine);
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||'_no_truncate',relation);EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()','aaa_'||guard||'_no_truncate',relation,routine);
   END LOOP;
  END IF;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_directory_ou_state(ous)','identity_directory_ou_lock(uuid)','identity_directory_ou_tree_valid(uuid)','identity_directory_ou_scope()','identity_directory_ou_fence()','identity_directory_ou_guard()','identity_directory_ou_revision()','identity_directory_ou_receiving()','identity_directory_ou_change(jsonb)','identity_directory_ou_commit()','identity_directory_ou_creation_commit()','identity_directory_ou_creation_guard()','identity_directory_ou_creation_admit(jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
