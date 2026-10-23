CREATE TABLE IF NOT EXISTS identity_employee_enrollments(
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),issuer TEXT NOT NULL,subject TEXT NOT NULL,user_id UUID NOT NULL,
 tenant JSONB NOT NULL,witness JSONB NOT NULL,console_client_id TEXT NOT NULL,link_revision BIGINT NOT NULL CHECK(link_revision>0),
 state TEXT NOT NULL CHECK(state IN('active','withdrawn')),revision BIGINT NOT NULL CHECK(revision>0),
 acceptance_mutation JSONB NOT NULL,user_after JSONB NOT NULL,creation_event_id UUID NOT NULL,event_id UUID NOT NULL,
 withdrawal_mutation JSONB,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),UNIQUE(issuer,subject)
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_employee_active_user ON identity_employee_enrollments(user_id) WHERE state='active';
CREATE TABLE IF NOT EXISTS identity_employee_enrollment_events(
 id UUID PRIMARY KEY REFERENCES identity_directory_user_events(id),enrollment_id UUID NOT NULL REFERENCES identity_employee_enrollments(id) DEFERRABLE INITIALLY DEFERRED,
 tenant_id UUID NOT NULL REFERENCES identity_tenants(id),action TEXT NOT NULL CHECK(action IN('complete','withdraw')),actor JSONB NOT NULL,
 before_state JSONB,after_state JSONB NOT NULL,admission_sha256 TEXT NOT NULL CHECK(admission_sha256~'^[a-f0-9]{64}$'),valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL DEFAULT txid_current(),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS identity_employee_enrollment_transaction ON identity_employee_enrollment_events(transaction_id);
CREATE TABLE IF NOT EXISTS identity_employee_enrollment_outbox(id UUID PRIMARY KEY REFERENCES identity_employee_enrollment_events(id),status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),fingerprint TEXT NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$'));
CREATE TABLE IF NOT EXISTS identity_employee_enrollment_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='identity_employee_enrollments'::regclass AND conname='identity_employee_original_event_fk') THEN
  ALTER TABLE identity_employee_enrollments ADD CONSTRAINT identity_employee_original_event_fk FOREIGN KEY(creation_event_id) REFERENCES identity_employee_enrollment_events(id) DEFERRABLE INITIALLY DEFERRED;
  ALTER TABLE identity_employee_enrollments ADD CONSTRAINT identity_employee_current_event_fk FOREIGN KEY(event_id) REFERENCES identity_employee_enrollment_events(id) DEFERRABLE INITIALLY DEFERRED;
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 PERFORM identity_company_group_rule_app_receiving();
 IF current_setting('session_replication_role')<>'origin' OR (SELECT count(*) FROM identity_employee_enrollment_manifest)<>23
  OR EXISTS(SELECT 1 FROM identity_employee_enrollment_manifest WHERE to_regprocedure(signature) IS NULL OR digest<>md5(pg_get_functiondef(to_regprocedure(signature))))
  OR EXISTS(SELECT 1 FROM pg_class relation WHERE relnamespace=current_schema()::regnamespace AND relkind='r'
   AND(SELECT count(*) FROM pg_trigger WHERE tgrelid=relation.oid AND NOT tgisinternal AND tgenabled='O' AND tgfoid='identity_employee_fence()'::regprocedure
    AND(tgname='aaa_identity_employee_fence' AND tgtype=31 AND NOT tgdeferrable OR tgname='identity_employee_effect_commit' AND tgtype=29 AND tgdeferrable AND tginitdeferred OR tgname='identity_employee_effect_truncate' AND tgtype=34 AND NOT tgdeferrable))<>3)
  OR EXISTS(SELECT 1 FROM(VALUES
   ('identity_employee_enrollments','employee_enrollment_before','identity_employee_guard()',31,false),
   ('identity_employee_enrollments','employee_enrollment_record','identity_employee_event()',21,false),
   ('identity_employee_enrollments','employee_enrollment_commit','identity_employee_guard()',21,true),
   ('users','aaa_identity_directory_user_mutation','identity_directory_user_mutation_guard()',27,false),
   ('users','identity_directory_user_mutation_record','identity_directory_user_mutation_guard()',25,false),
   ('users','identity_directory_user_mutation_commit','identity_directory_user_mutation_guard()',25,true),
   ('identity_subject_links','identity_authorization_link_guard','identity_authorization_link_guard()',7,false),
   ('identity_subject_links','identity_subject_tenant_changed','identity_subject_tenant_transition()',13,false),
   ('identity_subject_links','identity_subject_link_record','identity_link_changed()',13,false),
   ('identity_subject_tenant_bindings','identity_subject_tenant_binding_guard','identity_subject_tenant_binding_guard()',31,false),
   ('identity_employee_enrollment_events','employee_enrollment_evidence','identity_employee_evidence()',31,false),
   ('identity_employee_enrollment_outbox','employee_enrollment_evidence','identity_employee_evidence()',31,false),
   ('identity_employee_enrollment_manifest','employee_enrollment_evidence','identity_employee_evidence()',31,false)
  ) expected(relation,name,routine,kind,deferred) WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=expected.relation::regclass AND tgname=expected.name
   AND tgfoid=expected.routine::regprocedure AND tgtype=expected.kind AND tgenabled='O' AND NOT tgisinternal AND tgdeferrable=expected.deferred AND(NOT expected.deferred OR tginitdeferred)))
  THEN RAISE EXCEPTION 'Original employee enrollment receiving unavailable' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_scope() RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE scope JSONB;witness JSONB;source JSONB;
BEGIN
 PERFORM identity_employee_receiving();scope=NULLIF(current_setting('opendirectory.employee_enrollment',true),'')::jsonb;witness=scope->'witness';source=witness->'source';
 IF scope IS NULL OR scope->>'action' IS NULL OR scope->>'action' NOT IN('complete','withdraw') OR scope->>'operationId' IS NULL
  OR scope#>>'{proof,subject}' IS DISTINCT FROM 'oauth-provider' OR scope#>>'{proof,issuer}' IS DISTINCT FROM source->>'issuer'
  OR jsonb_typeof(scope#>'{proof,expiresAt}') IS DISTINCT FROM 'number' OR jsonb_typeof(scope->'validUntil') IS DISTINCT FROM 'number'
  OR (scope->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR (scope->>'validUntil')::numeric>(scope#>>'{proof,expiresAt}')::numeric
  OR source->'permissions' IS DISTINCT FROM '["employees.invitations.read","employees.invitations.create","employees.invitations.revoke"]'::jsonb
  OR scope#>'{authSource,witness}' IS DISTINCT FROM witness OR witness#>>'{request,id}' IS DISTINCT FROM witness->>'id'
  OR witness#>>'{request,userId}' IS DISTINCT FROM source#>>'{target,id}' OR witness#>>'{request,userRevision}' IS DISTINCT FROM source#>>'{target,revision}'
  OR witness->'tenant' IS DISTINCT FROM source->'tenant' OR witness#>'{source,target,enabled}' IS DISTINCT FROM 'false'::jsonb
  OR witness#>'{source,target,unlinked}' IS DISTINCT FROM 'true'::jsonb OR witness#>'{source,target,ordinary}' IS DISTINCT FROM 'true'::jsonb
  OR scope->>'action'='complete' AND(scope#>'{authSource,valid}' IS DISTINCT FROM 'true'::jsonb OR scope#>>'{authSource,status}' IS DISTINCT FROM 'credential_pending'
   OR (scope->>'validUntil')::numeric>extract(epoch FROM (witness->>'expiresAt')::timestamptz) OR jsonb_typeof(witness->'credential') IS DISTINCT FROM 'object')
  OR scope->>'action'='withdraw' AND scope#>'{authSource,revoked}' IS DISTINCT FROM 'true'::jsonb
  THEN RAISE EXCEPTION 'Actual original employee credential source required' USING ERRCODE='42501';END IF;
 RETURN scope;
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_withdrawal_unchanged(identifier UUID,actual JSONB) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE enrollment identity_employee_enrollments;original JSONB;
BEGIN
 SELECT * INTO enrollment FROM identity_employee_enrollments WHERE id=identifier;original=enrollment.user_after;
 IF enrollment.id IS NULL OR actual IS NULL OR actual->>'id' IS DISTINCT FROM enrollment.user_id::text THEN RETURN false;END IF;
 IF actual=original THEN RETURN true;END IF;
 RETURN actual-ARRAY['record_revision','authorization_revision','eligibility_revision','tenant_generation'] IS NOT DISTINCT FROM original-ARRAY['record_revision','authorization_revision','eligibility_revision','tenant_generation']
  AND(actual->>'record_revision')::bigint>(original->>'record_revision')::bigint AND(actual->>'authorization_revision')::bigint>(original->>'authorization_revision')::bigint
  AND(actual->>'eligibility_revision')::bigint>(original->>'eligibility_revision')::bigint
  AND(SELECT count(*) FROM identity_user_record_audit WHERE user_id=enrollment.user_id AND revision>(original->>'record_revision')::bigint AND revision<=(actual->>'record_revision')::bigint)=1
  AND EXISTS(SELECT 1 FROM identity_user_record_audit WHERE user_id=enrollment.user_id AND revision=(actual->>'record_revision')::bigint AND action='update'
   AND details->'before'=identity_directory_creation_values('user',original) AND details->'after'=identity_directory_creation_values('user',original))
  AND EXISTS(SELECT 1 FROM identity_tenants tenant JOIN identity_tenant_events event ON event.tenant_id=tenant.id AND event.action='tenant-update'
   JOIN identity_tenant_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=tenant.id AND outbox.action=event.action
   JOIN identity_user_audit audit ON audit.user_id=enrollment.user_id AND audit.revision=(actual->>'eligibility_revision')::bigint AND audit.actor=event.actor->>'databaseRole'
   JOIN identity_user_outbox user_outbox ON user_outbox.user_id=audit.user_id AND user_outbox.revision=audit.revision
   WHERE tenant.id=enrollment.tenant_id AND NOT tenant.enabled AND tenant.generation::text=actual->>'tenant_generation'
    AND event.details->>'generation'=tenant.generation::text AND event.details->>'version'=tenant.version::text AND event.details->'enabled'='false'::jsonb
    AND audit.details->>'tenantGeneration'=tenant.generation::text AND audit.details->'enabled'='false'::jsonb AND user_outbox.payload=audit.details);
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_actor(proof JSONB) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE scope JSONB;source JSONB;witness JSONB;before_state JSONB;expected JSONB;enrollment identity_employee_enrollments;
BEGIN
 scope=identity_employee_scope();witness=scope->'witness';source=witness->'source';before_state=proof#>'{target,before}';
 expected=identity_directory_creation_values('user',before_state)||jsonb_build_object('enabled',scope->>'action'='complete');
 IF proof IS DISTINCT FROM scope->'mutation' OR proof->'context' IS DISTINCT FROM 'null'::jsonb OR proof->'rolesSnapshot' IS DISTINCT FROM 'null'::jsonb
  OR proof->>'issuer' IS DISTINCT FROM source->>'issuer' OR proof->>'subject' IS DISTINCT FROM 'oauth-provider' OR proof->>'operationId' IS DISTINCT FROM scope->>'operationId'
  OR proof->'tenant' IS DISTINCT FROM witness->'tenant' OR proof->'validUntil' IS DISTINCT FROM scope->'validUntil'
  OR proof#>>'{target,id}' IS DISTINCT FROM source#>>'{target,id}' OR proof#>>'{target,action}' IS DISTINCT FROM 'update'
  OR proof#>'{target,expectedValues}' IS DISTINCT FROM expected OR before_state->'enabled' IS DISTINCT FROM to_jsonb(scope->>'action'='withdraw')
  OR scope->>'action'='complete' AND NOT EXISTS(SELECT 1 FROM identity_tenants tenant WHERE tenant.id::text=witness#>>'{tenant,id}' AND tenant.enabled
   AND tenant.version::text=witness#>>'{tenant,version}' AND tenant.generation::text=witness#>>'{tenant,generation}')
  OR scope->>'action'='withdraw' AND identity_tenant_id('user',(witness#>>'{request,userId}')::uuid)::text IS DISTINCT FROM witness#>>'{tenant,id}'
  THEN RAISE EXCEPTION 'Exact workload employee user transition required' USING ERRCODE='42501';END IF;
 IF scope->>'action'='complete' THEN
  IF before_state->>'record_revision' IS DISTINCT FROM source#>>'{target,revision}' OR before_state->>'tenant_generation' IS DISTINCT FROM source#>>'{target,tenantGeneration}'
   OR identity_subject_link_role_state((source->>'actorUserId')::uuid) IS DISTINCT FROM scope->'ownerRolesSnapshot'
   OR before_state->>'username' IS DISTINCT FROM source#>>'{target,username}' OR before_state->>'email' IS DISTINCT FROM source#>>'{target,email}'
   OR NOT EXISTS(SELECT 1 FROM identity_company_activations owner JOIN users account ON account.id=owner.user_id JOIN identity_subject_links link ON link.user_id=account.id
    WHERE owner.user_id::text=source->>'actorUserId' AND owner.tenant_id::text=witness#>>'{tenant,id}' AND owner.issuer=source->>'issuer' AND owner.subject=source->>'subject'
    AND owner.console_client_id=source->>'consoleClientId' AND identity_company_owner_active(owner) AND link.issuer=owner.issuer AND link.subject=owner.subject
    AND account.authorization_revision::text=source#>>'{context,revision}' AND link.authorization_revision::text=source#>>'{context,linkRevision}')
   OR EXISTS(SELECT 1 FROM identity_role_assignments WHERE user_id=(source#>>'{target,id}')::uuid AND role<>'user' AND revoked_at IS NULL)
   OR EXISTS(SELECT 1 FROM identity_pim_eligibilities WHERE user_id=(source#>>'{target,id}')::uuid AND revoked_at IS NULL)
   OR EXISTS(SELECT 1 FROM identity_company_activations WHERE user_id=(source#>>'{target,id}')::uuid)
   THEN RAISE EXCEPTION 'Original ordinary employee and actual owner required' USING ERRCODE='42501';END IF;
 ELSE
  SELECT * INTO enrollment FROM identity_employee_enrollments WHERE id=(scope#>>'{witness,id}')::uuid;
  IF enrollment.id IS NULL OR enrollment.witness IS DISTINCT FROM witness OR NOT identity_employee_withdrawal_unchanged(enrollment.id,before_state)
   THEN RAISE EXCEPTION 'Only the unchanged original partial enrollment can withdraw' USING ERRCODE='42501';END IF;
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_valid(identifier UUID) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
BEGIN
 PERFORM identity_employee_receiving();RETURN EXISTS(SELECT 1 FROM identity_employee_enrollments enrollment
  JOIN identity_employee_enrollment_events event ON event.id=enrollment.event_id AND event.enrollment_id=enrollment.id AND event.after_state=to_jsonb(enrollment)
  JOIN identity_employee_enrollment_outbox outbox ON outbox.id=event.id AND outbox.status='pending' AND outbox.fingerprint=encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex')
  JOIN identity_employee_enrollment_events original ON original.id=enrollment.creation_event_id AND original.enrollment_id=enrollment.id AND original.action='complete'
  JOIN identity_employee_enrollment_outbox original_outbox ON original_outbox.id=original.id AND original_outbox.fingerprint=encode(sha256(convert_to(to_jsonb(original)::text,'UTF8')),'hex')
  JOIN identity_directory_user_events mutation ON mutation.id=enrollment.creation_event_id AND mutation.user_id=enrollment.user_id AND mutation.tenant_id=enrollment.tenant_id AND mutation.action='update'
   AND mutation.actor=jsonb_build_object('issuer',enrollment.issuer,'subject','oauth-provider','userId',NULL::text)
   AND mutation.scope_sha256=encode(sha256(convert_to(enrollment.acceptance_mutation::text,'UTF8')),'hex')
   AND mutation.details->>'afterSha256'=encode(sha256(convert_to(enrollment.user_after::text,'UTF8')),'hex')
  JOIN identity_directory_user_outbox mutation_outbox ON mutation_outbox.id=mutation.id AND mutation_outbox.tenant_id=enrollment.tenant_id AND mutation_outbox.action='update'
  WHERE enrollment.id=identifier AND original.after_state->'witness'=enrollment.witness AND original.after_state->'acceptance_mutation'=enrollment.acceptance_mutation
   AND EXISTS(SELECT 1 FROM identity_link_audit WHERE action='link' AND actor='oauth-provider' AND details->>'issuer'=enrollment.issuer AND details->>'subject'=enrollment.subject
    AND details->>'user_id'=enrollment.user_id::text AND details->>'authorization_revision'=enrollment.link_revision::text));
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;witness JSONB;mutation JSONB;actual JSONB;event identity_employee_enrollment_events;core identity_directory_user_events;
BEGIN
 IF TG_OP IN('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Employee enrollment evidence is retained' USING ERRCODE='42501';END IF;
 scope=identity_employee_scope();witness=scope->'witness';mutation=scope->'mutation';PERFORM identity_employee_actor(mutation);
 IF NEW.id::text IS DISTINCT FROM witness->>'id' OR NEW.tenant IS DISTINCT FROM witness->'tenant' OR NEW.witness IS DISTINCT FROM witness OR NEW.tenant_id::text IS DISTINCT FROM witness#>>'{tenant,id}'
  OR NEW.issuer IS DISTINCT FROM witness#>>'{source,issuer}' OR NEW.subject IS DISTINCT FROM witness->>'subjectId' OR NEW.user_id::text IS DISTINCT FROM witness#>>'{request,userId}'
  OR NEW.console_client_id IS DISTINCT FROM witness#>>'{source,consoleClientId}' OR NEW.event_id::text IS DISTINCT FROM scope->>'operationId'
  THEN RAISE EXCEPTION 'Exact original employee enrollment namespace required' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF scope->>'action'<>'complete' OR NEW.state<>'active' OR NEW.revision<>1 OR NEW.withdrawal_mutation IS NOT NULL OR NEW.acceptance_mutation IS DISTINCT FROM mutation OR NEW.creation_event_id<>NEW.event_id
   THEN RAISE EXCEPTION 'Only original employee acceptance can create a certificate' USING ERRCODE='42501';END IF;
 ELSE
  IF scope->>'action'<>'withdraw' OR OLD.state<>'active' OR NEW.state<>'withdrawn' OR NEW.revision<>OLD.revision+1 OR NOT identity_employee_valid(OLD.id)
   OR NEW.withdrawal_mutation IS DISTINCT FROM mutation
   OR to_jsonb(NEW)-ARRAY['state','revision','event_id','withdrawal_mutation'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','revision','event_id','withdrawal_mutation']
   THEN RAISE EXCEPTION 'Only original partial enrollment withdrawal allowed' USING ERRCODE='42501';END IF;
 END IF;
 actual=identity_directory_user_state(identity_directory_creation_row('user',NEW.user_id));
 IF scope->>'action'='complete' AND(actual IS DISTINCT FROM NEW.user_after OR actual->'enabled' IS DISTINCT FROM 'true'::jsonb
  OR NOT EXISTS(SELECT 1 FROM identity_subject_links WHERE issuer=NEW.issuer AND subject=NEW.subject AND user_id=NEW.user_id AND authorization_revision=NEW.link_revision))
  OR scope->>'action'='withdraw' AND(actual->'enabled' IS DISTINCT FROM 'false'::jsonb OR EXISTS(SELECT 1 FROM identity_subject_links WHERE issuer=NEW.issuer AND subject=NEW.subject)
   OR NOT EXISTS(SELECT 1 FROM identity_link_audit WHERE action='unlink' AND actor='oauth-provider' AND details->>'issuer'=NEW.issuer AND details->>'subject'=NEW.subject AND details->>'authorization_revision'=NEW.link_revision::text))
  THEN RAISE EXCEPTION 'Actual coupled employee transition required' USING ERRCODE='42501';END IF;
 SELECT * INTO core FROM identity_directory_user_events WHERE id=NEW.event_id;
 IF core.id IS NULL OR core.transaction_id<>txid_current() OR core.user_id<>NEW.user_id OR core.tenant_id<>NEW.tenant_id OR core.action<>'update'
  OR core.scope_sha256 IS DISTINCT FROM encode(sha256(convert_to(mutation::text,'UTF8')),'hex') OR core.details->>'afterSha256' IS DISTINCT FROM encode(sha256(convert_to(actual::text,'UTF8')),'hex')
  OR NOT EXISTS(SELECT 1 FROM identity_directory_user_outbox WHERE id=core.id AND tenant_id=NEW.tenant_id AND action='update')
  THEN RAISE EXCEPTION 'Actual canonical employee user mutation receipt required' USING ERRCODE='42501';END IF;
 IF TG_WHEN='AFTER' THEN
  SELECT * INTO event FROM identity_employee_enrollment_events WHERE id=NEW.event_id;
  IF NOT identity_employee_valid(NEW.id) OR event.transaction_id<>txid_current() OR event.valid_until<=clock_timestamp() OR event.after_state IS DISTINCT FROM to_jsonb(NEW)
   OR event.admission_sha256 IS DISTINCT FROM encode(sha256(convert_to(scope::text,'UTF8')),'hex')
   THEN RAISE EXCEPTION 'Original employee enrollment commit evidence required' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_event() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;event identity_employee_enrollment_events;
BEGIN
 scope=identity_employee_scope();
 INSERT INTO identity_employee_enrollment_events(id,enrollment_id,tenant_id,action,actor,before_state,after_state,admission_sha256,valid_until)
  VALUES(NEW.event_id,NEW.id,NEW.tenant_id,scope->>'action',jsonb_build_object('kind','workload','issuer',scope#>>'{proof,issuer}','subject','oauth-provider','tokenId',scope#>>'{proof,tokenId}'),
   CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD) END,to_jsonb(NEW),encode(sha256(convert_to(scope::text,'UTF8')),'hex'),to_timestamp((scope->>'validUntil')::double precision)) RETURNING * INTO event;
 INSERT INTO identity_employee_enrollment_outbox VALUES(event.id,'pending',encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex'));RETURN NULL;
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_evidence() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;data JSONB;
BEGIN
 IF TG_OP='TRUNCATE' AND TG_TABLE_NAME<>'identity_employee_enrollment_manifest' AND NULLIF(current_setting('opendirectory.employee_enrollment',true),'') IS NULL
  AND NOT EXISTS(SELECT 1 FROM identity_employee_enrollments) AND NOT EXISTS(SELECT 1 FROM identity_employee_enrollment_events) AND NOT EXISTS(SELECT 1 FROM identity_employee_enrollment_outbox) THEN RETURN NULL;END IF;
 IF TG_OP<>'INSERT' OR TG_TABLE_NAME='identity_employee_enrollment_manifest' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Employee enrollment evidence is immutable' USING ERRCODE='42501';END IF;
 scope=identity_employee_scope();data=to_jsonb(NEW);
 IF data->>'id' IS DISTINCT FROM scope->>'operationId' OR TG_TABLE_NAME='identity_employee_enrollment_events' AND((data->>'transaction_id')::bigint<>txid_current() OR data->>'enrollment_id' IS DISTINCT FROM scope#>>'{witness,id}')
  THEN RAISE EXCEPTION 'Original employee enrollment evidence required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_employee_fence() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;data JSONB;witness JSONB;target TEXT;
BEGIN
 scope=NULLIF(current_setting('opendirectory.employee_enrollment',true),'')::jsonb;
 IF scope IS NULL THEN
  IF EXISTS(SELECT 1 FROM identity_employee_enrollment_events WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION 'Original employee scope cannot disappear' USING ERRCODE='42501';END IF;
  IF TG_OP='TRUNCATE' THEN RETURN NULL;ELSIF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Unrelated employee enrollment truncate forbidden' USING ERRCODE='42501';END IF;
 scope=identity_employee_scope();witness=scope->'witness';target=witness#>>'{request,userId}';data=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 IF TG_TABLE_NAME IN('identity_employee_enrollments','identity_employee_enrollment_events','identity_employee_enrollment_outbox') THEN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Employee enrollment is retained' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='users' THEN
  IF TG_OP<>'UPDATE' OR data->>'id' IS DISTINCT FROM target OR data-ARRAY['enabled','updated_at','record_revision','authorization_revision','eligibility_revision'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['enabled','updated_at','record_revision','authorization_revision','eligibility_revision']
   THEN RAISE EXCEPTION 'Only the exact employee status may change' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='identity_subject_links' THEN
  IF data->>'issuer' IS DISTINCT FROM witness#>>'{source,issuer}' OR data->>'subject' IS DISTINCT FROM witness->>'subjectId' OR data->>'user_id' IS DISTINCT FROM target
   OR TG_OP IS DISTINCT FROM(CASE WHEN scope->>'action'='complete' THEN 'INSERT' ELSE 'DELETE' END)
   THEN RAISE EXCEPTION 'Only the original employee subject link may change' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='identity_subject_tenant_bindings' THEN
  IF TG_OP<>'INSERT' OR data->>'issuer' IS DISTINCT FROM witness#>>'{source,issuer}' OR data->>'subject' IS DISTINCT FROM witness->>'subjectId' OR data->>'tenant_id' IS DISTINCT FROM witness#>>'{tenant,id}'
   OR TG_WHEN='BEFORE' AND pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Only the actual original subject tenant claim allowed' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME IN('identity_directory_user_events','identity_directory_user_outbox','identity_user_audit','identity_user_outbox','identity_user_record_audit','identity_authorization_audit','identity_link_audit','identity_tenant_events','identity_tenant_outbox') THEN
  IF TG_OP<>'INSERT' OR TG_WHEN='BEFORE' AND pg_trigger_depth()<2 OR data ? 'user_id' AND data->>'user_id' IS DISTINCT FROM target
   OR data ? 'tenant_id' AND data->>'tenant_id' IS DISTINCT FROM witness#>>'{tenant,id}' OR data ? 'actor' AND jsonb_typeof(data->'actor')='string' AND data->>'actor'<>'oauth-provider'
   THEN RAISE EXCEPTION 'Only actual employee mutation evidence fanout allowed' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'Unrelated employee enrollment write forbidden' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;

DO $$ DECLARE signature TEXT;definition TEXT;relation TEXT;hook RECORD;BEGIN
 definition=pg_get_functiondef('identity_directory_creation_actor(jsonb)'::regprocedure);
 IF strpos(definition,'identity_employee_actor(proof)')=0 THEN
  definition=replace(definition,E'BEGIN\n',E'BEGIN\n IF NULLIF(current_setting(''opendirectory.employee_enrollment'',true),'''') IS NOT NULL THEN PERFORM identity_employee_actor(proof);RETURN;END IF;\n');
 END IF;EXECUTE definition;
 DROP TRIGGER IF EXISTS employee_enrollment_evidence ON identity_employee_enrollment_manifest;
 FOREACH signature IN ARRAY ARRAY['identity_employee_receiving()','identity_employee_scope()','identity_employee_withdrawal_unchanged(uuid,jsonb)','identity_employee_actor(jsonb)','identity_employee_valid(uuid)','identity_employee_guard()','identity_employee_event()','identity_employee_evidence()','identity_employee_fence()',
  'identity_directory_creation_actor(jsonb)','identity_directory_user_mutation_guard()','identity_directory_user_mutation_actor(jsonb)','identity_directory_user_evidence_guard()',
  'identity_subject_tenant_transition()','identity_subject_tenant_binding_guard()','identity_link_changed()','identity_authorization_link_guard()','identity_authorization_user_guard()',
  'identity_user_eligibility_guard()','identity_user_record_version()','identity_user_record_changed()','identity_authorization_user_record()','identity_user_eligibility_record()'] LOOP
  IF left(signature,18)='identity_employee_' THEN
   EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
  END IF;
  INSERT INTO identity_employee_enrollment_manifest VALUES(signature,md5(pg_get_functiondef(to_regprocedure(signature)))) ON CONFLICT ON CONSTRAINT identity_employee_enrollment_manifest_pkey DO UPDATE SET digest=EXCLUDED.digest;
 END LOOP;
 CREATE OR REPLACE TRIGGER employee_enrollment_before BEFORE INSERT OR UPDATE OR DELETE ON identity_employee_enrollments FOR EACH ROW EXECUTE FUNCTION identity_employee_guard();
 CREATE OR REPLACE TRIGGER employee_enrollment_record AFTER INSERT OR UPDATE ON identity_employee_enrollments FOR EACH ROW EXECUTE FUNCTION identity_employee_event();
 DROP TRIGGER IF EXISTS employee_enrollment_commit ON identity_employee_enrollments;
 CREATE CONSTRAINT TRIGGER employee_enrollment_commit AFTER INSERT OR UPDATE ON identity_employee_enrollments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_employee_guard();
 FOREACH relation IN ARRAY ARRAY['identity_employee_enrollments','identity_employee_enrollment_events','identity_employee_enrollment_outbox','identity_employee_enrollment_manifest'] LOOP
  IF relation<>'identity_employee_enrollments' THEN EXECUTE format('CREATE OR REPLACE TRIGGER employee_enrollment_evidence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_employee_evidence()',relation);END IF;
  EXECUTE format('CREATE OR REPLACE TRIGGER employee_enrollment_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_employee_evidence()',relation);
  REVOKE ALL ON identity_employee_enrollments,identity_employee_enrollment_events,identity_employee_enrollment_outbox,identity_employee_enrollment_manifest FROM PUBLIC;
  FOR hook IN SELECT * FROM identity_license_user_source_hooks()
   UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_groups_fence','identity_company_offboarding_groups_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_access_fence','identity_company_offboarding_access_fence'
   UNION ALL SELECT 'aaa_identity_company_automation_fence','identity_automation_fence'
   UNION ALL SELECT 'zzz_company_group_rule_fence','identity_company_group_rule_fence'
   UNION ALL SELECT 'zzz_company_group_rule_work_fence','identity_company_group_rule_work_fence' LOOP
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,relation,hook.routine);
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',CASE hook.trigger_name WHEN 'zzz_company_group_rule_fence' THEN 'zzz_company_group_rule_no_truncate' WHEN 'zzz_company_group_rule_work_fence' THEN 'zzz_company_group_rule_work_truncate' ELSE regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate') END,relation,hook.routine);
  END LOOP;
  EXECUTE format('DROP TRIGGER IF EXISTS zzz_company_group_rule_commit_fence ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER zzz_company_group_rule_commit_fence AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS zzz_company_group_rule_work_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER zzz_company_group_rule_work_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_work_fence()',relation);
 END LOOP;
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind='r' LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER aaa_identity_employee_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_employee_fence()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_employee_effect_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_employee_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_employee_effect_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_employee_effect_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_employee_fence()',relation);
 END LOOP;
END; $$;
ALTER TABLE identity_company_group_rule_app_manifest DISABLE TRIGGER company_group_rule_app_manifest_guard;
UPDATE identity_company_group_rule_app_manifest SET digest=md5(pg_get_functiondef(to_regprocedure(signature))) WHERE signature='identity_directory_creation_actor(jsonb)';
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE identity_company_group_rule_app_manifest ENABLE TRIGGER company_group_rule_app_manifest_guard;
