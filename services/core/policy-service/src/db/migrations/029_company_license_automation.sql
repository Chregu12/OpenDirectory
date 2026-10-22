CREATE OR REPLACE FUNCTION company_blueprint_assignment_actor_id(source JSONB) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN source->>'kind'='application' THEN source->>'grantId' ELSE source->>'actorUserId' END;
$$;
CREATE OR REPLACE FUNCTION company_blueprint_assignment_machine_source(source JSONB,live BOOLEAN DEFAULT true) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
DECLARE item JSONB;seen TEXT[]='{}';membership_ids TEXT[]='{}';
BEGIN
 IF NOT license_company_exact(source,ARRAY['schemaVersion','companyLicenseAutomationProtocol','kind','issuer','subject','tokenId','expiresAt','clientRevision','tenant','grantId','jobId','leaseToken','ruleId','retryCount','validUntil','permissions','target','group'])
  OR source->'schemaVersion'<>'1'::jsonb OR source->'companyLicenseAutomationProtocol'<>'1'::jsonb OR source->>'kind'<>'application'
  OR NOT company_blueprint_text(source->'issuer',1,2048) OR NOT company_blueprint_text(source->'subject',1,255) OR NOT company_blueprint_text(source->'tokenId',1,255)
  OR NOT license_company_revision_valid(source->'clientRevision') OR source->'permissions'<>'["licenses.groups.reconcile"]'::jsonb
  OR NOT license_company_uuid(source->>'grantId') OR NOT license_company_uuid(source->>'jobId') OR NOT license_company_uuid(source->>'leaseToken') OR NOT license_company_uuid(source->>'ruleId')
  OR NOT license_company_exact(source->'tenant',ARRAY['id','version','generation'])
  OR NOT license_company_uuid(source#>>'{tenant,id}') OR NOT license_company_revision_valid(source#>'{tenant,generation}') OR NOT license_company_revision_valid(source#>'{tenant,version}')
  OR jsonb_typeof(source->'expiresAt')<>'number' OR NOT(source->>'expiresAt'~'^[0-9]{1,16}$') OR jsonb_typeof(source->'validUntil')<>'number' OR NOT(source->>'validUntil'~'^[0-9]{1,16}$')
  OR jsonb_typeof(source->'retryCount')<>'number' OR NOT(source->>'retryCount'~'^[0-9]{1,10}$') OR (source->>'retryCount')::numeric>2147483647 OR (source->>'validUntil')::numeric>(source->>'expiresAt')::numeric
  OR live AND ((source->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR (source->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+50)
  THEN RETURN false;END IF;
 IF source->'target'<>'null'::jsonb AND (NOT license_company_exact(source->'target',ARRAY['id','revision','eligibilityRevision','enabled','deleted'])
  OR NOT license_company_uuid(source#>>'{target,id}') OR NOT license_company_revision_valid(source#>'{target,eligibilityRevision}')
  OR jsonb_typeof(source#>'{target,enabled}')<>'boolean' OR jsonb_typeof(source#>'{target,deleted}')<>'boolean'
  OR CASE WHEN source#>'{target,deleted}'='true'::jsonb THEN source#>'{target,enabled}'<>'false'::jsonb OR source#>'{target,revision}'<>'null'::jsonb ELSE NOT license_company_revision_valid(source#>'{target,revision}') END)
  THEN RETURN false;END IF;
 IF NOT license_company_exact(source->'group',ARRAY['schemaVersion','groupId','name','revision','deleted','memberIds','inactiveMemberIds','unresolvedMemberIds','memberships'])
  OR source#>'{group,schemaVersion}'<>'3'::jsonb OR NOT license_company_uuid(source#>>'{group,groupId}') OR NOT license_company_revision_valid(source#>'{group,revision}')
  OR jsonb_typeof(source#>'{group,deleted}')<>'boolean' OR jsonb_typeof(source#>'{group,memberIds}')<>'array' OR jsonb_typeof(source#>'{group,memberships}')<>'array'
  OR jsonb_array_length(source#>'{group,memberIds}')>10000 OR jsonb_array_length(source#>'{group,memberships}')<>jsonb_array_length(source#>'{group,memberIds}') THEN RETURN false;END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(source#>'{group,memberships}') LOOP
  IF NOT license_company_exact(item,ARRAY['userId','membershipId','eligibilityRevision','reviewDeadlineAt']) OR NOT license_company_uuid(item->>'userId') OR NOT license_company_uuid(item->>'membershipId')
   OR NOT license_company_revision_valid(item->'eligibilityRevision') OR NOT (source#>'{group,memberIds}' ? (item->>'userId')) OR item->>'userId'=ANY(seen) OR item->>'membershipId'=ANY(membership_ids)
   OR item->>'reviewDeadlineAt' IS NOT NULL AND extract(epoch FROM (item->>'reviewDeadlineAt')::timestamptz)<(source->>'validUntil')::numeric THEN RETURN false;END IF;
  seen=array_append(seen,item->>'userId');membership_ids=array_append(membership_ids,item->>'membershipId');
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;

CREATE TABLE IF NOT EXISTS company_license_automation_cycles (
 job_id UUID NOT NULL,retry_count INTEGER NOT NULL CHECK(retry_count>=0),cycle INTEGER NOT NULL CHECK(cycle BETWEEN 1 AND 5),tenant_id UUID NOT NULL,grant_id UUID NOT NULL,rule_id UUID NOT NULL REFERENCES company_license_groups(id),
 rule_revision BIGINT NOT NULL,group_snapshot JSONB NOT NULL,targets UUID[] NOT NULL CHECK(cardinality(targets)<=10000),authority JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),transaction_id BIGINT NOT NULL DEFAULT txid_current(),
 PRIMARY KEY(job_id,retry_count,cycle)
);
CREATE TABLE IF NOT EXISTS company_license_automation_pages (
 job_id UUID NOT NULL,retry_count INTEGER NOT NULL,cycle INTEGER NOT NULL,page INTEGER NOT NULL CHECK(page>0),results JSONB NOT NULL,authority JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),transaction_id BIGINT NOT NULL DEFAULT txid_current(),
 PRIMARY KEY(job_id,retry_count,cycle,page),FOREIGN KEY(job_id,retry_count,cycle) REFERENCES company_license_automation_cycles(job_id,retry_count,cycle),
 CHECK(jsonb_typeof(results)='array' AND jsonb_array_length(results) BETWEEN 1 AND 25)
);
CREATE TABLE IF NOT EXISTS company_license_automation_outbox (
 job_id UUID NOT NULL,retry_count INTEGER NOT NULL,cycle INTEGER NOT NULL,page INTEGER NOT NULL CHECK(page>=0),status TEXT NOT NULL CHECK(status='pending'),
 fingerprint TEXT NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$'),created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(job_id,retry_count,cycle,page),FOREIGN KEY(job_id,retry_count,cycle) REFERENCES company_license_automation_cycles(job_id,retry_count,cycle)
);
CREATE OR REPLACE FUNCTION company_blueprint_assignment_automation_fingerprint(job UUID,epoch INTEGER,iteration INTEGER,ordinal INTEGER) RETURNS TEXT LANGUAGE plpgsql STABLE AS $$
DECLARE data JSONB;
BEGIN
 IF ordinal=0 THEN SELECT to_jsonb(actual) INTO data FROM company_license_automation_cycles actual WHERE job_id=job AND retry_count=epoch AND cycle=iteration;
 ELSE SELECT to_jsonb(actual) INTO data FROM company_license_automation_pages actual WHERE job_id=job AND retry_count=epoch AND cycle=iteration AND page=ordinal;END IF;
 RETURN encode(sha256(convert_to(data::text,'UTF8')),'hex');
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_assignment_automation_authority(source JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT (source-'group')||jsonb_build_object('groupSha256',encode(sha256(convert_to((source->'group')::text,'UTF8')),'hex'));
$$;
CREATE OR REPLACE FUNCTION company_blueprint_assignment_automation_guard() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source JSONB;rule company_license_groups;captured company_license_automation_cycles;previous_page INTEGER;targets UUID[];item JSONB;ordinal INTEGER;binding company_blueprint_user_assignments;
BEGIN
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM company_license_automation_cycles) THEN RAISE EXCEPTION 'License automation history retained' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'License automation journal is immutable' USING ERRCODE='42501';END IF;
 source=NULLIF(current_setting('opendirectory.company_license_automation',true),'')::jsonb;
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='license_catalog'::regclass) OR current_setting('role')<>'none'
  OR NOT company_blueprint_assignment_machine_source(source) OR source->'target'<>'null'::jsonb OR NEW.transaction_id<>txid_current() OR NEW.job_id::text<>source->>'jobId' OR NEW.retry_count::text<>source->>'retryCount'
  OR NEW.authority IS DISTINCT FROM company_blueprint_assignment_automation_authority(source)
  THEN RAISE EXCEPTION 'Original app job authority required for journal' USING ERRCODE='42501';END IF;
 SELECT * INTO rule FROM company_license_groups WHERE id=(source->>'ruleId')::uuid AND tenant_id=(source#>>'{tenant,id}')::uuid;
 IF rule.id IS NULL OR rule.group_id::text<>source#>>'{group,groupId}' THEN RAISE EXCEPTION 'Own license group journal required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='company_license_automation_cycles' THEN
  IF NEW.tenant_id<>rule.tenant_id OR NEW.grant_id::text<>source->>'grantId' OR NEW.rule_id<>rule.id OR NEW.rule_revision<>rule.revision OR NEW.group_snapshot IS DISTINCT FROM source->'group'
   OR NEW.cycle<>COALESCE((SELECT max(cycle) FROM company_license_automation_cycles WHERE job_id=NEW.job_id AND retry_count=NEW.retry_count AND cycle<>NEW.cycle),0)+1
   THEN RAISE EXCEPTION 'Original bounded license cycle required' USING ERRCODE='42501';END IF;
  IF EXISTS(SELECT 1 FROM company_blueprint_user_assignments active_binding WHERE tenant_id=rule.tenant_id AND blueprint_id=rule.blueprint_id AND status='active' AND NOT company_blueprint_assignment_binding_valid(active_binding))
   THEN RAISE EXCEPTION 'Complete current group bindings required' USING ERRCODE='42501';END IF;
  targets=ARRAY(SELECT id FROM(
   SELECT value::text::uuid AS id FROM jsonb_array_elements_text(source#>'{group,memberIds}') WHERE rule.status='active' AND source#>'{group,deleted}'='false'::jsonb
   UNION SELECT user_id FROM company_blueprint_user_assignments WHERE tenant_id=rule.tenant_id AND blueprint_id=rule.blueprint_id AND status='active') desired ORDER BY id);
  IF NEW.targets IS DISTINCT FROM targets THEN RAISE EXCEPTION 'Complete actual license targets required' USING ERRCODE='42501';END IF;
 ELSE
  SELECT * INTO captured FROM company_license_automation_cycles WHERE job_id=NEW.job_id AND retry_count=NEW.retry_count AND cycle=NEW.cycle;
  IF captured.job_id IS NULL OR captured.rule_id<>rule.id OR captured.grant_id::text<>source->>'grantId' OR captured.rule_revision<>rule.revision OR captured.group_snapshot IS DISTINCT FROM source->'group'
   OR NEW.page<>COALESCE((SELECT max(page) FROM company_license_automation_pages WHERE job_id=NEW.job_id AND retry_count=NEW.retry_count AND cycle=NEW.cycle AND page<>NEW.page),0)+1
   OR jsonb_array_length(NEW.results)<>LEAST(25,cardinality(captured.targets)-(NEW.page-1)*25) THEN RAISE EXCEPTION 'Original next license journal page required' USING ERRCODE='42501';END IF;
  ordinal=(NEW.page-1)*25;
  FOR item IN SELECT value FROM jsonb_array_elements(NEW.results) LOOP
   ordinal=ordinal+1;
   IF NOT license_company_exact(item,ARRAY['userId','status','code']) OR item->>'userId' IS DISTINCT FROM captured.targets[ordinal]::text OR item->>'status' NOT IN('assigned','retained','removed','blocked')
    OR (CASE WHEN item->>'status'='blocked' THEN item->'code' NOT IN('403'::jsonb,'404'::jsonb,'409'::jsonb) ELSE item->'code'<>'null'::jsonb END)
    THEN RAISE EXCEPTION 'Actual ordered member result required' USING ERRCODE='42501';END IF;
   IF item->>'status' IN('assigned','retained') THEN
    SELECT * INTO binding FROM company_blueprint_user_assignments WHERE tenant_id=rule.tenant_id AND blueprint_id=rule.blueprint_id AND user_id=(item->>'userId')::uuid AND status='active';
    IF binding.id IS NULL OR NOT company_blueprint_assignment_binding_valid(binding) OR NOT(source#>'{group,memberIds}' ? (item->>'userId')) THEN RAISE EXCEPTION 'Actual retained group allocation required' USING ERRCODE='42501';END IF;
    IF item->>'status'='assigned' AND NOT EXISTS(SELECT 1 FROM company_blueprint_assignment_operations operation JOIN company_blueprint_assignment_events event ON event.id=operation.id
     WHERE operation.assignment_id=binding.id AND operation.action='assigned' AND operation.source->>'jobId'=NEW.job_id::text) THEN RAISE EXCEPTION 'Actual app assignment receipt required' USING ERRCODE='42501';END IF;
   ELSIF item->>'status'='removed' AND EXISTS(SELECT 1 FROM company_blueprint_user_assignments WHERE tenant_id=rule.tenant_id AND blueprint_id=rule.blueprint_id AND user_id=(item->>'userId')::uuid AND status='active')
    THEN RAISE EXCEPTION 'Removed group source must be absent' USING ERRCODE='42501';END IF;
  END LOOP;
 END IF;
 IF TG_WHEN='AFTER' AND NOT EXISTS(SELECT 1 FROM company_license_automation_outbox box WHERE box.job_id=NEW.job_id AND box.retry_count=NEW.retry_count AND box.cycle=NEW.cycle
  AND box.page=CASE WHEN TG_TABLE_NAME='company_license_automation_cycles' THEN 0 ELSE (to_jsonb(NEW)->>'page')::integer END AND box.status='pending' AND box.created_at=NEW.created_at
  AND box.fingerprint=company_blueprint_assignment_automation_fingerprint(NEW.job_id,NEW.retry_count,NEW.cycle,box.page)) THEN RAISE EXCEPTION 'Original pending license journal outbox required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_assignment_automation_outbox_guard() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source JSONB;original_time TIMESTAMPTZ;original_xid BIGINT;authority JSONB;
BEGIN
 IF TG_OP='TRUNCATE' THEN IF EXISTS(SELECT 1 FROM company_license_automation_outbox) THEN RAISE EXCEPTION 'License journal outbox retained' USING ERRCODE='42501';END IF;RETURN NULL;END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'License journal outbox immutable' USING ERRCODE='42501';END IF;
 source=NULLIF(current_setting('opendirectory.company_license_automation',true),'')::jsonb;
 IF NEW.page=0 THEN SELECT created_at,transaction_id,actual.authority INTO original_time,original_xid,authority FROM company_license_automation_cycles actual WHERE job_id=NEW.job_id AND retry_count=NEW.retry_count AND cycle=NEW.cycle;
 ELSE SELECT created_at,transaction_id,actual.authority INTO original_time,original_xid,authority FROM company_license_automation_pages actual WHERE job_id=NEW.job_id AND retry_count=NEW.retry_count AND cycle=NEW.cycle AND page=NEW.page;END IF;
 IF NOT company_blueprint_assignment_machine_source(source) OR authority IS DISTINCT FROM company_blueprint_assignment_automation_authority(source)
  OR original_xid IS DISTINCT FROM txid_current() OR original_time IS DISTINCT FROM NEW.created_at OR NEW.status<>'pending'
  OR NEW.fingerprint IS DISTINCT FROM company_blueprint_assignment_automation_fingerprint(NEW.job_id,NEW.retry_count,NEW.cycle,NEW.page)
  THEN RAISE EXCEPTION 'Actual original journal effect required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
DO $$ DECLARE relation TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['company_license_automation_cycles','company_license_automation_pages'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER company_license_automation_before BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION company_blueprint_assignment_automation_guard()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER company_license_automation_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION company_blueprint_assignment_automation_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS company_license_automation_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER company_license_automation_commit AFTER INSERT ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_blueprint_assignment_automation_guard()',relation);
  EXECUTE format('REVOKE ALL ON %I FROM PUBLIC',relation);
 END LOOP;
END; $$;
CREATE OR REPLACE TRIGGER company_license_automation_outbox_before BEFORE INSERT OR UPDATE OR DELETE ON company_license_automation_outbox FOR EACH ROW EXECUTE FUNCTION company_blueprint_assignment_automation_outbox_guard();
CREATE OR REPLACE TRIGGER company_license_automation_outbox_truncate BEFORE TRUNCATE ON company_license_automation_outbox FOR EACH STATEMENT EXECUTE FUNCTION company_blueprint_assignment_automation_outbox_guard();
REVOKE ALL ON company_license_automation_outbox FROM PUBLIC;
CREATE OR REPLACE FUNCTION company_blueprint_assignment_automation_receiving() RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM company_license_group_receiving();
 IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgfoid='company_blueprint_assignment_automation_guard()'::regprocedure
  AND tgrelid IN('company_license_automation_cycles'::regclass,'company_license_automation_pages'::regclass)
  AND (tgname='company_license_automation_before' AND tgtype=31 AND NOT tgdeferrable OR tgname='company_license_automation_truncate' AND tgtype=34 AND NOT tgdeferrable
   OR tgname='company_license_automation_commit' AND tgtype=5 AND tgdeferrable AND tginitdeferred))<>6
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='company_license_automation_outbox'::regclass AND tgfoid='company_blueprint_assignment_automation_outbox_guard()'::regprocedure AND tgenabled='O' AND tgtype=31 AND tgname='company_license_automation_outbox_before')
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='company_license_automation_outbox'::regclass AND tgfoid='company_blueprint_assignment_automation_outbox_guard()'::regprocedure AND tgenabled='O' AND tgtype=34 AND tgname='company_license_automation_outbox_truncate')
  THEN RAISE EXCEPTION 'Complete app license journal receiving required' USING ERRCODE='42501';END IF;
END; $$;
DO $$ DECLARE routine RECORD;BEGIN
 FOR routine IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname LIKE 'company_blueprint_assignment_automation_%' LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine.signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine.signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
 END LOOP;
 ALTER TABLE company_blueprint_assignment_receiver_manifest DISABLE TRIGGER company_blueprint_assignment_receiver_manifest_guard;
 INSERT INTO company_blueprint_assignment_receiver_manifest(signature,digest,definer,definition)
 SELECT oid::regprocedure::text,md5(prosrc),prosecdef,pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname LIKE 'company_blueprint_assignment_automation_%'
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest,definer=EXCLUDED.definer,definition=EXCLUDED.definition;
 ALTER TABLE company_blueprint_assignment_receiver_manifest ENABLE TRIGGER company_blueprint_assignment_receiver_manifest_guard;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_assignment_machine_authority(source JSONB,application_source JSONB,command JSONB,live BOOLEAN DEFAULT true) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
DECLARE rule company_license_groups;binding company_blueprint_user_assignments;
BEGIN
 IF source IS DISTINCT FROM application_source OR NOT company_blueprint_assignment_machine_source(source,live) OR NOT company_blueprint_assignment_command_valid(command)
  OR command->>'action' NOT IN('assigned','removed') OR command->>'userId' IS DISTINCT FROM source#>>'{target,id}' OR command->>'eligibilityRevision' IS DISTINCT FROM source#>>'{target,eligibilityRevision}'
  OR jsonb_array_length(command->'pools')<>1 THEN RETURN false;END IF;
 SELECT * INTO rule FROM company_license_groups WHERE id=(source->>'ruleId')::uuid;
 IF rule.id IS NULL OR rule.tenant_id::text<>source#>>'{tenant,id}' OR rule.group_id::text<>source#>>'{group,groupId}' OR rule.pool_id::text<>command#>>'{pools,0,poolId}'
  OR NOT EXISTS(SELECT 1 FROM company_license_group_events event JOIN company_license_group_outbox box ON box.id=event.id AND box.status='pending' WHERE event.rule_id=rule.id
    AND event.result-'created_at'-'updated_at'=to_jsonb(rule)-'created_at'-'updated_at' AND (event.result->>'created_at')::timestamptz=rule.created_at AND (event.result->>'updated_at')::timestamptz=rule.updated_at)
  OR NOT EXISTS(SELECT 1 FROM company_blueprint_versions WHERE blueprint_id=rule.blueprint_id AND version=1 AND tenant_id=rule.tenant_id AND draft->'configurations'='[]'::jsonb AND draft->'appPoolIds'=jsonb_build_array(rule.pool_id)) THEN RETURN false;END IF;
 IF command->>'action'='assigned' THEN
  RETURN (NOT live OR rule.status='active') AND command->>'blueprintId'=rule.blueprint_id::text AND command->>'version'='1'
   AND source#>'{target,enabled}'='true'::jsonb AND source#>'{target,deleted}'='false'::jsonb AND source#>'{group,deleted}'='false'::jsonb
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(source#>'{group,memberships}') member WHERE member->>'userId'=command->>'userId' AND member->>'eligibilityRevision'=command->>'eligibilityRevision');
 END IF;
 SELECT * INTO binding FROM company_blueprint_user_assignments WHERE id=(command->>'assignmentId')::uuid;
 RETURN binding.id IS NOT NULL AND binding.tenant_id=rule.tenant_id AND binding.blueprint_id=rule.blueprint_id AND binding.version=1 AND binding.user_id::text=command->>'userId'
  AND (NOT live OR rule.status='unlinked' OR source#>'{group,deleted}'='true'::jsonb OR NOT((source#>'{group,memberIds}') ? (command->>'userId')) OR binding.eligibility_revision::text<>source#>>'{target,eligibilityRevision}');
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
DO $$ DECLARE definition TEXT;signature TEXT;BEGIN
 definition=pg_get_functiondef('company_blueprint_assignment_authority_valid(jsonb,jsonb,jsonb,boolean)'::regprocedure);
 IF strpos(definition,'company_blueprint_assignment_machine_authority(source,application_source,command,live)')=0 THEN
  EXECUTE replace(definition,E'BEGIN\n',E'BEGIN\n IF source->>''kind''=''application'' OR application_source->>''kind''=''application'' THEN RETURN company_blueprint_assignment_machine_authority(source,application_source,command,live);END IF;\n');
 END IF;
 definition=pg_get_functiondef('company_blueprint_assignment_live_sources(jsonb,jsonb,jsonb)'::regprocedure);
 IF strpos(definition,'company_blueprint_assignment_machine_source(source)')=0 THEN
  EXECUTE replace(definition,E'BEGIN\n',E'BEGIN\n IF source->>''kind''=''application'' THEN RETURN source=application_source AND company_blueprint_assignment_machine_source(source);END IF;\n');
 END IF;
 definition=pg_get_functiondef('company_blueprint_assignment_guard()'::regprocedure);
 EXECUTE replace(definition,'COALESCE(NEW.source,NEW.application_source)->>''actorUserId''','company_blueprint_assignment_actor_id(COALESCE(NEW.source,NEW.application_source))');
 definition=pg_get_functiondef('company_blueprint_assignment_begin(jsonb,jsonb,jsonb)'::regprocedure);
 EXECUTE replace(definition,'authority->>''actorUserId''','company_blueprint_assignment_actor_id(authority)');
 definition=pg_get_functiondef('company_blueprint_subject_locks(jsonb)'::regprocedure);
 EXECUTE replace(definition,'source->>''actorUserId''','company_blueprint_assignment_actor_id(source)');
 IF to_regprocedure('company_blueprint_assignment_view_human(company_blueprint_user_assignments)') IS NULL THEN
  definition=pg_get_functiondef('company_blueprint_assignment_view(company_blueprint_user_assignments)'::regprocedure);
  EXECUTE replace(definition,'FUNCTION '||quote_ident(current_schema())||'.company_blueprint_assignment_view(','FUNCTION '||quote_ident(current_schema())||'.company_blueprint_assignment_view_human(');
 END IF;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_assignment_view(binding company_blueprint_user_assignments) RETURNS JSONB LANGUAGE sql STABLE AS $$
 SELECT company_blueprint_assignment_view_human(binding)||CASE WHEN operation.source->>'kind'='application' THEN jsonb_build_object('actorUserId',NULL,'actor',jsonb_build_object('kind','application','id',operation.source->>'grantId','clientId',operation.source->>'subject','clientRevision',operation.source->>'clientRevision')) ELSE '{}'::jsonb END
 FROM company_blueprint_assignment_operations operation WHERE operation.id=binding.operation_id;
$$;
DO $$ DECLARE routine RECORD;BEGIN
 FOR routine IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname IN('company_blueprint_assignment_actor_id','company_blueprint_assignment_machine_source','company_blueprint_assignment_machine_authority','company_blueprint_assignment_view_human','company_blueprint_assignment_view') LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine.signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine.signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
 END LOOP;
 ALTER TABLE company_blueprint_assignment_receiver_manifest DISABLE TRIGGER company_blueprint_assignment_receiver_manifest_guard;
 INSERT INTO company_blueprint_assignment_receiver_manifest(signature,digest,definer,definition)
 SELECT oid::regprocedure::text,md5(prosrc),prosecdef,pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname IN(
  'company_blueprint_assignment_actor_id','company_blueprint_assignment_machine_source','company_blueprint_assignment_machine_authority','company_blueprint_assignment_authority_valid','company_blueprint_assignment_live_sources',
  'company_blueprint_assignment_guard','company_blueprint_assignment_begin','company_blueprint_subject_locks','company_blueprint_assignment_view_human','company_blueprint_assignment_view')
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest,definer=EXCLUDED.definer,definition=EXCLUDED.definition;
 ALTER TABLE company_blueprint_assignment_receiver_manifest ENABLE TRIGGER company_blueprint_assignment_receiver_manifest_guard;
END; $$;
