ALTER TABLE identity_automation_grants DROP CONSTRAINT IF EXISTS identity_automation_grants_actions_check;
ALTER TABLE identity_automation_grants ADD CONSTRAINT identity_automation_grants_actions_check CHECK(cardinality(actions) BETWEEN 1 AND 5 AND actions<@ARRAY['directory.users.export','directory.groups.export','directory.ous.export','licenses.groups.reconcile','directory.groups.reconcile']::text[]);
ALTER TABLE identity_membership_origins ADD COLUMN IF NOT EXISTS application_grant_id UUID REFERENCES identity_automation_grants(id);

CREATE TABLE IF NOT EXISTS identity_company_group_rule_runs (
 id UUID PRIMARY KEY,job_id UUID NOT NULL REFERENCES identity_automation_jobs(id),grant_id UUID NOT NULL REFERENCES identity_automation_grants(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 group_id UUID NOT NULL REFERENCES identity_company_group_rules(group_id),retry_count INTEGER NOT NULL CHECK(retry_count>=0),cycle INTEGER NOT NULL CHECK(cycle BETWEEN 1 AND 5),
 rule_revision BIGINT NOT NULL,observation TEXT NOT NULL CHECK(observation~'^[a-f0-9]{64}$'),desired JSONB NOT NULL,targets UUID[] NOT NULL,
 source JSONB NOT NULL,transaction_id BIGINT NOT NULL DEFAULT txid_current(),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),UNIQUE(job_id,retry_count,cycle)
);
CREATE TABLE IF NOT EXISTS identity_company_group_rule_steps (
 id UUID PRIMARY KEY,run_id UUID NOT NULL REFERENCES identity_company_group_rule_runs(id),user_id UUID NOT NULL,result JSONB NOT NULL,source JSONB NOT NULL,
 effect_id UUID REFERENCES identity_company_group_rule_effects(id),transaction_id BIGINT NOT NULL DEFAULT txid_current(),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),UNIQUE(run_id,user_id)
);
CREATE TABLE IF NOT EXISTS identity_company_group_rule_work_outbox (
 id UUID PRIMARY KEY,entity TEXT NOT NULL CHECK(entity IN('run','step')),fingerprint TEXT NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$'),status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_group_rule_app_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);

CREATE OR REPLACE FUNCTION identity_company_group_rule_app_source(source JSONB) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE permission identity_automation_grants;job identity_automation_jobs;setting identity_company_group_rules;
BEGIN
 PERFORM identity_authority_owner();
 IF source IS NULL OR jsonb_typeof(source)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(source))<>13
  OR NOT source ?& ARRAY['kind','issuer','clientId','clientRevision','grantId','jobId','leaseToken','tokenId','validUntil','tenant','ruleId','ruleRevision','retryCount']
  OR EXISTS(SELECT 1 FROM jsonb_each(source) field WHERE field.key NOT IN('validUntil','tenant') AND jsonb_typeof(field.value)<>'string')
  OR jsonb_typeof(source->'validUntil') IS DISTINCT FROM 'number' OR source->>'validUntil'!~'^[0-9]{1,12}$'
  OR source->>'kind' IS DISTINCT FROM 'application' OR jsonb_typeof(source->'tokenId')<>'string' OR length(source->>'tokenId') NOT BETWEEN 1 AND 1024
  OR (source->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  THEN RAISE EXCEPTION 'Original bounded group-rule app source required' USING ERRCODE='42501';END IF;
 SELECT * INTO permission FROM identity_automation_grants WHERE id=(source->>'grantId')::uuid FOR SHARE;
 SELECT * INTO job FROM identity_automation_jobs WHERE id=(source->>'jobId')::uuid;
 SELECT * INTO setting FROM identity_company_group_rules WHERE group_id=(source->>'ruleId')::uuid;
 IF permission.id IS NULL OR job.id IS NULL OR setting.group_id IS NULL OR NOT identity_automation_grant_live(permission.id)
  OR NOT 'directory.groups.reconcile'=ANY(permission.actions) OR permission.issuer IS DISTINCT FROM source->>'issuer' OR permission.client_id IS DISTINCT FROM source->>'clientId'
  OR permission.client_revision::text IS DISTINCT FROM source->>'clientRevision' OR permission.approval->'tenant' IS DISTINCT FROM source->'tenant'
  OR source->>'validUntil' IS NULL OR to_timestamp((source->>'validUntil')::double precision)>LEAST(permission.expires_at,job.lease_until)
  OR job.grant_id<>permission.id OR job.tenant_id<>permission.tenant_id OR job.action<>'directory.groups.reconcile' OR job.status<>'running'
  OR job.lease_token::text IS DISTINCT FROM source->>'leaseToken' OR job.lease_until<=clock_timestamp() OR job.retry_count::text IS DISTINCT FROM source->>'retryCount'
  OR job.rule_id<>setting.group_id OR setting.tenant_id<>permission.tenant_id OR setting.revision::text IS DISTINCT FROM source->>'ruleRevision'
  OR identity_tenant_id('group',setting.group_id) IS DISTINCT FROM permission.tenant_id OR NOT EXISTS(SELECT 1 FROM groups WHERE id=setting.group_id)
  OR NOT EXISTS(SELECT 1 FROM identity_automation_events event JOIN identity_automation_outbox box ON box.id=event.id AND box.status='pending'
   WHERE event.entity='job' AND event.entity_id=job.id AND event.revision=job.revision AND event.snapshot=identity_automation_snapshot(to_jsonb(job)))
  OR NOT EXISTS(SELECT 1 FROM identity_company_group_rule_events event JOIN identity_company_group_rule_outbox box ON box.id=event.id AND box.status='pending'
   AND box.fingerprint=encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex') WHERE event.id=setting.last_event_id AND event.result=to_jsonb(setting))
  THEN RAISE EXCEPTION 'Actual current own app grant, job lease and group rule required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_group_rule_effect_actor(source JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN source#>>'{authority,kind}'='application' THEN jsonb_build_object('kind','application','grantId',source#>>'{authority,grantId}','clientId',source#>>'{authority,clientId}','clientRevision',source#>>'{authority,clientRevision}')
 ELSE jsonb_build_object('issuer',source#>>'{authority,issuer}','subject',source#>>'{authority,subject}','userId',source#>>'{authority,actorUserId}') END;
$$;
CREATE OR REPLACE FUNCTION identity_directory_group_actor(proof JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN proof ? 'application' THEN identity_company_group_rule_effect_actor(jsonb_build_object('authority',proof->'application'))
 ELSE jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof#>>'{context,userId}') END;
$$;
CREATE OR REPLACE FUNCTION identity_membership_application_origin(identity UUID) RETURNS BOOLEAN LANGUAGE sql VOLATILE SECURITY DEFINER AS $$
 SELECT EXISTS(SELECT 1 FROM identity_membership_origins origin JOIN identity_automation_grants permission ON permission.id=origin.application_grant_id
  JOIN identity_company_group_rule_effects effect ON effect.membership_id=origin.membership_id AND effect.action='member-add' AND effect.group_id=origin.group_id AND effect.user_id=origin.user_id AND effect.tenant_id=permission.tenant_id
  JOIN identity_company_group_rule_effect_outbox box ON box.id=effect.id AND box.status='pending' AND box.fingerprint=encode(sha256(convert_to(to_jsonb(effect)::text,'UTF8')),'hex')
  JOIN identity_directory_group_events actual ON actual.id=effect.id AND actual.action=effect.action AND actual.group_id=effect.group_id AND actual.tenant_id=effect.tenant_id AND actual.transaction_id=effect.transaction_id AND actual.scope_sha256=effect.group_scope_sha256
  JOIN identity_directory_group_outbox delivery ON delivery.id=actual.id AND delivery.status='pending'
  WHERE origin.membership_id=identity AND origin.created_by IS NULL AND identity_tenant_id('group',origin.group_id)=permission.tenant_id AND identity_tenant_id('user',origin.user_id)=permission.tenant_id
   AND effect.source#>>'{authority,kind}'='application' AND effect.source#>>'{authority,grantId}'=permission.id::text AND effect.source#>>'{authority,issuer}'=permission.issuer
   AND effect.source#>>'{authority,clientId}'=permission.client_id AND effect.source#>>'{authority,clientRevision}'=permission.client_revision::text AND actual.actor=identity_company_group_rule_effect_actor(effect.source));
$$;
CREATE OR REPLACE FUNCTION identity_membership_review_allowed(identity UUID) RETURNS BOOLEAN LANGUAGE sql VOLATILE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id
  LEFT JOIN users ON users.id=origin.user_id WHERE lease.membership_id=identity AND(lease.state='denied' OR lease.deadline_at<=identity_membership_review_now()
   OR NOT(lease.initial_grace OR lease.cycle>1) OR users.id IS NULL OR NOT users.enabled OR users.eligibility_revision<>origin.eligibility_revision
   OR NOT EXISTS(SELECT 1 FROM group_members WHERE membership_id=identity)))
 AND NOT EXISTS(SELECT 1 FROM identity_membership_origins origin WHERE origin.membership_id=identity AND origin.application_grant_id IS NOT NULL AND NOT identity_membership_application_origin(identity));
$$;
CREATE OR REPLACE FUNCTION identity_company_group_rule_app_actor(proof JSONB) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE work JSONB;
BEGIN
 PERFORM identity_company_group_rule_app_source(proof->'application');
 work=NULLIF(current_setting('opendirectory.company_group_rule_work',true),'')::jsonb;
 IF proof IS DISTINCT FROM NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb
  OR work->>'kind' IS DISTINCT FROM 'step' OR work->'source' IS DISTINCT FROM proof->'application' OR work->>'userId' IS DISTINCT FROM proof#>>'{target,member,userId}'
  OR NOT EXISTS(SELECT 1 FROM identity_company_group_rule_runs run WHERE run.id=(work->>'runId')::uuid AND run.job_id::text=proof#>>'{application,jobId}'
   AND run.group_id::text=proof#>>'{application,ruleId}' AND run.rule_revision::text=proof#>>'{application,ruleRevision}' AND run.retry_count::text=proof#>>'{application,retryCount}' AND (work->>'userId')::uuid=ANY(run.targets))
  OR proof ?| ARRAY['context','rolesSnapshot','authentication','authTime','factorRevision','freshMfa']
  OR proof->'tenant' IS DISTINCT FROM proof#>'{application,tenant}' OR proof->>'issuer' IS DISTINCT FROM proof#>>'{application,issuer}'
  OR proof->>'subject' IS DISTINCT FROM proof#>>'{application,clientId}' OR proof->>'validUntil' IS DISTINCT FROM proof#>>'{application,validUntil}'
  OR proof#>>'{target,id}' IS DISTINCT FROM proof#>>'{application,ruleId}' OR proof#>>'{target,action}' NOT IN('member-add','member-remove')
  THEN RAISE EXCEPTION 'Exact machine-only canonical group membership proof required' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_work_guard() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;source JSONB;run identity_company_group_rule_runs;setting identity_company_group_rules;row_data JSONB;expected JSONB;current_targets UUID[];current_member RECORD;wanted BOOLEAN;captured_effect identity_company_group_rule_effects;box identity_company_group_rule_work_outbox;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM identity_company_group_rule_runs) OR EXISTS(SELECT 1 FROM identity_company_group_rule_steps) OR EXISTS(SELECT 1 FROM identity_company_group_rule_work_outbox) THEN RAISE EXCEPTION 'Original group-rule work is retained' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Original group-rule work is immutable' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.company_group_rule_work',true),'')::jsonb;source=scope->'source';PERFORM identity_company_group_rule_app_source(source);
 IF COALESCE(scope->>'kind','') NOT IN('capture','step') OR jsonb_typeof(scope) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(scope))<>(CASE WHEN scope->>'kind'='capture' THEN 3 ELSE 4 END)
  THEN RAISE EXCEPTION 'Exact original group-rule work scope required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_company_group_rule_work_outbox' THEN
  IF NEW.entity='run' THEN SELECT to_jsonb(actual) INTO row_data FROM identity_company_group_rule_runs actual WHERE id=NEW.id AND transaction_id=txid_current();
  ELSE SELECT to_jsonb(actual) INTO row_data FROM identity_company_group_rule_steps actual WHERE id=NEW.id AND transaction_id=txid_current();END IF;
  IF row_data IS NULL OR row_data->'source' IS DISTINCT FROM source OR NEW.status<>'pending' OR NEW.created_at<>(row_data->>'created_at')::timestamptz
   OR NEW.fingerprint<>encode(sha256(convert_to(row_data::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'Actual original work pending fingerprint required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 row_data=to_jsonb(NEW);
 IF NEW.transaction_id<>txid_current() OR NEW.source IS DISTINCT FROM source THEN RAISE EXCEPTION 'Same original work source required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_company_group_rule_runs' THEN
  IF scope->>'kind'<>'capture' OR scope->>'runId' IS DISTINCT FROM NEW.id::text OR NEW.job_id::text IS DISTINCT FROM source->>'jobId' OR NEW.grant_id::text IS DISTINCT FROM source->>'grantId'
   OR NEW.group_id::text IS DISTINCT FROM source->>'ruleId' OR NEW.tenant_id::text IS DISTINCT FROM source#>>'{tenant,id}' OR NEW.rule_revision::text IS DISTINCT FROM source->>'ruleRevision'
   OR NEW.retry_count::text IS DISTINCT FROM source->>'retryCount' OR NEW.cycle<>(SELECT COALESCE(max(cycle),0)+1 FROM identity_company_group_rule_runs WHERE job_id=NEW.job_id AND retry_count=NEW.retry_count AND id<>NEW.id)
   THEN RAISE EXCEPTION 'Exact next original group-rule run required' USING ERRCODE='42501';END IF;
  IF TG_WHEN='BEFORE' THEN
   SELECT * INTO setting FROM identity_company_group_rules WHERE group_id=NEW.group_id;
   SELECT COALESCE(jsonb_agg(jsonb_build_object('userId',id,'eligibilityRevision',eligibility_revision::text) ORDER BY id),'[]'::jsonb) INTO expected FROM users WHERE identity_tenant_id('user',id)=NEW.tenant_id AND identity_company_group_rule_wants(setting,id);
   SELECT COALESCE(array_agg(id ORDER BY id),ARRAY[]::uuid[]) INTO current_targets FROM(SELECT (value->>'userId')::uuid AS id FROM jsonb_array_elements(expected)
    UNION SELECT member.user_id::uuid FROM group_members member WHERE member.group_id=NEW.group_id AND EXISTS(SELECT 1 FROM identity_company_group_rule_effects effect WHERE effect.group_id=NEW.group_id AND effect.membership_id=member.membership_id AND effect.action='member-add')) target;
   IF NEW.desired IS DISTINCT FROM expected OR NEW.targets IS DISTINCT FROM current_targets OR cardinality(NEW.targets)>10000 THEN RAISE EXCEPTION 'Complete actual own group-rule target capture required' USING ERRCODE='42501';END IF;
  END IF;
 ELSE
  SELECT * INTO run FROM identity_company_group_rule_runs WHERE id=NEW.run_id;
  IF run.id IS NULL OR scope->>'kind'<>'step' OR scope->>'runId' IS DISTINCT FROM run.id::text OR scope->>'userId' IS DISTINCT FROM NEW.user_id::text
   OR run.job_id::text IS DISTINCT FROM source->>'jobId' OR run.retry_count::text IS DISTINCT FROM source->>'retryCount' OR run.rule_revision::text IS DISTINCT FROM source->>'ruleRevision'
   OR NOT NEW.user_id=ANY(run.targets) OR NEW.result->>'userId' IS DISTINCT FROM NEW.user_id::text OR (SELECT count(*) FROM jsonb_object_keys(NEW.result))<>3
   OR NOT NEW.result ?& ARRAY['userId','status','code'] OR NEW.result->>'status' NOT IN('added','retained','manual-retained','removed','awaiting-review','blocked')
   OR (NEW.result->>'status'='blocked') IS DISTINCT FROM (NEW.result->'code'<>'null'::jsonb) OR NEW.result->>'status'='blocked' AND NEW.result->>'code' NOT IN('403','404','409','428')
   OR NEW.result->>'status'='blocked' AND jsonb_typeof(NEW.result->'code') IS DISTINCT FROM 'number'
   THEN RAISE EXCEPTION 'Exact actual bounded group-rule step required' USING ERRCODE='42501';END IF;
  SELECT * INTO setting FROM identity_company_group_rules WHERE group_id=run.group_id;wanted=identity_company_group_rule_wants(setting,NEW.user_id);
  SELECT member.membership_id,origin.eligibility_revision,(SELECT effect.rule_revision FROM identity_company_group_rule_effects effect WHERE effect.membership_id=member.membership_id AND effect.action='member-add') AS managed_revision
   INTO current_member FROM group_members member JOIN identity_membership_origins origin ON origin.membership_id=member.membership_id WHERE member.group_id=run.group_id AND member.user_id=NEW.user_id::text;
  IF NEW.effect_id IS NOT NULL THEN
   SELECT * INTO captured_effect FROM identity_company_group_rule_effects WHERE id=NEW.effect_id AND transaction_id=txid_current();
   IF captured_effect.id IS NULL OR captured_effect.source->'authority' IS DISTINCT FROM source OR captured_effect.user_id<>NEW.user_id OR captured_effect.group_id<>run.group_id
    OR (captured_effect.action='member-remove') IS DISTINCT FROM (NEW.result->>'status'='removed') OR NEW.result->>'status' NOT IN('added','awaiting-review','removed')
    THEN RAISE EXCEPTION 'Actual same-transaction membership effect required' USING ERRCODE='42501';END IF;
  ELSIF NEW.result->>'status'='added' OR NEW.result->>'status'='awaiting-review' AND (NOT wanted OR current_member.membership_id IS NULL OR current_member.managed_revision IS DISTINCT FROM setting.revision OR identity_membership_review_allowed(current_member.membership_id)) OR NEW.result->>'status'='removed' AND current_member.membership_id IS NOT NULL
   OR NEW.result->>'status'='manual-retained' AND (current_member.membership_id IS NULL OR current_member.managed_revision IS NOT NULL)
   OR NEW.result->>'status'='retained' AND (NOT wanted OR current_member.managed_revision IS DISTINCT FROM setting.revision OR current_member.eligibility_revision IS DISTINCT FROM (SELECT eligibility_revision FROM users WHERE id=NEW.user_id))
   THEN RAISE EXCEPTION 'Actual retained or absent membership state required' USING ERRCODE='42501';END IF;
 END IF;
 IF TG_WHEN='AFTER' THEN
  SELECT * INTO box FROM identity_company_group_rule_work_outbox WHERE id=NEW.id;
  IF box.id IS NULL OR box.fingerprint<>encode(sha256(convert_to(row_data::text,'UTF8')),'hex') OR box.status<>'pending' OR box.created_at<>NEW.created_at
   THEN RAISE EXCEPTION 'Actual immutable work and pending receipt required' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_work_fence() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;active BOOLEAN;
BEGIN
 scope=NULLIF(current_setting('opendirectory.company_group_rule_work',true),'')::jsonb;
 active=scope IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_group_rule_runs WHERE transaction_id=txid_current()) OR EXISTS(SELECT 1 FROM identity_company_group_rule_steps WHERE transaction_id=txid_current());
 IF active AND (TG_OP='TRUNCATE' OR TG_TABLE_NAME NOT IN('identity_company_group_rule_runs','identity_company_group_rule_steps','identity_company_group_rule_work_outbox') AND
  (scope->>'kind' IS DISTINCT FROM 'step' OR TG_TABLE_NAME NOT IN('groups','group_members','identity_membership_origins','identity_membership_review_leases','identity_membership_review_audit','identity_group_audit','identity_group_outbox','identity_directory_group_events','identity_directory_group_outbox','identity_company_group_rule_effects','identity_company_group_rule_effect_outbox')))
  THEN RAISE EXCEPTION 'Group-rule work cannot piggyback unrelated canonical writes' USING ERRCODE='42501';END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;ELSIF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;

DO $$ DECLARE definition TEXT;signature TEXT;BEGIN
 definition=pg_get_functiondef('identity_automation_license_guard()'::regprocedure);
 definition=replace(definition,'NEW.action=''licenses.groups.reconcile''','NEW.action IN(''licenses.groups.reconcile'',''directory.groups.reconcile'')');
 definition=replace(definition,'NEW.action<>''licenses.groups.reconcile''','NEW.action NOT IN(''licenses.groups.reconcile'',''directory.groups.reconcile'')');EXECUTE definition;
 definition=pg_get_functiondef('identity_directory_creation_actor(jsonb)'::regprocedure);
 IF strpos(definition,'identity_company_group_rule_app_actor(proof)')=0 THEN definition=replace(definition,E'BEGIN\n',E'BEGIN\n IF proof ? ''application'' THEN PERFORM identity_company_group_rule_app_actor(proof);RETURN;END IF;\n');END IF;EXECUTE definition;
 FOREACH signature IN ARRAY ARRAY['identity_directory_group_validate(jsonb)','identity_directory_group_evidence_guard()','identity_directory_group_finish()'] LOOP
  definition=pg_get_functiondef(to_regprocedure(signature));
  definition=replace(definition,'jsonb_build_object(''issuer'',proof->>''issuer'',''subject'',proof->>''subject'',''userId'',proof->''context''->>''userId'')','identity_directory_group_actor(proof)');
  definition=replace(definition,'origin.created_by=(proof->''context''->>''userId'')::uuid','origin.created_by IS NOT DISTINCT FROM (proof->''context''->>''userId'')::uuid AND origin.application_grant_id IS NOT DISTINCT FROM (proof#>>''{application,grantId}'')::uuid');EXECUTE definition;
 END LOOP;
 definition=pg_get_functiondef('identity_directory_group_commit()'::regprocedure);
 IF strpos(definition,'Actual app membership requires its durable step receipt')=0 THEN
  definition=replace(definition,'actual=identity_directory_group_validate(proof);',E'actual=identity_directory_group_validate(proof);\n IF proof ? ''application'' AND NOT EXISTS(SELECT 1 FROM identity_company_group_rule_steps step WHERE step.effect_id=(proof->>''operationId'')::uuid AND step.transaction_id=txid_current() AND step.source=proof->''application'' AND step.run_id::text=NULLIF(current_setting(''opendirectory.company_group_rule_work'',true),'''')::jsonb->>''runId'') THEN RAISE EXCEPTION ''Actual app membership requires its durable step receipt'' USING ERRCODE=''42501'';END IF;');
 END IF;EXECUTE definition;
 definition=pg_get_functiondef('identity_membership_origin_capture()'::regprocedure);
 IF strpos(definition,'identity_company_group_rule_app_actor')=0 THEN
  definition=replace(definition,E'BEGIN\n',E'BEGIN\n IF NULLIF(current_setting(''opendirectory.group_mutation'',true),'''')::jsonb ? ''application'' THEN\n  proof=NULLIF(current_setting(''opendirectory.group_mutation'',true),'''')::jsonb;PERFORM identity_company_group_rule_app_actor(proof);\n  SELECT * INTO policy FROM identity_membership_review_policies WHERE group_id=NEW.group_id AND retired_at IS NULL;\n  IF policy.id IS NULL AND EXISTS(SELECT 1 FROM identity_membership_review_policies WHERE group_id=NEW.group_id) OR policy.id IS NOT NULL AND policy.issuer IS DISTINCT FROM proof->>''issuer'' THEN RAISE EXCEPTION ''Actual own active review policy required'' USING ERRCODE=''42501'';END IF;\n  INSERT INTO identity_membership_origins(membership_id,group_id,user_id,created_by,eligibility_revision,application_grant_id) SELECT NEW.membership_id,NEW.group_id,id,NULL,eligibility_revision,(proof#>>''{application,grantId}'')::uuid FROM users WHERE id::text=NEW.user_id;\n  IF policy.id IS NOT NULL THEN INSERT INTO identity_membership_review_leases(policy_id,membership_id,initial_grace,projected_active,due_at,deadline_at) VALUES(policy.id,NEW.membership_id,false,false,identity_membership_review_now(),identity_membership_review_now()+interval ''1 second'');END IF;RETURN NEW;\n END IF;\n');
 END IF;EXECUTE definition;
 definition=pg_get_functiondef('identity_membership_review_guard()'::regprocedure);
 definition=replace(definition,'origin.created_by IS NULL OR NEW.state','origin.created_by IS NULL AND NOT identity_membership_application_origin(OLD.membership_id) OR NEW.state');EXECUTE definition;
 definition=pg_get_functiondef('identity_membership_review_independent(uuid,uuid,uuid)'::regprocedure);
 IF strpos(definition,'permission.id=origin.application_grant_id')=0 THEN definition=replace(definition,'actor<>configurer','actor<>configurer AND NOT EXISTS(SELECT 1 FROM identity_automation_grants permission WHERE permission.id=origin.application_grant_id AND permission.created_by=actor)');END IF;EXECUTE definition;
 definition=pg_get_functiondef('identity_company_group_rule_effect_guard()'::regprocedure);
 IF strpos(definition,'identity_company_group_rule_app_source')=0 THEN
 definition=replace(definition,'PERFORM identity_automation_owner(scope->''authority'');','IF scope#>>''{authority,kind}''=''application'' THEN PERFORM identity_company_group_rule_app_source(scope->''authority'');ELSE PERFORM identity_automation_owner(scope->''authority'');END IF;');
 definition=replace(definition,'jsonb_build_object(''issuer'',scope#>>''{authority,issuer}'',''subject'',scope#>>''{authority,subject}'',''userId'',scope#>>''{authority,actorUserId}'')','identity_company_group_rule_effect_actor(scope)');
 definition=replace(definition,'origin.created_by::text IS DISTINCT FROM scope#>>''{authority,actorUserId}''','origin.created_by::text IS DISTINCT FROM scope#>>''{authority,actorUserId}'' OR origin.application_grant_id::text IS DISTINCT FROM scope#>>''{authority,grantId}''');END IF;EXECUTE definition;
END; $$;

DO $$ DECLARE relation RECORD;table_name TEXT;hook RECORD;BEGIN
 FOREACH table_name IN ARRAY ARRAY['identity_company_group_rule_runs','identity_company_group_rule_steps','identity_company_group_rule_work_outbox'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER company_group_rule_work_before BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_work_guard()',table_name);
  EXECUTE format('CREATE OR REPLACE TRIGGER company_group_rule_work_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_work_guard()',table_name);
  IF table_name<>'identity_company_group_rule_work_outbox' THEN
   EXECUTE format('DROP TRIGGER IF EXISTS company_group_rule_work_commit ON %I',table_name);
   EXECUTE format('CREATE CONSTRAINT TRIGGER company_group_rule_work_commit AFTER INSERT ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_work_guard()',table_name);
  END IF;
 END LOOP;
 FOR relation IN SELECT oid::regclass AS identity FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind='r' AND relname NOT IN('identity_company_group_rule_app_manifest','identity_company_group_rule_manifest') LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER zzz_company_group_rule_work_fence BEFORE INSERT OR UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_work_fence()',relation.identity);
  EXECUTE format('CREATE OR REPLACE TRIGGER zzz_company_group_rule_work_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_work_fence()',relation.identity);
  EXECUTE format('DROP TRIGGER IF EXISTS zzz_company_group_rule_work_commit ON %s',relation.identity);
  EXECUTE format('CREATE CONSTRAINT TRIGGER zzz_company_group_rule_work_commit AFTER INSERT OR UPDATE OR DELETE ON %s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_work_fence()',relation.identity);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['identity_company_group_rule_runs','identity_company_group_rule_steps','identity_company_group_rule_work_outbox','identity_company_group_rule_app_manifest'] LOOP
  FOR hook IN SELECT * FROM identity_license_user_source_hooks()
   UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_groups_fence','identity_company_offboarding_groups_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_access_fence','identity_company_offboarding_access_fence'
   UNION ALL SELECT 'aaa_identity_company_automation_fence','identity_automation_fence'
   UNION ALL SELECT 'zzz_company_group_rule_fence','identity_company_group_rule_fence' LOOP
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,table_name,hook.routine);
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',CASE WHEN hook.trigger_name='zzz_company_group_rule_fence' THEN 'zzz_company_group_rule_no_truncate' ELSE regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate') END,table_name,hook.routine);
  END LOOP;
  EXECUTE format('DROP TRIGGER IF EXISTS zzz_company_group_rule_commit_fence ON %I',table_name);
  EXECUTE format('CREATE CONSTRAINT TRIGGER zzz_company_group_rule_commit_fence AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_fence()',table_name);
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_app_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE entry RECORD;
BEGIN
 PERFORM identity_company_group_rule_receiving();
 IF (SELECT count(*) FROM identity_company_group_rule_app_manifest)<>21
  OR (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgfoid='identity_company_group_rule_work_guard()'::regprocedure
   AND(tgname='company_group_rule_work_before' AND tgtype=31 AND NOT tgdeferrable OR tgname='company_group_rule_work_commit' AND tgtype=5 AND tgdeferrable AND tginitdeferred OR tgname='company_group_rule_work_truncate' AND tgtype=34 AND NOT tgdeferrable))<>8
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_group_rule_app_manifest'::regclass AND tgname='company_group_rule_app_manifest_guard' AND tgfoid='identity_company_group_rule_manifest_guard()'::regprocedure AND tgenabled='O' AND tgtype=62 AND NOT tgdeferrable)
  OR (SELECT count(*) FROM pg_trigger WHERE tgrelid IN('groups'::regclass,'group_members'::regclass,'users'::regclass) AND tgname='aaa_identity_directory_group_mutation' AND tgfoid='identity_directory_group_mutation_guard()'::regprocedure AND tgtype=31 AND tgenabled='O' AND NOT tgdeferrable)<>3
  OR (SELECT count(*) FROM pg_trigger WHERE tgrelid IN('groups'::regclass,'group_members'::regclass) AND tgname='identity_directory_group_commit' AND tgfoid='identity_directory_group_commit()'::regprocedure AND tgtype=29 AND tgenabled='O' AND tgdeferrable AND tginitdeferred)<>2
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='group_members'::regclass AND tgname='identity_membership_generation' AND tgfoid='identity_membership_generation()'::regprocedure AND tgtype=7 AND tgenabled='O' AND NOT tgdeferrable)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='group_members'::regclass AND tgname='a_identity_membership_origin' AND tgfoid='identity_membership_origin_capture()'::regprocedure AND tgtype=5 AND tgenabled='O' AND NOT tgdeferrable)
  OR EXISTS(SELECT 1 FROM pg_class relation WHERE relnamespace=current_schema()::regnamespace AND relkind='r' AND relname NOT IN('identity_company_group_rule_app_manifest','identity_company_group_rule_manifest')
   AND (NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname='zzz_company_group_rule_work_fence' AND tgfoid='identity_company_group_rule_work_fence()'::regprocedure AND tgenabled='O' AND tgtype=31)
    OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname='zzz_company_group_rule_work_commit' AND tgfoid='identity_company_group_rule_work_fence()'::regprocedure AND tgenabled='O' AND tgtype=29 AND tgdeferrable AND tginitdeferred)
    OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname='zzz_company_group_rule_work_truncate' AND tgfoid='identity_company_group_rule_work_fence()'::regprocedure AND tgenabled='O' AND tgtype=34)))
  THEN RAISE EXCEPTION 'Actual group-rule app receiving required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM identity_company_group_rule_app_manifest LOOP
  IF to_regprocedure(entry.signature) IS NULL OR entry.digest<>md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original group-rule app receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;
DO $$ DECLARE signature TEXT;BEGIN
 FOREACH signature IN ARRAY ARRAY['identity_company_group_rule_app_source(jsonb)','identity_company_group_rule_effect_actor(jsonb)','identity_directory_group_actor(jsonb)','identity_company_group_rule_app_actor(jsonb)','identity_company_group_rule_work_guard()','identity_company_group_rule_work_fence()','identity_company_group_rule_app_receiving()','identity_membership_application_origin(uuid)','identity_membership_review_allowed(uuid)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
END; $$;
CREATE OR REPLACE TRIGGER company_group_rule_app_manifest_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON identity_company_group_rule_app_manifest FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_manifest_guard();
ALTER TABLE identity_company_group_rule_app_manifest DISABLE TRIGGER company_group_rule_app_manifest_guard;
INSERT INTO identity_company_group_rule_app_manifest SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY[
 'identity_company_group_rule_app_source(jsonb)','identity_company_group_rule_effect_actor(jsonb)','identity_directory_group_actor(jsonb)','identity_company_group_rule_app_actor(jsonb)','identity_company_group_rule_work_guard()','identity_company_group_rule_work_fence()','identity_company_group_rule_app_receiving()',
 'identity_directory_creation_actor(jsonb)','identity_directory_group_validate(jsonb)','identity_directory_group_evidence_guard()','identity_directory_group_finish()','identity_membership_origin_capture()','identity_membership_review_guard()','identity_membership_review_independent(uuid,uuid,uuid)',
 'identity_directory_group_mutation_guard()','identity_directory_group_commit()','identity_membership_generation()','identity_membership_evidence_guard()','identity_membership_review_allowed(uuid)','identity_company_group_rule_effect_guard()','identity_membership_application_origin(uuid)']) signature ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE identity_company_group_rule_app_manifest ENABLE TRIGGER company_group_rule_app_manifest_guard;
ALTER TABLE identity_company_group_rule_manifest DISABLE TRIGGER company_group_rule_manifest_guard;
UPDATE identity_company_group_rule_manifest SET digest=md5(pg_get_functiondef(to_regprocedure(signature)));
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE identity_company_group_rule_manifest ENABLE TRIGGER company_group_rule_manifest_guard;
UPDATE identity_automation_receiver_manifest SET digest=md5(pg_get_functiondef(to_regprocedure(signature)));
REVOKE ALL ON identity_company_group_rule_runs,identity_company_group_rule_steps,identity_company_group_rule_work_outbox,identity_company_group_rule_app_manifest FROM PUBLIC;
