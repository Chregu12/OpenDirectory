DO $install026$ DECLARE routine RECORD;BEGIN
IF EXISTS(SELECT 1 FROM license_schema_versions WHERE version=26) THEN
 FOR routine IN SELECT definition FROM company_blueprint_assignment_receiver_manifest ORDER BY signature LOOP EXECUTE routine.definition;END LOOP;
 ALTER TABLE license_company_commands DROP CONSTRAINT license_company_commands_action_check;
 ALTER TABLE license_company_commands ADD CONSTRAINT license_company_commands_action_check CHECK(action IN('create','assign','revoke','update','blueprint_assign','blueprint_revoke','manual_assign','manual_revoke','retire_sources'));
 ALTER TABLE license_company_events DROP CONSTRAINT license_company_events_type_check;
 ALTER TABLE license_company_events ADD CONSTRAINT license_company_events_type_check CHECK(type IN('app.license.pool.created','app.license.assigned','app.license.released','app.license.pool.updated','app.license.source.assigned','app.license.source.released'));
 PERFORM company_blueprint_assignment_receiving(false);
ELSE EXECUTE $migration026$
DO $$ BEGIN PERFORM license_company_edit_receiving();PERFORM company_blueprint_receiving();END; $$;

ALTER TABLE license_assignment_sources DROP CONSTRAINT license_assignment_sources_source_type_check;
ALTER TABLE license_assignment_sources ADD CONSTRAINT license_assignment_sources_source_type_check CHECK(source_type IN('direct','group','blueprint'));
ALTER TABLE license_company_commands ADD COLUMN protocol INTEGER NOT NULL DEFAULT 1 CHECK(protocol IN(1,2));
ALTER TABLE license_company_commands ADD COLUMN parent_operation_id UUID;
ALTER TABLE license_company_commands DROP CONSTRAINT license_company_commands_transaction_id_key;
CREATE UNIQUE INDEX license_company_p1_transaction ON license_company_commands(transaction_id) WHERE protocol=1;
CREATE UNIQUE INDEX license_company_p2_transaction_pool ON license_company_commands(transaction_id,license_id) WHERE protocol=2;
CREATE UNIQUE INDEX license_company_p2_parent_pool ON license_company_commands(parent_operation_id,license_id) WHERE protocol=2;
ALTER TABLE license_company_commands ADD CONSTRAINT license_company_protocol_parent CHECK((protocol=1 AND parent_operation_id IS NULL) OR(protocol=2 AND parent_operation_id IS NOT NULL));

CREATE TABLE company_blueprint_user_assignments (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,user_id UUID NOT NULL,blueprint_id UUID NOT NULL,version INTEGER NOT NULL,
 eligibility_revision BIGINT NOT NULL CHECK(eligibility_revision>0),revision BIGINT NOT NULL CHECK(revision>0),status TEXT NOT NULL CHECK(status IN('active','removed')),
 created_by UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL,removed_at TIMESTAMPTZ,operation_id UUID NOT NULL,removal_operation_id UUID,
 FOREIGN KEY(blueprint_id,tenant_id) REFERENCES company_blueprints(id,tenant_id),FOREIGN KEY(blueprint_id,version) REFERENCES company_blueprint_versions(blueprint_id,version),
 CHECK((status='active' AND revision=1 AND removed_at IS NULL AND removal_operation_id IS NULL) OR(status='removed' AND revision=2 AND removed_at IS NOT NULL AND removal_operation_id IS NOT NULL))
);
CREATE UNIQUE INDEX company_blueprint_assignment_active ON company_blueprint_user_assignments(tenant_id,user_id,blueprint_id) WHERE status='active';
CREATE TABLE company_blueprint_assignment_operations (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,actor_user_id UUID NOT NULL,user_id UUID NOT NULL,action TEXT NOT NULL,assignment_id UUID,
 command JSONB NOT NULL,source JSONB,application_source JSONB,before_state JSONB,created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL UNIQUE
);
ALTER TABLE company_blueprint_user_assignments ADD CONSTRAINT company_blueprint_assignment_origin FOREIGN KEY(operation_id) REFERENCES company_blueprint_assignment_operations(id);
ALTER TABLE company_blueprint_user_assignments ADD CONSTRAINT company_blueprint_assignment_removal FOREIGN KEY(removal_operation_id) REFERENCES company_blueprint_assignment_operations(id);
ALTER TABLE license_company_commands ADD CONSTRAINT license_company_p2_parent FOREIGN KEY(parent_operation_id) REFERENCES company_blueprint_assignment_operations(id);
CREATE TABLE company_blueprint_assignment_events (
 id UUID PRIMARY KEY REFERENCES company_blueprint_assignment_operations(id),tenant_id UUID NOT NULL,actor_user_id UUID NOT NULL,user_id UUID NOT NULL,
 type TEXT NOT NULL,version INTEGER NOT NULL CHECK(version=1),correlation_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL,proof JSONB NOT NULL,result JSONB NOT NULL
);
CREATE TABLE company_blueprint_assignment_outbox (
 id UUID PRIMARY KEY REFERENCES company_blueprint_assignment_events(id),tenant_id UUID NOT NULL,status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE company_blueprint_assignment_receiver_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL,definer BOOLEAN NOT NULL,definition TEXT NOT NULL);

CREATE FUNCTION license_company_sources(pool_id UUID,canonical_user UUID) RETURNS JSONB LANGUAGE sql STABLE AS $$
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sourceType',source_type,'sourceId',source_id,'grantId',grant_id) ORDER BY source_type,source_id,grant_id),'[]'::jsonb)
 FROM license_assignment_sources WHERE license_id=pool_id AND user_id=canonical_user::text;
$$;
CREATE FUNCTION company_blueprint_assignment_view(binding company_blueprint_user_assignments) RETURNS JSONB LANGUAGE sql STABLE AS $$
 SELECT jsonb_build_object('id',binding.id,'tenantId',binding.tenant_id,'userId',binding.user_id,'blueprintId',binding.blueprint_id,'version',binding.version,
 'eligibilityRevision',binding.eligibility_revision::text,'revision',binding.revision::text,'status',binding.status,'actorUserId',binding.created_by,
 'operationId',binding.operation_id,'removalOperationId',binding.removal_operation_id,'createdAt',to_char(binding.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
 'removedAt',CASE WHEN binding.removed_at IS NULL THEN NULL ELSE to_char(binding.removed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
 'appPoolIds',(SELECT draft->'appPoolIds' FROM company_blueprint_versions WHERE blueprint_id=binding.blueprint_id AND version=binding.version));
$$;
CREATE FUNCTION company_blueprint_assignment_source_valid(source JSONB,live BOOLEAN DEFAULT true) RETURNS BOOLEAN LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE(license_company_exact(source,ARRAY['schemaVersion','companyBlueprintAssignmentsProtocol','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','target'])
 AND source->'companyBlueprintAssignmentsProtocol'='1'::jsonb AND source->'permissions'='["company.blueprints.assignments.read","company.blueprints.assign"]'::jsonb
 AND company_blueprint_source_valid((source-'companyBlueprintAssignmentsProtocol'-'target')||jsonb_build_object('companyBlueprintProtocol',1,'permissions','["company.blueprints.read","company.blueprints.manage","company.blueprints.publish"]'::jsonb),live)
 AND (source->'target'='null'::jsonb OR license_company_exact(source->'target',ARRAY['id','revision','eligibilityRevision','enabled','deleted'])
 AND license_company_uuid(source#>>'{target,id}') AND license_company_revision_valid(source#>'{target,eligibilityRevision}')
 AND jsonb_typeof(source#>'{target,enabled}')='boolean' AND jsonb_typeof(source#>'{target,deleted}')='boolean'
 AND CASE WHEN source#>'{target,deleted}'='true'::jsonb THEN source#>'{target,enabled}'='false'::jsonb AND source#>'{target,revision}'='null'::jsonb ELSE license_company_revision_valid(source#>'{target,revision}') END),false);
$$;
CREATE FUNCTION company_blueprint_assignment_command_valid(command JSONB) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE item JSONB;seen TEXT[]='{}';
BEGIN
 IF NOT license_company_exact(command,ARRAY['id','correlationId','action','assignmentId','expectedRevision','userId','eligibilityRevision','blueprintId','version','pools','reason','values'])
 OR NOT license_company_uuid(command->>'id') OR NOT license_company_uuid(command->>'correlationId') OR NOT license_company_uuid(command->>'userId')
 OR NOT license_company_revision_valid(command->'eligibilityRevision') OR NOT company_blueprint_text(command->'reason',10,500)
 OR command->>'action' NOT IN('assigned','removed','manual_assign','manual_revoke','retire_sources')
 OR jsonb_typeof(command->'pools') IS DISTINCT FROM 'array' OR jsonb_array_length(command->'pools')>(CASE WHEN command->>'action'='retire_sources' THEN 10000 ELSE 25 END) THEN RETURN false;END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(command->'pools') LOOP
  IF NOT license_company_exact(item,ARRAY['poolId','poolRevision']) OR NOT license_company_uuid(item->>'poolId') OR NOT license_company_revision_valid(item->'poolRevision') OR item->>'poolId'=ANY(seen) THEN RETURN false;END IF;
  seen=array_append(seen,item->>'poolId');
 END LOOP;
 IF command->>'action' IN('assigned','removed') THEN
  IF NOT license_company_uuid(command->>'assignmentId') OR command->'values' IS DISTINCT FROM 'null'::jsonb THEN RETURN false;END IF;
  IF command->>'action'='assigned' THEN RETURN command->'expectedRevision'='"0"'::jsonb AND license_company_uuid(command->>'blueprintId')
   AND jsonb_typeof(command->'version')='number' AND command->>'version' ~ '^[1-9][0-9]{0,9}$' AND (command->>'version')::numeric<=2147483647;END IF;
  RETURN license_company_revision_valid(command->'expectedRevision') AND command->'blueprintId'='null'::jsonb AND command->'version'='null'::jsonb;
 END IF;
 RETURN command->'assignmentId'='null'::jsonb AND command->'expectedRevision'='"0"'::jsonb AND command->'blueprintId'='null'::jsonb AND command->'version'='null'::jsonb AND jsonb_typeof(command->'values')='object';
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE FUNCTION company_blueprint_assignment_authority_valid(source JSONB,application_source JSONB,command JSONB,live BOOLEAN DEFAULT true) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
DECLARE target JSONB;proof JSONB;needs_source BOOLEAN;
BEGIN
 IF NOT company_blueprint_assignment_command_valid(command) THEN RETURN false;END IF;
 needs_source=command->>'action' IN('assigned','removed') OR command->>'action'='retire_sources' AND jsonb_array_length(command#>'{values,bindings}')>0;
 IF needs_source THEN
  IF NOT company_blueprint_assignment_source_valid(source,live) OR source#>>'{target,id}' IS DISTINCT FROM command->>'userId' THEN RETURN false;END IF;
 ELSIF source IS NOT NULL THEN RETURN false;END IF;
 IF jsonb_array_length(command->'pools')>0 THEN
  proof=jsonb_build_object('id',command->>'id','correlationId',command->>'correlationId','licenseId',COALESCE(command#>>'{pools,0,poolId}',command->>'id'),
   'action','revoke','expectedVersion','1','reason',command->>'reason','values',NULL,'assignmentId',command->>'id');
  IF NOT (CASE WHEN live THEN license_company_proof_valid(application_source,proof) ELSE license_company_proof_retained(application_source,proof) END)
   OR application_source#>>'{target,id}' IS DISTINCT FROM command->>'userId' THEN RETURN false;END IF;
  IF source IS NOT NULL AND (source-ARRAY['companyBlueprintAssignmentsProtocol','permissions','validUntil']) IS DISTINCT FROM (application_source-ARRAY['permissions','validUntil']) THEN RETURN false;END IF;
 ELSIF application_source IS NOT NULL THEN RETURN false;END IF;
 target=COALESCE(source,application_source)->'target';
 IF target->>'eligibilityRevision' IS DISTINCT FROM command->>'eligibilityRevision' THEN RETURN false;END IF;
 IF command->>'action' IN('assigned','manual_assign') AND (target->'enabled' IS DISTINCT FROM 'true'::jsonb OR target->'deleted' IS DISTINCT FROM 'false'::jsonb) THEN RETURN false;END IF;
 IF command->>'action'='retire_sources' AND target->'enabled' IS DISTINCT FROM 'false'::jsonb THEN RETURN false;END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE FUNCTION license_company_p2_guard(relation TEXT,operation TEXT,before_data JSONB,after_data JSONB) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent company_blueprint_assignment_operations;child license_company_commands;payload JSONB;pool_id UUID;target JSONB;expected_type TEXT;expected_id TEXT;
BEGIN
 parent=company_blueprint_assignment_parent();payload=COALESCE(after_data,before_data);target=COALESCE(parent.source,parent.application_source)->'target';
 IF EXISTS(SELECT 1 FROM company_blueprint_assignment_events WHERE id=parent.id) OR operation='TRUNCATE' THEN RAISE EXCEPTION 'Completed P2 operation cannot write' USING ERRCODE='42501';END IF;
 IF relation='license_company_commands' THEN
  IF operation<>'INSERT' OR payload->>'protocol'<>'2' OR payload->>'parent_operation_id'<>parent.id::text OR payload->>'transaction_id'<>txid_current()::text
   OR payload->>'id' IS DISTINCT FROM current_setting('opendirectory.license_company_p2_child',true) OR payload->>'tenant_id'<>parent.tenant_id::text
   OR payload->>'actor_user_id'<>parent.actor_user_id::text OR payload->>'target_user_id'<>parent.user_id::text OR payload->'source' IS DISTINCT FROM parent.application_source
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(parent.command->'pools') item WHERE item->>'poolId'=payload->>'license_id' AND item->>'poolRevision'=payload#>>'{command,expectedVersion}')
   OR payload->'before_state' IS DISTINCT FROM license_company_p2_state((payload->>'license_id')::uuid,parent.actor_user_id,parent.user_id)
   OR payload->>'valid_until' IS NULL OR (payload->>'valid_until')::timestamptz<>parent.valid_until
   OR payload->>'action' IS DISTINCT FROM (CASE parent.action WHEN 'assigned' THEN 'blueprint_assign' WHEN 'removed' THEN 'blueprint_revoke' ELSE parent.action END)
   OR payload->'command' IS DISTINCT FROM jsonb_build_object('id',payload->>'id','correlationId',parent.command->>'correlationId','licenseId',payload->>'license_id','action',payload->>'action',
    'expectedVersion',payload#>>'{command,expectedVersion}','reason',parent.command->>'reason','values',jsonb_build_object('parentId',parent.id),'assignmentId',parent.assignment_id)
   THEN RAISE EXCEPTION 'Exact canonical P2 pool command required' USING ERRCODE='42501';END IF;RETURN;
 END IF;
 child=license_company_p2_scope();
 IF relation IN('license_company_origins','license_company_events','license_company_outbox') THEN
  IF operation<>'INSERT' THEN RAISE EXCEPTION 'P2 license evidence is append only' USING ERRCODE='42501';END IF;
  IF relation='license_company_origins' AND (pg_trigger_depth()<2 OR payload->>'command_id'<>child.id::text OR payload->>'id'<>child.id::text) THEN RAISE EXCEPTION 'Actual P2 effects required' USING ERRCODE='42501';END IF;
  IF relation IN('license_company_events','license_company_outbox') AND payload->>'id'<>child.id::text THEN RAISE EXCEPTION 'Original P2 child receipt required' USING ERRCODE='42501';END IF;RETURN;
 END IF;
 IF EXISTS(SELECT 1 FROM license_company_events WHERE id=child.id) THEN RAISE EXCEPTION 'Completed P2 child cannot write' USING ERRCODE='42501';END IF;
 IF relation='license_subjects' THEN
  IF operation='DELETE' OR payload->>'user_id' NOT IN(parent.actor_user_id::text,parent.user_id::text) OR after_data->>'business_tenant_id'<>parent.tenant_id::text
   OR before_data->>'business_tenant_id' IS NOT NULL AND before_data->>'business_tenant_id'<>parent.tenant_id::text THEN RAISE EXCEPTION 'Own P2 subject required' USING ERRCODE='42501';END IF;
  IF operation='INSERT' THEN
   IF EXISTS(SELECT 1 FROM license_subjects WHERE user_id=payload->>'user_id') THEN RETURN;END IF;
   IF after_data->'disabled'<>'false'::jsonb OR after_data->>'directory_revision' IS NOT NULL OR NOT license_company_subject_unused(payload->>'user_id',true,parent.tenant_id) THEN RAISE EXCEPTION 'Empty original P2 subject required' USING ERRCODE='23514';END IF;
  ELSIF before_data->>'business_tenant_id' IS NULL THEN
   IF before_data-'business_tenant_id' IS DISTINCT FROM after_data-'business_tenant_id' OR before_data->'disabled'<>'false'::jsonb OR before_data->>'directory_revision' IS NOT NULL
    OR NOT license_company_subject_unused(payload->>'user_id',false,parent.tenant_id) THEN RAISE EXCEPTION 'Legacy subject requires controlled migration' USING ERRCODE='23514';END IF;
  ELSIF before_data IS DISTINCT FROM after_data THEN
   IF parent.action NOT IN('assigned','manual_assign') OR payload->>'user_id'<>parent.user_id::text
    OR before_data-ARRAY['directory_revision','directory_enabled','directory_deleted','directory_checked_at','directory_attempted_at','directory_error'] IS DISTINCT FROM after_data-ARRAY['directory_revision','directory_enabled','directory_deleted','directory_checked_at','directory_attempted_at','directory_error']
    OR after_data->>'directory_revision' IS DISTINCT FROM target->>'eligibilityRevision' OR after_data->'directory_enabled' IS DISTINCT FROM target->'enabled'
    OR after_data->'directory_deleted' IS DISTINCT FROM target->'deleted' OR after_data->>'directory_error' IS NOT NULL THEN RAISE EXCEPTION 'Exact original P2 eligibility required' USING ERRCODE='23514';END IF;
  END IF;RETURN;
 END IF;
 pool_id=license_company_parent(relation,payload);
 IF pool_id IS DISTINCT FROM child.license_id AND NOT(relation='license_audit_events' AND pool_id IS NULL) THEN RAISE EXCEPTION 'P2 write exceeds current child pool' USING ERRCODE='42501';END IF;
 IF relation='license_catalog' THEN
  IF operation<>'UPDATE' OR before_data-ARRAY['used_seats','updated_at','business_revision'] IS DISTINCT FROM after_data-ARRAY['used_seats','updated_at','business_revision']
   OR (after_data->>'used_seats')::integer<>(SELECT count(*) FROM license_assignments WHERE license_id=child.license_id)
   OR after_data->>'business_revision' IS DISTINCT FROM before_data->>'business_revision' AND (current_setting('opendirectory.license_company_finish',true)<>child.id::text OR (after_data->>'business_revision')::bigint<>(before_data->>'business_revision')::bigint+1)
   THEN RAISE EXCEPTION 'Exact P2 derived counter required' USING ERRCODE='23514';END IF;
 ELSIF relation='license_assignment_sources' THEN
  expected_type=CASE WHEN parent.action IN('assigned','removed') THEN 'blueprint' ELSE 'direct' END;expected_id=CASE WHEN expected_type='blueprint' THEN parent.assignment_id::text ELSE 'direct' END;
  IF operation='UPDATE' OR payload->>'user_id'<>parent.user_id::text OR payload->>'expires_at' IS NOT NULL
   OR parent.action<>'retire_sources' AND (payload->>'source_type'<>expected_type OR payload->>'source_id'<>expected_id)
   OR operation='INSERT' AND (parent.action NOT IN('assigned','manual_assign') OR payload->>'assigned_by'<>parent.actor_user_id::text)
   OR operation='DELETE' AND (parent.action NOT IN('removed','manual_revoke','retire_sources') OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(child.before_state->'sources') item WHERE item=jsonb_build_object('sourceType',payload->>'source_type','sourceId',payload->>'source_id','grantId',payload->>'grant_id')))
   THEN RAISE EXCEPTION 'Exact purpose-bound P2 source required' USING ERRCODE='23514';END IF;
 ELSIF relation='license_assignments' THEN
  IF payload->>'assignee_type'<>'user' OR payload->>'assignee_id'<>parent.user_id::text OR payload->>'expires_at' IS NOT NULL OR operation='UPDATE'
   OR operation='INSERT' AND (parent.action NOT IN('assigned','manual_assign') OR payload->>'eligibility_revision' IS DISTINCT FROM parent.command->>'eligibilityRevision' OR payload->>'assigned_by'<>parent.actor_user_id::text)
   OR operation='DELETE' AND (parent.action NOT IN('removed','manual_revoke','retire_sources') OR before_data IS DISTINCT FROM child.before_state->'assignment' OR EXISTS(SELECT 1 FROM license_assignment_sources WHERE license_id=child.license_id AND user_id=parent.user_id::text))
   THEN RAISE EXCEPTION 'Exact source-derived P2 projection required' USING ERRCODE='23514';END IF;
 ELSIF relation='license_grants' THEN
  IF operation<>'INSERT' OR pg_trigger_depth()<2 OR parent.action NOT IN('assigned','manual_assign') OR payload->>'kind'<>'direct' OR payload->>'recipient_id'<>parent.user_id::text
   OR payload->>'origin'<>'allocated' OR payload->>'eligibility_revision' IS DISTINCT FROM parent.command->>'eligibilityRevision' THEN RAISE EXCEPTION 'Server-derived P2 user grant required' USING ERRCODE='23514';END IF;
 ELSIF relation='license_grant_events' THEN
  IF operation<>'INSERT' OR pg_trigger_depth()<2 OR payload->>'expires_at' IS NOT NULL OR payload->>'changed_user_id' IS NOT NULL
   OR ROW(payload->>'actor_user_id',payload->>'actor_issuer',payload->>'actor_subject') IS DISTINCT FROM ROW(parent.actor_user_id::text,COALESCE(parent.source,parent.application_source)->>'issuer',COALESCE(parent.source,parent.application_source)->>'subject')
   OR parent.action IN('assigned','manual_assign') AND ROW(payload->>'version',payload->>'state',payload->>'event') IS DISTINCT FROM ROW('1','active','source-created')
   OR parent.action IN('removed','manual_revoke','retire_sources') AND (payload->>'state'<>'revoked' OR payload->>'event'<>'source-removed'
    OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(child.before_state->'grantEvents') previous WHERE previous->>'grant_id'=payload->>'grant_id' AND (previous->>'version')::bigint+1=(payload->>'version')::bigint AND previous->>'state'='active'))
   THEN RAISE EXCEPTION 'Actual P2 source transition required' USING ERRCODE='23514';END IF;
 ELSIF relation='license_audit_events' THEN
  IF operation<>'INSERT' OR ROW(payload->>'actor_issuer',payload->>'actor_subject') IS DISTINCT FROM ROW(COALESCE(parent.source,parent.application_source)->>'issuer',COALESCE(parent.source,parent.application_source)->>'subject')
   OR payload->>'action' NOT IN('company-source-change','company-sources-retired','directory-eligibility-changed') THEN RAISE EXCEPTION 'Original P2 allocator audit required' USING ERRCODE='23514';END IF;
  IF payload->>'action'='directory-eligibility-changed' AND (parent.action NOT IN('assigned','manual_assign') OR payload->>'actor'<>'system:user-eligibility'
   OR payload->'details' IS DISTINCT FROM jsonb_build_object('schemaVersion',1,'userId',parent.user_id,'revision',target->>'eligibilityRevision','enabled',target->'enabled','deleted',target->'deleted')) THEN RAISE EXCEPTION 'Exact P2 eligibility audit required' USING ERRCODE='23514';END IF;
  IF payload->>'action' IN('company-source-change','company-sources-retired') AND (payload->>'actor'<>parent.actor_user_id::text
   OR EXISTS(SELECT 1 FROM license_company_origins original_effect WHERE original_effect.command_id=child.id AND original_effect.relation='license_audit_events' AND original_effect.after_state->>'action' IN('company-source-change','company-sources-retired'))
   OR payload->'details' IS DISTINCT FROM CASE WHEN parent.action='retire_sources' THEN jsonb_build_object('userId',parent.user_id,'assignmentId',child.before_state#>'{assignment,id}','sources',child.before_state->'sources') ELSE license_company_p2_result(child.id) END)
   THEN RAISE EXCEPTION 'Exact single P2 source audit required' USING ERRCODE='23514';END IF;
 ELSE RAISE EXCEPTION 'P2 cannot mutate governed or external resources' USING ERRCODE='42501';END IF;
END; $$;
CREATE FUNCTION license_company_p2_result(child_id UUID) RETURNS JSONB LANGUAGE plpgsql STABLE AS $$
DECLARE child license_company_commands;state JSONB;retained UUID[];
BEGIN
 SELECT * INTO child FROM license_company_commands WHERE id=child_id AND protocol=2;
 SELECT COALESCE(array_agg((value->>'grantId')::uuid),'{}') INTO retained FROM jsonb_array_elements(child.before_state->'sources');
 state=license_company_p2_state(child.license_id,child.actor_user_id,child.target_user_id,retained);
 RETURN jsonb_build_object('poolId',child.license_id,'eventId',child.id,'beforeRevision',child.command->>'expectedVersion','afterRevision',((child.command->>'expectedVersion')::bigint+1)::text,
 'sourceAdded',jsonb_array_length(state->'sources')>jsonb_array_length(child.before_state->'sources'),'sourceRemoved',jsonb_array_length(state->'sources')<jsonb_array_length(child.before_state->'sources'),
 'seatAllocated',child.before_state->'assignment'='null'::jsonb AND state->'assignment'<>'null'::jsonb,'seatReleased',child.before_state->'assignment'<>'null'::jsonb AND state->'assignment'='null'::jsonb,
 'effectiveAssignmentRetained',child.before_state->'assignment'<>'null'::jsonb AND state->'assignment'<>'null'::jsonb);
END; $$;
CREATE FUNCTION license_company_p2_begin(parent_id UUID,pool_id UUID) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
#variable_conflict use_variable
DECLARE parent company_blueprint_assignment_operations;child license_company_commands;capture JSONB;
BEGIN
 parent=company_blueprint_assignment_parent();
 IF parent.id<>parent_id OR EXISTS(SELECT 1 FROM license_company_events WHERE id=NULLIF(current_setting('opendirectory.license_company_p2_child',true),'')::uuid) IS FALSE
  AND NULLIF(current_setting('opendirectory.license_company_p2_child',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Previous P2 child must finish first' USING ERRCODE='42501';END IF;
 SELECT value INTO capture FROM jsonb_array_elements(parent.command->'pools') WHERE value->>'poolId'=pool_id::text;
 IF capture IS NULL THEN RAISE EXCEPTION 'Pool outside original P2 manifest' USING ERRCODE='42501';END IF;
 child.id=gen_random_uuid();child.correlation_id=(parent.command->>'correlationId')::uuid;child.license_id=pool_id;child.tenant_id=parent.tenant_id;child.actor_user_id=parent.actor_user_id;child.target_user_id=parent.user_id;
 child.action=CASE parent.action WHEN 'assigned' THEN 'blueprint_assign' WHEN 'removed' THEN 'blueprint_revoke' ELSE parent.action END;
 child.source=parent.application_source;child.command=jsonb_build_object('id',child.id,'correlationId',child.correlation_id,'licenseId',pool_id,'action',child.action,'expectedVersion',capture->>'poolRevision',
 'reason',parent.command->>'reason','values',jsonb_build_object('parentId',parent.id),'assignmentId',parent.assignment_id);
 child.before_state=license_company_p2_state(pool_id,parent.actor_user_id,parent.user_id);child.created_at=clock_timestamp();child.valid_until=parent.valid_until;child.transaction_id=txid_current();child.protocol=2;child.parent_operation_id=parent.id;
 child.new_subject_ids=ARRAY(SELECT identifier FROM unnest(ARRAY[parent.actor_user_id::text,parent.user_id::text]) identifier WHERE NOT EXISTS(SELECT 1 FROM license_subjects WHERE user_id=identifier) ORDER BY identifier);
 PERFORM set_config('opendirectory.license_company_p2_child',child.id::text,true);INSERT INTO license_company_commands SELECT child.*;RETURN child.id;
END; $$;
CREATE FUNCTION license_company_p2_finish(child_id UUID) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent company_blueprint_assignment_operations;child license_company_commands;event license_company_events;state JSONB;retained UUID[];expected INTEGER;result JSONB;
BEGIN
 parent=company_blueprint_assignment_parent();child=license_company_p2_scope();
 IF child.id<>child_id OR EXISTS(SELECT 1 FROM license_company_events WHERE id=child.id) THEN RAISE EXCEPTION 'Original unfinished P2 child required' USING ERRCODE='42501';END IF;
 expected=CASE WHEN parent.action IN('assigned','manual_assign') THEN 1 WHEN parent.action='retire_sources' THEN jsonb_array_length(child.before_state->'sources') ELSE 1 END;
 IF (SELECT count(*) FROM license_company_origins WHERE command_id=child.id AND relation='license_assignment_sources' AND operation=CASE WHEN parent.action IN('assigned','manual_assign') THEN 'INSERT' ELSE 'DELETE' END)<>expected
 OR (SELECT count(*) FROM license_company_origins WHERE command_id=child.id AND relation='license_grant_events')<>expected
 OR (SELECT count(*) FROM license_company_origins WHERE command_id=child.id AND relation='license_grants')<>(CASE WHEN parent.action IN('assigned','manual_assign') THEN 1 ELSE 0 END)
 THEN RAISE EXCEPTION 'Complete actual P2 source and grant effects required' USING ERRCODE='23514';END IF;
 result=license_company_p2_result(child.id);
 IF (SELECT count(*) FROM license_company_origins WHERE command_id=child.id AND relation='license_audit_events'
  AND after_state->>'action'=CASE WHEN parent.action='retire_sources' THEN 'company-sources-retired' ELSE 'company-source-change' END
  AND after_state->'details'=CASE WHEN parent.action='retire_sources' THEN jsonb_build_object('userId',parent.user_id,'assignmentId',child.before_state#>'{assignment,id}','sources',child.before_state->'sources') ELSE result END
  AND after_state->>'actor'=parent.actor_user_id::text)<>1 THEN RAISE EXCEPTION 'Exact P2 allocator audit required' USING ERRCODE='23514';END IF;
 PERFORM set_config('opendirectory.license_company_finish',child.id::text,true);
 UPDATE license_catalog SET business_revision=business_revision+1,updated_at=clock_timestamp() WHERE id=child.license_id AND business_revision::text=child.command->>'expectedVersion';
 IF NOT FOUND THEN RAISE EXCEPTION 'Pool version changed' USING ERRCODE='40001';END IF;
 SELECT COALESCE(array_agg((value->>'grantId')::uuid),'{}') INTO retained FROM jsonb_array_elements(child.before_state->'sources');
 state=license_company_p2_state(child.license_id,child.actor_user_id,child.target_user_id,retained);
 event.id=child.id;event.tenant_id=child.tenant_id;event.license_id=child.license_id;event.type=CASE WHEN parent.action IN('assigned','manual_assign') THEN 'app.license.source.assigned' ELSE 'app.license.source.released' END;
 event.version=1;event.actor_user_id=child.actor_user_id;event.target_user_id=child.target_user_id;event.correlation_id=child.correlation_id;event.created_at=clock_timestamp();event.before_revision=(child.command->>'expectedVersion')::bigint;event.after_revision=event.before_revision+1;
 event.proof=jsonb_build_object('source',child.source,'command',child.command,'parentId',parent.id,'result',result);event.before_state=child.before_state;event.after_state=state;
 INSERT INTO license_company_events SELECT event.*;INSERT INTO license_company_outbox VALUES(event.id,event.tenant_id,'pending',event.created_at);RETURN event.id;
END; $$;
CREATE FUNCTION company_blueprint_assignment_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent company_blueprint_assignment_operations;expected JSONB;
BEGIN
 IF TG_TABLE_NAME='company_blueprint_assignment_receiver_manifest' OR TG_OP='TRUNCATE' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'P2 evidence is retained' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='company_blueprint_assignment_operations' THEN
  IF TG_OP<>'INSERT' OR NEW.id::text IS DISTINCT FROM current_setting('opendirectory.company_blueprint_assignment',true) OR NEW.transaction_id<>txid_current()
   OR NOT company_blueprint_assignment_authority_valid(NEW.source,NEW.application_source,NEW.command)
   OR ROW(NEW.id::text,NEW.action,NEW.assignment_id::text,NEW.user_id::text,NEW.tenant_id::text,NEW.actor_user_id::text)
    IS DISTINCT FROM ROW(NEW.command->>'id',NEW.command->>'action',NEW.command->>'assignmentId',NEW.command->>'userId',COALESCE(NEW.source,NEW.application_source)#>>'{tenant,id}',COALESCE(NEW.source,NEW.application_source)->>'actorUserId')
   OR ROW(NULLIF(current_setting('opendirectory.license_actor_user',true),''),NULLIF(current_setting('opendirectory.license_actor_issuer',true),''),NULLIF(current_setting('opendirectory.license_actor_subject',true),''))
    IS DISTINCT FROM ROW(NEW.actor_user_id::text,COALESCE(NEW.source,NEW.application_source)->>'issuer',COALESCE(NEW.source,NEW.application_source)->>'subject')
   OR NEW.valid_until IS DISTINCT FROM to_timestamp(LEAST((NEW.source->>'validUntil')::bigint,(NEW.application_source->>'validUntil')::bigint))
   OR NEW.created_at>=NEW.valid_until OR session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='license_catalog'::regclass)
   THEN RAISE EXCEPTION 'Original immutable P2 operation required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 parent=company_blueprint_assignment_parent();
 IF TG_TABLE_NAME<>'company_blueprint_assignment_outbox' AND EXISTS(SELECT 1 FROM company_blueprint_assignment_events WHERE id=parent.id) THEN RAISE EXCEPTION 'P2 operation already complete' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='company_blueprint_user_assignments' THEN
  IF TG_OP='INSERT' THEN
   IF parent.action<>'assigned' OR NEW.id<>parent.assignment_id OR NEW.tenant_id<>parent.tenant_id OR NEW.user_id<>parent.user_id OR NEW.blueprint_id::text<>parent.command->>'blueprintId'
    OR NEW.version<>(parent.command->>'version')::integer OR NEW.eligibility_revision::text<>parent.command->>'eligibilityRevision' OR NEW.status<>'active' OR NEW.revision<>1
    OR NEW.created_by<>parent.actor_user_id OR NEW.operation_id<>parent.id OR NEW.created_at<>parent.created_at THEN RAISE EXCEPTION 'Pinned original P2 assignment required' USING ERRCODE='23514';END IF;
  ELSE
   IF parent.action NOT IN('removed','retire_sources') OR OLD.tenant_id<>parent.tenant_id OR OLD.user_id<>parent.user_id OR OLD.status<>'active' OR NEW.status<>'removed' OR NEW.revision<>2 OR NEW.removal_operation_id<>parent.id OR NEW.removed_at IS NULL
    OR to_jsonb(OLD)-ARRAY['revision','status','removed_at','removal_operation_id'] IS DISTINCT FROM to_jsonb(NEW)-ARRAY['revision','status','removed_at','removal_operation_id']
    OR parent.action='removed' AND (OLD.id<>parent.assignment_id OR OLD.revision::text<>parent.command->>'expectedRevision')
    OR parent.action='retire_sources' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(parent.command#>'{values,bindings}') binding WHERE binding->>'id'=OLD.id::text AND binding->>'revision'=OLD.revision::text)
    OR EXISTS(SELECT 1 FROM license_assignment_sources WHERE source_type='blueprint' AND source_id=OLD.id::text) THEN RAISE EXCEPTION 'Complete original P2 binding retirement required' USING ERRCODE='23514';END IF;
  END IF;
 ELSE
  IF TG_OP<>'INSERT' OR NEW.id<>parent.id OR NEW.tenant_id<>parent.tenant_id THEN RAISE EXCEPTION 'P2 receipt is append only' USING ERRCODE='23514';END IF;
  IF TG_TABLE_NAME='company_blueprint_assignment_events' THEN
   IF NEW.actor_user_id<>parent.actor_user_id OR NEW.user_id<>parent.user_id OR NEW.type<>parent.action OR NEW.version<>1 OR NEW.correlation_id::text<>parent.command->>'correlationId'
    OR NEW.proof IS DISTINCT FROM jsonb_build_object('source',parent.source,'applicationSource',parent.application_source,'command',parent.command)
    THEN RAISE EXCEPTION 'Exact original P2 final event required' USING ERRCODE='23514';END IF;
  ELSIF NEW.status<>'pending' OR NOT EXISTS(SELECT 1 FROM company_blueprint_assignment_events WHERE id=NEW.id AND created_at=NEW.created_at) THEN RAISE EXCEPTION 'Exact P2 pending outbox required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE FUNCTION license_company_p2_event_valid(event license_company_events) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE child license_company_commands;parent company_blueprint_assignment_operations;effect license_company_origins;expected INTEGER;
BEGIN
 SELECT * INTO child FROM license_company_commands WHERE id=event.id AND protocol=2;SELECT * INTO parent FROM company_blueprint_assignment_operations WHERE id=child.parent_operation_id;
 IF child.id IS NULL OR parent.id IS NULL OR NOT company_blueprint_assignment_authority_valid(parent.source,parent.application_source,parent.command,false)
 OR child.transaction_id<>parent.transaction_id OR child.valid_until<>parent.valid_until OR child.created_at<parent.created_at OR event.created_at<child.created_at OR event.created_at>=parent.valid_until
 OR ROW(event.tenant_id,event.license_id,event.actor_user_id,event.target_user_id,event.correlation_id) IS DISTINCT FROM ROW(child.tenant_id,child.license_id,child.actor_user_id,child.target_user_id,child.correlation_id)
 OR event.before_state IS DISTINCT FROM child.before_state OR event.before_revision::text IS DISTINCT FROM child.command->>'expectedVersion' OR event.after_revision<>event.before_revision+1
 OR event.after_state#>>'{catalog,business_revision}'<>event.after_revision::text OR event.after_state#>>'{catalog,business_tenant_id}'<>parent.tenant_id::text
 OR event.proof IS DISTINCT FROM jsonb_build_object('source',child.source,'command',child.command,'parentId',parent.id,'result',event.proof->'result')
 OR NOT EXISTS(SELECT 1 FROM license_company_outbox WHERE id=child.id AND tenant_id=child.tenant_id AND status='pending' AND created_at=event.created_at)
 OR NOT EXISTS(SELECT 1 FROM company_blueprint_assignment_events WHERE id=parent.id)
 OR NOT EXISTS(SELECT 1 FROM license_company_origins WHERE command_id=child.id AND relation='license_catalog' AND operation='UPDATE' AND after_state=event.after_state->'catalog') THEN RETURN false;END IF;
 expected=CASE WHEN parent.action='retire_sources' THEN jsonb_array_length(event.before_state->'sources') ELSE 1 END;
 IF (SELECT count(*) FROM license_company_origins WHERE command_id=child.id AND relation='license_assignment_sources' AND operation=CASE WHEN parent.action IN('assigned','manual_assign') THEN 'INSERT' ELSE 'DELETE' END)<>expected
 OR (SELECT count(*) FROM license_company_origins WHERE command_id=child.id AND relation='license_grant_events' AND operation='INSERT')<>expected THEN RETURN false;END IF;
 FOR effect IN SELECT * FROM license_company_origins WHERE command_id=child.id AND relation IN('license_grants','license_grant_events','license_audit_events') LOOP
  IF effect.operation<>'INSERT' THEN RETURN false;END IF;
  IF effect.relation='license_grants' AND NOT EXISTS(SELECT 1 FROM license_grants WHERE license_company_row('license_grants',to_jsonb(license_grants))=effect.after_state) THEN RETURN false;END IF;
  IF effect.relation='license_grant_events' AND NOT EXISTS(SELECT 1 FROM license_grant_events WHERE license_company_row('license_grant_events',to_jsonb(license_grant_events))=effect.after_state) THEN RETURN false;END IF;
  IF effect.relation='license_audit_events' AND NOT EXISTS(SELECT 1 FROM license_audit_events WHERE to_jsonb(license_audit_events)=effect.after_state) THEN RETURN false;END IF;
 END LOOP;RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE FUNCTION license_company_p2_pool_valid(pool_id UUID) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE catalog license_catalog;latest license_company_events;
BEGIN
 SELECT * INTO catalog FROM license_catalog WHERE id=pool_id;
 IF catalog.id IS NULL OR catalog.business_tenant_id IS NULL OR NOT license_company_supported(pool_id) OR catalog.license_type<>'per_user' OR catalog.total_seats NOT BETWEEN 1 AND 10000
 OR catalog.used_seats<>(SELECT count(*) FROM license_assignments WHERE license_id=pool_id) OR catalog.used_seats>catalog.total_seats THEN RETURN false;END IF;
 SELECT * INTO latest FROM license_company_events WHERE license_id=pool_id ORDER BY after_revision DESC LIMIT 1;
 IF latest.id IS NULL OR latest.after_revision<>catalog.business_revision OR latest.after_state->'catalog' IS DISTINCT FROM license_company_row('license_catalog',to_jsonb(catalog))
 OR (SELECT count(*) FROM license_company_events WHERE license_id=pool_id)<>catalog.business_revision
 OR EXISTS(SELECT 1 FROM license_company_events event WHERE license_id=pool_id AND NOT license_company_event_valid(event))
 OR EXISTS(SELECT 1 FROM license_company_events event LEFT JOIN license_company_events previous ON previous.license_id=event.license_id AND previous.after_revision=event.before_revision
  WHERE event.license_id=pool_id AND event.before_revision IS NOT NULL AND (previous.id IS NULL OR previous.after_state->'catalog' IS DISTINCT FROM event.before_state->'catalog')) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM license_assignment_sources source LEFT JOIN license_grants grant_row ON grant_row.id=source.grant_id
 LEFT JOIN license_assignments assignment ON assignment.license_id=source.license_id AND assignment.assignee_type='user' AND assignment.assignee_id=source.user_id
 LEFT JOIN license_subjects subject ON subject.user_id=source.user_id
 LEFT JOIN LATERAL(SELECT * FROM license_grant_events WHERE grant_id=source.grant_id ORDER BY version DESC LIMIT 1) history ON true
 WHERE source.license_id=pool_id AND (source.source_type NOT IN('direct','blueprint') OR source.expires_at IS NOT NULL OR assignment.id IS NULL OR subject.business_tenant_id IS DISTINCT FROM catalog.business_tenant_id
 OR grant_row.kind IS DISTINCT FROM 'direct' OR grant_row.license_id IS DISTINCT FROM pool_id OR grant_row.recipient_id IS DISTINCT FROM source.user_id OR grant_row.origin IS DISTINCT FROM 'allocated'
 OR grant_row.eligibility_revision IS DISTINCT FROM assignment.eligibility_revision OR history.state IS DISTINCT FROM 'active'
 OR source.source_type='direct' AND source.source_id<>'direct'
 OR source.source_type='blueprint' AND NOT EXISTS(SELECT 1 FROM company_blueprint_user_assignments binding WHERE binding.id::text=source.source_id AND binding.tenant_id=catalog.business_tenant_id AND binding.user_id::text=source.user_id AND binding.status='active' AND binding.eligibility_revision=grant_row.eligibility_revision))) THEN RETURN false;END IF;
 RETURN NOT EXISTS(SELECT 1 FROM license_assignments assignment WHERE license_id=pool_id AND (assignee_type<>'user' OR expires_at IS NOT NULL
  OR NOT EXISTS(SELECT 1 FROM license_assignment_sources WHERE license_id=pool_id AND user_id=assignment.assignee_id)));
END; $$;
CREATE FUNCTION company_blueprint_assignment_finish(parent_id UUID) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
#variable_conflict use_variable
DECLARE parent company_blueprint_assignment_operations;binding company_blueprint_user_assignments;result JSONB;event company_blueprint_assignment_events;pools JSONB;
BEGIN
 SELECT * INTO parent FROM company_blueprint_assignment_operations WHERE id=parent_id;
 IF parent.transaction_id<>txid_current() THEN
  SELECT * INTO event FROM company_blueprint_assignment_events WHERE id=parent_id;
  IF event.id IS NULL THEN RAISE EXCEPTION 'Retained P2 final receipt unavailable' USING ERRCODE='23514';END IF;RETURN event.result||jsonb_build_object('outcome','already_applied');
 END IF;
 parent=company_blueprint_assignment_parent();IF parent.id<>parent_id OR EXISTS(SELECT 1 FROM company_blueprint_assignment_events WHERE id=parent.id) THEN RAISE EXCEPTION 'Unfinished P2 parent required' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM license_company_events pool_event JOIN license_company_commands child ON child.id=pool_event.id WHERE child.parent_operation_id=parent.id)<>jsonb_array_length(parent.command->'pools') THEN RAISE EXCEPTION 'Every original P2 child must finish' USING ERRCODE='23514';END IF;
 IF parent.action='removed' THEN
  UPDATE company_blueprint_user_assignments SET revision=2,status='removed',removed_at=clock_timestamp(),removal_operation_id=parent.id WHERE id=parent.assignment_id AND revision=1;
 ELSIF parent.action='retire_sources' THEN EXECUTE 'SELECT company_blueprint_assignment_retirement_finish($1)' USING parent.id;END IF;
 SELECT * INTO binding FROM company_blueprint_user_assignments WHERE id=parent.assignment_id;
 SELECT COALESCE(jsonb_agg(pool_event.proof->'result' ORDER BY pool_event.license_id),'[]'::jsonb) INTO pools FROM license_company_events pool_event JOIN license_company_commands child ON child.id=pool_event.id WHERE child.parent_operation_id=parent.id;
 result=jsonb_build_object('schemaVersion',1,'actorUserId',parent.actor_user_id,'tenantId',parent.tenant_id,'operationId',parent.id,'assignmentId',parent.assignment_id,'action',parent.action,
 'outcome','applied','revision',binding.revision::text,'deliveryStatus','pending','pools',pools);
 event.id=parent.id;event.tenant_id=parent.tenant_id;event.actor_user_id=parent.actor_user_id;event.user_id=parent.user_id;event.type=parent.action;event.version=1;event.correlation_id=(parent.command->>'correlationId')::uuid;
 event.created_at=clock_timestamp();event.proof=jsonb_build_object('source',parent.source,'applicationSource',parent.application_source,'command',parent.command);event.result=result;
 INSERT INTO company_blueprint_assignment_events SELECT event.*;INSERT INTO company_blueprint_assignment_outbox VALUES(event.id,event.tenant_id,'pending',event.created_at);RETURN result;
END; $$;
CREATE FUNCTION company_blueprint_assignment_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent company_blueprint_assignment_operations;event company_blueprint_assignment_events;child license_company_commands;binding company_blueprint_user_assignments;
BEGIN
 PERFORM company_blueprint_assignment_receiving();parent=company_blueprint_assignment_parent();SELECT * INTO event FROM company_blueprint_assignment_events WHERE id=parent.id;
 IF event.id IS NULL OR event.created_at>=parent.valid_until OR NOT EXISTS(SELECT 1 FROM company_blueprint_assignment_outbox WHERE id=event.id AND tenant_id=event.tenant_id AND created_at=event.created_at AND status='pending')
 OR (SELECT count(*) FROM license_company_commands WHERE parent_operation_id=parent.id)<>jsonb_array_length(parent.command->'pools') THEN RAISE EXCEPTION 'Complete atomic P2 final receipt required' USING ERRCODE='23514';END IF;
 FOR child IN SELECT * FROM license_company_commands WHERE parent_operation_id=parent.id LOOP
  IF NOT license_company_pool_valid(child.license_id) THEN RAISE EXCEPTION 'Canonical P2 pool evidence unavailable at commit' USING ERRCODE='23514';END IF;
 END LOOP;
 IF parent.action='assigned' THEN
  SELECT * INTO binding FROM company_blueprint_user_assignments WHERE id=parent.assignment_id;
  IF binding.status<>'active' OR (SELECT count(*) FROM license_assignment_sources WHERE source_type='blueprint' AND source_id=binding.id::text)<>jsonb_array_length(parent.command->'pools') THEN RAISE EXCEPTION 'Complete original blueprint grants required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;
DO $$
DECLARE definition TEXT;receiver TEXT;original TEXT;digest TEXT;relation TEXT;
BEGIN
 definition=pg_get_functiondef('license_company_event_valid(license_company_events)'::regprocedure);
 EXECUTE replace(definition,'FUNCTION '||quote_ident(current_schema())||'.license_company_event_valid(','FUNCTION '||quote_ident(current_schema())||'.license_company_event_valid_v1(');
 definition=pg_get_functiondef('license_company_pool_valid(uuid)'::regprocedure);
 EXECUTE replace(definition,'FUNCTION '||quote_ident(current_schema())||'.license_company_pool_valid(','FUNCTION '||quote_ident(current_schema())||'.license_company_pool_valid_v1(');
 definition=pg_get_functiondef('license_company_guard()'::regprocedure);
 EXECUTE regexp_replace(definition,E'\nBEGIN\n',E'\nBEGIN\n IF NULLIF(current_setting(''opendirectory.company_blueprint_assignment'',true),'''') IS NOT NULL THEN\n  IF TG_OP=''TRUNCATE'' THEN RAISE EXCEPTION ''P2 evidence cannot be truncated'' USING ERRCODE=''42501'';END IF;\n  PERFORM license_company_p2_guard(TG_TABLE_NAME,TG_OP,CASE WHEN TG_OP=''INSERT'' THEN NULL ELSE license_company_row(TG_TABLE_NAME,to_jsonb(OLD)) END,CASE WHEN TG_OP=''DELETE'' THEN NULL ELSE license_company_row(TG_TABLE_NAME,to_jsonb(NEW)) END);\n  IF TG_OP=''DELETE'' THEN RETURN OLD;ELSE RETURN NEW;END IF;\n END IF;\n IF TG_TABLE_NAME=''license_company_commands'' AND TG_OP=''INSERT'' THEN\n  IF NEW.protocol<>1 OR NEW.parent_operation_id IS NOT NULL THEN RAISE EXCEPTION ''P1 command cannot impersonate P2'' USING ERRCODE=''42501'';END IF;\n END IF;\n');
 definition=pg_get_functiondef('license_company_observe()'::regprocedure);
 EXECUTE regexp_replace(definition,E'\nBEGIN\n',E'\nBEGIN\n IF NULLIF(current_setting(''opendirectory.company_blueprint_assignment'',true),'''') IS NOT NULL THEN\n  receipt=license_company_p2_scope();\n  INSERT INTO license_company_origins(id,command_id,relation,operation,before_state,after_state) VALUES(receipt.id,receipt.id,TG_TABLE_NAME,TG_OP,CASE WHEN TG_OP=''INSERT'' THEN NULL ELSE license_company_row(TG_TABLE_NAME,to_jsonb(OLD)) END,CASE WHEN TG_OP=''DELETE'' THEN NULL ELSE license_company_row(TG_TABLE_NAME,to_jsonb(NEW)) END);RETURN NULL;\n END IF;\n');
 definition=pg_get_functiondef('license_company_scope()'::regprocedure);
 EXECUTE regexp_replace(definition,E'\nBEGIN\n',E'\nBEGIN\n IF NULLIF(current_setting(''opendirectory.company_blueprint_assignment'',true),'''') IS NOT NULL THEN RETURN license_company_p2_scope();END IF;\n');
 definition=pg_get_functiondef('license_company_begin(jsonb,jsonb)'::regprocedure);
 EXECUTE regexp_replace(definition,E'\nBEGIN\n',E'\nBEGIN\n receipt.protocol=1;receipt.parent_operation_id=NULL;\n IF EXISTS(SELECT 1 FROM company_blueprint_assignment_operations WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION ''P1 cannot enter P2 operations'' USING ERRCODE=''42501'';END IF;\n IF command->>''action'' IN(''assign'',''revoke'') AND EXISTS(SELECT 1 FROM license_assignment_sources WHERE license_id=(command->>''licenseId'')::uuid AND source_type=''blueprint'') THEN RAISE EXCEPTION ''upgrade_required'' USING ERRCODE=''23514'';END IF;\n IF command->>''action'' IN(''assign'',''revoke'') THEN PERFORM company_blueprint_subject_locks(source);END IF;\n');
 definition=pg_get_functiondef('license_company_commit()'::regprocedure);
 EXECUTE regexp_replace(definition,E'\nBEGIN\n',E'\nBEGIN\n IF NEW.protocol=2 THEN RETURN company_blueprint_assignment_commit_dispatch(NEW);END IF;\n');
 definition=pg_get_functiondef('license_source_grant_before()'::regprocedure);
 original=E'  IF NEW.source_type=''group'' THEN';
 receiver=E'  IF NEW.source_type=''blueprint'' THEN\n    IF TG_OP<>''INSERT'' OR NEW.expires_at IS NOT NULL OR NOT license_company_uuid(NEW.source_id) OR NOT EXISTS(SELECT 1 FROM company_blueprint_user_assignments binding CROSS JOIN LATERAL company_blueprint_assignment_parent() p2_parent WHERE binding.id::text=NEW.source_id AND binding.status=''active'' AND binding.tenant_id=p2_parent.tenant_id AND binding.user_id::text=NEW.user_id AND binding.id=p2_parent.assignment_id AND p2_parent.action=''assigned'' AND (license_company_p2_scope()).license_id=NEW.license_id) THEN RAISE EXCEPTION ''Current purpose-bound blueprint user source required'' USING ERRCODE=''23514'';END IF;\n    NEW.grant_id=gen_random_uuid();RETURN NEW;\n  END IF;\n'||original;
 IF strpos(definition,original)=0 THEN RAISE EXCEPTION 'Original source guard not found';END IF;EXECUTE replace(definition,original,receiver);
 definition=pg_get_functiondef('license_source_grant_after()'::regprocedure);
 EXECUTE replace(definition,'IF source.source_type=''direct'' THEN','IF source.source_type IN(''direct'',''blueprint'') THEN');
 definition=pg_get_functiondef('license_scope_business_guard()'::regprocedure);
 EXECUTE replace(definition,'ELSIF payload->>''source_type''=''direct'' THEN',E'ELSIF payload->>''source_type'' IN(''direct'',''blueprint'') THEN\n  IF payload->>''source_type''=''blueprint'' THEN PERFORM company_blueprint_assignment_parent();END IF;');
 definition=pg_get_functiondef('license_company_supported(uuid)'::regprocedure);
 EXECUTE replace(definition,'source_type<>''direct'' OR source_id<>''direct'' OR expires_at IS NOT NULL','source_type NOT IN(''direct'',''blueprint'') OR source_type=''direct'' AND source_id<>''direct'' OR source_type=''blueprint'' AND NOT license_company_uuid(source_id) OR expires_at IS NOT NULL');
 definition=pg_get_functiondef('company_blueprint_change(jsonb,jsonb,jsonb)'::regprocedure);
 original='FOR application IN SELECT value FROM jsonb_array_elements(document->''appPoolIds'') LOOP';
 IF strpos(definition,original)=0 THEN RAISE EXCEPTION 'Original blueprint app lock loop unavailable';END IF;
 EXECUTE replace(definition,original,'PERFORM 1 FROM license_catalog WHERE id IN(SELECT (value#>>''{}'')::uuid FROM jsonb_array_elements(document->''appPoolIds'')) ORDER BY id FOR SHARE; '||original);
 SELECT md5(prosrc) INTO digest FROM pg_proc WHERE oid='company_blueprint_change(jsonb,jsonb,jsonb)'::regprocedure;
 definition=pg_get_functiondef('company_blueprint_receiving()'::regprocedure);
 EXECUTE replace(definition,'0cb8e9e33afcfb1e45bdd61029de8627',digest);
END; $$;

CREATE OR REPLACE FUNCTION license_company_event_valid(event license_company_events) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM license_company_commands WHERE id=event.id AND protocol=2) THEN RETURN license_company_p2_event_valid(event);END IF;
 RETURN license_company_event_valid_v1(event);
END; $$;
CREATE OR REPLACE FUNCTION license_company_pool_valid(pool_id UUID) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM license_company_commands WHERE license_id=pool_id AND protocol=2) THEN RETURN license_company_p2_pool_valid(pool_id);END IF;
 RETURN license_company_pool_valid_v1(pool_id);
END; $$;
CREATE OR REPLACE FUNCTION license_company_edit_receiving() RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN PERFORM company_blueprint_assignment_receiving(false);END; $$;
CREATE FUNCTION company_blueprint_assignment_commit_dispatch(child license_company_commands) RETURNS license_company_commands LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent company_blueprint_assignment_operations;event company_blueprint_assignment_events;
BEGIN
 parent=company_blueprint_assignment_parent();SELECT * INTO event FROM company_blueprint_assignment_events WHERE id=parent.id;
 IF child.parent_operation_id<>parent.id OR event.id IS NULL OR NOT license_company_pool_valid(child.license_id) THEN RAISE EXCEPTION 'P2 child final receipt required' USING ERRCODE='23514';END IF;RETURN child;
END; $$;

ALTER TABLE license_company_commands DROP CONSTRAINT license_company_commands_action_check;
ALTER TABLE license_company_commands ADD CONSTRAINT license_company_commands_action_check CHECK(action IN('create','assign','revoke','update','blueprint_assign','blueprint_revoke','manual_assign','manual_revoke','retire_sources'));
ALTER TABLE license_company_events DROP CONSTRAINT license_company_events_type_check;
ALTER TABLE license_company_events ADD CONSTRAINT license_company_events_type_check CHECK(type IN('app.license.pool.created','app.license.assigned','app.license.released','app.license.pool.updated','app.license.source.assigned','app.license.source.released'));
CREATE FUNCTION company_blueprint_assignment_install() RETURNS VOID LANGUAGE plpgsql AS $$ DECLARE relation TEXT;routine RECORD;BEGIN
 INSERT INTO license_schema_versions(version) VALUES(26);
 FOR routine IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND (proname LIKE 'company_blueprint_assignment_%' OR proname LIKE 'license_company_p2_%' OR proname IN('license_company_sources','company_blueprint_subject_locks','license_company_event_valid_v1','license_company_pool_valid_v1')) LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine.signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine.signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
 END LOOP;
 INSERT INTO company_blueprint_assignment_receiver_manifest SELECT oid::regprocedure::text,md5(prosrc),prosecdef,pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND
 (proname LIKE 'company_blueprint_assignment_%' OR proname LIKE 'license_company_%' OR proname IN('company_blueprint_subject_locks','license_source_grant_before','license_source_grant_after','license_scope_business_guard','company_blueprint_change','company_blueprint_receiving')) AND proname<>'company_blueprint_assignment_install';
 FOREACH relation IN ARRAY ARRAY['company_blueprint_user_assignments','company_blueprint_assignment_operations','company_blueprint_assignment_events','company_blueprint_assignment_outbox','company_blueprint_assignment_receiver_manifest'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION company_blueprint_assignment_guard()',relation||'_guard',relation);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION company_blueprint_assignment_guard()',relation||'_truncate',relation);
  EXECUTE format('REVOKE ALL ON %I FROM PUBLIC',relation);
 END LOOP;
 CREATE CONSTRAINT TRIGGER company_blueprint_assignment_commit AFTER INSERT ON company_blueprint_assignment_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_blueprint_assignment_commit();
 CREATE TRIGGER company_blueprint_assignment_admit AFTER INSERT ON company_blueprint_assignment_operations FOR EACH ROW EXECUTE FUNCTION company_blueprint_assignment_admit();
END; $$;
CREATE FUNCTION company_blueprint_subject_locks(source JSONB) RETURNS VOID LANGUAGE plpgsql VOLATILE AS $$
DECLARE identifier TEXT;
BEGIN
 FOR identifier IN SELECT DISTINCT value FROM unnest(ARRAY[source->>'actorUserId',source#>>'{target,id}']) value WHERE value IS NOT NULL ORDER BY value LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended('company-license-subject:'||identifier,19770026));
  PERFORM 1 FROM license_subjects WHERE user_id=identifier FOR UPDATE;
 END LOOP;
END; $$;
CREATE FUNCTION company_blueprint_assignment_live_sources(source JSONB,application_source JSONB,command JSONB) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
DECLARE probe JSONB;
BEGIN
 IF command->>'action'='retire_sources' THEN RETURN company_blueprint_assignment_authority_valid(source,application_source,command);END IF;
 probe=command||jsonb_build_object('action',CASE WHEN source IS NULL THEN 'manual_revoke' ELSE 'removed' END,
 'assignmentId',CASE WHEN source IS NULL THEN NULL ELSE command->>'id' END,'expectedRevision',CASE WHEN source IS NULL THEN '0' ELSE '1' END,
 'blueprintId',NULL,'version',NULL,'values',CASE WHEN source IS NULL THEN '{}'::jsonb ELSE 'null'::jsonb END,
 'eligibilityRevision',COALESCE(source,application_source)#>>'{target,eligibilityRevision}');
 RETURN company_blueprint_assignment_authority_valid(source,application_source,probe);
END; $$;
CREATE FUNCTION license_company_p2_state(pool_id UUID,actor_id UUID,target_id UUID,retained UUID[] DEFAULT '{}') RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT (license_company_state(pool_id,actor_id,target_id)-ARRAY['source','grant','grantEvent'])||jsonb_build_object('sources',license_company_sources(pool_id,target_id),
 'grants',COALESCE((SELECT jsonb_agg(license_company_row('license_grants',to_jsonb(grants)) ORDER BY grants.id) FROM license_grants grants WHERE grants.id=ANY(retained)
 OR grants.id IN(SELECT grant_id FROM license_assignment_sources WHERE license_id=pool_id AND user_id=target_id::text)),'[]'::jsonb),
 'grantEvents',COALESCE((SELECT jsonb_agg(license_company_row('license_grant_events',to_jsonb(history)) ORDER BY history.grant_id) FROM license_grants grants
 CROSS JOIN LATERAL(SELECT * FROM license_grant_events WHERE grant_id=grants.id ORDER BY version DESC LIMIT 1) history
 WHERE grants.id=ANY(retained) OR grants.id IN(SELECT grant_id FROM license_assignment_sources WHERE license_id=pool_id AND user_id=target_id::text)),'[]'::jsonb));
$$;
CREATE FUNCTION company_blueprint_assignment_parent() RETURNS company_blueprint_assignment_operations LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt company_blueprint_assignment_operations;
BEGIN
 SELECT * INTO receipt FROM company_blueprint_assignment_operations WHERE id=NULLIF(current_setting('opendirectory.company_blueprint_assignment',true),'')::uuid AND transaction_id=txid_current();
 IF receipt.id IS NULL OR receipt.valid_until<=clock_timestamp() OR NOT company_blueprint_assignment_authority_valid(receipt.source,receipt.application_source,receipt.command)
 OR current_setting('role',true) NOT IN('none','') OR current_setting('session_replication_role')<>'origin'
 OR session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='license_catalog'::regclass)
 OR NOT license_company_control_clean() OR EXISTS(SELECT 1 FROM license_company_commands WHERE transaction_id=txid_current() AND protocol=1)
 THEN RAISE EXCEPTION 'Original purpose-bound P2 parent required' USING ERRCODE='42501';END IF;RETURN receipt;
END; $$;
CREATE FUNCTION license_company_p2_scope() RETURNS license_company_commands LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent company_blueprint_assignment_operations;child license_company_commands;
BEGIN
 parent=company_blueprint_assignment_parent();
 SELECT * INTO child FROM license_company_commands WHERE id=NULLIF(current_setting('opendirectory.license_company_p2_child',true),'')::uuid AND protocol=2 AND parent_operation_id=parent.id AND transaction_id=txid_current();
 IF child.id IS NULL OR child.valid_until<>parent.valid_until OR child.tenant_id<>parent.tenant_id OR child.actor_user_id<>parent.actor_user_id OR child.target_user_id<>parent.user_id
 THEN RAISE EXCEPTION 'Original P2 pool child required' USING ERRCODE='42501';END IF;RETURN child;
END; $$;
CREATE FUNCTION company_blueprint_assignment_receiving(require_lifecycle BOOLEAN DEFAULT true) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE specification RECORD;relation TEXT;
BEGIN
 PERFORM company_blueprint_receiving();PERFORM license_company_receiving();
 IF NOT EXISTS(SELECT 1 FROM license_schema_versions WHERE version=24) OR NOT EXISTS(SELECT 1 FROM license_schema_versions WHERE version=26)
 OR current_setting('session_replication_role')<>'origin' THEN RAISE EXCEPTION 'Company pool edit migration 024 and P2 migration required' USING ERRCODE='42501';END IF;
 FOR specification IN SELECT * FROM company_blueprint_assignment_receiver_manifest LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid=to_regprocedure(specification.signature) AND md5(prosrc)=specification.digest AND prosecdef=specification.definer
   AND proowner=(SELECT relowner FROM pg_class WHERE oid='license_catalog'::regclass)) THEN RAISE EXCEPTION 'P2 receiver changed: %',specification.signature USING ERRCODE='42501';END IF;
 END LOOP;
 IF (SELECT count(*) FROM company_blueprint_assignment_receiver_manifest)<20 THEN RAISE EXCEPTION 'Complete P2 receiver manifest required' USING ERRCODE='42501';END IF;
 FOR specification IN SELECT * FROM(VALUES
  ('license_company_commands','license_company_commands_action_check','CHECK ((action = ANY (ARRAY[''create''::text, ''assign''::text, ''revoke''::text, ''update''::text, ''blueprint_assign''::text, ''blueprint_revoke''::text, ''manual_assign''::text, ''manual_revoke''::text, ''retire_sources''::text])))'),
  ('license_company_events','license_company_events_type_check','CHECK ((type = ANY (ARRAY[''app.license.pool.created''::text, ''app.license.assigned''::text, ''app.license.released''::text, ''app.license.pool.updated''::text, ''app.license.source.assigned''::text, ''app.license.source.released''::text])))'),
  ('license_catalog','license_company_edit_stock','CHECK (((business_tenant_id IS NULL) OR ((total_seats >= 1) AND (total_seats <= 10000) AND (used_seats >= 0) AND (used_seats <= total_seats))))')
 ) constraints(relation,name,definition) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass(specification.relation) AND conname=specification.name AND contype='c' AND convalidated AND pg_get_constraintdef(oid)=specification.definition)
  THEN RAISE EXCEPTION 'P2/Company edit constraint unavailable: %',specification.name USING ERRCODE='42501';END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['company_blueprint_user_assignments','company_blueprint_assignment_operations','company_blueprint_assignment_events','company_blueprint_assignment_outbox','company_blueprint_assignment_receiver_manifest'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=to_regclass(relation) AND relkind='r' AND relowner=(SELECT relowner FROM pg_class WHERE oid='license_catalog'::regclass))
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname=relation||'_guard' AND tgenabled='O' AND tgtype=31 AND tgqual IS NULL AND tgfoid='company_blueprint_assignment_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname=relation||'_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='company_blueprint_assignment_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'P2 metadata guard unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='company_blueprint_assignment_operations'::regclass AND tgname='company_blueprint_assignment_commit' AND tgenabled='O' AND tgtype=5 AND tgqual IS NULL AND tgnargs=0 AND tgdeferrable AND tginitdeferred AND tgfoid='company_blueprint_assignment_commit()'::regprocedure)
 THEN RAISE EXCEPTION 'P2 deferred commit guard unavailable' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='company_blueprint_assignment_operations'::regclass AND tgname='company_blueprint_assignment_admit' AND tgenabled='O' AND tgtype=5 AND tgqual IS NULL AND tgnargs=0 AND tgfoid='company_blueprint_assignment_admit()'::regprocedure)
 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid=to_regclass('license_company_p1_transaction') AND indisunique AND indisvalid AND pg_get_expr(indpred,indrelid)='(protocol = 1)')
 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid=to_regclass('license_company_p2_transaction_pool') AND indisunique AND indisvalid AND pg_get_expr(indpred,indrelid)='(protocol = 2)')
 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid=to_regclass('license_company_p2_parent_pool') AND indisunique AND indisvalid AND pg_get_expr(indpred,indrelid)='(protocol = 2)')
 THEN RAISE EXCEPTION 'P2 admission or protocol cardinality receiver unavailable' USING ERRCODE='42501';END IF;
 IF require_lifecycle THEN
  IF to_regprocedure('company_blueprint_assignment_retirement_receiving()') IS NULL THEN RAISE EXCEPTION 'P2 negative lifecycle migration 027 required' USING ERRCODE='42501';END IF;
  EXECUTE 'SELECT company_blueprint_assignment_retirement_receiving()';
 END IF;
END; $$;
CREATE FUNCTION company_blueprint_assignment_begin(source JSONB,application_source JSONB,command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
#variable_conflict use_variable
DECLARE receipt company_blueprint_assignment_operations;prior company_blueprint_assignment_operations;binding company_blueprint_user_assignments;release company_blueprint_versions;catalog license_catalog;item JSONB;actual JSONB;authority JSONB;
BEGIN
 PERFORM company_blueprint_assignment_receiving();
 IF NOT company_blueprint_assignment_command_valid(command) OR NOT company_blueprint_assignment_live_sources(source,application_source,command) OR NULLIF(current_setting('opendirectory.company_blueprint_assignment',true),'') IS NOT NULL
 OR NULLIF(current_setting('opendirectory.license_company',true),'') IS NOT NULL OR NOT license_company_control_clean()
 OR EXISTS(SELECT 1 FROM license_company_commands WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION 'Independent P2 authority required' USING ERRCODE='42501';END IF;
 authority=COALESCE(source,application_source);PERFORM pg_advisory_xact_lock(hashtextextended(command->>'id',0));
 SELECT * INTO prior FROM company_blueprint_assignment_operations WHERE id=(command->>'id')::uuid;
 IF prior.id IS NOT NULL THEN
  IF prior.tenant_id::text IS DISTINCT FROM authority#>>'{tenant,id}' OR prior.actor_user_id::text IS DISTINCT FROM authority->>'actorUserId'
   OR COALESCE(prior.source,prior.application_source)->>'issuer' IS DISTINCT FROM authority->>'issuer' OR COALESCE(prior.source,prior.application_source)->>'subject' IS DISTINCT FROM authority->>'subject'
   OR prior.command-'correlationId' IS DISTINCT FROM command-'correlationId' THEN RAISE EXCEPTION 'P2 operation intent mismatch' USING ERRCODE='23505';END IF;
  RETURN prior.id;
 END IF;
 IF NOT company_blueprint_assignment_authority_valid(source,application_source,command) THEN RAISE EXCEPTION 'Original employee eligibility changed' USING ERRCODE='40001';END IF;
 PERFORM company_blueprint_subject_locks(authority);
 IF command->>'action' IN('assigned','removed') THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('company-blueprint-user:'||(authority#>>'{tenant,id}')||':'||(command->>'userId'),19770026));
  SELECT * INTO binding FROM company_blueprint_user_assignments WHERE id=(command->>'assignmentId')::uuid FOR UPDATE;
  IF command->>'action'='assigned' THEN
   IF binding.id IS NOT NULL THEN RAISE EXCEPTION 'Assignment incarnation already exists' USING ERRCODE='23505';END IF;
   IF EXISTS(SELECT 1 FROM company_blueprint_user_assignments WHERE tenant_id=(authority#>>'{tenant,id}')::uuid AND user_id=(command->>'userId')::uuid AND status='active' AND eligibility_revision::text IS DISTINCT FROM command->>'eligibilityRevision') THEN RAISE EXCEPTION 'Original binding generation requires explicit cleanup' USING ERRCODE='23514';END IF;
   SELECT * INTO release FROM company_blueprint_versions WHERE blueprint_id=(command->>'blueprintId')::uuid AND tenant_id=(authority#>>'{tenant,id}')::uuid AND version=(command->>'version')::integer;
  ELSE
   IF binding.id IS NULL OR binding.tenant_id::text IS DISTINCT FROM authority#>>'{tenant,id}' OR binding.user_id::text IS DISTINCT FROM command->>'userId' THEN RAISE EXCEPTION 'Own assignment not found' USING ERRCODE='P0002';END IF;
   IF binding.revision::text IS DISTINCT FROM command->>'expectedRevision' OR binding.status<>'active' THEN RAISE EXCEPTION 'Assignment changed' USING ERRCODE='40001';END IF;
   SELECT * INTO release FROM company_blueprint_versions WHERE blueprint_id=binding.blueprint_id AND version=binding.version;
  END IF;
  IF release.operation_id IS NULL THEN RAISE EXCEPTION 'Own immutable release not found' USING ERRCODE='P0002';END IF;
  IF (SELECT COALESCE(jsonb_agg(value ORDER BY value),'[]'::jsonb) FROM jsonb_array_elements(release.draft->'appPoolIds')) IS DISTINCT FROM
   (SELECT COALESCE(jsonb_agg(value->'poolId' ORDER BY value->'poolId'),'[]'::jsonb) FROM jsonb_array_elements(command->'pools')) THEN RAISE EXCEPTION 'Exact immutable app pool captures required' USING ERRCODE='23514';END IF;
 END IF;
 FOR catalog IN SELECT * FROM license_catalog WHERE id IN(SELECT (value->>'poolId')::uuid FROM jsonb_array_elements(command->'pools')) ORDER BY id FOR UPDATE LOOP
  SELECT value INTO item FROM jsonb_array_elements(command->'pools') WHERE value->>'poolId'=catalog.id::text;
  IF catalog.business_tenant_id::text IS DISTINCT FROM authority#>>'{tenant,id}' THEN RAISE EXCEPTION 'Own app pool required' USING ERRCODE='P0002';END IF;
  IF catalog.business_revision::text IS DISTINCT FROM item->>'poolRevision' THEN RAISE EXCEPTION 'App pool version changed' USING ERRCODE='40001';END IF;
  IF NOT license_company_pool_valid(catalog.id) OR NOT license_company_supported(catalog.id) OR catalog.business_revision=9223372036854775807 THEN RAISE EXCEPTION 'Supported canonical app pool required' USING ERRCODE='23514';END IF;
 END LOOP;
 IF (SELECT count(*) FROM license_catalog WHERE id IN(SELECT (value->>'poolId')::uuid FROM jsonb_array_elements(command->'pools')))<>jsonb_array_length(command->'pools') THEN RAISE EXCEPTION 'Own app pool not found' USING ERRCODE='P0002';END IF;
 IF command->>'action' IN('manual_assign','manual_revoke') THEN
  IF jsonb_array_length(command->'pools')<>1 OR NOT license_company_exact(command->'values',ARRAY['projectionId','grantId','sources']) THEN RAISE EXCEPTION 'Exact manual source capture required' USING ERRCODE='23514';END IF;
  actual=license_company_sources((command#>>'{pools,0,poolId}')::uuid,(command->>'userId')::uuid);
  IF actual IS DISTINCT FROM command#>'{values,sources}' THEN RAISE EXCEPTION 'Manual source capture changed' USING ERRCODE='40001';END IF;
  IF command->>'action'='manual_assign' AND (command#>'{values,grantId}'<>'null'::jsonb OR EXISTS(SELECT 1 FROM jsonb_array_elements(actual) original_source WHERE original_source.value->>'sourceType'='direct')) THEN RAISE EXCEPTION 'Manual source already exists' USING ERRCODE='23514';END IF;
  IF command->>'action'='manual_revoke' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(actual) original_source WHERE original_source.value->>'sourceType'='direct' AND original_source.value->>'grantId'=command#>>'{values,grantId}') THEN RAISE EXCEPTION 'Original manual grant required' USING ERRCODE='23514';END IF;
  IF command#>'{values,projectionId}' IS DISTINCT FROM COALESCE((SELECT to_jsonb(id) FROM license_assignments WHERE license_id=(command#>>'{pools,0,poolId}')::uuid AND assignee_type='user' AND assignee_id=command->>'userId'),'null'::jsonb) THEN RAISE EXCEPTION 'Original projection capture required' USING ERRCODE='40001';END IF;
 END IF;
 receipt.id=(command->>'id')::uuid;receipt.tenant_id=(authority#>>'{tenant,id}')::uuid;receipt.actor_user_id=(authority->>'actorUserId')::uuid;receipt.user_id=(command->>'userId')::uuid;
 receipt.action=command->>'action';receipt.assignment_id=(command->>'assignmentId')::uuid;receipt.command=command;receipt.source=source;receipt.application_source=application_source;
 receipt.before_state=CASE WHEN binding.id IS NULL THEN NULL ELSE company_blueprint_assignment_view(binding) END;receipt.created_at=clock_timestamp();
 receipt.valid_until=to_timestamp(LEAST((source->>'validUntil')::bigint,(application_source->>'validUntil')::bigint));receipt.transaction_id=txid_current();
 PERFORM set_config('opendirectory.company_blueprint_assignment',receipt.id::text,true);INSERT INTO company_blueprint_assignment_operations SELECT receipt.*;
 IF receipt.action='assigned' THEN
  INSERT INTO company_blueprint_user_assignments VALUES(receipt.assignment_id,receipt.tenant_id,receipt.user_id,release.blueprint_id,release.version,(command->>'eligibilityRevision')::bigint,1,'active',receipt.actor_user_id,receipt.created_at,NULL,receipt.id,NULL);
 ELSIF receipt.action='retire_sources' THEN EXECUTE 'SELECT company_blueprint_assignment_retirement_prepare($1)' USING receipt.id;END IF;
 RETURN receipt.id;
END; $$;
CREATE FUNCTION company_blueprint_assignment_binding_valid(binding company_blueprint_user_assignments) RETURNS BOOLEAN LANGUAGE plpgsql STABLE AS $$
DECLARE original company_blueprint_assignment_operations;closing company_blueprint_assignment_operations;
BEGIN
 SELECT * INTO original FROM company_blueprint_assignment_operations WHERE id=binding.operation_id;
 IF original.id IS NULL OR original.action<>'assigned' OR original.assignment_id<>binding.id OR original.tenant_id<>binding.tenant_id OR original.user_id<>binding.user_id OR original.actor_user_id<>binding.created_by
 OR original.command->>'blueprintId'<>binding.blueprint_id::text OR original.command->>'version'<>binding.version::text OR original.command->>'eligibilityRevision'<>binding.eligibility_revision::text OR original.created_at<>binding.created_at
 OR NOT company_blueprint_assignment_authority_valid(original.source,original.application_source,original.command,false)
 OR NOT EXISTS(SELECT 1 FROM company_blueprint_assignment_events event JOIN company_blueprint_assignment_outbox outbox ON outbox.id=event.id AND outbox.status='pending' AND outbox.created_at=event.created_at
  WHERE event.id=original.id AND event.created_at<original.valid_until AND event.proof=jsonb_build_object('source',original.source,'applicationSource',original.application_source,'command',original.command))
 OR NOT EXISTS(SELECT 1 FROM company_blueprint_versions WHERE blueprint_id=binding.blueprint_id AND tenant_id=binding.tenant_id AND version=binding.version) THEN RETURN false;END IF;
 IF binding.status='removed' THEN
  SELECT * INTO closing FROM company_blueprint_assignment_operations WHERE id=binding.removal_operation_id;
  IF closing.id IS NULL OR closing.action NOT IN('removed','retire_sources') OR closing.tenant_id<>binding.tenant_id OR closing.user_id<>binding.user_id
   OR NOT EXISTS(SELECT 1 FROM company_blueprint_assignment_events event JOIN company_blueprint_assignment_outbox outbox ON outbox.id=event.id AND outbox.status='pending' WHERE event.id=closing.id AND event.created_at<closing.valid_until)
   THEN RETURN false;END IF;
 END IF;RETURN true;
END; $$;
CREATE FUNCTION company_blueprint_assignment_admit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE release company_blueprint_versions;binding company_blueprint_user_assignments;catalog license_catalog;capture JSONB;actual JSONB;
BEGIN
 IF NEW.action='retire_sources' THEN EXECUTE 'SELECT company_blueprint_assignment_retirement_prepare($1)' USING NEW.id;RETURN NEW;END IF;
 IF NEW.action IN('assigned','removed') THEN
  SELECT * INTO binding FROM company_blueprint_user_assignments WHERE id=NEW.assignment_id;
  IF NEW.action='assigned' THEN
   IF binding.id IS NOT NULL THEN RAISE EXCEPTION 'Original new assignment identity required' USING ERRCODE='23505';END IF;
   SELECT * INTO release FROM company_blueprint_versions WHERE blueprint_id=(NEW.command->>'blueprintId')::uuid AND tenant_id=NEW.tenant_id AND version=(NEW.command->>'version')::integer;
  ELSE
   IF binding.id IS NULL OR binding.status<>'active' OR binding.tenant_id<>NEW.tenant_id OR binding.user_id<>NEW.user_id OR binding.revision::text<>NEW.command->>'expectedRevision' OR NEW.before_state IS DISTINCT FROM company_blueprint_assignment_view(binding) THEN RAISE EXCEPTION 'Original binding capture required' USING ERRCODE='23514';END IF;
   SELECT * INTO release FROM company_blueprint_versions WHERE blueprint_id=binding.blueprint_id AND version=binding.version;
  END IF;
  IF release.operation_id IS NULL OR (SELECT COALESCE(jsonb_agg(value ORDER BY value),'[]'::jsonb) FROM jsonb_array_elements(release.draft->'appPoolIds')) IS DISTINCT FROM
   (SELECT COALESCE(jsonb_agg(value->'poolId' ORDER BY value->'poolId'),'[]'::jsonb) FROM jsonb_array_elements(NEW.command->'pools')) THEN RAISE EXCEPTION 'Exact immutable release admission required' USING ERRCODE='23514';END IF;
 END IF;
 FOR capture IN SELECT value FROM jsonb_array_elements(NEW.command->'pools') ORDER BY value->>'poolId' LOOP
  SELECT * INTO catalog FROM license_catalog WHERE id=(capture->>'poolId')::uuid FOR UPDATE;
  IF catalog.id IS NULL OR catalog.business_tenant_id<>NEW.tenant_id OR catalog.business_revision::text<>capture->>'poolRevision' OR NOT license_company_pool_valid(catalog.id) OR NOT license_company_supported(catalog.id) THEN RAISE EXCEPTION 'Original canonical pool admission required' USING ERRCODE='23514';END IF;
  IF NEW.action IN('manual_assign','manual_revoke') THEN
   actual=license_company_sources(catalog.id,NEW.user_id);
   IF actual IS DISTINCT FROM NEW.command#>'{values,sources}' THEN RAISE EXCEPTION 'Original manual sources required' USING ERRCODE='23514';END IF;
  END IF;
 END LOOP;RETURN NEW;
END; $$;
SELECT company_blueprint_assignment_install();
DROP FUNCTION company_blueprint_assignment_install();
$migration026$;END IF;END; $install026$;
