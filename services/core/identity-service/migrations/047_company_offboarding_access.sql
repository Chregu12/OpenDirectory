CREATE TABLE IF NOT EXISTS identity_company_offboarding_access_checks (
 transaction_id BIGINT PRIMARY KEY DEFAULT txid_current(),source JSONB NOT NULL,before_state JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_offboarding_access_receipts (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,workflow_id UUID NOT NULL,user_id UUID NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('role','eligibility')),resource_id UUID NOT NULL,
 role_assignment_id UUID REFERENCES identity_role_assignments(id),eligibility_id UUID REFERENCES identity_pim_eligibilities(id),
 role TEXT NOT NULL,version TEXT NOT NULL CHECK(version~'^[a-f0-9]{64}$'),
 checkpoint_id UUID NOT NULL UNIQUE REFERENCES identity_authority_command_checkpoints(id) DEFERRABLE INITIALLY DEFERRED,
 actor_user_id UUID NOT NULL,correlation_id UUID NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500 AND btrim(reason)=reason AND reason!~'[[:cntrl:]]'),
 eligibility_revision BIGINT NOT NULL CHECK(eligibility_revision>0),source JSONB NOT NULL,before_state JSONB NOT NULL,after_state JSONB NOT NULL,
 role_audit JSONB NOT NULL,pim_audit JSONB NOT NULL,authorization_audit JSONB NOT NULL,record_audit JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),valid_until TIMESTAMPTZ NOT NULL,
 transaction_id BIGINT NOT NULL DEFAULT txid_current(),
 FOREIGN KEY(tenant_id,workflow_id) REFERENCES identity_company_offboarding_receipts(tenant_id,workflow_id),
 UNIQUE(tenant_id,workflow_id,kind,resource_id),
 CHECK((kind='role' AND role_assignment_id=resource_id AND eligibility_id IS NULL) OR (kind='eligibility' AND eligibility_id=resource_id AND role_assignment_id IS NULL)),
 CHECK(user_id<>actor_user_id AND isfinite(created_at) AND isfinite(valid_until) AND created_at<valid_until)
);
CREATE INDEX IF NOT EXISTS identity_company_offboarding_access_history ON identity_company_offboarding_access_receipts(tenant_id,workflow_id,user_id,kind,created_at,id);
CREATE TABLE IF NOT EXISTS identity_company_offboarding_access_outbox (
 id UUID PRIMARY KEY REFERENCES identity_company_offboarding_access_receipts(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_capture(grant_kind TEXT,identifier UUID,recipient UUID,owner UUID) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE grant_row JSONB;requests JSONB;assignments JSONB;
BEGIN
 IF grant_kind NOT IN('role','eligibility') OR grant_kind IS NULL OR identity_tenant_id('user',recipient) IS DISTINCT FROM owner
  THEN RAISE EXCEPTION 'Owned typed access grant required' USING ERRCODE='23503';END IF;
 IF grant_kind='role' THEN
  SELECT to_jsonb(assignment) INTO grant_row FROM identity_role_assignments assignment WHERE id=identifier AND user_id=recipient;
  SELECT COALESCE(jsonb_agg(to_jsonb(request) ORDER BY request.id),'[]') INTO requests FROM identity_pim_requests request WHERE id=(grant_row->>'activation_request_id')::uuid;
  assignments='[]';
  IF grant_row->>'activation_request_id' IS NOT NULL AND (jsonb_array_length(requests)<>1 OR NOT EXISTS(
   SELECT 1 FROM identity_pim_requests request JOIN identity_pim_eligibilities eligibility ON eligibility.id=request.eligibility_id
   WHERE request.id=(grant_row->>'activation_request_id')::uuid AND request.user_id=recipient AND eligibility.user_id=recipient AND eligibility.role=grant_row->>'role'))
   THEN RAISE EXCEPTION 'Coherent owned activation origin required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT to_jsonb(eligibility) INTO grant_row FROM identity_pim_eligibilities eligibility WHERE id=identifier AND user_id=recipient;
  SELECT COALESCE(jsonb_agg(to_jsonb(request) ORDER BY request.id),'[]') INTO requests FROM identity_pim_requests request WHERE eligibility_id=identifier;
  SELECT COALESCE(jsonb_agg(to_jsonb(assignment) ORDER BY assignment.id),'[]') INTO assignments FROM identity_role_assignments assignment
   WHERE activation_request_id IN(SELECT id FROM identity_pim_requests WHERE eligibility_id=identifier);
 END IF;
 IF grant_row IS NULL THEN RETURN NULL;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(requests) request WHERE request->>'user_id' IS DISTINCT FROM recipient::text
   OR identity_tenant_id('user',(request->>'user_id')::uuid) IS DISTINCT FROM owner)
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(assignments) assignment WHERE assignment->>'user_id' IS DISTINCT FROM recipient::text
   OR assignment->>'role' IS DISTINCT FROM grant_row->>'role' OR identity_tenant_id('user',(assignment->>'user_id')::uuid) IS DISTINCT FROM owner)
  OR grant_kind='eligibility' AND EXISTS(SELECT 1 FROM jsonb_array_elements(requests) request WHERE request->>'state'='active'
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(assignments) assignment WHERE assignment->>'activation_request_id'=request->>'id'))
  THEN RAISE EXCEPTION 'No foreign or malformed activation cascade permitted' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('grant',grant_row,'requests',requests,'assignments',assignments);
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_protected() RETURNS text[] LANGUAGE sql IMMUTABLE AS $$
 SELECT ARRAY['admin','role-administrator','pim-administrator','pim-approver','application-authentication-administrator','authentication-policy-administrator',
  'license-provider-administrator','license-fulfillment-operator','privileged-access-policy-administrator','access-review-administrator','access-reviewer',
  'license-review-administrator','license-reviewer','license-scope-administrator','license-delegate','license-scope-activation-reviewer','license-scope-policy-administrator',
  'license-delegation-review-administrator','license-delegation-reviewer','group-review-administrator','group-reviewer','policy-administrator','policy-publication-reviewer']::text[];
$$;
CREATE OR REPLACE FUNCTION identity_company_offboarding_access_actor(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE owner UUID;actual_roles TEXT[];tenant identity_tenants;grant_role TEXT;
BEGIN
 PERFORM identity_authority_owner();
 IF jsonb_typeof(proof) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(proof))<>19
  OR NOT proof ?& ARRAY['issuer','subject','context','tenant','rolesSnapshot','validUntil','authTime','tokenSha256','tokenIdSha256','workflowId','userId',
   'eligibilityRevision','kind','resourceId','version','receiptId','correlationId','reason','recovery']
  OR proof->>'kind' NOT IN('role','eligibility') OR jsonb_typeof(proof->'recovery') IS DISTINCT FROM 'boolean'
  OR proof->>'version'!~'^[a-f0-9]{64}$' OR proof->>'tokenSha256'!~'^[a-f0-9]{64}$' OR proof->>'tokenIdSha256'!~'^[a-f0-9]{64}$'
  OR jsonb_typeof(proof->'eligibilityRevision') IS DISTINCT FROM 'string' OR proof->>'eligibilityRevision'!~'^[1-9][0-9]{0,18}$'
  OR (proof->>'eligibilityRevision')::numeric>9223372036854775807
  OR proof->>'authTime'!~'^[0-9]{1,12}$' OR proof->>'validUntil'!~'^[0-9]{1,12}$'
  OR (proof->>'authTime')::bigint>extract(epoch FROM clock_timestamp())+5 OR (proof->>'validUntil')::bigint>(proof->>'authTime')::bigint+300
  OR to_timestamp((proof->>'validUntil')::bigint)<=clock_timestamp()
  OR jsonb_typeof(proof->'reason') IS DISTINCT FROM 'string' OR length(proof->>'reason') NOT BETWEEN 10 AND 500
  OR btrim(proof->>'reason') IS DISTINCT FROM proof->>'reason' OR proof->>'reason'~'[[:cntrl:]]'
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['workflowId','userId','resourceId','receiptId','correlationId']) field WHERE COALESCE(proof->>field,'')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  THEN RAISE EXCEPTION 'Exact fresh original access cleanup source required' USING ERRCODE='28000';END IF;
 owner=identity_authority_actor_home((proof->'context')||jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject'));
 SELECT * INTO tenant FROM identity_tenants WHERE id=owner AND enabled;
 IF proof->'tenant' IS DISTINCT FROM jsonb_build_object('id',owner,'version',tenant.version::text,'generation',tenant.generation::text)
  OR proof->'context'->>'userId'=proof->>'userId' OR proof->'rolesSnapshot' IS DISTINCT FROM identity_subject_link_role_state((proof->'context'->>'userId')::uuid)
  THEN RAISE EXCEPTION 'Original canonical cleanup actor and home tenant required' USING ERRCODE='28000';END IF;
 SELECT COALESCE(array_agg(DISTINCT assignment.role),'{}') INTO actual_roles FROM identity_role_assignments assignment
  JOIN identity_role_activation_policies policy ON policy.role=assignment.role AND policy.version=assignment.policy_version
  LEFT JOIN identity_pim_requests request ON request.id=assignment.activation_request_id
  WHERE assignment.user_id=(proof->'context'->>'userId')::uuid AND assignment.revoked_at IS NULL AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp())
   AND (NOT policy.activation_required OR assignment.activation_request_id IS NOT NULL)
   AND NOT EXISTS(SELECT 1 FROM identity_role_review_leases review WHERE review.target_kind='assignment' AND review.target_id=assignment.id AND (review.state='denied' OR review.deadline_at<=identity_role_review_now()))
   AND (assignment.activation_request_id IS NULL OR identity_role_review_eligible(request.eligibility_id));
 IF NOT('admin'=ANY(actual_roles) OR CASE WHEN proof->>'kind'='role' THEN 'role-administrator'=ANY(actual_roles) ELSE 'pim-administrator'=ANY(actual_roles) END)
  THEN RAISE EXCEPTION 'Independent actual canonical cleanup duty required' USING ERRCODE='42501';END IF;
 IF proof->>'kind'='role' THEN SELECT role INTO grant_role FROM identity_role_assignments WHERE id=(proof->>'resourceId')::uuid AND user_id=(proof->>'userId')::uuid;
 ELSE SELECT role INTO grant_role FROM identity_pim_eligibilities WHERE id=(proof->>'resourceId')::uuid AND user_id=(proof->>'userId')::uuid;END IF;
 IF grant_role=ANY(identity_company_offboarding_access_protected()) AND NOT('admin'=ANY(actual_roles))
  THEN RAISE EXCEPTION 'Actual canonical administrator required for protected access revocation' USING ERRCODE='42501';END IF;
 PERFORM identity_company_offboarding_validate(owner,(proof->>'workflowId')::uuid,(proof->>'userId')::uuid);
 IF NOT EXISTS(SELECT 1 FROM identity_company_offboarding_receipts WHERE tenant_id=owner AND workflow_id=(proof->>'workflowId')::uuid
  AND user_id=(proof->>'userId')::uuid AND after_eligibility_revision::text=proof->>'eligibilityRevision')
  THEN RAISE EXCEPTION 'Exact original negative eligibility required' USING ERRCODE='23514';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_offboarding_groups_receiving();PERFORM identity_authority_checkpoint_receiving();
 IF current_setting('session_replication_role')<>'origin' OR EXISTS(
  SELECT 1 FROM pg_class relation CROSS JOIN (VALUES('aaa_identity_company_offboarding_access_fence',31),('aaa_identity_company_offboarding_access_no_truncate',34)) expected(name,kind)
  WHERE relation.relnamespace=current_schema()::regnamespace AND relation.relkind IN('r','p') AND (left(relation.relname,9)='identity_' OR relation.relname IN('users','groups','group_members','ous'))
  AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O' AND NOT tgdeferrable AND tgfoid='identity_company_offboarding_access_fence()'::regprocedure)
 ) OR EXISTS(
  SELECT 1 FROM unnest(ARRAY['identity_company_offboarding_access_checks','identity_company_offboarding_access_receipts','identity_company_offboarding_access_outbox']) relation(name)
  CROSS JOIN (VALUES('identity_company_offboarding_access_guard',31,false,'identity_company_offboarding_access_guard()'),
   ('identity_company_offboarding_access_no_truncate',34,false,'identity_company_offboarding_access_guard()'),
   ('identity_company_offboarding_access_commit',29,true,'identity_company_offboarding_access_commit()')) expected(name,kind,deferred,routine)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation.name) AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O'
   AND tgdeferrable=expected.deferred AND tginitdeferred=expected.deferred AND tgfoid=to_regprocedure(expected.routine))
 ) OR EXISTS(
  SELECT 1 FROM unnest(ARRAY['identity_company_offboarding_access_checks','identity_company_offboarding_access_receipts','identity_company_offboarding_access_outbox']) relation(name)
  CROSS JOIN (SELECT * FROM identity_license_user_source_hooks() UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_groups_fence','identity_company_offboarding_groups_fence') hook
  CROSS JOIN (VALUES(false),(true)) truncation(enabled)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation.name)
   AND tgname=CASE WHEN truncation.enabled THEN regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate') ELSE hook.trigger_name END
   AND tgtype=CASE WHEN truncation.enabled THEN 34 ELSE 31 END AND tgenabled='O' AND NOT tgdeferrable AND tgfoid=to_regprocedure(hook.routine||'()'))
 ) OR EXISTS(
  SELECT 1 FROM (VALUES('identity_role_assignments','identity_role_guard','identity_role_guard()',31),
   ('identity_role_assignments','identity_role_changed','identity_role_changed()',21),('identity_pim_eligibilities','identity_pim_guard','identity_pim_guard()',31),
   ('identity_pim_eligibilities','identity_pim_changed','identity_pim_changed()',21),('identity_pim_requests','identity_pim_guard','identity_pim_guard()',31),
   ('identity_pim_requests','identity_pim_changed','identity_pim_changed()',21),('identity_role_assignments','identity_pim_assignment_revoked','identity_pim_assignment_revoked()',17)) expected(relation,name,routine,kind)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(expected.relation) AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O' AND tgfoid=to_regprocedure(expected.routine))
 ) THEN RAISE EXCEPTION 'Complete canonical access cleanup receiving guards required' USING ERRCODE='55000';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_begin(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE before_state JSONB;retained identity_company_offboarding_access_receipts;
BEGIN
 PERFORM identity_company_offboarding_access_receiving();PERFORM identity_company_offboarding_access_actor(proof);
 IF NULLIF(current_setting('opendirectory.company_offboarding_access',true),'') IS NOT NULL
  OR EXISTS(SELECT 1 FROM identity_company_offboarding_access_checks WHERE transaction_id=txid_current())
  OR EXISTS(SELECT 1 FROM identity_authority_command_checkpoints WHERE transaction_id=txid_current())
  OR EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid=1948783475::oid AND objid=1735549296::oid AND objsubid=2 AND mode='ShareLock' AND granted)
  THEN RAISE EXCEPTION 'One original access cleanup child per transaction required' USING ERRCODE='42501';END IF;
 PERFORM id FROM identity_tenants WHERE id=(proof->'tenant'->>'id')::uuid FOR SHARE;
 PERFORM id FROM users WHERE id IN((proof->'context'->>'userId')::uuid,(proof->>'userId')::uuid) ORDER BY id FOR UPDATE;
 IF proof->>'kind'='role' THEN PERFORM id FROM identity_role_assignments WHERE id=(proof->>'resourceId')::uuid FOR UPDATE;
 ELSE
  PERFORM id FROM identity_pim_eligibilities WHERE id=(proof->>'resourceId')::uuid FOR UPDATE;
  PERFORM id FROM identity_pim_requests WHERE eligibility_id=(proof->>'resourceId')::uuid ORDER BY id FOR UPDATE;
  PERFORM id FROM identity_role_assignments WHERE activation_request_id IN(SELECT id FROM identity_pim_requests WHERE eligibility_id=(proof->>'resourceId')::uuid) ORDER BY id FOR UPDATE;
 END IF;
 IF proof->'recovery'='true'::jsonb THEN
  SELECT * INTO retained FROM identity_company_offboarding_access_receipts WHERE id=(proof->>'receiptId')::uuid;
  IF retained.id IS NULL OR retained.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id' OR retained.workflow_id::text IS DISTINCT FROM proof->>'workflowId'
   OR retained.user_id::text IS DISTINCT FROM proof->>'userId' OR retained.kind IS DISTINCT FROM proof->>'kind'
   OR retained.resource_id::text IS DISTINCT FROM proof->>'resourceId' OR retained.version IS DISTINCT FROM proof->>'version'
   THEN RAISE EXCEPTION 'Only exact retained cleanup incarnation can recover' USING ERRCODE='23514';END IF;
  PERFORM identity_company_offboarding_access_validate(retained.id);before_state=retained.before_state;
 ELSE
  before_state=identity_company_offboarding_access_capture(proof->>'kind',(proof->>'resourceId')::uuid,(proof->>'userId')::uuid,(proof->'tenant'->>'id')::uuid);
  IF before_state IS NULL OR before_state->'grant'->>'revoked_at' IS NOT NULL OR identity_authority_hash(before_state->'grant') IS DISTINCT FROM proof->>'version'
   THEN RAISE EXCEPTION 'Original unrevoked captured access incarnation required' USING ERRCODE='23514';END IF;
 END IF;
 PERFORM set_config('opendirectory.company_offboarding_access',proof::text,true);
 INSERT INTO identity_company_offboarding_access_checks(source,before_state) VALUES(proof,before_state);
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_finish(checkpoint UUID,proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE captured JSONB;after_state JSONB;role_evidence JSONB;pim_evidence JSONB;authorization_evidence JSONB;record_evidence JSONB;receipt identity_company_offboarding_access_receipts;
BEGIN
 PERFORM identity_company_offboarding_access_actor(proof);
 SELECT before_state INTO captured FROM identity_company_offboarding_access_checks WHERE transaction_id=txid_current() AND source=proof;
 IF captured IS NULL OR proof IS DISTINCT FROM NULLIF(current_setting('opendirectory.company_offboarding_access',true),'')::jsonb OR proof->'recovery'<>'false'::jsonb
  OR EXISTS(SELECT 1 FROM identity_authority_command_checkpoints WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION 'Original canonical child before final checkpoint required' USING ERRCODE='42501';END IF;
 after_state=identity_company_offboarding_access_capture(proof->>'kind',(proof->>'resourceId')::uuid,(proof->>'userId')::uuid,(proof->'tenant'->>'id')::uuid);
 SELECT COALESCE(jsonb_agg(to_jsonb(audit) ORDER BY audit.id),'[]') INTO role_evidence FROM identity_role_audit audit
  WHERE audit.action='revoked' AND (audit.assignment_id=CASE WHEN proof->>'kind'='role' THEN (proof->>'resourceId')::uuid ELSE NULL END
   OR audit.assignment_id IN(SELECT (assignment->>'id')::uuid FROM jsonb_array_elements(captured->'assignments') assignment WHERE assignment->>'revoked_at' IS NULL));
 SELECT COALESCE(jsonb_agg(to_jsonb(audit) ORDER BY audit.id),'[]') INTO pim_evidence FROM identity_pim_audit audit
  WHERE (proof->>'kind'='eligibility' AND audit.entity_id=(proof->>'resourceId')::uuid AND audit.action='identity_pim_eligibilities:update')
   OR audit.action='identity_pim_requests:update' AND audit.details=(SELECT actual FROM jsonb_array_elements(after_state->'requests') actual WHERE actual->>'id'=audit.entity_id::text)
    AND audit.entity_id IN(SELECT (request->>'id')::uuid FROM jsonb_array_elements(captured->'requests') request
    WHERE request IS DISTINCT FROM (SELECT actual FROM jsonb_array_elements(after_state->'requests') actual WHERE actual->>'id'=request->>'id'));
 SELECT COALESCE(jsonb_agg(to_jsonb(audit) ORDER BY audit.id),'[]') INTO authorization_evidence FROM identity_authorization_audit audit
  WHERE audit.user_id=(proof->>'userId')::uuid AND audit.reason='security_reset' AND audit.created_at=transaction_timestamp();
 SELECT COALESCE(jsonb_agg(to_jsonb(audit) ORDER BY audit.id),'[]') INTO record_evidence FROM identity_user_record_audit audit
  WHERE audit.user_id=(proof->>'userId')::uuid AND audit.action='update' AND audit.created_at=transaction_timestamp();
 INSERT INTO identity_company_offboarding_access_receipts(id,tenant_id,workflow_id,user_id,kind,resource_id,role_assignment_id,eligibility_id,role,version,checkpoint_id,
  actor_user_id,correlation_id,reason,eligibility_revision,source,before_state,after_state,role_audit,pim_audit,authorization_audit,record_audit,valid_until)
 VALUES((proof->>'receiptId')::uuid,(proof->'tenant'->>'id')::uuid,(proof->>'workflowId')::uuid,(proof->>'userId')::uuid,proof->>'kind',(proof->>'resourceId')::uuid,
  CASE WHEN proof->>'kind'='role' THEN (proof->>'resourceId')::uuid END,CASE WHEN proof->>'kind'='eligibility' THEN (proof->>'resourceId')::uuid END,
  captured->'grant'->>'role',proof->>'version',checkpoint,(proof->'context'->>'userId')::uuid,(proof->>'correlationId')::uuid,proof->>'reason',
  (proof->>'eligibilityRevision')::bigint,proof,captured,after_state,role_evidence,pim_evidence,authorization_evidence,record_evidence,to_timestamp((proof->>'validUntil')::bigint)) RETURNING * INTO receipt;
 INSERT INTO identity_company_offboarding_access_outbox(id,tenant_id,created_at) VALUES(receipt.id,receipt.tenant_id,receipt.created_at);
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_validate(identifier UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt identity_company_offboarding_access_receipts;checkpoint identity_authority_command_checkpoints;before_row JSONB;after_row JSONB;expected JSONB;actual JSONB;
 request JSONB;current_assignment JSONB;evidence JSONB;actor TEXT;expected_roles INTEGER;expected_pim INTEGER;
BEGIN
 PERFORM identity_company_offboarding_access_receiving();SELECT * INTO receipt FROM identity_company_offboarding_access_receipts WHERE id=identifier;
 IF receipt.id IS NULL THEN RAISE EXCEPTION 'Retained real access cleanup receipt required' USING ERRCODE='23514';END IF;
 PERFORM identity_company_offboarding_validate(receipt.tenant_id,receipt.workflow_id,receipt.user_id);
 SELECT * INTO checkpoint FROM identity_authority_command_checkpoints WHERE id=receipt.checkpoint_id;
 before_row=receipt.before_state->'grant';after_row=receipt.after_state->'grant';actor=jsonb_build_object('issuer',receipt.source->>'issuer','subject',receipt.source->>'subject','userId',receipt.actor_user_id)::text;
 IF receipt.source->>'receiptId' IS DISTINCT FROM receipt.id::text OR receipt.source->'tenant'->>'id' IS DISTINCT FROM receipt.tenant_id::text
  OR receipt.source->>'workflowId' IS DISTINCT FROM receipt.workflow_id::text OR receipt.source->>'userId' IS DISTINCT FROM receipt.user_id::text
  OR receipt.source->>'kind' IS DISTINCT FROM receipt.kind OR receipt.source->>'resourceId' IS DISTINCT FROM receipt.resource_id::text OR receipt.source->>'version' IS DISTINCT FROM receipt.version
  OR receipt.source->'context'->>'userId' IS DISTINCT FROM receipt.actor_user_id::text OR receipt.source->>'correlationId' IS DISTINCT FROM receipt.correlation_id::text
  OR receipt.source->>'reason' IS DISTINCT FROM receipt.reason OR receipt.source->'recovery' IS DISTINCT FROM 'false'::jsonb
  OR receipt.source->>'eligibilityRevision' IS DISTINCT FROM receipt.eligibility_revision::text
  OR receipt.valid_until IS DISTINCT FROM to_timestamp((receipt.source->>'validUntil')::bigint)
  OR before_row->>'id' IS DISTINCT FROM receipt.resource_id::text OR before_row->>'user_id' IS DISTINCT FROM receipt.user_id::text OR before_row->>'role' IS DISTINCT FROM receipt.role
  OR before_row->>'revoked_at' IS NOT NULL OR after_row->>'revoked_at' IS NULL OR before_row-'revoked_at' IS DISTINCT FROM after_row-'revoked_at'
  OR receipt.version IS DISTINCT FROM identity_authority_hash(before_row)
  OR NOT EXISTS(SELECT 1 FROM identity_company_offboarding_receipts WHERE tenant_id=receipt.tenant_id AND workflow_id=receipt.workflow_id AND user_id=receipt.user_id AND after_eligibility_revision=receipt.eligibility_revision)
  OR checkpoint.id IS NULL OR checkpoint.transaction_id<>receipt.transaction_id OR checkpoint.tenant_id<>receipt.tenant_id OR checkpoint.user_id<>receipt.actor_user_id
  OR checkpoint.issuer IS DISTINCT FROM receipt.source->>'issuer' OR checkpoint.subject IS DISTINCT FROM receipt.source->>'subject'
  OR checkpoint.original_context IS DISTINCT FROM receipt.source->'context' OR checkpoint.token_sha256 IS DISTINCT FROM receipt.source->>'tokenIdSha256'
  OR checkpoint.roles_snapshot_sha256 IS DISTINCT FROM identity_authority_hash(receipt.source->'rolesSnapshot')
  OR checkpoint.created_at<receipt.created_at OR checkpoint.created_at>=receipt.valid_until
  OR NOT EXISTS(SELECT 1 FROM identity_authority_command_checkpoint_events event JOIN identity_authority_command_checkpoint_outbox outbox USING(id)
   WHERE event.id=checkpoint.id AND event.tenant_id=receipt.tenant_id AND outbox.tenant_id=receipt.tenant_id AND outbox.status='pending' AND outbox.action=event.action
    AND event.action='authority-checkpoint' AND event.scope_sha256=identity_authority_hash(to_jsonb(checkpoint)))
  OR NOT EXISTS(SELECT 1 FROM identity_company_offboarding_access_checks WHERE transaction_id=receipt.transaction_id AND source=receipt.source AND before_state=receipt.before_state)
  OR NOT EXISTS(SELECT 1 FROM identity_company_offboarding_access_outbox WHERE id=receipt.id AND tenant_id=receipt.tenant_id AND status='pending' AND created_at=receipt.created_at)
  OR receipt.after_state IS DISTINCT FROM identity_company_offboarding_access_capture(receipt.kind,receipt.resource_id,receipt.user_id,receipt.tenant_id)
  THEN RAISE EXCEPTION 'Exact real canonical access child, original parent, final checkpoint and pending outboxes required' USING ERRCODE='23514';END IF;
 expected_roles=CASE WHEN receipt.kind='role' THEN 1 ELSE 0 END;expected_pim=CASE WHEN receipt.kind='eligibility' THEN 1 ELSE 0 END;
 FOR request IN SELECT value FROM jsonb_array_elements(receipt.before_state->'requests') LOOP
  SELECT value INTO actual FROM jsonb_array_elements(receipt.after_state->'requests') WHERE value->>'id'=request->>'id';expected=request;
  IF receipt.kind='eligibility' AND request->>'state' IN('pending','approved') THEN expected=jsonb_set(request,'{state}','"cancelled"');
  ELSIF request->>'state'='active' AND (receipt.kind='role' OR EXISTS(SELECT 1 FROM jsonb_array_elements(receipt.before_state->'assignments') assignment WHERE assignment->>'activation_request_id'=request->>'id' AND assignment->>'revoked_at' IS NULL))
   THEN expected=jsonb_set(request,'{state}','"revoked"');END IF;
  IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact original PIM request cascade required' USING ERRCODE='23514';END IF;
  IF actual IS DISTINCT FROM request THEN
   expected_pim=expected_pim+1;
   IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(receipt.pim_audit) audit WHERE audit->>'entity_id'=request->>'id'
    AND audit->>'action'='identity_pim_requests:update' AND audit->'details'=actual AND (audit->>'actor')::jsonb=actor::jsonb)
    THEN RAISE EXCEPTION 'Actual request cascade audit required' USING ERRCODE='23514';END IF;
  END IF;
 END LOOP;
 FOR current_assignment IN SELECT value FROM jsonb_array_elements(receipt.before_state->'assignments') LOOP
  SELECT value INTO actual FROM jsonb_array_elements(receipt.after_state->'assignments') WHERE value->>'id'=current_assignment->>'id';
  IF current_assignment->>'revoked_at' IS NULL THEN
   expected_roles=expected_roles+1;
   IF actual->>'revoked_at' IS NULL OR current_assignment-'revoked_at' IS DISTINCT FROM actual-'revoked_at' THEN RAISE EXCEPTION 'Actual one-way assignment cascade required' USING ERRCODE='23514';END IF;
  ELSIF actual IS DISTINCT FROM current_assignment THEN RAISE EXCEPTION 'Already revoked assignment cannot change' USING ERRCODE='23514';END IF;
 END LOOP;
 IF jsonb_array_length(receipt.role_audit)<>expected_roles OR jsonb_array_length(receipt.pim_audit)<>expected_pim OR jsonb_array_length(receipt.authorization_audit)<>expected_roles OR jsonb_array_length(receipt.record_audit)<>expected_roles THEN RAISE EXCEPTION 'Exact canonical cascade audit counts required' USING ERRCODE='23514';END IF;
 FOR evidence IN SELECT value FROM jsonb_array_elements(receipt.record_audit) LOOP
  IF NOT EXISTS(SELECT 1 FROM identity_user_record_audit audit WHERE to_jsonb(audit)=evidence) OR evidence->>'user_id' IS DISTINCT FROM receipt.user_id::text
   OR evidence->>'action'<>'update' OR evidence->'details'->'before' IS DISTINCT FROM evidence->'details'->'after'
   OR evidence->'details'->'after'->'enabled' IS DISTINCT FROM 'false'::jsonb
   OR (evidence->>'actor')::jsonb IS DISTINCT FROM actor::jsonb THEN RAISE EXCEPTION 'Actual unchanged account record audit required' USING ERRCODE='23514';END IF;
 END LOOP;
 FOR evidence IN SELECT value FROM jsonb_array_elements(receipt.authorization_audit) LOOP
  IF NOT EXISTS(SELECT 1 FROM identity_authorization_audit audit WHERE to_jsonb(audit)=evidence) OR evidence->>'user_id' IS DISTINCT FROM receipt.user_id::text
   OR evidence->>'reason'<>'security_reset' OR evidence->'details' IS DISTINCT FROM jsonb_build_object('enabled',false)
   OR (evidence->>'actor')::jsonb IS DISTINCT FROM actor::jsonb THEN RAISE EXCEPTION 'Actual canonical account invalidation audit required' USING ERRCODE='23514';END IF;
 END LOOP;
 FOR evidence IN SELECT value FROM jsonb_array_elements(receipt.role_audit) LOOP
  IF NOT EXISTS(SELECT 1 FROM identity_role_audit audit WHERE to_jsonb(audit)=evidence)
   OR evidence->>'action'<>'revoked' OR evidence->>'user_id' IS DISTINCT FROM receipt.user_id::text OR (evidence->>'actor')::jsonb IS DISTINCT FROM actor::jsonb
   OR NOT EXISTS(SELECT 1 FROM (SELECT receipt.after_state->'grant' AS value WHERE receipt.kind='role' UNION ALL SELECT value FROM jsonb_array_elements(receipt.after_state->'assignments')) changed
    WHERE changed.value->>'id'=evidence->>'assignment_id' AND changed.value->>'revoked_at' IS NOT NULL AND evidence->'details'=jsonb_build_object('role',changed.value->'role','reason',changed.value->'reason','expiresAt',changed.value->'expires_at','revokedAt',changed.value->'revoked_at'))
   THEN RAISE EXCEPTION 'Retained actual assignment audit and actor required' USING ERRCODE='23514';END IF;
 END LOOP;
 FOR evidence IN SELECT value FROM jsonb_array_elements(receipt.pim_audit) LOOP
  IF NOT EXISTS(SELECT 1 FROM identity_pim_audit audit WHERE to_jsonb(audit)=evidence) OR evidence->>'user_id' IS DISTINCT FROM receipt.user_id::text
   OR (evidence->>'actor')::jsonb IS DISTINCT FROM actor::jsonb
   OR NOT EXISTS(SELECT 1 FROM (SELECT receipt.after_state->'grant' AS value WHERE receipt.kind='eligibility' UNION ALL SELECT value FROM jsonb_array_elements(receipt.after_state->'requests')) changed WHERE changed.value=evidence->'details' AND changed.value->>'id'=evidence->>'entity_id')
   THEN RAISE EXCEPTION 'Retained actual PIM audit and actor required' USING ERRCODE='23514';END IF;
 END LOOP;
 IF receipt.transaction_id=txid_current() THEN PERFORM identity_company_offboarding_access_actor(receipt.source);END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;receipt identity_company_offboarding_access_receipts;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM identity_company_offboarding_access_checks) OR EXISTS(SELECT 1 FROM identity_company_offboarding_access_receipts)
   THEN RAISE EXCEPTION 'Access cleanup evidence cannot be truncated' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 proof=NULLIF(current_setting('opendirectory.company_offboarding_access',true),'')::jsonb;
 IF TG_OP<>'INSERT' OR proof IS NULL THEN RAISE EXCEPTION 'Access cleanup evidence is immutable' USING ERRCODE='42501';END IF;
 PERFORM identity_company_offboarding_access_actor(proof);
 IF TG_TABLE_NAME='identity_company_offboarding_access_checks' THEN
  IF NEW.transaction_id<>txid_current() OR NEW.source IS DISTINCT FROM proof THEN RAISE EXCEPTION 'Exact original cleanup check required' USING ERRCODE='23514';END IF;
  IF proof->'recovery'='false'::jsonb THEN
   IF NEW.before_state IS DISTINCT FROM identity_company_offboarding_access_capture(proof->>'kind',(proof->>'resourceId')::uuid,(proof->>'userId')::uuid,(proof->'tenant'->>'id')::uuid)
    OR NEW.before_state IS NULL OR NEW.before_state->'grant'->>'revoked_at' IS NOT NULL OR identity_authority_hash(NEW.before_state->'grant') IS DISTINCT FROM proof->>'version'
    THEN RAISE EXCEPTION 'Only the actual current unrevoked before-state can be admitted' USING ERRCODE='23514';END IF;
  ELSE
   SELECT * INTO receipt FROM identity_company_offboarding_access_receipts WHERE id=(proof->>'receiptId')::uuid;
   IF receipt.id IS NULL OR NEW.before_state IS DISTINCT FROM receipt.before_state OR receipt.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id'
    OR receipt.workflow_id::text IS DISTINCT FROM proof->>'workflowId' OR receipt.user_id::text IS DISTINCT FROM proof->>'userId'
    OR receipt.kind IS DISTINCT FROM proof->>'kind' OR receipt.resource_id::text IS DISTINCT FROM proof->>'resourceId' OR receipt.version IS DISTINCT FROM proof->>'version'
    THEN RAISE EXCEPTION 'Only the exact retained original before-state can recover' USING ERRCODE='23514';END IF;
  END IF;
 ELSIF TG_TABLE_NAME='identity_company_offboarding_access_receipts' THEN
  IF NEW.source IS DISTINCT FROM proof OR NEW.transaction_id<>txid_current() OR NEW.id::text IS DISTINCT FROM proof->>'receiptId' OR proof->'recovery'<>'false'::jsonb
   THEN RAISE EXCEPTION 'Exact actual child receipt required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO receipt FROM identity_company_offboarding_access_receipts WHERE id=NEW.id;
  IF receipt.id IS NULL OR receipt.id::text IS DISTINCT FROM proof->>'receiptId' OR NEW.tenant_id<>receipt.tenant_id OR NEW.created_at<>receipt.created_at OR NEW.status<>'pending'
   THEN RAISE EXCEPTION 'Exact mandatory pending child outbox required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_fence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;stored JSONB;captured JSONB;before_row JSONB;after_row JSONB;actor JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.company_offboarding_access',true),'')::jsonb;
 SELECT source,before_state INTO stored,captured FROM identity_company_offboarding_access_checks WHERE transaction_id=txid_current();
 IF stored IS NOT NULL AND proof IS DISTINCT FROM stored THEN RAISE EXCEPTION 'Original access cleanup scope cannot disappear or change' USING ERRCODE='42501';END IF;
 IF proof IS NULL THEN IF TG_OP='TRUNCATE' THEN RETURN NULL;ELSIF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 PERFORM identity_company_offboarding_access_actor(proof);
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Access cleanup cannot truncate' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_company_offboarding_access_checks' AND TG_OP='INSERT' AND stored IS NULL THEN RETURN NEW;END IF;
 IF proof->'recovery'='true'::jsonb THEN RAISE EXCEPTION 'Retained access cleanup recovery must be effect-free' USING ERRCODE='42501';END IF;
 IF stored IS NULL THEN RAISE EXCEPTION 'Original immutable cleanup source required before effects' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' AND TG_TABLE_NAME IN('identity_company_offboarding_access_receipts','identity_company_offboarding_access_outbox') THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' THEN
  before_row=to_jsonb(OLD);after_row=to_jsonb(NEW);
  IF TG_TABLE_NAME='identity_role_assignments' AND (proof->>'kind'='role' AND before_row=captured->'grant'
    OR proof->>'kind'='eligibility' AND EXISTS(SELECT 1 FROM jsonb_array_elements(captured->'assignments') assignment WHERE assignment=before_row))
   AND before_row->>'revoked_at' IS NULL AND after_row->>'revoked_at' IS NOT NULL AND before_row-'revoked_at'=after_row-'revoked_at' THEN RETURN NEW;END IF;
  IF TG_TABLE_NAME='identity_pim_eligibilities' AND proof->>'kind'='eligibility' AND before_row=captured->'grant' AND before_row->>'revoked_at' IS NULL
   AND after_row->>'revoked_at' IS NOT NULL AND before_row-'revoked_at'=after_row-'revoked_at' THEN RETURN NEW;END IF;
  IF TG_TABLE_NAME='identity_pim_requests' AND pg_trigger_depth()>1 AND EXISTS(SELECT 1 FROM jsonb_array_elements(captured->'requests') request WHERE request=before_row)
   AND before_row-'state'=after_row-'state' AND ((before_row->>'state' IN('pending','approved') AND after_row->>'state'='cancelled' AND proof->>'kind'='eligibility')
    OR before_row->>'state'='active' AND after_row->>'state'='revoked') THEN RETURN NEW;END IF;
  IF TG_TABLE_NAME='users' AND pg_trigger_depth()>1 AND before_row->>'id'=proof->>'userId'
   AND before_row-ARRAY['authorization_revision','updated_at']=after_row-ARRAY['authorization_revision','updated_at']
   AND (after_row->>'authorization_revision')::bigint=(before_row->>'authorization_revision')::bigint+1 THEN RETURN NEW;END IF;
 END IF;
 IF TG_OP='INSERT' THEN
  after_row=to_jsonb(NEW);actor=jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId');
  IF TG_TABLE_NAME IN('identity_role_audit','identity_pim_audit') AND pg_trigger_depth()>1 AND after_row->>'user_id'=proof->>'userId'
   AND (after_row->>'actor')::jsonb=actor THEN RETURN NEW;END IF;
  IF TG_TABLE_NAME='identity_authorization_audit' AND pg_trigger_depth()>1 AND after_row->>'user_id'=proof->>'userId' AND (after_row->>'actor')::jsonb=actor
   AND after_row->>'reason'='security_reset' AND after_row->'details'=jsonb_build_object('enabled',false)
   AND EXISTS(SELECT 1 FROM users WHERE id=(proof->>'userId')::uuid AND authorization_revision::text=after_row->>'revision') THEN RETURN NEW;END IF;
  IF TG_TABLE_NAME='identity_user_record_audit' AND pg_trigger_depth()>1 AND after_row->>'user_id'=proof->>'userId' AND (after_row->>'actor')::jsonb=actor
   AND after_row->>'action'='update' AND after_row->'details'->'before'=after_row->'details'->'after'
   AND after_row->'details'->'after'->'enabled'='false'::jsonb
   AND EXISTS(SELECT 1 FROM users WHERE id=(proof->>'userId')::uuid AND record_revision::text=after_row->>'revision') THEN RETURN NEW;END IF;
  IF TG_TABLE_NAME IN('identity_authority_command_checkpoints','identity_authority_command_checkpoint_events','identity_authority_command_checkpoint_outbox')
   AND EXISTS(SELECT 1 FROM identity_company_offboarding_access_receipts WHERE transaction_id=txid_current() AND checkpoint_id=(after_row->>'id')::uuid AND source=proof) THEN RETURN NEW;END IF;
 END IF;
 RAISE EXCEPTION 'Only the bound canonical access revocation and its actual cascade may have effects' USING ERRCODE='42501';
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_access_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;receipt identity_company_offboarding_access_receipts;
BEGIN
 PERFORM identity_company_offboarding_access_receiving();
 SELECT source INTO proof FROM identity_company_offboarding_access_checks WHERE transaction_id=txid_current();
 IF proof IS NULL OR proof IS DISTINCT FROM NULLIF(current_setting('opendirectory.company_offboarding_access',true),'')::jsonb
  THEN RAISE EXCEPTION 'Immutable original access source required at physical commit' USING ERRCODE='42501';END IF;
 PERFORM identity_company_offboarding_access_actor(proof);
 SELECT * INTO receipt FROM identity_company_offboarding_access_receipts WHERE id=(proof->>'receiptId')::uuid;
 PERFORM identity_company_offboarding_access_validate((proof->>'receiptId')::uuid);
 IF receipt.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id' OR receipt.workflow_id::text IS DISTINCT FROM proof->>'workflowId'
  OR receipt.user_id::text IS DISTINCT FROM proof->>'userId' OR receipt.kind IS DISTINCT FROM proof->>'kind'
  OR receipt.resource_id::text IS DISTINCT FROM proof->>'resourceId' OR receipt.version IS DISTINCT FROM proof->>'version'
  OR proof->'recovery'='false'::jsonb AND (receipt.transaction_id<>txid_current() OR receipt.source IS DISTINCT FROM proof)
  OR proof->'recovery'='true'::jsonb AND EXISTS(SELECT 1 FROM identity_authority_command_checkpoints WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'One exact original access child or effect-free retained recovery required' USING ERRCODE='23514';END IF;
 PERFORM identity_company_offboarding_access_actor(proof);RETURN NULL;
END; $$;

DO $$ DECLARE relation TEXT;hook RECORD;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_offboarding_access_checks','identity_company_offboarding_access_receipts','identity_company_offboarding_access_outbox'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_company_offboarding_access_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_access_guard()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_company_offboarding_access_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_offboarding_access_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_offboarding_access_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_company_offboarding_access_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_access_commit()',relation);
  FOR hook IN SELECT * FROM identity_license_user_source_hooks() UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_groups_fence','identity_company_offboarding_groups_fence' LOOP
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,relation,hook.routine);
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation,hook.routine);
  END LOOP;
  EXECUTE format('REVOKE ALL ON TABLE %I FROM PUBLIC',relation);
 END LOOP;
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER aaa_identity_company_offboarding_access_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_access_fence()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER aaa_identity_company_offboarding_access_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_offboarding_access_fence()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_company_offboarding_access_capture(text,uuid,uuid,uuid)','identity_company_offboarding_access_protected()','identity_company_offboarding_access_actor(jsonb)',
  'identity_company_offboarding_access_receiving()','identity_company_offboarding_access_begin(jsonb)','identity_company_offboarding_access_finish(uuid,jsonb)',
  'identity_company_offboarding_access_validate(uuid)','identity_company_offboarding_access_guard()','identity_company_offboarding_access_fence()','identity_company_offboarding_access_commit()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
