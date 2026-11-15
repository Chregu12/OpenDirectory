BEGIN;
ALTER TABLE identity_company_pim_policies ADD COLUMN IF NOT EXISTS reviewer_group_id UUID REFERENCES groups(id);
ALTER TABLE identity_company_pim_policies ADD COLUMN IF NOT EXISTS reviewer_group_generation BIGINT;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='identity_company_pim_policies'::regclass AND conname='identity_company_pim_reviewer_group') THEN
  ALTER TABLE identity_company_pim_policies ADD CONSTRAINT identity_company_pim_reviewer_group CHECK(
   (reviewer_group_id IS NULL)=(reviewer_group_generation IS NULL) AND (reviewer_group_generation IS NULL OR reviewer_group_generation>0 AND approval_required));
 END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_pim_approver_group_current(identity UUID,home UUID,generation BIGINT) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT CASE WHEN identity IS NULL THEN $3 IS NULL ELSE EXISTS(
  SELECT 1 FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=home
   JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=home AND protected.generation=namespace.generation
  WHERE collection.id=identity AND namespace.generation=$3 AND identity_tenant_id('group',collection.id)=home) END;
$$;
CREATE OR REPLACE FUNCTION identity_company_pim_reviewer_source(proof JSONB,identity UUID) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE policy identity_company_pim_policies;home UUID;actor UUID;member group_members;deadline TIMESTAMPTZ;
BEGIN
 PERFORM identity_directory_creation_actor(proof);home=(proof#>>'{tenant,id}')::uuid;actor=(proof#>>'{context,userId}')::uuid;
 IF NOT EXISTS(SELECT 1 FROM identity_company_roles WHERE id=identity AND tenant_id=home) THEN RETURN NULL;END IF;
 SELECT * INTO policy FROM identity_company_pim_policies WHERE role_id=identity AND tenant_id=home;
 IF policy.reviewer_group_id IS NULL THEN
  IF identity_company_pim_approval_reviewer(proof) THEN RETURN jsonb_build_object('kind','canonical','validUntil',proof->>'validUntil');END IF;RETURN NULL;
 END IF;
 IF NOT policy.approval_required OR NOT identity_company_pim_approver_group_current(policy.reviewer_group_id,home,policy.reviewer_group_generation) THEN RETURN NULL;END IF;
 SELECT * INTO member FROM group_members WHERE group_id=policy.reviewer_group_id AND user_id=actor::text;
 IF member.membership_id IS NULL OR NOT identity_tenant_user_enabled(actor) THEN RETURN NULL;END IF;
 deadline=least(identity_membership_rule_deadline(member.membership_id),to_timestamp((proof->>'validUntil')::double precision));
 IF deadline<=clock_timestamp() THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('kind','group','groupId',policy.reviewer_group_id,'generation',policy.reviewer_group_generation::text,'membershipId',member.membership_id,'validUntil',floor(extract(epoch FROM deadline))::bigint::text);
END; $$;

CREATE OR REPLACE FUNCTION identity_company_pim_approval_policy(identity UUID) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT coalesce((SELECT jsonb_build_object('revision',revision::text,'approvalRequired',approval_required,'windowSeconds',approval_window_seconds,'reviewerGroupId',reviewer_group_id) FROM identity_company_pim_policies WHERE role_id=identity),
 jsonb_build_object('revision','0','approvalRequired',false,'windowSeconds',300,'reviewerGroupId',NULL));
$$;

CREATE OR REPLACE FUNCTION identity_company_pim_request_status(original identity_company_pim_requests) RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE policy JSONB;candidate JSONB;
BEGIN
 IF original.state IN('cancelled','denied','activated') THEN RETURN original.state;END IF;
 IF original.expires_at<=clock_timestamp() OR original.state='approved' AND original.approval_expires_at<=clock_timestamp() THEN RETURN 'expired';END IF;
 policy=identity_company_pim_approval_policy(original.role_id);
 SELECT value INTO candidate FROM jsonb_array_elements(identity_company_role_pim_candidates(original.user_id,original.tenant_id)) WHERE value->>'id'=original.eligibility_id::text;
 IF NOT (policy->>'approvalRequired')::boolean OR policy->>'revision' IS DISTINCT FROM original.policy_revision::text OR candidate IS NULL
  OR candidate-'validUntil' IS DISTINCT FROM original.scope-'validUntil' OR least((candidate->>'validUntil')::numeric,(original.scope->>'validUntil')::numeric)<extract(epoch FROM clock_timestamp())+original.duration_seconds
  OR NOT EXISTS(SELECT 1 FROM identity_company_role_eligibilities WHERE id=original.eligibility_id AND tenant_id=original.tenant_id AND revision=original.eligibility_revision)
  OR NOT EXISTS(SELECT 1 FROM users account JOIN identity_subject_links link ON link.user_id=account.id JOIN identity_tenants home ON home.id=original.tenant_id
   JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=home.id
   WHERE account.id=original.user_id AND account.enabled AND home.enabled AND identity_tenant_id('user',account.id)=home.id
    AND link.issuer=original.actor->>'issuer' AND link.subject=original.actor->>'subject'
    AND account.authorization_revision::text=original.actor#>>'{context,revision}' AND link.authorization_revision::text=original.actor#>>'{context,linkRevision}'
    AND home.version::text=original.actor#>>'{tenant,version}' AND home.generation::text=original.actor#>>'{tenant,generation}')
  OR EXISTS(SELECT 1 FROM identity_company_pim_policies configuration WHERE configuration.role_id=original.role_id AND NOT identity_company_pim_approver_group_current(configuration.reviewer_group_id,configuration.tenant_id,configuration.reviewer_group_generation))
  OR identity_subject_link_role_state(original.user_id) IS DISTINCT FROM original.actor->'rolesSnapshot' THEN RETURN 'stale';END IF;
 RETURN original.state;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_pim_approval_active(lease identity_company_role_activations) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT CASE WHEN lease.approval_policy_revision=0 THEN lease.approval_request_id IS NULL AND NOT EXISTS(SELECT 1 FROM identity_company_pim_policies policy JOIN identity_company_role_eligibilities eligible ON eligible.role_id=policy.role_id WHERE eligible.id=lease.eligibility_id)
 ELSE EXISTS(SELECT 1 FROM identity_company_role_eligibilities eligible JOIN identity_company_pim_policies policy ON policy.role_id=eligible.role_id AND policy.tenant_id=lease.tenant_id
  WHERE identity_company_pim_approver_group_current(policy.reviewer_group_id,policy.tenant_id,policy.reviewer_group_generation) AND eligible.id=lease.eligibility_id AND policy.revision=lease.approval_policy_revision AND (NOT policy.approval_required AND lease.approval_request_id IS NULL OR policy.approval_required AND EXISTS(
   SELECT 1 FROM identity_company_pim_requests request JOIN identity_company_role_events decision ON decision.id=request.decision_event_id JOIN identity_company_role_outbox outbox ON outbox.id=decision.id AND outbox.tenant_id=decision.tenant_id,
    LATERAL jsonb_array_elements(identity_company_role_pim_candidates(lease.user_id,lease.tenant_id)) candidate
   WHERE request.id=lease.approval_request_id AND request.tenant_id=lease.tenant_id AND request.user_id=lease.user_id AND request.eligibility_id=lease.eligibility_id
    AND request.policy_revision=policy.revision AND request.eligibility_revision=eligible.revision AND request.role_revision=eligible.role_revision
    AND request.state='activated' AND request.activation_id=lease.id AND request.activated_at=lease.created_at AND request.decided_by<>request.user_id
    AND request.approval_expires_at>=lease.created_at AND lease.expires_at-lease.created_at=make_interval(secs=>request.duration_seconds)
    AND request.scope-'validUntil'=candidate-'validUntil' AND lease.expires_at<=to_timestamp((request.scope->>'validUntil')::double precision)
    AND decision.action='pim-request-approve' AND decision.resource_id=request.id AND decision.tenant_id=request.tenant_id AND decision.actor#>>'{context,userId}'=request.decided_by::text
    AND decision.after_state->>'state'='approved' AND decision.after_state->>'decision_event_id'=decision.id::text AND decision.after_state->'scope'=request.scope
    AND decision.after_state->>'policy_revision'=request.policy_revision::text AND decision.after_state->>'eligibility_revision'=request.eligibility_revision::text
    AND decision.after_state->>'duration_seconds'=request.duration_seconds::text AND decision.after_state->>'user_id'=request.user_id::text AND outbox.status='pending'
  ))) END;
$$;

CREATE OR REPLACE FUNCTION identity_company_pim_approval_change(command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;home UUID;operator UUID;identity UUID;values JSONB;moment TIMESTAMPTZ;policy JSONB;candidate JSONB;
 event identity_company_role_events;outbox identity_company_role_outbox;configuration identity_company_pim_policies;old_configuration identity_company_pim_policies;
 request identity_company_pim_requests;previous identity_company_pim_requests;eligible identity_company_role_eligibilities;definition identity_company_roles;
 effects JSONB='[]'::jsonb;effect JSONB;relation TEXT;columns TEXT;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_role_receiving();proof=command->'actor';home=(proof#>>'{tenant,id}')::uuid;operator=(proof#>>'{context,userId}')::uuid;
 PERFORM identity_company_roles_lock(home);values=command->'values';moment=clock_timestamp();identity=(command->>'id')::uuid;
 IF NULLIF(current_setting('opendirectory.company_role_command',true),'') IS NOT NULL THEN RAISE EXCEPTION 'One original role command required' USING ERRCODE='42501';END IF;
 event.id=(command->>'eventId')::uuid;event.tenant_id=home;event.action=command->>'action';event.resource_id=identity;event.actor=proof;event.reason=values->>'reason';event.created_at=moment;event.valid_until=to_timestamp((proof->>'validUntil')::double precision);event.transaction_id=txid_current();
 PERFORM identity_company_role_pim_actor(proof,event.action<>'pim-request-cancel');
 IF event.action='pim-policy-update' AND NOT identity_company_role_manager(proof) THEN RAISE EXCEPTION 'Actual role manager required' USING ERRCODE='42501';END IF;
 IF event.action IN('pim-request-approve','pim-request-deny') AND (proof->'reviewerSource' IS NULL OR identity_company_pim_reviewer_source(proof,(SELECT role_id FROM identity_company_pim_requests WHERE id=identity AND tenant_id=home)) IS DISTINCT FROM proof->'reviewerSource') THEN RAISE EXCEPTION 'Actual independent PIM approver required' USING ERRCODE='42501';END IF;
 IF event.action='pim-policy-update' THEN
  SELECT * INTO definition FROM identity_company_roles WHERE id=identity AND tenant_id=home FOR UPDATE;IF definition.id IS NULL THEN RAISE EXCEPTION 'Own actual role required' USING ERRCODE='23503';END IF;
  SELECT * INTO old_configuration FROM identity_company_pim_policies WHERE role_id=identity AND tenant_id=home FOR UPDATE;
  IF coalesce(old_configuration.revision,0)::text IS DISTINCT FROM command->>'expectedRevision' THEN RAISE EXCEPTION 'Exact policy version required' USING ERRCODE='23514';END IF;
  configuration.role_id=identity;configuration.tenant_id=home;configuration.approval_required=(values->>'approvalRequired')::boolean;configuration.approval_window_seconds=(values->>'windowSeconds')::integer;
  IF old_configuration.reviewer_group_id IS NOT NULL AND NOT values ? 'reviewerGroupId' THEN RAISE EXCEPTION 'Explicit original reviewer group decision required' USING ERRCODE='23514';END IF;
  configuration.reviewer_group_id=(values->>'reviewerGroupId')::uuid;
  IF configuration.reviewer_group_id IS NOT NULL THEN
   SELECT namespace.generation INTO configuration.reviewer_group_generation FROM identity_tenant_ownership namespace WHERE namespace.resource_kind='group' AND namespace.resource_id=configuration.reviewer_group_id AND namespace.tenant_id=home;
   IF NOT configuration.approval_required OR configuration.reviewer_group_generation IS NULL OR NOT identity_company_pim_approver_group_current(configuration.reviewer_group_id,home,configuration.reviewer_group_generation)
    OR NOT EXISTS(SELECT 1 FROM group_members member WHERE member.group_id=configuration.reviewer_group_id AND identity_tenant_id('user',member.user_id::uuid)=home AND identity_tenant_user_enabled(member.user_id::uuid) AND identity_membership_rule_deadline(member.membership_id)>moment)
    THEN RAISE EXCEPTION 'Own protected reviewer group with an enabled current member required' USING ERRCODE='23514';END IF;
  END IF;
  configuration.revision=coalesce(old_configuration.revision,0)+1;configuration.created_at=coalesce(old_configuration.created_at,moment);configuration.updated_at=moment;
  event.before_state=CASE WHEN old_configuration.role_id IS NULL THEN NULL ELSE to_jsonb(old_configuration) END;event.after_state=to_jsonb(configuration);relation='identity_company_pim_policies';
  effects=jsonb_build_array(jsonb_build_object('table',relation,'key','role_id','before',event.before_state,'after',event.after_state));
 ELSIF event.action='pim-request-create' THEN
  SELECT value INTO candidate FROM jsonb_array_elements(identity_company_role_pim_candidates(operator,home)) WHERE value->>'id'=command->>'eligibilityId';
  IF candidate IS NULL THEN RAISE EXCEPTION 'Own current eligibility required' USING ERRCODE='23503';END IF;
  SELECT * INTO eligible FROM identity_company_role_eligibilities WHERE id=(candidate->>'id')::uuid AND tenant_id=home FOR UPDATE;
  SELECT * INTO definition FROM identity_company_roles WHERE id=eligible.role_id AND tenant_id=home FOR UPDATE;policy=identity_company_pim_approval_policy(definition.id);
  IF eligible.revision::text IS DISTINCT FROM command->>'expectedRevision' OR NOT (policy->>'approvalRequired')::boolean OR policy->>'revision' IS DISTINCT FROM values->>'policyRevision'
   OR (values->>'durationSeconds')::integer NOT BETWEEN 60 AND definition.max_duration_seconds OR (candidate->>'validUntil')::numeric<extract(epoch FROM moment)+(values->>'durationSeconds')::integer THEN RAISE EXCEPTION 'Current exact policy and bounded request duration required' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM identity_company_pim_requests old WHERE old.tenant_id=home AND old.user_id=operator AND old.eligibility_id=eligible.id AND identity_company_pim_request_status(old) IN('pending','approved')
   AND old.actor->>'issuer'=proof->>'issuer' AND old.actor->>'subject'=proof->>'subject' AND old.actor->'context'=proof->'context' AND old.actor#>>'{mfa,revision}'=proof#>>'{mfa,revision}') THEN RAISE EXCEPTION 'A current request already exists' USING ERRCODE='23505';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(identity_company_role_pim_sources(operator,home,definition.permissions[1],NULL,NULL)) source WHERE source->>'id'=eligible.id::text AND source->>'mfaRevision'=proof#>>'{mfa,revision}' AND source->'actorContext'=proof->'context') THEN RAISE EXCEPTION 'Eligibility is already active' USING ERRCODE='23505';END IF;
  request.id=identity;request.tenant_id=home;request.role_id=definition.id;request.role_revision=definition.revision;request.eligibility_id=eligible.id;request.eligibility_revision=eligible.revision;
  request.policy_revision=(policy->>'revision')::bigint;request.user_id=operator;request.scope=candidate;request.definition=to_jsonb(definition);request.actor=proof;request.duration_seconds=(values->>'durationSeconds')::integer;request.reason=values->>'reason';request.state='pending';request.revision=1;request.created_at=moment;
  request.expires_at=least(moment+interval '24 hours',to_timestamp((candidate->>'validUntil')::double precision));event.after_state=to_jsonb(request);relation='identity_company_pim_requests';
 ELSE
  SELECT * INTO previous FROM identity_company_pim_requests WHERE id=identity AND tenant_id=home FOR UPDATE;
  IF previous.id IS NULL OR previous.revision::text IS DISTINCT FROM command->>'expectedRevision' THEN RAISE EXCEPTION 'Exact original request required' USING ERRCODE='23514';END IF;
  request=previous;
  IF event.action='pim-request-cancel' THEN
   IF previous.user_id<>operator OR previous.state NOT IN('pending','approved') THEN RAISE EXCEPTION 'Own unconsumed request required' USING ERRCODE='42501';END IF;request.state='cancelled';request.closed_at=moment;request.closed_by=operator;
  ELSIF event.action IN('pim-request-approve','pim-request-deny') THEN
   IF previous.user_id=operator OR identity_company_pim_request_status(previous)<>'pending' THEN RAISE EXCEPTION 'Independent current pending request required' USING ERRCODE='42501';END IF;
   request.decided_at=moment;request.decided_by=operator;request.decision_event_id=event.id;
   IF event.action='pim-request-approve' THEN policy=identity_company_pim_approval_policy(previous.role_id);request.state='approved';request.approval_expires_at=least(previous.expires_at,moment+make_interval(secs=>(policy->>'windowSeconds')::integer));
   ELSE request.state='denied';END IF;
  ELSE RAISE EXCEPTION 'Unknown own PIM approval command' USING ERRCODE='42501';END IF;
  request.revision=request.revision+1;event.before_state=to_jsonb(previous);event.after_state=to_jsonb(request);relation='identity_company_pim_requests';
 END IF;
 IF relation='identity_company_pim_requests' THEN effects=jsonb_build_array(jsonb_build_object('table',relation,'key','id','before',event.before_state,'after',event.after_state));END IF;
 outbox.id=event.id;outbox.tenant_id=home;outbox.status='pending';outbox.created_at=moment;
 effects=effects||jsonb_build_array(jsonb_build_object('table','identity_company_role_events','key','id','before',NULL,'after',to_jsonb(event)),jsonb_build_object('table','identity_company_role_outbox','key','id','before',NULL,'after',to_jsonb(outbox)));
 PERFORM set_config('opendirectory.company_role_command',jsonb_build_object('transactionId',txid_current()::text,'validUntil',proof->'validUntil','effects',effects)::text,true);
 FOR effect IN SELECT value FROM jsonb_array_elements(effects) LOOP
  relation=effect->>'table';
  IF effect->'before'='null'::jsonb THEN EXECUTE format('INSERT INTO %I SELECT (jsonb_populate_record(NULL::%I,$1)).*',relation,relation) USING effect->'after';
  ELSE
   SELECT string_agg(format('%I',attname),',' ORDER BY attnum) INTO columns FROM pg_attribute WHERE attrelid=to_regclass(relation) AND attnum>0 AND NOT attisdropped AND attname<>effect->>'key';
   EXECUTE format('UPDATE %I SET (%s)=(SELECT %s FROM jsonb_populate_record(NULL::%I,$1)) WHERE %I::text=$2',relation,columns,columns,relation,effect->>'key') USING effect->'after',effect->'after'->>(effect->>'key');
  END IF;
 END LOOP;RETURN event.id;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_role_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE envelope JSONB;effect JSONB;actual JSONB;receipt identity_company_role_events;
BEGIN
 PERFORM identity_company_role_receiving();envelope=NULLIF(current_setting('opendirectory.company_role_command',true),'')::jsonb;
 SELECT * INTO receipt FROM identity_company_role_events WHERE id=NEW.id;
 IF envelope IS NULL OR receipt IS DISTINCT FROM NEW OR envelope->>'transactionId' IS DISTINCT FROM txid_current()::text
  OR receipt.valid_until<=clock_timestamp()
  THEN RAISE EXCEPTION 'Original company role source and deadline required' USING ERRCODE='42501';END IF;
 IF receipt.action IN('activation-create','activation-cancel','pim-request-create','pim-request-cancel') THEN
  PERFORM identity_company_role_pim_actor(receipt.actor,receipt.action IN('activation-create','pim-request-create'));
  IF receipt.after_state->>'user_id' IS DISTINCT FROM receipt.actor#>>'{context,userId}' THEN RAISE EXCEPTION 'Original PIM self actor required' USING ERRCODE='42501';END IF;
 ELSE
  IF receipt.action IN('pim-policy-update','pim-request-approve','pim-request-deny') THEN PERFORM identity_company_role_pim_actor(receipt.actor);END IF;
  IF receipt.action IN('pim-request-approve','pim-request-deny') AND (receipt.actor->'reviewerSource' IS NULL OR identity_company_pim_reviewer_source(receipt.actor,(receipt.after_state->>'role_id')::uuid) IS DISTINCT FROM receipt.actor->'reviewerSource') OR receipt.action NOT IN('pim-request-approve','pim-request-deny') AND NOT identity_company_role_manager(receipt.actor) THEN RAISE EXCEPTION 'Original company role manager required' USING ERRCODE='42501';END IF;
 END IF;
 FOR effect IN SELECT value FROM jsonb_array_elements(envelope->'effects') LOOP
  IF effect->>'table' NOT IN('identity_company_pim_policies','identity_company_pim_requests','identity_company_role_eligibilities','identity_company_role_activations','identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox') THEN RAISE EXCEPTION 'Unknown company role receiver' USING ERRCODE='42501';END IF;
  EXECUTE format('SELECT to_jsonb(row) FROM %I row WHERE %I::text=$1',effect->>'table',effect->>'key') INTO actual USING effect->'after'->>(effect->>'key');
  IF actual IS DISTINCT FROM effect->'after' THEN RAISE EXCEPTION 'Actual company role effect and receipt required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF receipt.action IN('pim-request-create','pim-request-approve') AND NOT EXISTS(SELECT 1 FROM identity_company_pim_requests request WHERE request.id=receipt.resource_id AND identity_company_pim_request_status(request)=CASE WHEN receipt.action='pim-request-create' THEN 'pending' ELSE 'approved' END) THEN RAISE EXCEPTION 'Current original request source required at commit' USING ERRCODE='42501';END IF;
 IF receipt.action='pim-policy-update' AND NOT identity_company_pim_approver_group_current((receipt.after_state->>'reviewer_group_id')::uuid,receipt.tenant_id,(receipt.after_state->>'reviewer_group_generation')::bigint) THEN RAISE EXCEPTION 'Current protected reviewer group required at commit' USING ERRCODE='42501';END IF;
 IF receipt.action='eligibility-create' AND NOT identity_company_role_pim_eligibility_current(receipt.resource_id) THEN RAISE EXCEPTION 'Current eligibility source required at commit' USING ERRCODE='42501';END IF;
 IF receipt.action='activation-create' AND NOT EXISTS(SELECT 1 FROM identity_company_role_activations activation JOIN identity_company_role_eligibilities eligible ON eligible.id=activation.eligibility_id JOIN identity_company_roles role ON role.id=eligible.role_id,
  LATERAL jsonb_array_elements(identity_company_role_pim_sources(activation.user_id,activation.tenant_id,role.permissions[1],NULL,NULL)) source
  WHERE activation.id=receipt.resource_id AND source->>'activationId'=activation.id::text AND activation.actor=receipt.actor) THEN RAISE EXCEPTION 'Current exact PIM source required at commit' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_pim_approval_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE entry RECORD;
BEGIN
 IF to_regclass('identity_company_pim_policies') IS NULL OR to_regclass('identity_company_pim_requests') IS NULL OR to_regclass('identity_company_pim_approval_manifest') IS NULL
  THEN RAISE EXCEPTION 'Own PIM approval storage unavailable' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM identity_company_pim_approval_manifest)<>8 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_pim_approval_manifest'::regclass AND tgname='company_pim_approval_manifest_guard' AND tgenabled='O' AND tgfoid='identity_company_group_rule_manifest_guard()'::regprocedure AND tgtype=62)
  THEN RAISE EXCEPTION 'Complete PIM approval manifest required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM identity_company_pim_approval_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original PIM approval receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;

DO $$ DECLARE signature TEXT;BEGIN
 ALTER TABLE identity_company_role_manifest DISABLE TRIGGER company_role_manifest_guard;
 ALTER TABLE identity_company_pim_approval_manifest DISABLE TRIGGER company_pim_approval_manifest_guard;
 UPDATE identity_company_role_manifest entry SET digest=md5(pg_get_functiondef(to_regprocedure(entry.signature))) WHERE entry.signature='identity_company_role_commit()';
 FOREACH signature IN ARRAY ARRAY['identity_company_pim_approval_policy(uuid)','identity_company_pim_request_status(identity_company_pim_requests)',
  'identity_company_pim_approval_active(identity_company_role_activations)','identity_company_pim_approval_change(jsonb)','identity_company_pim_approval_reviewer(jsonb)','identity_company_pim_approval_receiving()',
  'identity_company_pim_approver_group_current(uuid,uuid,bigint)','identity_company_pim_reviewer_source(jsonb,uuid)'] LOOP
  INSERT INTO identity_company_pim_approval_manifest VALUES(signature,md5(pg_get_functiondef(to_regprocedure(signature)))) ON CONFLICT ON CONSTRAINT identity_company_pim_approval_manifest_pkey DO UPDATE SET digest=EXCLUDED.digest;
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
 SET CONSTRAINTS ALL IMMEDIATE;
 ALTER TABLE identity_company_role_manifest ENABLE TRIGGER company_role_manifest_guard;
 ALTER TABLE identity_company_pim_approval_manifest ENABLE TRIGGER company_pim_approval_manifest_guard;
 SET CONSTRAINTS ALL DEFERRED;
END; $$;
COMMIT;
