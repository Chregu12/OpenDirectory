BEGIN;
CREATE TABLE IF NOT EXISTS identity_company_pim_policies (
 role_id UUID PRIMARY KEY REFERENCES identity_company_roles(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 approval_required BOOLEAN NOT NULL,approval_window_seconds INTEGER NOT NULL CHECK(approval_window_seconds BETWEEN 60 AND 3600),
 revision BIGINT NOT NULL CHECK(revision>0),created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_pim_requests (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),role_id UUID NOT NULL REFERENCES identity_company_roles(id),role_revision BIGINT NOT NULL,
 eligibility_id UUID NOT NULL REFERENCES identity_company_role_eligibilities(id),eligibility_revision BIGINT NOT NULL,policy_revision BIGINT NOT NULL CHECK(policy_revision>0),
 user_id UUID NOT NULL,scope JSONB NOT NULL,definition JSONB NOT NULL,actor JSONB NOT NULL,duration_seconds INTEGER NOT NULL CHECK(duration_seconds BETWEEN 60 AND 36000),reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
 state TEXT NOT NULL CHECK(state IN('pending','approved','denied','cancelled','activated')),revision BIGINT NOT NULL CHECK(revision>0),
 created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,decided_at TIMESTAMPTZ,decided_by UUID,decision_event_id UUID REFERENCES identity_company_role_events(id) DEFERRABLE INITIALLY DEFERRED,
 approval_expires_at TIMESTAMPTZ,activation_id UUID REFERENCES identity_company_role_activations(id) DEFERRABLE INITIALLY DEFERRED,activated_at TIMESTAMPTZ,closed_at TIMESTAMPTZ,closed_by UUID,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours'),CHECK((decided_at IS NULL)=(decided_by IS NULL) AND (decided_at IS NULL)=(decision_event_id IS NULL)),
 CHECK(decided_at IS NULL OR decided_at>=created_at),CHECK(approval_expires_at IS NULL OR approval_expires_at>decided_at AND approval_expires_at<=expires_at AND approval_expires_at<=decided_at+interval '1 hour'),
 CHECK((closed_at IS NULL)=(closed_by IS NULL)),CHECK((activation_id IS NULL)=(activated_at IS NULL)),
 CHECK(state<>'pending' OR decided_at IS NULL AND closed_at IS NULL AND activation_id IS NULL),
 CHECK(state<>'approved' OR decided_at IS NOT NULL AND approval_expires_at IS NOT NULL AND closed_at IS NULL AND activation_id IS NULL),
 CHECK(state<>'denied' OR decided_at IS NOT NULL AND approval_expires_at IS NULL AND closed_at IS NULL AND activation_id IS NULL),
 CHECK(state<>'cancelled' OR closed_at IS NOT NULL AND activation_id IS NULL),
 CHECK(state<>'activated' OR decided_at IS NOT NULL AND approval_expires_at IS NOT NULL AND activation_id IS NOT NULL AND closed_at IS NULL)
);
CREATE INDEX IF NOT EXISTS identity_company_pim_request_queue ON identity_company_pim_requests(tenant_id,state,created_at,id);
CREATE INDEX IF NOT EXISTS identity_company_pim_request_self ON identity_company_pim_requests(tenant_id,user_id,eligibility_id);
CREATE UNIQUE INDEX IF NOT EXISTS identity_company_pim_activation_request ON identity_company_pim_requests(activation_id) WHERE activation_id IS NOT NULL;
ALTER TABLE identity_company_role_activations ADD COLUMN IF NOT EXISTS approval_policy_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE identity_company_role_activations ADD COLUMN IF NOT EXISTS approval_request_id UUID REFERENCES identity_company_pim_requests(id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS identity_company_pim_approval_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE OR REPLACE FUNCTION identity_company_pim_approval_policy(identity UUID) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT coalesce((SELECT jsonb_build_object('revision',revision::text,'approvalRequired',approval_required,'windowSeconds',approval_window_seconds) FROM identity_company_pim_policies WHERE role_id=identity),
 jsonb_build_object('revision','0','approvalRequired',false,'windowSeconds',300));
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
  OR identity_subject_link_role_state(original.user_id) IS DISTINCT FROM original.actor->'rolesSnapshot' THEN RETURN 'stale';END IF;
 RETURN original.state;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_pim_approval_active(lease identity_company_role_activations) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT CASE WHEN lease.approval_policy_revision=0 THEN lease.approval_request_id IS NULL AND NOT EXISTS(SELECT 1 FROM identity_company_pim_policies policy JOIN identity_company_role_eligibilities eligible ON eligible.role_id=policy.role_id WHERE eligible.id=lease.eligibility_id)
 ELSE EXISTS(SELECT 1 FROM identity_company_role_eligibilities eligible JOIN identity_company_pim_policies policy ON policy.role_id=eligible.role_id AND policy.tenant_id=lease.tenant_id
  WHERE eligible.id=lease.eligibility_id AND policy.revision=lease.approval_policy_revision AND (NOT policy.approval_required AND lease.approval_request_id IS NULL OR policy.approval_required AND EXISTS(
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
CREATE OR REPLACE FUNCTION identity_company_pim_approval_reviewer(proof JSONB) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor UUID;
BEGIN
 PERFORM identity_directory_creation_actor(proof);actor=(proof#>>'{context,userId}')::uuid;
 IF EXISTS(SELECT 1 FROM identity_company_activations owner WHERE owner.user_id=actor AND owner.tenant_id=(proof#>>'{tenant,id}')::uuid
  AND owner.issuer=proof->>'issuer' AND owner.subject=proof->>'subject' AND identity_company_activation_valid(owner.registration_id) AND identity_company_owner_active(owner)) THEN RETURN true;END IF;
 RETURN EXISTS(SELECT 1 FROM identity_role_assignments assignment JOIN identity_role_activation_policies policy ON policy.role=assignment.role
  LEFT JOIN identity_role_review_leases review ON review.target_kind='assignment' AND review.target_id=assignment.id
  LEFT JOIN identity_pim_requests request ON request.id=assignment.activation_request_id
  WHERE assignment.user_id=actor AND assignment.role IN('admin','role-administrator','pim-approver') AND assignment.revoked_at IS NULL
   AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp()) AND assignment.policy_version=policy.version
   AND (NOT policy.activation_required OR assignment.activation_request_id IS NOT NULL)
   AND (review.id IS NULL OR review.state<>'denied' AND (review.deadline_at IS NULL OR review.deadline_at>identity_role_review_now()))
   AND (assignment.activation_request_id IS NULL OR identity_role_review_eligible(request.eligibility_id)));
END; $$;
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
 IF event.action IN('pim-request-approve','pim-request-deny') AND NOT identity_company_pim_approval_reviewer(proof) THEN RAISE EXCEPTION 'Actual independent PIM approver required' USING ERRCODE='42501';END IF;
 IF event.action='pim-policy-update' THEN
  SELECT * INTO definition FROM identity_company_roles WHERE id=identity AND tenant_id=home FOR UPDATE;IF definition.id IS NULL THEN RAISE EXCEPTION 'Own actual role required' USING ERRCODE='23503';END IF;
  SELECT * INTO old_configuration FROM identity_company_pim_policies WHERE role_id=identity AND tenant_id=home FOR UPDATE;
  IF coalesce(old_configuration.revision,0)::text IS DISTINCT FROM command->>'expectedRevision' THEN RAISE EXCEPTION 'Exact policy version required' USING ERRCODE='23514';END IF;
  configuration.role_id=identity;configuration.tenant_id=home;configuration.approval_required=(values->>'approvalRequired')::boolean;configuration.approval_window_seconds=(values->>'windowSeconds')::integer;
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

CREATE OR REPLACE FUNCTION identity_company_role_pim_sources(subject_id UUID,tenant UUID,permission TEXT,kind TEXT DEFAULT NULL,resource UUID DEFAULT NULL) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT coalesce(jsonb_agg(source ORDER BY source->>'id',source->>'activationId'),'[]'::jsonb) FROM (
  SELECT (candidate-'userGeneration')||jsonb_build_object('activationId',activation.id,'mfaRevision',activation.actor#>>'{mfa,revision}','authTime',activation.actor#>>'{mfa,authTime}',
   'issuer',activation.actor->>'issuer','subject',activation.actor->>'subject','actorContext',activation.actor->'context',
   'validUntil',least((candidate->>'validUntil')::bigint,floor(extract(epoch FROM activation.expires_at))::bigint)::text) source
  FROM jsonb_array_elements(identity_company_role_pim_candidates(subject_id,tenant)) candidate
   JOIN identity_company_roles role ON role.id=(candidate->>'roleId')::uuid
   JOIN identity_company_role_activations activation ON activation.eligibility_id=(candidate->>'id')::uuid AND activation.tenant_id=tenant AND activation.user_id=subject_id
   JOIN users account ON account.id=subject_id
   JOIN identity_subject_links link ON link.user_id=subject_id AND link.issuer=activation.actor->>'issuer' AND link.subject=activation.actor->>'subject'
   JOIN identity_tenants home ON home.id=tenant AND home.enabled
   JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=tenant
  WHERE permission=ANY(role.permissions) AND activation.ended_at IS NULL AND activation.expires_at>clock_timestamp() AND identity_company_pim_approval_active(activation)
   AND activation.user_generation::text=candidate->>'userGeneration' AND activation.membership_id IS NOT DISTINCT FROM (candidate->>'membershipId')::uuid
   AND activation.actor->'rolesSnapshot'=identity_subject_link_role_state(subject_id)
   AND account.authorization_revision::text=activation.actor#>>'{context,revision}' AND link.authorization_revision::text=activation.actor#>>'{context,linkRevision}'
   AND home.version::text=activation.actor#>>'{tenant,version}' AND home.generation::text=activation.actor#>>'{tenant,generation}'
   AND (candidate->>'scopeType'='tenant' OR kind IS NULL OR kind='user' AND EXISTS(SELECT 1 FROM identity_directory_ou_members member
    WHERE member.user_id=resource AND member.tenant_id=tenant AND identity_company_role_contains((candidate->>'ouId')::uuid,member.ou_id,tenant)))
 ) sources;
$$;
CREATE OR REPLACE FUNCTION identity_company_role_pim_change(command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;tenant UUID;actor UUID;identity UUID;event identity_company_role_events;outbox identity_company_role_outbox;
 role_row identity_company_roles;eligible identity_company_role_eligibilities;old_eligible identity_company_role_eligibilities;
 activation identity_company_role_activations;old_activation identity_company_role_activations;marker identity_company_role_ous;
 approval_policy JSONB;approval identity_company_pim_requests;approval_before JSONB;values JSONB;effects JSONB='[]'::jsonb;effect JSONB;moment TIMESTAMPTZ;generation BIGINT;scope_generation BIGINT;candidate JSONB;relation TEXT;columns TEXT;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_role_receiving();proof=command->'actor';tenant=(proof#>>'{tenant,id}')::uuid;actor=(proof#>>'{context,userId}')::uuid;
 PERFORM identity_company_roles_lock(tenant);values=command->'values';moment=clock_timestamp();identity=(command->>'id')::uuid;
 IF NULLIF(current_setting('opendirectory.company_role_command',true),'') IS NOT NULL THEN RAISE EXCEPTION 'One original role command required' USING ERRCODE='42501';END IF;
 event.id=(command->>'eventId')::uuid;event.tenant_id=tenant;event.action=command->>'action';event.resource_id=identity;event.actor=proof;event.reason=values->>'reason';
 event.created_at=moment;event.valid_until=to_timestamp((proof->>'validUntil')::double precision);event.transaction_id=txid_current();
 IF event.action IN('eligibility-create','eligibility-revoke','activation-revoke') THEN
  PERFORM identity_company_role_pim_actor(proof);IF NOT identity_company_role_manager(proof) THEN RAISE EXCEPTION 'Original independent role manager required' USING ERRCODE='42501';END IF;
 ELSE PERFORM identity_company_role_pim_actor(proof,event.action<>'activation-cancel');END IF;
 IF event.action='eligibility-create' THEN
  SELECT * INTO role_row FROM identity_company_roles WHERE id=(command->>'roleId')::uuid AND tenant_id=tenant FOR UPDATE;
  IF role_row.id IS NULL OR NOT role_row.enabled OR role_row.revision::text IS DISTINCT FROM command->>'expectedRevision' OR (values->>'validForSeconds')::int NOT BETWEEN 60 AND 31536000
   THEN RAISE EXCEPTION 'Current role and bounded eligibility required' USING ERRCODE='23514';END IF;
  eligible.id=identity;eligible.tenant_id=tenant;eligible.role_id=role_row.id;eligible.role_revision=role_row.revision;
  eligible.target_type=values->>'targetType';eligible.target_id=(values->>'targetId')::uuid;eligible.scope_type=values->>'scopeType';eligible.ou_id=(values->>'ouId')::uuid;
  IF eligible.target_type='user' THEN
   SELECT eligibility_revision INTO generation FROM users WHERE id=eligible.target_id AND identity_tenant_id('user',id)=tenant AND identity_tenant_user_enabled(id) FOR UPDATE;
   IF eligible.target_id=actor THEN RAISE EXCEPTION 'Independent eligibility recipient required' USING ERRCODE='42501';END IF;
  ELSE
   SELECT namespace.generation INTO generation FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=tenant
    JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=tenant AND protected.generation=namespace.generation
    WHERE collection.id=eligible.target_id AND identity_tenant_id('group',collection.id)=tenant FOR UPDATE OF collection;
   IF EXISTS(SELECT 1 FROM group_members WHERE group_id=eligible.target_id AND user_id=actor::text) THEN RAISE EXCEPTION 'Independent eligibility group required' USING ERRCODE='42501';END IF;
  END IF;
  IF generation IS NULL THEN RAISE EXCEPTION 'Own active eligibility recipient required' USING ERRCODE='23503';END IF;eligible.target_generation=generation;
  IF eligible.scope_type='ou' THEN
   IF NOT role_row.permissions<@ARRAY['users.read','users.update','users.status.manage']::text[] THEN RAISE EXCEPTION 'OU scope supports user actions only' USING ERRCODE='23514';END IF;
   SELECT namespace.generation INTO scope_generation FROM ous unit JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=tenant
    WHERE unit.id=eligible.ou_id AND identity_tenant_id('ou',unit.id)=tenant FOR UPDATE OF unit;
   IF scope_generation IS NULL THEN RAISE EXCEPTION 'Own OU scope required' USING ERRCODE='23503';END IF;eligible.ou_generation=scope_generation;
   IF NOT EXISTS(SELECT 1 FROM identity_company_role_ous WHERE ou_id=eligible.ou_id) THEN
    marker.ou_id=eligible.ou_id;marker.tenant_id=tenant;marker.generation=scope_generation;marker.created_at=moment;
    effects=effects||jsonb_build_array(jsonb_build_object('table','identity_company_role_ous','key','ou_id','before',NULL,'after',to_jsonb(marker)));
   END IF;
  END IF;
  IF EXISTS(SELECT 1 FROM identity_company_role_eligibilities previous WHERE previous.tenant_id=tenant AND previous.role_id=role_row.id AND previous.role_revision=role_row.revision
   AND previous.target_type=eligible.target_type AND previous.target_id=eligible.target_id AND previous.target_generation=eligible.target_generation
   AND previous.scope_type=eligible.scope_type AND previous.ou_id IS NOT DISTINCT FROM eligible.ou_id AND previous.revoked_at IS NULL AND previous.expires_at>moment)
   THEN RAISE EXCEPTION 'Eligibility already assigned' USING ERRCODE='23505';END IF;
  eligible.expires_at=moment+make_interval(secs=>(values->>'validForSeconds')::int);eligible.revision=1;eligible.created_at=moment;
  event.after_state=to_jsonb(eligible);relation='identity_company_role_eligibilities';
 ELSIF event.action='eligibility-revoke' THEN
  SELECT * INTO old_eligible FROM identity_company_role_eligibilities WHERE id=identity AND tenant_id=tenant FOR UPDATE;
  IF old_eligible.id IS NULL OR old_eligible.revoked_at IS NOT NULL OR old_eligible.revision::text IS DISTINCT FROM command->>'expectedRevision' THEN RAISE EXCEPTION 'Exact eligibility required' USING ERRCODE='23514';END IF;
  eligible=old_eligible;eligible.revoked_at=moment;eligible.revision=eligible.revision+1;event.before_state=to_jsonb(old_eligible);event.after_state=to_jsonb(eligible);relation='identity_company_role_eligibilities';
 ELSIF event.action='activation-create' THEN
  SELECT value INTO candidate FROM jsonb_array_elements(identity_company_role_pim_candidates(actor,tenant)) WHERE value->>'id'=command->>'eligibilityId';
  IF candidate IS NULL THEN RAISE EXCEPTION 'Current own activation eligibility required' USING ERRCODE='23503';END IF;
  SELECT * INTO eligible FROM identity_company_role_eligibilities WHERE id=(candidate->>'id')::uuid AND tenant_id=tenant FOR UPDATE;
  SELECT * INTO role_row FROM identity_company_roles WHERE id=eligible.role_id AND tenant_id=tenant FOR UPDATE;
  IF eligible.revision::text IS DISTINCT FROM command->>'expectedRevision' OR (values->>'durationSeconds')::int NOT BETWEEN 60 AND role_row.max_duration_seconds
   OR (candidate->>'validUntil')::numeric<floor(extract(epoch FROM moment))+(values->>'durationSeconds')::int THEN RAISE EXCEPTION 'Exact eligibility and remaining activation duration required' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(identity_company_role_pim_sources(actor,tenant,role_row.permissions[1],NULL,NULL)) source WHERE source->>'id'=eligible.id::text AND source->>'mfaRevision'=proof#>>'{mfa,revision}' AND source->'actorContext'=proof->'context' AND (source->>'authTime')::numeric<=(proof#>>'{mfa,authTime}')::numeric)
   THEN RAISE EXCEPTION 'Eligibility already active' USING ERRCODE='23505';END IF;
  approval_policy=identity_company_pim_approval_policy(role_row.id);
  IF (approval_policy->>'approvalRequired')::boolean THEN
   SELECT * INTO approval FROM identity_company_pim_requests WHERE id=(command->>'requestId')::uuid AND tenant_id=tenant FOR UPDATE;
   IF approval.id IS NULL OR identity_company_pim_request_status(approval)<>'approved' OR approval.revision::text IS DISTINCT FROM command->>'requestRevision'
    OR approval.user_id<>actor OR approval.eligibility_id<>eligible.id OR approval.eligibility_revision<>eligible.revision OR approval.role_revision<>role_row.revision OR approval.policy_revision::text IS DISTINCT FROM approval_policy->>'revision'
    OR approval.duration_seconds IS DISTINCT FROM (values->>'durationSeconds')::integer OR approval.scope-'validUntil' IS DISTINCT FROM candidate-'validUntil'
    OR approval.actor->>'issuer' IS DISTINCT FROM proof->>'issuer' OR approval.actor->>'subject' IS DISTINCT FROM proof->>'subject' OR approval.actor->'context' IS DISTINCT FROM proof->'context'
    OR approval.actor#>>'{mfa,revision}' IS DISTINCT FROM proof#>>'{mfa,revision}' OR (approval.actor#>>'{mfa,authTime}')::numeric>(proof#>>'{mfa,authTime}')::numeric
    OR (proof->>'validUntil')::numeric>extract(epoch FROM approval.approval_expires_at)
    THEN RAISE EXCEPTION 'Exact independently approved original activation request required' USING ERRCODE='42501';END IF;
   approval_before=to_jsonb(approval);approval.state='activated';approval.activation_id=identity;approval.activated_at=moment;approval.revision=approval.revision+1;
   effects=effects||jsonb_build_array(jsonb_build_object('table','identity_company_pim_requests','key','id','before',approval_before,'after',to_jsonb(approval)));
  ELSIF command->>'requestId' IS NOT NULL THEN RAISE EXCEPTION 'Original approval policy changed' USING ERRCODE='23514';END IF;
  activation.approval_policy_revision=(approval_policy->>'revision')::bigint;activation.approval_request_id=approval.id;
  activation.id=identity;activation.tenant_id=tenant;activation.eligibility_id=eligible.id;activation.user_id=actor;activation.user_generation=(candidate->>'userGeneration')::bigint;
  activation.membership_id=(candidate->>'membershipId')::uuid;activation.actor=proof;activation.revision=1;activation.created_at=moment;activation.expires_at=moment+make_interval(secs=>(values->>'durationSeconds')::int);
  event.after_state=to_jsonb(activation)||jsonb_build_object('role_id',role_row.id);IF approval.id IS NOT NULL THEN event.after_state=event.after_state||jsonb_build_object('approval_request_before',approval_before,'approval_request_after',to_jsonb(approval));END IF;relation='identity_company_role_activations';
 ELSIF event.action IN('activation-cancel','activation-revoke') THEN
  SELECT * INTO old_activation FROM identity_company_role_activations WHERE id=identity AND tenant_id=tenant FOR UPDATE;
  IF old_activation.id IS NULL OR old_activation.ended_at IS NOT NULL OR old_activation.revision::text IS DISTINCT FROM command->>'expectedRevision'
   OR event.action='activation-cancel' AND old_activation.user_id<>actor OR event.action='activation-revoke' AND old_activation.user_id=actor
   THEN RAISE EXCEPTION 'Exact independently authorized activation required' USING ERRCODE='23514';END IF;
  activation=old_activation;activation.ended_at=moment;activation.ended_by=actor;activation.revision=activation.revision+1;
  SELECT * INTO eligible FROM identity_company_role_eligibilities WHERE id=activation.eligibility_id;
  event.before_state=to_jsonb(old_activation);event.after_state=to_jsonb(activation)||jsonb_build_object('role_id',eligible.role_id);relation='identity_company_role_activations';
 ELSE RAISE EXCEPTION 'Unknown company PIM command' USING ERRCODE='42501';END IF;
 effects=effects||jsonb_build_array(jsonb_build_object('table',relation,'key','id','before',event.before_state,'after',CASE WHEN relation='identity_company_role_activations' THEN to_jsonb(activation) ELSE to_jsonb(eligible) END));
 outbox.id=event.id;outbox.tenant_id=tenant;outbox.status='pending';outbox.created_at=moment;
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
  IF receipt.action IN('pim-request-approve','pim-request-deny') AND NOT identity_company_pim_approval_reviewer(receipt.actor) OR receipt.action NOT IN('pim-request-approve','pim-request-deny') AND NOT identity_company_role_manager(receipt.actor) THEN RAISE EXCEPTION 'Original company role manager required' USING ERRCODE='42501';END IF;
 END IF;
 FOR effect IN SELECT value FROM jsonb_array_elements(envelope->'effects') LOOP
  IF effect->>'table' NOT IN('identity_company_pim_policies','identity_company_pim_requests','identity_company_role_eligibilities','identity_company_role_activations','identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox') THEN RAISE EXCEPTION 'Unknown company role receiver' USING ERRCODE='42501';END IF;
  EXECUTE format('SELECT to_jsonb(row) FROM %I row WHERE %I::text=$1',effect->>'table',effect->>'key') INTO actual USING effect->'after'->>(effect->>'key');
  IF actual IS DISTINCT FROM effect->'after' THEN RAISE EXCEPTION 'Actual company role effect and receipt required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF receipt.action IN('pim-request-create','pim-request-approve') AND NOT EXISTS(SELECT 1 FROM identity_company_pim_requests request WHERE request.id=receipt.resource_id AND identity_company_pim_request_status(request)=CASE WHEN receipt.action='pim-request-create' THEN 'pending' ELSE 'approved' END) THEN RAISE EXCEPTION 'Current original request source required at commit' USING ERRCODE='42501';END IF;
 IF receipt.action='eligibility-create' AND NOT identity_company_role_pim_eligibility_current(receipt.resource_id) THEN RAISE EXCEPTION 'Current eligibility source required at commit' USING ERRCODE='42501';END IF;
 IF receipt.action='activation-create' AND NOT EXISTS(SELECT 1 FROM identity_company_role_activations activation JOIN identity_company_role_eligibilities eligible ON eligible.id=activation.eligibility_id JOIN identity_company_roles role ON role.id=eligible.role_id,
  LATERAL jsonb_array_elements(identity_company_role_pim_sources(activation.user_id,activation.tenant_id,role.permissions[1],NULL,NULL)) source
  WHERE activation.id=receipt.resource_id AND source->>'activationId'=activation.id::text AND activation.actor=receipt.actor) THEN RAISE EXCEPTION 'Current exact PIM source required at commit' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;entry RECORD;
BEGIN
 PERFORM identity_directory_ou_receiving();PERFORM identity_company_role_pim_receiving();PERFORM identity_company_pim_approval_receiving();
 FOREACH relation IN ARRAY ARRAY['identity_company_pim_policies','identity_company_pim_requests','identity_company_role_eligibilities','identity_company_role_activations','identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='identity_company_role_guard' AND tgenabled='O' AND tgfoid='identity_company_role_guard()'::regprocedure AND tgtype=31)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='identity_company_role_truncate' AND tgenabled='O' AND tgfoid='identity_company_role_guard()'::regprocedure AND tgtype=34)
   THEN RAISE EXCEPTION 'Company role row receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_role_events'::regclass AND tgname='identity_company_role_commit' AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_company_role_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Company role commit receiver unavailable' USING ERRCODE='42501';END IF;
 FOREACH relation IN ARRAY ARRAY['groups','group_members','ous','identity_directory_ou_members','identity_company_group_rules'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='identity_company_role_directory_guard' AND tgenabled='O' AND tgfoid='identity_company_role_directory_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'Protected directory receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF (SELECT count(*) FROM identity_company_role_manifest)<>17 THEN RAISE EXCEPTION 'Complete company role manifest required' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_role_uses'::regclass AND tgname='identity_company_role_usage_guard' AND tgenabled='O' AND tgfoid='identity_company_role_usage_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_role_uses'::regclass AND tgname='identity_company_role_usage_truncate' AND tgenabled='O' AND tgfoid='identity_company_role_usage_guard()'::regprocedure AND tgtype=34)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_role_uses'::regclass AND tgname='identity_company_role_usage_commit' AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_company_role_usage_commit()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_role_manifest'::regclass AND tgname='company_role_manifest_guard' AND tgenabled='O' AND tgfoid='identity_company_group_rule_manifest_guard()'::regprocedure)
  THEN RAISE EXCEPTION 'Custom role use receivers unavailable' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM identity_company_role_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Company role source changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_pim_approval_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE entry RECORD;
BEGIN
 IF to_regclass('identity_company_pim_policies') IS NULL OR to_regclass('identity_company_pim_requests') IS NULL OR to_regclass('identity_company_pim_approval_manifest') IS NULL
  THEN RAISE EXCEPTION 'Own PIM approval storage unavailable' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM identity_company_pim_approval_manifest)<>6 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_pim_approval_manifest'::regclass AND tgname='company_pim_approval_manifest_guard' AND tgenabled='O' AND tgfoid='identity_company_group_rule_manifest_guard()'::regprocedure AND tgtype=62)
  THEN RAISE EXCEPTION 'Complete PIM approval manifest required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM identity_company_pim_approval_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original PIM approval receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;
DO $$ DECLARE relation TEXT;signature TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_pim_policies','identity_company_pim_requests'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_company_role_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_role_guard()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_company_role_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_role_guard()',relation);
 END LOOP;
 CREATE OR REPLACE TRIGGER company_pim_approval_manifest_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON identity_company_pim_approval_manifest FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_manifest_guard();
 ALTER TABLE identity_company_role_manifest DISABLE TRIGGER company_role_manifest_guard;
 ALTER TABLE identity_company_role_pim_manifest DISABLE TRIGGER company_role_pim_manifest_guard;
 ALTER TABLE identity_company_pim_approval_manifest DISABLE TRIGGER company_pim_approval_manifest_guard;
 UPDATE identity_company_role_manifest entry SET digest=md5(pg_get_functiondef(to_regprocedure(entry.signature))) WHERE entry.signature IN('identity_company_role_commit()','identity_company_role_receiving()');
 UPDATE identity_company_role_pim_manifest entry SET digest=md5(pg_get_functiondef(to_regprocedure(entry.signature))) WHERE entry.signature IN('identity_company_role_pim_change(jsonb)','identity_company_role_pim_sources(uuid,uuid,text,text,uuid)');
 FOREACH signature IN ARRAY ARRAY['identity_company_pim_approval_policy(uuid)','identity_company_pim_request_status(identity_company_pim_requests)',
  'identity_company_pim_approval_active(identity_company_role_activations)','identity_company_pim_approval_change(jsonb)','identity_company_pim_approval_reviewer(jsonb)','identity_company_pim_approval_receiving()'] LOOP
  INSERT INTO identity_company_pim_approval_manifest VALUES(signature,md5(pg_get_functiondef(to_regprocedure(signature)))) ON CONFLICT ON CONSTRAINT identity_company_pim_approval_manifest_pkey DO UPDATE SET digest=EXCLUDED.digest;
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
 SET CONSTRAINTS ALL IMMEDIATE;
 ALTER TABLE identity_company_role_manifest ENABLE TRIGGER company_role_manifest_guard;
 ALTER TABLE identity_company_role_pim_manifest ENABLE TRIGGER company_role_pim_manifest_guard;
 ALTER TABLE identity_company_pim_approval_manifest ENABLE TRIGGER company_pim_approval_manifest_guard;
 SET CONSTRAINTS ALL DEFERRED;
END; $$;

DO $$ DECLARE relation TEXT;hook RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_pim_policies','identity_company_pim_requests','identity_company_pim_approval_manifest'] LOOP
  EXECUTE format('REVOKE ALL ON %I FROM PUBLIC',relation);
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
  EXECUTE format('CREATE OR REPLACE TRIGGER aaa_identity_employee_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_employee_fence()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_employee_effect_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_employee_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_employee_effect_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_employee_effect_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_employee_fence()',relation);
 END LOOP;
END; $$;

COMMIT;
