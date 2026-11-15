BEGIN;
-- Separate device scopes never reuse user OU grants or authorize a tenant-wide receiver.
DO $$ DECLARE relation TEXT;entry RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_role_grants','identity_company_role_eligibilities'] LOOP
  FOR entry IN SELECT conname FROM pg_constraint WHERE conrelid=to_regclass(relation) AND contype='c' AND pg_get_constraintdef(oid) LIKE '%scope_type%' LOOP
   EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I',relation,entry.conname);
  END LOOP;
  EXECUTE format('ALTER TABLE %I ADD CONSTRAINT company_scope_kind CHECK(scope_type IN(''tenant'',''ou'',''device-ou''))',relation);
  EXECUTE format('ALTER TABLE %I ADD CONSTRAINT company_scope_resource CHECK((scope_type=''tenant'' AND ou_id IS NULL AND ou_generation IS NULL) OR (scope_type IN(''ou'',''device-ou'') AND ou_id IS NOT NULL AND ou_generation IS NOT NULL))',relation);
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_role_change(command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;tenant UUID;actor UUID;identity UUID;event identity_company_role_events;outbox identity_company_role_outbox;
 role_row identity_company_roles;old_role identity_company_roles;grant_row identity_company_role_grants;old_grant identity_company_role_grants;
 group_marker identity_company_role_groups;ou_marker identity_company_role_ous;values JSONB;effects JSONB='[]'::jsonb;effect JSONB;moment TIMESTAMPTZ;
 target_generation BIGINT;scope_generation BIGINT;relation TEXT;columns TEXT;creation JSONB;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_role_receiving();proof=command->'actor';tenant=(proof#>>'{tenant,id}')::uuid;actor=(proof#>>'{context,userId}')::uuid;
 PERFORM identity_company_roles_lock(tenant);
 IF NOT identity_company_role_manager(proof) OR (proof->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300
  OR NULLIF(current_setting('opendirectory.company_role_command',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Fresh original company role manager required' USING ERRCODE='42501';END IF;
 values=command->'values';moment=clock_timestamp();identity=(command->>'id')::uuid;
 event.id=(command->>'eventId')::uuid;event.tenant_id=tenant;event.action=command->>'action';event.resource_id=identity;event.actor=proof;event.reason=values->>'reason';
 event.created_at=moment;event.valid_until=to_timestamp((proof->>'validUntil')::double precision);event.transaction_id=txid_current();
 IF event.action IN('role-create','role-update') THEN
  SELECT * INTO old_role FROM identity_company_roles WHERE id=identity AND tenant_id=tenant FOR UPDATE;
  IF event.action='role-create' AND old_role.id IS NOT NULL OR event.action='role-update' AND (old_role.id IS NULL OR old_role.revision::text IS DISTINCT FROM command->>'expectedRevision')
   THEN RAISE EXCEPTION 'Exact current company role required' USING ERRCODE='23514';END IF;
  role_row.id=identity;role_row.tenant_id=tenant;role_row.name=values->>'name';role_row.description=values->>'description';
  role_row.permissions=ARRAY(SELECT jsonb_array_elements_text(values->'permissions'));role_row.max_duration_seconds=(values->>'maxDurationSeconds')::int;role_row.enabled=(values->>'enabled')::boolean;
  role_row.revision=coalesce(old_role.revision,0)+1;role_row.created_at=coalesce(old_role.created_at,moment);role_row.updated_at=moment;
  event.before_state=CASE WHEN old_role.id IS NULL THEN NULL ELSE to_jsonb(old_role) END;event.after_state=to_jsonb(role_row);
  effects=effects||jsonb_build_array(jsonb_build_object('table','identity_company_roles','key','id','before',event.before_state,'after',event.after_state));
 ELSIF event.action='group-protect' THEN
  creation=NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb;
  PERFORM identity_directory_creation_actor(creation);
  IF creation#>>'{resource,id}' IS DISTINCT FROM identity::text OR creation#>>'{resource,kind}' IS DISTINCT FROM 'group'
   OR creation->'context' IS DISTINCT FROM proof->'context' OR creation->'tenant' IS DISTINCT FROM proof->'tenant'
   OR NOT EXISTS(SELECT 1 FROM identity_tenant_ownership ownership WHERE ownership.resource_kind='group' AND ownership.resource_id=identity AND ownership.tenant_id=tenant
    AND ownership.reason='Original-token-bound new-resource creation' AND ownership.created_at>=transaction_timestamp())
   THEN RAISE EXCEPTION 'Only an original newly created group can be role assignable' USING ERRCODE='42501';END IF;
  SELECT namespace.generation INTO target_generation FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=tenant WHERE collection.id=identity AND identity_tenant_id('group',collection.id)=tenant FOR UPDATE OF collection;
  group_marker.group_id=identity;group_marker.tenant_id=tenant;group_marker.generation=target_generation;group_marker.created_at=moment;
  event.after_state=to_jsonb(group_marker);effects=effects||jsonb_build_array(jsonb_build_object('table','identity_company_role_groups','key','group_id','before',NULL,'after',event.after_state));
 ELSIF event.action='grant-create' THEN
  SELECT * INTO role_row FROM identity_company_roles WHERE id=(command->>'roleId')::uuid AND tenant_id=tenant FOR UPDATE;
  IF role_row.id IS NULL OR NOT role_row.enabled OR role_row.revision::text IS DISTINCT FROM command->>'expectedRevision'
   OR (values->>'durationSeconds')::int NOT BETWEEN 60 AND role_row.max_duration_seconds THEN RAISE EXCEPTION 'Current enabled company role and bounded duration required' USING ERRCODE='23514';END IF;
  grant_row.id=identity;grant_row.tenant_id=tenant;grant_row.role_id=role_row.id;grant_row.role_revision=role_row.revision;
  grant_row.target_type=values->>'targetType';grant_row.target_id=(values->>'targetId')::uuid;grant_row.scope_type=values->>'scopeType';grant_row.ou_id=(values->>'ouId')::uuid;
  IF grant_row.target_type='user' THEN
   SELECT eligibility_revision INTO target_generation FROM users WHERE id=grant_row.target_id AND identity_tenant_id('user',id)=tenant AND identity_tenant_user_enabled(id) FOR UPDATE;
   IF grant_row.target_id=actor THEN RAISE EXCEPTION 'Independent company role recipient required' USING ERRCODE='42501';END IF;
  ELSE
   SELECT namespace.generation INTO target_generation FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=tenant JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=tenant AND protected.generation=namespace.generation
    WHERE collection.id=grant_row.target_id AND identity_tenant_id('group',collection.id)=tenant FOR UPDATE OF collection;
   IF EXISTS(SELECT 1 FROM group_members WHERE group_id=grant_row.target_id AND user_id=actor::text) THEN RAISE EXCEPTION 'Independent company role group required' USING ERRCODE='42501';END IF;
  END IF;
  IF target_generation IS NULL THEN RAISE EXCEPTION 'Own active role recipient required' USING ERRCODE='23503';END IF;
  grant_row.target_generation=target_generation;
  IF grant_row.scope_type IN('ou','device-ou') THEN
   IF grant_row.scope_type='ou' AND NOT role_row.permissions<@ARRAY['users.read','users.update','users.status.manage']::text[]
    OR grant_row.scope_type='device-ou' AND NOT role_row.permissions<@ARRAY['devices.inventory.read','devices.inventory.create','devices.inventory.assign','devices.compliance.read']::text[]
    THEN RAISE EXCEPTION 'OU actions must match their user or device scope' USING ERRCODE='23514';END IF;
   SELECT namespace.generation INTO scope_generation FROM ous unit JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=tenant WHERE unit.id=grant_row.ou_id AND identity_tenant_id('ou',unit.id)=tenant FOR UPDATE OF unit;
   IF scope_generation IS NULL THEN RAISE EXCEPTION 'Own OU scope required' USING ERRCODE='23503';END IF;grant_row.ou_generation=scope_generation;
   IF NOT EXISTS(SELECT 1 FROM identity_company_role_ous WHERE ou_id=grant_row.ou_id) THEN
    ou_marker.ou_id=grant_row.ou_id;ou_marker.tenant_id=tenant;ou_marker.generation=scope_generation;ou_marker.created_at=moment;
    effects=effects||jsonb_build_array(jsonb_build_object('table','identity_company_role_ous','key','ou_id','before',NULL,'after',to_jsonb(ou_marker)));
   END IF;
  END IF;
  IF EXISTS(SELECT 1 FROM identity_company_role_grants previous WHERE previous.tenant_id=tenant AND previous.role_id=role_row.id AND previous.role_revision=role_row.revision
   AND previous.target_type=grant_row.target_type AND previous.target_id=grant_row.target_id AND previous.target_generation=grant_row.target_generation
   AND previous.scope_type=grant_row.scope_type AND previous.ou_id IS NOT DISTINCT FROM grant_row.ou_id AND previous.revoked_at IS NULL AND previous.expires_at>moment)
   THEN RAISE EXCEPTION 'Company role already assigned' USING ERRCODE='23505';END IF;
  grant_row.expires_at=moment+make_interval(secs=>(values->>'durationSeconds')::int);grant_row.revision=1;grant_row.created_at=moment;
  event.after_state=to_jsonb(grant_row);effects=effects||jsonb_build_array(jsonb_build_object('table','identity_company_role_grants','key','id','before',NULL,'after',event.after_state));
 ELSIF event.action='grant-revoke' THEN
  SELECT * INTO old_grant FROM identity_company_role_grants WHERE id=identity AND tenant_id=tenant FOR UPDATE;
  IF old_grant.id IS NULL OR old_grant.revoked_at IS NOT NULL OR old_grant.revision::text IS DISTINCT FROM command->>'expectedRevision' THEN RAISE EXCEPTION 'Exact current grant required' USING ERRCODE='23514';END IF;
  grant_row=old_grant;grant_row.revoked_at=moment;grant_row.revision=old_grant.revision+1;event.before_state=to_jsonb(old_grant);event.after_state=to_jsonb(grant_row);
  effects=effects||jsonb_build_array(jsonb_build_object('table','identity_company_role_grants','key','id','before',event.before_state,'after',event.after_state));
 ELSE RAISE EXCEPTION 'Unknown company role command' USING ERRCODE='42501';END IF;
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
  IF eligible.scope_type IN('ou','device-ou') THEN
   IF eligible.scope_type='ou' AND NOT role_row.permissions<@ARRAY['users.read','users.update','users.status.manage']::text[]
    OR eligible.scope_type='device-ou' AND NOT role_row.permissions<@ARRAY['devices.inventory.read','devices.inventory.create','devices.inventory.assign','devices.compliance.read']::text[]
    THEN RAISE EXCEPTION 'OU actions must match their user or device scope' USING ERRCODE='23514';END IF;
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

CREATE OR REPLACE FUNCTION identity_company_role_direct_sources(actor UUID,tenant UUID,permission TEXT,kind TEXT DEFAULT NULL,resource UUID DEFAULT NULL) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT coalesce(jsonb_agg(source ORDER BY source->>'id'),'[]'::jsonb) FROM (
  SELECT jsonb_build_object('id',grant_row.id,'roleId',role.id,'roleRevision',role.revision::text,'scopeType',grant_row.scope_type,'ouId',grant_row.ou_id,
   'targetType',grant_row.target_type,'targetId',grant_row.target_id,'membershipId',member.membership_id,
   'validUntil',floor(extract(epoch FROM least(grant_row.expires_at,CASE WHEN member.membership_id IS NULL THEN 'infinity'::timestamptz ELSE identity_membership_rule_deadline(member.membership_id) END)))::bigint::text) || CASE WHEN grant_row.scope_type='device-ou' THEN jsonb_build_object('ouGeneration',grant_row.ou_generation::text) ELSE '{}'::jsonb END AS source
  FROM identity_company_role_grants grant_row JOIN identity_company_roles role ON role.id=grant_row.role_id AND role.tenant_id=grant_row.tenant_id
  LEFT JOIN group_members member ON grant_row.target_type='group' AND member.group_id=grant_row.target_id AND member.user_id=actor::text
  WHERE grant_row.tenant_id=tenant AND role.enabled AND role.revision=grant_row.role_revision AND permission=ANY(role.permissions)
   AND grant_row.revoked_at IS NULL AND grant_row.expires_at>clock_timestamp() AND identity_tenant_user_enabled(actor) AND identity_tenant_id('user',actor)=tenant
   AND (grant_row.target_type='user' AND grant_row.target_id=actor AND EXISTS(SELECT 1 FROM users WHERE id=actor AND eligibility_revision=grant_row.target_generation)
    OR grant_row.target_type='group' AND member.membership_id IS NOT NULL AND identity_membership_rule_deadline(member.membership_id)>clock_timestamp()
     AND EXISTS(SELECT 1 FROM groups collection JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=tenant
      JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=tenant
      WHERE collection.id=grant_row.target_id AND namespace.generation=grant_row.target_generation AND namespace.generation=protected.generation AND identity_tenant_id('group',collection.id)=tenant))
   AND (grant_row.scope_type='tenant' OR (grant_row.scope_type='ou' AND permission=ANY(ARRAY['users.read','users.update','users.status.manage']::text[])
    OR grant_row.scope_type='device-ou' AND permission=ANY(ARRAY['devices.inventory.read','devices.inventory.create','devices.inventory.assign','devices.compliance.read']::text[])) AND EXISTS(
    SELECT 1 FROM ous unit JOIN identity_company_role_ous protected ON protected.ou_id=unit.id AND protected.tenant_id=tenant
    JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=tenant
    WHERE unit.id=grant_row.ou_id AND namespace.generation=grant_row.ou_generation AND namespace.generation=protected.generation AND identity_tenant_id('ou',unit.id)=tenant
     AND (kind IS NULL OR grant_row.scope_type='ou' AND kind='user' AND EXISTS(SELECT 1 FROM identity_directory_ou_members link WHERE link.user_id=resource AND link.tenant_id=tenant AND identity_company_role_contains(unit.id,link.ou_id,tenant))
      OR grant_row.scope_type='device-ou' AND kind='device-ou' AND EXISTS(SELECT 1 FROM ous selected JOIN identity_tenant_ownership selected_owner ON selected_owner.resource_kind='ou' AND selected_owner.resource_id=selected.id AND selected_owner.tenant_id=tenant WHERE selected.id=resource AND identity_tenant_id('ou',selected.id)=tenant AND identity_company_role_contains(unit.id,selected.id,tenant)))))
 ) sources;
$$;

CREATE OR REPLACE FUNCTION identity_company_role_pim_candidates(actor UUID,tenant UUID) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT coalesce(jsonb_agg(candidate ORDER BY candidate->>'id'),'[]'::jsonb) FROM (
  SELECT jsonb_build_object('id',eligible.id,'roleId',role.id,'roleRevision',role.revision::text,'scopeType',eligible.scope_type,'ouId',eligible.ou_id,
   'targetType',eligible.target_type,'targetId',eligible.target_id,'membershipId',member.membership_id,'userGeneration',account.eligibility_revision::text,
   'validUntil',floor(extract(epoch FROM least(eligible.expires_at,CASE WHEN member.membership_id IS NULL THEN 'infinity'::timestamptz ELSE identity_membership_rule_deadline(member.membership_id) END)))::bigint::text) || CASE WHEN eligible.scope_type='device-ou' THEN jsonb_build_object('ouGeneration',eligible.ou_generation::text) ELSE '{}'::jsonb END candidate
  FROM identity_company_role_eligibilities eligible JOIN identity_company_roles role ON role.id=eligible.role_id AND role.tenant_id=eligible.tenant_id
   JOIN users account ON account.id=actor AND account.enabled AND identity_tenant_id('user',account.id)=tenant
   LEFT JOIN group_members member ON eligible.target_type='group' AND member.group_id=eligible.target_id AND member.user_id=actor::text
  WHERE eligible.tenant_id=tenant AND role.enabled AND role.revision=eligible.role_revision AND eligible.revoked_at IS NULL AND eligible.expires_at>clock_timestamp()
   AND (eligible.target_type='user' AND eligible.target_id=actor AND eligible.target_generation=account.eligibility_revision
    OR eligible.target_type='group' AND member.membership_id IS NOT NULL AND identity_membership_rule_deadline(member.membership_id)>clock_timestamp()
     AND EXISTS(SELECT 1 FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=tenant
      JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=tenant AND protected.generation=namespace.generation
      WHERE collection.id=eligible.target_id AND namespace.generation=eligible.target_generation AND identity_tenant_id('group',collection.id)=tenant))
   AND (eligible.scope_type='tenant' OR (eligible.scope_type='ou' AND role.permissions<@ARRAY['users.read','users.update','users.status.manage']::text[]
    OR eligible.scope_type='device-ou' AND role.permissions<@ARRAY['devices.inventory.read','devices.inventory.create','devices.inventory.assign','devices.compliance.read']::text[]) AND EXISTS(
    SELECT 1 FROM ous unit JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=tenant
     JOIN identity_company_role_ous protected ON protected.ou_id=unit.id AND protected.tenant_id=tenant AND protected.generation=namespace.generation
    WHERE unit.id=eligible.ou_id AND namespace.generation=eligible.ou_generation AND identity_tenant_id('ou',unit.id)=tenant))
 ) candidates;
$$;

CREATE OR REPLACE FUNCTION identity_company_role_pim_eligibility_current(identity UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM identity_company_role_eligibilities eligible JOIN identity_company_roles role ON role.id=eligible.role_id AND role.tenant_id=eligible.tenant_id
 WHERE eligible.id=identity AND eligible.revoked_at IS NULL AND eligible.expires_at>clock_timestamp() AND role.enabled AND role.revision=eligible.role_revision
 AND (eligible.target_type='user' AND EXISTS(SELECT 1 FROM users account WHERE account.id=eligible.target_id AND identity_tenant_user_enabled(account.id) AND identity_tenant_id('user',account.id)=eligible.tenant_id AND account.eligibility_revision=eligible.target_generation)
 OR eligible.target_type='group' AND EXISTS(SELECT 1 FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=eligible.tenant_id
 JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=eligible.tenant_id AND protected.generation=namespace.generation
 WHERE collection.id=eligible.target_id AND namespace.generation=eligible.target_generation AND identity_tenant_id('group',collection.id)=eligible.tenant_id))
 AND (eligible.scope_type='tenant' OR (eligible.scope_type='ou' AND role.permissions<@ARRAY['users.read','users.update','users.status.manage']::text[]
    OR eligible.scope_type='device-ou' AND role.permissions<@ARRAY['devices.inventory.read','devices.inventory.create','devices.inventory.assign','devices.compliance.read']::text[]) AND EXISTS(SELECT 1 FROM ous unit
 JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=eligible.tenant_id
 JOIN identity_company_role_ous protected ON protected.ou_id=unit.id AND protected.tenant_id=eligible.tenant_id AND protected.generation=namespace.generation
 WHERE unit.id=eligible.ou_id AND namespace.generation=eligible.ou_generation AND identity_tenant_id('ou',unit.id)=eligible.tenant_id)));
$$;

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
   AND (candidate->>'scopeType'='tenant' OR kind IS NULL OR candidate->>'scopeType'='ou' AND kind='user' AND EXISTS(SELECT 1 FROM identity_directory_ou_members member
    WHERE member.user_id=resource AND member.tenant_id=tenant AND identity_company_role_contains((candidate->>'ouId')::uuid,member.ou_id,tenant))
    OR candidate->>'scopeType'='device-ou' AND kind='device-ou' AND EXISTS(SELECT 1 FROM ous selected JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=selected.id AND namespace.tenant_id=tenant
     WHERE selected.id=resource AND identity_tenant_id('ou',selected.id)=tenant AND identity_company_role_contains((candidate->>'ouId')::uuid,selected.id,tenant)))
 ) sources;
$$;

DO $$ DECLARE signature TEXT;BEGIN
 FOREACH signature IN ARRAY ARRAY[
  'identity_company_role_change(jsonb)',
  'identity_company_role_pim_change(jsonb)',
  'identity_company_role_direct_sources(uuid,uuid,text,text,uuid)',
  'identity_company_role_pim_candidates(uuid,uuid)',
  'identity_company_role_pim_eligibility_current(uuid)',
  'identity_company_role_pim_sources(uuid,uuid,text,text,uuid)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path FROM CURRENT',signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
 ALTER TABLE identity_company_role_manifest DISABLE TRIGGER company_role_manifest_guard;
 ALTER TABLE identity_company_role_pim_manifest DISABLE TRIGGER company_role_pim_manifest_guard;
 UPDATE identity_company_role_manifest entry SET digest=md5(pg_get_functiondef(to_regprocedure(entry.signature))) WHERE entry.signature='identity_company_role_change(jsonb)';
 UPDATE identity_company_role_pim_manifest entry SET digest=md5(pg_get_functiondef(to_regprocedure(entry.signature))) WHERE entry.signature IN('identity_company_role_direct_sources(uuid,uuid,text,text,uuid)','identity_company_role_pim_change(jsonb)','identity_company_role_pim_candidates(uuid,uuid)','identity_company_role_pim_sources(uuid,uuid,text,text,uuid)','identity_company_role_pim_eligibility_current(uuid)');
 SET CONSTRAINTS ALL IMMEDIATE;
 ALTER TABLE identity_company_role_manifest ENABLE TRIGGER company_role_manifest_guard;
 ALTER TABLE identity_company_role_pim_manifest ENABLE TRIGGER company_role_pim_manifest_guard;
 SET CONSTRAINTS ALL DEFERRED;
 PERFORM identity_company_role_receiving();
END; $$;
COMMIT;
