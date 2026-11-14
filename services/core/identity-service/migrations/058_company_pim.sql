BEGIN;
CREATE TABLE IF NOT EXISTS identity_company_role_eligibilities (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),role_id UUID NOT NULL REFERENCES identity_company_roles(id),role_revision BIGINT NOT NULL,
 target_type TEXT NOT NULL CHECK(target_type IN('user','group')),target_id UUID NOT NULL,target_generation BIGINT NOT NULL,
 scope_type TEXT NOT NULL CHECK(scope_type IN('tenant','ou')),ou_id UUID,ou_generation BIGINT,
 expires_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ,revision BIGINT NOT NULL CHECK(revision>0),created_at TIMESTAMPTZ NOT NULL,
 CHECK((scope_type='tenant' AND ou_id IS NULL AND ou_generation IS NULL) OR (scope_type='ou' AND ou_id IS NOT NULL AND ou_generation IS NOT NULL)),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '365 days')
);
CREATE INDEX IF NOT EXISTS identity_company_role_eligibility_lookup ON identity_company_role_eligibilities(tenant_id,target_id,role_id);
CREATE TABLE IF NOT EXISTS identity_company_role_activations (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),eligibility_id UUID NOT NULL REFERENCES identity_company_role_eligibilities(id),
 user_id UUID NOT NULL,user_generation BIGINT NOT NULL,membership_id UUID,actor JSONB NOT NULL,revision BIGINT NOT NULL CHECK(revision>0),
 created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,ended_at TIMESTAMPTZ,ended_by UUID,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '10 hours'),CHECK((ended_at IS NULL)=(ended_by IS NULL))
);
CREATE INDEX IF NOT EXISTS identity_company_role_activation_lookup ON identity_company_role_activations(tenant_id,user_id,eligibility_id);
CREATE TABLE IF NOT EXISTS identity_company_role_pim_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE OR REPLACE FUNCTION identity_company_role_pim_candidates(actor UUID,tenant UUID) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT coalesce(jsonb_agg(candidate ORDER BY candidate->>'id'),'[]'::jsonb) FROM (
  SELECT jsonb_build_object('id',eligible.id,'roleId',role.id,'roleRevision',role.revision::text,'scopeType',eligible.scope_type,'ouId',eligible.ou_id,
   'targetType',eligible.target_type,'targetId',eligible.target_id,'membershipId',member.membership_id,'userGeneration',account.eligibility_revision::text,
   'validUntil',floor(extract(epoch FROM least(eligible.expires_at,CASE WHEN member.membership_id IS NULL THEN 'infinity'::timestamptz ELSE identity_membership_rule_deadline(member.membership_id) END)))::bigint::text) candidate
  FROM identity_company_role_eligibilities eligible JOIN identity_company_roles role ON role.id=eligible.role_id AND role.tenant_id=eligible.tenant_id
   JOIN users account ON account.id=actor AND account.enabled AND identity_tenant_id('user',account.id)=tenant
   LEFT JOIN group_members member ON eligible.target_type='group' AND member.group_id=eligible.target_id AND member.user_id=actor::text
  WHERE eligible.tenant_id=tenant AND role.enabled AND role.revision=eligible.role_revision AND eligible.revoked_at IS NULL AND eligible.expires_at>clock_timestamp()
   AND (eligible.target_type='user' AND eligible.target_id=actor AND eligible.target_generation=account.eligibility_revision
    OR eligible.target_type='group' AND member.membership_id IS NOT NULL AND identity_membership_rule_deadline(member.membership_id)>clock_timestamp()
     AND EXISTS(SELECT 1 FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=tenant
      JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=tenant AND protected.generation=namespace.generation
      WHERE collection.id=eligible.target_id AND namespace.generation=eligible.target_generation AND identity_tenant_id('group',collection.id)=tenant))
   AND (eligible.scope_type='tenant' OR role.permissions<@ARRAY['users.read','users.update','users.status.manage']::text[] AND EXISTS(
    SELECT 1 FROM ous unit JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=tenant
     JOIN identity_company_role_ous protected ON protected.ou_id=unit.id AND protected.tenant_id=tenant AND protected.generation=namespace.generation
    WHERE unit.id=eligible.ou_id AND namespace.generation=eligible.ou_generation AND identity_tenant_id('ou',unit.id)=tenant))
 ) candidates;
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
  WHERE permission=ANY(role.permissions) AND activation.ended_at IS NULL AND activation.expires_at>clock_timestamp()
   AND activation.user_generation::text=candidate->>'userGeneration' AND activation.membership_id IS NOT DISTINCT FROM (candidate->>'membershipId')::uuid
   AND activation.actor->'rolesSnapshot'=identity_subject_link_role_state(subject_id)
   AND account.authorization_revision::text=activation.actor#>>'{context,revision}' AND link.authorization_revision::text=activation.actor#>>'{context,linkRevision}'
   AND home.version::text=activation.actor#>>'{tenant,version}' AND home.generation::text=activation.actor#>>'{tenant,generation}'
   AND (candidate->>'scopeType'='tenant' OR kind IS NULL OR kind='user' AND EXISTS(SELECT 1 FROM identity_directory_ou_members member
    WHERE member.user_id=resource AND member.tenant_id=tenant AND identity_company_role_contains((candidate->>'ouId')::uuid,member.ou_id,tenant)))
 ) sources;
$$;
CREATE OR REPLACE FUNCTION identity_company_role_covers(actor UUID,tenant UUID,permission TEXT,kind TEXT,resource UUID,captured JSONB) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(identity_company_role_sources(actor,tenant,permission,kind,resource)) actual WHERE captured @> jsonb_build_array(actual));
$$;
CREATE OR REPLACE FUNCTION identity_company_role_pim_actor(proof JSONB,fresh BOOLEAN DEFAULT true) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_directory_creation_actor(proof);
 IF fresh AND (proof#>>'{mfa,userId}' IS DISTINCT FROM proof#>>'{context,userId}' OR (proof#>'{mfa,methods}' IN ('["pwd","otp"]'::jsonb,'["federated","otp"]'::jsonb)) IS DISTINCT FROM true OR proof#>>'{mfa,schemaVersion}' IS DISTINCT FROM '1'
  OR (proof#>>'{mfa,authTime}')::numeric>extract(epoch FROM clock_timestamp())+5 OR (proof->>'validUntil')::numeric>(proof#>>'{mfa,authTime}')::numeric+300
  OR proof#>>'{mfa,revision}' IS NULL OR proof#>>'{mfa,authTime}' IS NULL) THEN RAISE EXCEPTION 'Fresh original bound MFA activation required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_pim_change(command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;tenant UUID;actor UUID;identity UUID;event identity_company_role_events;outbox identity_company_role_outbox;
 role_row identity_company_roles;eligible identity_company_role_eligibilities;old_eligible identity_company_role_eligibilities;
 activation identity_company_role_activations;old_activation identity_company_role_activations;marker identity_company_role_ous;
 values JSONB;effects JSONB='[]'::jsonb;effect JSONB;moment TIMESTAMPTZ;generation BIGINT;scope_generation BIGINT;candidate JSONB;relation TEXT;columns TEXT;
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
  activation.id=identity;activation.tenant_id=tenant;activation.eligibility_id=eligible.id;activation.user_id=actor;activation.user_generation=(candidate->>'userGeneration')::bigint;
  activation.membership_id=(candidate->>'membershipId')::uuid;activation.actor=proof;activation.revision=1;activation.created_at=moment;activation.expires_at=moment+make_interval(secs=>(values->>'durationSeconds')::int);
  event.after_state=to_jsonb(activation)||jsonb_build_object('role_id',role_row.id);relation='identity_company_role_activations';
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
   'validUntil',floor(extract(epoch FROM least(grant_row.expires_at,CASE WHEN member.membership_id IS NULL THEN 'infinity'::timestamptz ELSE identity_membership_rule_deadline(member.membership_id) END)))::bigint::text) AS source
  FROM identity_company_role_grants grant_row JOIN identity_company_roles role ON role.id=grant_row.role_id AND role.tenant_id=grant_row.tenant_id
  LEFT JOIN group_members member ON grant_row.target_type='group' AND member.group_id=grant_row.target_id AND member.user_id=actor::text
  WHERE grant_row.tenant_id=tenant AND role.enabled AND role.revision=grant_row.role_revision AND permission=ANY(role.permissions)
   AND grant_row.revoked_at IS NULL AND grant_row.expires_at>clock_timestamp() AND identity_tenant_user_enabled(actor) AND identity_tenant_id('user',actor)=tenant
   AND (grant_row.target_type='user' AND grant_row.target_id=actor AND EXISTS(SELECT 1 FROM users WHERE id=actor AND eligibility_revision=grant_row.target_generation)
    OR grant_row.target_type='group' AND member.membership_id IS NOT NULL AND identity_membership_rule_deadline(member.membership_id)>clock_timestamp()
     AND EXISTS(SELECT 1 FROM groups collection JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=tenant
      JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=tenant
      WHERE collection.id=grant_row.target_id AND namespace.generation=grant_row.target_generation AND namespace.generation=protected.generation AND identity_tenant_id('group',collection.id)=tenant))
   AND (grant_row.scope_type='tenant' OR permission=ANY(ARRAY['users.read','users.update','users.status.manage']) AND EXISTS(
    SELECT 1 FROM ous unit JOIN identity_company_role_ous protected ON protected.ou_id=unit.id AND protected.tenant_id=tenant
    JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=tenant
    WHERE unit.id=grant_row.ou_id AND namespace.generation=grant_row.ou_generation AND namespace.generation=protected.generation AND identity_tenant_id('ou',unit.id)=tenant
     AND (kind IS NULL OR kind='user' AND EXISTS(SELECT 1 FROM identity_directory_ou_members link WHERE link.user_id=resource AND link.tenant_id=tenant AND identity_company_role_contains(unit.id,link.ou_id,tenant)))))
 ) sources;
$$;
CREATE OR REPLACE FUNCTION identity_company_role_sources(actor UUID,tenant UUID,permission TEXT,kind TEXT DEFAULT NULL,resource UUID DEFAULT NULL) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT coalesce(jsonb_agg(source ORDER BY source->>'id',source->>'activationId'),'[]'::jsonb) FROM jsonb_array_elements(
 identity_company_role_direct_sources(actor,tenant,permission,kind,resource)||identity_company_role_pim_sources(actor,tenant,permission,kind,resource)) source;
$$;
CREATE OR REPLACE FUNCTION identity_company_role_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE envelope JSONB;effect JSONB;actual JSONB;receipt identity_company_role_events;
BEGIN
 PERFORM identity_company_role_receiving();envelope=NULLIF(current_setting('opendirectory.company_role_command',true),'')::jsonb;
 SELECT * INTO receipt FROM identity_company_role_events WHERE id=NEW.id;
 IF envelope IS NULL OR receipt IS DISTINCT FROM NEW OR envelope->>'transactionId' IS DISTINCT FROM txid_current()::text
  OR receipt.valid_until<=clock_timestamp()
  THEN RAISE EXCEPTION 'Original company role source and deadline required' USING ERRCODE='42501';END IF;
 IF receipt.action IN('activation-create','activation-cancel') THEN
  PERFORM identity_company_role_pim_actor(receipt.actor,receipt.action='activation-create');
  IF receipt.after_state->>'user_id' IS DISTINCT FROM receipt.actor#>>'{context,userId}' THEN RAISE EXCEPTION 'Original PIM self actor required' USING ERRCODE='42501';END IF;
 ELSE
  IF NOT identity_company_role_manager(receipt.actor) THEN RAISE EXCEPTION 'Original company role manager required' USING ERRCODE='42501';END IF;
 END IF;
 FOR effect IN SELECT value FROM jsonb_array_elements(envelope->'effects') LOOP
  IF effect->>'table' NOT IN('identity_company_role_eligibilities','identity_company_role_activations','identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox') THEN RAISE EXCEPTION 'Unknown company role receiver' USING ERRCODE='42501';END IF;
  EXECUTE format('SELECT to_jsonb(row) FROM %I row WHERE %I::text=$1',effect->>'table',effect->>'key') INTO actual USING effect->'after'->>(effect->>'key');
  IF actual IS DISTINCT FROM effect->'after' THEN RAISE EXCEPTION 'Actual company role effect and receipt required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF receipt.action='eligibility-create' AND NOT identity_company_role_pim_eligibility_current(receipt.resource_id) THEN RAISE EXCEPTION 'Current eligibility source required at commit' USING ERRCODE='42501';END IF;
 IF receipt.action='activation-create' AND NOT EXISTS(SELECT 1 FROM identity_company_role_activations activation JOIN identity_company_role_eligibilities eligible ON eligible.id=activation.eligibility_id JOIN identity_company_roles role ON role.id=eligible.role_id,
  LATERAL jsonb_array_elements(identity_company_role_pim_sources(activation.user_id,activation.tenant_id,role.permissions[1],NULL,NULL)) source
  WHERE activation.id=receipt.resource_id AND source->>'activationId'=activation.id::text AND activation.actor=receipt.actor) THEN RAISE EXCEPTION 'Current exact PIM source required at commit' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;entry RECORD;
BEGIN
 PERFORM identity_directory_ou_receiving();PERFORM identity_company_role_pim_receiving();
 FOREACH relation IN ARRAY ARRAY['identity_company_role_eligibilities','identity_company_role_activations','identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox'] LOOP
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
CREATE OR REPLACE FUNCTION identity_company_role_admit_use(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt identity_company_role_uses;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_role_receiving();
 IF NOT (proof ? 'companyRoles' OR proof ? 'companyGovernance') OR NULLIF(current_setting('opendirectory.company_role_use',true),'') IS NOT NULL
  OR (proof->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300 AND (NOT proof ? 'companyRoles' OR EXISTS(SELECT 1 FROM jsonb_array_elements(proof#>'{companyRoles,grants}') item WHERE NOT item->'source' ? 'activationId')) THEN RAISE EXCEPTION 'Exact fresh original custom role admission required' USING ERRCODE='42501';END IF;
 receipt.id=coalesce(proof->>'operationId',proof#>>'{resource,id}')::uuid;receipt.tenant_id=(proof#>>'{tenant,id}')::uuid;
 receipt.resource_kind=coalesce(proof#>>'{companyRoles,kind}',proof#>>'{resource,kind}',CASE WHEN proof#>'{target,before}' ? 'parent_id' THEN 'ou' ELSE 'group' END);receipt.resource_id=coalesce(proof#>>'{companyRoles,id}',proof#>>'{resource,id}',proof#>>'{target,id}')::uuid;receipt.proof=proof;receipt.transaction_id=txid_current();receipt.created_at=clock_timestamp();
 PERFORM set_config('opendirectory.company_role_use',to_jsonb(receipt)::text,true);
 PERFORM identity_directory_creation_actor(proof);PERFORM identity_company_role_use(proof);PERFORM identity_company_role_governance_use(proof);
 INSERT INTO identity_company_role_uses SELECT receipt.*;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_pim_eligibility_current(identity UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM identity_company_role_eligibilities eligible JOIN identity_company_roles role ON role.id=eligible.role_id AND role.tenant_id=eligible.tenant_id
 WHERE eligible.id=identity AND eligible.revoked_at IS NULL AND eligible.expires_at>clock_timestamp() AND role.enabled AND role.revision=eligible.role_revision
 AND (eligible.target_type='user' AND EXISTS(SELECT 1 FROM users account WHERE account.id=eligible.target_id AND identity_tenant_user_enabled(account.id) AND identity_tenant_id('user',account.id)=eligible.tenant_id AND account.eligibility_revision=eligible.target_generation)
 OR eligible.target_type='group' AND EXISTS(SELECT 1 FROM groups collection JOIN identity_tenant_ownership namespace ON namespace.resource_kind='group' AND namespace.resource_id=collection.id AND namespace.tenant_id=eligible.tenant_id
 JOIN identity_company_role_groups protected ON protected.group_id=collection.id AND protected.tenant_id=eligible.tenant_id AND protected.generation=namespace.generation
 WHERE collection.id=eligible.target_id AND namespace.generation=eligible.target_generation AND identity_tenant_id('group',collection.id)=eligible.tenant_id))
 AND (eligible.scope_type='tenant' OR role.permissions<@ARRAY['users.read','users.update','users.status.manage']::text[] AND EXISTS(SELECT 1 FROM ous unit
 JOIN identity_tenant_ownership namespace ON namespace.resource_kind='ou' AND namespace.resource_id=unit.id AND namespace.tenant_id=eligible.tenant_id
 JOIN identity_company_role_ous protected ON protected.ou_id=unit.id AND protected.tenant_id=eligible.tenant_id AND protected.generation=namespace.generation
 WHERE unit.id=eligible.ou_id AND namespace.generation=eligible.ou_generation AND identity_tenant_id('ou',unit.id)=eligible.tenant_id)));
$$;
CREATE OR REPLACE FUNCTION identity_company_role_pim_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE entry RECORD;
BEGIN
 IF to_regclass('identity_company_role_eligibilities') IS NULL OR to_regclass('identity_company_role_activations') IS NULL
  OR to_regclass('identity_company_role_pim_manifest') IS NULL THEN RAISE EXCEPTION 'Company PIM storage unavailable' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM identity_company_role_pim_manifest)<>8 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_role_pim_manifest'::regclass AND tgname='company_role_pim_manifest_guard' AND tgenabled='O' AND tgfoid='identity_company_group_rule_manifest_guard()'::regprocedure AND tgtype=62)
  THEN RAISE EXCEPTION 'Complete company PIM manifest required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM identity_company_role_pim_manifest LOOP
  IF entry.digest IS DISTINCT FROM md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original company PIM receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;
DO $$ DECLARE relation TEXT;signature TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_role_eligibilities','identity_company_role_activations'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_company_role_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_role_guard()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_company_role_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_role_guard()',relation);
 END LOOP;
 CREATE OR REPLACE TRIGGER company_role_pim_manifest_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON identity_company_role_pim_manifest FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_manifest_guard();
 ALTER TABLE identity_company_role_manifest DISABLE TRIGGER company_role_manifest_guard;
 UPDATE identity_company_role_manifest entry SET digest=md5(pg_get_functiondef(to_regprocedure(entry.signature))) WHERE entry.signature IN('identity_company_role_sources(uuid,uuid,text,text,uuid)','identity_company_role_commit()','identity_company_role_receiving()','identity_company_role_admit_use(jsonb)');
 ALTER TABLE identity_company_role_pim_manifest DISABLE TRIGGER company_role_pim_manifest_guard;
 FOREACH signature IN ARRAY ARRAY['identity_company_role_pim_candidates(uuid,uuid)','identity_company_role_pim_sources(uuid,uuid,text,text,uuid)',
  'identity_company_role_covers(uuid,uuid,text,text,uuid,jsonb)','identity_company_role_pim_actor(jsonb,boolean)','identity_company_role_pim_change(jsonb)',
  'identity_company_role_direct_sources(uuid,uuid,text,text,uuid)','identity_company_role_pim_eligibility_current(uuid)','identity_company_role_pim_receiving()'] LOOP
  INSERT INTO identity_company_role_pim_manifest VALUES(signature,md5(pg_get_functiondef(to_regprocedure(signature)))) ON CONFLICT ON CONSTRAINT identity_company_role_pim_manifest_pkey DO UPDATE SET digest=EXCLUDED.digest;
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
 SET CONSTRAINTS ALL IMMEDIATE;
 ALTER TABLE identity_company_role_manifest ENABLE TRIGGER company_role_manifest_guard;
 ALTER TABLE identity_company_role_pim_manifest ENABLE TRIGGER company_role_pim_manifest_guard;
 SET CONSTRAINTS ALL DEFERRED;
END; $$;

DO $$ DECLARE relation TEXT;hook RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_role_eligibilities','identity_company_role_activations','identity_company_role_pim_manifest'] LOOP
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
