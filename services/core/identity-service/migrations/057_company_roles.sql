BEGIN;
CREATE TABLE IF NOT EXISTS identity_company_roles (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),name TEXT NOT NULL,description TEXT NOT NULL,
 permissions TEXT[] NOT NULL,max_duration_seconds INTEGER NOT NULL CHECK(max_duration_seconds BETWEEN 60 AND 36000),enabled BOOLEAN NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0),created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
 CHECK(length(name) BETWEEN 2 AND 120 AND length(description)<=1000),
 CHECK(cardinality(permissions)>0 AND permissions<@ARRAY['users.read','users.create','users.update','users.status.manage','groups.read','groups.create','groups.update','groups.delete','groups.members.manage','ous.read','ous.create','ous.update','ous.delete','ous.members.manage']::text[])
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_company_role_names ON identity_company_roles(tenant_id,lower(name));
CREATE TABLE IF NOT EXISTS identity_company_role_groups (
 group_id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),generation BIGINT NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_role_ous (
 ou_id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),generation BIGINT NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_role_grants (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),role_id UUID NOT NULL REFERENCES identity_company_roles(id),role_revision BIGINT NOT NULL,
 target_type TEXT NOT NULL CHECK(target_type IN('user','group')),target_id UUID NOT NULL,target_generation BIGINT NOT NULL,
 scope_type TEXT NOT NULL CHECK(scope_type IN('tenant','ou')),ou_id UUID,ou_generation BIGINT,
 expires_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ,revision BIGINT NOT NULL CHECK(revision>0),created_at TIMESTAMPTZ NOT NULL,
 CHECK((scope_type='tenant' AND ou_id IS NULL AND ou_generation IS NULL) OR (scope_type='ou' AND ou_id IS NOT NULL AND ou_generation IS NOT NULL)),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '10 hours')
);
CREATE INDEX IF NOT EXISTS identity_company_role_grant_lookup ON identity_company_role_grants(tenant_id,target_id,role_id);
CREATE TABLE IF NOT EXISTS identity_company_role_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),action TEXT NOT NULL,resource_id UUID NOT NULL,
 actor JSONB NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),before_state JSONB,after_state JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_role_outbox(id UUID PRIMARY KEY REFERENCES identity_company_role_events(id),tenant_id UUID NOT NULL,status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS identity_company_role_uses (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,resource_kind TEXT NOT NULL CHECK(resource_kind IN('user','group','ou')),resource_id UUID NOT NULL,
 proof JSONB NOT NULL,transaction_id BIGINT NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_role_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE OR REPLACE FUNCTION identity_company_roles_lock(tenant UUID) RETURNS void LANGUAGE sql VOLATILE AS $$
 SELECT pg_advisory_xact_lock(hashtextextended('company-roles:'||tenant::text,0));
$$;
CREATE OR REPLACE FUNCTION identity_company_role_manager(proof JSONB) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor UUID;
BEGIN
 PERFORM identity_directory_creation_actor(proof);actor=(proof#>>'{context,userId}')::uuid;
 IF EXISTS(SELECT 1 FROM identity_company_activations owner WHERE owner.user_id=actor AND owner.tenant_id=(proof#>>'{tenant,id}')::uuid
  AND owner.issuer=proof->>'issuer' AND owner.subject=proof->>'subject' AND identity_company_activation_valid(owner.registration_id) AND identity_company_owner_active(owner)) THEN RETURN true;END IF;
 RETURN EXISTS(SELECT 1 FROM identity_role_assignments assignment JOIN identity_role_activation_policies policy ON policy.role=assignment.role
  LEFT JOIN identity_role_review_leases review ON review.target_kind='assignment' AND review.target_id=assignment.id
  LEFT JOIN identity_pim_requests request ON request.id=assignment.activation_request_id
  WHERE assignment.user_id=actor AND assignment.role IN('admin','role-administrator') AND assignment.revoked_at IS NULL
   AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp()) AND assignment.policy_version=policy.version
   AND (NOT policy.activation_required OR assignment.activation_request_id IS NOT NULL)
   AND (review.id IS NULL OR review.state<>'denied' AND (review.deadline_at IS NULL OR review.deadline_at>identity_role_review_now()))
   AND (assignment.activation_request_id IS NULL OR identity_role_review_eligible(request.eligibility_id)));
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_contains(root UUID,unit UUID,tenant UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 WITH RECURSIVE tree AS (
  SELECT id,parent_id,ARRAY[id] AS path FROM ous WHERE id=unit AND identity_tenant_id('ou',id)=tenant
  UNION ALL SELECT parent.id,parent.parent_id,tree.path||parent.id FROM ous parent JOIN tree ON parent.id=tree.parent_id
  WHERE cardinality(tree.path)<256 AND NOT parent.id=ANY(tree.path) AND identity_tenant_id('ou',parent.id)=tenant)
 SELECT EXISTS(SELECT 1 FROM tree WHERE id=root);
$$;
CREATE OR REPLACE FUNCTION identity_company_role_sources(actor UUID,tenant UUID,permission TEXT,kind TEXT DEFAULT NULL,resource UUID DEFAULT NULL) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
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
CREATE OR REPLACE FUNCTION identity_company_role_use(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE item JSONB;captured JSONB;kind TEXT;resource UUID;actual JSONB;
BEGIN
 IF NOT proof ? 'companyRoles' THEN RETURN;END IF;
 PERFORM identity_company_role_receiving();
 IF NULLIF(current_setting('opendirectory.company_role_use',true),'')::jsonb->'proof' IS DISTINCT FROM proof THEN RAISE EXCEPTION 'Original custom role use admission required' USING ERRCODE='42501';END IF;
 captured=proof->'companyRoles';kind=captured->>'kind';resource=(captured->>'id')::uuid;
 IF kind NOT IN('user','group','ou') OR resource::text IS DISTINCT FROM coalesce(proof#>>'{resource,id}',proof#>>'{target,id}')
  OR proof ? 'resource' AND kind IS DISTINCT FROM proof#>>'{resource,kind}' OR jsonb_typeof(captured->'grants') IS DISTINCT FROM 'array' OR jsonb_array_length(captured->'grants')=0
  THEN RAISE EXCEPTION 'Exact custom directory resource required' USING ERRCODE='42501';END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(captured->'grants') LOOP
  actual=identity_company_role_sources((proof#>>'{context,userId}')::uuid,(proof#>>'{tenant,id}')::uuid,item->>'permission',kind,resource);
  IF NOT actual @> jsonb_build_array(item->'source') OR (proof->>'validUntil')::numeric>(item#>>'{source,validUntil}')::numeric
   OR split_part(item->>'permission','.',1) IS DISTINCT FROM (CASE kind WHEN 'user' THEN 'users' WHEN 'group' THEN 'groups' ELSE 'ous' END)
   THEN RAISE EXCEPTION 'Original custom role source changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE envelope JSONB;effect JSONB;before_data JSONB;after_data JSONB;matched BOOLEAN=false;
BEGIN
 IF TG_OP IN('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Retained company role records required' USING ERRCODE='42501';END IF;
 envelope=NULLIF(current_setting('opendirectory.company_role_command',true),'')::jsonb;
 IF envelope IS NULL OR envelope->>'transactionId' IS DISTINCT FROM txid_current()::text OR (envelope->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  THEN RAISE EXCEPTION 'Original company role command required' USING ERRCODE='42501';END IF;
 before_data=CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD) END;after_data=to_jsonb(NEW);
 FOR effect IN SELECT value FROM jsonb_array_elements(envelope->'effects') LOOP
  IF effect->>'table'=TG_TABLE_NAME AND effect->'before' IS NOT DISTINCT FROM coalesce(before_data,'null'::jsonb) AND effect->'after'=after_data THEN matched=true;END IF;
 END LOOP;
 IF NOT matched THEN RAISE EXCEPTION 'Exact company role effect required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE envelope JSONB;effect JSONB;actual JSONB;receipt identity_company_role_events;
BEGIN
 PERFORM identity_company_role_receiving();envelope=NULLIF(current_setting('opendirectory.company_role_command',true),'')::jsonb;
 SELECT * INTO receipt FROM identity_company_role_events WHERE id=NEW.id;
 IF envelope IS NULL OR receipt IS DISTINCT FROM NEW OR envelope->>'transactionId' IS DISTINCT FROM txid_current()::text
  OR receipt.valid_until<=clock_timestamp() OR NOT identity_company_role_manager(receipt.actor)
  THEN RAISE EXCEPTION 'Original company role source and deadline required' USING ERRCODE='42501';END IF;
 FOR effect IN SELECT value FROM jsonb_array_elements(envelope->'effects') LOOP
  IF effect->>'table' NOT IN('identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox') THEN RAISE EXCEPTION 'Unknown company role receiver' USING ERRCODE='42501';END IF;
  EXECUTE format('SELECT to_jsonb(row) FROM %I row WHERE %I::text=$1',effect->>'table',effect->>'key') INTO actual USING effect->'after'->>(effect->>'key');
  IF actual IS DISTINCT FROM effect->'after' THEN RAISE EXCEPTION 'Actual company role effect and receipt required' USING ERRCODE='42501';END IF;
 END LOOP;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;entry RECORD;
BEGIN
 PERFORM identity_directory_ou_receiving();
 FOREACH relation IN ARRAY ARRAY['identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox'] LOOP
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
  IF grant_row.scope_type='ou' THEN
   IF NOT role_row.permissions<@ARRAY['users.read','users.update','users.status.manage']::text[] THEN RAISE EXCEPTION 'OU scope supports user actions only' USING ERRCODE='23514';END IF;
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
CREATE OR REPLACE FUNCTION identity_company_role_governance_use(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE governance JSONB;
BEGIN
 IF NOT proof ? 'companyGovernance' THEN RETURN;END IF;PERFORM identity_company_role_receiving();governance=proof->'companyGovernance';
 IF governance->'context' IS DISTINCT FROM proof->'context' OR governance->'tenant' IS DISTINCT FROM proof->'tenant'
  OR governance->>'issuer' IS DISTINCT FROM proof->>'issuer' OR governance->>'subject' IS DISTINCT FROM proof->>'subject'
  OR (proof->>'validUntil')::numeric>(governance->>'validUntil')::numeric OR NOT identity_company_role_manager(governance)
  OR NULLIF(current_setting('opendirectory.company_role_use',true),'')::jsonb->'proof' IS DISTINCT FROM proof
  THEN RAISE EXCEPTION 'Original protected directory manager changed' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_usage_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF TG_OP<>'INSERT' OR NULLIF(current_setting('opendirectory.company_role_use',true),'')::jsonb IS DISTINCT FROM to_jsonb(NEW)
  OR NEW.transaction_id<>txid_current() THEN RAISE EXCEPTION 'Original retained custom role use required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_admit_use(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt identity_company_role_uses;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_role_receiving();
 IF NOT (proof ? 'companyRoles' OR proof ? 'companyGovernance') OR NULLIF(current_setting('opendirectory.company_role_use',true),'') IS NOT NULL
  OR (proof->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300 THEN RAISE EXCEPTION 'Exact fresh original custom role admission required' USING ERRCODE='42501';END IF;
 receipt.id=coalesce(proof->>'operationId',proof#>>'{resource,id}')::uuid;receipt.tenant_id=(proof#>>'{tenant,id}')::uuid;
 receipt.resource_kind=coalesce(proof#>>'{companyRoles,kind}',proof#>>'{resource,kind}',CASE WHEN proof#>'{target,before}' ? 'parent_id' THEN 'ou' ELSE 'group' END);receipt.resource_id=coalesce(proof#>>'{companyRoles,id}',proof#>>'{resource,id}',proof#>>'{target,id}')::uuid;receipt.proof=proof;receipt.transaction_id=txid_current();receipt.created_at=clock_timestamp();
 PERFORM set_config('opendirectory.company_role_use',to_jsonb(receipt)::text,true);
 PERFORM identity_directory_creation_actor(proof);PERFORM identity_company_role_use(proof);PERFORM identity_company_role_governance_use(proof);
 INSERT INTO identity_company_role_uses SELECT receipt.*;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_usage_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE confirmed BOOLEAN=false;
BEGIN
 PERFORM identity_company_role_receiving();PERFORM identity_directory_creation_actor(NEW.proof);PERFORM identity_company_role_use(NEW.proof);PERFORM identity_company_role_governance_use(NEW.proof);
 IF NEW.proof ? 'resource' THEN
  SELECT EXISTS(SELECT 1 FROM identity_tenant_ownership owner JOIN identity_tenant_events event ON event.tenant_id=owner.tenant_id
   JOIN identity_tenant_outbox outbox ON outbox.id=event.id AND outbox.tenant_id=event.tenant_id
   WHERE owner.resource_id=NEW.resource_id AND owner.resource_kind=NEW.resource_kind AND owner.tenant_id=NEW.tenant_id
    AND owner.reason='Original-token-bound new-resource creation' AND event.action='resource-created' AND event.details->>'resourceId'=NEW.resource_id::text
    AND event.details->>'kind'=NEW.resource_kind AND event.details->>'contentSha256'=encode(sha256(convert_to((NEW.proof#>'{resource,values}')::text,'UTF8')),'hex')) INTO confirmed;
 ELSIF NEW.resource_kind='user' THEN
  SELECT EXISTS(SELECT 1 FROM identity_directory_user_events event JOIN identity_directory_user_outbox outbox USING(id)
   WHERE event.id=NEW.id AND event.tenant_id=NEW.tenant_id AND event.user_id=NEW.resource_id AND event.transaction_id=NEW.transaction_id
    AND event.scope_sha256=encode(sha256(convert_to(NEW.proof::text,'UTF8')),'hex') AND outbox.tenant_id=event.tenant_id AND outbox.status='pending') INTO confirmed;
 ELSIF NEW.resource_kind='group' THEN
  SELECT EXISTS(SELECT 1 FROM identity_directory_group_events event JOIN identity_directory_group_outbox outbox USING(id)
   WHERE event.id=NEW.id AND event.tenant_id=NEW.tenant_id AND event.group_id=NEW.resource_id AND event.transaction_id=NEW.transaction_id
    AND event.scope_sha256=encode(sha256(convert_to(NEW.proof::text,'UTF8')),'hex') AND outbox.tenant_id=event.tenant_id AND outbox.status='pending') INTO confirmed;
 ELSE
  SELECT EXISTS(SELECT 1 FROM identity_directory_ou_events event JOIN identity_directory_ou_outbox outbox USING(id)
   WHERE event.id=NEW.id AND event.tenant_id=NEW.tenant_id AND event.ou_id=NEW.resource_id AND event.transaction_id=NEW.transaction_id
    AND event.proof=NEW.proof AND outbox.tenant_id=event.tenant_id AND outbox.status='pending') INTO confirmed;
 END IF;
 IF NOT confirmed OR NULLIF(current_setting('opendirectory.company_role_use',true),'')::jsonb IS DISTINCT FROM to_jsonb(NEW)
  OR NOT EXISTS(SELECT 1 FROM identity_company_role_uses WHERE id=NEW.id AND to_jsonb(identity_company_role_uses)=to_jsonb(NEW))
  THEN RAISE EXCEPTION 'Actual custom role effect, source and original receipt required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_role_protected(kind TEXT,identity UUID,parent UUID DEFAULT NULL) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT CASE kind WHEN 'group' THEN EXISTS(SELECT 1 FROM identity_company_role_groups WHERE group_id=identity)
 WHEN 'ou' THEN EXISTS(SELECT 1 FROM identity_company_role_ous root WHERE identity_company_role_contains(root.ou_id,identity,root.tenant_id)
  OR parent IS NOT NULL AND identity_company_role_contains(root.ou_id,parent,root.tenant_id)) ELSE false END;
$$;
CREATE OR REPLACE FUNCTION identity_company_role_directory_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE data JSONB;kind TEXT;identity UUID;parent UUID;proof JSONB;governance JSONB;
BEGIN
 data=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 kind=CASE WHEN TG_TABLE_NAME IN('groups','group_members','identity_company_group_rules') THEN 'group' ELSE 'ou' END;
 identity=(CASE WHEN TG_TABLE_NAME IN('groups','ous') THEN data->>'id' WHEN kind='group' THEN data->>'group_id' ELSE data->>'ou_id' END)::uuid;
 IF TG_TABLE_NAME='ous' THEN parent=(data->>'parent_id')::uuid;END IF;
 IF NOT identity_company_role_protected(kind,identity,parent) THEN RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;END IF;
 IF TG_TABLE_NAME='identity_company_group_rules' THEN RAISE EXCEPTION 'Role-assignable groups must remain static' USING ERRCODE='23514';END IF;
 proof=CASE WHEN kind='group' THEN NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb
  WHEN TG_OP='INSERT' AND TG_TABLE_NAME='ous' THEN NULLIF(current_setting('opendirectory.directory_creation',true),'')::jsonb
  ELSE NULLIF(current_setting('opendirectory.ou_mutation',true),'')::jsonb->'proof' END;
 governance=proof->'companyGovernance';
 IF TG_TABLE_NAME='group_members' AND TG_OP='INSERT' AND data->>'user_id'=proof#>>'{context,userId}' THEN RAISE EXCEPTION 'Independent role group membership operator required' USING ERRCODE='42501';END IF;
 PERFORM identity_company_role_governance_use(proof);
 IF governance IS NULL OR governance->'context' IS DISTINCT FROM proof->'context' OR governance->'tenant' IS DISTINCT FROM proof->'tenant'
  OR (governance->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300 OR NOT identity_company_role_manager(governance)
  THEN RAISE EXCEPTION 'Fresh independent role manager required for protected group or OU changes' USING ERRCODE='42501';END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END; $$;
CREATE OR REPLACE TRIGGER company_role_manifest_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON identity_company_role_manifest FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_manifest_guard();
DROP TRIGGER IF EXISTS identity_company_role_usage_guard ON identity_company_role_uses;
CREATE TRIGGER identity_company_role_usage_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_company_role_uses FOR EACH ROW EXECUTE FUNCTION identity_company_role_usage_guard();
DROP TRIGGER IF EXISTS identity_company_role_usage_truncate ON identity_company_role_uses;
CREATE TRIGGER identity_company_role_usage_truncate BEFORE TRUNCATE ON identity_company_role_uses FOR EACH STATEMENT EXECUTE FUNCTION identity_company_role_usage_guard();
DROP TRIGGER IF EXISTS identity_company_role_usage_commit ON identity_company_role_uses;
CREATE CONSTRAINT TRIGGER identity_company_role_usage_commit AFTER INSERT ON identity_company_role_uses DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_role_usage_commit();
DO $$ DECLARE relation TEXT;definition TEXT;signature TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_role_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_company_role_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_role_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_role_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_company_role_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_role_guard()',relation);
 END LOOP;
 DROP TRIGGER IF EXISTS identity_company_role_commit ON identity_company_role_events;
 CREATE CONSTRAINT TRIGGER identity_company_role_commit AFTER INSERT ON identity_company_role_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_role_commit();
 FOREACH relation IN ARRAY ARRAY['groups','group_members','ous','identity_directory_ou_members','identity_company_group_rules'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_role_directory_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_company_role_directory_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_role_directory_guard()',relation);
 END LOOP;
 definition=pg_get_functiondef('identity_directory_creation_actor(jsonb)'::regprocedure);
 IF strpos(definition,'identity_company_role_use(proof)')=0 THEN definition=replace(definition,E'BEGIN\n',E'BEGIN\n IF proof ? ''companyRoles'' THEN PERFORM identity_company_role_use(proof);END IF;\n');END IF;EXECUTE definition;
 ALTER TABLE identity_company_group_rule_app_manifest DISABLE TRIGGER company_group_rule_app_manifest_guard;
 ALTER TABLE identity_employee_enrollment_manifest DISABLE TRIGGER employee_enrollment_evidence;
 UPDATE identity_company_group_rule_app_manifest entry SET digest=md5(pg_get_functiondef(to_regprocedure(entry.signature))) WHERE entry.signature='identity_directory_creation_actor(jsonb)';
 UPDATE identity_employee_enrollment_manifest entry SET digest=md5(pg_get_functiondef(to_regprocedure(entry.signature))) WHERE entry.signature='identity_directory_creation_actor(jsonb)';
 SET CONSTRAINTS ALL IMMEDIATE;
 ALTER TABLE identity_company_group_rule_app_manifest ENABLE TRIGGER company_group_rule_app_manifest_guard;
 ALTER TABLE identity_employee_enrollment_manifest ENABLE TRIGGER employee_enrollment_evidence;
 SET CONSTRAINTS ALL DEFERRED;
 ALTER TABLE identity_company_role_manifest DISABLE TRIGGER company_role_manifest_guard;
 FOREACH signature IN ARRAY ARRAY['identity_company_roles_lock(uuid)','identity_company_role_manager(jsonb)','identity_company_role_contains(uuid,uuid,uuid)',
  'identity_company_role_sources(uuid,uuid,text,text,uuid)','identity_company_role_use(jsonb)','identity_company_role_guard()','identity_company_role_commit()',
  'identity_company_role_change(jsonb)','identity_company_role_usage_guard()','identity_company_role_governance_use(jsonb)','identity_company_role_admit_use(jsonb)','identity_company_role_usage_commit()','identity_company_role_receiving()','identity_company_group_rule_manifest_guard()','identity_company_role_protected(text,uuid,uuid)','identity_company_role_directory_guard()','identity_directory_creation_actor(jsonb)'] LOOP
  INSERT INTO identity_company_role_manifest VALUES(signature,md5(pg_get_functiondef(to_regprocedure(signature)))) ON CONFLICT ON CONSTRAINT identity_company_role_manifest_pkey DO UPDATE SET digest=EXCLUDED.digest;
 END LOOP;
 SET CONSTRAINTS ALL IMMEDIATE;
 ALTER TABLE identity_company_role_manifest ENABLE TRIGGER company_role_manifest_guard;
END; $$;
DO $$ DECLARE entry RECORD;BEGIN
 FOR entry IN SELECT signature FROM identity_company_role_manifest WHERE signature LIKE 'identity_company_role%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',entry.signature);
 END LOOP;
END; $$;
DO $$ DECLARE relation TEXT;hook RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox','identity_company_role_uses','identity_company_role_manifest'] LOOP
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
