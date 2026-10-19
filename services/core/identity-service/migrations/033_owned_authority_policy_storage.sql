CREATE SEQUENCE IF NOT EXISTS identity_authority_namespace_generation;
CREATE TABLE IF NOT EXISTS identity_authority_namespaces (
 id UUID PRIMARY KEY,candidate_id UUID NOT NULL UNIQUE REFERENCES identity_authority_candidates(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),issuer TEXT NOT NULL,
 generation BIGINT NOT NULL UNIQUE CHECK(generation>0),tenant_version BIGINT NOT NULL CHECK(tenant_version>0),tenant_generation BIGINT NOT NULL CHECK(tenant_generation>0),
 state TEXT NOT NULL CHECK(state='sealed'),manifest_sha256 TEXT NOT NULL,inventory_sha256 TEXT NOT NULL,content_sha256 TEXT NOT NULL,
 sealed_by NAME NOT NULL,created_at TIMESTAMPTZ NOT NULL,publication_deadline TIMESTAMPTZ NOT NULL CHECK(publication_deadline>created_at),transaction_id BIGINT NOT NULL,
 UNIQUE(id,tenant_id),CHECK(id<>candidate_id),CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$' AND inventory_sha256 ~ '^[a-f0-9]{64}$' AND content_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE INDEX IF NOT EXISTS identity_authority_namespaces_transaction ON identity_authority_namespaces(transaction_id);
CREATE TABLE IF NOT EXISTS identity_owned_role_authentication (
 namespace_id UUID NOT NULL,tenant_id UUID NOT NULL,role TEXT NOT NULL,version BIGINT NOT NULL CHECK(version>0),required BOOLEAN NOT NULL,max_age_seconds INTEGER NOT NULL CHECK(max_age_seconds BETWEEN 300 AND 86400),
 PRIMARY KEY(namespace_id,role,version),FOREIGN KEY(namespace_id,tenant_id) REFERENCES identity_authority_namespaces(id,tenant_id),
 CHECK(NOT(identity_authority_catalog()->'lockedMfaRoles' ? role) OR required AND max_age_seconds=300)
);
CREATE TABLE IF NOT EXISTS identity_owned_role_activation (
 namespace_id UUID NOT NULL,tenant_id UUID NOT NULL,role TEXT NOT NULL,version BIGINT NOT NULL CHECK(version>0),required BOOLEAN NOT NULL,
 max_duration_seconds INTEGER NOT NULL CHECK(max_duration_seconds BETWEEN 60 AND 28800),reviewer_user_ids UUID[] NOT NULL CHECK(identity_activation_reviewers_valid(reviewer_user_ids)),
 PRIMARY KEY(namespace_id,role,version),FOREIGN KEY(namespace_id,tenant_id) REFERENCES identity_authority_namespaces(id,tenant_id),
 CHECK(cardinality(reviewer_user_ids)=0 OR required AND identity_authority_catalog()->'protectedRoles' ? role),
 CHECK(role<>'admin' OR NOT required OR cardinality(reviewer_user_ids)>0),CHECK(role<>'user' OR NOT required AND max_duration_seconds=28800 AND cardinality(reviewer_user_ids)=0)
);
CREATE TABLE IF NOT EXISTS identity_owned_role_reviews (
 namespace_id UUID NOT NULL,tenant_id UUID NOT NULL,role TEXT NOT NULL,version BIGINT NOT NULL CHECK(version>0),required BOOLEAN NOT NULL,
 interval_seconds INTEGER,window_seconds INTEGER,reviewer_user_ids UUID[] NOT NULL CHECK(identity_activation_reviewers_valid(reviewer_user_ids)),
 PRIMARY KEY(namespace_id,role,version),FOREIGN KEY(namespace_id,tenant_id) REFERENCES identity_authority_namespaces(id,tenant_id),
 CHECK((NOT required AND interval_seconds IS NULL AND window_seconds IS NULL AND cardinality(reviewer_user_ids)=0)
  OR required AND role<>'user' AND interval_seconds IS NOT NULL AND window_seconds IS NOT NULL
   AND interval_seconds BETWEEN 3600 AND 31536000 AND window_seconds BETWEEN 60 AND least(604800,interval_seconds-1) AND cardinality(reviewer_user_ids)>0)
);
CREATE TABLE IF NOT EXISTS identity_owned_role_policies (
 namespace_id UUID NOT NULL,tenant_id UUID NOT NULL,role TEXT NOT NULL,authentication_version BIGINT NOT NULL,activation_version BIGINT NOT NULL,review_version BIGINT NOT NULL,
 PRIMARY KEY(namespace_id,role),FOREIGN KEY(namespace_id,tenant_id) REFERENCES identity_authority_namespaces(id,tenant_id),
 FOREIGN KEY(namespace_id,role,authentication_version) REFERENCES identity_owned_role_authentication(namespace_id,role,version),
 FOREIGN KEY(namespace_id,role,activation_version) REFERENCES identity_owned_role_activation(namespace_id,role,version),
 FOREIGN KEY(namespace_id,role,review_version) REFERENCES identity_owned_role_reviews(namespace_id,role,version)
);
CREATE TABLE IF NOT EXISTS identity_authority_namespace_events (
 id UUID PRIMARY KEY REFERENCES identity_authority_namespaces(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),action TEXT NOT NULL CHECK(action='authority-sealed'),
 actor JSONB NOT NULL,details JSONB NOT NULL,scope_sha256 TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_authority_namespace_outbox (
 id UUID PRIMARY KEY REFERENCES identity_authority_namespace_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),action TEXT NOT NULL CHECK(action='authority-sealed'),
 status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION identity_authority_policy_rows(identifier UUID,owner UUID,body JSONB) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_object(
  'identity_owned_role_authentication',(SELECT jsonb_agg(jsonb_build_object('namespace_id',identifier,'tenant_id',owner,'role',profile->>'role','version',1,
   'required',profile->'authentication'->'required','max_age_seconds',profile->'authentication'->'maxAgeSeconds') ORDER BY (profile->>'role') COLLATE "C") FROM jsonb_array_elements(body->'policies') profile),
  'identity_owned_role_activation',(SELECT jsonb_agg(jsonb_build_object('namespace_id',identifier,'tenant_id',owner,'role',profile->>'role','version',1,
   'required',profile->'activation'->'required','max_duration_seconds',profile->'activation'->'maxDurationSeconds','reviewer_user_ids',profile->'activation'->'reviewerUserIds') ORDER BY (profile->>'role') COLLATE "C") FROM jsonb_array_elements(body->'policies') profile),
  'identity_owned_role_reviews',(SELECT jsonb_agg(jsonb_build_object('namespace_id',identifier,'tenant_id',owner,'role',profile->>'role','version',1,'required',profile->'review'<>'null'::jsonb,
   'interval_seconds',profile->'review'->'intervalSeconds','window_seconds',profile->'review'->'windowSeconds','reviewer_user_ids',COALESCE(profile->'review'->'reviewerUserIds','[]')) ORDER BY (profile->>'role') COLLATE "C") FROM jsonb_array_elements(body->'policies') profile),
  'identity_owned_role_policies',(SELECT jsonb_agg(jsonb_build_object('namespace_id',identifier,'tenant_id',owner,'role',profile->>'role',
   'authentication_version',1,'activation_version',1,'review_version',1) ORDER BY (profile->>'role') COLLATE "C") FROM jsonb_array_elements(body->'policies') profile));
$$;
CREATE OR REPLACE FUNCTION identity_authority_namespace_rows(identifier UUID) RETURNS jsonb LANGUAGE sql SECURITY DEFINER AS $$
 SELECT jsonb_build_object(
  'identity_owned_role_authentication',COALESCE((SELECT jsonb_agg(to_jsonb(policy) ORDER BY role COLLATE "C") FROM identity_owned_role_authentication policy WHERE namespace_id=identifier),'[]'),
  'identity_owned_role_activation',COALESCE((SELECT jsonb_agg(to_jsonb(policy) ORDER BY role COLLATE "C") FROM identity_owned_role_activation policy WHERE namespace_id=identifier),'[]'),
  'identity_owned_role_reviews',COALESCE((SELECT jsonb_agg(to_jsonb(policy) ORDER BY role COLLATE "C") FROM identity_owned_role_reviews policy WHERE namespace_id=identifier),'[]'),
  'identity_owned_role_policies',COALESCE((SELECT jsonb_agg(to_jsonb(policy) ORDER BY role COLLATE "C") FROM identity_owned_role_policies policy WHERE namespace_id=identifier),'[]'));
$$;
CREATE OR REPLACE FUNCTION identity_authority_namespace_no_effects() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.authority_seal',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_authority_namespaces WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Sealing owned policy cannot change live identity or governance' USING ERRCODE='42501';END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_namespace_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Sealed authority policies and evidence are immutable' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.authority_seal',true),'')::jsonb;
 IF scope IS NULL OR current_setting('opendirectory.authority_seal_review',true) IS DISTINCT FROM 'explicit-offline-owned-policy-seal'
  THEN RAISE EXCEPTION 'Exact offline owned-policy seal required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_authority_namespaces' THEN
  IF EXISTS(SELECT 1 FROM identity_authority_namespaces WHERE transaction_id=txid_current()) OR to_jsonb(NEW) IS DISTINCT FROM scope->'namespace'
   THEN RAISE EXCEPTION 'One exact owned-policy namespace root required' USING ERRCODE='42501';END IF;
  PERFORM set_config('opendirectory.authority_seal_admitted',NEW.id::text,true);
 ELSE
  data=to_jsonb(NEW);
  IF TG_TABLE_NAME='identity_authority_namespace_events' THEN
   IF data->>'scope_sha256' IS DISTINCT FROM identity_authority_hash(scope) THEN RAISE EXCEPTION 'Owned-policy scope evidence required' USING ERRCODE='42501';END IF;
   data=data-'scope_sha256';
  END IF;
  IF current_setting('opendirectory.authority_seal_admitted',true) IS DISTINCT FROM scope->'namespace'->>'id'
   OR NOT EXISTS(SELECT 1 FROM identity_authority_namespaces WHERE id=(scope->'namespace'->>'id')::uuid AND transaction_id=txid_current())
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(scope->'rows'->TG_TABLE_NAME) expected WHERE expected=data)
   THEN RAISE EXCEPTION 'Exact owned policy or seal evidence required' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_namespace_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;owned BOOLEAN;
BEGIN
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')
  AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) ORDER BY relname LOOP
  owned=relation IN('identity_authority_namespaces','identity_owned_role_authentication','identity_owned_role_activation','identity_owned_role_reviews','identity_owned_role_policies','identity_authority_namespace_events','identity_authority_namespace_outbox');
  IF owned AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_authority_namespace_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_authority_namespace_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_authority_seal_no_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='identity_authority_namespace_no_effects()'::regprocedure)
   OR NOT owned AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_authority_seal_no_effects' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_authority_namespace_no_effects()'::regprocedure)
   THEN RAISE EXCEPTION 'Complete owned-policy receiving and no-effects guards required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='identity_authority_namespaces'::regclass AND tgname='identity_authority_namespace_commit'
  AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_authority_namespace_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Owned-policy deferred receiving guard required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_namespace_receipt(identifier UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE namespace identity_authority_namespaces;candidate identity_authority_candidates;scope JSONB;expected JSONB;expected_actor JSONB;expected_details JSONB;
BEGIN
 PERFORM identity_authority_owner();
 SELECT * INTO namespace FROM identity_authority_namespaces WHERE id=identifier;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned authority namespace not found' USING ERRCODE='23503';END IF;
 SELECT * INTO candidate FROM identity_authority_candidates WHERE id=namespace.candidate_id;
 expected=identity_authority_policy_rows(identifier,namespace.tenant_id,candidate.manifest);
 expected_actor=jsonb_build_object('kind','offline-owned-policy-seal','databaseRole',namespace.sealed_by,'reviewAnchorUserId',candidate.manifest->>'reviewAnchorUserId');
 expected_details=jsonb_build_object('candidateId',candidate.id,'manifestSha256',namespace.manifest_sha256,'inventorySha256',namespace.inventory_sha256,'contentSha256',namespace.content_sha256,'state','sealed','canAuthorize',false);
 scope=jsonb_build_object('namespace',to_jsonb(namespace),'rows',expected||jsonb_build_object(
  'identity_authority_namespace_events',jsonb_build_array(jsonb_build_object('id',identifier,'tenant_id',namespace.tenant_id,'action','authority-sealed','actor',expected_actor,'details',expected_details,'created_at',namespace.created_at)),
  'identity_authority_namespace_outbox',jsonb_build_array(jsonb_build_object('id',identifier,'tenant_id',namespace.tenant_id,'action','authority-sealed','status','pending','created_at',namespace.created_at))));
 IF candidate.id IS NULL OR namespace.state<>'sealed' OR namespace.id=namespace.candidate_id OR namespace.tenant_id<>candidate.tenant_id OR namespace.issuer IS DISTINCT FROM candidate.manifest->>'issuer'
  OR namespace.tenant_version<>candidate.tenant_version OR namespace.tenant_generation<>candidate.tenant_generation
  OR namespace.manifest_sha256<>candidate.manifest_sha256 OR namespace.inventory_sha256<>candidate.inventory_sha256
  OR candidate.manifest_sha256<>identity_authority_hash(candidate.manifest) OR candidate.inventory_sha256<>identity_authority_hash(candidate.inventory)
  OR NOT EXISTS(SELECT 1 FROM identity_authority_candidate_events event JOIN identity_authority_candidate_outbox outbox USING(id)
   WHERE event.id=candidate.id AND event.tenant_id=candidate.tenant_id AND outbox.tenant_id=candidate.tenant_id AND event.action='migration-staged' AND outbox.action=event.action AND outbox.status='pending'
    AND event.actor=jsonb_build_object('kind','offline-authority-stage','databaseRole',candidate.reviewed_by,'reviewAnchorUserId',candidate.manifest->>'reviewAnchorUserId')
    AND event.details=jsonb_build_object('reason',candidate.manifest->>'reason','manifestSha256',candidate.manifest_sha256,'inventorySha256',candidate.inventory_sha256,'state','draft','canAuthorize',false)
    AND event.scope_sha256=identity_authority_hash(jsonb_build_object('id',candidate.id,'tenantId',candidate.tenant_id,'tenantVersion',candidate.tenant_version::text,'tenantGeneration',candidate.tenant_generation::text,
     'manifestSha256',candidate.manifest_sha256,'inventorySha256',candidate.inventory_sha256,'createdAt',candidate.created_at)))
  OR namespace.publication_deadline IS DISTINCT FROM candidate.valid_until OR namespace.content_sha256<>identity_authority_hash(expected)
  OR identity_authority_namespace_rows(identifier) IS DISTINCT FROM expected
  OR NOT EXISTS(SELECT 1 FROM identity_authority_namespace_events event JOIN identity_authority_namespace_outbox outbox USING(id)
   WHERE event.id=identifier AND event.tenant_id=namespace.tenant_id AND outbox.tenant_id=namespace.tenant_id AND event.action='authority-sealed' AND outbox.action=event.action AND outbox.status='pending'
    AND event.actor=expected_actor AND event.details=expected_details AND event.created_at=namespace.created_at AND outbox.created_at=namespace.created_at
    AND event.scope_sha256=identity_authority_hash(scope))
  THEN RAISE EXCEPTION 'Exact sealed owned-policy content and retained evidence required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_namespace_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;namespace identity_authority_namespaces;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_authority_namespace_receiving();PERFORM identity_authority_namespace_receipt(NEW.id);
 scope=NULLIF(current_setting('opendirectory.authority_seal',true),'')::jsonb;SELECT * INTO namespace FROM identity_authority_namespaces WHERE id=NEW.id;
 IF scope IS NULL OR scope->'namespace' IS DISTINCT FROM to_jsonb(namespace) OR namespace.transaction_id<>txid_current() OR namespace.sealed_by<>session_user
  OR namespace.publication_deadline<=clock_timestamp() OR current_setting('opendirectory.authority_seal_review',true) IS DISTINCT FROM 'explicit-offline-owned-policy-seal'
  THEN RAISE EXCEPTION 'Current exact owned-policy sealing admission required' USING ERRCODE='42501';END IF;
 PERFORM identity_authority_candidate_snapshot(namespace.candidate_id,namespace.tenant_id,namespace.issuer);RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_seal(identifier UUID,owner UUID,authority TEXT) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE candidate identity_authority_candidates;namespace identity_authority_namespaces;scope JSONB;rows JSONB;actor JSONB;details JSONB;relation TEXT;amount INTEGER;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_authority_namespace_receiving();
 IF pg_current_xact_id_if_assigned() IS NOT NULL THEN RAISE EXCEPTION 'A fresh transaction without earlier writes or row locks is required for sealing' USING ERRCODE='42501';END IF;
 IF current_setting('opendirectory.authority_seal_review',true) IS DISTINCT FROM 'explicit-offline-owned-policy-seal'
  OR NULLIF(current_setting('opendirectory.authority_seal',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_authority_namespaces WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'One explicit offline owned-policy seal per transaction required' USING ERRCODE='42501';END IF;
 SELECT * INTO candidate FROM identity_authority_candidates WHERE id=identifier AND tenant_id=owner AND manifest->>'issuer'=authority;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned authority candidate not found' USING ERRCODE='23503';END IF;
 PERFORM id FROM identity_tenants WHERE id=owner AND enabled FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Enabled authority tenant required' USING ERRCODE='23514';END IF;
 PERFORM account.id FROM users account JOIN identity_tenant_ownership ownership ON ownership.resource_kind='user' AND ownership.resource_id=account.id
  WHERE ownership.tenant_id=owner ORDER BY account.id LIMIT 1001 FOR UPDATE OF account;
 GET DIAGNOSTICS amount=ROW_COUNT;IF amount>1000 THEN RAISE EXCEPTION 'Owned-policy user boundary exceeded' USING ERRCODE='54000';END IF;
 PERFORM identity_authority_candidate_snapshot(identifier,owner,authority);
 namespace.id=gen_random_uuid();namespace.candidate_id=identifier;namespace.tenant_id=owner;namespace.issuer=authority;namespace.generation=nextval('identity_authority_namespace_generation');
 namespace.tenant_version=candidate.tenant_version;namespace.tenant_generation=candidate.tenant_generation;namespace.state='sealed';namespace.manifest_sha256=candidate.manifest_sha256;namespace.inventory_sha256=candidate.inventory_sha256;
 namespace.sealed_by=session_user;namespace.created_at=clock_timestamp();namespace.publication_deadline=candidate.valid_until;namespace.transaction_id=txid_current();
 rows=identity_authority_policy_rows(namespace.id,owner,candidate.manifest);namespace.content_sha256=identity_authority_hash(rows);
 actor=jsonb_build_object('kind','offline-owned-policy-seal','databaseRole',session_user,'reviewAnchorUserId',candidate.manifest->>'reviewAnchorUserId');
 details=jsonb_build_object('candidateId',identifier,'manifestSha256',namespace.manifest_sha256,'inventorySha256',namespace.inventory_sha256,'contentSha256',namespace.content_sha256,'state','sealed','canAuthorize',false);
 rows=rows||jsonb_build_object('identity_authority_namespace_events',jsonb_build_array(jsonb_build_object('id',namespace.id,'tenant_id',owner,'action','authority-sealed','actor',actor,'details',details,'created_at',namespace.created_at)),
  'identity_authority_namespace_outbox',jsonb_build_array(jsonb_build_object('id',namespace.id,'tenant_id',owner,'action','authority-sealed','status','pending','created_at',namespace.created_at)));
 scope=jsonb_build_object('namespace',to_jsonb(namespace),'rows',rows);
 PERFORM set_config('opendirectory.authority_seal',scope::text,true);
 INSERT INTO identity_authority_namespaces SELECT (namespace).*;
 IF current_setting('opendirectory.authority_seal_admitted',true) IS DISTINCT FROM namespace.id::text THEN RAISE EXCEPTION 'Owned-policy root admission missing' USING ERRCODE='42501';END IF;
 FOREACH relation IN ARRAY ARRAY['identity_owned_role_authentication','identity_owned_role_activation','identity_owned_role_reviews','identity_owned_role_policies'] LOOP
  EXECUTE format('INSERT INTO %I SELECT * FROM jsonb_populate_recordset(NULL::%I,$1)',relation,relation) USING rows->relation;
 END LOOP;
 INSERT INTO identity_authority_namespace_events SELECT * FROM jsonb_populate_recordset(NULL::identity_authority_namespace_events,
  jsonb_build_array((rows->'identity_authority_namespace_events'->0)||jsonb_build_object('scope_sha256',identity_authority_hash(scope))));
 INSERT INTO identity_authority_namespace_outbox SELECT * FROM jsonb_populate_recordset(NULL::identity_authority_namespace_outbox,rows->'identity_authority_namespace_outbox');
 RETURN jsonb_build_object('namespaceId',namespace.id,'candidateId',identifier,'tenantId',owner,'generation',namespace.generation::text,'state','sealed','canAuthorize',false,
  'policyCount',jsonb_array_length(candidate.manifest->'policies'),'contentSha256',namespace.content_sha256,'publicationDeadline',namespace.publication_deadline);
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_owned_policy(identifier UUID,owner UUID,authority TEXT,role_name TEXT) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE namespace identity_authority_namespaces;policy JSONB;
BEGIN
 PERFORM identity_authority_owner();
 SELECT * INTO namespace FROM identity_authority_namespaces WHERE id=identifier AND tenant_id=owner AND issuer=authority;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned authority namespace not found' USING ERRCODE='23503';END IF;
 IF namespace.transaction_id=txid_current() THEN RAISE EXCEPTION 'A committed sealed namespace is required' USING ERRCODE='42501';END IF;
 PERFORM identity_authority_namespace_receiving();PERFORM identity_authority_namespace_receipt(identifier);
 SELECT jsonb_build_object('role',head.role,'authentication',jsonb_build_object('version',authentication.version::text,'required',authentication.required,'maxAgeSeconds',authentication.max_age_seconds),
  'activation',jsonb_build_object('version',activation.version::text,'required',activation.required,'maxDurationSeconds',activation.max_duration_seconds,'reviewerUserIds',to_jsonb(activation.reviewer_user_ids)),
  'review',jsonb_build_object('version',review.version::text,'required',review.required,'intervalSeconds',review.interval_seconds,'windowSeconds',review.window_seconds,'reviewerUserIds',to_jsonb(review.reviewer_user_ids))) INTO policy
 FROM identity_owned_role_policies head
 JOIN identity_owned_role_authentication authentication ON authentication.namespace_id=head.namespace_id AND authentication.role=head.role AND authentication.version=head.authentication_version
 JOIN identity_owned_role_activation activation ON activation.namespace_id=head.namespace_id AND activation.role=head.role AND activation.version=head.activation_version
 JOIN identity_owned_role_reviews review ON review.namespace_id=head.namespace_id AND review.role=head.role AND review.version=head.review_version
 WHERE head.namespace_id=identifier AND head.tenant_id=owner AND head.role=role_name;
 IF policy IS NULL THEN RAISE EXCEPTION 'Explicit owned policy unavailable' USING ERRCODE='23503';END IF;
 RETURN jsonb_build_object('schemaVersion',1,'canAuthorize',false,'namespaceId',identifier,'tenantId',owner,'issuer',authority,'generation',namespace.generation::text,'state','sealed',
  'contentSha256',namespace.content_sha256,'publicationDeadline',namespace.publication_deadline,'policy',policy);
END; $$;

DROP TRIGGER IF EXISTS identity_authority_namespace_commit ON identity_authority_namespaces;
CREATE CONSTRAINT TRIGGER identity_authority_namespace_commit AFTER INSERT OR UPDATE ON identity_authority_namespaces DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_authority_namespace_commit();
DO $$ DECLARE relation TEXT;owned BOOLEAN;routine TEXT;BEGIN
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')
  AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) ORDER BY relname LOOP
  owned=relation IN('identity_authority_namespaces','identity_owned_role_authentication','identity_owned_role_activation','identity_owned_role_reviews','identity_owned_role_policies','identity_authority_namespace_events','identity_authority_namespace_outbox');
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_seal_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_authority_seal_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_authority_namespace_no_effects()',relation);
  IF owned THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_authority_namespace_guard ON %I',relation);
   EXECUTE format('CREATE TRIGGER identity_authority_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_namespace_guard()',relation);
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_stage_no_effects ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_stage_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_stage_no_effects()',relation);
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_stage_no_truncate ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_stage_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_authority_stage_no_effects()',relation);
  ELSE
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_seal_no_effects ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_seal_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_namespace_no_effects()',relation);
  END IF;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_authority_policy_rows(uuid,uuid,jsonb)','identity_authority_namespace_rows(uuid)','identity_authority_namespace_no_effects()',
  'identity_authority_namespace_guard()','identity_authority_namespace_receiving()','identity_authority_namespace_receipt(uuid)','identity_authority_namespace_commit()',
  'identity_authority_seal(uuid,uuid,text)','identity_authority_owned_policy(uuid,uuid,text,text)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
