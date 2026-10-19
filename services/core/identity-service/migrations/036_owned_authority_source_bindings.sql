CREATE TABLE IF NOT EXISTS identity_authority_source_sets (
 namespace_id UUID PRIMARY KEY,tenant_id UUID NOT NULL,issuer TEXT NOT NULL,review_anchor_user_id UUID NOT NULL,accounts JSONB NOT NULL,
 manifest_sha256 TEXT NOT NULL,inventory_sha256 TEXT NOT NULL,policy_sha256 TEXT NOT NULL,content_sha256 TEXT NOT NULL,
 source_count INTEGER NOT NULL CHECK(source_count BETWEEN 0 AND 1000),created_at TIMESTAMPTZ NOT NULL,reviewed_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,
 recorded_by NAME NOT NULL,transaction_id BIGINT NOT NULL UNIQUE,UNIQUE(namespace_id,tenant_id),
 FOREIGN KEY(namespace_id,tenant_id) REFERENCES identity_authority_namespaces(id,tenant_id),
 CHECK(jsonb_typeof(accounts)='array' AND jsonb_array_length(accounts)<=1000),CHECK(valid_until>created_at),
 CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$' AND inventory_sha256 ~ '^[a-f0-9]{64}$' AND policy_sha256 ~ '^[a-f0-9]{64}$' AND content_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TABLE IF NOT EXISTS identity_owned_authority_source_versions (
 namespace_id UUID NOT NULL,tenant_id UUID NOT NULL,kind TEXT NOT NULL CHECK(kind IN('assignment','eligibility','request','review')),source_id UUID NOT NULL,
 source_version BIGINT NOT NULL CHECK(source_version>0),user_id UUID NOT NULL,role TEXT,policy_role TEXT,
 authentication_version BIGINT,activation_version BIGINT,review_version BIGINT,
 disposition TEXT NOT NULL CHECK(disposition IN('adopt','quarantine')),origin TEXT NOT NULL CHECK(origin IN('canonical-home-coherent','offline-review-required','unresolved','foreign')),
 offline_accepted BOOLEAN NOT NULL,was_live BOOLEAN NOT NULL,before_sha256 TEXT NOT NULL CHECK(before_sha256 ~ '^[a-f0-9]{64}$'),source_state JSONB NOT NULL,review_lineage JSONB,
 PRIMARY KEY(namespace_id,kind,source_id,source_version),FOREIGN KEY(namespace_id,tenant_id) REFERENCES identity_authority_source_sets(namespace_id,tenant_id),
 FOREIGN KEY(namespace_id,policy_role) REFERENCES identity_owned_role_policies(namespace_id,role),
 FOREIGN KEY(namespace_id,policy_role,authentication_version) REFERENCES identity_owned_role_authentication(namespace_id,role,version),
 FOREIGN KEY(namespace_id,policy_role,activation_version) REFERENCES identity_owned_role_activation(namespace_id,role,version),
 FOREIGN KEY(namespace_id,policy_role,review_version) REFERENCES identity_owned_role_reviews(namespace_id,role,version),
 CHECK(jsonb_typeof(source_state)='object' AND source_state->>'id'=source_id::text AND source_state->>'user_id'=user_id::text),
 CHECK((policy_role IS NULL AND authentication_version IS NULL AND activation_version IS NULL AND review_version IS NULL)
  OR policy_role IS NOT NULL AND policy_role=role AND authentication_version IS NOT NULL AND activation_version IS NOT NULL AND review_version IS NOT NULL),
 CHECK(disposition='quarantine' OR policy_role IS NOT NULL AND was_live AND (origin='canonical-home-coherent' OR origin='offline-review-required' AND offline_accepted)),
 CHECK(NOT offline_accepted OR disposition='adopt' AND origin='offline-review-required'),
 CHECK(review_lineage IS NULL OR kind='review' AND jsonb_typeof(review_lineage)='object'),
 CHECK(kind<>'review' OR disposition='quarantine' OR review_lineage IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS identity_owned_authority_source_edges (
 namespace_id UUID NOT NULL,tenant_id UUID NOT NULL,kind TEXT NOT NULL,source_id UUID NOT NULL,source_version BIGINT NOT NULL,
 position INTEGER NOT NULL CHECK(position BETWEEN 1 AND 1000),related_kind TEXT NOT NULL CHECK(related_kind IN('assignment','eligibility','request','review')),related_id UUID NOT NULL,related_version BIGINT,
 resolution TEXT NOT NULL CHECK(resolution IN('owned','unresolved')),
 PRIMARY KEY(namespace_id,kind,source_id,source_version,position),UNIQUE(namespace_id,kind,source_id,source_version,related_kind,related_id),
 FOREIGN KEY(namespace_id,tenant_id) REFERENCES identity_authority_source_sets(namespace_id,tenant_id),
 FOREIGN KEY(namespace_id,kind,source_id,source_version) REFERENCES identity_owned_authority_source_versions(namespace_id,kind,source_id,source_version),
 FOREIGN KEY(namespace_id,related_kind,related_id,related_version) REFERENCES identity_owned_authority_source_versions(namespace_id,kind,source_id,source_version),
 CHECK(resolution='owned' AND related_version IS NOT NULL OR resolution='unresolved' AND related_version IS NULL)
);
CREATE TABLE IF NOT EXISTS identity_authority_source_set_events (
 id UUID PRIMARY KEY REFERENCES identity_authority_source_sets(namespace_id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action='sources-materialized'),actor JSONB NOT NULL,details JSONB NOT NULL,scope_sha256 TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_authority_source_set_outbox (
 id UUID PRIMARY KEY REFERENCES identity_authority_source_set_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action='sources-materialized'),status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION identity_authority_source_set_model(identifier UUID,owner UUID,body JSONB,inventory JSONB) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE source JSONB;intention JSONB;reference JSONB;position INTEGER;profile TEXT;related_version BIGINT;lineage JSONB;versions JSONB='[]';edges JSONB='[]';
BEGIN
 IF jsonb_array_length(inventory->'sources')>1000 OR jsonb_array_length(inventory->'users')>1000 THEN RAISE EXCEPTION 'Owned source base boundary exceeded' USING ERRCODE='54000';END IF;
 FOR source IN SELECT value FROM jsonb_array_elements(inventory->'sources') ORDER BY value->>'kind' COLLATE "C",value->>'id' COLLATE "C" LOOP
  SELECT value INTO intention FROM jsonb_array_elements(body->'sources') WHERE value->>'kind'=source->>'kind' AND value->>'id'=source->>'id';
  SELECT value->>'role' INTO profile FROM jsonb_array_elements(body->'policies') WHERE value->>'role'=source->>'role';
  lineage=NULL;
  IF source->>'kind'='review' THEN SELECT value INTO lineage FROM jsonb_array_elements(inventory->'reviewPolicies') WHERE value->>'id'=source->'state'->>'policy_id';END IF;
  versions=versions||jsonb_build_array(jsonb_build_object('namespace_id',identifier,'tenant_id',owner,'kind',source->>'kind','source_id',source->>'id','source_version',1,
   'user_id',source->>'userId','role',source->'role','policy_role',profile,'authentication_version',CASE WHEN profile IS NOT NULL THEN 1 END,'activation_version',CASE WHEN profile IS NOT NULL THEN 1 END,
   'review_version',CASE WHEN profile IS NOT NULL THEN 1 END,'disposition',intention->>'disposition','origin',source->>'origin','offline_accepted',COALESCE(intention->'acceptOfflineOrigin'='true'::jsonb,false),
   'was_live',source->'live','before_sha256',source->>'beforeSha256','source_state',source->'state','review_lineage',lineage));
  IF jsonb_array_length(source->'relatedSources')>1000 THEN RAISE EXCEPTION 'Owned source edge boundary exceeded' USING ERRCODE='54000';END IF;
  FOR reference,position IN SELECT value,ordinality::integer FROM jsonb_array_elements(source->'relatedSources') WITH ORDINALITY LOOP
   related_version=CASE WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(inventory->'sources') related WHERE related->>'kind'=reference->>'kind' AND related->>'id'=reference->>'id') THEN 1 END;
   edges=edges||jsonb_build_array(jsonb_build_object('namespace_id',identifier,'tenant_id',owner,'kind',source->>'kind','source_id',source->>'id','source_version',1,'position',position,
    'related_kind',reference->>'kind','related_id',reference->>'id','related_version',related_version,'resolution',CASE WHEN related_version IS NULL THEN 'unresolved' ELSE 'owned' END));
  END LOOP;
 END LOOP;
 RETURN jsonb_build_object('users',inventory->'users','rows',jsonb_build_object('identity_owned_authority_source_versions',versions,'identity_owned_authority_source_edges',edges));
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_source_set_rows(identifier UUID) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_authority_owner();
 RETURN jsonb_build_object('users',(SELECT accounts FROM identity_authority_source_sets WHERE namespace_id=identifier),'rows',jsonb_build_object(
  'identity_owned_authority_source_versions',COALESCE((SELECT jsonb_agg(to_jsonb(source) ORDER BY kind COLLATE "C",source_id) FROM identity_owned_authority_source_versions source WHERE namespace_id=identifier AND source_version=1),'[]'),
  'identity_owned_authority_source_edges',COALESCE((SELECT jsonb_agg(to_jsonb(edge) ORDER BY kind COLLATE "C",source_id,position) FROM identity_owned_authority_source_edges edge WHERE namespace_id=identifier AND source_version=1),'[]')));
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_source_set_no_effects() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.authority_source_set',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_authority_source_sets WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Source materialization cannot change canonical live or governance state' USING ERRCODE='42501';END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_source_set_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Initial owned source bases are immutable' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.authority_source_set',true),'')::jsonb;data=to_jsonb(NEW);
 IF scope IS NULL OR current_setting('opendirectory.authority_source_review',true) IS DISTINCT FROM 'explicit-offline-owned-source-review'
  THEN RAISE EXCEPTION 'Exact offline source materialization scope required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_authority_source_sets' THEN
  IF data IS DISTINCT FROM scope->'root' OR EXISTS(SELECT 1 FROM identity_authority_source_sets WHERE transaction_id=txid_current())
   THEN RAISE EXCEPTION 'One exact owned source set required' USING ERRCODE='42501';END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM identity_authority_source_sets WHERE namespace_id=(scope->'root'->>'namespace_id')::uuid AND transaction_id=txid_current())
   THEN RAISE EXCEPTION 'Current source set root required' USING ERRCODE='42501';END IF;
  IF TG_TABLE_NAME IN('identity_owned_authority_source_versions','identity_owned_authority_source_edges') THEN
   IF NEW.namespace_id::text IS DISTINCT FROM scope->'root'->>'namespace_id' OR NEW.tenant_id::text IS DISTINCT FROM scope->'root'->>'tenant_id' OR NEW.source_version<>1
    OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(scope->'rows'->TG_TABLE_NAME) expected WHERE expected=data)
    THEN RAISE EXCEPTION 'Exact initial source version or edge required' USING ERRCODE='42501';END IF;
  ELSE
   IF data->>'id' IS DISTINCT FROM scope->'root'->>'namespace_id' OR data->>'tenant_id' IS DISTINCT FROM scope->'root'->>'tenant_id' OR data->'created_at' IS DISTINCT FROM scope->'root'->'created_at' OR NEW.action<>'sources-materialized'
    THEN RAISE EXCEPTION 'Exact source materialization evidence required' USING ERRCODE='42501';END IF;
   IF TG_TABLE_NAME='identity_authority_source_set_events' THEN
    IF NEW.actor IS DISTINCT FROM jsonb_build_object('kind','offline-source-materialization','databaseRole',scope->'root'->>'recorded_by','reviewAnchorUserId',scope->'root'->>'review_anchor_user_id')
     OR NEW.details IS DISTINCT FROM jsonb_build_object('contentSha256',scope->'root'->>'content_sha256','manifestSha256',scope->'root'->>'manifest_sha256','inventorySha256',scope->'root'->>'inventory_sha256','canAuthorize',false)
     OR NEW.scope_sha256 IS DISTINCT FROM identity_authority_hash(scope) THEN RAISE EXCEPTION 'Exact source materialization actor and content required' USING ERRCODE='42501';END IF;
   ELSIF NEW.status<>'pending' THEN RAISE EXCEPTION 'Pending source materialization outbox required' USING ERRCODE='42501';END IF;
  END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_source_set_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;owned BOOLEAN;
BEGIN
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')
  AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) ORDER BY relname LOOP
  owned=relation IN('identity_authority_source_sets','identity_owned_authority_source_versions','identity_owned_authority_source_edges','identity_authority_source_set_events','identity_authority_source_set_outbox');
  IF owned AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_authority_source_set_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_authority_source_set_guard()'::regprocedure)
   OR NOT owned AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_authority_source_set_no_effects' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_authority_source_set_no_effects()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_authority_source_set_no_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='identity_authority_source_set_no_effects()'::regprocedure)
   THEN RAISE EXCEPTION 'Complete owned source materialization guards required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='identity_authority_source_sets'::regclass AND tgname='identity_authority_source_set_commit' AND tgenabled='O'
  AND tgdeferrable AND tginitdeferred AND tgtype=21 AND tgfoid='identity_authority_source_set_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Deferred source materialization validation required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_source_set_receipt(identifier UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source_set identity_authority_source_sets;namespace identity_authority_namespaces;candidate identity_authority_candidates;model JSONB;scope JSONB;
BEGIN
 PERFORM identity_authority_owner();SELECT * INTO source_set FROM identity_authority_source_sets WHERE namespace_id=identifier;
 IF NOT FOUND THEN RAISE EXCEPTION 'Materialized owned source set not found' USING ERRCODE='23503';END IF;
 PERFORM identity_authority_namespace_receiving();PERFORM identity_authority_namespace_receipt(identifier);
 SELECT * INTO namespace FROM identity_authority_namespaces WHERE id=identifier;SELECT * INTO candidate FROM identity_authority_candidates WHERE id=namespace.candidate_id;
 model=identity_authority_source_set_model(identifier,namespace.tenant_id,candidate.manifest,candidate.inventory);
 scope=jsonb_build_object('root',to_jsonb(source_set),'rows',model->'rows');
 IF source_set.tenant_id<>namespace.tenant_id OR source_set.issuer<>namespace.issuer OR source_set.manifest_sha256<>namespace.manifest_sha256 OR source_set.inventory_sha256<>namespace.inventory_sha256
  OR source_set.policy_sha256<>namespace.content_sha256 OR source_set.accounts IS DISTINCT FROM model->'users' OR source_set.source_count<>jsonb_array_length(candidate.inventory->'sources')
  OR source_set.review_anchor_user_id::text IS DISTINCT FROM candidate.manifest->>'reviewAnchorUserId' OR source_set.reviewed_at IS DISTINCT FROM candidate.created_at OR source_set.valid_until IS DISTINCT FROM namespace.publication_deadline
  OR source_set.content_sha256 IS DISTINCT FROM identity_authority_hash(model) OR identity_authority_source_set_rows(identifier) IS DISTINCT FROM model
  OR NOT EXISTS(SELECT 1 FROM identity_authority_source_set_events event JOIN identity_authority_source_set_outbox outbox USING(id)
   WHERE event.id=identifier AND event.tenant_id=source_set.tenant_id AND outbox.tenant_id=source_set.tenant_id AND event.action='sources-materialized' AND outbox.action=event.action AND outbox.status='pending'
    AND event.created_at=source_set.created_at AND outbox.created_at=source_set.created_at AND event.scope_sha256=identity_authority_hash(scope)
    AND event.actor=jsonb_build_object('kind','offline-source-materialization','databaseRole',source_set.recorded_by,'reviewAnchorUserId',source_set.review_anchor_user_id)
    AND event.details=jsonb_build_object('contentSha256',source_set.content_sha256,'manifestSha256',source_set.manifest_sha256,'inventorySha256',source_set.inventory_sha256,'canAuthorize',false))
  THEN RAISE EXCEPTION 'Exact source versions edges and retained evidence required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_source_set_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source_set identity_authority_source_sets;scope JSONB;candidate_id UUID;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_authority_source_set_receiving();PERFORM identity_authority_source_set_receipt(NEW.namespace_id);
 SELECT * INTO source_set FROM identity_authority_source_sets WHERE namespace_id=NEW.namespace_id;scope=NULLIF(current_setting('opendirectory.authority_source_set',true),'')::jsonb;
 IF scope IS DISTINCT FROM jsonb_build_object('root',to_jsonb(source_set),'rows',identity_authority_source_set_rows(NEW.namespace_id)->'rows') OR source_set.transaction_id<>txid_current() OR source_set.recorded_by<>session_user
  OR source_set.valid_until<=clock_timestamp() OR current_setting('opendirectory.authority_source_review',true) IS DISTINCT FROM 'explicit-offline-owned-source-review'
  THEN RAISE EXCEPTION 'Current exact source materialization admission required' USING ERRCODE='42501';END IF;
 SELECT namespace.candidate_id INTO candidate_id FROM identity_authority_namespaces namespace WHERE id=source_set.namespace_id;
 PERFORM identity_authority_candidate_snapshot(candidate_id,source_set.tenant_id,source_set.issuer);
 IF source_set.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original source materialization deadline expired' USING ERRCODE='42501';END IF;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_bind_sources(identifier UUID,owner UUID,authority TEXT) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE namespace identity_authority_namespaces;candidate identity_authority_candidates;source_set identity_authority_source_sets;model JSONB;scope JSONB;relation TEXT;amount INTEGER;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_authority_source_set_receiving();
 IF pg_current_xact_id_if_assigned() IS NOT NULL THEN RAISE EXCEPTION 'Fresh transaction without preceding effects required for source materialization' USING ERRCODE='42501';END IF;
 IF current_setting('opendirectory.authority_source_review',true) IS DISTINCT FROM 'explicit-offline-owned-source-review' OR NULLIF(current_setting('opendirectory.authority_source_set',true),'') IS NOT NULL
  THEN RAISE EXCEPTION 'Explicit offline owned source review required' USING ERRCODE='42501';END IF;
 SELECT * INTO namespace FROM identity_authority_namespaces WHERE id=identifier AND tenant_id=owner AND issuer=authority;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned sealed namespace not found' USING ERRCODE='23503';END IF;
 IF namespace.transaction_id=txid_current() THEN RAISE EXCEPTION 'Committed owned policy namespace required' USING ERRCODE='42501';END IF;
 PERFORM id FROM identity_tenants WHERE id=owner AND enabled FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Enabled source owner required' USING ERRCODE='42501';END IF;
 PERFORM account.id FROM users account JOIN identity_tenant_ownership ownership ON ownership.resource_kind='user' AND ownership.resource_id=account.id
  WHERE ownership.tenant_id=owner ORDER BY account.id LIMIT 1001 FOR UPDATE OF account;
 GET DIAGNOSTICS amount=ROW_COUNT;IF amount>1000 THEN RAISE EXCEPTION 'Owned source user boundary exceeded' USING ERRCODE='54000';END IF;
 PERFORM identity_authority_namespace_receiving();PERFORM identity_authority_namespace_receipt(identifier);PERFORM identity_authority_candidate_snapshot(namespace.candidate_id,owner,authority);
 SELECT * INTO candidate FROM identity_authority_candidates WHERE id=namespace.candidate_id;model=identity_authority_source_set_model(identifier,owner,candidate.manifest,candidate.inventory);
 source_set.namespace_id=identifier;source_set.tenant_id=owner;source_set.issuer=authority;source_set.review_anchor_user_id=(candidate.manifest->>'reviewAnchorUserId')::uuid;
 source_set.accounts=model->'users';source_set.manifest_sha256=namespace.manifest_sha256;source_set.inventory_sha256=namespace.inventory_sha256;source_set.policy_sha256=namespace.content_sha256;source_set.content_sha256=identity_authority_hash(model);
 source_set.source_count=jsonb_array_length(candidate.inventory->'sources');source_set.created_at=clock_timestamp();source_set.reviewed_at=candidate.created_at;source_set.valid_until=namespace.publication_deadline;source_set.recorded_by=session_user;source_set.transaction_id=txid_current();
 scope=jsonb_build_object('root',to_jsonb(source_set),'rows',model->'rows');PERFORM set_config('opendirectory.authority_source_set',scope::text,true);
 INSERT INTO identity_authority_source_sets SELECT source_set.*;
 FOREACH relation IN ARRAY ARRAY['identity_owned_authority_source_versions','identity_owned_authority_source_edges'] LOOP
  EXECUTE format('INSERT INTO %I SELECT * FROM jsonb_populate_recordset(NULL::%I,$1)',relation,relation) USING model->'rows'->relation;
 END LOOP;
 INSERT INTO identity_authority_source_set_events VALUES(identifier,owner,'sources-materialized',jsonb_build_object('kind','offline-source-materialization','databaseRole',session_user,'reviewAnchorUserId',source_set.review_anchor_user_id),
  jsonb_build_object('contentSha256',source_set.content_sha256,'manifestSha256',source_set.manifest_sha256,'inventorySha256',source_set.inventory_sha256,'canAuthorize',false),identity_authority_hash(scope),source_set.created_at);
 INSERT INTO identity_authority_source_set_outbox VALUES(identifier,owner,'sources-materialized','pending',source_set.created_at);
 RETURN jsonb_build_object('schemaVersion',1,'canAuthorize',false,'namespaceId',identifier,'tenantId',owner,'state','sealed-sources','sourceVersion','1','sourceCount',source_set.source_count,'contentSha256',source_set.content_sha256,'validUntil',source_set.valid_until);
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_owned_source_data(identifier UUID,owner UUID,authority TEXT) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source_set identity_authority_source_sets;sources JSONB;rules JSONB;
BEGIN
 PERFORM identity_authority_owner();SELECT * INTO source_set FROM identity_authority_source_sets WHERE namespace_id=identifier AND tenant_id=owner AND issuer=authority;
 IF NOT FOUND THEN RAISE EXCEPTION 'Materialized owned source set not found' USING ERRCODE='23503';END IF;
 IF source_set.transaction_id=txid_current() THEN RAISE EXCEPTION 'Committed owned source set required' USING ERRCODE='42501';END IF;
 PERFORM identity_authority_source_set_receiving();PERFORM identity_authority_source_set_receipt(identifier);
 SELECT COALESCE(jsonb_agg(jsonb_build_object('kind',source.kind,'id',source.source_id,'userId',source.user_id,'role',source.role,'sourceVersion',source.source_version::text,
  'authenticationVersion',source.authentication_version::text,'activationVersion',source.activation_version::text,'reviewVersion',source.review_version::text,'disposition',source.disposition,
  'acceptOfflineOrigin',source.offline_accepted,'origin',source.origin,'live',source.was_live,'state',source.source_state,'beforeSha256',source.before_sha256,
  'relatedSources',COALESCE((SELECT jsonb_agg(jsonb_build_object('kind',edge.related_kind,'id',edge.related_id) ORDER BY edge.position) FROM identity_owned_authority_source_edges edge
   WHERE edge.namespace_id=source.namespace_id AND edge.kind=source.kind AND edge.source_id=source.source_id AND edge.source_version=source.source_version),'[]')) ORDER BY source.kind COLLATE "C",source.source_id),'[]') INTO sources
 FROM identity_owned_authority_source_versions source WHERE namespace_id=identifier AND source_version=1;
 SELECT COALESCE(jsonb_agg(lineage ORDER BY lineage->>'id' COLLATE "C"),'[]') INTO rules FROM (SELECT DISTINCT review_lineage AS lineage FROM identity_owned_authority_source_versions WHERE namespace_id=identifier AND source_version=1 AND review_lineage IS NOT NULL) retained;
 RETURN jsonb_build_object('schemaVersion',1,'canAuthorize',false,'contentSha256',source_set.content_sha256,'reviewedAt',source_set.reviewed_at,'users',source_set.accounts,'sources',sources,'reviewPolicies',rules);
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_owned_role_evidence(identifier UUID,owner UUID,authority TEXT,recipient UUID) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE namespace identity_authority_namespaces;source_data JSONB;tenant identity_tenants;account users;retained JSONB;links JSONB;canonical BOOLEAN;
 source JSONB;observation JSONB;bindings JSONB='{}';entry JSONB;reference JSONB;reference_key TEXT;pending TEXT[];visited TEXT[];position INTEGER;
 assignment JSONB;state JSONB;profile JSONB;request JSONB;eligibility JSONB;target_key TEXT;eligibility_key TEXT;lease JSONB;old_rule JSONB;lease_count INTEGER;
 issue TEXT;cutoff TIMESTAMPTZ;due_epoch NUMERIC;review_cutoff NUMERIC;assignments JSONB='[]';grants JSONB='[]';roles JSONB;policies JSONB;fingerprint JSONB;result JSONB;
 observed TIMESTAMPTZ;recipient_active BOOLEAN;required BOOLEAN;max_age INTEGER;amount INTEGER=0;owned_profiles JSONB;
BEGIN
 PERFORM identity_authority_owner();
 SELECT * INTO namespace FROM identity_authority_namespaces WHERE id=identifier AND tenant_id=owner AND issuer=authority;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned authority namespace not found' USING ERRCODE='23503';END IF;
 IF namespace.transaction_id=txid_current() THEN RAISE EXCEPTION 'A committed sealed namespace is required' USING ERRCODE='42501';END IF;
 SELECT * INTO account FROM users WHERE id=recipient AND identity_tenant_id('user',id)=owner;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned bound recipient not found' USING ERRCODE='23503';END IF;
 source_data=identity_authority_owned_source_data(identifier,owner,authority);
 SELECT * INTO tenant FROM identity_tenants WHERE id=owner;
 IF NOT tenant.enabled OR tenant.version<>namespace.tenant_version OR tenant.generation<>namespace.tenant_generation OR namespace.publication_deadline<=clock_timestamp()
  THEN RAISE EXCEPTION 'Current sealed authority incarnation required' USING ERRCODE='42501';END IF;
 SELECT jsonb_agg(jsonb_build_object('role',head.role,'authenticationVersion',authentication.version::text,'activationVersion',activation.version::text,'reviewVersion',review.version::text,
  'authentication',jsonb_build_object('required',authentication.required,'maxAgeSeconds',authentication.max_age_seconds),
  'activation',jsonb_build_object('required',activation.required,'maxDurationSeconds',activation.max_duration_seconds,'reviewerUserIds',to_jsonb(activation.reviewer_user_ids)),
  'review',CASE WHEN review.required THEN jsonb_build_object('intervalSeconds',review.interval_seconds,'windowSeconds',review.window_seconds,'reviewerUserIds',to_jsonb(review.reviewer_user_ids)) ELSE 'null'::jsonb END) ORDER BY head.role COLLATE "C") INTO owned_profiles
 FROM identity_owned_role_policies head
 JOIN identity_owned_role_authentication authentication ON authentication.namespace_id=head.namespace_id AND authentication.role=head.role AND authentication.version=head.authentication_version
 JOIN identity_owned_role_activation activation ON activation.namespace_id=head.namespace_id AND activation.role=head.role AND activation.version=head.activation_version
 JOIN identity_owned_role_reviews review ON review.namespace_id=head.namespace_id AND review.role=head.role AND review.version=head.review_version
 WHERE head.namespace_id=identifier AND head.tenant_id=owner;
 SELECT value INTO retained FROM jsonb_array_elements(source_data->'users') WHERE value->>'id'=recipient::text;
 IF retained IS NULL THEN RAISE EXCEPTION 'Owned bound recipient not found' USING ERRCODE='23503';END IF;
 SELECT COALESCE(jsonb_agg(to_jsonb(link) ORDER BY link.issuer,link.subject),'[]') INTO links FROM (SELECT * FROM identity_subject_links WHERE user_id=recipient ORDER BY issuer,subject LIMIT 1001) link;
 IF jsonb_array_length(links)>1000 THEN RAISE EXCEPTION 'Owned source link boundary exceeded' USING ERRCODE='54000';END IF;
 SELECT EXISTS(SELECT 1 FROM identity_subject_links link JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=owner WHERE link.user_id=recipient AND link.issuer=authority) INTO canonical;
 recipient_active=account.enabled AND canonical AND account.tenant_generation::text=retained->>'tenantGeneration';observed=clock_timestamp();
 FOR source IN SELECT value FROM jsonb_array_elements(source_data->'sources') WHERE value->>'userId'=recipient::text ORDER BY value->>'kind',value->>'id' LOOP
  observation=identity_authority_source_observation(source->>'kind',(source->>'id')::uuid,owner,(source_data->>'reviewedAt')::timestamptz);
  entry=source||jsonb_build_object('disposition',source->>'disposition','matches',COALESCE(observation->'state'=source->'state' AND observation->'beforeSha256'=source->'beforeSha256' AND observation->'relatedSources'=source->'relatedSources',false),
   'acceptedOrigin',source->>'origin'='canonical-home-coherent' OR source->>'origin'='offline-review-required' AND source->'acceptOfflineOrigin'='true'::jsonb);
  bindings=jsonb_set(bindings,ARRAY[(source->>'kind')||':'||(source->>'id')],entry);
 END LOOP;
 FOR assignment IN SELECT value FROM jsonb_each(bindings) WHERE value->>'kind'='assignment' ORDER BY key COLLATE "C" LOOP
  state=assignment->'state';issue=NULL;request=NULL;eligibility=NULL;eligibility_key=NULL;cutoff=namespace.publication_deadline;
  pending=ARRAY['assignment:'||(assignment->>'id')];visited='{}';position=1;
  SELECT value INTO profile FROM jsonb_array_elements(owned_profiles) WHERE value->>'role'=assignment->>'role';
  WHILE position<=cardinality(pending) LOOP
   entry=bindings->pending[position];visited=array_append(visited,pending[position]);position=position+1;
   IF entry IS NULL OR entry->>'userId' IS DISTINCT FROM recipient::text OR entry->>'role' IS DISTINCT FROM assignment->>'role' THEN issue='incoherent_component';EXIT;END IF;
   IF entry->>'disposition' IS DISTINCT FROM 'adopt' THEN issue='quarantined_component';EXIT;END IF;
   IF entry->'acceptedOrigin' IS DISTINCT FROM 'true'::jsonb OR entry->'live' IS DISTINCT FROM 'true'::jsonb THEN issue='unavailable_component';EXIT;END IF;
   IF entry->'matches' IS DISTINCT FROM 'true'::jsonb THEN issue='source_changed';EXIT;END IF;
   FOR reference IN SELECT value FROM jsonb_array_elements(entry->'relatedSources') LOOP
    reference_key=(reference->>'kind')||':'||(reference->>'id');
    IF NOT reference_key=ANY(pending) THEN pending=array_append(pending,reference_key);END IF;
   END LOOP;
   IF cardinality(pending)>1000 THEN RAISE EXCEPTION 'Owned component boundary exceeded' USING ERRCODE='54000';END IF;
  END LOOP;
  IF issue IS NULL AND NOT recipient_active THEN issue='recipient_unavailable';END IF;
  IF issue IS NULL AND (state->>'role' IS DISTINCT FROM assignment->>'role' OR state->'revoked_at'<>'null'::jsonb OR profile IS NULL) THEN issue='assignment_unavailable';END IF;
  IF issue IS NULL THEN
   IF (state->>'created_at')::timestamptz>observed OR state->'expires_at'<>'null'::jsonb AND ((state->>'expires_at')::timestamptz<=observed OR (state->>'expires_at')::timestamptz<=(state->>'created_at')::timestamptz) THEN issue='assignment_expired';
   ELSIF assignment->>'role'<>'user' AND (state->'expires_at'='null'::jsonb OR extract(epoch FROM (state->>'expires_at')::timestamptz-(state->>'created_at')::timestamptz)>(profile->'activation'->>'maxDurationSeconds')::integer) THEN issue='duration_requires_new_grant';
   ELSE cutoff=least(cutoff,(state->>'expires_at')::timestamptz);END IF;
  END IF;
  IF issue IS NULL AND profile->'activation'->'required'='true'::jsonb AND state->'activation_request_id'='null'::jsonb THEN issue='owned_activation_required';END IF;
  IF issue IS NULL AND state->'activation_request_id'<>'null'::jsonb THEN
   request=bindings->('request:'||(state->>'activation_request_id'));eligibility_key='eligibility:'||(request->'state'->>'eligibility_id');eligibility=bindings->eligibility_key;
   IF request IS NULL OR eligibility IS NULL OR NOT ('request:'||(request->>'id'))=ANY(visited) OR NOT eligibility_key=ANY(visited)
    OR request->'state'->>'state'<>'active' OR request->'state'->>'user_id' IS DISTINCT FROM recipient::text OR eligibility->'state'->>'user_id' IS DISTINCT FROM recipient::text
    OR eligibility->'state'->>'role' IS DISTINCT FROM assignment->>'role' OR eligibility->'state'->'revoked_at'<>'null'::jsonb
    OR request->'state'->'policy_version' IS DISTINCT FROM state->'policy_version'
    OR (request->'state'->>'duration_seconds')::integer>(profile->'activation'->>'maxDurationSeconds')::integer
    OR (request->'state'->>'duration_seconds')::integer>(eligibility->'state'->>'max_duration_seconds')::integer THEN issue='owned_activation_unavailable';
   ELSIF (eligibility->'state'->>'expires_at')::timestamptz<=observed OR (state->>'expires_at')::timestamptz>(eligibility->'state'->>'expires_at')::timestamptz
    OR extract(epoch FROM (state->>'expires_at')::timestamptz-(state->>'created_at')::timestamptz)>(request->'state'->>'duration_seconds')::integer THEN issue='owned_activation_expired';
   ELSE cutoff=least(cutoff,(eligibility->'state'->>'expires_at')::timestamptz);END IF;
  END IF;
  IF issue IS NULL THEN
   FOREACH target_key IN ARRAY ARRAY['assignment:'||(assignment->>'id'),eligibility_key] LOOP
    IF target_key IS NULL THEN CONTINUE;END IF;
    SELECT count(*),jsonb_agg(value ORDER BY key) INTO lease_count,lease FROM jsonb_each(bindings) WHERE key=ANY(visited) AND value->>'kind'='review'
     AND (value->'state'->>'target_kind')||':'||(value->'state'->>'target_id')=target_key;
    IF lease_count>1 THEN issue='incoherent_review';EXIT;END IF;
    lease=lease->0->'state';
    IF profile->'review'<>'null'::jsonb AND (lease IS NULL OR lease->>'state'<>'pending') THEN issue='owned_review_required';EXIT;END IF;
    IF lease IS NOT NULL THEN
     IF lease->>'state' NOT IN('pending','exempt') THEN issue='owned_review_unavailable';EXIT;END IF;
     IF lease->>'state'='pending' THEN
      due_epoch=extract(epoch FROM (lease->>'due_at')::timestamptz);review_cutoff=extract(epoch FROM (lease->>'deadline_at')::timestamptz);
      IF profile->'review'<>'null'::jsonb THEN
       SELECT value INTO old_rule FROM jsonb_array_elements(source_data->'reviewPolicies') WHERE value->>'id'=lease->>'policy_id' AND value->>'role'=assignment->>'role' AND value->'retired'='false'::jsonb;
       IF old_rule IS NULL THEN issue='owned_review_unavailable';EXIT;END IF;
       due_epoch=due_epoch-greatest(0,(old_rule->>'intervalSeconds')::integer-(profile->'review'->>'intervalSeconds')::integer)::numeric*((lease->>'cycle')::numeric-1);
       review_cutoff=least(review_cutoff,due_epoch+(profile->'review'->>'windowSeconds')::integer);
      END IF;
      IF review_cutoff<=extract(epoch FROM observed) THEN issue='owned_review_expired';EXIT;END IF;
      cutoff=least(cutoff,to_timestamp(review_cutoff::double precision));
     ELSIF lease->'due_at'<>'null'::jsonb OR lease->'deadline_at'<>'null'::jsonb THEN issue='owned_review_unavailable';EXIT;
     END IF;
    END IF;
   END LOOP;
  END IF;
  IF issue IS NULL AND cutoff<=clock_timestamp() THEN issue='source_expired';END IF;
  assignments=assignments||jsonb_build_array(jsonb_build_object('id',assignment->>'id','role',assignment->>'role','eligibleForAdoption',issue IS NULL,'issue',issue));
  IF issue IS NULL THEN
   amount=amount+1;IF amount>100 THEN RAISE EXCEPTION 'Owned positive assignment boundary exceeded' USING ERRCODE='54000';END IF;
   grants=grants||jsonb_build_array(jsonb_build_object('id',assignment->>'id','role',assignment->>'role','validUntil',cutoff,
    'authenticationVersion',profile->>'authenticationVersion','activationVersion',profile->>'activationVersion','reviewVersion',profile->>'reviewVersion','sources',(SELECT jsonb_agg(jsonb_build_array(key,value->>'beforeSha256',value->>'sourceVersion',value->>'authenticationVersion',value->>'activationVersion',value->>'reviewVersion') ORDER BY key COLLATE "C") FROM jsonb_each(bindings) WHERE key=ANY(visited))));
  END IF;
 END LOOP;
 SELECT COALESCE(jsonb_agg(role ORDER BY role COLLATE "C"),'[]') INTO roles FROM (SELECT DISTINCT value->>'role' AS role FROM jsonb_array_elements(grants)) held;
 SELECT COALESCE(jsonb_agg(setting.value ORDER BY setting.value->>'role' COLLATE "C"),'[]'),COALESCE(bool_or((setting.value->'authentication'->>'required')::boolean),false),
  COALESCE(min((setting.value->'authentication'->>'maxAgeSeconds')::integer) FILTER(WHERE setting.value->'authentication'->'required'='true'::jsonb),86400) INTO policies,required,max_age FROM jsonb_array_elements(owned_profiles) setting WHERE roles ? (setting.value->>'role');
 fingerprint=jsonb_build_array('owned-authority-sealed-evidence-v2',identifier,namespace.generation::text,source_data->>'contentSha256',owner,tenant.version::text,tenant.generation::text,authority,
  recipient,account.authorization_revision::text,account.eligibility_revision::text,account.tenant_generation::text,identity_authority_hash(links),grants,policies);
 SELECT least(namespace.publication_deadline,min((value->>'validUntil')::timestamptz)) INTO cutoff FROM jsonb_array_elements(grants);
 IF namespace.publication_deadline<=clock_timestamp() THEN RAISE EXCEPTION 'Current sealed authority incarnation required' USING ERRCODE='42501';END IF;
 result=jsonb_build_object('schemaVersion',2,'canAuthorize',false,'state','sealed','namespaceId',identifier,'namespaceGeneration',namespace.generation::text,'sourceSetSha256',source_data->>'contentSha256',
  'tenant',jsonb_build_object('id',owner,'version',tenant.version::text,'generation',tenant.generation::text),'issuer',authority,'userId',recipient,'recipientActive',recipient_active,
  'proposedRoles',roles,'authentication',jsonb_build_object('required',required,'maxAgeSeconds',max_age),'proposedRolesRevision',identity_authority_hash(fingerprint),'assignments',assignments,'grants',grants,'validUntil',cutoff);
 RETURN result;
END; $$;
DROP TRIGGER IF EXISTS identity_authority_source_set_commit ON identity_authority_source_sets;
CREATE CONSTRAINT TRIGGER identity_authority_source_set_commit AFTER INSERT OR UPDATE ON identity_authority_source_sets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_authority_source_set_commit();
DO $$ DECLARE relation TEXT;owned BOOLEAN;routine TEXT;BEGIN
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')
  AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) ORDER BY relname LOOP
  owned=relation IN('identity_authority_source_sets','identity_owned_authority_source_versions','identity_owned_authority_source_edges','identity_authority_source_set_events','identity_authority_source_set_outbox');
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_source_set_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_authority_source_set_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_authority_source_set_no_effects()',relation);
  IF owned THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_authority_source_set_guard ON %I',relation);
   EXECUTE format('CREATE TRIGGER identity_authority_source_set_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_source_set_guard()',relation);
   FOREACH routine IN ARRAY ARRAY['stage','seal','checkpoint'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_identity_authority_'||routine||'_no_effects',relation);
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()','aaa_identity_authority_'||routine||'_no_effects',relation,
     CASE routine WHEN 'stage' THEN 'identity_authority_stage_no_effects' WHEN 'seal' THEN 'identity_authority_namespace_no_effects' ELSE 'identity_authority_checkpoint_no_effects' END);
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_identity_authority_'||routine||'_no_truncate',relation);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()','aaa_identity_authority_'||routine||'_no_truncate',relation,
     CASE routine WHEN 'stage' THEN 'identity_authority_stage_no_effects' WHEN 'seal' THEN 'identity_authority_namespace_no_effects' ELSE 'identity_authority_checkpoint_no_effects' END);
   END LOOP;
  ELSE
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_source_set_no_effects ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_source_set_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_source_set_no_effects()',relation);
  END IF;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_authority_source_set_model(uuid,uuid,jsonb,jsonb)','identity_authority_source_set_rows(uuid)','identity_authority_source_set_no_effects()',
  'identity_authority_source_set_guard()','identity_authority_source_set_receiving()','identity_authority_source_set_receipt(uuid)','identity_authority_source_set_commit()',
  'identity_authority_bind_sources(uuid,uuid,text)','identity_authority_owned_source_data(uuid,uuid,text)','identity_authority_owned_role_evidence(uuid,uuid,text,uuid)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;

