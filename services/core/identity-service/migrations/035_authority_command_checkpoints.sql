CREATE TABLE IF NOT EXISTS identity_authority_command_checkpoints (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),tenant_version BIGINT NOT NULL CHECK(tenant_version>0),tenant_generation BIGINT NOT NULL CHECK(tenant_generation>0),
 user_id UUID NOT NULL,issuer TEXT NOT NULL,subject TEXT NOT NULL,original_context JSONB NOT NULL,token_sha256 TEXT NOT NULL,
 user_revision BIGINT NOT NULL CHECK(user_revision>0),link_revision BIGINT NOT NULL CHECK(link_revision>0),user_generation BIGINT NOT NULL CHECK(user_generation>0),roles_snapshot_sha256 TEXT NOT NULL,
 valid_until TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL,recorded_by NAME NOT NULL,transaction_id BIGINT NOT NULL,
 CHECK(valid_until>created_at),CHECK(token_sha256 ~ '^[a-f0-9]{64}$' AND roles_snapshot_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_authority_command_checkpoint_transaction ON identity_authority_command_checkpoints(transaction_id);
CREATE TABLE IF NOT EXISTS identity_authority_command_checkpoint_events (
 id UUID PRIMARY KEY REFERENCES identity_authority_command_checkpoints(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action='authority-checkpoint'),actor JSONB NOT NULL,details JSONB NOT NULL,scope_sha256 TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_authority_command_checkpoint_outbox (
 id UUID PRIMARY KEY REFERENCES identity_authority_command_checkpoint_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action='authority-checkpoint'),status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION identity_authority_command_context(proof JSONB) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE owner UUID;tenant identity_tenants;account users;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_authority_checkpoint_receiving();
 BEGIN owner=identity_authority_actor_home(proof);EXCEPTION WHEN SQLSTATE '42501' THEN RAISE EXCEPTION 'Original command identity changed' USING ERRCODE='28000';END;
 IF NOT(proof ?& ARRAY['revision','linkRevision','rolesRevision']) OR proof->>'rolesRevision'!~'^[a-f0-9]{64}$'
  THEN RAISE EXCEPTION 'Original complete command context required' USING ERRCODE='42501';END IF;
 SELECT * INTO tenant FROM identity_tenants WHERE id=owner AND enabled FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Current command tenant required' USING ERRCODE='28000';END IF;
 SELECT * INTO account FROM users WHERE id=(proof->>'userId')::uuid;
 RETURN jsonb_build_object('schemaVersion',1,'tenant',jsonb_build_object('id',owner,'version',tenant.version::text,'generation',tenant.generation::text),
  'userId',account.id,'linkRevision',proof->>'linkRevision','tenantGeneration',account.tenant_generation::text);
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_checkpoint_no_effects() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.authority_command_checkpoint',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_authority_command_checkpoints WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'No canonical effects are allowed after the final authority checkpoint' USING ERRCODE='42501';END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_checkpoint_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Authority checkpoint evidence is immutable' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.authority_command_checkpoint',true),'')::jsonb;data=to_jsonb(NEW);
 IF scope IS NULL THEN RAISE EXCEPTION 'Exact final authority checkpoint scope required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_authority_command_checkpoints' THEN
  IF data IS DISTINCT FROM scope OR EXISTS(SELECT 1 FROM identity_authority_command_checkpoints WHERE transaction_id=txid_current())
   THEN RAISE EXCEPTION 'One exact final checkpoint per transaction required' USING ERRCODE='42501';END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM identity_authority_command_checkpoints WHERE id=(scope->>'id')::uuid AND transaction_id=txid_current())
   OR data->>'id' IS DISTINCT FROM scope->>'id' OR data->>'tenant_id' IS DISTINCT FROM scope->>'tenant_id' OR data->'created_at' IS DISTINCT FROM scope->'created_at'
   OR NEW.action<>'authority-checkpoint'
   THEN RAISE EXCEPTION 'Exact final checkpoint evidence required' USING ERRCODE='42501';END IF;
  IF TG_TABLE_NAME='identity_authority_command_checkpoint_events' THEN
   IF NEW.actor IS DISTINCT FROM jsonb_build_object('issuer',scope->>'issuer','subject',scope->>'subject','userId',scope->>'user_id')
    OR NEW.details IS DISTINCT FROM jsonb_build_object('kind','final-application-checkpoint','originalContext',scope->'original_context','tokenSha256',scope->>'token_sha256','validUntil',scope->'valid_until')
    OR NEW.scope_sha256 IS DISTINCT FROM identity_authority_hash(scope) THEN RAISE EXCEPTION 'Exact original checkpoint actor and content required' USING ERRCODE='42501';END IF;
  ELSIF NEW.status<>'pending' THEN RAISE EXCEPTION 'Pending checkpoint outbox required' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_checkpoint_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;owned BOOLEAN;
BEGIN
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')
  AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) ORDER BY relname LOOP
  owned=relation IN('identity_authority_command_checkpoints','identity_authority_command_checkpoint_events','identity_authority_command_checkpoint_outbox');
  IF owned AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_authority_checkpoint_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_authority_checkpoint_guard()'::regprocedure)
   OR NOT owned AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_authority_checkpoint_no_effects' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_authority_checkpoint_no_effects()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_authority_checkpoint_no_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='identity_authority_checkpoint_no_effects()'::regprocedure)
   THEN RAISE EXCEPTION 'Complete final checkpoint receiving guards required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='identity_authority_command_checkpoints'::regclass AND tgname='identity_authority_checkpoint_commit'
  AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgtype=21 AND tgfoid='identity_authority_checkpoint_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Deferred final checkpoint validation required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_checkpoint_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE checkpoint identity_authority_command_checkpoints;scope JSONB;account users;tenant identity_tenants;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_authority_checkpoint_receiving();
 SELECT * INTO checkpoint FROM identity_authority_command_checkpoints WHERE id=NEW.id;
 scope=NULLIF(current_setting('opendirectory.authority_command_checkpoint',true),'')::jsonb;
 IF checkpoint.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original command assurance expired at commit' USING ERRCODE='28000';END IF;
 IF scope IS NULL OR scope IS DISTINCT FROM to_jsonb(checkpoint) OR checkpoint.transaction_id<>txid_current() OR checkpoint.recorded_by<>session_user
  THEN RAISE EXCEPTION 'Current original checkpoint required at commit' USING ERRCODE='42501';END IF;
 SELECT * INTO account FROM users WHERE id=checkpoint.user_id;SELECT * INTO tenant FROM identity_tenants WHERE id=checkpoint.tenant_id;
 IF account.id IS NULL OR NOT account.enabled OR tenant.id IS NULL OR NOT tenant.enabled OR tenant.version<>checkpoint.tenant_version OR tenant.generation<>checkpoint.tenant_generation
  OR account.authorization_revision<>checkpoint.user_revision OR account.tenant_generation<>checkpoint.user_generation OR identity_tenant_id('user',account.id) IS DISTINCT FROM checkpoint.tenant_id
  OR NOT EXISTS(SELECT 1 FROM identity_subject_links link JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=checkpoint.tenant_id
   WHERE link.issuer=checkpoint.issuer AND link.subject=checkpoint.subject AND link.user_id=checkpoint.user_id AND link.authorization_revision=checkpoint.link_revision)
  OR identity_authority_hash(identity_subject_link_role_state(checkpoint.user_id)) IS DISTINCT FROM checkpoint.roles_snapshot_sha256
  OR NOT EXISTS(SELECT 1 FROM identity_authority_command_checkpoint_events event JOIN identity_authority_command_checkpoint_outbox outbox USING(id)
   WHERE event.id=checkpoint.id AND event.tenant_id=checkpoint.tenant_id AND outbox.tenant_id=checkpoint.tenant_id AND event.action='authority-checkpoint' AND outbox.action=event.action AND outbox.status='pending'
    AND event.created_at=checkpoint.created_at AND outbox.created_at=checkpoint.created_at AND event.scope_sha256=identity_authority_hash(to_jsonb(checkpoint))
    AND event.actor=jsonb_build_object('issuer',checkpoint.issuer,'subject',checkpoint.subject,'userId',checkpoint.user_id)
    AND event.details=jsonb_build_object('kind','final-application-checkpoint','originalContext',checkpoint.original_context,'tokenSha256',checkpoint.token_sha256,'validUntil',checkpoint.valid_until))
  THEN RAISE EXCEPTION 'Unchanged local checkpoint and mandatory evidence required at commit' USING ERRCODE='42501';END IF;
 IF checkpoint.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original command assurance expired during commit validation' USING ERRCODE='28000';END IF;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_command_checkpoint(identifier UUID,proof JSONB,initial JSONB,deadline BIGINT) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE checkpoint identity_authority_command_checkpoints;scope JSONB;owner UUID;tenant identity_tenants;account users;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_authority_checkpoint_receiving();
 IF identifier IS NULL OR jsonb_typeof(proof->'tokenId') IS DISTINCT FROM 'string' OR length(proof->>'tokenId') NOT BETWEEN 1 AND 128 OR proof->>'tokenId'~'[[:cntrl:]]'
  OR jsonb_typeof(proof->'expiresAt') IS DISTINCT FROM 'number' OR proof->>'expiresAt'!~'^[0-9]{1,12}$' OR deadline IS NULL OR deadline>(proof->>'expiresAt')::bigint
  OR NULLIF(current_setting('opendirectory.authority_command_checkpoint',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_authority_command_checkpoints WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Exact original command lifetime required' USING ERRCODE='42501';END IF;
 owner=identity_authority_actor_home(proof-'revision');
 SELECT * INTO tenant FROM identity_tenants WHERE id=owner AND enabled FOR SHARE;SELECT * INTO account FROM users WHERE id=(proof->>'userId')::uuid;
 IF initial IS DISTINCT FROM jsonb_build_object('schemaVersion',1,'tenant',jsonb_build_object('id',owner,'version',tenant.version::text,'generation',tenant.generation::text),
  'userId',account.id,'linkRevision',proof->>'linkRevision','tenantGeneration',account.tenant_generation::text)
  THEN RAISE EXCEPTION 'Original held command tenant and link required' USING ERRCODE='42501';END IF;
 checkpoint.id=identifier;checkpoint.tenant_id=owner;checkpoint.tenant_version=tenant.version;checkpoint.tenant_generation=tenant.generation;
 checkpoint.user_id=account.id;checkpoint.issuer=proof->>'issuer';checkpoint.subject=proof->>'subject';
 checkpoint.original_context=jsonb_build_object('userId',proof->>'userId','revision',proof->>'revision','linkRevision',proof->>'linkRevision','rolesRevision',proof->>'rolesRevision');
 checkpoint.token_sha256=identity_authority_hash(proof->'tokenId');checkpoint.user_revision=account.authorization_revision;checkpoint.link_revision=(proof->>'linkRevision')::bigint;checkpoint.user_generation=account.tenant_generation;
 checkpoint.roles_snapshot_sha256=identity_authority_hash(identity_subject_link_role_state(account.id));checkpoint.valid_until=to_timestamp(deadline);checkpoint.created_at=clock_timestamp();checkpoint.recorded_by=session_user;checkpoint.transaction_id=txid_current();
 IF checkpoint.valid_until<=checkpoint.created_at THEN RAISE EXCEPTION 'Original command assurance expired' USING ERRCODE='28000';END IF;
 scope=to_jsonb(checkpoint);PERFORM set_config('opendirectory.authority_command_checkpoint',scope::text,true);
 INSERT INTO identity_authority_command_checkpoints SELECT checkpoint.*;
 INSERT INTO identity_authority_command_checkpoint_events VALUES(identifier,owner,'authority-checkpoint',jsonb_build_object('issuer',checkpoint.issuer,'subject',checkpoint.subject,'userId',checkpoint.user_id),
  jsonb_build_object('kind','final-application-checkpoint','originalContext',checkpoint.original_context,'tokenSha256',checkpoint.token_sha256,'validUntil',checkpoint.valid_until),identity_authority_hash(scope),checkpoint.created_at);
 INSERT INTO identity_authority_command_checkpoint_outbox VALUES(identifier,owner,'authority-checkpoint','pending',checkpoint.created_at);
 RETURN jsonb_build_object('id',identifier,'tenantId',owner,'validUntil',deadline::text,'recorded',true);
END; $$;

DROP TRIGGER IF EXISTS identity_authority_checkpoint_commit ON identity_authority_command_checkpoints;
CREATE CONSTRAINT TRIGGER identity_authority_checkpoint_commit AFTER INSERT OR UPDATE ON identity_authority_command_checkpoints DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_authority_checkpoint_commit();
DO $$ DECLARE relation TEXT;owned BOOLEAN;routine TEXT;BEGIN
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')
  AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) ORDER BY relname LOOP
  owned=relation IN('identity_authority_command_checkpoints','identity_authority_command_checkpoint_events','identity_authority_command_checkpoint_outbox');
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_checkpoint_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_authority_checkpoint_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_authority_checkpoint_no_effects()',relation);
  IF owned THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_authority_checkpoint_guard ON %I',relation);
   EXECUTE format('CREATE TRIGGER identity_authority_checkpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_checkpoint_guard()',relation);
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_stage_no_effects ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_stage_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_stage_no_effects()',relation);
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_stage_no_truncate ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_stage_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_authority_stage_no_effects()',relation);
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_seal_no_effects ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_seal_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_namespace_no_effects()',relation);
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_seal_no_truncate ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_seal_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_authority_namespace_no_effects()',relation);
  ELSE
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_checkpoint_no_effects ON %I',relation);
   EXECUTE format('CREATE TRIGGER aaa_identity_authority_checkpoint_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_checkpoint_no_effects()',relation);
  END IF;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_authority_command_context(jsonb)','identity_authority_checkpoint_no_effects()','identity_authority_checkpoint_guard()',
  'identity_authority_checkpoint_receiving()','identity_authority_checkpoint_commit()','identity_authority_command_checkpoint(uuid,jsonb,jsonb,bigint)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
