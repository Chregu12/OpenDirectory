CREATE TABLE IF NOT EXISTS identity_directory_user_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),user_id UUID NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('update','delete','invalidate')),actor JSONB NOT NULL,
 scope_sha256 TEXT NOT NULL CHECK(scope_sha256 ~ '^[a-f0-9]{64}$'),details JSONB NOT NULL,
 transaction_id BIGINT NOT NULL DEFAULT txid_current(),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS identity_directory_user_events_target ON identity_directory_user_events(tenant_id,user_id,created_at);
CREATE TABLE IF NOT EXISTS identity_directory_user_outbox (
 id UUID PRIMARY KEY REFERENCES identity_directory_user_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action IN ('update','delete','invalidate')),status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION identity_directory_user_state(data JSONB) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN data IS NULL THEN NULL ELSE data || jsonb_build_object('authorization_revision',data->>'authorization_revision',
  'eligibility_revision',data->>'eligibility_revision','record_revision',data->>'record_revision','tenant_generation',data->>'tenant_generation') END;
$$;

CREATE OR REPLACE FUNCTION identity_directory_user_evidence_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;event identity_directory_user_events%ROWTYPE;
BEGIN
 proof=NULLIF(current_setting('opendirectory.user_mutation',true),'')::jsonb;
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 OR proof IS NULL
  OR NEW.id::text IS DISTINCT FROM proof->>'operationId'
  OR current_setting('opendirectory.user_mutation_admitted',true) IS DISTINCT FROM proof->>'operationId'
  OR NEW.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id'
  OR NEW.action IS DISTINCT FROM proof->'target'->>'action'
  THEN RAISE EXCEPTION 'Actual user mutation transition evidence required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_directory_user_events' THEN
  IF NEW.user_id::text IS DISTINCT FROM proof->'target'->>'id'
   OR NEW.actor IS DISTINCT FROM jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId')
   OR NEW.scope_sha256 IS DISTINCT FROM encode(sha256(convert_to(proof::text,'UTF8')),'hex')
   OR NEW.transaction_id<>txid_current()
   THEN RAISE EXCEPTION 'Exact original-actor user mutation evidence required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO event FROM identity_directory_user_events WHERE id=NEW.id;
  IF event.id IS NULL OR event.tenant_id<>NEW.tenant_id OR event.action<>NEW.action OR event.transaction_id<>txid_current()
   THEN RAISE EXCEPTION 'Exact user mutation outbox origin required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_user_mutation_actor(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor_id UUID;target UUID;action TEXT;reduction BOOLEAN;
BEGIN
 actor_id=(proof->'context'->>'userId')::uuid;target=(proof->'target'->>'id')::uuid;action=proof->'target'->>'action';
 reduction=COALESCE(actor_id=target AND (action IN ('delete','invalidate') OR action='update'
  AND proof->'target'->'before'->'enabled'='true'::jsonb AND proof->'target'->'expectedValues'->'enabled'='false'::jsonb),false);
 IF NOT reduction THEN PERFORM identity_directory_creation_actor(proof);RETURN;END IF;
 IF proof->>'validUntil' IS NULL OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  OR proof->'target'->'before'->>'authorization_revision' IS DISTINCT FROM proof->'context'->>'revision'
  OR proof->'target'->'before'->'enabled' IS DISTINCT FROM 'true'::jsonb
  OR identity_subject_link_role_state(actor_id) IS DISTINCT FROM proof->'rolesSnapshot'
  OR NOT EXISTS(SELECT 1 FROM identity_tenants tenant JOIN identity_subject_tenant_bindings binding ON binding.tenant_id=tenant.id
   WHERE tenant.id=identity_tenant_id('user',target) AND tenant.id::text=proof->'tenant'->>'id' AND tenant.enabled
   AND tenant.version::text=proof->'tenant'->>'version' AND tenant.generation::text=proof->'tenant'->>'generation'
   AND binding.issuer=proof->>'issuer' AND binding.subject=proof->>'subject')
  THEN RAISE EXCEPTION 'Original self-reduction authority is no longer current' USING ERRCODE='42501';END IF;
 IF action='delete' THEN
  IF EXISTS(SELECT 1 FROM users WHERE id=actor_id) OR EXISTS(SELECT 1 FROM identity_subject_links WHERE issuer=proof->>'issuer' AND subject=proof->>'subject')
   OR NOT EXISTS(SELECT 1 FROM identity_link_audit evidence WHERE evidence.action='unlink' AND evidence.actor=proof->>'subject'
    AND evidence.details->>'issuer'=proof->>'issuer' AND evidence.details->>'subject'=proof->>'subject' AND evidence.details->>'user_id'=actor_id::text
    AND evidence.details->>'authorization_revision'=proof->'context'->>'linkRevision')
   THEN RAISE EXCEPTION 'Actual original-subject deletion and unlink required' USING ERRCODE='42501';END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM users account JOIN identity_subject_links link ON link.user_id=account.id
   WHERE account.id=actor_id AND link.issuer=proof->>'issuer' AND link.subject=proof->>'subject'
   AND link.authorization_revision::text=proof->'context'->>'linkRevision'
   AND account.authorization_revision>(proof->'context'->>'revision')::bigint
   AND account.enabled=(action='invalidate'))
   THEN RAISE EXCEPTION 'Actual original-subject authority reduction required' USING ERRCODE='42501';END IF;
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_directory_user_mutation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;action TEXT;before_state JSONB;after_state JSONB;actual JSONB;owner_role NAME;
 event identity_directory_user_events%ROWTYPE;omitted TEXT[];changed_status BOOLEAN;
BEGIN
 proof=NULLIF(current_setting('opendirectory.user_mutation',true),'')::jsonb;
 IF proof IS NULL THEN
  IF TG_WHEN='AFTER' AND EXISTS(SELECT 1 FROM identity_directory_user_events WHERE user_id=OLD.id AND transaction_id=txid_current())
   THEN RAISE EXCEPTION 'User mutation scope cannot disappear before commit' USING ERRCODE='42501';END IF;
  IF TG_WHEN='BEFORE' THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;ELSE RETURN NULL;END IF;
 END IF;
 action=proof->'target'->>'action';before_state=identity_directory_user_state(to_jsonb(OLD));
 IF proof->'target'->>'id' IS DISTINCT FROM OLD.id::text OR proof->'target'->'before' IS DISTINCT FROM before_state
  OR identity_tenant_id('user',OLD.id)::text IS DISTINCT FROM proof->'tenant'->>'id'
  OR action IS NULL OR action NOT IN ('update','delete','invalidate') OR (TG_OP='DELETE') IS DISTINCT FROM (action='delete')
  THEN RAISE EXCEPTION 'Exact owned user mutation target and locked version required' USING ERRCODE='23514';END IF;
 IF TG_WHEN='BEFORE' THEN
  SELECT pg_catalog.pg_get_userbyid(relowner) INTO owner_role FROM pg_catalog.pg_class WHERE oid=TG_RELID;
  IF owner_role IS NULL OR NOT pg_catalog.pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
   THEN RAISE EXCEPTION 'Actual database owner required for original-actor user mutation' USING ERRCODE='42501';END IF;
  PERFORM identity_directory_creation_actor(proof);
  IF NULLIF(current_setting('opendirectory.user_mutation_admitted',true),'') IS NOT NULL
   THEN RAISE EXCEPTION 'One exact user transition per original-actor admission required' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' THEN
   omitted=CASE WHEN action='invalidate' THEN ARRAY['authorization_revision'] ELSE ARRAY['username','email','display_name','department','title','enabled','updated_at'] END;
   IF identity_directory_user_state(to_jsonb(NEW))-omitted IS DISTINCT FROM before_state-omitted
    OR identity_directory_creation_values('user',to_jsonb(NEW)) IS DISTINCT FROM proof->'target'->'expectedValues'
    OR action='invalidate' AND NEW.authorization_revision<>OLD.authorization_revision+1
    THEN RAISE EXCEPTION 'Only exact requested user fields may change' USING ERRCODE='23514';END IF;
  ELSIF proof->'target'->'expectedValues' IS DISTINCT FROM 'null'::jsonb
   THEN RAISE EXCEPTION 'Deletion cannot carry replacement user values' USING ERRCODE='23514';END IF;
  PERFORM set_config('opendirectory.user_mutation_admitted',proof->>'operationId',true);
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 IF TG_NAME='identity_directory_user_mutation_record' THEN
  IF current_setting('opendirectory.user_mutation_admitted',true) IS DISTINCT FROM proof->>'operationId'
   THEN RAISE EXCEPTION 'Actual admitted user transition required' USING ERRCODE='42501';END IF;
  IF TG_OP='UPDATE' THEN after_state=identity_directory_user_state(to_jsonb(NEW));END IF;
  INSERT INTO identity_directory_user_events(id,tenant_id,user_id,action,actor,scope_sha256,details)
   VALUES((proof->>'operationId')::uuid,(proof->'tenant'->>'id')::uuid,OLD.id,action,
    jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId'),
    encode(sha256(convert_to(proof::text,'UTF8')),'hex'),jsonb_build_object('beforeRevision',before_state->>'record_revision',
     'afterRevision',after_state->>'record_revision','beforeSha256',encode(sha256(convert_to(before_state::text,'UTF8')),'hex'),
     'afterSha256',CASE WHEN after_state IS NULL THEN NULL ELSE encode(sha256(convert_to(after_state::text,'UTF8')),'hex') END));
  INSERT INTO identity_directory_user_outbox(id,tenant_id,action) VALUES((proof->>'operationId')::uuid,(proof->'tenant'->>'id')::uuid,action);RETURN NULL;
 END IF;
 SELECT evidence.* INTO event FROM identity_directory_user_events evidence WHERE evidence.id=(proof->>'operationId')::uuid AND evidence.user_id=OLD.id
  AND evidence.tenant_id=(proof->'tenant'->>'id')::uuid AND evidence.action=proof->'target'->>'action' AND evidence.transaction_id=txid_current()
  AND evidence.scope_sha256=encode(sha256(convert_to(proof::text,'UTF8')),'hex');
 IF event.id IS NULL OR NOT EXISTS(SELECT 1 FROM identity_directory_user_outbox evidence WHERE evidence.id=event.id AND evidence.tenant_id=event.tenant_id AND evidence.action=event.action)
  THEN RAISE EXCEPTION 'Durable exact user mutation receipt required' USING ERRCODE='23514';END IF;
 actual=identity_directory_user_state(identity_directory_creation_row('user',OLD.id));
 IF TG_OP='DELETE' THEN
  IF actual IS NOT NULL OR event.details->'afterSha256' IS DISTINCT FROM 'null'::jsonb
   OR NOT EXISTS(SELECT 1 FROM identity_tenant_retirements WHERE resource_kind='user' AND resource_id=OLD.id AND tenant_id=event.tenant_id)
   OR NOT EXISTS(SELECT 1 FROM identity_deleted_users deleted JOIN identity_user_audit audit ON audit.user_id=deleted.user_id AND audit.revision=deleted.revision
    JOIN identity_user_outbox outbox ON outbox.user_id=deleted.user_id AND outbox.revision=deleted.revision
    WHERE deleted.user_id=OLD.id AND deleted.revision>OLD.eligibility_revision AND audit.actor=proof->>'subject'
    AND audit.details->'deleted'='true'::jsonb AND outbox.payload->'deleted'='true'::jsonb AND outbox.payload->'enabled'='false'::jsonb)
   OR NOT EXISTS(SELECT 1 FROM identity_authorization_audit WHERE user_id=OLD.id AND reason='deleted' AND revision>OLD.authorization_revision AND actor=proof->>'subject')
   OR NOT EXISTS(SELECT 1 FROM identity_user_record_audit evidence WHERE evidence.user_id=OLD.id AND evidence.action='delete' AND evidence.revision>OLD.record_revision AND evidence.actor=proof->>'subject')
   THEN RAISE EXCEPTION 'Actual user deletion and retained negative evidence required' USING ERRCODE='23514';END IF;
 ELSE
  changed_status=NEW.enabled IS DISTINCT FROM OLD.enabled;
  omitted=ARRAY['record_revision','authorization_revision','eligibility_revision'] || CASE WHEN action='update'
   THEN ARRAY['username','email','display_name','department','title','enabled','updated_at'] ELSE ARRAY[]::text[] END;
  IF actual IS NULL OR actual IS DISTINCT FROM identity_directory_user_state(to_jsonb(NEW))
   OR actual-omitted IS DISTINCT FROM before_state-omitted
   OR event.details->>'afterSha256' IS DISTINCT FROM encode(sha256(convert_to(actual::text,'UTF8')),'hex')
   OR identity_directory_creation_values('user',actual) IS DISTINCT FROM proof->'target'->'expectedValues'
   OR NEW.record_revision<=OLD.record_revision OR NEW.tenant_generation<>OLD.tenant_generation
   OR (changed_status OR action='invalidate') AND NEW.authorization_revision<=OLD.authorization_revision
   OR NOT (changed_status OR action='invalidate') AND NEW.authorization_revision<>OLD.authorization_revision
   OR changed_status AND NEW.eligibility_revision<=OLD.eligibility_revision
   OR NOT changed_status AND NEW.eligibility_revision<>OLD.eligibility_revision
   OR NOT EXISTS(SELECT 1 FROM identity_user_record_audit evidence WHERE evidence.user_id=OLD.id AND evidence.revision=NEW.record_revision
    AND evidence.action='update' AND evidence.actor=proof->>'subject'
    AND evidence.details->'after'=proof->'target'->'expectedValues')
   OR (changed_status OR action='invalidate') AND NOT EXISTS(SELECT 1 FROM identity_authorization_audit evidence WHERE evidence.user_id=OLD.id
    AND evidence.revision=NEW.authorization_revision AND evidence.actor=proof->>'subject' AND evidence.details->'enabled'=to_jsonb(NEW.enabled)
    AND evidence.reason=CASE WHEN changed_status THEN 'enabled_changed' ELSE 'security_reset' END)
   OR changed_status AND NOT EXISTS(SELECT 1 FROM identity_user_audit audit JOIN identity_user_outbox outbox ON outbox.user_id=audit.user_id AND outbox.revision=audit.revision
    WHERE audit.user_id=OLD.id AND audit.revision=NEW.eligibility_revision AND audit.actor=proof->>'subject'
    AND audit.details->'enabled'=to_jsonb(NEW.enabled) AND outbox.payload->'enabled'=to_jsonb(NEW.enabled) AND outbox.payload->'deleted'='false'::jsonb)
   THEN RAISE EXCEPTION 'Exact final user content and authority generations required' USING ERRCODE='23514';END IF;
 END IF;
 PERFORM identity_directory_user_mutation_actor(proof);RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS aaa_identity_directory_user_mutation ON users;
CREATE TRIGGER aaa_identity_directory_user_mutation BEFORE UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION identity_directory_user_mutation_guard();
DROP TRIGGER IF EXISTS identity_directory_user_mutation_record ON users;
CREATE TRIGGER identity_directory_user_mutation_record AFTER UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION identity_directory_user_mutation_guard();
DROP TRIGGER IF EXISTS identity_directory_user_mutation_commit ON users;
CREATE CONSTRAINT TRIGGER identity_directory_user_mutation_commit AFTER UPDATE OR DELETE ON users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_directory_user_mutation_guard();
DO $$ DECLARE relation TEXT;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_directory_user_events','identity_directory_user_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_directory_user_evidence_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_directory_user_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_directory_user_evidence_guard()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_directory_user_state(jsonb)','identity_directory_user_evidence_guard()',
  'identity_directory_user_mutation_actor(jsonb)','identity_directory_user_mutation_guard()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
