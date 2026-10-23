BEGIN;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS company_tenant JSONB;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS company_request JSONB;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS company_event_id UUID;
ALTER TABLE oauth_client_audit ADD COLUMN IF NOT EXISTS company_event_id UUID UNIQUE;
ALTER TABLE oauth_client_audit ADD COLUMN IF NOT EXISTS company_transaction BIGINT;
CREATE UNIQUE INDEX IF NOT EXISTS oauth_company_app_revision ON oauth_client_audit(client_id,revision) WHERE company_event_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS oauth_company_app_outbox(
 id UUID PRIMARY KEY REFERENCES oauth_client_audit(company_event_id) DEFERRABLE INITIALLY DEFERRED,
 fingerprint TEXT NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$'),status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending')
);
CREATE TABLE IF NOT EXISTS oauth_company_app_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='oauth_clients'::regclass AND conname='oauth_company_app_event') THEN
  ALTER TABLE oauth_clients ADD CONSTRAINT oauth_company_app_event FOREIGN KEY(company_event_id) REFERENCES oauth_client_audit(company_event_id) DEFERRABLE INITIALLY DEFERRED;
 END IF;
END; $$;
CREATE OR REPLACE FUNCTION oauth_company_app_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM oauth_company_app_manifest)<>5 OR EXISTS(SELECT 1 FROM oauth_company_app_manifest WHERE to_regprocedure(signature) IS NULL OR digest<>md5(pg_get_functiondef(to_regprocedure(signature))))
  OR (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND (
   tgrelid='oauth_clients'::regclass AND(tgname='oauth_company_app_before' AND tgtype=23 AND tgfoid='oauth_company_app_guard()'::regprocedure
    OR tgname='oauth_company_app_event' AND tgtype=21 AND tgfoid='oauth_company_app_event()'::regprocedure
    OR tgname='oauth_company_app_commit' AND tgtype=21 AND tgfoid='oauth_company_app_guard()'::regprocedure AND tgdeferrable AND tginitdeferred)
   OR tgrelid='oauth_client_audit'::regclass AND tgname='oauth_company_app_evidence' AND tgtype=7 AND tgfoid='oauth_company_app_evidence_guard()'::regprocedure
   OR tgrelid IN('oauth_company_app_outbox'::regclass,'oauth_company_app_manifest'::regclass) AND tgname='oauth_company_app_evidence' AND tgtype=31 AND tgfoid='oauth_company_app_evidence_guard()'::regprocedure
   OR tgrelid IN('oauth_client_audit'::regclass,'oauth_company_app_outbox'::regclass,'oauth_company_app_manifest'::regclass) AND tgname='oauth_company_app_truncate' AND tgtype=34 AND tgfoid='oauth_company_app_evidence_guard()'::regprocedure))<>9
 THEN RAISE EXCEPTION 'Company app receiving unavailable' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION oauth_company_app_record_valid(client_identity TEXT) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE result BOOLEAN;
BEGIN
 PERFORM oauth_company_app_receiving();
 SELECT EXISTS(SELECT 1 FROM oauth_clients client JOIN oauth_client_audit audit ON audit.company_event_id=client.company_event_id AND audit.client_id=client.id AND audit.revision=client.revision
  JOIN oauth_company_app_outbox box ON box.id=audit.company_event_id AND box.status='pending' AND box.fingerprint=encode(sha256(convert_to(to_jsonb(audit)::text,'UTF8')),'hex')
  WHERE client.id=client_identity AND audit.details->'snapshot'=to_jsonb(client)-ARRAY['secret','secret_hash']
  AND audit.details#>'{source,tenant}'=client.company_tenant AND audit.actor_type='user' AND audit.actor_user_id::text=audit.details#>>'{source,actorUserId}') INTO result;
 RETURN result;
END; $$;
CREATE OR REPLACE FUNCTION oauth_company_app_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;proof JSONB;action TEXT;fields TEXT[];
BEGIN
 scope=NULLIF(current_setting('opendirectory.company_apps',true),'')::jsonb;
 IF NEW.company_tenant IS NULL AND (TG_OP='INSERT' OR OLD.company_tenant IS NULL) THEN
  IF scope IS NOT NULL OR NEW.company_request IS NOT NULL OR NEW.company_event_id IS NOT NULL THEN RAISE EXCEPTION 'No unrelated company app effect' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 proof=scope->'source';action=scope->>'action';
 IF jsonb_typeof(proof) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(proof))<>11
  OR proof->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR proof->'companyAppProtocol' IS DISTINCT FROM '1'::jsonb
  OR proof->'permissions' IS DISTINCT FROM '["company.apps.read","company.apps.create","company.apps.update","company.apps.credentials.rotate","company.apps.delete"]'::jsonb
  OR proof->>'actorUserId' IS DISTINCT FROM proof#>>'{context,userId}' OR proof->'tenant' IS DISTINCT FROM NEW.company_tenant
  OR jsonb_typeof(proof->'validUntil') IS DISTINCT FROM 'number' OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  OR (proof->>'validUntil')::numeric>(proof->>'expiresAt')::numeric OR jsonb_typeof(scope->'reason') IS DISTINCT FROM 'string' OR length(btrim(scope->>'reason')) NOT BETWEEN 10 AND 500
  OR jsonb_typeof(NEW.company_tenant) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(NEW.company_tenant))<>3
  OR NOT(NEW.company_tenant->>'id'~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR NOT(NEW.company_tenant->>'version'~'^[1-9][0-9]{0,18}$') OR NOT(NEW.company_tenant->>'generation'~'^[1-9][0-9]{0,18}$')
  OR NEW.grants IS DISTINCT FROM '["client_credentials"]'::jsonb OR NEW.redirect_uris IS DISTINCT FROM '[]'::jsonb
  OR NEW.scopes NOT IN('[]'::jsonb,'["company.automation"]'::jsonb) OR NEW.token_endpoint_auth_method<>'client_secret_post' OR NEW.mfa_required
  THEN RAISE EXCEPTION 'Original bounded company app authority required' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF action IS DISTINCT FROM 'created' OR NEW.enabled OR NEW.company_request->>'requestId' IS DISTINCT FROM NEW.id OR NEW.company_request->>'name' IS DISTINCT FROM NEW.name
   OR NEW.id !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' OR NEW.company_request->>'purpose' IS DISTINCT FROM (CASE WHEN NEW.scopes='[]'::jsonb THEN 'none' ELSE 'company-automation' END)
   OR NEW.company_request->>'reason' IS DISTINCT FROM scope->>'reason' OR NEW.company_request->'confirm' IS DISTINCT FROM 'true'::jsonb
   THEN RAISE EXCEPTION 'Original disabled company app creation required' USING ERRCODE='42501';END IF;
 ELSE
  IF OLD.company_tenant IS NULL OR NEW.company_tenant->>'id' IS DISTINCT FROM OLD.company_tenant->>'id' OR NEW.company_request IS DISTINCT FROM OLD.company_request
   OR NOT oauth_company_app_record_valid(OLD.id) THEN RAISE EXCEPTION 'Immutable original company app required' USING ERRCODE='42501';END IF;
  fields=CASE action WHEN 'updated' THEN ARRAY['name','scopes','enabled'] WHEN 'rotated' THEN ARRAY['secret_hash'] WHEN 'deleted' THEN ARRAY['enabled','deleted_at'] ELSE ARRAY[]::text[] END;
  IF cardinality(fields)=0 OR to_jsonb(NEW)-(fields||ARRAY['revision','updated_at','company_tenant','company_event_id']) IS DISTINCT FROM to_jsonb(OLD)-(fields||ARRAY['revision','updated_at','company_tenant','company_event_id'])
   OR action='deleted' AND (NEW.enabled OR NEW.deleted_at IS NULL) THEN RAISE EXCEPTION 'Bounded company app transition required' USING ERRCODE='42501';END IF;
 END IF;
 IF TG_WHEN='BEFORE' THEN NEW.company_event_id=gen_random_uuid();
 ELSE
  IF NOT oauth_company_app_record_valid(NEW.id) OR NOT EXISTS(SELECT 1 FROM oauth_client_audit audit JOIN oauth_company_app_outbox box ON box.id=audit.company_event_id
   WHERE audit.company_event_id=NEW.company_event_id AND audit.company_transaction=txid_current() AND audit.details->'snapshot'=to_jsonb(NEW)-ARRAY['secret','secret_hash']
   AND box.fingerprint=encode(sha256(convert_to(to_jsonb(audit)::text,'UTF8')),'hex')) THEN RAISE EXCEPTION 'Atomic company app receipt required' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION oauth_company_app_event() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;record oauth_client_audit;
BEGIN
 IF NEW.company_tenant IS NULL THEN RETURN NULL;END IF;scope=current_setting('opendirectory.company_apps')::jsonb;
 INSERT INTO oauth_client_audit(client_id,revision,action,actor_issuer,actor_subject,actor_user_id,actor_type,details,company_event_id,company_transaction)
 VALUES(NEW.id,NEW.revision,scope->>'action',scope#>>'{source,issuer}',scope#>>'{source,subject}',(scope#>>'{source,actorUserId}')::uuid,'user',
  jsonb_build_object('snapshot',to_jsonb(NEW)-ARRAY['secret','secret_hash'],'source',scope->'source','reason',scope->>'reason'),NEW.company_event_id,txid_current()) RETURNING * INTO record;
 INSERT INTO oauth_company_app_outbox(id,fingerprint) VALUES(record.company_event_id,encode(sha256(convert_to(to_jsonb(record)::text,'UTF8')),'hex'));RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION oauth_company_app_evidence_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE data JSONB;
BEGIN
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM oauth_clients WHERE company_tenant IS NOT NULL) THEN RAISE EXCEPTION 'Company app evidence retained' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 data=to_jsonb(NEW);
 IF TG_TABLE_NAME='oauth_client_audit' AND data->>'company_event_id' IS NULL AND NOT EXISTS(SELECT 1 FROM oauth_clients WHERE id=data->>'client_id' AND company_tenant IS NOT NULL) THEN RETURN NEW;END IF;
 IF TG_OP<>'INSERT' OR TG_TABLE_NAME='oauth_company_app_manifest' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Company app evidence is immutable' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='oauth_client_audit' AND((data->>'company_transaction')::bigint IS DISTINCT FROM txid_current() OR NOT EXISTS(SELECT 1 FROM oauth_clients WHERE id=data->>'client_id' AND company_event_id=(data->>'company_event_id')::uuid AND revision=(data->>'revision')::bigint))
  OR TG_TABLE_NAME='oauth_company_app_outbox' AND NOT EXISTS(SELECT 1 FROM oauth_client_audit WHERE company_event_id=(data->>'id')::uuid AND company_transaction=txid_current()
   AND data->>'fingerprint'=encode(sha256(convert_to(to_jsonb(oauth_client_audit)::text,'UTF8')),'hex'))
  THEN RAISE EXCEPTION 'Original physical company app event required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
DO $$ DECLARE relation TEXT;signature TEXT;BEGIN
 DROP TRIGGER IF EXISTS oauth_company_app_evidence ON oauth_company_app_manifest;
 FOREACH signature IN ARRAY ARRAY['oauth_company_app_receiving()','oauth_company_app_record_valid(text)','oauth_company_app_guard()','oauth_company_app_event()','oauth_company_app_evidence_guard()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
  INSERT INTO oauth_company_app_manifest VALUES(signature,md5(pg_get_functiondef(to_regprocedure(signature)))) ON CONFLICT ON CONSTRAINT oauth_company_app_manifest_pkey DO UPDATE SET digest=EXCLUDED.digest;
 END LOOP;
 CREATE OR REPLACE TRIGGER oauth_company_app_before BEFORE INSERT OR UPDATE ON oauth_clients FOR EACH ROW EXECUTE FUNCTION oauth_company_app_guard();
 CREATE OR REPLACE TRIGGER oauth_company_app_event AFTER INSERT OR UPDATE ON oauth_clients FOR EACH ROW EXECUTE FUNCTION oauth_company_app_event();
 DROP TRIGGER IF EXISTS oauth_company_app_commit ON oauth_clients;
 CREATE CONSTRAINT TRIGGER oauth_company_app_commit AFTER INSERT OR UPDATE ON oauth_clients DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION oauth_company_app_guard();
 CREATE OR REPLACE TRIGGER oauth_company_app_evidence BEFORE INSERT ON oauth_client_audit FOR EACH ROW EXECUTE FUNCTION oauth_company_app_evidence_guard();
 FOREACH relation IN ARRAY ARRAY['oauth_company_app_outbox','oauth_company_app_manifest'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER oauth_company_app_evidence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION oauth_company_app_evidence_guard()',relation);
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['oauth_client_audit','oauth_company_app_outbox','oauth_company_app_manifest'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER oauth_company_app_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION oauth_company_app_evidence_guard()',relation);
 END LOOP;
END; $$;
COMMIT;
