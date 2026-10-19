CREATE TABLE IF NOT EXISTS identity_company_registrations (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL UNIQUE REFERENCES identity_tenants(id) DEFERRABLE INITIALLY DEFERRED,
 user_id UUID NOT NULL UNIQUE REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED,issuer TEXT NOT NULL,subject TEXT NOT NULL,username TEXT NOT NULL,email TEXT NOT NULL,display_name TEXT NOT NULL,
 profile JSONB NOT NULL CHECK(identity_organization_profile_valid(profile)),payload_sha256 TEXT NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 proof_nonce UUID NOT NULL UNIQUE,proof_issued_at TIMESTAMPTZ NOT NULL,proof_valid_until TIMESTAMPTZ NOT NULL,request_sha256 TEXT NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 event_id UUID NOT NULL UNIQUE,created_at TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL UNIQUE,UNIQUE(issuer,subject),CHECK(proof_valid_until>created_at AND proof_valid_until<=proof_issued_at+interval '30 seconds')
);
CREATE TABLE IF NOT EXISTS identity_company_registration_events (
 id UUID PRIMARY KEY,registration_id UUID NOT NULL UNIQUE REFERENCES identity_company_registrations(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 type TEXT NOT NULL CHECK(type='company.registration.requested'),version INTEGER NOT NULL CHECK(version=1),correlation_id UUID NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,payload JSONB NOT NULL,receipt JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_registration_outbox (
 id UUID PRIMARY KEY REFERENCES identity_company_registration_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='identity_company_registrations'::regclass AND conname='identity_company_registration_event') THEN
  ALTER TABLE identity_company_registrations ADD CONSTRAINT identity_company_registration_event FOREIGN KEY(event_id) REFERENCES identity_company_registration_events(id) DEFERRABLE INITIALLY DEFERRED;
 END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_registration_scope() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;retained identity_company_registrations;
BEGIN
 PERFORM identity_authority_owner();scope=NULLIF(current_setting('opendirectory.company_registration',true),'')::jsonb;
 SELECT * INTO retained FROM identity_company_registrations WHERE transaction_id=txid_current();
 IF scope IS NULL OR (scope->>'transaction_id')::bigint<>txid_current() OR (scope->>'proof_valid_until')::timestamptz<=clock_timestamp()
  OR retained.id IS NOT NULL AND to_jsonb(retained) IS DISTINCT FROM scope THEN RAISE EXCEPTION 'Exact current company registration admission required' USING ERRCODE='42501';END IF;
 RETURN scope;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_review(relation_identity OID) RETURNS void LANGUAGE plpgsql AS $$
DECLARE owner_role NAME;explanation TEXT;
BEGIN
 SELECT pg_get_userbyid(relowner) INTO owner_role FROM pg_class WHERE oid=relation_identity;
 IF owner_role IS NULL OR NOT pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none' THEN RAISE EXCEPTION 'Explicit actual-owner tenant review required' USING ERRCODE='42501';END IF;
 IF NULLIF(current_setting('opendirectory.company_registration',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_registrations WHERE transaction_id=txid_current()) THEN
  PERFORM identity_company_registration_scope();
  IF relation_identity NOT IN('identity_tenants'::regclass,'identity_tenant_ownership'::regclass) THEN RAISE EXCEPTION 'Company registration cannot review other resources' USING ERRCODE='42501';END IF;RETURN;
 END IF;
 explanation=current_setting('opendirectory.tenant_reason',true);
 IF owner_role IS NULL OR NOT pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
  OR current_setting('opendirectory.tenant_review',true) IS DISTINCT FROM 'explicit-offline-owner-review'
  OR explanation IS NULL OR length(btrim(explanation)) NOT BETWEEN 10 AND 500 OR explanation ~ '[[:cntrl:]]'
  THEN RAISE EXCEPTION 'Explicit actual-owner tenant review required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_registration_fence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;identifier UUID;
BEGIN
 IF NULLIF(current_setting('opendirectory.company_registration',true),'') IS NULL AND NOT EXISTS(SELECT 1 FROM identity_company_registrations WHERE transaction_id=txid_current()) THEN
  IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 scope=identity_company_registration_scope();identifier=(scope->>'id')::uuid;
 IF TG_OP IN('DELETE','TRUNCATE') OR EXISTS(SELECT 1 FROM identity_company_registration_events WHERE registration_id=identifier) THEN RAISE EXCEPTION 'Only original pending registration effects are admitted' USING ERRCODE='42501';END IF;
 data=to_jsonb(NEW);
 IF TG_TABLE_NAME='identity_tenants' THEN
  IF TG_OP<>'INSERT' OR NEW.id::text IS DISTINCT FROM scope->>'tenant_id' OR NEW.enabled OR NEW.external_key IS DISTINCT FROM 'registration-'||identifier::text OR NEW.display_name IS DISTINCT FROM scope->'profile'->>'name'
   THEN RAISE EXCEPTION 'One new disabled registration tenant required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='users' THEN
  IF NEW.id::text IS DISTINCT FROM scope->>'user_id' OR NEW.enabled OR NEW.username IS DISTINCT FROM scope->>'username' OR NEW.email IS DISTINCT FROM scope->>'email'
   OR NEW.display_name IS DISTINCT FROM scope->>'display_name' OR NEW.department IS NOT NULL OR NEW.title IS NOT NULL
   OR TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['authorization_revision','eligibility_revision','tenant_generation','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['authorization_revision','eligibility_revision','tenant_generation','updated_at'])
   THEN RAISE EXCEPTION 'One new disabled canonical administrator candidate required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='identity_tenant_ownership' THEN
  IF TG_OP<>'INSERT' OR NEW.resource_kind<>'user' OR NEW.resource_id::text IS DISTINCT FROM scope->>'user_id' OR NEW.tenant_id::text IS DISTINCT FROM scope->>'tenant_id' OR NEW.reviewed_version<>1 THEN RAISE EXCEPTION 'Only the new registration candidate can be owned' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME IN('identity_subject_links','identity_subject_tenant_bindings') THEN
  IF TG_OP<>'INSERT' OR NEW.issuer IS DISTINCT FROM scope->>'issuer' OR NEW.subject IS DISTINCT FROM scope->>'subject'
   OR TG_TABLE_NAME='identity_subject_links' AND data->>'user_id' IS DISTINCT FROM scope->>'user_id'
   OR TG_TABLE_NAME='identity_subject_tenant_bindings' AND data->>'tenant_id' IS DISTINCT FROM scope->>'tenant_id' THEN RAISE EXCEPTION 'Only the verified credential subject may be bound' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME IN('identity_user_audit','identity_user_outbox','identity_user_record_audit','identity_authorization_audit','identity_link_audit','identity_tenant_events','identity_tenant_outbox') THEN
  IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 OR data ? 'user_id' AND data->>'user_id' IS DISTINCT FROM scope->>'user_id'
   OR data ? 'tenant_id' AND data->>'tenant_id' IS DISTINCT FROM scope->>'tenant_id' THEN RAISE EXCEPTION 'Only actual registration-triggered evidence is allowed' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'Unrelated effects cannot ride company registration' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_registration_snapshot(registration identity_company_registrations) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT jsonb_build_object(
  'tenant',(SELECT to_jsonb(tenant) FROM identity_tenants tenant WHERE id=registration.tenant_id),
  'user',(SELECT to_jsonb(account) FROM users account WHERE id=registration.user_id),
  'ownership',(SELECT to_jsonb(ownership) FROM identity_tenant_ownership ownership WHERE resource_kind='user' AND resource_id=registration.user_id),
  'link',(SELECT to_jsonb(link) FROM identity_subject_links link WHERE issuer=registration.issuer AND subject=registration.subject),
  'binding',(SELECT to_jsonb(binding) FROM identity_subject_tenant_bindings binding WHERE issuer=registration.issuer AND subject=registration.subject),
  'tenantEvents',(SELECT jsonb_agg(to_jsonb(event) ORDER BY id) FROM identity_tenant_events event WHERE tenant_id=registration.tenant_id),
  'tenantOutbox',(SELECT jsonb_agg(to_jsonb(outbox) ORDER BY id) FROM identity_tenant_outbox outbox WHERE tenant_id=registration.tenant_id),
  'userAudit',(SELECT jsonb_agg(to_jsonb(event) ORDER BY id) FROM identity_user_audit event WHERE user_id=registration.user_id),
  'userOutbox',(SELECT jsonb_agg(to_jsonb(outbox) ORDER BY id) FROM identity_user_outbox outbox WHERE user_id=registration.user_id),
  'recordAudit',(SELECT jsonb_agg(to_jsonb(event) ORDER BY id) FROM identity_user_record_audit event WHERE user_id=registration.user_id),
  'authorizationAudit',(SELECT jsonb_agg(to_jsonb(event) ORDER BY id) FROM identity_authorization_audit event WHERE user_id=registration.user_id),
  'linkAudit',(SELECT jsonb_agg(to_jsonb(event) ORDER BY id) FROM identity_link_audit event WHERE details->>'issuer'=registration.issuer AND details->>'subject'=registration.subject));
$$;
CREATE OR REPLACE FUNCTION identity_company_registration_valid(identifier UUID) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$
DECLARE registration identity_company_registrations;event identity_company_registration_events;snapshot JSONB;
BEGIN
 SELECT * INTO registration FROM identity_company_registrations WHERE id=identifier;SELECT * INTO event FROM identity_company_registration_events WHERE id=registration.event_id;
 IF registration.id IS NULL OR event.id IS NULL THEN RETURN false;END IF;snapshot=identity_company_registration_snapshot(registration);
 RETURN event.registration_id=registration.id AND event.tenant_id=registration.tenant_id AND event.type='company.registration.requested' AND event.version=1 AND event.correlation_id=registration.id AND event.created_at=registration.created_at
  AND event.payload=jsonb_build_object('registrationId',registration.id,'administratorId',registration.user_id,'status','pending-verification','requestSha256',registration.request_sha256)
  AND event.receipt=snapshot AND EXISTS(SELECT 1 FROM identity_company_registration_outbox outbox WHERE outbox.id=event.id AND outbox.tenant_id=event.tenant_id AND outbox.status='pending' AND outbox.created_at=event.created_at)
  AND snapshot->'tenant'->'enabled'='false'::jsonb AND snapshot->'tenant'->>'version'='1' AND snapshot->'tenant'->>'external_key'='registration-'||registration.id::text
  AND snapshot->'user'->'enabled'='false'::jsonb AND snapshot->'user'->>'username'=registration.username AND snapshot->'user'->>'email'=registration.email AND snapshot->'user'->>'display_name'=registration.display_name
  AND snapshot->'ownership'->>'tenant_id'=registration.tenant_id::text AND snapshot->'link'->>'user_id'=registration.user_id::text AND snapshot->'binding'->>'tenant_id'=registration.tenant_id::text
  AND jsonb_array_length(snapshot->'tenantEvents')=3 AND jsonb_array_length(snapshot->'tenantOutbox')=3
  AND NOT EXISTS(SELECT 1 FROM identity_tenant_events source LEFT JOIN identity_tenant_outbox outbox ON outbox.id=source.id AND outbox.tenant_id=source.tenant_id AND outbox.action=source.action WHERE source.tenant_id=registration.tenant_id AND outbox.id IS NULL)
  AND EXISTS(SELECT 1 FROM users account JOIN identity_user_audit audit ON audit.user_id=account.id AND audit.revision=account.eligibility_revision
   JOIN identity_user_outbox outbox ON outbox.user_id=account.id AND outbox.revision=audit.revision WHERE account.id=registration.user_id AND audit.details->'enabled'='false'::jsonb AND outbox.payload->'enabled'='false'::jsonb)
  AND EXISTS(SELECT 1 FROM users account JOIN identity_authorization_audit audit ON audit.user_id=account.id AND audit.revision=account.authorization_revision WHERE account.id=registration.user_id AND audit.details->'enabled'='false'::jsonb)
  AND EXISTS(SELECT 1 FROM users account JOIN identity_user_record_audit audit ON audit.user_id=account.id AND audit.revision=account.record_revision WHERE account.id=registration.user_id AND audit.details->'after'->'enabled'='false'::jsonb)
  AND jsonb_array_length(snapshot->'linkAudit')=1
  AND (SELECT count(*) FROM identity_tenant_ownership WHERE tenant_id=registration.tenant_id)=1 AND (SELECT count(*) FROM identity_subject_links WHERE user_id=registration.user_id)=1
  AND NOT EXISTS(SELECT 1 FROM identity_role_assignments WHERE user_id=registration.user_id) AND NOT EXISTS(SELECT 1 FROM identity_pim_eligibilities WHERE user_id=registration.user_id)
  AND NOT EXISTS(SELECT 1 FROM identity_organization_profiles WHERE tenant_id=registration.tenant_id) AND NOT EXISTS(SELECT 1 FROM identity_organization_delegations WHERE user_id=registration.user_id);
END; $$;
CREATE OR REPLACE FUNCTION identity_company_registration_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;expected JSONB;
BEGIN
 PERFORM identity_authority_owner();IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Company registration and evidence are immutable' USING ERRCODE='42501';END IF;scope=identity_company_registration_scope();
 IF TG_TABLE_NAME='identity_company_registrations' THEN expected=scope;
 ELSIF TG_TABLE_NAME='identity_company_registration_events' THEN
  expected=jsonb_build_object('id',scope->'event_id','registration_id',scope->'id','tenant_id',scope->'tenant_id','type','company.registration.requested','version',1,'correlation_id',scope->'id','created_at',scope->'created_at',
   'payload',jsonb_build_object('registrationId',scope->'id','administratorId',scope->'user_id','status','pending-verification','requestSha256',scope->'request_sha256'),
   'receipt',identity_company_registration_snapshot(jsonb_populate_record(NULL::identity_company_registrations,scope)));
 ELSE expected=jsonb_build_object('id',scope->'event_id','tenant_id',scope->'tenant_id','status','pending','created_at',scope->'created_at');END IF;
 IF to_jsonb(NEW) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact registration record and evidence required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_registration_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;owned BOOLEAN;
BEGIN
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  owned=relation IN('identity_company_registrations','identity_company_registration_events','identity_company_registration_outbox');
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname=CASE WHEN owned THEN 'identity_company_registration_guard' ELSE 'aaa_identity_company_registration_fence' END
   AND tgtype=31 AND tgenabled='O' AND tgfoid=(CASE WHEN owned THEN 'identity_company_registration_guard()' ELSE 'identity_company_registration_fence()' END)::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_company_registration_no_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='identity_company_registration_fence()'::regprocedure)
   THEN RAISE EXCEPTION 'Company registration receiving unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_registrations'::regclass AND tgname='identity_company_registration_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_company_registration_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Deferred registration receiving unavailable' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_registration_submit(proof JSONB,input JSONB) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE registration identity_company_registrations;event identity_company_registration_events;scope JSONB;digest TEXT;reason TEXT='Verified credential registration pending independent verification';
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_registration_receiving();
 IF NULLIF(current_setting('opendirectory.company_registration',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_registrations WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION 'One independent registration command required' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(proof)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(proof))<>6 OR COALESCE(proof->>'issuer','')!~'^https?://[^/?#@[:space:]]+([^?#[:space:]]*)$'
  OR length(proof->>'issuer')>2048 OR COALESCE(proof->>'subject','')='' OR length(proof->>'subject')>255 OR proof->>'subject' IS DISTINCT FROM input->>'subject'
  OR COALESCE(proof->>'nonce','')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' OR COALESCE(proof->>'issuedAt','')!~'^[1-9][0-9]{0,12}$' OR COALESCE(proof->>'expiresAt','')!~'^[1-9][0-9]{0,12}$'
  OR COALESCE(proof->>'requestSha256','')!~'^[a-f0-9]{64}$' OR jsonb_typeof(input)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(input))<>4
  OR COALESCE(input->>'registrationId','')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' OR NOT identity_organization_profile_valid(input->'profile')
  OR jsonb_typeof(input->'principal')<>'object' OR (SELECT count(*) FROM jsonb_object_keys(input->'principal'))<>3 THEN RAISE EXCEPTION 'Exact registration principal, profile and issuer proof required' USING ERRCODE='23514';END IF;
 IF to_timestamp((proof->>'expiresAt')::bigint)<=clock_timestamp() OR (proof->>'expiresAt')::bigint>(proof->>'issuedAt')::bigint+30 OR to_timestamp((proof->>'issuedAt')::bigint)>clock_timestamp()+interval '1 second' THEN RAISE EXCEPTION 'Original registration proof expired' USING ERRCODE='28000';END IF;
 PERFORM identity_tenant_lock(ARRAY['registration:'||(input->>'registrationId'),'registration-subject:'||identity_authority_hash(jsonb_build_array(proof->>'issuer',input->>'subject'))]);
 digest=identity_authority_hash(input);SELECT * INTO registration FROM identity_company_registrations WHERE id=(input->>'registrationId')::uuid;
 IF registration.id IS NOT NULL THEN
  IF registration.issuer IS DISTINCT FROM proof->>'issuer' OR registration.subject IS DISTINCT FROM input->>'subject' OR registration.payload_sha256<>digest THEN RAISE EXCEPTION 'Registration key is bound to a different exact request' USING ERRCODE='23505';END IF;
  IF NOT COALESCE(identity_company_registration_valid(registration.id),false) THEN RAISE EXCEPTION 'Retained registration evidence unavailable' USING ERRCODE='42501';END IF;
  RETURN jsonb_build_object('id',registration.id,'replayed',true);
 END IF;
 IF EXISTS(SELECT 1 FROM identity_subject_links WHERE issuer=proof->>'issuer' AND subject=input->>'subject') OR EXISTS(SELECT 1 FROM identity_subject_tenant_bindings WHERE issuer=proof->>'issuer' AND subject=input->>'subject')
  OR EXISTS(SELECT 1 FROM identity_company_registrations WHERE issuer=proof->>'issuer' AND subject=input->>'subject') THEN RAISE EXCEPTION 'Credential subject already has a canonical registration or binding' USING ERRCODE='23505';END IF;
 registration.id=(input->>'registrationId')::uuid;registration.tenant_id=gen_random_uuid();registration.user_id=gen_random_uuid();registration.issuer=proof->>'issuer';registration.subject=input->>'subject';
 registration.username=input->'principal'->>'username';registration.email=input->'principal'->>'email';registration.display_name=input->'principal'->>'displayName';registration.profile=input->'profile';registration.payload_sha256=digest;
 IF registration.username IS NULL OR length(btrim(registration.username)) NOT BETWEEN 1 AND 255 OR registration.username<>btrim(registration.username) OR registration.username~'[[:cntrl:]]'
  OR registration.email IS NULL OR length(registration.email)>254 OR registration.email!~'^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
  OR registration.display_name IS NULL OR length(btrim(registration.display_name)) NOT BETWEEN 1 AND 255 OR registration.display_name<>btrim(registration.display_name) OR registration.display_name~'[[:cntrl:]]' THEN RAISE EXCEPTION 'Bounded verified credential principal required' USING ERRCODE='23514';END IF;
 registration.proof_nonce=(proof->>'nonce')::uuid;registration.proof_issued_at=to_timestamp((proof->>'issuedAt')::bigint);registration.proof_valid_until=to_timestamp((proof->>'expiresAt')::bigint);registration.request_sha256=proof->>'requestSha256';
 registration.event_id=gen_random_uuid();registration.created_at=clock_timestamp();registration.transaction_id=txid_current();scope=to_jsonb(registration);
 PERFORM set_config('opendirectory.company_registration',scope::text,true);PERFORM set_config('opendirectory.tenant_reason',reason,true);
 PERFORM set_config('opendirectory.actor',jsonb_build_object('kind','company-registration','issuer',registration.issuer,'subject',registration.subject,'registrationId',registration.id)::text,true);
 INSERT INTO identity_company_registrations SELECT registration.*;
 INSERT INTO identity_tenants(id,external_key,display_name) VALUES(registration.tenant_id,'registration-'||registration.id::text,registration.profile->>'name');
 INSERT INTO users(id,username,email,display_name,enabled) VALUES(registration.user_id,registration.username,registration.email,registration.display_name,false);
 INSERT INTO identity_tenant_ownership(resource_kind,resource_id,tenant_id,reviewed_version,reason) VALUES('user',registration.user_id,registration.tenant_id,1,reason);
 INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES(registration.issuer,registration.subject,registration.user_id);
 event.id=registration.event_id;event.registration_id=registration.id;event.tenant_id=registration.tenant_id;event.type='company.registration.requested';event.version=1;event.correlation_id=registration.id;event.created_at=registration.created_at;
 event.payload=jsonb_build_object('registrationId',registration.id,'administratorId',registration.user_id,'status','pending-verification','requestSha256',registration.request_sha256);event.receipt=identity_company_registration_snapshot(registration);
 INSERT INTO identity_company_registration_events SELECT event.*;INSERT INTO identity_company_registration_outbox VALUES(event.id,event.tenant_id,'pending',event.created_at);
 RETURN jsonb_build_object('id',registration.id,'replayed',false);
END; $$;
CREATE OR REPLACE FUNCTION identity_company_registration_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_company_registration_receiving();
 IF NEW.proof_valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original registration proof expired at commit' USING ERRCODE='28000';END IF;
 IF identity_company_registration_scope() IS DISTINCT FROM to_jsonb(NEW) OR NOT COALESCE(identity_company_registration_valid(NEW.id),false) THEN RAISE EXCEPTION 'Exact pending registration and retained evidence required' USING ERRCODE='42501';END IF;
 RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS identity_company_registration_commit ON identity_company_registrations;
CREATE CONSTRAINT TRIGGER identity_company_registration_commit AFTER INSERT ON identity_company_registrations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_registration_commit();
DO $$ DECLARE relation TEXT;owned BOOLEAN;routine TEXT;guard TEXT;BEGIN
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  owned=relation IN('identity_company_registrations','identity_company_registration_events','identity_company_registration_outbox');
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_company_registration_no_truncate ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_company_registration_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_registration_fence()',relation);
  IF owned THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_company_registration_guard ON %I',relation);EXECUTE format('CREATE TRIGGER identity_company_registration_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_registration_guard()',relation);
   FOR guard,routine IN SELECT * FROM (VALUES ('identity_authority_stage','identity_authority_stage_no_effects'),('identity_authority_seal','identity_authority_namespace_no_effects'),('identity_authority_checkpoint','identity_authority_checkpoint_no_effects'),('identity_authority_source_set','identity_authority_source_set_no_effects'),('identity_organization','identity_organization_no_effects')) guards(name,routine) LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||'_no_effects',relation);EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()','aaa_'||guard||'_no_effects',relation,routine);
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||'_no_truncate',relation);EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()','aaa_'||guard||'_no_truncate',relation,routine);
   END LOOP;
  ELSE EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_company_registration_fence ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_company_registration_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_registration_fence()',relation);END IF;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_company_registration_scope()','identity_company_registration_fence()','identity_company_registration_snapshot(identity_company_registrations)','identity_company_registration_valid(uuid)','identity_company_registration_guard()','identity_company_registration_receiving()','identity_company_registration_submit(jsonb,jsonb)','identity_company_registration_commit()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
