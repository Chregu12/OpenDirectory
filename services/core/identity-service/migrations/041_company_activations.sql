CREATE TABLE IF NOT EXISTS identity_company_activations (
 id UUID PRIMARY KEY,registration_id UUID NOT NULL UNIQUE REFERENCES identity_company_registrations(id),review_id UUID NOT NULL UNIQUE REFERENCES identity_company_registration_reviews(id),
 tenant_id UUID NOT NULL UNIQUE REFERENCES identity_tenants(id),user_id UUID NOT NULL UNIQUE REFERENCES users(id),issuer TEXT NOT NULL,subject TEXT NOT NULL,
 console_client_id TEXT NOT NULL CHECK(console_client_id ~ '^[A-Za-z0-9._~-]{1,255}$'),profile_id UUID NOT NULL UNIQUE,profile_event_id UUID NOT NULL UNIQUE REFERENCES identity_organization_events(id) DEFERRABLE INITIALLY DEFERRED,
 proof_nonce UUID NOT NULL UNIQUE,request_sha256 TEXT NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL UNIQUE,
 CHECK(valid_until>created_at AND valid_until<=created_at+interval '30 seconds'),FOREIGN KEY(profile_id,tenant_id) REFERENCES identity_organization_profiles(id,tenant_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS identity_company_activation_events (
 id UUID PRIMARY KEY REFERENCES identity_company_activations(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),type TEXT NOT NULL CHECK(type='company.activated'),version INTEGER NOT NULL CHECK(version=1),
 correlation_id UUID NOT NULL REFERENCES identity_company_registrations(id),actor JSONB NOT NULL,before_state JSONB NOT NULL,after_state JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_activation_outbox (
 id UUID PRIMARY KEY REFERENCES identity_company_activation_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE OR REPLACE FUNCTION identity_company_activation_scope() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;retained identity_company_activations;
BEGIN
 PERFORM identity_authority_owner();scope=NULLIF(current_setting('opendirectory.company_activation',true),'')::jsonb;SELECT * INTO retained FROM identity_company_activations WHERE transaction_id=txid_current();
 IF scope IS NULL OR (scope->>'transaction_id')::bigint<>txid_current() OR (scope->>'valid_until')::timestamptz<=clock_timestamp() OR retained.id IS NOT NULL AND to_jsonb(retained) IS DISTINCT FROM scope
  THEN RAISE EXCEPTION 'Exact current original company activation required' USING ERRCODE='42501';END IF;RETURN scope;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_activation_snapshot(identifier UUID) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT jsonb_build_object('activation',to_jsonb(activation.*),'canonical',identity_company_registration_snapshot(registration),'profile',to_jsonb(profile.*),'profileEvent',to_jsonb(event),'profileOutbox',to_jsonb(outbox))
 FROM identity_company_registrations registration JOIN identity_company_activations activation ON activation.registration_id=registration.id JOIN identity_organization_profiles profile ON profile.tenant_id=registration.tenant_id
 JOIN identity_organization_events event ON event.id=profile.command_id JOIN identity_organization_outbox outbox ON outbox.id=event.id WHERE registration.id=identifier;
$$;
CREATE OR REPLACE FUNCTION identity_company_activation_valid(identifier UUID) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$
DECLARE activation identity_company_activations;registration identity_company_registrations;event identity_company_activation_events;requested identity_company_registration_events;entry JSONB;field TEXT;relation TEXT;retained BOOLEAN;
BEGIN
 SELECT * INTO registration FROM identity_company_registrations WHERE id=identifier;SELECT * INTO activation FROM identity_company_activations WHERE registration_id=identifier;
 SELECT * INTO event FROM identity_company_activation_events WHERE id=activation.id;SELECT * INTO requested FROM identity_company_registration_events WHERE id=registration.event_id;
 IF activation.id IS NULL OR event.id IS NULL OR requested.id IS NULL OR activation.tenant_id<>registration.tenant_id OR activation.user_id<>registration.user_id OR activation.issuer<>registration.issuer OR activation.subject<>registration.subject
  OR event.tenant_id<>registration.tenant_id OR event.type<>'company.activated' OR event.version<>1 OR event.correlation_id<>identifier OR event.created_at<>activation.created_at OR event.before_state IS DISTINCT FROM requested.receipt
  OR event.after_state->'activation' IS DISTINCT FROM to_jsonb(activation) OR requested.registration_id<>registration.id OR requested.tenant_id<>registration.tenant_id OR requested.type<>'company.registration.requested' OR requested.version<>1 OR requested.correlation_id<>registration.id OR requested.created_at<>registration.created_at
  OR requested.payload IS DISTINCT FROM jsonb_build_object('registrationId',registration.id,'administratorId',registration.user_id,'status','pending-verification','requestSha256',registration.request_sha256)
  OR registration.payload_sha256<>identity_authority_hash(jsonb_build_object('registrationId',registration.id,'subject',registration.subject,'principal',jsonb_build_object('username',registration.username,'email',registration.email,'displayName',registration.display_name),'profile',registration.profile))
  OR registration.profile IS DISTINCT FROM identity_organization_profile_data(jsonb_populate_record(NULL::identity_organization_profiles,event.after_state->'profile'))
  OR event.actor IS DISTINCT FROM jsonb_build_object('kind','credential-bound-company-activation','issuer',registration.issuer,'subject',registration.subject,'userId',registration.user_id,'proofNonce',activation.proof_nonce,'requestSha256',activation.request_sha256)
  OR NOT EXISTS(SELECT 1 FROM identity_company_registration_outbox WHERE id=requested.id AND tenant_id=registration.tenant_id AND status='pending' AND created_at=requested.created_at)
  OR NOT EXISTS(SELECT 1 FROM identity_company_activation_outbox WHERE id=event.id AND tenant_id=event.tenant_id AND status='pending' AND created_at=event.created_at)
  OR NOT EXISTS(SELECT 1 FROM identity_company_registration_reviews WHERE registration_id=identifier AND id=activation.review_id AND decision='approved') OR NOT identity_company_review_valid(identifier)
  OR event.after_state->'canonical'->'tenant'->'enabled' IS DISTINCT FROM 'true'::jsonb OR event.after_state->'canonical'->'user'->'enabled' IS DISTINCT FROM 'true'::jsonb
  OR event.after_state->'profile'->>'command_id' IS DISTINCT FROM activation.profile_event_id::text OR event.after_state->'profile'->>'id' IS DISTINCT FROM activation.profile_id::text THEN RETURN false;END IF;
 FOR field,relation IN SELECT * FROM (VALUES ('tenantEvents','identity_tenant_events'),('tenantOutbox','identity_tenant_outbox'),('userAudit','identity_user_audit'),('userOutbox','identity_user_outbox'),('authorizationAudit','identity_authorization_audit'),('recordAudit','identity_user_record_audit'),('linkAudit','identity_link_audit')) evidence(field,relation) LOOP
  IF jsonb_typeof(event.after_state->'canonical'->field) IS DISTINCT FROM 'array' OR jsonb_array_length(event.after_state->'canonical'->field)=0 THEN RETURN false;END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(event.after_state->'canonical'->field) LOOP
   EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I source WHERE to_jsonb(source)=$1)',relation) INTO retained USING entry;IF NOT retained THEN RETURN false;END IF;
  END LOOP;
 END LOOP;
 RETURN EXISTS(SELECT 1 FROM jsonb_array_elements(event.after_state->'canonical'->'userAudit') source WHERE source->>'revision'=event.after_state->'canonical'->'user'->>'eligibility_revision' AND source->'details'->'enabled'='true'::jsonb)
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(event.after_state->'canonical'->'userOutbox') source WHERE source->>'revision'=event.after_state->'canonical'->'user'->>'eligibility_revision' AND source->'payload'->'enabled'='true'::jsonb)
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(event.after_state->'canonical'->'authorizationAudit') source WHERE source->>'revision'=event.after_state->'canonical'->'user'->>'authorization_revision' AND source->'details'->'enabled'='true'::jsonb)
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(event.after_state->'canonical'->'recordAudit') source WHERE source->>'revision'=event.after_state->'canonical'->'user'->>'record_revision' AND source->'details'->'after'->'enabled'='true'::jsonb)
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(event.after_state->'canonical'->'tenantEvents') source WHERE source->>'action'='tenant-update' AND source->'details'->'enabled'='true'::jsonb AND source->'details'->>'version'=event.after_state->'canonical'->'tenant'->>'version')
 AND EXISTS(SELECT 1 FROM identity_organization_events source JOIN identity_organization_outbox outbox USING(id) WHERE source.id=activation.profile_event_id AND to_jsonb(source)=event.after_state->'profileEvent'
  AND to_jsonb(outbox)=event.after_state->'profileOutbox' AND source.after_state=event.after_state->'profile' AND source.tenant_id=activation.tenant_id);
END; $$;
CREATE OR REPLACE FUNCTION identity_company_registration_retained_valid(identifier UUID) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM identity_company_activations WHERE registration_id=identifier) THEN identity_company_activation_valid(identifier) ELSE identity_company_registration_valid(identifier) END;
$$;
CREATE OR REPLACE FUNCTION identity_company_owner_active(owner identity_company_activations) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT identity_company_activation_valid(owner.registration_id) AND identity_tenant_user_enabled(owner.user_id) AND identity_tenant_id('user',owner.user_id)=owner.tenant_id
  AND EXISTS(SELECT 1 FROM identity_subject_links WHERE issuer=owner.issuer AND subject=owner.subject AND user_id=owner.user_id)
  AND EXISTS(SELECT 1 FROM identity_subject_tenant_bindings WHERE issuer=owner.issuer AND subject=owner.subject AND tenant_id=owner.tenant_id);
$$;
CREATE OR REPLACE FUNCTION identity_company_activation_fence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;
BEGIN
 IF NULLIF(current_setting('opendirectory.company_activation',true),'') IS NULL AND NOT EXISTS(SELECT 1 FROM identity_company_activations WHERE transaction_id=txid_current()) THEN
  IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 scope=identity_company_activation_scope();
 IF TG_OP IN('DELETE','TRUNCATE') OR EXISTS(SELECT 1 FROM identity_company_activation_events WHERE id=(scope->>'id')::uuid) THEN RAISE EXCEPTION 'Only original new-company activation effects allowed' USING ERRCODE='42501';END IF;data=to_jsonb(NEW);
 IF TG_TABLE_NAME IN('identity_company_activations','identity_company_activation_outbox') THEN RETURN NEW;
 ELSIF TG_TABLE_NAME='identity_tenants' THEN
  IF TG_OP<>'UPDATE' OR NEW.id::text IS DISTINCT FROM scope->>'tenant_id' OR NOT NEW.enabled OR (to_jsonb(NEW)-ARRAY['enabled','version','generation']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['enabled','version','generation']) THEN RAISE EXCEPTION 'Only the reviewed company can activate' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='users' THEN
  IF TG_OP<>'UPDATE' OR NEW.id::text IS DISTINCT FROM scope->>'user_id' OR (to_jsonb(NEW)-ARRAY['enabled','authorization_revision','eligibility_revision','tenant_generation','record_revision','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['enabled','authorization_revision','eligibility_revision','tenant_generation','record_revision','updated_at']) THEN RAISE EXCEPTION 'Only the reviewed candidate can activate' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME IN('identity_organization_profiles','identity_organization_events','identity_organization_outbox') THEN
  IF TG_OP<>'INSERT' OR data->>'tenant_id' IS DISTINCT FROM scope->>'tenant_id' THEN RAISE EXCEPTION 'Only the original new company profile allowed' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME IN('identity_user_audit','identity_user_outbox','identity_user_record_audit','identity_authorization_audit','identity_tenant_events','identity_tenant_outbox') THEN
  IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 OR data ? 'user_id' AND data->>'user_id' IS DISTINCT FROM scope->>'user_id' OR data ? 'tenant_id' AND data->>'tenant_id' IS DISTINCT FROM scope->>'tenant_id' THEN RAISE EXCEPTION 'Only actual activation audit fanout allowed' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'Unrelated effects cannot ride company activation' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_activation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;expected JSONB;registration identity_company_registrations;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Company activation records are immutable' USING ERRCODE='42501';END IF;scope=identity_company_activation_scope();
 SELECT * INTO registration FROM identity_company_registrations WHERE id=(scope->>'registration_id')::uuid;
 IF TG_TABLE_NAME='identity_company_activations' THEN expected=scope;
 ELSIF TG_TABLE_NAME='identity_company_activation_events' THEN expected=jsonb_build_object('id',scope->'id','tenant_id',scope->'tenant_id','type','company.activated','version',1,'correlation_id',scope->'registration_id',
  'actor',jsonb_build_object('kind','credential-bound-company-activation','issuer',scope->'issuer','subject',scope->'subject','userId',scope->'user_id','proofNonce',scope->'proof_nonce','requestSha256',scope->'request_sha256'),
  'before_state',(SELECT receipt FROM identity_company_registration_events WHERE id=registration.event_id),'after_state',identity_company_activation_snapshot(registration.id),'created_at',scope->'created_at');
 ELSE expected=jsonb_build_object('id',scope->'id','tenant_id',scope->'tenant_id','status','pending','created_at',scope->'created_at');END IF;
 IF to_jsonb(NEW) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact original company activation evidence required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_activation_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;owned BOOLEAN;
BEGIN
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  owned=relation IN('identity_company_activations','identity_company_activation_events','identity_company_activation_outbox');
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname=CASE WHEN owned THEN 'identity_company_activation_guard' ELSE 'aaa_identity_company_activation_fence' END AND tgtype=31 AND tgenabled='O'
   AND tgfoid=(CASE WHEN owned THEN 'identity_company_activation_guard()' ELSE 'identity_company_activation_fence()' END)::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_company_activation_no_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='identity_company_activation_fence()'::regprocedure) THEN RAISE EXCEPTION 'Company activation receiving unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_activations'::regclass AND tgname='identity_company_activation_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_company_activation_commit()'::regprocedure) THEN RAISE EXCEPTION 'Deferred company activation required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_activation_admit(proof JSONB,input JSONB) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE registration identity_company_registrations;
BEGIN
 PERFORM identity_authority_owner();
 SELECT * INTO registration FROM identity_company_registrations WHERE id=(input->>'registrationId')::uuid;
 IF EXISTS(SELECT 1 FROM identity_company_activations WHERE registration_id=registration.id) THEN
  IF proof->>'issuer' IS DISTINCT FROM registration.issuer OR input->>'subject' IS DISTINCT FROM registration.subject OR identity_authority_hash(input)<>registration.payload_sha256 THEN RAISE EXCEPTION 'Registration key conflict' USING ERRCODE='23505';END IF;
  IF NOT identity_company_activation_valid(registration.id) THEN RAISE EXCEPTION 'Retained company activation unavailable' USING ERRCODE='42501';END IF;RETURN jsonb_build_object('id',registration.id,'replayed',true);
 END IF;RETURN identity_company_registration_submit(proof,input);
END; $$;
CREATE OR REPLACE FUNCTION identity_company_activate(proof JSONB,input JSONB) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE registration identity_company_registrations;activation identity_company_activations;profile identity_organization_profiles;event identity_organization_events;source JSONB;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_activation_receiving();PERFORM identity_organization_receiving();
 IF NULLIF(current_setting('opendirectory.company_activation',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_activations WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION 'One independent company activation required' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(proof) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(proof))<>6 OR COALESCE(proof->>'issuer','')!~'^https?://[^/?#@[:space:]]+([^?#[:space:]]*)$'
  OR length(proof->>'issuer')>2048 OR proof->>'subject' IS DISTINCT FROM input->>'subject' OR COALESCE(proof->>'nonce','')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  OR COALESCE(proof->>'issuedAt','')!~'^[1-9][0-9]{0,12}$' OR COALESCE(proof->>'expiresAt','')!~'^[1-9][0-9]{0,12}$' OR COALESCE(proof->>'requestSha256','')!~'^[a-f0-9]{64}$'
  OR jsonb_typeof(input) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(input))<>3 OR COALESCE(input->>'consoleClientId','')!~'^[A-Za-z0-9._~-]{1,255}$' THEN RAISE EXCEPTION 'Exact issuer-bound activation required' USING ERRCODE='23514';END IF;
 IF to_timestamp((proof->>'expiresAt')::bigint)<=clock_timestamp() OR (proof->>'expiresAt')::bigint>(proof->>'issuedAt')::bigint+30 OR to_timestamp((proof->>'issuedAt')::bigint)>clock_timestamp()+interval '1 second' THEN RAISE EXCEPTION 'Original activation proof expired' USING ERRCODE='28000';END IF;
 PERFORM identity_tenant_lock(ARRAY['registration:'||(input->>'registrationId')]);SELECT * INTO registration FROM identity_company_registrations WHERE id=(input->>'registrationId')::uuid FOR UPDATE;
 IF registration.id IS NULL OR registration.issuer IS DISTINCT FROM proof->>'issuer' OR registration.subject IS DISTINCT FROM input->>'subject' THEN RAISE EXCEPTION 'Own registration not found' USING ERRCODE='23503';END IF;
 SELECT * INTO activation FROM identity_company_activations WHERE registration_id=registration.id;
 IF activation.id IS NOT NULL THEN
  IF activation.console_client_id IS DISTINCT FROM input->>'consoleClientId' THEN RAISE EXCEPTION 'Activation console conflict' USING ERRCODE='23505';END IF;
  IF NOT identity_company_activation_valid(registration.id) THEN RAISE EXCEPTION 'Activation history unavailable' USING ERRCODE='42501';END IF;RETURN jsonb_build_object('id',activation.id,'replayed',true);
 END IF;
 PERFORM id FROM users WHERE id=registration.user_id FOR UPDATE;PERFORM id FROM identity_tenants WHERE id=registration.tenant_id FOR UPDATE;
 IF NOT identity_company_registration_valid(registration.id) OR NOT identity_company_review_valid(registration.id) OR NOT EXISTS(SELECT 1 FROM identity_company_registration_reviews WHERE registration_id=registration.id AND decision='approved') THEN RAISE EXCEPTION 'Independently approved unchanged registration required' USING ERRCODE='23514';END IF;
 SELECT id INTO activation.review_id FROM identity_company_registration_reviews WHERE registration_id=registration.id;
 activation.id=gen_random_uuid();activation.registration_id=registration.id;activation.tenant_id=registration.tenant_id;activation.user_id=registration.user_id;activation.issuer=registration.issuer;activation.subject=registration.subject;
 activation.console_client_id=input->>'consoleClientId';activation.profile_id=gen_random_uuid();activation.profile_event_id=gen_random_uuid();activation.proof_nonce=(proof->>'nonce')::uuid;activation.request_sha256=proof->>'requestSha256';activation.created_at=clock_timestamp();activation.valid_until=to_timestamp((proof->>'expiresAt')::bigint);activation.transaction_id=txid_current();
 PERFORM set_config('opendirectory.company_activation',to_jsonb(activation)::text,true);PERFORM set_config('opendirectory.tenant_reason','Independent approved company applicant activation',true);
 PERFORM set_config('opendirectory.actor',jsonb_build_object('kind','company-activation','issuer',registration.issuer,'subject',registration.subject,'registrationId',registration.id)::text,true);
 INSERT INTO identity_company_activations SELECT activation.*;
 UPDATE identity_tenants SET enabled=true,version=version+1 WHERE id=registration.tenant_id;UPDATE users SET enabled=true WHERE id=registration.user_id;
 source=registration.profile;profile.id=activation.profile_id;profile.tenant_id=registration.tenant_id;profile.version=1;profile.name=source->>'name';profile.legal_form=source->>'legalForm';profile.registration_number=source->>'registrationNumber';profile.tax_id=source->>'taxId';
 profile.address_line1=source->>'addressLine1';profile.address_line2=source->>'addressLine2';profile.postal_code=source->>'postalCode';profile.city=source->>'city';profile.country=source->>'country';profile.timezone=source->>'timezone';profile.default_language=source->>'defaultLanguage';profile.contact_email=source->>'contactEmail';profile.contact_phone=source->>'contactPhone';profile.website=source->>'website';
 profile.command_id=activation.profile_event_id;profile.created_at=activation.created_at;profile.updated_at=activation.created_at;INSERT INTO identity_organization_profiles SELECT profile.*;
 event.id=profile.command_id;event.tenant_id=registration.tenant_id;event.organization_id=profile.id;event.action='created';event.actor=jsonb_build_object('kind','company-activation','issuer',registration.issuer,'subject',registration.subject,'userId',registration.user_id);
 event.token_sha256=identity_authority_hash(to_jsonb(activation.proof_nonce));event.reason='Original approved registration profile activation';event.after_state=to_jsonb(profile);event.created_at=activation.created_at;event.valid_until=activation.valid_until;event.transaction_id=txid_current();
 INSERT INTO identity_organization_events SELECT event.*;INSERT INTO identity_organization_outbox VALUES(event.id,event.tenant_id,event.action,'pending',event.created_at);
 INSERT INTO identity_company_activation_events VALUES(activation.id,activation.tenant_id,'company.activated',1,registration.id,
  jsonb_build_object('kind','credential-bound-company-activation','issuer',registration.issuer,'subject',registration.subject,'userId',registration.user_id,'proofNonce',activation.proof_nonce,'requestSha256',activation.request_sha256),
  (SELECT receipt FROM identity_company_registration_events WHERE id=registration.event_id),identity_company_activation_snapshot(registration.id),activation.created_at);
 INSERT INTO identity_company_activation_outbox VALUES(activation.id,activation.tenant_id,'pending',activation.created_at);RETURN jsonb_build_object('id',activation.id,'replayed',false);
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_no_effects() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.company_activation',true),'') IS NOT NULL AND TG_OP='INSERT' AND TG_TABLE_NAME IN('identity_company_activations','identity_company_activation_events','identity_company_activation_outbox') THEN
  PERFORM identity_company_activation_scope();RETURN NEW;
 END IF;
 IF NULLIF(current_setting('opendirectory.organization_mutation',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_organization_events WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION 'Unrelated effects cannot ride an organization mutation' USING ERRCODE='42501';END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_activation_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_company_activation_receiving();PERFORM identity_organization_receiving();
 IF NEW.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original company activation expired at commit' USING ERRCODE='28000';END IF;
 IF identity_company_activation_scope() IS DISTINCT FROM to_jsonb(NEW) OR NOT identity_company_activation_valid(NEW.registration_id)
  OR NOT identity_company_owner_active(NEW) OR (SELECT after_state FROM identity_company_activation_events WHERE id=NEW.id) IS DISTINCT FROM identity_company_activation_snapshot(NEW.registration_id)
  OR EXISTS(SELECT 1 FROM identity_role_assignments WHERE user_id=NEW.user_id) OR EXISTS(SELECT 1 FROM identity_pim_eligibilities WHERE user_id=NEW.user_id)
  THEN RAISE EXCEPTION 'Exact company owner activation and current receipt required' USING ERRCODE='42501';END IF;RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS identity_company_activation_commit ON identity_company_activations;
CREATE CONSTRAINT TRIGGER identity_company_activation_commit AFTER INSERT ON identity_company_activations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_activation_commit();

CREATE OR REPLACE FUNCTION identity_organization_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;owner UUID;
BEGIN
 IF NULLIF(current_setting('opendirectory.company_activation',true),'') IS NOT NULL THEN
  scope=identity_company_activation_scope();IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Only initial company profile allowed' USING ERRCODE='42501';END IF;
  IF TG_TABLE_NAME='identity_organization_profiles' THEN
   IF NEW.id::text IS DISTINCT FROM scope->>'profile_id' OR NEW.tenant_id::text IS DISTINCT FROM scope->>'tenant_id' OR NEW.command_id::text IS DISTINCT FROM scope->>'profile_event_id' OR NEW.version<>1
    OR NEW.created_at<>(scope->>'created_at')::timestamptz OR NEW.updated_at<>NEW.created_at OR identity_organization_profile_data(NEW) IS DISTINCT FROM (SELECT profile FROM identity_company_registrations WHERE id=(scope->>'registration_id')::uuid) THEN RAISE EXCEPTION 'Original reviewed registration profile required' USING ERRCODE='42501';END IF;
  ELSIF TG_TABLE_NAME='identity_organization_events' THEN
   IF NEW.id::text IS DISTINCT FROM scope->>'profile_event_id' OR NEW.tenant_id::text IS DISTINCT FROM scope->>'tenant_id' OR NEW.organization_id::text IS DISTINCT FROM scope->>'profile_id' OR NEW.action<>'created' OR NEW.before_state IS NOT NULL
    OR NEW.actor IS DISTINCT FROM jsonb_build_object('kind','company-activation','issuer',scope->'issuer','subject',scope->'subject','userId',scope->'user_id') OR NEW.token_sha256<>identity_authority_hash(scope->'proof_nonce')
    OR NEW.reason<>'Original approved registration profile activation' OR NEW.created_at<>(scope->>'created_at')::timestamptz OR NEW.valid_until<>(scope->>'valid_until')::timestamptz OR NEW.transaction_id<>txid_current()
    OR NEW.after_state IS DISTINCT FROM (SELECT to_jsonb(profile) FROM identity_organization_profiles profile WHERE id=(scope->>'profile_id')::uuid) THEN RAISE EXCEPTION 'Original initial profile event required' USING ERRCODE='42501';END IF;
  ELSIF to_jsonb(NEW) IS DISTINCT FROM jsonb_build_object('id',scope->'profile_event_id','tenant_id',scope->'tenant_id','action','created','status','pending','created_at',scope->'created_at') THEN RAISE EXCEPTION 'Initial profile pending outbox required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 PERFORM identity_authority_owner();scope=NULLIF(current_setting('opendirectory.organization_mutation',true),'')::jsonb;data=to_jsonb(NEW);
 IF scope IS NULL OR TG_OP='DELETE' THEN RAISE EXCEPTION 'Exact organization mutation admission required' USING ERRCODE='42501';END IF;
 owner=identity_authority_actor_home(scope->'actor');
 IF scope->>'tenant_id' IS DISTINCT FROM owner::text OR (scope->>'transaction_id')::bigint<>txid_current() THEN RAISE EXCEPTION 'Owned current organization command required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_organization_profiles' THEN
  IF data IS DISTINCT FROM scope->'after_state' OR NEW.tenant_id<>owner OR NEW.command_id::text IS DISTINCT FROM scope->>'id' OR NOT identity_organization_profile_valid(identity_organization_profile_data(NEW))
   OR TG_OP='INSERT' AND (scope->'before_state'<>'null'::jsonb OR NEW.version<>1 OR NEW.created_at<>NEW.updated_at)
   OR TG_OP='UPDATE' AND (to_jsonb(OLD) IS DISTINCT FROM scope->'before_state' OR NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id OR NEW.created_at<>OLD.created_at OR NEW.version<>OLD.version+1)
   OR EXISTS(SELECT 1 FROM identity_organization_events WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION 'Exact versioned owned organization effect required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='identity_organization_events' THEN
  IF TG_OP<>'INSERT' OR data IS DISTINCT FROM scope OR NEW.action IS DISTINCT FROM (CASE WHEN NEW.before_state IS NULL THEN 'created' ELSE 'updated' END)
   OR NOT EXISTS(SELECT 1 FROM identity_organization_profiles profile WHERE profile.command_id=NEW.id AND to_jsonb(profile)=NEW.after_state) THEN RAISE EXCEPTION 'Exact immutable organization event required' USING ERRCODE='42501';END IF;
 ELSE
  IF TG_OP<>'INSERT' OR data IS DISTINCT FROM jsonb_build_object('id',scope->'id','tenant_id',scope->'tenant_id','action',scope->'action','status','pending','created_at',scope->'created_at') THEN RAISE EXCEPTION 'Exact pending organization outbox required' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;event identity_organization_events;profile identity_organization_profiles;
BEGIN
 IF NULLIF(current_setting('opendirectory.company_activation',true),'') IS NOT NULL THEN
  scope=identity_company_activation_scope();PERFORM identity_organization_receiving();
  IF NEW.id::text IS DISTINCT FROM scope->>'profile_id' OR NEW.command_id::text IS DISTINCT FROM scope->>'profile_event_id' OR NOT identity_company_activation_valid((scope->>'registration_id')::uuid) THEN RAISE EXCEPTION 'Original activation profile receipt required' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 PERFORM identity_authority_owner();PERFORM identity_organization_receiving();PERFORM identity_authority_checkpoint_receiving();
 scope=NULLIF(current_setting('opendirectory.organization_mutation',true),'')::jsonb;SELECT * INTO profile FROM identity_organization_profiles WHERE id=NEW.id;
 SELECT * INTO event FROM identity_organization_events WHERE id=profile.command_id;
 IF event.id IS NULL OR event.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original organization assurance expired or absent' USING ERRCODE='28000';END IF;
 IF scope IS DISTINCT FROM to_jsonb(event) OR event.after_state IS DISTINCT FROM to_jsonb(profile) OR event.transaction_id<>txid_current() OR identity_authority_actor_home(event.actor)<>event.tenant_id
  OR NOT EXISTS(SELECT 1 FROM identity_organization_outbox outbox WHERE outbox.id=event.id AND outbox.tenant_id=event.tenant_id AND outbox.action=event.action AND outbox.status='pending' AND outbox.created_at=event.created_at)
  OR NOT EXISTS(SELECT 1 FROM identity_authority_command_checkpoints checkpoint WHERE checkpoint.transaction_id=event.transaction_id AND checkpoint.tenant_id=event.tenant_id AND checkpoint.user_id=(event.actor->>'userId')::uuid
   AND checkpoint.original_context=event.actor-ARRAY['issuer','subject'] AND checkpoint.token_sha256=event.token_sha256 AND checkpoint.valid_until<=event.valid_until AND checkpoint.valid_until>clock_timestamp()) THEN RAISE EXCEPTION 'Exact organization event outbox and original checkpoint required' USING ERRCODE='42501';END IF;
 IF event.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original organization assurance expired' USING ERRCODE='28000';END IF;
 RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_tenant_review(relation_identity OID) RETURNS void LANGUAGE plpgsql AS $$
DECLARE owner_role NAME;explanation TEXT;
BEGIN
 SELECT pg_get_userbyid(relowner) INTO owner_role FROM pg_class WHERE oid=relation_identity;
 IF owner_role IS NULL OR NOT pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none' THEN RAISE EXCEPTION 'Explicit actual-owner tenant review required' USING ERRCODE='42501';END IF;

 IF NULLIF(current_setting('opendirectory.company_activation',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_activations WHERE transaction_id=txid_current()) THEN
  PERFORM identity_company_activation_scope();IF relation_identity<>'identity_tenants'::regclass THEN RAISE EXCEPTION 'Only reviewed tenant enablement allowed' USING ERRCODE='42501';END IF;RETURN;
 END IF;
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

DO $$ DECLARE relation TEXT;owned BOOLEAN;routine TEXT;guard TEXT;BEGIN
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  owned=relation IN('identity_company_activations','identity_company_activation_events','identity_company_activation_outbox');
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_company_activation_no_truncate ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_company_activation_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_activation_fence()',relation);
  IF owned THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_company_activation_guard ON %I',relation);EXECUTE format('CREATE TRIGGER identity_company_activation_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_activation_guard()',relation);
   FOR guard,routine IN SELECT * FROM (VALUES ('identity_authority_stage','identity_authority_stage_no_effects'),('identity_authority_seal','identity_authority_namespace_no_effects'),('identity_authority_checkpoint','identity_authority_checkpoint_no_effects'),('identity_authority_source_set','identity_authority_source_set_no_effects'),('identity_organization','identity_organization_no_effects'),('identity_company_registration','identity_company_registration_fence'),('identity_company_review','identity_company_review_no_effects')) guards(name,routine) LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||CASE WHEN guard='identity_company_registration' THEN '_fence' ELSE '_no_effects' END,relation);
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()','aaa_'||guard||CASE WHEN guard='identity_company_registration' THEN '_fence' ELSE '_no_effects' END,relation,routine);
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||'_no_truncate',relation);EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()','aaa_'||guard||'_no_truncate',relation,routine);
   END LOOP;
  ELSE EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_company_activation_fence ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_company_activation_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_activation_fence()',relation);END IF;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_company_activation_scope()','identity_company_activation_snapshot(uuid)','identity_company_activation_valid(uuid)','identity_company_registration_retained_valid(uuid)','identity_company_owner_active(identity_company_activations)','identity_company_activation_fence()','identity_company_activation_guard()','identity_company_activation_receiving()','identity_company_activation_admit(jsonb,jsonb)','identity_company_activate(jsonb,jsonb)','identity_company_activation_commit()','identity_organization_guard()','identity_organization_commit()','identity_organization_no_effects()','identity_tenant_review(oid)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
