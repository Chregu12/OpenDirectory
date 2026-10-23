ALTER TABLE users ADD COLUMN IF NOT EXISTS security_revision BIGINT NOT NULL DEFAULT 1 CHECK(security_revision>0);
CREATE OR REPLACE FUNCTION authentication_credential_revision() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 NEW.record_revision=OLD.record_revision+1;NEW.updated_at=clock_timestamp();NEW.security_revision=OLD.security_revision;
 IF NEW.password_hash IS DISTINCT FROM OLD.password_hash OR NEW.is_locked IS DISTINCT FROM OLD.is_locked OR NEW.locked_until IS DISTINCT FROM OLD.locked_until
  OR NEW.mfa_enabled IS DISTINCT FROM OLD.mfa_enabled OR NEW.mfa_secret IS DISTINCT FROM OLD.mfa_secret OR NEW.recovery_codes IS DISTINCT FROM OLD.recovery_codes THEN NEW.security_revision=OLD.security_revision+1;END IF;
 IF NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN NEW.password_changed_at=NEW.updated_at;END IF;RETURN NEW;
END; $$;
CREATE TABLE IF NOT EXISTS auth_employee_invitations(
 id UUID PRIMARY KEY,tenant JSONB NOT NULL,target_id UUID NOT NULL,subject_id UUID NOT NULL UNIQUE,
 login_name TEXT NOT NULL,token_hash TEXT NOT NULL CHECK(token_hash~'^[a-f0-9]{64}$'),request JSONB NOT NULL,grant_source JSONB NOT NULL,
 status TEXT NOT NULL CHECK(status IN('pending','credential_pending','accepted','revoked')),revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
 created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,creation_event_id UUID NOT NULL,event_id UUID NOT NULL,
 credential_event_id UUID,credential_id UUID UNIQUE REFERENCES users(id),credential_revision BIGINT,identity_receipt JSONB,revocation_request JSONB,
 CHECK((credential_event_id IS NULL)=(credential_id IS NULL) AND (credential_id IS NULL)=(credential_revision IS NULL)),
 CHECK(credential_id IS NULL OR credential_id=subject_id),
 CHECK((status='pending' AND credential_id IS NULL OR status='credential_pending' AND credential_id IS NOT NULL OR status IN('accepted','revoked'))),
 CHECK((status='accepted')=(identity_receipt IS NOT NULL)),
 CHECK((status='revoked')=(revocation_request IS NOT NULL)),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '72 hours')
);
CREATE UNIQUE INDEX IF NOT EXISTS auth_employee_pending_target ON auth_employee_invitations((tenant->>'id'),target_id) WHERE status IN('pending','credential_pending');
CREATE TABLE IF NOT EXISTS auth_employee_invitation_events(
 id UUID PRIMARY KEY,invitation_id UUID NOT NULL REFERENCES auth_employee_invitations(id),action TEXT NOT NULL CHECK(action IN('created','credentialed','accepted','revoked')),
 actor JSONB NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),before_state JSONB,after_state JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL DEFAULT txid_current()
);
CREATE TABLE IF NOT EXISTS auth_employee_invitation_outbox(id UUID PRIMARY KEY REFERENCES auth_employee_invitation_events(id),fingerprint TEXT NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$'),status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'));
CREATE TABLE IF NOT EXISTS auth_employee_invitation_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='auth_employee_invitations'::regclass AND conname='auth_employee_event_fk') THEN
  ALTER TABLE auth_employee_invitations ADD CONSTRAINT auth_employee_event_fk FOREIGN KEY(event_id) REFERENCES auth_employee_invitation_events(id) DEFERRABLE INITIALLY DEFERRED;
  ALTER TABLE auth_employee_invitations ADD CONSTRAINT auth_employee_creation_fk FOREIGN KEY(creation_event_id) REFERENCES auth_employee_invitation_events(id) DEFERRABLE INITIALLY DEFERRED;
  ALTER TABLE auth_employee_invitations ADD CONSTRAINT auth_employee_credential_fk FOREIGN KEY(credential_event_id) REFERENCES auth_employee_invitation_events(id) DEFERRABLE INITIALLY DEFERRED;
 END IF;
END; $$;
CREATE OR REPLACE FUNCTION auth_employee_invitation_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM auth_employee_invitation_manifest)<>8 OR EXISTS(SELECT 1 FROM auth_employee_invitation_manifest WHERE to_regprocedure(signature) IS NULL OR digest<>md5(pg_get_functiondef(to_regprocedure(signature))))
 OR (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND(
  tgrelid='auth_employee_invitations'::regclass AND(tgname='auth_employee_before' AND tgtype=31 AND tgfoid='auth_employee_invitation_guard()'::regprocedure
   OR tgname='auth_employee_after' AND tgtype=21 AND tgfoid='auth_employee_invitation_event()'::regprocedure
   OR tgname='auth_employee_commit' AND tgtype=21 AND tgdeferrable AND tginitdeferred AND tgfoid='auth_employee_invitation_guard()'::regprocedure)
  OR tgrelid IN('auth_employee_invitation_events'::regclass,'auth_employee_invitation_outbox'::regclass,'auth_employee_invitation_manifest'::regclass) AND tgname='auth_employee_evidence' AND tgtype=31 AND tgfoid='auth_employee_invitation_evidence()'::regprocedure
  OR tgrelid IN('auth_employee_invitations'::regclass,'auth_employee_invitation_events'::regclass,'auth_employee_invitation_outbox'::regclass,'auth_employee_invitation_manifest'::regclass) AND tgname='auth_employee_truncate' AND tgtype=34 AND tgfoid='auth_employee_invitation_evidence()'::regprocedure
  OR tgrelid='users'::regclass AND tgname='authentication_credential_revision' AND tgtype=19 AND tgfoid='authentication_credential_revision()'::regprocedure))<>11
 OR EXISTS(SELECT 1 FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname=current_schema() AND relation.relkind='r' AND relation.relname NOT IN('auth_employee_invitations','auth_employee_invitation_events','auth_employee_invitation_outbox','auth_employee_invitation_manifest')
   AND(SELECT count(*) FROM pg_trigger WHERE tgrelid=relation.oid AND NOT tgisinternal AND tgenabled='O' AND tgfoid='auth_employee_invitation_fence()'::regprocedure
    AND(tgname='aaa_auth_employee_fence' AND tgtype=31 OR tgname='auth_employee_effect_commit' AND tgtype=29 AND tgdeferrable AND tginitdeferred OR tgname='auth_employee_effect_truncate' AND tgtype=34))<>3)
 THEN RAISE EXCEPTION 'Original employee invitation receiving unavailable' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION auth_employee_invitation_witness(data JSONB) RETURNS JSONB LANGUAGE sql STABLE AS $$
 SELECT jsonb_build_object('id',data->'id','tenant',data->'tenant','subjectId',data->'subject_id','request',data->'request','source',data->'grant_source',
  'createdAt',to_char((data->>'created_at')::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  'expiresAt',to_char((data->>'expires_at')::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'creationEventId',data->'creation_event_id',
  'credential',CASE WHEN data->'credential_event_id'='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object('eventId',data->'credential_event_id','revision',data->>'credential_revision') END);
$$;
CREATE OR REPLACE FUNCTION auth_employee_invitation_valid(identifier UUID) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
BEGIN
 PERFORM auth_employee_invitation_receiving();RETURN EXISTS(SELECT 1 FROM auth_employee_invitations invitation JOIN auth_employee_invitation_events event ON event.id=invitation.event_id
  JOIN auth_employee_invitation_outbox outbox ON outbox.id=event.id AND outbox.fingerprint=encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex')
  WHERE invitation.id=identifier AND event.invitation_id=invitation.id AND event.after_state=to_jsonb(invitation)-'token_hash');
END; $$;
CREATE OR REPLACE FUNCTION auth_employee_invitation_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;data JSONB;source JSONB;fields TEXT[];credential users;event auth_employee_invitation_events;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Employee invitations are retained' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.employee_invitation',true),'')::jsonb;data=to_jsonb(NEW);source=scope->'ownerSource';
 IF scope IS NULL OR scope->>'action' IS NULL OR scope->>'action' NOT IN('created','credentialed','accepted','revoked')
  OR jsonb_typeof(scope->'validUntil') IS DISTINCT FROM 'number' OR jsonb_typeof(scope#>'{proof,expiresAt}') IS DISTINCT FROM 'number'
  OR scope->>'invitationId' IS DISTINCT FROM NEW.id::text OR (scope->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  OR scope#>>'{proof,issuer}' IS DISTINCT FROM NEW.grant_source->>'issuer' OR scope#>>'{proof,subject}' IS DISTINCT FROM 'oauth-provider'
  OR (scope->>'validUntil')::numeric>(scope#>>'{proof,expiresAt}')::numeric
  THEN RAISE EXCEPTION 'Original employee invitation admission required' USING ERRCODE='42501';END IF;
 IF scope->>'action' IN('created','revoked') AND(source->>'employeeInvitationProtocol' IS DISTINCT FROM '1' OR source#>>'{tenant,id}' IS DISTINCT FROM NEW.tenant->>'id'
  OR source->'permissions' IS DISTINCT FROM '["employees.invitations.read","employees.invitations.create","employees.invitations.revoke"]'::jsonb
  OR jsonb_typeof(source->'validUntil') IS DISTINCT FROM 'number'
  OR (scope->>'validUntil')::numeric>(source->>'validUntil')::numeric) THEN RAISE EXCEPTION 'Current original owner source required' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF scope->>'action' IS DISTINCT FROM 'created' OR NEW.status<>'pending' OR NEW.revision<>1 OR NEW.credential_event_id IS NOT NULL OR NEW.credential_revision IS NOT NULL OR NEW.identity_receipt IS NOT NULL OR NEW.revocation_request IS NOT NULL
   OR NEW.grant_source IS DISTINCT FROM source OR NEW.tenant IS DISTINCT FROM source->'tenant' OR NEW.target_id::text IS DISTINCT FROM source#>>'{target,id}'
   OR NEW.request->>'id' IS DISTINCT FROM NEW.id::text OR NEW.request->>'userId' IS DISTINCT FROM NEW.target_id::text OR NEW.request->>'userRevision' IS DISTINCT FROM source#>>'{target,revision}'
   OR NEW.login_name IS DISTINCT FROM NEW.request->>'loginName' OR NEW.request->'confirm' IS DISTINCT FROM 'true'::jsonb
   OR source#>'{target,enabled}' IS DISTINCT FROM 'false'::jsonb OR source#>'{target,unlinked}' IS DISTINCT FROM 'true'::jsonb OR source#>'{target,ordinary}' IS DISTINCT FROM 'true'::jsonb
   OR NEW.expires_at-NEW.created_at IS DISTINCT FROM (NEW.request->>'durationHours')::integer*interval '1 hour'
   THEN RAISE EXCEPTION 'Exact disabled ordinary employee invitation required' USING ERRCODE='42501';END IF;
 ELSE
  IF NOT auth_employee_invitation_valid(OLD.id) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'Original employee invitation version required' USING ERRCODE='42501';END IF;
  fields=ARRAY['status','revision','event_id']||CASE scope->>'action' WHEN 'credentialed' THEN ARRAY['credential_event_id','credential_id','credential_revision'] WHEN 'accepted' THEN ARRAY['identity_receipt'] WHEN 'revoked' THEN ARRAY['revocation_request'] ELSE ARRAY[]::text[] END;
  IF to_jsonb(NEW)-fields IS DISTINCT FROM to_jsonb(OLD)-fields OR NOT(
   scope->>'action'='credentialed' AND OLD.status='pending' AND NEW.status='credential_pending'
   OR scope->>'action'='accepted' AND OLD.status='credential_pending' AND NEW.status='accepted'
   OR scope->>'action'='revoked' AND OLD.status IN('pending','credential_pending') AND NEW.status='revoked') THEN RAISE EXCEPTION 'Bounded employee invitation transition required' USING ERRCODE='42501';END IF;
 END IF;
 IF scope->>'action'='revoked' AND(NEW.revocation_request IS DISTINCT FROM scope->'revocationRequest' OR NEW.revocation_request->>'id' IS DISTINCT FROM NEW.id::text
  OR NEW.revocation_request->>'revision' IS DISTINCT FROM OLD.revision::text OR NEW.revocation_request->'confirm' IS DISTINCT FROM 'true'::jsonb
  OR jsonb_typeof(NEW.revocation_request->'reason') IS DISTINCT FROM 'string' OR length(btrim(NEW.revocation_request->>'reason')) NOT BETWEEN 10 AND 500)
  THEN RAISE EXCEPTION 'Exact confirmed employee revocation required' USING ERRCODE='42501';END IF;
 IF scope->>'action' IN('credentialed','accepted') THEN
  SELECT * INTO credential FROM users WHERE id=NEW.subject_id;
  IF credential.id IS NULL OR credential.username IS DISTINCT FROM NEW.login_name OR credential.roles IS DISTINCT FROM '["user"]'::jsonb OR credential.permissions IS DISTINCT FROM '[]'::jsonb
   OR credential.password_hash IS NULL OR credential.mfa_enabled OR credential.provider<>'local' THEN RAISE EXCEPTION 'Actual dedicated ordinary credential required' USING ERRCODE='42501';END IF;
  IF scope->>'action'='credentialed' AND(NOT credential.is_locked OR credential.record_revision<>NEW.credential_revision OR scope#>'{observation,eligible}' IS DISTINCT FROM 'true'::jsonb
   OR NOT EXISTS(SELECT 1 FROM password_history WHERE user_id=NEW.subject_id::text AND password_hash=credential.password_hash)
   OR jsonb_typeof(scope#>'{observation,validUntil}') IS DISTINCT FROM 'number' OR (scope->>'validUntil')::numeric>(scope#>>'{observation,validUntil}')::numeric
   OR (scope->>'validUntil')::numeric>extract(epoch FROM NEW.expires_at)
   OR scope#>'{observation,witness}' IS DISTINCT FROM auth_employee_invitation_witness(to_jsonb(OLD))) THEN RAISE EXCEPTION 'Original live recipient and locked credential required' USING ERRCODE='42501';END IF;
  IF scope->>'action'='accepted' AND(credential.is_locked OR credential.record_revision<>NEW.credential_revision+1 OR NEW.identity_receipt#>>'{invitationId}' IS DISTINCT FROM NEW.id::text OR NEW.identity_receipt->>'subjectId' IS DISTINCT FROM NEW.subject_id::text
   OR NEW.identity_receipt->>'userId' IS DISTINCT FROM NEW.target_id::text OR NEW.identity_receipt#>>'{tenant,id}' IS DISTINCT FROM NEW.tenant->>'id' OR NEW.identity_receipt->'confirmed' IS DISTINCT FROM 'true'::jsonb)
   THEN RAISE EXCEPTION 'Actual confirmed identity acceptance required' USING ERRCODE='42501';END IF;
 END IF;
 IF TG_WHEN='BEFORE' THEN
  NEW.event_id=(scope->>'eventId')::uuid;IF TG_OP='INSERT' THEN NEW.creation_event_id=NEW.event_id;END IF;IF scope->>'action'='credentialed' THEN NEW.credential_event_id=NEW.event_id;END IF;
 ELSE
  SELECT * INTO event FROM auth_employee_invitation_events WHERE id=NEW.event_id;
  IF NOT auth_employee_invitation_valid(NEW.id) OR event.transaction_id<>txid_current() OR event.valid_until<=clock_timestamp() OR event.after_state IS DISTINCT FROM to_jsonb(NEW)-'token_hash'
   THEN RAISE EXCEPTION 'Atomic original employee invitation receipt required' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION auth_employee_invitation_event() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;event auth_employee_invitation_events;
BEGIN
 scope=current_setting('opendirectory.employee_invitation')::jsonb;
 INSERT INTO auth_employee_invitation_events(id,invitation_id,action,actor,reason,before_state,after_state,valid_until) VALUES(NEW.event_id,NEW.id,scope->>'action',
  CASE WHEN scope->>'action' IN('created','revoked') THEN jsonb_build_object('kind','owner','issuer',scope#>>'{ownerSource,issuer}','subject',scope#>>'{ownerSource,subject}','userId',scope#>>'{ownerSource,actorUserId}')
  ELSE jsonb_build_object('kind','invitation-recipient','issuer',scope#>>'{proof,issuer}','subject','oauth-provider','invitationId',NEW.id) END,
  CASE scope->>'action' WHEN 'created' THEN NEW.request->>'reason' WHEN 'revoked' THEN NEW.revocation_request->>'reason'
   WHEN 'credentialed' THEN 'Recipient established the original locked credential' ELSE 'Canonical identity acceptance confirmed before credential activation' END,
  CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD)-'token_hash' END,to_jsonb(NEW)-'token_hash',to_timestamp((scope->>'validUntil')::double precision)) RETURNING * INTO event;
 INSERT INTO auth_employee_invitation_outbox VALUES(event.id,encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex'),'pending');RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION auth_employee_invitation_evidence() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;data JSONB;
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Employee invitation evidence is retained' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.employee_invitation',true),'')::jsonb;data=to_jsonb(NEW);
 IF TG_OP<>'INSERT' OR scope IS NULL OR pg_trigger_depth()<2 OR TG_TABLE_NAME='auth_employee_invitation_manifest'
  OR data->>'id' IS DISTINCT FROM scope->>'eventId' THEN RAISE EXCEPTION 'Original immutable employee invitation evidence required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='auth_employee_invitation_events' AND((data->>'transaction_id')::bigint<>txid_current() OR data->>'invitation_id' IS DISTINCT FROM scope->>'invitationId') THEN RAISE EXCEPTION 'Actual employee invitation transaction required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION auth_employee_invitation_fence() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE scope JSONB;invitation auth_employee_invitations;data JSONB;event auth_employee_invitation_events;credential users;
BEGIN
 scope=NULLIF(current_setting('opendirectory.employee_invitation',true),'')::jsonb;
 IF TG_OP='TRUNCATE' THEN
  IF scope IS NOT NULL OR TG_TABLE_NAME='users' AND EXISTS(SELECT 1 FROM auth_employee_invitations WHERE credential_id IS NOT NULL)
   THEN RAISE EXCEPTION 'Employee credential effects cannot be truncated' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 data=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 IF scope IS NULL THEN
  IF TG_TABLE_NAME='users' AND EXISTS(SELECT 1 FROM auth_employee_invitations WHERE subject_id=(data->>'id')::uuid AND status<>'accepted')
   THEN RAISE EXCEPTION 'Unfinished employee credential remains protected' USING ERRCODE='42501';END IF;
  IF TG_TABLE_NAME='password_history' AND EXISTS(SELECT 1 FROM auth_employee_invitations WHERE subject_id::text=data->>'user_id' AND status<>'accepted')
   THEN RAISE EXCEPTION 'Unfinished employee password history remains protected' USING ERRCODE='42501';END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
 END IF;
 IF TG_TABLE_NAME NOT IN('users','password_history') OR TG_OP='DELETE' THEN RAISE EXCEPTION 'Unrelated employee invitation write forbidden' USING ERRCODE='42501';END IF;
 PERFORM auth_employee_invitation_receiving();
 SELECT * INTO invitation FROM auth_employee_invitations WHERE id=(scope->>'invitationId')::uuid;
 IF invitation.id IS NULL OR invitation.subject_id::text IS DISTINCT FROM (CASE WHEN TG_TABLE_NAME='users' THEN data->>'id' ELSE data->>'user_id' END) OR scope->>'action' IS NULL OR scope->>'action' NOT IN('credentialed','accepted')
  OR jsonb_typeof(scope->'validUntil') IS DISTINCT FROM 'number' OR (scope->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  OR scope#>>'{proof,issuer}' IS DISTINCT FROM invitation.grant_source->>'issuer' OR scope#>>'{proof,subject}' IS DISTINCT FROM 'oauth-provider'
  OR jsonb_typeof(scope#>'{proof,expiresAt}') IS DISTINCT FROM 'number' OR (scope->>'validUntil')::numeric>(scope#>>'{proof,expiresAt}')::numeric
  THEN RAISE EXCEPTION 'Original live employee credential admission required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='password_history' THEN
  SELECT * INTO credential FROM users WHERE id=invitation.subject_id;
  IF scope->>'action'<>'credentialed' OR TG_OP<>'INSERT' OR credential.id IS NULL OR NOT credential.is_locked OR credential.record_revision<>1
   OR data->>'password_hash' IS DISTINCT FROM credential.password_hash
   OR TG_WHEN='BEFORE' AND(invitation.status<>'pending' OR EXISTS(SELECT 1 FROM password_history WHERE user_id=invitation.subject_id::text))
   OR TG_WHEN='AFTER' AND(invitation.status<>'credential_pending' OR NOT auth_employee_invitation_valid(invitation.id)
    OR invitation.credential_event_id::text IS DISTINCT FROM scope->>'eventId'
    OR NOT EXISTS(SELECT 1 FROM auth_employee_invitation_events WHERE id=invitation.credential_event_id AND transaction_id=txid_current() AND valid_until>clock_timestamp()))
   THEN RAISE EXCEPTION 'Exact original employee password history required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF TG_WHEN='BEFORE' THEN
  IF scope->>'action'='credentialed' AND(TG_OP<>'INSERT' OR invitation.status<>'pending' OR data->>'username' IS DISTINCT FROM invitation.login_name
   OR data->>'email' IS DISTINCT FROM invitation.grant_source#>>'{target,email}' OR data->'is_locked' IS DISTINCT FROM 'true'::jsonb OR data->'mfa_enabled' IS DISTINCT FROM 'false'::jsonb
   OR data->'roles' IS DISTINCT FROM '["user"]'::jsonb OR data->'permissions' IS DISTINCT FROM '[]'::jsonb OR data->>'provider' IS DISTINCT FROM 'local'
   OR data->>'password_hash' IS NULL OR data->>'record_revision' IS DISTINCT FROM '1' OR data->>'security_revision' IS DISTINCT FROM '1'
   OR jsonb_typeof(scope#>'{observation,validUntil}') IS DISTINCT FROM 'number' OR (scope->>'validUntil')::numeric>(scope#>>'{observation,validUntil}')::numeric
   OR (scope->>'validUntil')::numeric>extract(epoch FROM invitation.expires_at)
   OR scope#>'{observation,eligible}' IS DISTINCT FROM 'true'::jsonb OR scope#>'{observation,witness}' IS DISTINCT FROM auth_employee_invitation_witness(to_jsonb(invitation)))
   THEN RAISE EXCEPTION 'Exact original locked credential creation required' USING ERRCODE='42501';END IF;
  IF scope->>'action'='accepted' AND(TG_OP<>'UPDATE' OR invitation.status<>'credential_pending' OR NOT OLD.is_locked OR OLD.record_revision<>invitation.credential_revision
   OR data->'is_locked' IS DISTINCT FROM 'false'::jsonb
   OR data-ARRAY['is_locked','updated_at','record_revision','security_revision'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['is_locked','updated_at','record_revision','security_revision'])
   THEN RAISE EXCEPTION 'Only original employee credential activation allowed' USING ERRCODE='42501';END IF;
 ELSE
  SELECT * INTO event FROM auth_employee_invitation_events WHERE id=(scope->>'eventId')::uuid;
  IF NOT auth_employee_invitation_valid(invitation.id) OR event.id IS NULL OR event.id<>invitation.event_id OR event.transaction_id<>txid_current() OR event.valid_until<=clock_timestamp()
   OR invitation.credential_id::text IS DISTINCT FROM data->>'id' OR event.action IS DISTINCT FROM scope->>'action'
   OR scope->>'action'='credentialed' AND(invitation.status<>'credential_pending' OR invitation.credential_revision<>(data->>'record_revision')::bigint)
   OR scope->>'action'='accepted' AND(invitation.status<>'accepted' OR invitation.credential_revision+1<>(data->>'record_revision')::bigint)
   THEN RAISE EXCEPTION 'Atomic original employee credential effect required' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;
DO $$ DECLARE signature TEXT;relation TEXT;BEGIN
 DROP TRIGGER IF EXISTS auth_employee_evidence ON auth_employee_invitation_manifest;
 FOREACH signature IN ARRAY ARRAY['authentication_credential_revision()','auth_employee_invitation_receiving()','auth_employee_invitation_witness(jsonb)','auth_employee_invitation_valid(uuid)','auth_employee_invitation_guard()','auth_employee_invitation_event()','auth_employee_invitation_evidence()','auth_employee_invitation_fence()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
  INSERT INTO auth_employee_invitation_manifest VALUES(signature,md5(pg_get_functiondef(to_regprocedure(signature)))) ON CONFLICT ON CONSTRAINT auth_employee_invitation_manifest_pkey DO UPDATE SET digest=EXCLUDED.digest;
 END LOOP;
 CREATE OR REPLACE TRIGGER auth_employee_before BEFORE INSERT OR UPDATE OR DELETE ON auth_employee_invitations FOR EACH ROW EXECUTE FUNCTION auth_employee_invitation_guard();
 CREATE OR REPLACE TRIGGER auth_employee_after AFTER INSERT OR UPDATE ON auth_employee_invitations FOR EACH ROW EXECUTE FUNCTION auth_employee_invitation_event();
 DROP TRIGGER IF EXISTS auth_employee_commit ON auth_employee_invitations;
 CREATE CONSTRAINT TRIGGER auth_employee_commit AFTER INSERT OR UPDATE ON auth_employee_invitations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth_employee_invitation_guard();
 FOREACH relation IN ARRAY ARRAY['auth_employee_invitation_events','auth_employee_invitation_outbox','auth_employee_invitation_manifest'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER auth_employee_evidence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION auth_employee_invitation_evidence()',relation);
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['auth_employee_invitations','auth_employee_invitation_events','auth_employee_invitation_outbox','auth_employee_invitation_manifest'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER auth_employee_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION auth_employee_invitation_evidence()',relation);
 END LOOP;
 FOR relation IN SELECT relname FROM pg_class JOIN pg_namespace ON pg_namespace.oid=relnamespace
  WHERE nspname=current_schema() AND relkind='r' AND relname NOT IN('auth_employee_invitations','auth_employee_invitation_events','auth_employee_invitation_outbox','auth_employee_invitation_manifest') LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER aaa_auth_employee_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION auth_employee_invitation_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS auth_employee_effect_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER auth_employee_effect_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth_employee_invitation_fence()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER auth_employee_effect_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION auth_employee_invitation_fence()',relation);
 END LOOP;
END; $$;
