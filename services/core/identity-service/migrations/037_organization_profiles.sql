CREATE TABLE IF NOT EXISTS identity_organization_profiles (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL UNIQUE REFERENCES identity_tenants(id),version BIGINT NOT NULL CHECK(version>0),
 name TEXT NOT NULL,legal_form TEXT NOT NULL,registration_number TEXT NOT NULL,tax_id TEXT NOT NULL,address_line1 TEXT NOT NULL,address_line2 TEXT NOT NULL,
 postal_code TEXT NOT NULL,city TEXT NOT NULL,country TEXT NOT NULL,timezone TEXT NOT NULL,default_language TEXT NOT NULL,contact_email TEXT NOT NULL,contact_phone TEXT NOT NULL,website TEXT NOT NULL,
 command_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,
 UNIQUE(id,tenant_id),CHECK(updated_at>=created_at)
);
CREATE TABLE IF NOT EXISTS identity_organization_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),organization_id UUID NOT NULL,action TEXT NOT NULL CHECK(action IN('created','updated')),
 actor JSONB NOT NULL,token_sha256 TEXT NOT NULL CHECK(token_sha256 ~ '^[a-f0-9]{64}$'),reason TEXT NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 500 AND reason!~'[[:cntrl:]]'),
 before_state JSONB,after_state JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL CHECK(valid_until>created_at),transaction_id BIGINT NOT NULL UNIQUE,
 FOREIGN KEY(organization_id,tenant_id) REFERENCES identity_organization_profiles(id,tenant_id)
);
CREATE TABLE IF NOT EXISTS identity_organization_outbox (
 id UUID PRIMARY KEY REFERENCES identity_organization_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),action TEXT NOT NULL CHECK(action IN('created','updated')),
 status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='identity_organization_profiles'::regclass AND conname='identity_organization_command') THEN
  ALTER TABLE identity_organization_profiles ADD CONSTRAINT identity_organization_command FOREIGN KEY(command_id) REFERENCES identity_organization_events(id) DEFERRABLE INITIALLY DEFERRED;
 END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_profile_data(profile identity_organization_profiles) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_object('name',profile.name,'legalForm',profile.legal_form,'registrationNumber',profile.registration_number,'taxId',profile.tax_id,
  'addressLine1',profile.address_line1,'addressLine2',profile.address_line2,'postalCode',profile.postal_code,'city',profile.city,'country',profile.country,
  'timezone',profile.timezone,'defaultLanguage',profile.default_language,'contactEmail',profile.contact_email,'contactPhone',profile.contact_phone,'website',profile.website);
$$;
CREATE OR REPLACE FUNCTION identity_organization_profile_valid(profile JSONB) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE field TEXT;maximum INTEGER;value TEXT;
BEGIN
 IF jsonb_typeof(profile) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(profile))<>14 THEN RETURN false;END IF;
 FOR field,maximum IN SELECT * FROM (VALUES ('name',160),('legalForm',80),('registrationNumber',80),('taxId',80),('addressLine1',180),('addressLine2',180),('postalCode',32),('city',100),('country',2),('timezone',64),('defaultLanguage',2),('contactEmail',254),('contactPhone',40),('website',2048)) fields(name,maximum) LOOP
  value=profile->>field;
  IF jsonb_typeof(profile->field) IS DISTINCT FROM 'string' OR value<>btrim(value) OR length(value)>maximum OR value~'[[:cntrl:]]'
   OR field IN('name','addressLine1','postalCode','city','country','timezone','defaultLanguage','contactEmail') AND length(value)=0 THEN RETURN false;END IF;
 END LOOP;
 RETURN length(profile->>'name')>=2 AND profile->>'country' ~ '^[A-Z]{2}$' AND profile->>'defaultLanguage' IN('de','en')
  AND profile->>'contactEmail' ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' AND profile->>'contactPhone' ~ '^[+0-9 ()/.-]*$'
  AND (profile->>'website'='' OR profile->>'website' ~ '^https://[^/@[:space:]]+([/?#].*)?$')
  AND EXISTS(SELECT 1 FROM pg_timezone_names WHERE name=profile->>'timezone');
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_no_effects() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.organization_mutation',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_organization_events WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Unrelated effects cannot ride an organization mutation' USING ERRCODE='42501';END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;data JSONB;owner UUID;
BEGIN
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
CREATE OR REPLACE FUNCTION identity_organization_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;owned BOOLEAN;checkpoint BOOLEAN;
BEGIN
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  owned=relation IN('identity_organization_profiles','identity_organization_events','identity_organization_outbox');
  checkpoint=relation IN('identity_authority_command_checkpoints','identity_authority_command_checkpoint_events','identity_authority_command_checkpoint_outbox');
  IF owned AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_organization_guard' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_organization_guard()'::regprocedure)
   OR NOT owned AND NOT checkpoint AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_organization_no_effects' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_organization_no_effects()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_organization_no_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='identity_organization_no_effects()'::regprocedure) THEN RAISE EXCEPTION 'Organization receiving guards unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_organization_profiles'::regclass AND tgname='identity_organization_commit' AND tgenabled='O' AND tgtype=21 AND tgdeferrable AND tginitdeferred AND tgfoid='identity_organization_commit()'::regprocedure) THEN RAISE EXCEPTION 'Deferred organization validation required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_save(proof JSONB,token_identifier TEXT,expected_etag TEXT,body JSONB,reason TEXT,deadline BIGINT) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE owner UUID;tenant identity_tenants;before_row identity_organization_profiles;after_row identity_organization_profiles;event identity_organization_events;tag TEXT;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_organization_receiving();PERFORM identity_authority_checkpoint_receiving();owner=identity_authority_actor_home(proof);
 IF NULLIF(current_setting('opendirectory.organization_mutation',true),'') IS NOT NULL OR token_identifier IS NULL OR length(token_identifier) NOT BETWEEN 1 AND 128 OR deadline IS NULL THEN RAISE EXCEPTION 'One original organization command required' USING ERRCODE='42501';END IF;
 PERFORM id FROM users WHERE id=(proof->>'userId')::uuid FOR UPDATE;SELECT * INTO tenant FROM identity_tenants WHERE id=owner AND enabled FOR SHARE;
 SELECT * INTO before_row FROM identity_organization_profiles WHERE tenant_id=owner FOR UPDATE;
 IF before_row.id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identity_organization_events prior JOIN identity_organization_outbox outbox USING(id)
  WHERE prior.id=before_row.command_id AND prior.tenant_id=owner AND prior.after_state=to_jsonb(before_row) AND outbox.tenant_id=owner AND outbox.action=prior.action AND outbox.status='pending' AND outbox.created_at=prior.created_at) THEN RAISE EXCEPTION 'Retained organization before-state evidence required' USING ERRCODE='42501';END IF;
 tag='"organization-'||owner::text||'-'||tenant.generation::text||'-'||tenant.version::text||'-'||COALESCE(before_row.version,0)::text||'"';
 IF expected_etag IS DISTINCT FROM tag THEN RAISE EXCEPTION 'Organization version changed' USING ERRCODE='40001';END IF;
 IF to_timestamp(deadline)<=clock_timestamp() THEN RAISE EXCEPTION 'Original organization assurance expired' USING ERRCODE='28000';END IF;
 IF NOT identity_organization_profile_valid(body) THEN RAISE EXCEPTION 'Exact typed organization profile required' USING ERRCODE='23514';END IF;
 after_row=jsonb_populate_record(NULL::identity_organization_profiles,jsonb_build_object('name',body->'name','legal_form',body->'legalForm','registration_number',body->'registrationNumber','tax_id',body->'taxId',
  'address_line1',body->'addressLine1','address_line2',body->'addressLine2','postal_code',body->'postalCode','city',body->'city','country',body->'country','timezone',body->'timezone','default_language',body->'defaultLanguage','contact_email',body->'contactEmail','contact_phone',body->'contactPhone','website',body->'website'));
 after_row.id=COALESCE(before_row.id,gen_random_uuid());after_row.tenant_id=owner;after_row.version=COALESCE(before_row.version,0)+1;after_row.command_id=gen_random_uuid();
 after_row.updated_at=clock_timestamp();after_row.created_at=COALESCE(before_row.created_at,after_row.updated_at);
 event.id=after_row.command_id;event.tenant_id=owner;event.organization_id=after_row.id;event.action=CASE WHEN before_row.id IS NULL THEN 'created' ELSE 'updated' END;event.actor=proof;
 event.token_sha256=identity_authority_hash(to_jsonb(token_identifier));event.reason=reason;event.before_state=CASE WHEN before_row.id IS NOT NULL THEN to_jsonb(before_row) END;event.after_state=to_jsonb(after_row);event.created_at=after_row.updated_at;event.valid_until=to_timestamp(deadline);event.transaction_id=txid_current();
 PERFORM set_config('opendirectory.organization_mutation',to_jsonb(event)::text,true);
 IF before_row.id IS NULL THEN INSERT INTO identity_organization_profiles SELECT after_row.*;
 ELSE UPDATE identity_organization_profiles SET version=after_row.version,name=after_row.name,legal_form=after_row.legal_form,registration_number=after_row.registration_number,tax_id=after_row.tax_id,
  address_line1=after_row.address_line1,address_line2=after_row.address_line2,postal_code=after_row.postal_code,city=after_row.city,country=after_row.country,timezone=after_row.timezone,default_language=after_row.default_language,
  contact_email=after_row.contact_email,contact_phone=after_row.contact_phone,website=after_row.website,command_id=after_row.command_id,updated_at=after_row.updated_at WHERE tenant_id=owner;END IF;
 INSERT INTO identity_organization_events SELECT event.*;INSERT INTO identity_organization_outbox VALUES(event.id,owner,event.action,'pending',event.created_at);
 RETURN event.id;
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;event identity_organization_events;profile identity_organization_profiles;
BEGIN
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
DROP TRIGGER IF EXISTS identity_organization_commit ON identity_organization_profiles;
CREATE CONSTRAINT TRIGGER identity_organization_commit AFTER INSERT OR UPDATE ON identity_organization_profiles DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_organization_commit();
DO $$ DECLARE relation TEXT;owned BOOLEAN;checkpoint BOOLEAN;routine TEXT;guard TEXT;BEGIN
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  owned=relation IN('identity_organization_profiles','identity_organization_events','identity_organization_outbox');checkpoint=relation IN('identity_authority_command_checkpoints','identity_authority_command_checkpoint_events','identity_authority_command_checkpoint_outbox');
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_organization_no_truncate ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_organization_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_organization_no_effects()',relation);
  IF owned THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_organization_guard ON %I',relation);EXECUTE format('CREATE TRIGGER identity_organization_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_organization_guard()',relation);
   FOR guard,routine IN SELECT * FROM (VALUES ('stage','identity_authority_stage_no_effects'),('seal','identity_authority_namespace_no_effects'),('checkpoint','identity_authority_checkpoint_no_effects'),('source_set','identity_authority_source_set_no_effects')) guards(name,routine) LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_identity_authority_'||guard||'_no_effects',relation);EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()','aaa_identity_authority_'||guard||'_no_effects',relation,routine);
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_identity_authority_'||guard||'_no_truncate',relation);EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()','aaa_identity_authority_'||guard||'_no_truncate',relation,routine);
   END LOOP;
  ELSIF NOT checkpoint THEN
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_organization_no_effects ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_organization_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_organization_no_effects()',relation);
  END IF;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_organization_profile_data(identity_organization_profiles)','identity_organization_profile_valid(jsonb)','identity_organization_no_effects()','identity_organization_guard()','identity_organization_receiving()','identity_organization_save(jsonb,text,text,jsonb,text,bigint)','identity_organization_commit()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
