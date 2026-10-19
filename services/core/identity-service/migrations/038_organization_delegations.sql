CREATE TABLE IF NOT EXISTS identity_organization_delegation_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),user_id UUID NOT NULL REFERENCES users(id),grant_id UUID NOT NULL,
 action TEXT NOT NULL CHECK(action IN('granted','revoked')),expires_at TIMESTAMPTZ NOT NULL,actor JSONB NOT NULL,token_sha256 TEXT NOT NULL CHECK(token_sha256 ~ '^[a-f0-9]{64}$'),
 reason TEXT NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 500 AND reason!~'[[:cntrl:]]'),created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL CHECK(valid_until>created_at),
 user_revision BIGINT NOT NULL CHECK(user_revision>0),transaction_id BIGINT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS identity_organization_delegations (
 id UUID PRIMARY KEY REFERENCES identity_organization_delegation_events(id) DEFERRABLE INITIALLY DEFERRED,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 user_id UUID NOT NULL REFERENCES users(id),expires_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL,CHECK(expires_at>created_at)
);
CREATE INDEX IF NOT EXISTS identity_organization_delegations_subject ON identity_organization_delegations(tenant_id,user_id,expires_at);
CREATE INDEX IF NOT EXISTS identity_organization_delegations_history ON identity_organization_delegations(tenant_id,created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS identity_organization_delegation_revocations (
 grant_id UUID PRIMARY KEY REFERENCES identity_organization_delegations(id),event_id UUID NOT NULL UNIQUE REFERENCES identity_organization_delegation_events(id) DEFERRABLE INITIALLY DEFERRED,
 tenant_id UUID NOT NULL REFERENCES identity_tenants(id),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_organization_delegation_outbox (
 id UUID PRIMARY KEY REFERENCES identity_organization_delegation_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action IN('granted','revoked')),status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE OR REPLACE FUNCTION identity_organization_delegation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;expected JSONB;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP='TRUNCATE' THEN
  IF NULLIF(current_setting('opendirectory.organization_delegation',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_organization_delegation_events WHERE transaction_id=txid_current())
   THEN RAISE EXCEPTION 'Truncate cannot ride a delegation command' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Organization delegations and evidence are retained immutable records' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.organization_delegation',true),'')::jsonb;
 IF scope IS NULL OR (scope->>'transaction_id')::bigint<>txid_current() OR identity_authority_actor_home(scope->'actor')::text IS DISTINCT FROM scope->>'tenant_id'
  OR identity_tenant_id('user',(scope->>'user_id')::uuid)::text IS DISTINCT FROM scope->>'tenant_id' OR scope->'actor'->>'userId'=scope->>'user_id'
  THEN RAISE EXCEPTION 'Exact independent owned delegation command required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_organization_delegation_events' THEN expected=scope;
 ELSIF TG_TABLE_NAME='identity_organization_delegations' AND scope->>'action'='granted' THEN
  expected=jsonb_build_object('id',scope->'grant_id','tenant_id',scope->'tenant_id','user_id',scope->'user_id','expires_at',scope->'expires_at','created_at',scope->'created_at');
 ELSIF TG_TABLE_NAME='identity_organization_delegation_revocations' AND scope->>'action'='revoked' THEN
  expected=jsonb_build_object('grant_id',scope->'grant_id','event_id',scope->'id','tenant_id',scope->'tenant_id','created_at',scope->'created_at');
 ELSIF TG_TABLE_NAME='identity_organization_delegation_outbox' THEN
  expected=jsonb_build_object('id',scope->'id','tenant_id',scope->'tenant_id','action',scope->'action','status','pending','created_at',scope->'created_at');
 END IF;
 IF expected IS NULL OR to_jsonb(NEW) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact delegation effect required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_delegation_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;
BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_organization_delegations','identity_organization_delegation_events','identity_organization_delegation_revocations','identity_organization_delegation_outbox'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_organization_delegation_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='identity_organization_delegation_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_organization_delegation_no_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='identity_organization_delegation_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'Organization delegation receiving unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_organization_delegation_events'::regclass AND tgname='identity_organization_delegation_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_organization_delegation_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Deferred delegation receiving unavailable' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_delegation_evidence(identifier UUID) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT EXISTS(SELECT 1 FROM identity_organization_delegations grant_row JOIN identity_organization_delegation_events event ON event.id=grant_row.id
  JOIN identity_organization_delegation_outbox outbox ON outbox.id=event.id WHERE grant_row.id=identifier AND event.grant_id=grant_row.id AND event.action='granted'
   AND event.user_id=grant_row.user_id AND event.tenant_id=grant_row.tenant_id AND event.expires_at=grant_row.expires_at AND event.created_at=grant_row.created_at
   AND outbox.tenant_id=event.tenant_id AND outbox.action=event.action AND outbox.created_at=event.created_at AND outbox.status='pending')
 AND NOT EXISTS(SELECT 1 FROM identity_organization_delegation_revocations revoked WHERE revoked.grant_id=identifier AND NOT EXISTS(
  SELECT 1 FROM identity_organization_delegation_events event JOIN identity_organization_delegation_outbox outbox ON outbox.id=event.id
  JOIN identity_organization_delegations grant_row ON grant_row.id=revoked.grant_id WHERE event.id=revoked.event_id AND event.grant_id=grant_row.id AND event.action='revoked'
   AND event.user_id=grant_row.user_id AND event.tenant_id=grant_row.tenant_id AND event.tenant_id=revoked.tenant_id AND event.expires_at=grant_row.expires_at
   AND event.created_at=revoked.created_at AND outbox.tenant_id=event.tenant_id AND outbox.action=event.action AND outbox.created_at=event.created_at AND outbox.status='pending'));
$$;
CREATE OR REPLACE FUNCTION identity_organization_delegation_change(proof JSONB,token_identifier TEXT,transition TEXT,target UUID,duration_seconds INTEGER,reason TEXT,deadline BIGINT) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE owner UUID;recipient UUID;grant_row identity_organization_delegations;event identity_organization_delegation_events;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_organization_delegation_receiving();PERFORM identity_authority_checkpoint_receiving();owner=identity_authority_actor_home(proof);
 IF NULLIF(current_setting('opendirectory.organization_delegation',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_organization_delegation_events WHERE transaction_id=txid_current())
  OR token_identifier IS NULL OR length(token_identifier) NOT BETWEEN 1 AND 128 OR deadline IS NULL OR transition NOT IN('granted','revoked') OR target IS NULL
  OR transition='granted' AND (duration_seconds IS NULL OR duration_seconds NOT BETWEEN 60 AND 28800) OR transition='revoked' AND duration_seconds IS NOT NULL
  THEN RAISE EXCEPTION 'One exact bounded delegation command required' USING ERRCODE='23514';END IF;
 IF transition='granted' THEN recipient=target;
 ELSE SELECT * INTO grant_row FROM identity_organization_delegations WHERE id=target AND tenant_id=owner;recipient=grant_row.user_id;END IF;
 IF recipient IS NULL OR identity_tenant_id('user',recipient) IS DISTINCT FROM owner OR NOT EXISTS(SELECT 1 FROM users WHERE id=recipient AND (transition='revoked' OR enabled))
  THEN RAISE EXCEPTION 'Own enabled delegation target not found' USING ERRCODE='23503';END IF;
 IF recipient=(proof->>'userId')::uuid THEN RAISE EXCEPTION 'Independent delegation target required' USING ERRCODE='23514';END IF;
 PERFORM id FROM users WHERE id IN(recipient,(proof->>'userId')::uuid) AND identity_tenant_id('user',id)=owner ORDER BY id FOR UPDATE;
 PERFORM identity_authority_actor_home(proof);
 IF transition='granted' AND NOT EXISTS(SELECT 1 FROM users WHERE id=recipient AND enabled) THEN RAISE EXCEPTION 'Enabled target changed' USING ERRCODE='23503';END IF;
 IF transition='granted' THEN
  IF EXISTS(SELECT 1 FROM identity_organization_delegations active WHERE active.user_id=recipient AND active.tenant_id=owner AND active.expires_at>clock_timestamp()
   AND NOT EXISTS(SELECT 1 FROM identity_organization_delegation_revocations revoked WHERE revoked.grant_id=active.id)) THEN RAISE EXCEPTION 'Active organization delegation already exists' USING ERRCODE='23505';END IF;
  grant_row.id=gen_random_uuid();grant_row.user_id=recipient;grant_row.tenant_id=owner;grant_row.created_at=clock_timestamp();grant_row.expires_at=grant_row.created_at+duration_seconds*interval '1 second';
 ELSE
  IF NOT identity_organization_delegation_evidence(grant_row.id) THEN RAISE EXCEPTION 'Retained delegation evidence required' USING ERRCODE='42501';END IF;
  IF EXISTS(SELECT 1 FROM identity_organization_delegation_revocations WHERE grant_id=grant_row.id) THEN RAISE EXCEPTION 'Delegation already revoked' USING ERRCODE='23505';END IF;
 END IF;
 IF to_timestamp(deadline)<=clock_timestamp() THEN RAISE EXCEPTION 'Original delegation assurance expired' USING ERRCODE='28000';END IF;
 UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=recipient RETURNING authorization_revision INTO event.user_revision;
 event.id=CASE WHEN transition='granted' THEN grant_row.id ELSE gen_random_uuid() END;event.tenant_id=owner;event.user_id=recipient;event.grant_id=grant_row.id;
 event.action=transition;event.expires_at=grant_row.expires_at;event.actor=proof;event.token_sha256=identity_authority_hash(to_jsonb(token_identifier));event.reason=reason;
 event.created_at=CASE WHEN transition='granted' THEN grant_row.created_at ELSE clock_timestamp() END;event.valid_until=to_timestamp(deadline);event.transaction_id=txid_current();
 PERFORM set_config('opendirectory.organization_delegation',to_jsonb(event)::text,true);
 IF transition='granted' THEN INSERT INTO identity_organization_delegations SELECT grant_row.*;
 ELSE INSERT INTO identity_organization_delegation_revocations VALUES(grant_row.id,event.id,owner,event.created_at);END IF;
 INSERT INTO identity_organization_delegation_events SELECT event.*;INSERT INTO identity_organization_delegation_outbox VALUES(event.id,owner,transition,'pending',event.created_at);RETURN event.id;
END; $$;
CREATE OR REPLACE FUNCTION identity_organization_delegation_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_organization_delegation_receiving();PERFORM identity_authority_checkpoint_receiving();
 IF NEW.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original delegation assurance expired' USING ERRCODE='28000';END IF;
 IF NULLIF(current_setting('opendirectory.organization_delegation',true),'')::jsonb IS DISTINCT FROM to_jsonb(NEW) OR NEW.transaction_id<>txid_current()
  OR identity_authority_actor_home(NEW.actor)<>NEW.tenant_id OR NOT identity_organization_delegation_evidence(NEW.grant_id)
  OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND authorization_revision=NEW.user_revision AND (NEW.action='revoked' OR enabled) AND identity_tenant_id('user',id)=NEW.tenant_id)
  OR NOT EXISTS(SELECT 1 FROM identity_authority_command_checkpoints checkpoint WHERE checkpoint.transaction_id=NEW.transaction_id AND checkpoint.user_id=(NEW.actor->>'userId')::uuid
   AND checkpoint.tenant_id=NEW.tenant_id AND checkpoint.original_context=NEW.actor-ARRAY['issuer','subject'] AND checkpoint.token_sha256=NEW.token_sha256 AND checkpoint.valid_until<=NEW.valid_until AND checkpoint.valid_until>clock_timestamp())
  THEN RAISE EXCEPTION 'Exact delegation evidence and original final checkpoint required' USING ERRCODE='42501';END IF;
 RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS identity_organization_delegation_commit ON identity_organization_delegation_events;
CREATE CONSTRAINT TRIGGER identity_organization_delegation_commit AFTER INSERT ON identity_organization_delegation_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_organization_delegation_commit();
DO $$ DECLARE relation TEXT;routine TEXT;guard TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_organization_delegations','identity_organization_delegation_events','identity_organization_delegation_revocations','identity_organization_delegation_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_organization_delegation_guard ON %I',relation);EXECUTE format('CREATE TRIGGER identity_organization_delegation_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_organization_delegation_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_organization_delegation_no_truncate ON %I',relation);EXECUTE format('CREATE TRIGGER identity_organization_delegation_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_organization_delegation_guard()',relation);
  FOR guard,routine IN SELECT * FROM (VALUES ('identity_authority_stage','identity_authority_stage_no_effects'),('identity_authority_seal','identity_authority_namespace_no_effects'),('identity_authority_checkpoint','identity_authority_checkpoint_no_effects'),('identity_authority_source_set','identity_authority_source_set_no_effects'),('identity_organization','identity_organization_no_effects')) guards(name,routine) LOOP
   EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||'_no_effects',relation);EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()','aaa_'||guard||'_no_effects',relation,routine);
   EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||'_no_truncate',relation);EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()','aaa_'||guard||'_no_truncate',relation,routine);
  END LOOP;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_organization_delegation_guard()','identity_organization_delegation_receiving()','identity_organization_delegation_evidence(uuid)','identity_organization_delegation_change(jsonb,text,text,uuid,integer,text,bigint)','identity_organization_delegation_commit()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
