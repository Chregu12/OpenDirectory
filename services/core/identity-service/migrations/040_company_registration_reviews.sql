CREATE TABLE IF NOT EXISTS identity_company_review_operators (
 issuer TEXT NOT NULL,user_id UUID NOT NULL REFERENCES users(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 version BIGINT NOT NULL CHECK(version>0),enabled BOOLEAN NOT NULL,command_id UUID NOT NULL UNIQUE,updated_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(issuer,user_id)
);
CREATE TABLE IF NOT EXISTS identity_company_registration_reviews (
 registration_id UUID PRIMARY KEY REFERENCES identity_company_registrations(id),id UUID NOT NULL UNIQUE,decision TEXT NOT NULL CHECK(decision IN('approved','rejected')),
 operator_event_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_company_review_events (
 id UUID PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN('operator','decision')),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),target_id UUID NOT NULL,
 actor JSONB NOT NULL,token_sha256 TEXT,reason TEXT NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 500 AND reason!~'[[:cntrl:]]'),
 before_state JSONB,after_state JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ,transaction_id BIGINT NOT NULL UNIQUE,
 CHECK(kind='operator' AND token_sha256 IS NULL AND valid_until IS NULL OR kind='decision' AND token_sha256 IS NOT NULL AND token_sha256 ~ '^[a-f0-9]{64}$' AND valid_until IS NOT NULL AND valid_until>created_at)
);
CREATE TABLE IF NOT EXISTS identity_company_review_outbox (
 id UUID PRIMARY KEY REFERENCES identity_company_review_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_company_registrations_queue ON identity_company_registrations(created_at DESC,id DESC);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='identity_company_review_operators'::regclass AND conname='identity_company_review_operator_event') THEN
  ALTER TABLE identity_company_review_operators ADD CONSTRAINT identity_company_review_operator_event FOREIGN KEY(command_id) REFERENCES identity_company_review_events(id) DEFERRABLE INITIALLY DEFERRED;
  ALTER TABLE identity_company_registration_reviews ADD CONSTRAINT identity_company_review_decision_event FOREIGN KEY(id) REFERENCES identity_company_review_events(id) DEFERRABLE INITIALLY DEFERRED;
  ALTER TABLE identity_company_registration_reviews ADD CONSTRAINT identity_company_review_source_event FOREIGN KEY(operator_event_id) REFERENCES identity_company_review_events(id);
 END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_review_event_valid(identifier UUID) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT EXISTS(SELECT 1 FROM identity_company_review_events event JOIN identity_company_review_outbox outbox USING(id)
  WHERE event.id=identifier AND outbox.tenant_id=event.tenant_id AND outbox.created_at=event.created_at AND outbox.status='pending');
$$;
CREATE OR REPLACE FUNCTION identity_company_review_operator_valid(source identity_company_review_operators) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT EXISTS(SELECT 1 FROM identity_company_review_events event WHERE event.id=source.command_id AND event.kind='operator' AND event.tenant_id=source.tenant_id
  AND event.target_id=source.user_id AND event.after_state->'operator'=to_jsonb(source) AND identity_company_review_event_valid(event.id));
$$;
CREATE OR REPLACE FUNCTION identity_company_review_valid(identifier UUID) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
 SELECT EXISTS(SELECT 1 FROM identity_company_registration_reviews review JOIN identity_company_registrations registration ON registration.id=review.registration_id
  JOIN identity_company_review_events event ON event.id=review.id JOIN identity_company_review_events source ON source.id=review.operator_event_id
  WHERE registration.id=identifier AND event.kind='decision' AND event.target_id=registration.id AND event.tenant_id=registration.tenant_id
   AND event.after_state=to_jsonb(review) AND event.created_at=review.created_at
   AND event.before_state=jsonb_build_object('registrationId',registration.id,'payloadSha256',registration.payload_sha256,'status','pending-verification')
   AND source.kind='operator' AND source.after_state->'operator'->'enabled'='true'::jsonb
   AND source.after_state->'operator'->>'user_id'=event.actor->>'userId' AND source.after_state->'operator'->>'issuer'=event.actor->>'issuer'
   AND source.target_id<>registration.user_id AND identity_company_review_event_valid(source.id) AND identity_company_review_event_valid(event.id));
$$;
CREATE OR REPLACE FUNCTION identity_company_review_scope() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;retained identity_company_review_events;
BEGIN
 PERFORM identity_authority_owner();scope=NULLIF(current_setting('opendirectory.company_review',true),'')::jsonb;
 SELECT * INTO retained FROM identity_company_review_events WHERE transaction_id=txid_current();
 IF scope IS NULL OR (scope->>'transaction_id')::bigint<>txid_current() OR retained.id IS NOT NULL AND to_jsonb(retained) IS DISTINCT FROM scope
  THEN RAISE EXCEPTION 'Exact current company review admission required' USING ERRCODE='42501';END IF;RETURN scope;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_review_no_effects() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.company_review',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_review_events WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Unrelated effects cannot ride company review' USING ERRCODE='42501';END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_review_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;expected JSONB;
BEGIN
 scope=identity_company_review_scope();
 IF TG_OP='DELETE' OR TG_OP='UPDATE' AND TG_TABLE_NAME<>'identity_company_review_operators' THEN RAISE EXCEPTION 'Company review evidence is immutable' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_company_review_events' AND TG_OP='INSERT' THEN expected=scope;
 ELSIF TG_TABLE_NAME='identity_company_review_outbox' AND TG_OP='INSERT' THEN expected=jsonb_build_object('id',scope->'id','tenant_id',scope->'tenant_id','status','pending','created_at',scope->'created_at');
 ELSIF TG_TABLE_NAME='identity_company_registration_reviews' AND scope->>'kind'='decision' AND TG_OP='INSERT' THEN expected=scope->'after_state';
 ELSIF TG_TABLE_NAME='identity_company_review_operators' AND scope->>'kind'='operator' THEN
  expected=scope->'after_state'->'operator';
  IF TG_OP='UPDATE' AND (to_jsonb(OLD) IS DISTINCT FROM scope->'before_state'->'operator' OR NEW.version<>OLD.version+1 OR NEW.issuer<>OLD.issuer OR NEW.user_id<>OLD.user_id OR NEW.tenant_id<>OLD.tenant_id)
   OR TG_OP='INSERT' AND (scope->'before_state'->'operator'<>'null'::jsonb OR NEW.version<>1) THEN RAISE EXCEPTION 'Exact versioned reviewer change required' USING ERRCODE='42501';END IF;
 END IF;
 IF expected IS NULL OR to_jsonb(NEW) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact company review effect required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_review_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;owned BOOLEAN;checkpoint BOOLEAN;
BEGIN
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  owned=relation IN('identity_company_review_operators','identity_company_registration_reviews','identity_company_review_events','identity_company_review_outbox');
  checkpoint=relation IN('identity_authority_command_checkpoints','identity_authority_command_checkpoint_events','identity_authority_command_checkpoint_outbox');
  IF owned AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_company_review_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='identity_company_review_guard()'::regprocedure)
   OR NOT owned AND NOT checkpoint AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_company_review_no_effects' AND tgtype=31 AND tgenabled='O' AND tgfoid='identity_company_review_no_effects()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_company_review_no_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='identity_company_review_no_effects()'::regprocedure)
   THEN RAISE EXCEPTION 'Company review receiving unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_review_events'::regclass AND tgname='identity_company_review_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_company_review_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Deferred company review validation required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_review_operator_change(issuer_value TEXT,target UUID,expected_version BIGINT,active BOOLEAN,explanation TEXT) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE prior identity_company_review_operators;next_row identity_company_review_operators;event identity_company_review_events;before_user JSONB;after_user JSONB;owner UUID;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_review_receiving();
 IF issuer_value IS NULL OR length(issuer_value) NOT BETWEEN 1 AND 2048 OR issuer_value~'[[:cntrl:]]' OR target IS NULL OR expected_version IS NULL OR expected_version<0 OR active IS NULL
  OR NULLIF(current_setting('opendirectory.company_review',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_review_events WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'One exact offline reviewer command required' USING ERRCODE='23514';END IF;
 SELECT to_jsonb(account) INTO before_user FROM users account WHERE id=target FOR UPDATE;owner=identity_tenant_id('user',target);
 SELECT * INTO prior FROM identity_company_review_operators WHERE issuer=issuer_value AND user_id=target FOR UPDATE;
 IF COALESCE(prior.version,0)<>expected_version OR prior.enabled IS NOT DISTINCT FROM active THEN RAISE EXCEPTION 'Reviewer version changed' USING ERRCODE='40001';END IF;
 IF before_user IS NULL OR owner IS NULL OR prior.user_id IS NOT NULL AND (NOT identity_company_review_operator_valid(prior) OR prior.tenant_id<>owner)
  OR active AND (before_user->'enabled'<>'true'::jsonb OR NOT EXISTS(SELECT 1 FROM identity_tenants WHERE id=owner AND enabled)
   OR NOT EXISTS(SELECT 1 FROM identity_subject_links WHERE issuer=issuer_value AND user_id=target)) THEN RAISE EXCEPTION 'Canonical reviewer with retained source required' USING ERRCODE='42501';END IF;
 UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=target RETURNING to_jsonb(users) INTO after_user;
 IF (after_user-ARRAY['authorization_revision','record_revision','updated_at']) IS DISTINCT FROM (before_user-ARRAY['authorization_revision','record_revision','updated_at'])
  OR (after_user->>'authorization_revision')::bigint<=(before_user->>'authorization_revision')::bigint THEN RAISE EXCEPTION 'Only reviewer authorization invalidation allowed' USING ERRCODE='42501';END IF;
 next_row.issuer=issuer_value;next_row.user_id=target;next_row.tenant_id=owner;next_row.version=expected_version+1;next_row.enabled=active;next_row.command_id=gen_random_uuid();next_row.updated_at=clock_timestamp();
 event.id=next_row.command_id;event.kind='operator';event.tenant_id=owner;event.target_id=target;event.actor=jsonb_build_object('kind','offline-company-review-operator','databaseRole',session_user);
 event.reason=explanation;event.before_state=jsonb_build_object('operator',CASE WHEN prior.user_id IS NOT NULL THEN to_jsonb(prior) END,'user',before_user);
 event.after_state=jsonb_build_object('operator',to_jsonb(next_row),'user',after_user);event.created_at=next_row.updated_at;event.transaction_id=txid_current();
 PERFORM set_config('opendirectory.company_review',to_jsonb(event)::text,true);
 IF prior.user_id IS NULL THEN INSERT INTO identity_company_review_operators SELECT next_row.*;
 ELSE UPDATE identity_company_review_operators SET version=next_row.version,enabled=active,command_id=event.id,updated_at=event.created_at WHERE issuer=issuer_value AND user_id=target;END IF;
 INSERT INTO identity_company_review_events SELECT event.*;INSERT INTO identity_company_review_outbox VALUES(event.id,owner,'pending',event.created_at);RETURN event.id;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_review_decide(proof JSONB,token_identifier TEXT,identifier UUID,expected_etag TEXT,decision_value TEXT,explanation TEXT,deadline BIGINT) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source identity_company_review_operators;registration identity_company_registrations;review identity_company_registration_reviews;event identity_company_review_events;home UUID;
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_company_review_receiving();PERFORM identity_authority_checkpoint_receiving();home=identity_authority_actor_home(proof);
 IF NULLIF(current_setting('opendirectory.company_review',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_review_events WHERE transaction_id=txid_current())
  OR token_identifier IS NULL OR length(token_identifier) NOT BETWEEN 1 AND 128 OR decision_value IS NULL OR decision_value NOT IN('approved','rejected') OR deadline IS NULL
  THEN RAISE EXCEPTION 'One original company review command required' USING ERRCODE='23514';END IF;
 PERFORM id FROM users WHERE id=(proof->>'userId')::uuid FOR UPDATE;PERFORM identity_authority_actor_home(proof);
 SELECT * INTO source FROM identity_company_review_operators WHERE issuer=proof->>'issuer' AND user_id=(proof->>'userId')::uuid FOR SHARE;
 IF source.user_id IS NULL OR NOT source.enabled OR source.tenant_id<>home OR NOT identity_company_review_operator_valid(source) THEN RAISE EXCEPTION 'Explicit platform reviewer required' USING ERRCODE='42501';END IF;
 SELECT * INTO registration FROM identity_company_registrations WHERE id=identifier FOR UPDATE;
 IF registration.id IS NULL THEN RAISE EXCEPTION 'Registration not found' USING ERRCODE='23503';END IF;
 IF registration.user_id=source.user_id OR registration.issuer=proof->>'issuer' AND registration.subject=proof->>'subject' THEN RAISE EXCEPTION 'Independent company reviewer required' USING ERRCODE='42501';END IF;
 IF NOT identity_company_registration_valid(identifier) THEN RAISE EXCEPTION 'Original pending registration evidence required' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM identity_company_registration_reviews WHERE registration_id=identifier) OR expected_etag IS DISTINCT FROM '"company-review-'||identifier::text||'-'||registration.payload_sha256||'-pending"'
  THEN RAISE EXCEPTION 'Company review version changed' USING ERRCODE='40001';END IF;
 IF to_timestamp(deadline)<=clock_timestamp() THEN RAISE EXCEPTION 'Original reviewer assurance expired' USING ERRCODE='28000';END IF;
 review.registration_id=identifier;review.id=gen_random_uuid();review.decision=decision_value;review.operator_event_id=source.command_id;review.created_at=clock_timestamp();
 event.id=review.id;event.kind='decision';event.tenant_id=registration.tenant_id;event.target_id=identifier;event.actor=proof;event.token_sha256=identity_authority_hash(to_jsonb(token_identifier));event.reason=explanation;
 event.before_state=jsonb_build_object('registrationId',identifier,'payloadSha256',registration.payload_sha256,'status','pending-verification');event.after_state=to_jsonb(review);event.created_at=review.created_at;event.valid_until=to_timestamp(deadline);event.transaction_id=txid_current();
 PERFORM set_config('opendirectory.company_review',to_jsonb(event)::text,true);
 INSERT INTO identity_company_registration_reviews SELECT review.*;INSERT INTO identity_company_review_events SELECT event.*;INSERT INTO identity_company_review_outbox VALUES(event.id,event.tenant_id,'pending',event.created_at);RETURN event.id;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_review_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source identity_company_review_operators;home UUID;
BEGIN
 PERFORM identity_company_review_receiving();
 IF identity_company_review_scope() IS DISTINCT FROM to_jsonb(NEW) OR NOT identity_company_review_event_valid(NEW.id) THEN RAISE EXCEPTION 'Exact company review event and outbox required' USING ERRCODE='42501';END IF;
 IF NEW.kind='operator' THEN
  SELECT * INTO source FROM identity_company_review_operators WHERE command_id=NEW.id;
  IF source.user_id IS NULL OR NOT identity_company_review_operator_valid(source) OR NOT EXISTS(SELECT 1 FROM users account
   JOIN identity_authorization_audit audit ON audit.user_id=account.id AND audit.revision=account.authorization_revision
   JOIN identity_user_record_audit record ON record.user_id=account.id AND record.revision=account.record_revision
   WHERE account.id=NEW.target_id AND to_jsonb(account)=NEW.after_state->'user' AND record.action='update' AND audit.reason='security_reset'
    AND record.details->'after'=jsonb_build_object('username',account.username,'email',account.email,'displayName',account.display_name,'department',account.department,'title',account.title,'enabled',account.enabled))
   THEN RAISE EXCEPTION 'Actual reviewer state and authorization invalidation evidence required' USING ERRCODE='42501';END IF;
 ELSE
  PERFORM identity_authority_checkpoint_receiving();home=identity_authority_actor_home(NEW.actor);
  SELECT * INTO source FROM identity_company_review_operators WHERE issuer=NEW.actor->>'issuer' AND user_id=(NEW.actor->>'userId')::uuid;
  IF NEW.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'Original reviewer assurance expired' USING ERRCODE='28000';END IF;
  IF source.user_id IS NULL OR NOT source.enabled OR source.tenant_id<>home OR NOT identity_company_review_operator_valid(source)
   OR NOT identity_company_review_valid(NEW.target_id) OR NOT identity_company_registration_valid(NEW.target_id)
   OR NEW.after_state->>'operator_event_id'<>source.command_id::text
   OR NOT EXISTS(SELECT 1 FROM identity_authority_command_checkpoints checkpoint WHERE checkpoint.transaction_id=NEW.transaction_id AND checkpoint.tenant_id=home
    AND checkpoint.user_id=source.user_id AND checkpoint.original_context=NEW.actor-ARRAY['issuer','subject'] AND checkpoint.token_sha256=NEW.token_sha256
    AND checkpoint.valid_until<=NEW.valid_until AND checkpoint.valid_until>clock_timestamp()) THEN RAISE EXCEPTION 'Original independent reviewer and final checkpoint required' USING ERRCODE='42501';END IF;
 END IF;RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS identity_company_review_commit ON identity_company_review_events;
CREATE CONSTRAINT TRIGGER identity_company_review_commit AFTER INSERT ON identity_company_review_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_review_commit();
DO $$ DECLARE relation TEXT;owned BOOLEAN;checkpoint BOOLEAN;routine TEXT;guard TEXT;BEGIN
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  owned=relation IN('identity_company_review_operators','identity_company_registration_reviews','identity_company_review_events','identity_company_review_outbox');
  checkpoint=relation IN('identity_authority_command_checkpoints','identity_authority_command_checkpoint_events','identity_authority_command_checkpoint_outbox');
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_company_review_no_truncate ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_company_review_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_review_no_effects()',relation);
  IF owned THEN
   EXECUTE format('DROP TRIGGER IF EXISTS identity_company_review_guard ON %I',relation);EXECUTE format('CREATE TRIGGER identity_company_review_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_review_guard()',relation);
   FOR guard,routine IN SELECT * FROM (VALUES ('identity_authority_stage','identity_authority_stage_no_effects'),('identity_authority_seal','identity_authority_namespace_no_effects'),('identity_authority_checkpoint','identity_authority_checkpoint_no_effects'),('identity_authority_source_set','identity_authority_source_set_no_effects'),('identity_organization','identity_organization_no_effects'),('identity_company_registration','identity_company_registration_fence')) guards(name,routine) LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||CASE WHEN guard='identity_company_registration' THEN '_fence' ELSE '_no_effects' END,relation);
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()','aaa_'||guard||CASE WHEN guard='identity_company_registration' THEN '_fence' ELSE '_no_effects' END,relation,routine);
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I','aaa_'||guard||'_no_truncate',relation);EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()','aaa_'||guard||'_no_truncate',relation,routine);
   END LOOP;
  ELSIF NOT checkpoint THEN
   EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_company_review_no_effects ON %I',relation);EXECUTE format('CREATE TRIGGER aaa_identity_company_review_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_review_no_effects()',relation);
  END IF;
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_company_review_event_valid(uuid)','identity_company_review_operator_valid(identity_company_review_operators)','identity_company_review_valid(uuid)','identity_company_review_scope()','identity_company_review_no_effects()','identity_company_review_guard()','identity_company_review_receiving()','identity_company_review_operator_change(text,uuid,bigint,boolean,text)','identity_company_review_decide(jsonb,text,uuid,text,text,text,bigint)','identity_company_review_commit()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
