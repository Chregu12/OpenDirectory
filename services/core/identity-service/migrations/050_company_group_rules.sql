CREATE TABLE IF NOT EXISTS identity_company_group_rules (
 group_id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),revision BIGINT NOT NULL CHECK(revision>0),enabled BOOLEAN NOT NULL,draft JSONB NOT NULL,
 approval JSONB NOT NULL,created_by UUID NOT NULL,last_event_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS identity_company_group_rule_events (
 id UUID PRIMARY KEY,group_id UUID NOT NULL REFERENCES identity_company_group_rules(group_id) DEFERRABLE INITIALLY DEFERRED,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),revision BIGINT NOT NULL,
 command JSONB NOT NULL,result JSONB NOT NULL,transaction_id BIGINT NOT NULL DEFAULT txid_current(),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),UNIQUE(group_id,revision)
);
CREATE INDEX IF NOT EXISTS identity_company_group_rule_transaction ON identity_company_group_rule_events(transaction_id);
CREATE TABLE IF NOT EXISTS identity_company_group_rule_outbox (
 id UUID PRIMARY KEY REFERENCES identity_company_group_rule_events(id),status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),fingerprint TEXT NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$'),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS identity_company_group_rule_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_company_group_rule_effects (
 id UUID PRIMARY KEY REFERENCES identity_directory_group_events(id),group_id UUID NOT NULL REFERENCES identity_company_group_rules(group_id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 membership_id UUID NOT NULL REFERENCES identity_membership_origins(membership_id),user_id UUID NOT NULL,rule_revision BIGINT NOT NULL,action TEXT NOT NULL CHECK(action IN('member-add','member-remove')),
 source JSONB NOT NULL,group_scope_sha256 TEXT NOT NULL CHECK(group_scope_sha256~'^[a-f0-9]{64}$'),transaction_id BIGINT NOT NULL DEFAULT txid_current(),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS identity_company_group_rule_effect_member ON identity_company_group_rule_effects(group_id,membership_id) WHERE action='member-add';
CREATE TABLE IF NOT EXISTS identity_company_group_rule_effect_outbox (
 id UUID PRIMARY KEY REFERENCES identity_company_group_rule_effects(id),status TEXT NOT NULL CHECK(status='pending'),fingerprint TEXT NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$'),created_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION identity_company_group_rule_draft_valid(data JSONB) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE condition JSONB;field TEXT;values JSONB;count_values INTEGER;
BEGIN
 IF jsonb_typeof(data)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(data))<>3 OR NOT data ?& ARRAY['dynamic','childGroupIds','excludedUserIds'] THEN RETURN false;END IF;
 IF data->'dynamic'<>'null'::jsonb THEN
  IF jsonb_typeof(data->'dynamic')<>'object' OR (SELECT count(*) FROM jsonb_object_keys(data->'dynamic'))<>1 OR jsonb_typeof(data#>'{dynamic,all}')<>'array'
   OR jsonb_array_length(data#>'{dynamic,all}') NOT BETWEEN 1 AND 8 OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(data#>'{dynamic,all}'))<>jsonb_array_length(data#>'{dynamic,all}') THEN RETURN false;END IF;
  FOR condition IN SELECT value FROM jsonb_array_elements(data#>'{dynamic,all}') LOOP
   IF jsonb_typeof(condition)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(condition))<>3 OR NOT condition ?& ARRAY['attribute','operator','value']
    OR jsonb_typeof(condition->'attribute')<>'string' OR jsonb_typeof(condition->'operator')<>'string'
    OR condition->>'attribute' NOT IN('department','title','email','username','displayName') OR condition->>'operator' NOT IN('equals','startsWith','endsWith')
    OR jsonb_typeof(condition->'value')<>'string' OR length(condition->>'value') NOT BETWEEN 1 AND 160
    OR btrim(condition->>'value',U&'\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000\FEFF')<>condition->>'value'
    OR condition->>'value'~U&'[\0001-\001F\007F-\009F]' THEN RETURN false;END IF;
  END LOOP;
 END IF;
 FOREACH field IN ARRAY ARRAY['childGroupIds','excludedUserIds'] LOOP
  values=data->field;IF jsonb_typeof(values)<>'array' THEN RETURN false;END IF;count_values=jsonb_array_length(values);
  IF count_values>(CASE WHEN field='childGroupIds' THEN 25 ELSE 10000 END) OR EXISTS(SELECT 1 FROM jsonb_array_elements(values) value WHERE jsonb_typeof(value)<>'string' OR value#>>'{}'!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
   OR (SELECT COALESCE(jsonb_agg(value ORDER BY value),'[]'::jsonb) FROM(SELECT DISTINCT value FROM jsonb_array_elements(values)) unique_value) IS DISTINCT FROM values THEN RETURN false;END IF;
 END LOOP;
 RETURN data->'dynamic'<>'null'::jsonb OR jsonb_array_length(data->'childGroupIds')>0;
EXCEPTION WHEN OTHERS THEN RETURN false;END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_graph(tenant UUID,target UUID,children JSONB) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE invalid BOOLEAN;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('company-group-rule:'||tenant::text,500050));
 WITH RECURSIVE edges AS (
  SELECT group_id AS parent,value::uuid AS child FROM identity_company_group_rules rule CROSS JOIN LATERAL jsonb_array_elements_text(rule.draft->'childGroupIds') child(value) WHERE tenant_id=tenant AND enabled AND group_id<>target
  UNION ALL SELECT target,value::uuid FROM jsonb_array_elements_text(children)
 ), ancestors(node,depth) AS (
  SELECT parent,1 FROM edges WHERE child=target UNION SELECT edge.parent,path.depth+1 FROM ancestors path JOIN edges edge ON edge.child=path.node WHERE path.depth<17
 ), descendants(node,depth) AS (
  SELECT child,1 FROM edges WHERE parent=target UNION SELECT edge.child,path.depth+1 FROM descendants path JOIN edges edge ON edge.parent=path.node WHERE path.depth<17
 ) SELECT EXISTS(SELECT 1 FROM descendants WHERE node=target) OR COALESCE((SELECT max(depth) FROM ancestors),0)+COALESCE((SELECT max(depth) FROM descendants),0)>16 INTO invalid;
 IF invalid THEN RAISE EXCEPTION 'Nested groups must be acyclic and at most 16 links deep' USING ERRCODE='23514';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_wants(setting identity_company_group_rules,target UUID) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
DECLARE account RECORD;condition JSONB;actual TEXT;wanted TEXT;dynamic_matches BOOLEAN;
BEGIN
 IF NOT setting.enabled OR NOT identity_company_group_rule_draft_valid(setting.draft) OR setting.draft->'excludedUserIds' ? target::text THEN RETURN false;END IF;
 SELECT id,department,title,email,username,display_name INTO account FROM users WHERE id=target AND identity_tenant_id('user',id)=setting.tenant_id AND identity_tenant_user_enabled(id);
 IF account.id IS NULL THEN RETURN false;END IF;
 dynamic_matches=setting.draft->'dynamic'<>'null'::jsonb;
 IF dynamic_matches THEN
  FOR condition IN SELECT value FROM jsonb_array_elements(setting.draft#>'{dynamic,all}') LOOP
   actual=lower(COALESCE(CASE condition->>'attribute' WHEN 'department' THEN account.department WHEN 'title' THEN account.title WHEN 'email' THEN account.email WHEN 'username' THEN account.username WHEN 'displayName' THEN account.display_name END,''));wanted=lower(condition->>'value');
   IF NOT(CASE condition->>'operator' WHEN 'equals' THEN actual=wanted WHEN 'startsWith' THEN starts_with(actual,wanted) WHEN 'endsWith' THEN right(actual,length(wanted))=wanted ELSE false END) THEN dynamic_matches=false;EXIT;END IF;
  END LOOP;
 END IF;
 RETURN dynamic_matches OR EXISTS(SELECT 1 FROM group_members membership JOIN groups collection ON collection.id=membership.group_id
  WHERE membership.user_id=target::text AND identity_tenant_id('group',collection.id)=setting.tenant_id AND setting.draft->'childGroupIds' ? collection.id::text AND identity_membership_review_allowed(membership.membership_id));
END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_guard() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;source JSONB;prior identity_company_group_rules;event identity_company_group_rule_events;reference TEXT;actor UUID;
BEGIN
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM identity_company_group_rule_events) THEN RAISE EXCEPTION 'Group rule history retained' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 IF TG_OP IN('DELETE','UPDATE') AND TG_TABLE_NAME<>'identity_company_group_rules' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'Original group rule history is immutable' USING ERRCODE='42501';END IF;
 PERFORM identity_authority_owner();scope=NULLIF(current_setting('opendirectory.company_group_rule',true),'')::jsonb;
 IF scope IS NULL OR jsonb_typeof(scope)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(scope))<>6 OR NOT scope ?& ARRAY['kind','id','source','groupId','expectedRevision','values'] OR scope->>'kind' IS DISTINCT FROM 'configure'
  OR jsonb_typeof(scope->'values')<>'object' OR (SELECT count(*) FROM jsonb_object_keys(scope->'values'))<>4 OR NOT scope->'values' ?& ARRAY['draft','enabled','reason','confirm']
  OR jsonb_typeof(scope#>'{values,enabled}')<>'boolean' OR scope#>'{values,confirm}' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(scope#>'{values,reason}')<>'string'
  OR btrim(scope#>>'{values,reason}') IS DISTINCT FROM scope#>>'{values,reason}' OR scope#>>'{values,reason}'~'[[:cntrl:]]'
  THEN RAISE EXCEPTION 'Original group rule configuration source required' USING ERRCODE='42501';END IF;
 source=scope->'source';actor=(source->>'actorUserId')::uuid;PERFORM identity_automation_owner(source);
 IF TG_TABLE_NAME='identity_company_group_rules' THEN
  IF NEW.tenant_id::text<>source#>>'{tenant,id}' OR NEW.group_id::text<>scope->>'groupId' OR NEW.last_event_id::text<>scope->>'id'
   OR NEW.draft IS DISTINCT FROM scope#>'{values,draft}' OR NEW.enabled IS DISTINCT FROM (scope#>>'{values,enabled}')::boolean OR NEW.approval IS DISTINCT FROM source
   OR scope#>'{values,confirm}'<>'true'::jsonb OR length(scope#>>'{values,reason}') NOT BETWEEN 10 AND 500 OR NOT identity_company_group_rule_draft_valid(NEW.draft)
   OR identity_tenant_id('group',NEW.group_id) IS DISTINCT FROM NEW.tenant_id OR NOT EXISTS(SELECT 1 FROM groups WHERE id=NEW.group_id)
   THEN RAISE EXCEPTION 'Exact own group rule content required' USING ERRCODE='42501';END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.revision<>1 OR NEW.created_by<>actor OR scope->'expectedRevision'<>'null'::jsonb THEN RAISE EXCEPTION 'New group rule origin required' USING ERRCODE='42501';END IF;
  ELSIF NEW.revision<>OLD.revision+1 OR OLD.revision::text IS DISTINCT FROM scope->>'expectedRevision'
   OR (to_jsonb(NEW)-ARRAY['revision','enabled','draft','approval','last_event_id','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['revision','enabled','draft','approval','last_event_id','updated_at'])
   OR NEW.enabled=OLD.enabled AND NEW.draft=OLD.draft THEN RAISE EXCEPTION 'Conditional changed group rule required' USING ERRCODE='40001';END IF;
  IF TG_WHEN='BEFORE' THEN
    FOR reference IN SELECT value FROM jsonb_array_elements_text(NEW.draft->'childGroupIds') child(value) LOOP
     IF reference=NEW.group_id::text OR identity_tenant_id('group',reference::uuid) IS DISTINCT FROM NEW.tenant_id OR NEW.enabled AND NOT EXISTS(SELECT 1 FROM groups WHERE id=reference::uuid) THEN RAISE EXCEPTION 'Actual own child group required' USING ERRCODE='23503';END IF;
    END LOOP;
    FOR reference IN SELECT value FROM jsonb_array_elements_text(NEW.draft->'excludedUserIds') excluded(value) LOOP
     IF identity_tenant_id('user',reference::uuid) IS DISTINCT FROM NEW.tenant_id THEN RAISE EXCEPTION 'Own excluded user required' USING ERRCODE='23503';END IF;
    END LOOP;
   PERFORM identity_company_group_rule_graph(NEW.tenant_id,NEW.group_id,CASE WHEN NEW.enabled THEN NEW.draft->'childGroupIds' ELSE '[]'::jsonb END);
  ELSE
   SELECT * INTO event FROM identity_company_group_rule_events WHERE id=NEW.last_event_id AND transaction_id=txid_current();
   IF event.id IS NULL OR event.command IS DISTINCT FROM scope OR event.result IS DISTINCT FROM to_jsonb(NEW) OR event.group_id<>NEW.group_id OR event.tenant_id<>NEW.tenant_id OR event.revision<>NEW.revision
    OR NOT EXISTS(SELECT 1 FROM identity_company_group_rule_outbox WHERE id=event.id AND status='pending' AND fingerprint=encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex')) THEN RAISE EXCEPTION 'Actual group rule event and pending receipt required' USING ERRCODE='42501';END IF;
  END IF;
 ELSIF TG_TABLE_NAME='identity_company_group_rule_events' THEN
  IF NEW.id::text<>scope->>'id' OR NEW.command IS DISTINCT FROM scope OR NEW.transaction_id<>txid_current() OR NEW.result IS DISTINCT FROM (SELECT to_jsonb(actual) FROM identity_company_group_rules actual WHERE group_id=NEW.group_id AND tenant_id=NEW.tenant_id AND revision=NEW.revision AND last_event_id=NEW.id)
   THEN RAISE EXCEPTION 'Actual group rule effect required' USING ERRCODE='42501';END IF;
 ELSE
  SELECT * INTO event FROM identity_company_group_rule_events WHERE id=NEW.id AND transaction_id=txid_current();
  IF event.id IS NULL OR event.command IS DISTINCT FROM scope OR NEW.status<>'pending' OR NEW.created_at<>event.created_at OR NEW.fingerprint<>encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'Same original group rule pending receipt required' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_fence() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.company_group_rule',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_company_group_rule_events WHERE transaction_id=txid_current()) THEN
  IF TG_TABLE_NAME NOT IN('identity_company_group_rules','identity_company_group_rule_events','identity_company_group_rule_outbox') THEN RAISE EXCEPTION 'Group rule configuration cannot piggyback canonical mutations' USING ERRCODE='42501';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSIF TG_OP='TRUNCATE' THEN RETURN NULL;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_group_rule_effect_guard() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;mutation JSONB;setting identity_company_group_rules;event identity_directory_group_events;membership UUID;desired BOOLEAN;origin identity_membership_origins;effect identity_company_group_rule_effects;
BEGIN
 IF TG_OP='TRUNCATE' THEN IF EXISTS(SELECT 1 FROM identity_company_group_rule_effects) THEN RAISE EXCEPTION 'Group rule effects retained' USING ERRCODE='42501';END IF;RETURN NULL;END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Group rule effects are immutable' USING ERRCODE='42501';END IF;
 PERFORM identity_authority_owner();scope=NULLIF(current_setting('opendirectory.company_group_rule_effect',true),'')::jsonb;mutation=NULLIF(current_setting('opendirectory.group_mutation',true),'')::jsonb;
 IF TG_TABLE_NAME='identity_company_group_rule_effect_outbox' THEN
  SELECT * INTO effect FROM identity_company_group_rule_effects WHERE id=NEW.id;
  IF effect.id IS NULL OR scope IS NULL OR effect.source IS DISTINCT FROM scope OR effect.transaction_id<>txid_current() OR NEW.status<>'pending' OR NEW.created_at<>effect.created_at
   OR NEW.fingerprint<>encode(sha256(convert_to(to_jsonb(effect)::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'Actual group-rule effect pending fingerprint required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF scope IS NULL OR mutation IS NULL OR scope->>'reason' IS NULL OR length(scope->>'reason') NOT BETWEEN 10 AND 500 OR NEW.source IS DISTINCT FROM scope OR NEW.transaction_id<>txid_current() OR scope->>'groupId' IS DISTINCT FROM NEW.group_id::text
  OR scope->>'ruleRevision' IS DISTINCT FROM NEW.rule_revision::text OR scope->>'operationId' IS DISTINCT FROM NEW.id::text THEN RAISE EXCEPTION 'Actual original group rule effect required' USING ERRCODE='42501';END IF;
 PERFORM identity_automation_owner(scope->'authority');
 SELECT * INTO setting FROM identity_company_group_rules WHERE group_id=NEW.group_id AND tenant_id=NEW.tenant_id;
 SELECT * INTO event FROM identity_directory_group_events WHERE id=NEW.id AND tenant_id=NEW.tenant_id AND group_id=NEW.group_id AND transaction_id=txid_current();
 IF setting.group_id IS NULL OR setting.revision<>NEW.rule_revision OR scope#>>'{authority,tenant,id}' IS DISTINCT FROM NEW.tenant_id::text
  OR event.id IS NULL OR event.action<>NEW.action OR event.scope_sha256<>NEW.group_scope_sha256 OR NEW.group_scope_sha256<>encode(sha256(convert_to(mutation::text,'UTF8')),'hex')
  OR event.actor IS DISTINCT FROM jsonb_build_object('issuer',scope#>>'{authority,issuer}','subject',scope#>>'{authority,subject}','userId',scope#>>'{authority,actorUserId}')
  OR mutation#>>'{target,member,userId}' IS DISTINCT FROM NEW.user_id::text OR mutation#>>'{target,id}' IS DISTINCT FROM NEW.group_id::text
  OR NOT EXISTS(SELECT 1 FROM identity_directory_group_outbox WHERE id=NEW.id AND tenant_id=NEW.tenant_id AND action=NEW.action)
  OR NOT EXISTS(SELECT 1 FROM identity_company_group_rule_events original JOIN identity_company_group_rule_outbox box ON box.id=original.id AND box.status='pending' WHERE original.id=setting.last_event_id AND original.result=to_jsonb(setting))
  THEN RAISE EXCEPTION 'Actual original canonical membership and rule receipts required' USING ERRCODE='42501';END IF;
 SELECT * INTO origin FROM identity_membership_origins WHERE membership_id=NEW.membership_id AND group_id=NEW.group_id AND user_id=NEW.user_id;
 desired=identity_company_group_rule_wants(setting,NEW.user_id);
 IF NEW.action='member-add' THEN
  membership=NULLIF(current_setting('opendirectory.group_mutation_membership',true),'')::uuid;
  IF NOT desired OR membership IS DISTINCT FROM NEW.membership_id OR origin.created_by::text IS DISTINCT FROM scope#>>'{authority,actorUserId}'
   OR NOT EXISTS(SELECT 1 FROM group_members WHERE membership_id=NEW.membership_id AND group_id=NEW.group_id AND user_id=NEW.user_id::text)
   THEN RAISE EXCEPTION 'Actual desired new group-rule membership required' USING ERRCODE='42501';END IF;
 ELSE
  IF mutation#>>'{target,member,id}' IS DISTINCT FROM NEW.membership_id::text OR EXISTS(SELECT 1 FROM group_members WHERE membership_id=NEW.membership_id)
   OR NOT EXISTS(SELECT 1 FROM identity_company_group_rule_effects original WHERE original.action='member-add' AND original.membership_id=NEW.membership_id AND original.group_id=NEW.group_id
    AND original.user_id=NEW.user_id AND (NOT desired OR original.rule_revision<>setting.revision OR origin.eligibility_revision::text IS DISTINCT FROM mutation#>>'{target,member,eligibilityRevision}'))
   THEN RAISE EXCEPTION 'Only obsolete original rule membership may be removed' USING ERRCODE='42501';END IF;
 END IF;
 IF TG_WHEN='AFTER' AND NOT EXISTS(SELECT 1 FROM identity_company_group_rule_effect_outbox WHERE id=NEW.id AND status='pending' AND created_at=NEW.created_at AND fingerprint=encode(sha256(convert_to(to_jsonb(NEW)::text,'UTF8')),'hex'))
  THEN RAISE EXCEPTION 'Original group rule effect pending receipt required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
DO $$ DECLARE relation RECORD;table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['identity_company_group_rules','identity_company_group_rule_events','identity_company_group_rule_outbox'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER company_group_rule_before BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_guard()',table_name);
  EXECUTE format('CREATE OR REPLACE TRIGGER company_group_rule_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_guard()',table_name);
  EXECUTE format('REVOKE ALL ON %I FROM PUBLIC',table_name);
 END LOOP;
 DROP TRIGGER IF EXISTS company_group_rule_commit ON identity_company_group_rules;
 CREATE CONSTRAINT TRIGGER company_group_rule_commit AFTER INSERT OR UPDATE ON identity_company_group_rules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_guard();
 CREATE OR REPLACE TRIGGER company_group_rule_effect_before BEFORE INSERT OR UPDATE OR DELETE ON identity_company_group_rule_effects FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_effect_guard();
 CREATE OR REPLACE TRIGGER company_group_rule_effect_truncate BEFORE TRUNCATE ON identity_company_group_rule_effects FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_effect_guard();
 DROP TRIGGER IF EXISTS company_group_rule_effect_commit ON identity_company_group_rule_effects;
 CREATE CONSTRAINT TRIGGER company_group_rule_effect_commit AFTER INSERT ON identity_company_group_rule_effects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_effect_guard();
 CREATE OR REPLACE TRIGGER company_group_rule_effect_before BEFORE INSERT OR UPDATE OR DELETE ON identity_company_group_rule_effect_outbox FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_effect_guard();
 CREATE OR REPLACE TRIGGER company_group_rule_effect_truncate BEFORE TRUNCATE ON identity_company_group_rule_effect_outbox FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_effect_guard();
 REVOKE ALL ON identity_company_group_rule_effects FROM PUBLIC;
 REVOKE ALL ON identity_company_group_rule_effect_outbox FROM PUBLIC;
 FOR relation IN SELECT oid::regclass AS identity,relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind='r' AND relname<>'identity_company_group_rule_manifest' LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER zzz_company_group_rule_fence BEFORE INSERT OR UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_fence()',relation.identity);
  EXECUTE format('CREATE OR REPLACE TRIGGER zzz_company_group_rule_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_fence()',relation.identity);
  EXECUTE format('DROP TRIGGER IF EXISTS zzz_company_group_rule_commit_fence ON %s',relation.identity);
  EXECUTE format('CREATE CONSTRAINT TRIGGER zzz_company_group_rule_commit_fence AFTER INSERT OR UPDATE OR DELETE ON %s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_fence()',relation.identity);
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE entry RECORD;
BEGIN
 PERFORM identity_automation_receiving();
 IF (SELECT count(*) FROM identity_company_group_rule_manifest)<>8 OR (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgfoid='identity_company_group_rule_guard()'::regprocedure
   AND tgrelid IN('identity_company_group_rules'::regclass,'identity_company_group_rule_events'::regclass,'identity_company_group_rule_outbox'::regclass)
   AND (tgname='company_group_rule_before' AND tgtype=31 AND NOT tgdeferrable OR tgname='company_group_rule_truncate' AND tgtype=34 AND NOT tgdeferrable OR tgname='company_group_rule_commit' AND tgtype=21 AND tgdeferrable AND tginitdeferred))<>7
  OR EXISTS(SELECT 1 FROM pg_class relation WHERE relnamespace=current_schema()::regnamespace AND relkind='r' AND relname<>'identity_company_group_rule_manifest'
   AND (NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname='zzz_company_group_rule_fence' AND tgfoid='identity_company_group_rule_fence()'::regprocedure AND tgenabled='O' AND tgtype=31 AND NOT tgdeferrable)
    OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname='zzz_company_group_rule_commit_fence' AND tgfoid='identity_company_group_rule_fence()'::regprocedure AND tgenabled='O' AND tgtype=29 AND tgdeferrable AND tginitdeferred)
    OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname='zzz_company_group_rule_no_truncate' AND tgfoid='identity_company_group_rule_fence()'::regprocedure AND tgenabled='O' AND tgtype=34 AND NOT tgdeferrable)))
  OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identity_company_group_rule_manifest'::regclass AND tgname='company_group_rule_manifest_guard' AND tgfoid='identity_company_group_rule_manifest_guard()'::regprocedure AND tgenabled='O')
  OR (SELECT count(*) FROM pg_trigger WHERE tgrelid='identity_company_group_rule_effects'::regclass AND tgfoid='identity_company_group_rule_effect_guard()'::regprocedure AND tgenabled='O'
   AND(tgname='company_group_rule_effect_before' AND tgtype=31 AND NOT tgdeferrable OR tgname='company_group_rule_effect_truncate' AND tgtype=34 AND NOT tgdeferrable OR tgname='company_group_rule_effect_commit' AND tgtype=5 AND tgdeferrable AND tginitdeferred))<>3
  OR (SELECT count(*) FROM pg_trigger WHERE tgrelid='identity_company_group_rule_effect_outbox'::regclass AND tgfoid='identity_company_group_rule_effect_guard()'::regprocedure AND tgenabled='O'
   AND(tgname='company_group_rule_effect_before' AND tgtype=31 AND NOT tgdeferrable OR tgname='company_group_rule_effect_truncate' AND tgtype=34 AND NOT tgdeferrable))<>2
  THEN RAISE EXCEPTION 'Actual group rule receiving required' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT * FROM identity_company_group_rule_manifest LOOP
  IF to_regprocedure(entry.signature) IS NULL OR entry.digest<>md5(pg_get_functiondef(to_regprocedure(entry.signature))) THEN RAISE EXCEPTION 'Original group rule receiver changed' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION identity_company_group_rule_manifest_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Group rule receiver manifest is immutable' USING ERRCODE='42501';END; $$;
CREATE OR REPLACE TRIGGER company_group_rule_manifest_guard BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON identity_company_group_rule_manifest FOR EACH STATEMENT EXECUTE FUNCTION identity_company_group_rule_manifest_guard();
DO $$ DECLARE signature TEXT;BEGIN
 FOREACH signature IN ARRAY ARRAY['identity_company_group_rule_draft_valid(jsonb)','identity_company_group_rule_graph(uuid,uuid,jsonb)','identity_company_group_rule_guard()','identity_company_group_rule_fence()','identity_company_group_rule_receiving()','identity_company_group_rule_manifest_guard()','identity_company_group_rule_wants(identity_company_group_rules,uuid)','identity_company_group_rule_effect_guard()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
END; $$;
ALTER TABLE identity_company_group_rule_manifest DISABLE TRIGGER company_group_rule_manifest_guard;
INSERT INTO identity_company_group_rule_manifest SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY['identity_company_group_rule_draft_valid(jsonb)','identity_company_group_rule_graph(uuid,uuid,jsonb)','identity_company_group_rule_guard()','identity_company_group_rule_fence()','identity_company_group_rule_receiving()','identity_company_group_rule_manifest_guard()','identity_company_group_rule_wants(identity_company_group_rules,uuid)','identity_company_group_rule_effect_guard()']) signature
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE identity_company_group_rule_manifest ENABLE TRIGGER company_group_rule_manifest_guard;
REVOKE ALL ON identity_company_group_rule_manifest FROM PUBLIC;
DO $$ DECLARE relation TEXT;hook RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_group_rules','identity_company_group_rule_events','identity_company_group_rule_outbox','identity_company_group_rule_manifest','identity_company_group_rule_effects','identity_company_group_rule_effect_outbox'] LOOP
  FOR hook IN SELECT * FROM identity_license_user_source_hooks()
   UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_groups_fence','identity_company_offboarding_groups_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_access_fence','identity_company_offboarding_access_fence'
   UNION ALL SELECT 'aaa_identity_company_automation_fence','identity_automation_fence' LOOP
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,relation,hook.routine);
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation,hook.routine);
  END LOOP;
 END LOOP;
END; $$;
