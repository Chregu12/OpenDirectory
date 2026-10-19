CREATE TABLE IF NOT EXISTS company_blueprints (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,revision BIGINT NOT NULL CHECK(revision>0),published_version INTEGER CHECK(published_version>0),
 draft JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,UNIQUE(id,tenant_id)
);
CREATE INDEX IF NOT EXISTS company_blueprint_page ON company_blueprints(tenant_id,id);
CREATE TABLE IF NOT EXISTS company_blueprint_operations (
 id UUID PRIMARY KEY,blueprint_id UUID NOT NULL,tenant_id UUID NOT NULL,actor_user_id UUID NOT NULL,issuer TEXT NOT NULL,subject TEXT NOT NULL,
 command JSONB NOT NULL,source JSONB NOT NULL,application_source JSONB,before_state JSONB,after_state JSONB NOT NULL,version_state JSONB,
 created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL UNIQUE,
 FOREIGN KEY(blueprint_id,tenant_id) REFERENCES company_blueprints(id,tenant_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS company_blueprint_versions (
 blueprint_id UUID NOT NULL,tenant_id UUID NOT NULL,version INTEGER NOT NULL CHECK(version>0),source_revision BIGINT NOT NULL CHECK(source_revision>0),
 published_revision BIGINT NOT NULL CHECK(published_revision=source_revision+1),actor_user_id UUID NOT NULL,
 operation_id UUID NOT NULL UNIQUE REFERENCES company_blueprint_operations(id),created_at TIMESTAMPTZ NOT NULL,draft JSONB NOT NULL,apps JSONB NOT NULL,
 PRIMARY KEY(blueprint_id,version),FOREIGN KEY(blueprint_id,tenant_id) REFERENCES company_blueprints(id,tenant_id)
);
CREATE TABLE IF NOT EXISTS company_blueprint_events (
 id UUID PRIMARY KEY REFERENCES company_blueprint_operations(id),tenant_id UUID NOT NULL,blueprint_id UUID NOT NULL,
 type TEXT NOT NULL CHECK(type IN('blueprint.created','blueprint.draft.updated','blueprint.published','blueprint.draft.restored')),
 version INTEGER NOT NULL CHECK(version=1),actor_user_id UUID NOT NULL,correlation_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL,
 before_revision BIGINT,after_revision BIGINT NOT NULL CHECK(after_revision>0),released_version INTEGER,restored_from INTEGER,reason TEXT NOT NULL,
 UNIQUE(blueprint_id,after_revision),FOREIGN KEY(blueprint_id,tenant_id) REFERENCES company_blueprints(id,tenant_id)
);
CREATE INDEX IF NOT EXISTS company_blueprint_history ON company_blueprint_events(tenant_id,blueprint_id,after_revision);
CREATE TABLE IF NOT EXISTS company_blueprint_outbox (
 id UUID PRIMARY KEY REFERENCES company_blueprint_events(id),tenant_id UUID NOT NULL,status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION company_blueprint_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
CREATE OR REPLACE FUNCTION company_blueprint_text(data JSONB,minimum INTEGER,maximum INTEGER) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(jsonb_typeof(data)='string' AND length(data#>>'{}') BETWEEN minimum AND maximum
 AND data#>>'{}'=btrim(data#>>'{}',U&'\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000\FEFF')
 AND NOT data#>>'{}' ~ U&'[\0001-\001F\007F-\009F]',false);
$$;
CREATE OR REPLACE FUNCTION company_blueprint_draft_valid(document JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE configuration JSONB;payload JSONB;field TEXT;seen TEXT[]='{}';application JSONB;bytes INTEGER=0;
BEGIN
 IF NOT license_company_exact(document,ARRAY['name','description','platform','configurations','appPoolIds'])
  OR NOT company_blueprint_text(document->'name',1,160) OR NOT company_blueprint_text(document->'description',0,2000)
  OR document->>'platform' NOT IN('all','windows','macos','linux') OR jsonb_typeof(document->'platform') IS DISTINCT FROM 'string'
  OR jsonb_typeof(document->'configurations') IS DISTINCT FROM 'array' OR jsonb_array_length(document->'configurations')>25
  OR jsonb_typeof(document->'appPoolIds') IS DISTINCT FROM 'array' OR jsonb_array_length(document->'appPoolIds')>25 THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['name','description'] LOOP
  IF document->>field IS DISTINCT FROM btrim(document->>field) OR document->>field ~ '[[:cntrl:]]' THEN RETURN false;END IF;
 END LOOP;
 FOR configuration IN SELECT value FROM jsonb_array_elements(document->'configurations') LOOP
  IF NOT license_company_exact(configuration,ARRAY['id','type','name','payloadJson']) OR NOT license_company_uuid(configuration->>'id')
   OR configuration->>'id'=ANY(seen) OR NOT company_blueprint_text(configuration->'name',1,160)
   OR configuration->>'name' IS DISTINCT FROM btrim(configuration->>'name') OR configuration->>'name' ~ '[[:cntrl:]]'
   OR jsonb_typeof(configuration->'type') IS DISTINCT FROM 'string' OR configuration->>'type' NOT IN('screen_lock','filevault','software_update')
   OR jsonb_typeof(configuration->'payloadJson') IS DISTINCT FROM 'string' OR octet_length(configuration->>'payloadJson')>65536 THEN RETURN false;END IF;
  seen=array_append(seen,configuration->>'id');bytes=bytes+octet_length(configuration->>'payloadJson');IF bytes>262144 THEN RETURN false;END IF;
  IF configuration->>'payloadJson' ~ '[0-9][.eE]' THEN RETURN false;END IF;
  payload=(configuration->>'payloadJson')::jsonb;
  IF (SELECT count(*) FROM regexp_matches(configuration->>'payloadJson','"\s*:','g'))<>(SELECT count(*) FROM jsonb_object_keys(payload)) THEN RETURN false;END IF;
  CASE configuration->>'type'
   WHEN 'screen_lock' THEN
    IF NOT license_company_exact(payload,ARRAY['minutes','requirePassword']) OR jsonb_typeof(payload->'minutes') IS DISTINCT FROM 'number'
     OR (payload->>'minutes')::numeric<>trunc((payload->>'minutes')::numeric) OR (payload->>'minutes')::numeric NOT BETWEEN 1 AND 1440
     OR jsonb_typeof(payload->'requirePassword') IS DISTINCT FROM 'boolean' THEN RETURN false;END IF;
   WHEN 'filevault' THEN
    IF NOT license_company_exact(payload,ARRAY['enabled']) OR jsonb_typeof(payload->'enabled') IS DISTINCT FROM 'boolean' THEN RETURN false;END IF;
   WHEN 'software_update' THEN
    IF NOT license_company_exact(payload,ARRAY['automatic','deferralDays']) OR jsonb_typeof(payload->'automatic') IS DISTINCT FROM 'boolean'
     OR jsonb_typeof(payload->'deferralDays') IS DISTINCT FROM 'number' OR (payload->>'deferralDays')::numeric<>trunc((payload->>'deferralDays')::numeric)
     OR (payload->>'deferralDays')::numeric NOT BETWEEN 0 AND 365 THEN RETURN false;END IF;
  END CASE;
 END LOOP;
 seen='{}';
 FOR application IN SELECT value FROM jsonb_array_elements(document->'appPoolIds') LOOP
  IF jsonb_typeof(application) IS DISTINCT FROM 'string' OR NOT license_company_uuid(application#>>'{}') OR application#>>'{}'=ANY(seen) THEN RETURN false;END IF;
  seen=array_append(seen,application#>>'{}');
 END LOOP;RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_document(document JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_set(document,'{configurations}',COALESCE((SELECT jsonb_agg(jsonb_set(configuration,'{payloadJson}',to_jsonb(((configuration->>'payloadJson')::jsonb)::text)) ORDER BY ordinal)
 FROM jsonb_array_elements(document->'configurations') WITH ORDINALITY configurations(configuration,ordinal)),'[]'::jsonb));
$$;
CREATE OR REPLACE FUNCTION company_blueprint_source_valid(source JSONB,live BOOLEAN DEFAULT true) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
DECLARE field TEXT;
BEGIN
 IF NOT license_company_exact(source,ARRAY['schemaVersion','companyBlueprintProtocol','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil'])
  OR source->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR source->'companyBlueprintProtocol' IS DISTINCT FROM '1'::jsonb
  OR source->'permissions' IS DISTINCT FROM '["company.blueprints.read","company.blueprints.manage","company.blueprints.publish"]'::jsonb
  OR NOT license_company_exact(source->'context',ARRAY['userId','revision','linkRevision','rolesRevision'])
  OR NOT license_company_exact(source->'tenant',ARRAY['id','version','generation']) OR NOT license_company_uuid(source->>'actorUserId')
  OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId' OR NOT license_company_uuid(source#>>'{tenant,id}')
  OR NOT license_company_revision_valid(source#>'{context,revision}') OR NOT license_company_revision_valid(source#>'{context,linkRevision}')
  OR NOT license_company_revision_valid(source#>'{tenant,version}') OR NOT license_company_revision_valid(source#>'{tenant,generation}')
  OR NOT COALESCE(source#>>'{context,rolesRevision}' ~ '^[a-f0-9]{64}$',false) THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['issuer','subject','tokenId'] LOOP
  IF NOT company_blueprint_text(source->field,1,CASE WHEN field='issuer' THEN 2048 ELSE 255 END) THEN RETURN false;END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['expiresAt','validUntil'] LOOP
  IF jsonb_typeof(source->field) IS DISTINCT FROM 'number' OR NOT COALESCE(source->>field ~ '^[0-9]{1,12}$',false) THEN RETURN false;END IF;
 END LOOP;
 RETURN (source->>'validUntil')::numeric<=(source->>'expiresAt')::numeric AND (NOT live OR
  (source->>'validUntil')::numeric>extract(epoch FROM company_blueprint_now()) AND (source->>'validUntil')::numeric<=extract(epoch FROM company_blueprint_now())+300);
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_app_source_valid(source JSONB,application_source JSONB,live BOOLEAN DEFAULT true) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE(license_company_exact(application_source,ARRAY['schemaVersion','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','target'])
 AND application_source->'target'='null'::jsonb AND application_source->'permissions'='["company.apps.read","company.apps.create","company.apps.assign"]'::jsonb
 AND (application_source-'target'-'permissions'-'validUntil')=(source-'companyBlueprintProtocol'-'permissions'-'validUntil')
 AND jsonb_typeof(application_source->'validUntil')='number' AND application_source->>'validUntil' ~ '^[0-9]{1,12}$'
 AND (application_source->>'validUntil')::numeric<=(source->>'expiresAt')::numeric AND (NOT live OR
 (application_source->>'validUntil')::numeric>extract(epoch FROM company_blueprint_now()) AND (application_source->>'validUntil')::numeric<=extract(epoch FROM company_blueprint_now())+300),false);
$$;
CREATE OR REPLACE FUNCTION company_blueprint_command_valid(command JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
 IF NOT license_company_exact(command,ARRAY['id','correlationId','blueprintId','action','expectedRevision','reason','draft','version'])
  OR NOT license_company_uuid(command->>'id') OR NOT license_company_uuid(command->>'correlationId') OR NOT license_company_uuid(command->>'blueprintId')
  OR NOT company_blueprint_text(command->'reason',10,500)
  OR NOT COALESCE(command->>'action' IN('created','updated','published','restored'),false) THEN RETURN false;END IF;
 IF command->>'action'='created' THEN
  RETURN command->'expectedRevision'='"0"'::jsonb AND command->'version'='null'::jsonb AND company_blueprint_draft_valid(command->'draft');
 END IF;
 IF NOT license_company_revision_valid(command->'expectedRevision') THEN RETURN false;END IF;
 IF command->>'action'='updated' THEN RETURN command->'version'='null'::jsonb AND company_blueprint_draft_valid(command->'draft');END IF;
 IF command->'draft' IS DISTINCT FROM 'null'::jsonb THEN RETURN false;END IF;
 IF command->>'action'='published' THEN RETURN command->'version'='null'::jsonb;END IF;
 RETURN COALESCE(jsonb_typeof(command->'version')='number' AND command->>'version' ~ '^[1-9][0-9]{0,9}$' AND (command->>'version')::numeric<=2147483647,false);
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_state(head company_blueprints) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_object('id',head.id,'tenantId',head.tenant_id,'revision',head.revision::text,'publishedVersion',head.published_version,'draft',head.draft,
 'createdAt',to_char(head.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'updatedAt',to_char(head.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
$$;
CREATE OR REPLACE FUNCTION company_blueprint_release(release company_blueprint_versions) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_object('version',release.version,'sourceRevision',release.source_revision::text,'publishedRevision',release.published_revision::text,
 'actorUserId',release.actor_user_id,'operationId',release.operation_id,'createdAt',to_char(release.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'draft',release.draft,'apps',release.apps);
$$;
CREATE OR REPLACE FUNCTION company_blueprint_event(receipt company_blueprint_operations) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_object('id',receipt.id,'tenant_id',receipt.tenant_id,'blueprint_id',receipt.blueprint_id,'type',CASE receipt.command->>'action'
 WHEN 'created' THEN 'blueprint.created' WHEN 'updated' THEN 'blueprint.draft.updated' WHEN 'published' THEN 'blueprint.published' ELSE 'blueprint.draft.restored' END,
 'version',1,'actor_user_id',receipt.actor_user_id,'correlation_id',receipt.command->>'correlationId','created_at',receipt.created_at,
 'before_revision',CASE WHEN receipt.before_state IS NULL THEN NULL ELSE (receipt.before_state->>'revision')::bigint END,
 'after_revision',(receipt.after_state->>'revision')::bigint,'released_version',CASE WHEN receipt.command->>'action'='published' THEN (receipt.after_state->>'publishedVersion')::integer ELSE NULL END,
 'restored_from',receipt.command->'version','reason',receipt.command->>'reason');
$$;
CREATE OR REPLACE FUNCTION company_blueprint_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt company_blueprint_operations;actual JSONB;
BEGIN
 IF TG_OP='TRUNCATE' THEN RAISE EXCEPTION 'Company blueprint history is retained' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' OR TG_OP='UPDATE' AND TG_TABLE_NAME<>'company_blueprints' THEN RAISE EXCEPTION 'Immutable company blueprint evidence' USING ERRCODE='42501';END IF;
 SELECT * INTO receipt FROM company_blueprint_operations WHERE id=NULLIF(current_setting('opendirectory.company_blueprint',true),'')::uuid AND transaction_id=txid_current();
 IF TG_TABLE_NAME='company_blueprint_operations' AND TG_OP='INSERT' THEN receipt=NEW;END IF;
 IF receipt.id IS NULL OR receipt.id::text IS DISTINCT FROM NULLIF(current_setting('opendirectory.company_blueprint',true),'')
  OR receipt.transaction_id<>txid_current() OR receipt.valid_until<=company_blueprint_now() OR NOT company_blueprint_source_valid(receipt.source)
  OR NOT company_blueprint_command_valid(receipt.command) OR session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='company_blueprints'::regclass)
  OR current_setting('role',true) NOT IN('none','') OR current_setting('session_replication_role')<>'origin'
  OR jsonb_array_length(receipt.after_state#>'{draft,appPoolIds}')>0 AND NOT company_blueprint_app_source_valid(receipt.source,receipt.application_source)
  THEN RAISE EXCEPTION 'Original company blueprint admission required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='company_blueprints' THEN
  IF TG_OP='UPDATE' AND company_blueprint_state(OLD) IS DISTINCT FROM receipt.before_state OR company_blueprint_state(NEW) IS DISTINCT FROM receipt.after_state
   OR TG_OP='INSERT' AND receipt.before_state IS NOT NULL THEN RAISE EXCEPTION 'Blueprint head differs from original intent' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='company_blueprint_versions' THEN
  IF company_blueprint_release(NEW) IS DISTINCT FROM receipt.version_state OR NEW.blueprint_id<>receipt.blueprint_id OR NEW.tenant_id<>receipt.tenant_id THEN RAISE EXCEPTION 'Release differs from original intent' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='company_blueprint_events' THEN
  IF to_jsonb(NEW) IS DISTINCT FROM company_blueprint_event(receipt) THEN RAISE EXCEPTION 'Event differs from original intent' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='company_blueprint_outbox' THEN
  IF NEW.id<>receipt.id OR NEW.tenant_id<>receipt.tenant_id OR NEW.status<>'pending' OR NEW.created_at<>receipt.created_at THEN RAISE EXCEPTION 'Outbox differs from original intent' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_evidence_valid(receipt company_blueprint_operations) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
DECLARE event company_blueprint_events;release company_blueprint_versions;previous company_blueprint_operations;application JSONB;application_ids JSONB='[]';
BEGIN
 IF NOT company_blueprint_source_valid(receipt.source,false) OR NOT company_blueprint_command_valid(receipt.command)
  OR receipt.id::text IS DISTINCT FROM receipt.command->>'id' OR receipt.blueprint_id::text IS DISTINCT FROM receipt.command->>'blueprintId'
  OR receipt.tenant_id::text IS DISTINCT FROM receipt.source#>>'{tenant,id}' OR receipt.actor_user_id::text IS DISTINCT FROM receipt.source->>'actorUserId'
  OR receipt.issuer IS DISTINCT FROM receipt.source->>'issuer' OR receipt.subject IS DISTINCT FROM receipt.source->>'subject'
  OR receipt.valid_until IS DISTINCT FROM to_timestamp(LEAST((receipt.source->>'validUntil')::bigint,COALESCE((receipt.application_source->>'validUntil')::bigint,(receipt.source->>'validUntil')::bigint)))
  OR NOT license_company_exact(receipt.after_state,ARRAY['id','tenantId','revision','publishedVersion','draft','createdAt','updatedAt'])
  OR NOT company_blueprint_draft_valid(receipt.after_state->'draft') OR receipt.after_state->>'id' IS DISTINCT FROM receipt.blueprint_id::text
  OR receipt.after_state->>'tenantId' IS DISTINCT FROM receipt.tenant_id::text
  OR receipt.after_state->>'revision' IS DISTINCT FROM ((receipt.command->>'expectedRevision')::bigint+1)::text
  OR receipt.after_state->>'updatedAt' IS DISTINCT FROM to_char(receipt.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  OR receipt.valid_until<=receipt.created_at OR (receipt.after_state->>'createdAt')::timestamptz>receipt.created_at
  OR jsonb_array_length(receipt.after_state#>'{draft,appPoolIds}')=0 AND receipt.application_source IS NOT NULL
  OR jsonb_array_length(receipt.after_state#>'{draft,appPoolIds}')>0 AND NOT company_blueprint_app_source_valid(receipt.source,receipt.application_source,false) THEN RETURN false;END IF;
 IF receipt.command->>'action'='created' THEN
  IF receipt.before_state IS NOT NULL OR receipt.after_state->'publishedVersion'<>'null'::jsonb OR receipt.after_state->'draft' IS DISTINCT FROM company_blueprint_document(receipt.command->'draft')
   OR receipt.after_state->'createdAt' IS DISTINCT FROM receipt.after_state->'updatedAt' THEN RETURN false;END IF;
 ELSE
  SELECT * INTO previous FROM company_blueprint_operations WHERE blueprint_id=receipt.blueprint_id AND after_state->>'revision'=receipt.command->>'expectedRevision';
  IF previous.id IS NULL OR receipt.before_state IS DISTINCT FROM previous.after_state OR receipt.before_state->>'createdAt' IS DISTINCT FROM receipt.after_state->>'createdAt' THEN RETURN false;END IF;
  IF receipt.command->>'action'='updated' AND (receipt.after_state->'draft' IS DISTINCT FROM company_blueprint_document(receipt.command->'draft') OR receipt.before_state->'draft'=receipt.after_state->'draft') THEN RETURN false;END IF;
  IF receipt.command->>'action'='restored' THEN
   SELECT * INTO release FROM company_blueprint_versions WHERE blueprint_id=receipt.blueprint_id AND version=(receipt.command->>'version')::integer;
   IF release.operation_id IS NULL OR receipt.after_state->'draft' IS DISTINCT FROM release.draft OR receipt.before_state->'draft'=receipt.after_state->'draft' THEN RETURN false;END IF;
  END IF;
  IF receipt.command->>'action'<>'published' AND receipt.after_state->'publishedVersion' IS DISTINCT FROM receipt.before_state->'publishedVersion' THEN RETURN false;END IF;
 END IF;
 IF receipt.command->>'action'='published' THEN
  SELECT * INTO release FROM company_blueprint_versions WHERE operation_id=receipt.id;
  IF release.operation_id IS NULL OR release.blueprint_id<>receipt.blueprint_id OR release.tenant_id<>receipt.tenant_id OR company_blueprint_release(release) IS DISTINCT FROM receipt.version_state
   OR release.draft IS DISTINCT FROM receipt.after_state->'draft' OR receipt.after_state->'draft' IS DISTINCT FROM receipt.before_state->'draft'
   OR release.version<>COALESCE((receipt.before_state->>'publishedVersion')::integer,0)+1 OR release.version<>(receipt.after_state->>'publishedVersion')::integer
   OR release.source_revision<>(receipt.command->>'expectedRevision')::bigint OR release.published_revision<>(receipt.after_state->>'revision')::bigint
   OR release.actor_user_id<>receipt.actor_user_id OR release.created_at<>receipt.created_at THEN RETURN false;END IF;
  IF jsonb_typeof(release.apps) IS DISTINCT FROM 'array' OR jsonb_array_length(release.draft->'configurations')+jsonb_array_length(release.draft->'appPoolIds')=0
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(release.draft->'configurations') configuration GROUP BY configuration->>'type' HAVING count(DISTINCT (configuration->>'payloadJson')::jsonb)>1)
   OR EXISTS(SELECT 1 FROM company_blueprint_versions latest WHERE latest.blueprint_id=receipt.blueprint_id AND latest.version=(receipt.before_state->>'publishedVersion')::integer AND latest.draft=release.draft) THEN RETURN false;END IF;
  FOR application IN SELECT value FROM jsonb_array_elements(release.apps) LOOP
   IF NOT license_company_exact(application,ARRAY['id','name','vendor','revision']) OR NOT license_company_uuid(application->>'id') OR NOT license_company_revision_valid(application->'revision')
    OR NOT company_blueprint_text(application->'name',1,160) OR NOT company_blueprint_text(application->'vendor',1,160) THEN RETURN false;END IF;
   application_ids=application_ids||jsonb_build_array(application->'id');
  END LOOP;
  IF application_ids IS DISTINCT FROM release.draft->'appPoolIds' THEN RETURN false;END IF;
 ELSE
  IF receipt.version_state IS NOT NULL OR EXISTS(SELECT 1 FROM company_blueprint_versions WHERE operation_id=receipt.id) THEN RETURN false;END IF;
 END IF;
 SELECT * INTO event FROM company_blueprint_events WHERE id=receipt.id;
 RETURN event.id IS NOT NULL AND to_jsonb(event)=company_blueprint_event(receipt)
  AND EXISTS(SELECT 1 FROM company_blueprint_outbox WHERE id=receipt.id AND tenant_id=receipt.tenant_id AND status='pending' AND created_at=receipt.created_at);
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;specification RECORD;
BEGIN
 IF current_setting('session_replication_role')<>'origin' OR NOT EXISTS(SELECT 1 FROM license_schema_versions WHERE version=25) THEN RAISE EXCEPTION 'Company blueprint receiver unavailable' USING ERRCODE='42501';END IF;
 FOR specification IN SELECT * FROM(VALUES
  ('license_company_exact(jsonb,text[])','0bdd7bf5d38af27f190c2b35f878a34f',false),
  ('license_company_uuid(text)','d677a2e93ed09bd539e568b95531daac',false),
  ('license_company_revision_valid(jsonb,boolean)','eb58e561ab7d128db5755b5ce06535e1',false),
  ('company_blueprint_text(jsonb,integer,integer)','3ddce7da2077ad8a921911e916fe2e04',false),
  ('company_blueprint_draft_valid(jsonb)','517e4448f877aea109d9992f60e2a326',false),
  ('company_blueprint_document(jsonb)','35cfc99fa49f0e60cb450532d3c7be7f',false),
  ('company_blueprint_source_valid(jsonb,boolean)','643b184e2abb6ec7ec9c60238294d742',false),
  ('company_blueprint_app_source_valid(jsonb,jsonb,boolean)','3f9178427db0b76a2f448133582fe4e6',false),
  ('company_blueprint_command_valid(jsonb)','1c38399768b443b8735a055bb3be124a',false),
  ('company_blueprint_state(company_blueprints)','cb5a6f05c09a66b171e173f44cc9fcc7',false),
  ('company_blueprint_release(company_blueprint_versions)','d8ff727bd72a2bf8f3d7bdf76e24ca1e',false),
  ('company_blueprint_event(company_blueprint_operations)','e5980567ba5ecaed3b758c80026114ba',false),
  ('company_blueprint_guard()','8f697ba88b18b2fa312bbb6bb7a1e509',true),
  ('company_blueprint_evidence_valid(company_blueprint_operations)','501d60e82f2cf01c848ffc91885e6294',false),
  ('company_blueprint_commit()','1f5ea6f3ebd5d5112dd0b4bf8d9a1d98',true),
  ('company_blueprint_change(jsonb,jsonb,jsonb)','0cb8e9e33afcfb1e45bdd61029de8627',true)
 ) routines(signature,digest,definer) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid=to_regprocedure(specification.signature) AND md5(prosrc)=specification.digest AND prosecdef=specification.definer
   AND proowner=(SELECT relowner FROM pg_class WHERE oid='company_blueprints'::regclass)) THEN RAISE EXCEPTION 'Original company blueprint receiver changed: %',specification.signature USING ERRCODE='42501';END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['company_blueprints','company_blueprint_operations','company_blueprint_versions','company_blueprint_events','company_blueprint_outbox'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=to_regclass(relation) AND relkind='r' AND relowner=(SELECT relowner FROM pg_class WHERE oid='company_blueprints'::regclass))
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname=relation||'_guard' AND tgenabled='O' AND tgtype=31 AND tgqual IS NULL AND tgnargs=0 AND tgfoid='company_blueprint_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname=relation||'_truncate' AND tgenabled='O' AND tgtype=34 AND tgqual IS NULL AND tgnargs=0 AND tgfoid='company_blueprint_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname=relation||'_commit' AND tgenabled='O' AND tgtype=29 AND tgqual IS NULL AND tgnargs=0 AND tgdeferrable AND tginitdeferred AND tgfoid='company_blueprint_commit()'::regprocedure)
   THEN RAISE EXCEPTION 'Company blueprint guard unavailable: %',relation USING ERRCODE='42501';END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM company_blueprint_operations receipt WHERE NOT company_blueprint_evidence_valid(receipt))
  OR EXISTS(SELECT 1 FROM company_blueprints head WHERE NOT EXISTS(SELECT 1 FROM company_blueprint_operations receipt WHERE receipt.blueprint_id=head.id AND receipt.tenant_id=head.tenant_id
   AND receipt.after_state=company_blueprint_state(head) AND NOT EXISTS(SELECT 1 FROM company_blueprint_operations later WHERE later.blueprint_id=head.id AND (later.after_state->>'revision')::bigint>head.revision)))
  OR EXISTS(SELECT 1 FROM company_blueprint_versions release WHERE NOT EXISTS(SELECT 1 FROM company_blueprint_operations receipt WHERE receipt.id=release.operation_id AND receipt.version_state=company_blueprint_release(release)))
  OR EXISTS(SELECT 1 FROM company_blueprint_events event WHERE NOT EXISTS(SELECT 1 FROM company_blueprint_operations receipt WHERE receipt.id=event.id))
  OR EXISTS(SELECT 1 FROM company_blueprint_outbox outbox WHERE NOT EXISTS(SELECT 1 FROM company_blueprint_events event WHERE event.id=outbox.id))
  THEN RAISE EXCEPTION 'Complete company blueprint history required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt company_blueprint_operations;application JSONB;catalog license_catalog;
BEGIN
 SELECT * INTO receipt FROM company_blueprint_operations WHERE id=NULLIF(current_setting('opendirectory.company_blueprint',true),'')::uuid AND transaction_id=txid_current();
 IF receipt.id IS NULL OR receipt.valid_until<=company_blueprint_now() OR NOT company_blueprint_source_valid(receipt.source)
  OR jsonb_array_length(receipt.after_state#>'{draft,appPoolIds}')>0 AND NOT company_blueprint_app_source_valid(receipt.source,receipt.application_source)
  THEN RAISE EXCEPTION 'Company blueprint authority expired before commit' USING ERRCODE='42501';END IF;
 IF jsonb_array_length(receipt.after_state#>'{draft,appPoolIds}')>0 THEN
  PERFORM license_company_edit_receiving();
  FOR application IN SELECT value FROM jsonb_array_elements(receipt.after_state#>'{draft,appPoolIds}') LOOP
   SELECT * INTO catalog FROM license_catalog WHERE id=(application#>>'{}')::uuid AND business_tenant_id=receipt.tenant_id;
   IF catalog.id IS NULL OR NOT license_company_pool_valid(catalog.id) OR catalog.license_type<>'per_user' OR catalog.total_seats NOT BETWEEN 1 AND 10000
    THEN RAISE EXCEPTION 'Original app pool evidence lost before commit' USING ERRCODE='42501';END IF;
   IF receipt.version_state IS NOT NULL AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(receipt.version_state->'apps') snapshot
    WHERE snapshot=jsonb_build_object('id',catalog.id,'name',catalog.name,'vendor',catalog.vendor,'revision',catalog.business_revision::text))
    THEN RAISE EXCEPTION 'Original app metadata snapshot lost before commit' USING ERRCODE='42501';END IF;
  END LOOP;
 END IF;
 PERFORM company_blueprint_receiving();RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION company_blueprint_change(source JSONB,application_source JSONB,command JSONB) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
#variable_conflict use_variable
DECLARE head company_blueprints;receipt company_blueprint_operations;prior company_blueprint_operations;release company_blueprint_versions;document JSONB;apps JSONB='[]';application JSONB;catalog license_catalog;stamp TIMESTAMPTZ;state_before JSONB;ordinal INTEGER;
BEGIN
 PERFORM company_blueprint_receiving();
 IF NOT company_blueprint_source_valid(source) OR NOT company_blueprint_command_valid(command) OR current_setting('role',true) NOT IN('none','')
  OR session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='company_blueprints'::regclass)
  OR NULLIF(current_setting('opendirectory.company_blueprint',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Original company blueprint source required' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(command->>'id',0));
 SELECT * INTO prior FROM company_blueprint_operations WHERE id=(command->>'id')::uuid;
 IF prior.id IS NOT NULL THEN
  IF prior.tenant_id::text IS DISTINCT FROM source#>>'{tenant,id}' OR prior.actor_user_id::text IS DISTINCT FROM source->>'actorUserId' OR prior.issuer IS DISTINCT FROM source->>'issuer' OR prior.subject IS DISTINCT FROM source->>'subject'
   OR prior.command-'correlationId' IS DISTINCT FROM command-'correlationId' THEN RAISE EXCEPTION 'Blueprint operation intent mismatch' USING ERRCODE='23505';END IF;
  RETURN jsonb_build_object('schemaVersion',1,'actorUserId',prior.actor_user_id,'tenantId',prior.tenant_id,'operationId',prior.id,'blueprintId',prior.blueprint_id,'revision',prior.after_state->>'revision',
   'publishedVersion',prior.after_state->'publishedVersion','action',prior.command->>'action','outcome','already_applied','deliveryStatus','pending');
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(command->>'blueprintId',1));
 SELECT * INTO head FROM company_blueprints WHERE id=(command->>'blueprintId')::uuid AND tenant_id=(source#>>'{tenant,id}')::uuid FOR UPDATE;
 IF command->>'action'='created' THEN
  IF head.id IS NOT NULL OR EXISTS(SELECT 1 FROM company_blueprints WHERE id=(command->>'blueprintId')::uuid) THEN RAISE EXCEPTION 'Blueprint identifier unavailable' USING ERRCODE='23505';END IF;
 ELSE
  IF head.id IS NULL THEN RAISE EXCEPTION 'Own company blueprint not found' USING ERRCODE='P0002';END IF;
  IF head.revision::text IS DISTINCT FROM command->>'expectedRevision' THEN RAISE EXCEPTION 'Company blueprint revision changed' USING ERRCODE='40001';END IF;
  state_before=company_blueprint_state(head);
 END IF;
 document=CASE WHEN command->>'action' IN('created','updated') THEN company_blueprint_document(command->'draft') ELSE head.draft END;
 IF command->>'action'='restored' THEN
  SELECT * INTO release FROM company_blueprint_versions WHERE blueprint_id=head.id AND tenant_id=head.tenant_id AND version=(command->>'version')::integer;
  IF release.operation_id IS NULL THEN RAISE EXCEPTION 'Own blueprint version not found' USING ERRCODE='P0002';END IF;document=release.draft;
 END IF;
 IF command->>'action' IN('updated','restored') AND document=head.draft THEN RAISE EXCEPTION 'Blueprint draft has no changes' USING ERRCODE='23514';END IF;
 IF jsonb_array_length(document->'appPoolIds')>0 THEN
  IF NOT company_blueprint_app_source_valid(source,application_source) THEN RAISE EXCEPTION 'Independent original app authority required' USING ERRCODE='42501';END IF;
  PERFORM license_company_edit_receiving();
  FOR application IN SELECT value FROM jsonb_array_elements(document->'appPoolIds') LOOP
   SELECT * INTO catalog FROM license_catalog WHERE id=(application#>>'{}')::uuid AND business_tenant_id=(source#>>'{tenant,id}')::uuid FOR SHARE;
   IF catalog.id IS NULL THEN RAISE EXCEPTION 'Own company app pool not found' USING ERRCODE='P0002';END IF;
   IF NOT license_company_pool_valid(catalog.id) OR catalog.license_type<>'per_user' OR catalog.total_seats NOT BETWEEN 1 AND 10000 OR catalog.business_revision IS NULL THEN RAISE EXCEPTION 'Own finite company pool evidence unavailable' USING ERRCODE='42501';END IF;
   apps=apps||jsonb_build_array(jsonb_build_object('id',catalog.id,'name',catalog.name,'vendor',catalog.vendor,'revision',catalog.business_revision::text));
  END LOOP;
 ELSIF application_source IS NOT NULL THEN RAISE EXCEPTION 'Unexpected app authority' USING ERRCODE='42501';END IF;
 IF command->>'action'='published' THEN
  IF jsonb_array_length(document->'configurations')=0 AND jsonb_array_length(document->'appPoolIds')=0 THEN RAISE EXCEPTION 'company_blueprint_empty' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(document->'configurations') configuration GROUP BY configuration->>'type' HAVING count(DISTINCT (configuration->>'payloadJson')::jsonb)>1)
   THEN RAISE EXCEPTION 'Blueprint configuration conflict' USING ERRCODE='23514';END IF;
  IF head.published_version IS NOT NULL AND document=(SELECT draft FROM company_blueprint_versions WHERE blueprint_id=head.id AND version=head.published_version)
   THEN RAISE EXCEPTION 'No changes since latest published version' USING ERRCODE='23514';END IF;
  ordinal=COALESCE(head.published_version,0)+1;
 END IF;
 stamp=company_blueprint_now();
 IF command->>'action'='created' THEN head.id=(command->>'blueprintId')::uuid;head.tenant_id=(source#>>'{tenant,id}')::uuid;head.revision=1;head.published_version=NULL;head.created_at=stamp;
 ELSE head.revision=head.revision+1;END IF;
 head.draft=document;head.updated_at=stamp;IF ordinal IS NOT NULL THEN head.published_version=ordinal;END IF;
 receipt.id=(command->>'id')::uuid;receipt.blueprint_id=head.id;receipt.tenant_id=head.tenant_id;receipt.actor_user_id=(source->>'actorUserId')::uuid;receipt.issuer=source->>'issuer';receipt.subject=source->>'subject';
 receipt.command=command;receipt.source=source;receipt.application_source=application_source;receipt.before_state=state_before;receipt.after_state=company_blueprint_state(head);receipt.created_at=stamp;
 receipt.valid_until=to_timestamp(LEAST((source->>'validUntil')::bigint,COALESCE((application_source->>'validUntil')::bigint,(source->>'validUntil')::bigint)));receipt.transaction_id=txid_current();
 IF ordinal IS NOT NULL THEN
  release.blueprint_id=head.id;release.tenant_id=head.tenant_id;release.version=ordinal;release.source_revision=(command->>'expectedRevision')::bigint;release.published_revision=head.revision;
  release.actor_user_id=receipt.actor_user_id;release.operation_id=receipt.id;release.created_at=stamp;release.draft=document;release.apps=apps;receipt.version_state=company_blueprint_release(release);
 END IF;
 PERFORM set_config('opendirectory.company_blueprint',receipt.id::text,true);
 INSERT INTO company_blueprint_operations SELECT receipt.*;
 IF command->>'action'='created' THEN INSERT INTO company_blueprints SELECT head.*;
 ELSE UPDATE company_blueprints SET revision=head.revision,published_version=head.published_version,draft=head.draft,updated_at=head.updated_at WHERE id=head.id;END IF;
 IF ordinal IS NOT NULL THEN INSERT INTO company_blueprint_versions SELECT release.*;END IF;
 INSERT INTO company_blueprint_events SELECT * FROM jsonb_populate_record(NULL::company_blueprint_events,company_blueprint_event(receipt));
 INSERT INTO company_blueprint_outbox VALUES(receipt.id,receipt.tenant_id,'pending',stamp);
 RETURN jsonb_build_object('schemaVersion',1,'actorUserId',receipt.actor_user_id,'tenantId',receipt.tenant_id,'operationId',receipt.id,'blueprintId',head.id,'revision',head.revision::text,
 'publishedVersion',head.published_version,'action',command->>'action','outcome','applied','deliveryStatus','pending');
END; $$;
DO $$ DECLARE relation TEXT;routine RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['company_blueprints','company_blueprint_operations','company_blueprint_versions','company_blueprint_events','company_blueprint_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',relation||'_guard',relation);
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION company_blueprint_guard()',relation||'_guard',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',relation||'_truncate',relation);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION company_blueprint_guard()',relation||'_truncate',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',relation||'_commit',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_blueprint_commit()',relation||'_commit',relation);
 END LOOP;
 FOR routine IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname LIKE 'company_blueprint_%' LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine.signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine.signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
 END LOOP;
END; $$;
INSERT INTO license_schema_versions(version) VALUES(25) ON CONFLICT DO NOTHING;
