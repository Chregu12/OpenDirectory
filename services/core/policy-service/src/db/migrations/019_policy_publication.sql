CREATE TABLE IF NOT EXISTS policy_publication_heads (
 resource_kind TEXT NOT NULL CHECK(resource_kind IN('policy','blueprint')),resource_id UUID NOT NULL,
 configuration_version INTEGER NOT NULL CHECK(configuration_version>0),verified_origin BOOLEAN NOT NULL,
 PRIMARY KEY(resource_kind,resource_id)
);
INSERT INTO policy_publication_heads(resource_kind,resource_id,configuration_version,verified_origin)
 SELECT origin.resource_kind,origin.resource_id,resource.version,origin.origin='created' AND EXISTS(
  SELECT 1 FROM policy_configuration_audit audit WHERE audit.resource_kind=origin.resource_kind AND audit.resource_id=origin.resource_id AND audit.action='created')
 FROM policy_configuration_origins origin JOIN (SELECT 'policy' AS kind,id,version FROM policies UNION ALL SELECT 'blueprint',id,version FROM blueprints) resource
 ON resource.kind=origin.resource_kind AND resource.id=origin.resource_id
 WHERE NOT EXISTS(SELECT 1 FROM policy_publication_heads head WHERE head.resource_kind=origin.resource_kind AND head.resource_id=origin.resource_id);

CREATE TABLE IF NOT EXISTS policy_publications (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),resource_kind TEXT NOT NULL,resource_id UUID NOT NULL,
 resource_version INTEGER NOT NULL CHECK(resource_version>0),configuration_version INTEGER NOT NULL CHECK(configuration_version>0),
 configuration_hash TEXT NOT NULL CHECK(configuration_hash ~ '^[a-f0-9]{64}$'),issuer TEXT NOT NULL,
 requested_by UUID NOT NULL,reviewer_user_id UUID NOT NULL CHECK(reviewer_user_id<>requested_by),
 requester_revision TEXT NOT NULL CHECK(requester_revision ~ '^[a-f0-9]{64}$'),reviewer_revision TEXT NOT NULL CHECK(reviewer_revision ~ '^[a-f0-9]{64}$'),
 validity_seconds INTEGER NOT NULL CHECK(validity_seconds BETWEEN 300 AND 28800),
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','approved','denied','withdrawn')),version INTEGER NOT NULL DEFAULT 1 CHECK(version>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT policy_configuration_now(),expires_at TIMESTAMPTZ NOT NULL,
 decided_by UUID,decided_at TIMESTAMPTZ,FOREIGN KEY(resource_kind,resource_id) REFERENCES policy_publication_heads(resource_kind,resource_id)
);
CREATE INDEX IF NOT EXISTS policy_publications_resource ON policy_publications(resource_kind,resource_id,created_at DESC,id);
CREATE TABLE IF NOT EXISTS policy_publication_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),publication_id UUID NOT NULL REFERENCES policy_publications(id),version INTEGER NOT NULL,action TEXT NOT NULL,
 resource_kind TEXT NOT NULL,resource_id UUID NOT NULL,configuration_version INTEGER NOT NULL,configuration_hash TEXT NOT NULL,
 actor JSONB NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),previous_state TEXT,current_state TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT policy_configuration_now(),UNIQUE(publication_id,version)
);
CREATE TABLE IF NOT EXISTS policy_publication_outbox (
 id UUID PRIMARY KEY REFERENCES policy_publication_audit(id),publication_id UUID NOT NULL,version INTEGER NOT NULL,action TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT policy_configuration_now(),UNIQUE(publication_id,version)
);

CREATE OR REPLACE FUNCTION policy_publication_frame(kind TEXT,identity UUID) RETURNS JSONB LANGUAGE plpgsql STABLE AS $$
DECLARE resource JSONB;targets JSONB;children JSONB;head policy_publication_heads%ROWTYPE;total_bytes BIGINT;total_rows BIGINT;
BEGIN
 IF kind='policy' THEN SELECT to_jsonb(policy) INTO resource FROM policies policy WHERE id=identity;
 ELSIF kind='blueprint' THEN SELECT to_jsonb(blueprint) INTO resource FROM blueprints blueprint WHERE id=identity;
 ELSE RAISE EXCEPTION 'Canonical publication resource required' USING ERRCODE='23514';END IF;
 IF resource IS NULL THEN RETURN NULL;END IF;
 SELECT * INTO head FROM policy_publication_heads WHERE resource_kind=kind AND resource_id=identity;
 IF head.resource_id IS NULL THEN RAISE EXCEPTION 'Publication lineage unavailable' USING ERRCODE='23514';END IF;
 IF kind='policy' THEN
  SELECT count(*),COALESCE(sum(octet_length(to_jsonb(assignment)::text)),0) INTO total_rows,total_bytes FROM policy_assignments assignment WHERE policy_id=identity;
  SELECT total_rows+count(*),total_bytes+COALESCE(sum(octet_length(to_jsonb(link)::text)),0) INTO total_rows,total_bytes FROM policy_links link WHERE policy_id=identity;
 ELSE
  SELECT count(*),COALESCE(sum(octet_length(to_jsonb(assignment)::text)),0) INTO total_rows,total_bytes FROM blueprint_assignments assignment WHERE blueprint_id=identity;
  SELECT total_rows+count(*),total_bytes+COALESCE(sum(octet_length(to_jsonb(configuration)::text)),0) INTO total_rows,total_bytes FROM blueprint_configurations configuration WHERE blueprint_id=identity;
 END IF;
 IF total_rows>2000 OR total_bytes+octet_length(resource::text)>2097152 THEN RAISE EXCEPTION 'Bounded publication frame required' USING ERRCODE='23514';END IF;
 IF kind='policy' THEN
  SELECT COALESCE(jsonb_agg(to_jsonb(assignment) ORDER BY assignment.id),'[]'::jsonb) INTO targets FROM policy_assignments assignment WHERE policy_id=identity;
  SELECT COALESCE(jsonb_agg(to_jsonb(link) ORDER BY link.id),'[]'::jsonb) INTO children FROM policy_links link WHERE policy_id=identity;
 ELSE
  SELECT COALESCE(jsonb_agg(to_jsonb(assignment) ORDER BY assignment.id),'[]'::jsonb) INTO targets FROM blueprint_assignments assignment WHERE blueprint_id=identity;
  SELECT COALESCE(jsonb_agg(to_jsonb(configuration) ORDER BY configuration.id),'[]'::jsonb) INTO children FROM blueprint_configurations configuration WHERE blueprint_id=identity;
 END IF;
 RETURN jsonb_build_object('resource',resource-ARRAY['version','created_at','updated_at','status','activated_at'],
  'configurationVersion',head.configuration_version,'assignments',targets,'children',children);
END; $$;
CREATE OR REPLACE FUNCTION policy_publication_hash(kind TEXT,identity UUID) RETURNS TEXT LANGUAGE sql STABLE AS $$
 SELECT encode(sha256(convert_to(policy_publication_frame(kind,identity)::text,'UTF8')),'hex');
$$;
CREATE OR REPLACE FUNCTION policy_publication_independent(kind TEXT,identity UUID,reviewer UUID) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT COALESCE((SELECT head.verified_origin FROM policy_publication_heads head WHERE head.resource_kind=kind AND head.resource_id=identity),false)
 AND NOT EXISTS(SELECT 1 FROM policy_configuration_audit audit WHERE audit.resource_kind=kind AND audit.resource_id=identity
  AND audit.action NOT IN('activated','deactivated','deleted') AND audit.actor->>'userId'=reviewer::text);
$$;
CREATE OR REPLACE FUNCTION policy_publication_usable(publication UUID,kind TEXT,identity UUID) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT EXISTS(SELECT 1 FROM policy_publications approval JOIN policy_publication_heads head USING(resource_kind,resource_id)
  WHERE approval.id=publication AND approval.resource_kind=kind AND approval.resource_id=identity AND approval.state='approved'
   AND approval.expires_at>policy_configuration_now() AND approval.configuration_version=head.configuration_version
   AND approval.configuration_hash=policy_publication_hash(kind,identity) AND policy_publication_independent(kind,identity,approval.reviewer_user_id));
$$;
CREATE OR REPLACE FUNCTION policy_publication_fresh(proof JSONB) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE(policy_configuration_fresh(proof||jsonb_build_object('permission','policies.manage','action','updated'))
 AND proof->>'permission' IN('policies.publication.request','policies.publication.review')
 AND proof->>'action' IN('requested','approved','denied','withdrawn'),false);
$$;
CREATE OR REPLACE FUNCTION policy_publication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;parent_version INTEGER;head policy_publication_heads%ROWTYPE;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_publication',true),'')::jsonb;
 IF NOT policy_publication_fresh(proof) OR TG_OP='DELETE' OR proof->>'resourceKind' IS DISTINCT FROM NEW.resource_kind
  OR proof->>'resourceId' IS DISTINCT FROM NEW.resource_id::text OR proof->'actor'->>'issuer' IS DISTINCT FROM NEW.issuer
  THEN RAISE EXCEPTION 'Original fresh publication authority required' USING ERRCODE='42501';END IF;
 IF NEW.resource_kind='policy' THEN SELECT version INTO parent_version FROM policies WHERE id=NEW.resource_id FOR UPDATE;
 ELSE SELECT version INTO parent_version FROM blueprints WHERE id=NEW.resource_id FOR UPDATE;END IF;
 IF parent_version IS NULL THEN RAISE EXCEPTION 'Current publication parent required' USING ERRCODE='23514';END IF;
 SELECT * INTO head FROM policy_publication_heads WHERE resource_kind=NEW.resource_kind AND resource_id=NEW.resource_id;
 IF TG_OP='INSERT' THEN
  IF proof->>'action'<>'requested' OR proof->>'permission'<>'policies.publication.request' OR proof->>'expectedVersion'<>'0'
   OR NEW.version<>1 OR NEW.state<>'pending' OR NEW.requested_by::text IS DISTINCT FROM proof->'actor'->>'userId'
   OR NEW.decided_by IS NOT NULL OR NEW.decided_at IS NOT NULL
   OR NEW.requester_revision IS DISTINCT FROM proof->>'requesterRevision' OR NEW.reviewer_revision IS DISTINCT FROM proof->>'reviewerRevision'
   OR EXISTS(SELECT 1 FROM policy_publications existing WHERE existing.resource_kind=NEW.resource_kind AND existing.resource_id=NEW.resource_id
    AND existing.configuration_version=head.configuration_version AND existing.state IN('pending','approved') AND existing.expires_at>policy_configuration_now())
   THEN RAISE EXCEPTION 'Exact independent publication request required' USING ERRCODE='23514';END IF;
  NEW.created_at=date_trunc('milliseconds',policy_configuration_now());NEW.expires_at=NEW.created_at+NEW.validity_seconds*interval '1 second';
 ELSE
  IF proof->>'publicationId' IS DISTINCT FROM OLD.id::text OR proof->>'expectedVersion' IS DISTINCT FROM OLD.version::text
   THEN RAISE EXCEPTION 'Exact publication version required' USING ERRCODE='23514',CONSTRAINT='policy_publication_version';END IF;
  IF (to_jsonb(NEW)-ARRAY['state','version','decided_by','decided_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','version','decided_by','decided_at'])
   OR OLD.version>=2147483647 OR NEW.state IS DISTINCT FROM proof->>'action' THEN RAISE EXCEPTION 'Publication origin is immutable' USING ERRCODE='23514';END IF;
  IF NEW.state='withdrawn' THEN
   IF OLD.state NOT IN('pending','approved') OR proof->'actor'->>'userId' NOT IN(OLD.requested_by::text,OLD.reviewer_user_id::text)
    OR proof->>'permission' IS DISTINCT FROM (CASE WHEN proof->'actor'->>'userId'=OLD.requested_by::text THEN 'policies.publication.request' ELSE 'policies.publication.review' END)
    THEN RAISE EXCEPTION 'Original publication withdrawal duty required' USING ERRCODE='42501';END IF;
  ELSIF NEW.state IN('approved','denied') THEN
   IF OLD.state<>'pending' OR proof->>'permission'<>'policies.publication.review' OR proof->'actor'->>'userId' IS DISTINCT FROM OLD.reviewer_user_id::text
    OR NEW.requester_revision IS DISTINCT FROM proof->>'requesterRevision' OR NEW.reviewer_revision IS DISTINCT FROM proof->>'reviewerRevision'
    OR OLD.expires_at<=policy_configuration_now() THEN RAISE EXCEPTION 'Current assigned publication reviewer required' USING ERRCODE='42501';END IF;
  ELSE RAISE EXCEPTION 'Terminal publication cannot be revived' USING ERRCODE='42501';END IF;
  NEW.version=OLD.version+1;NEW.decided_by=(proof->'actor'->>'userId')::uuid;NEW.decided_at=date_trunc('milliseconds',policy_configuration_now());
 END IF;
 IF NEW.state<>'withdrawn' AND (NEW.resource_version<>parent_version OR NEW.configuration_version<>head.configuration_version
  OR NEW.configuration_hash IS DISTINCT FROM policy_publication_hash(NEW.resource_kind,NEW.resource_id)
  OR NOT policy_publication_independent(NEW.resource_kind,NEW.resource_id,NEW.reviewer_user_id))
  THEN RAISE EXCEPTION 'Exact independently reviewed configuration required' USING ERRCODE='23514',CONSTRAINT='policy_publication_configuration';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_publication_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;event UUID;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_publication',true),'')::jsonb;
 INSERT INTO policy_publication_audit(publication_id,version,action,resource_kind,resource_id,configuration_version,configuration_hash,actor,reason,previous_state,current_state)
 VALUES(NEW.id,NEW.version,proof->>'action',NEW.resource_kind,NEW.resource_id,NEW.configuration_version,NEW.configuration_hash,proof->'actor',proof->>'reason',
  CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.state END,NEW.state) RETURNING id INTO event;
 INSERT INTO policy_publication_outbox(id,publication_id,version,action) VALUES(event,NEW.id,NEW.version,proof->>'action');RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_publication_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_publication',true),'')::jsonb;
 IF (proof->'actor'->>'expiresAt')::numeric<=floor(EXTRACT(epoch FROM policy_configuration_now())) THEN RAISE EXCEPTION 'Publication token expired' USING ERRCODE='23514',CONSTRAINT='policy_configuration_token_expired';END IF;
 IF NOT policy_publication_fresh(proof) THEN RAISE EXCEPTION 'Publication MFA expired' USING ERRCODE='23514',CONSTRAINT='policy_configuration_lease';END IF;
 IF NEW.state<>'withdrawn' AND NEW.expires_at<=policy_configuration_now() THEN RAISE EXCEPTION 'Publication expired before commit' USING ERRCODE='23514',CONSTRAINT='policy_publication_expired';END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_publication_head_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Publication lineage requires actual configuration' USING ERRCODE='42501';END IF;
 IF TG_OP='UPDATE' AND (NEW.resource_kind<>OLD.resource_kind OR NEW.resource_id<>OLD.resource_id OR NEW.verified_origin<>OLD.verified_origin OR NEW.configuration_version<=OLD.configuration_version)
  THEN RAISE EXCEPTION 'Publication lineage cannot be replaced' USING ERRCODE='23514';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_publication_head_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;kind TEXT;identity UUID;next_version INTEGER;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb;
 IF proof->>'action' IN('activated','deactivated') THEN RETURN NULL;END IF;
 kind=proof->>'resourceKind';identity=CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;next_version=CASE WHEN TG_OP='DELETE' THEN OLD.version+1 ELSE NEW.version END;
 INSERT INTO policy_publication_heads(resource_kind,resource_id,configuration_version,verified_origin) VALUES(kind,identity,next_version,true)
  ON CONFLICT(resource_kind,resource_id) DO UPDATE SET configuration_version=EXCLUDED.configuration_version;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_publication_activation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb;
 IF proof->>'action'='activated' THEN
  IF NOT COALESCE(proof->>'publicationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
   OR NOT policy_publication_usable((proof->>'publicationId')::uuid,'policy',NEW.id)
   THEN RAISE EXCEPTION 'Independent current publication required' USING ERRCODE='23514',CONSTRAINT='policy_publication_required';END IF;
 ELSIF proof->>'action' NOT IN('created','deactivated') THEN NEW.status='draft';NEW.activated_at=NULL;END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_publication_activation_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb;
 IF proof->>'action'='activated' AND NOT policy_publication_usable((proof->>'publicationId')::uuid,'policy',NEW.id)
  THEN RAISE EXCEPTION 'Publication expired before activation commit' USING ERRCODE='23514',CONSTRAINT='policy_publication_required';END IF;RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS policy_publication_guard ON policy_publications;
CREATE TRIGGER policy_publication_guard BEFORE INSERT OR UPDATE OR DELETE ON policy_publications FOR EACH ROW EXECUTE FUNCTION policy_publication_guard();
DROP TRIGGER IF EXISTS policy_publication_changed ON policy_publications;
CREATE TRIGGER policy_publication_changed AFTER INSERT OR UPDATE ON policy_publications FOR EACH ROW EXECUTE FUNCTION policy_publication_changed();
DROP TRIGGER IF EXISTS policy_publication_commit_guard ON policy_publications;
CREATE CONSTRAINT TRIGGER policy_publication_commit_guard AFTER INSERT OR UPDATE ON policy_publications DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION policy_publication_commit_guard();
DROP TRIGGER IF EXISTS policy_publication_head_guard ON policy_publication_heads;
CREATE TRIGGER policy_publication_head_guard BEFORE INSERT OR UPDATE OR DELETE ON policy_publication_heads FOR EACH ROW EXECUTE FUNCTION policy_publication_head_guard();
DROP TRIGGER IF EXISTS policy_publication_fence ON policies;
CREATE TRIGGER policy_publication_fence BEFORE UPDATE ON policies FOR EACH ROW EXECUTE FUNCTION policy_publication_activation_guard();
DROP TRIGGER IF EXISTS policy_publication_activation_commit_guard ON policies;
CREATE CONSTRAINT TRIGGER policy_publication_activation_commit_guard AFTER UPDATE ON policies DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION policy_publication_activation_commit_guard();
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['policies','blueprints'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS policy_publication_head_changed ON %I',table_name);
  EXECUTE format('CREATE TRIGGER policy_publication_head_changed AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION policy_publication_head_changed()',table_name);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['policy_publication_audit','policy_publication_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS policy_configuration_evidence_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER policy_configuration_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION policy_configuration_evidence_guard()',table_name);
 END LOOP;
END; $$;
