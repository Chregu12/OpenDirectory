CREATE TABLE IF NOT EXISTS license_grants (
  id UUID PRIMARY KEY,
  license_id UUID NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('direct','group')),
  recipient_id TEXT NOT NULL,
  origin TEXT NOT NULL CHECK(origin IN ('observed','allocated')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS license_grants_pool ON license_grants(license_id,id);
CREATE TABLE IF NOT EXISTS license_grant_events (
  grant_id UUID NOT NULL REFERENCES license_grants(id),
  version BIGINT NOT NULL CHECK(version>0),
  state TEXT NOT NULL CHECK(state IN ('active','revoked','deleted')),
  event TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  changed_user_id TEXT,
  actor_user_id TEXT,
  actor_issuer TEXT,
  actor_subject TEXT,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(grant_id,version)
);
ALTER TABLE license_group_rules ADD COLUMN IF NOT EXISTS grant_id UUID;
ALTER TABLE license_assignment_sources ADD COLUMN IF NOT EXISTS grant_id UUID;

DO $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM license_schema_versions WHERE version=10) THEN
    UPDATE license_group_rules SET grant_id=gen_random_uuid();
    INSERT INTO license_grants(id,license_id,kind,recipient_id,origin)
      SELECT grant_id,license_id,'group',group_id,'observed' FROM license_group_rules;
    INSERT INTO license_grant_events(grant_id,version,state,event,expires_at)
      SELECT grant_id,1,CASE WHEN enabled THEN 'active' ELSE 'revoked' END,'observed',expires_at FROM license_group_rules;
    UPDATE license_assignment_sources sources SET grant_id=rules.grant_id FROM license_group_rules rules
      WHERE sources.source_type='group' AND sources.license_id=rules.license_id AND sources.source_id=rules.group_id;
    IF EXISTS(SELECT 1 FROM license_assignment_sources WHERE source_type='group' AND grant_id IS NULL) THEN
      RAISE EXCEPTION 'Unresolved group license sources require explicit reconciliation' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM license_assignment_sources sources JOIN license_group_rules rules ON rules.grant_id=sources.grant_id
      WHERE NOT rules.enabled OR sources.expires_at IS DISTINCT FROM rules.expires_at) THEN
      RAISE EXCEPTION 'Inconsistent group license sources require explicit reconciliation' USING ERRCODE='23514';
    END IF;
    UPDATE license_assignment_sources SET grant_id=gen_random_uuid() WHERE source_type='direct';
    INSERT INTO license_grants(id,license_id,kind,recipient_id,origin)
      SELECT grant_id,license_id,'direct',user_id,'observed' FROM license_assignment_sources WHERE source_type='direct';
    INSERT INTO license_grant_events(grant_id,version,state,event,expires_at)
      SELECT grant_id,1,'active','observed',expires_at FROM license_assignment_sources WHERE source_type='direct';
    INSERT INTO license_schema_versions(version) VALUES(10);
  END IF;
END;
$$;
ALTER TABLE license_group_rules ALTER COLUMN grant_id SET NOT NULL;
ALTER TABLE license_assignment_sources ALTER COLUMN grant_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS license_group_rule_grant ON license_group_rules(grant_id);
CREATE INDEX IF NOT EXISTS license_source_grant ON license_assignment_sources(grant_id,user_id);
DO $$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='license_group_rules'::regclass AND conname='license_group_grant_fk') THEN
    ALTER TABLE license_group_rules ADD CONSTRAINT license_group_grant_fk FOREIGN KEY(grant_id) REFERENCES license_grants(id) DEFERRABLE INITIALLY DEFERRED;
    ALTER TABLE license_assignment_sources ADD CONSTRAINT license_source_grant_fk FOREIGN KEY(grant_id) REFERENCES license_grants(id) DEFERRABLE INITIALLY DEFERRED;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION license_grant_history_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP='INSERT' AND pg_trigger_depth()>1 THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'License grant history is append-only and source-derived' USING ERRCODE='42501';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS license_grants_guard ON license_grants;
CREATE TRIGGER license_grants_guard BEFORE INSERT OR UPDATE OR DELETE ON license_grants FOR EACH ROW EXECUTE FUNCTION license_grant_history_guard();
DROP TRIGGER IF EXISTS license_grant_events_guard ON license_grant_events;
CREATE TRIGGER license_grant_events_guard BEFORE INSERT OR UPDATE OR DELETE ON license_grant_events FOR EACH ROW EXECUTE FUNCTION license_grant_history_guard();

CREATE OR REPLACE FUNCTION license_grant_event(grant_identity UUID,next_state TEXT,change TEXT,expiry TIMESTAMPTZ,changed_user TEXT DEFAULT NULL) RETURNS void AS $$
DECLARE previous license_grant_events;
BEGIN
  IF pg_trigger_depth()=0 THEN RAISE EXCEPTION 'Grant events require a source mutation' USING ERRCODE='42501'; END IF;
  PERFORM 1 FROM license_grants WHERE id=grant_identity FOR UPDATE;
  SELECT * INTO previous FROM license_grant_events WHERE grant_id=grant_identity ORDER BY version DESC LIMIT 1;
  IF previous.state IS NOT NULL AND previous.state<>'active' THEN
    RAISE EXCEPTION 'A retired license grant cannot be changed' USING ERRCODE='42501';
  END IF;
  INSERT INTO license_grant_events(grant_id,version,state,event,expires_at,changed_user_id,actor_user_id,actor_issuer,actor_subject)
    VALUES(grant_identity,COALESCE(previous.version,0)+1,next_state,change,expiry,changed_user,
      NULLIF(current_setting('opendirectory.license_actor_user',true),''),
      NULLIF(current_setting('opendirectory.license_actor_issuer',true),''),
      NULLIF(current_setting('opendirectory.license_actor_subject',true),''));
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION license_group_grant_before() RETURNS trigger AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.grant_id IS NOT NULL THEN RAISE EXCEPTION 'Grant identity is server-generated' USING ERRCODE='42501'; END IF;
    NEW.grant_id=gen_random_uuid();
    RETURN NEW;
  END IF;
  IF ROW(NEW.license_id,NEW.group_id,NEW.grant_id) IS DISTINCT FROM ROW(OLD.license_id,OLD.group_id,OLD.grant_id) THEN
    RAISE EXCEPTION 'License grant targets are immutable' USING ERRCODE='42501';
  END IF;
  IF NOT OLD.enabled AND NEW.enabled THEN
    IF EXISTS(SELECT 1 FROM license_assignment_sources WHERE grant_id=OLD.grant_id) THEN
      RAISE EXCEPTION 'Retired group sources must be removed before a new grant' USING ERRCODE='23514';
    END IF;
    NEW.grant_id=gen_random_uuid();
  ELSIF OLD.enabled AND OLD.expires_at<=clock_timestamp() AND NEW.enabled AND NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'An expired group grant must be retired before regranting' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION license_group_grant_after() RETURNS trigger AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    IF OLD.enabled THEN PERFORM license_grant_event(OLD.grant_id,'deleted','rule-deleted',OLD.expires_at); END IF;
    RETURN OLD;
  END IF;
  IF TG_OP='INSERT' OR NEW.grant_id IS DISTINCT FROM OLD.grant_id THEN
    INSERT INTO license_grants(id,license_id,kind,recipient_id,origin) VALUES(NEW.grant_id,NEW.license_id,'group',NEW.group_id,'allocated');
    PERFORM license_grant_event(NEW.grant_id,CASE WHEN NEW.enabled THEN 'active' ELSE 'revoked' END,'rule-created',NEW.expires_at);
  ELSIF OLD.enabled AND (NOT NEW.enabled OR NEW.expires_at IS DISTINCT FROM OLD.expires_at) THEN
    PERFORM license_grant_event(NEW.grant_id,CASE WHEN NEW.enabled THEN 'active' ELSE 'revoked' END,
      CASE WHEN NEW.enabled THEN 'expiry-changed' ELSE 'rule-retired' END,NEW.expires_at);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS license_group_grant_before ON license_group_rules;
CREATE TRIGGER license_group_grant_before BEFORE INSERT OR UPDATE ON license_group_rules FOR EACH ROW EXECUTE FUNCTION license_group_grant_before();
DROP TRIGGER IF EXISTS license_group_grant_after ON license_group_rules;
CREATE TRIGGER license_group_grant_after AFTER INSERT OR UPDATE OR DELETE ON license_group_rules FOR EACH ROW EXECUTE FUNCTION license_group_grant_after();

CREATE OR REPLACE FUNCTION license_source_grant_before() RETURNS trigger AS $$
DECLARE parent license_group_rules;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF (to_jsonb(NEW)-'expires_at') IS DISTINCT FROM (to_jsonb(OLD)-'expires_at') THEN
      RAISE EXCEPTION 'License source identity and provenance are immutable' USING ERRCODE='42501';
    END IF;
    IF OLD.source_type='direct' AND OLD.expires_at<=clock_timestamp() AND NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
      RAISE EXCEPTION 'An expired direct grant requires a new incarnation' USING ERRCODE='23514';
    END IF;
  ELSIF NEW.grant_id IS NOT NULL THEN
    RAISE EXCEPTION 'Grant identity is server-generated' USING ERRCODE='42501';
  END IF;
  IF NEW.source_type='group' THEN
    SELECT * INTO parent FROM license_group_rules WHERE license_id=NEW.license_id AND group_id=NEW.source_id FOR SHARE;
    IF parent.grant_id IS NULL OR NOT parent.enabled OR NEW.expires_at IS DISTINCT FROM parent.expires_at THEN
      RAISE EXCEPTION 'Group sources require the current enabled grant and expiry' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' AND NEW.grant_id<>parent.grant_id THEN
      RAISE EXCEPTION 'Group source incarnation changed' USING ERRCODE='23514';
    END IF;
    NEW.grant_id=parent.grant_id;
  ELSIF TG_OP='INSERT' THEN
    IF NEW.source_id<>'direct' THEN RAISE EXCEPTION 'Invalid direct source' USING ERRCODE='23514'; END IF;
    NEW.grant_id=gen_random_uuid();
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION license_source_grant_after() RETURNS trigger AS $$
DECLARE parent license_group_rules;
DECLARE source license_assignment_sources;
BEGIN
  source=CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
  IF source.source_type='direct' THEN
    IF TG_OP='INSERT' THEN
      INSERT INTO license_grants(id,license_id,kind,recipient_id,origin) VALUES(source.grant_id,source.license_id,'direct',source.user_id,'allocated');
    END IF;
    IF TG_OP<>'UPDATE' OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
      PERFORM license_grant_event(source.grant_id,CASE WHEN TG_OP='DELETE' THEN 'revoked' ELSE 'active' END,
        CASE TG_OP WHEN 'INSERT' THEN 'source-created' WHEN 'DELETE' THEN 'source-removed' ELSE 'expiry-changed' END,source.expires_at);
    END IF;
  ELSIF TG_OP IN ('INSERT','DELETE') THEN
    SELECT * INTO parent FROM license_group_rules WHERE grant_id=source.grant_id FOR UPDATE;
    IF parent.enabled THEN
      PERFORM license_grant_event(source.grant_id,'active',CASE WHEN TG_OP='INSERT' THEN 'member-added' ELSE 'member-removed' END,parent.expires_at,source.user_id);
    END IF;
  END IF;
  RETURN source;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS license_source_grant_before ON license_assignment_sources;
CREATE TRIGGER license_source_grant_before BEFORE INSERT OR UPDATE ON license_assignment_sources FOR EACH ROW EXECUTE FUNCTION license_source_grant_before();
DROP TRIGGER IF EXISTS license_source_grant_after ON license_assignment_sources;
CREATE TRIGGER license_source_grant_after AFTER INSERT OR UPDATE OR DELETE ON license_assignment_sources FOR EACH ROW EXECUTE FUNCTION license_source_grant_after();
