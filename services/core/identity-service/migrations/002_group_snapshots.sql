CREATE SEQUENCE IF NOT EXISTS identity_group_revision_seq;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT nextval('identity_group_revision_seq');
ALTER TABLE groups ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TABLE IF NOT EXISTS identity_deleted_groups (
  group_id UUID PRIMARY KEY,
  revision BIGINT NOT NULL,
  deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS identity_group_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id UUID NOT NULL,
  revision BIGINT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS identity_group_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id UUID NOT NULL,
  revision BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  published_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_identity_group_outbox_pending ON identity_group_outbox(created_at) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_identity_group_audit_revision ON identity_group_audit(group_id, revision);

CREATE OR REPLACE FUNCTION identity_group_revision() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' AND EXISTS (SELECT 1 FROM identity_deleted_groups WHERE group_id = NEW.id) THEN
    RAISE EXCEPTION 'A deleted group identifier cannot be reused' USING ERRCODE = '23514';
  END IF;
  NEW.revision := nextval('identity_group_revision_seq');
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_group_revision_guard ON groups;
CREATE TRIGGER identity_group_revision_guard BEFORE INSERT OR UPDATE ON groups FOR EACH ROW EXECUTE FUNCTION identity_group_revision();

CREATE OR REPLACE FUNCTION identity_group_record_change() RETURNS trigger AS $$
DECLARE group_identifier UUID;
DECLARE group_revision BIGINT;
DECLARE deleted BOOLEAN := TG_OP = 'DELETE';
DECLARE event_payload JSONB;
BEGIN
  IF deleted THEN
    group_identifier := OLD.id;
    group_revision := nextval('identity_group_revision_seq');
    INSERT INTO identity_deleted_groups(group_id, revision) VALUES(group_identifier, group_revision);
  ELSE
    group_identifier := NEW.id;
    group_revision := NEW.revision;
  END IF;
  event_payload := jsonb_build_object('groupId', group_identifier, 'revision', group_revision::text, 'deleted', deleted);
  INSERT INTO identity_group_outbox(group_id, revision, event_type, payload)
    VALUES(group_identifier, group_revision, 'identity.group.changed', event_payload);
  INSERT INTO identity_group_audit(group_id, revision, action, actor, details)
    VALUES(group_identifier, group_revision, lower(TG_OP), COALESCE(NULLIF(current_setting('opendirectory.actor', true), ''), 'database'), event_payload);
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_group_change_record ON groups;
CREATE TRIGGER identity_group_change_record AFTER INSERT OR UPDATE OR DELETE ON groups FOR EACH ROW EXECUTE FUNCTION identity_group_record_change();

CREATE OR REPLACE FUNCTION identity_member_validate() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'Remove and re-add a membership instead of updating it' USING ERRCODE = '42501';
  END IF;
  PERFORM id FROM users WHERE id::text = NEW.user_id FOR KEY SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Membership requires an existing identity user' USING ERRCODE = '23503'; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_member_validation ON group_members;
CREATE TRIGGER identity_member_validation BEFORE INSERT OR UPDATE ON group_members FOR EACH ROW EXECUTE FUNCTION identity_member_validate();

CREATE OR REPLACE FUNCTION identity_member_changed() RETURNS trigger AS $$
DECLARE group_identifier UUID;
DECLARE member_identifier TEXT;
DECLARE group_revision BIGINT;
BEGIN
  IF TG_OP = 'DELETE' THEN
    group_identifier := OLD.group_id;
    member_identifier := OLD.user_id;
  ELSE
    group_identifier := NEW.group_id;
    member_identifier := NEW.user_id;
  END IF;
  UPDATE groups SET updated_at = clock_timestamp() WHERE id = group_identifier RETURNING revision INTO group_revision;
  IF FOUND THEN
    INSERT INTO identity_group_audit(group_id, revision, action, actor, details)
      VALUES(group_identifier, group_revision, CASE WHEN TG_OP = 'DELETE' THEN 'member-removed' ELSE 'member-added' END,
        COALESCE(NULLIF(current_setting('opendirectory.actor', true), ''), 'database'), jsonb_build_object('userId', member_identifier));
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_member_change_record ON group_members;
CREATE TRIGGER identity_member_change_record AFTER INSERT OR DELETE ON group_members FOR EACH ROW EXECUTE FUNCTION identity_member_changed();

CREATE OR REPLACE FUNCTION identity_user_memberships() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' OR NEW.enabled IS DISTINCT FROM OLD.enabled THEN
    PERFORM id FROM groups WHERE id IN (SELECT group_id FROM group_members WHERE user_id = OLD.id::text) ORDER BY id FOR UPDATE;
    IF TG_OP = 'DELETE' THEN
      DELETE FROM group_members WHERE user_id = OLD.id::text;
      RETURN OLD;
    END IF;
    UPDATE groups SET updated_at = clock_timestamp() WHERE id IN (SELECT group_id FROM group_members WHERE user_id = OLD.id::text);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_user_membership_state ON users;
CREATE TRIGGER identity_user_membership_state BEFORE UPDATE OF enabled OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION identity_user_memberships();

CREATE OR REPLACE FUNCTION identity_group_audit_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Group audit entries are append-only' USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_group_audit_guard ON identity_group_audit;
CREATE TRIGGER identity_group_audit_guard BEFORE UPDATE OR DELETE ON identity_group_audit FOR EACH ROW EXECUTE FUNCTION identity_group_audit_immutable();
