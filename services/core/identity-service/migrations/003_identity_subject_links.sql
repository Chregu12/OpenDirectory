CREATE TABLE IF NOT EXISTS identity_subject_links (
  issuer TEXT NOT NULL,
  subject VARCHAR(255) NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(issuer,subject),
  UNIQUE(issuer,user_id)
);
CREATE TABLE IF NOT EXISTS identity_link_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE OR REPLACE FUNCTION identity_link_changed() RETURNS trigger AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    INSERT INTO identity_link_audit(action,actor,details) VALUES('unlink',COALESCE(NULLIF(current_setting('opendirectory.actor',true),''),'database'),to_jsonb(OLD));
  ELSE
    INSERT INTO identity_link_audit(action,actor,details) VALUES('link',COALESCE(NULLIF(current_setting('opendirectory.actor',true),''),'database'),to_jsonb(NEW));
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_subject_link_record ON identity_subject_links;
CREATE TRIGGER identity_subject_link_record AFTER INSERT OR DELETE ON identity_subject_links FOR EACH ROW EXECUTE FUNCTION identity_link_changed();
CREATE OR REPLACE FUNCTION identity_link_no_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Explicitly unlink and relink instead of rewriting identity bindings' USING ERRCODE='42501';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS identity_subject_link_immutable ON identity_subject_links;
CREATE TRIGGER identity_subject_link_immutable BEFORE UPDATE ON identity_subject_links FOR EACH ROW EXECUTE FUNCTION identity_link_no_update();
DROP TRIGGER IF EXISTS identity_link_audit_guard ON identity_link_audit;
CREATE TRIGGER identity_link_audit_guard BEFORE UPDATE OR DELETE ON identity_link_audit FOR EACH ROW EXECUTE FUNCTION identity_group_audit_immutable();
