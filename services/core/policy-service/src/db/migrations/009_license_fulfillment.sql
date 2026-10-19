ALTER TABLE license_assignments ADD COLUMN IF NOT EXISTS eligibility_revision BIGINT;
CREATE OR REPLACE FUNCTION license_assignment_eligibility_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    NEW.eligibility_revision:=NULL;
    IF NEW.assignee_type='user' THEN SELECT directory_revision INTO NEW.eligibility_revision FROM license_subjects WHERE user_id=NEW.assignee_id; END IF;
  ELSIF NEW.eligibility_revision IS DISTINCT FROM OLD.eligibility_revision OR NEW.license_id IS DISTINCT FROM OLD.license_id
    OR NEW.assignee_id IS DISTINCT FROM OLD.assignee_id OR NEW.assignee_type IS DISTINCT FROM OLD.assignee_type THEN
    RAISE EXCEPTION 'Entitlement identity and eligibility origin cannot be rewritten' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS license_assignment_eligibility_guard ON license_assignments;
CREATE TRIGGER license_assignment_eligibility_guard BEFORE INSERT OR UPDATE ON license_assignments FOR EACH ROW EXECUTE FUNCTION license_assignment_eligibility_guard();

CREATE TABLE IF NOT EXISTS license_provider_connectors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL UNIQUE,
  enabled BOOLEAN NOT NULL DEFAULT false,
  version BIGINT NOT NULL DEFAULT 1 CHECK(version>0)
);
CREATE TABLE IF NOT EXISTS license_provider_products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id UUID NOT NULL UNIQUE REFERENCES license_catalog(id),
  connector_id UUID NOT NULL REFERENCES license_provider_connectors(id),
  sku_id UUID NOT NULL,
  disabled_plans JSONB NOT NULL CHECK(jsonb_typeof(disabled_plans)='array'),
  enabled BOOLEAN NOT NULL DEFAULT false,
  version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
  UNIQUE(connector_id,sku_id)
);
CREATE TABLE IF NOT EXISTS license_provider_subjects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connector_id UUID NOT NULL REFERENCES license_provider_connectors(id),
  user_id UUID NOT NULL,
  object_id UUID NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT false,
  version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
  UNIQUE(connector_id,user_id),
  UNIQUE(connector_id,object_id)
);
CREATE TABLE IF NOT EXISTS license_fulfillment_targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id UUID NOT NULL REFERENCES license_provider_products(id),
  subject_id UUID NOT NULL REFERENCES license_provider_subjects(id),
  version BIGINT NOT NULL DEFAULT 1 CHECK(version>0),
  desired BOOLEAN NOT NULL,
  eligibility_revision BIGINT,
  authority_revision BIGINT,
  authority_enabled BOOLEAN,
  authority_deleted BOOLEAN,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','checking','in_flight','verifying','confirmed','unknown','conflict','failed')),
  owned BOOLEAN NOT NULL DEFAULT false,
  observation JSONB,
  checked_at TIMESTAMPTZ,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  error TEXT,
  attempt_id UUID,
  uncertain_add_id UUID,
  attempt_desired BOOLEAN,
  attempt_version BIGINT,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count>=0),
  CHECK((authority_revision IS NULL AND authority_enabled IS NULL AND authority_deleted IS NULL) OR
    (authority_revision>0 AND authority_enabled IS NOT NULL AND authority_deleted IS NOT NULL AND NOT(authority_deleted AND authority_enabled))),
  UNIQUE(product_id,subject_id)
);
CREATE TABLE IF NOT EXISTS license_provider_limits (
  connector_id UUID PRIMARY KEY REFERENCES license_provider_connectors(id),
  not_before TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS license_fulfillment_changes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL REFERENCES license_fulfillment_targets(id),
  version BIGINT NOT NULL,
  desired BOOLEAN NOT NULL,
  source JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(target_id,version)
);
CREATE TABLE IF NOT EXISTS license_fulfillment_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID REFERENCES license_fulfillment_targets(id),
  version BIGINT,
  action TEXT NOT NULL,
  actor JSONB NOT NULL,
  details JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION license_fulfillment_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Provider evidence is append only' USING ERRCODE='23514';
END;
$$;
CREATE OR REPLACE FUNCTION license_fulfillment_target_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Fulfillment targets are retained evidence' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
    IF NOT EXISTS(SELECT 1 FROM license_provider_products product JOIN license_provider_subjects subject ON product.connector_id=subject.connector_id WHERE product.id=NEW.product_id AND subject.id=NEW.subject_id) THEN
      RAISE EXCEPTION 'Provider target requires one connector namespace' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.product_id IS DISTINCT FROM OLD.product_id OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
    OR NEW.version<OLD.version OR NEW.version>OLD.version+1 OR (NEW.desired IS DISTINCT FROM OLD.desired AND NEW.version<>OLD.version+1)
    OR OLD.uncertain_add_id IS NOT NULL AND NEW.uncertain_add_id IS DISTINCT FROM OLD.uncertain_add_id THEN
    RAISE EXCEPTION 'Fulfillment identity and generation cannot be rewritten' USING ERRCODE='23514';
  END IF;
  IF OLD.authority_revision IS NOT NULL AND (NEW.authority_revision IS NULL OR NEW.authority_revision<OLD.authority_revision
    OR NEW.authority_revision=OLD.authority_revision AND (NEW.authority_enabled IS DISTINCT FROM OLD.authority_enabled OR NEW.authority_deleted IS DISTINCT FROM OLD.authority_deleted)
    OR OLD.authority_deleted AND NOT NEW.authority_deleted) THEN
    RAISE EXCEPTION 'Canonical fulfillment eligibility cannot regress' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS license_fulfillment_target_guard ON license_fulfillment_targets;
CREATE TRIGGER license_fulfillment_target_guard BEFORE INSERT OR UPDATE OR DELETE ON license_fulfillment_targets FOR EACH ROW EXECUTE FUNCTION license_fulfillment_target_guard();
DROP TRIGGER IF EXISTS license_fulfillment_change_guard ON license_fulfillment_changes;
CREATE TRIGGER license_fulfillment_change_guard BEFORE UPDATE OR DELETE ON license_fulfillment_changes FOR EACH ROW EXECUTE FUNCTION license_fulfillment_immutable();
DROP TRIGGER IF EXISTS license_fulfillment_event_guard ON license_fulfillment_events;
CREATE TRIGGER license_fulfillment_event_guard BEFORE UPDATE OR DELETE ON license_fulfillment_events FOR EACH ROW EXECUTE FUNCTION license_fulfillment_immutable();

CREATE OR REPLACE FUNCTION license_provider_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Provider bindings are retained; pause rather than retarget or delete' USING ERRCODE='23514'; END IF;
  IF (to_jsonb(NEW)-ARRAY['enabled','version']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['enabled','version']) OR NEW.version<>OLD.version+1 THEN
    RAISE EXCEPTION 'Provider bindings only permit conditional enablement changes' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS license_provider_connector_guard ON license_provider_connectors;
CREATE TRIGGER license_provider_connector_guard BEFORE UPDATE OR DELETE ON license_provider_connectors FOR EACH ROW EXECUTE FUNCTION license_provider_guard();
DROP TRIGGER IF EXISTS license_provider_product_guard ON license_provider_products;
CREATE TRIGGER license_provider_product_guard BEFORE UPDATE OR DELETE ON license_provider_products FOR EACH ROW EXECUTE FUNCTION license_provider_guard();
DROP TRIGGER IF EXISTS license_provider_subject_guard ON license_provider_subjects;
CREATE TRIGGER license_provider_subject_guard BEFORE UPDATE OR DELETE ON license_provider_subjects FOR EACH ROW EXECUTE FUNCTION license_provider_guard();

CREATE OR REPLACE FUNCTION license_fulfillment_refresh(pool_id UUID,canonical_user UUID,origin JSONB,force_change BOOLEAN DEFAULT true) RETURNS void LANGUAGE plpgsql AS $$
DECLARE mapping RECORD; wanted BOOLEAN; captured_revision BIGINT; target license_fulfillment_targets%ROWTYPE;
BEGIN
  FOR mapping IN SELECT product.id AS product_id,subject.id AS subject_id FROM license_provider_products product
    JOIN license_provider_subjects subject ON subject.connector_id=product.connector_id
    WHERE product.license_id=pool_id AND subject.user_id=canonical_user ORDER BY product.id,subject.id
  LOOP
    SELECT * INTO target FROM license_fulfillment_targets WHERE product_id=mapping.product_id AND subject_id=mapping.subject_id FOR UPDATE;
    SELECT eligibility_revision INTO captured_revision FROM license_assignments WHERE license_id=pool_id AND assignee_type='user' AND assignee_id=canonical_user::text;
    wanted := EXISTS(SELECT 1 FROM license_assignments assignment LEFT JOIN license_subjects local_subject ON local_subject.user_id=assignment.assignee_id
      WHERE assignment.license_id=pool_id AND assignment.assignee_type='user' AND assignment.assignee_id=canonical_user::text
      AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp()) AND COALESCE(local_subject.disabled,false)=false
      AND local_subject.directory_enabled IS DISTINCT FROM false AND local_subject.directory_deleted IS DISTINCT FROM true
      AND (assignment.eligibility_revision IS NULL OR assignment.eligibility_revision=local_subject.directory_revision)
      AND (target.authority_revision IS NULL OR target.authority_enabled AND NOT target.authority_deleted AND (assignment.eligibility_revision IS NULL OR assignment.eligibility_revision=target.authority_revision)));
    IF target.id IS NOT NULL AND target.desired=wanted AND NOT force_change THEN CONTINUE; END IF;
    INSERT INTO license_fulfillment_targets(product_id,subject_id,desired,eligibility_revision) VALUES(mapping.product_id,mapping.subject_id,wanted,captured_revision)
    ON CONFLICT(product_id,subject_id) DO UPDATE SET desired=EXCLUDED.desired,eligibility_revision=EXCLUDED.eligibility_revision,version=license_fulfillment_targets.version+1,
      status=CASE WHEN license_fulfillment_targets.status IN('in_flight','unknown') THEN license_fulfillment_targets.status ELSE 'pending' END,
      next_attempt_at=clock_timestamp(),error=CASE WHEN license_fulfillment_targets.status='unknown' THEN license_fulfillment_targets.error ELSE NULL END
    RETURNING * INTO target;
    INSERT INTO license_fulfillment_changes(target_id,version,desired,source) VALUES(target.id,target.version,target.desired,origin);
  END LOOP;
END;
$$;
CREATE OR REPLACE FUNCTION license_fulfillment_assignment_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE assignment RECORD;
BEGIN
  IF TG_OP='DELETE' THEN assignment:=OLD; ELSE assignment:=NEW; END IF;
  IF assignment.assignee_type='user' AND assignment.assignee_id ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN
    PERFORM license_fulfillment_refresh(assignment.license_id,assignment.assignee_id::uuid,
      jsonb_build_object('type','effective-assignment','operation',TG_OP,'assignmentId',assignment.id,'assignedBy',assignment.assigned_by));
  END IF;
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS license_fulfillment_assignment_changed ON license_assignments;
CREATE TRIGGER license_fulfillment_assignment_changed AFTER INSERT OR UPDATE OR DELETE ON license_assignments FOR EACH ROW EXECUTE FUNCTION license_fulfillment_assignment_changed();

CREATE OR REPLACE FUNCTION license_fulfillment_binding_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE mapping RECORD; actor JSONB; explanation TEXT;
BEGIN
  actor:=NULLIF(current_setting('opendirectory.provider_actor',true),'')::jsonb;
  explanation:=NULLIF(current_setting('opendirectory.provider_reason',true),'');
  IF actor IS NULL OR explanation IS NULL OR length(explanation) NOT BETWEEN 10 AND 500 THEN
    RAISE EXCEPTION 'Provider configuration requires a verified actor and reviewed reason' USING ERRCODE='23514';
  END IF;
  INSERT INTO license_fulfillment_events(action,actor,details) VALUES('binding-'||TG_OP,actor,jsonb_build_object('table',TG_TABLE_NAME,'binding',to_jsonb(NEW),'reason',explanation));
  FOR mapping IN SELECT product.license_id,subject.user_id FROM license_provider_products product
    JOIN license_provider_subjects subject ON subject.connector_id=product.connector_id
    WHERE (TG_TABLE_NAME='license_provider_connectors' AND product.connector_id=NEW.id)
      OR (TG_TABLE_NAME='license_provider_products' AND product.id=NEW.id)
      OR (TG_TABLE_NAME='license_provider_subjects' AND subject.id=NEW.id)
    ORDER BY product.id,subject.id
  LOOP
    PERFORM license_fulfillment_refresh(mapping.license_id,mapping.user_id,jsonb_build_object('type','binding','table',TG_TABLE_NAME,'id',NEW.id));
  END LOOP;
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS license_fulfillment_connector_changed ON license_provider_connectors;
CREATE TRIGGER license_fulfillment_connector_changed AFTER INSERT OR UPDATE ON license_provider_connectors FOR EACH ROW EXECUTE FUNCTION license_fulfillment_binding_changed();
DROP TRIGGER IF EXISTS license_fulfillment_product_changed ON license_provider_products;
CREATE TRIGGER license_fulfillment_product_changed AFTER INSERT OR UPDATE ON license_provider_products FOR EACH ROW EXECUTE FUNCTION license_fulfillment_binding_changed();
DROP TRIGGER IF EXISTS license_fulfillment_subject_changed ON license_provider_subjects;
CREATE TRIGGER license_fulfillment_subject_changed AFTER INSERT OR UPDATE ON license_provider_subjects FOR EACH ROW EXECUTE FUNCTION license_fulfillment_binding_changed();

CREATE OR REPLACE FUNCTION license_fulfillment_subject_changed_local() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE mapping RECORD;
BEGIN
  IF NEW.user_id !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN RETURN NULL; END IF;
  FOR mapping IN SELECT product.license_id FROM license_provider_products product JOIN license_provider_subjects subject ON product.connector_id=subject.connector_id
    WHERE subject.user_id=NEW.user_id::uuid ORDER BY product.id
  LOOP
    PERFORM license_fulfillment_refresh(mapping.license_id,NEW.user_id::uuid,jsonb_build_object('type','local-eligibility'),false);
  END LOOP;
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS license_fulfillment_local_eligibility_changed ON license_subjects;
CREATE TRIGGER license_fulfillment_local_eligibility_changed AFTER INSERT OR UPDATE OF disabled,directory_enabled,directory_deleted ON license_subjects
FOR EACH ROW EXECUTE FUNCTION license_fulfillment_subject_changed_local();
