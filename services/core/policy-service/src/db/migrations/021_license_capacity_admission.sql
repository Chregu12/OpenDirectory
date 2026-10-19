CREATE TABLE IF NOT EXISTS license_capacity_budgets (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),generation BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
 product_id UUID NOT NULL REFERENCES license_provider_products(id),previous_id UUID REFERENCES license_capacity_budgets(id),
 run_id UUID NOT NULL REFERENCES license_capacity_runs(id),source_id UUID NOT NULL REFERENCES license_capacity_sources(id),
 source_version BIGINT NOT NULL,connector_version BIGINT NOT NULL,product_version BIGINT NOT NULL,
 units INTEGER NOT NULL CHECK(units>=0),reason TEXT NOT NULL,reviewed_by NAME NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT license_capacity_now(),UNIQUE(product_id,run_id)
);
CREATE INDEX IF NOT EXISTS license_capacity_budget_head ON license_capacity_budgets(product_id,generation DESC);
CREATE TABLE IF NOT EXISTS license_capacity_reservations (
 attempt_id UUID PRIMARY KEY,target_id UUID NOT NULL REFERENCES license_fulfillment_targets(id),target_version BIGINT NOT NULL,
 budget_id UUID NOT NULL REFERENCES license_capacity_budgets(id),run_id UUID NOT NULL REFERENCES license_capacity_runs(id),
 reserved_at TIMESTAMPTZ NOT NULL DEFAULT license_capacity_now(),dispatch_before TIMESTAMPTZ NOT NULL,
 dispatched_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS license_capacity_budget_charges ON license_capacity_reservations(budget_id,reserved_at);
CREATE INDEX IF NOT EXISTS license_capacity_target_charges ON license_capacity_reservations(target_id,reserved_at DESC);
CREATE INDEX IF NOT EXISTS license_capacity_observed_outcomes ON license_fulfillment_events(target_id,created_at DESC,id DESC) WHERE action='observation';
CREATE TABLE IF NOT EXISTS license_capacity_admission_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),budget_id UUID NOT NULL REFERENCES license_capacity_budgets(id),attempt_id UUID,
 action TEXT NOT NULL,actor JSONB NOT NULL,details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT license_capacity_now()
);
CREATE TABLE IF NOT EXISTS license_capacity_admission_outbox (
 id UUID PRIMARY KEY REFERENCES license_capacity_admission_events(id),budget_id UUID NOT NULL,attempt_id UUID,
 action TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT license_capacity_now()
);
CREATE OR REPLACE FUNCTION license_capacity_admission_state(product_identity UUID,own_attempt UUID DEFAULT NULL) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE product license_provider_products%ROWTYPE;source license_capacity_sources%ROWTYPE;connector license_provider_connectors%ROWTYPE;
 budget license_capacity_budgets%ROWTYPE;capture license_capacity_runs%ROWTYPE;sku JSONB;charged BIGINT;uncovered BIGINT;remaining BIGINT;
BEGIN
 SELECT * INTO product FROM license_provider_products WHERE id=product_identity;
 IF product.id IS NULL THEN RETURN jsonb_build_object('error','capacity_product_required');END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('license-capacity-admission:'||product.connector_id::text,0));
 SELECT * INTO source FROM license_capacity_sources WHERE connector_id=product.connector_id AND enabled FOR SHARE;
 SELECT * INTO connector FROM license_provider_connectors WHERE id=product.connector_id FOR SHARE;
 SELECT * INTO product FROM license_provider_products WHERE id=product_identity FOR SHARE;
 SELECT * INTO budget FROM license_capacity_budgets WHERE product_id=product.id ORDER BY generation DESC LIMIT 1;
 IF budget.id IS NULL THEN RETURN jsonb_build_object('error','capacity_budget_required');END IF;
 IF NOT connector.enabled OR NOT product.enabled OR source.id IS NULL OR source.id<>budget.source_id OR source.version<>budget.source_version
  OR connector.version<>budget.connector_version OR product.version<>budget.product_version THEN RETURN jsonb_build_object('error','capacity_binding_review_required');END IF;
 SELECT capture_row.* INTO capture FROM license_capacity_runs capture_row JOIN license_capacity_sources origin ON origin.id=capture_row.source_id
  WHERE origin.connector_id=connector.id ORDER BY capture_row.run_number DESC LIMIT 1;
 IF capture.id IS NULL OR capture.status<>'complete' OR capture.source_id<>source.id OR capture.source_version<>source.version OR capture.connector_version<>connector.version
  OR capture.started_at>license_capacity_now() OR capture.valid_until<=license_capacity_now() THEN RETURN jsonb_build_object('error','capacity_observation_required');END IF;
 SELECT item INTO sku FROM jsonb_array_elements(capture.payload) item WHERE item->>'skuId'=product.sku_id::text;
 IF sku IS NULL OR sku->>'appliesTo'<>'User' OR sku->>'capabilityStatus'<>'Enabled' THEN RETURN jsonb_build_object('error','capacity_enabled_user_sku_required');END IF;
 SELECT count(*) INTO charged FROM license_capacity_reservations WHERE budget_id=budget.id AND attempt_id IS DISTINCT FROM own_attempt;
 SELECT count(*) INTO uncovered FROM license_capacity_reservations reservation JOIN license_fulfillment_targets target ON target.id=reservation.target_id
  WHERE reservation.budget_id=budget.id AND reservation.attempt_id IS DISTINCT FROM own_attempt
  AND (reservation.reserved_at>=capture.started_at OR reservation.dispatched_at IS NULL OR target.status<>'confirmed'
   OR target.checked_at IS NULL OR target.checked_at>=capture.started_at OR target.observation->'present' IS DISTINCT FROM 'true'::jsonb
   OR NOT target.owned OR target.observation->'active' IS DISTINCT FROM 'true'::jsonb OR target.observation->'direct' IS DISTINCT FROM 'true'::jsonb
   OR target.observation->'plansMatch' IS DISTINCT FROM 'true'::jsonb OR target.observation->'inherited' IS DISTINCT FROM 'false'::jsonb);
 remaining=LEAST(budget.units::bigint-charged,(sku->'prepaidUnits'->>'enabled')::bigint-(sku->>'consumedUnits')::bigint-uncovered);
 RETURN jsonb_build_object('error',CASE WHEN remaining<1 THEN 'capacity_admission_exhausted' ELSE NULL END,
  'budgetId',budget.id,'runId',capture.id,'validUntil',capture.valid_until,'available',GREATEST(0,remaining),'chargedUnits',charged,'budgetUnits',budget.units);
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_budget_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE product license_provider_products%ROWTYPE;source license_capacity_sources%ROWTYPE;connector license_provider_connectors%ROWTYPE;
 capture license_capacity_runs%ROWTYPE;previous license_capacity_budgets%ROWTYPE;sku JSONB;owner_role NAME;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Capacity budgets are retained' USING ERRCODE='42501';END IF;
 SELECT pg_get_userbyid(relowner) INTO owner_role FROM pg_class WHERE oid=TG_RELID;
 IF NOT pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
  OR current_setting('opendirectory.capacity_budget_review',true) IS DISTINCT FROM 'external-usage-and-all-attempts-reviewed'
  OR length(btrim(NEW.reason)) NOT BETWEEN 10 AND 500 OR NEW.reason ~ '[[:cntrl:]]' THEN RAISE EXCEPTION 'Reviewed offline schema-owner capacity budget required' USING ERRCODE='42501';END IF;
 SELECT * INTO product FROM license_provider_products WHERE id=NEW.product_id;
 PERFORM pg_advisory_xact_lock(hashtextextended('license-capacity-admission:'||product.connector_id::text,0));
 SELECT * INTO source FROM license_capacity_sources WHERE connector_id=product.connector_id AND enabled FOR SHARE;
 SELECT * INTO connector FROM license_provider_connectors WHERE id=product.connector_id FOR SHARE;
 SELECT * INTO product FROM license_provider_products WHERE id=NEW.product_id FOR SHARE;
 SELECT * INTO previous FROM license_capacity_budgets WHERE product_id=product.id ORDER BY generation DESC LIMIT 1;
 SELECT capture_row.* INTO capture FROM license_capacity_runs capture_row JOIN license_capacity_sources origin ON origin.id=capture_row.source_id
  WHERE origin.connector_id=connector.id ORDER BY capture_row.run_number DESC LIMIT 1;
 IF NEW.previous_id IS DISTINCT FROM previous.id OR NEW.product_version<>product.version OR NOT product.enabled OR NOT connector.enabled
  OR source.id IS NULL OR capture.id IS NULL OR NEW.run_id<>capture.id OR capture.status<>'complete' OR capture.source_id<>source.id
  OR capture.source_version<>source.version OR capture.connector_version<>connector.version OR capture.started_at>license_capacity_now()
  OR capture.valid_until<=license_capacity_now() OR previous.id IS NOT NULL AND capture.started_at<=previous.created_at THEN
  RAISE EXCEPTION 'Current conditional capacity budget review required' USING ERRCODE='23514';END IF;
 SELECT item INTO sku FROM jsonb_array_elements(capture.payload) item WHERE item->>'skuId'=product.sku_id::text;
 IF sku IS NULL OR sku->>'appliesTo'<>'User' OR sku->>'capabilityStatus'<>'Enabled' THEN RAISE EXCEPTION 'Enabled user SKU required for budget review' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM license_fulfillment_targets target LEFT JOIN LATERAL
  (SELECT event.* FROM license_fulfillment_events event WHERE event.target_id=target.id AND event.action='observation' ORDER BY event.created_at DESC,event.id DESC LIMIT 1) observed ON true
  WHERE target.product_id=product.id AND target.attempt_id IS NOT NULL AND
  (target.status NOT IN('confirmed','failed','conflict') OR observed.id IS NULL OR observed.created_at>=capture.started_at
   OR observed.version<>target.version OR observed.details->'observation' IS DISTINCT FROM target.observation
   OR observed.created_at<COALESCE((SELECT max(reserved_at) FROM license_capacity_reservations WHERE target_id=target.id),'-infinity'::timestamptz)
   OR NOT COALESCE(target.observation->'present'='false'::jsonb OR target.owned AND target.observation @> '{"present":true,"direct":true,"active":true,"plansMatch":true,"inherited":false}'::jsonb,false))) THEN
  RAISE EXCEPTION 'Unfinished or unobserved capacity liabilities require outcome review' USING ERRCODE='23514';END IF;
 NEW.source_id=source.id;NEW.source_version=source.version;NEW.connector_version=connector.version;
 NEW.units=GREATEST(0,(sku->'prepaidUnits'->>'enabled')::bigint-(sku->>'consumedUnits')::bigint);
 NEW.created_at=license_capacity_now();NEW.reviewed_by=session_user;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_budget_changed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event UUID;
BEGIN
 INSERT INTO license_capacity_admission_events(budget_id,action,actor,details) VALUES(NEW.id,'budget-reviewed',jsonb_build_object('databaseRole',session_user),
  jsonb_build_object('productId',NEW.product_id,'previousId',NEW.previous_id,'runId',NEW.run_id,'units',NEW.units,'reason',NEW.reason)) RETURNING id INTO event;
 INSERT INTO license_capacity_admission_outbox(id,budget_id,action) VALUES(event,NEW.id,'budget-reviewed');RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_budget_commit_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM license_capacity_runs capture JOIN license_capacity_sources source ON source.id=capture.source_id
  JOIN license_provider_connectors connector ON connector.id=source.connector_id JOIN license_provider_products product ON product.connector_id=connector.id
  WHERE capture.id=NEW.run_id AND source.id=NEW.source_id AND source.enabled AND source.version=NEW.source_version
   AND connector.enabled AND connector.version=NEW.connector_version AND product.id=NEW.product_id AND product.enabled AND product.version=NEW.product_version
   AND capture.status='complete' AND capture.valid_until>license_capacity_now()) THEN RAISE EXCEPTION 'Capacity budget review expired before commit' USING ERRCODE='23514';END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_reservation_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF TG_OP='DELETE' OR TG_OP='INSERT' AND pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Capacity charges derive from actual write intent' USING ERRCODE='42501';END IF;
 IF TG_OP='UPDATE' AND (OLD.dispatched_at IS NOT NULL OR NEW.dispatched_at IS NULL OR
  (to_jsonb(NEW)-'dispatched_at') IS DISTINCT FROM (to_jsonb(OLD)-'dispatched_at')) THEN RAISE EXCEPTION 'Capacity dispatch is one way' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_intent_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE state JSONB;entitlement_cutoff TIMESTAMPTZ;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.status='in_flight' THEN RAISE EXCEPTION 'capacity_initial_target_intent_forbidden' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF NEW.status<>'in_flight' OR OLD.status='in_flight' AND NEW.attempt_id IS NOT DISTINCT FROM OLD.attempt_id THEN RETURN NEW;END IF;
 IF NEW.attempt_id IS NULL OR NEW.attempt_desired IS DISTINCT FROM NEW.desired OR NEW.attempt_version<>NEW.version THEN RAISE EXCEPTION 'Exact provider write intent required' USING ERRCODE='23514';END IF;
 IF NOT NEW.desired THEN RETURN NEW;END IF;
 IF current_setting('opendirectory.capacity_protocol',true) IS DISTINCT FROM '1' THEN RAISE EXCEPTION 'capacity_worker_upgrade_required' USING ERRCODE='23514';END IF;
 state=license_capacity_admission_state(NEW.product_id);
 IF state->>'error' IS NOT NULL THEN RAISE EXCEPTION '%',state->>'error' USING ERRCODE='23514';END IF;
 SELECT assignment.expires_at INTO entitlement_cutoff FROM license_assignments assignment JOIN license_provider_products product ON product.license_id=assignment.license_id
  JOIN license_provider_subjects subject ON subject.user_id::text=assignment.assignee_id WHERE product.id=NEW.product_id AND subject.id=NEW.subject_id AND assignment.assignee_type='user';
 INSERT INTO license_capacity_reservations(attempt_id,target_id,target_version,budget_id,run_id,dispatch_before)
  VALUES(NEW.attempt_id,NEW.id,NEW.version,(state->>'budgetId')::uuid,(state->>'runId')::uuid,
   LEAST(license_capacity_now()+interval '10 seconds',(state->>'validUntil')::timestamptz,entitlement_cutoff));RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_reservation_changed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event UUID;transition TEXT;
BEGIN
 transition=CASE WHEN TG_OP='INSERT' THEN 'capacity-reserved' ELSE 'dispatch-admitted' END;
 INSERT INTO license_capacity_admission_events(budget_id,attempt_id,action,actor,details) VALUES(NEW.budget_id,NEW.attempt_id,transition,
  jsonb_build_object('databaseRole',session_user),jsonb_build_object('targetId',NEW.target_id,'targetVersion',NEW.target_version::text,'runId',NEW.run_id,'dispatchBefore',NEW.dispatch_before)) RETURNING id INTO event;
 INSERT INTO license_capacity_admission_outbox(id,budget_id,attempt_id,action) VALUES(event,NEW.budget_id,NEW.attempt_id,transition);RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_dispatch(attempt UUID,target_identity UUID) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE reservation license_capacity_reservations%ROWTYPE;target license_fulfillment_targets%ROWTYPE;state JSONB;
BEGIN
 SELECT * INTO target FROM license_fulfillment_targets WHERE id=target_identity FOR UPDATE;
 PERFORM license_fulfillment_refresh(product.license_id,subject.user_id,jsonb_build_object('type','capacity-dispatch-expiry-check'),false)
  FROM license_provider_products product JOIN license_provider_subjects subject ON subject.id=target.subject_id WHERE product.id=target.product_id;
 SELECT * INTO target FROM license_fulfillment_targets WHERE id=target_identity;
 SELECT * INTO reservation FROM license_capacity_reservations WHERE attempt_id=attempt AND target_id=target.id FOR UPDATE;
 IF reservation.attempt_id IS NULL OR reservation.dispatched_at IS NOT NULL OR reservation.dispatch_before<=license_capacity_now()
  OR target.status<>'in_flight' OR NOT target.desired OR target.attempt_id<>attempt OR target.version<>reservation.target_version
  OR NOT EXISTS(SELECT 1 FROM license_provider_subjects WHERE id=target.subject_id AND enabled) THEN RETURN false;END IF;
 state=license_capacity_admission_state(target.product_id,attempt);
 IF state->>'error' IS NOT NULL OR state->>'budgetId'<>reservation.budget_id::text THEN RETURN false;END IF;
 UPDATE license_capacity_reservations SET dispatched_at=license_capacity_now() WHERE attempt_id=attempt;RETURN true;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_admission_commit_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE state JSONB;target license_fulfillment_targets%ROWTYPE;
BEGIN
 SELECT * INTO target FROM license_fulfillment_targets WHERE id=NEW.target_id;
 state=license_capacity_admission_state(target.product_id,NEW.attempt_id);
 IF NEW.dispatch_before<=license_capacity_now() OR state->>'error' IS NOT NULL OR state->>'budgetId'<>NEW.budget_id::text
  OR target.status<>'in_flight' OR target.version<>NEW.target_version OR target.attempt_id<>NEW.attempt_id THEN
  RAISE EXCEPTION 'capacity_dispatch_admission_changed' USING ERRCODE='23514';END IF;RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS license_capacity_budget_guard ON license_capacity_budgets;
CREATE TRIGGER license_capacity_budget_guard BEFORE INSERT OR UPDATE OR DELETE ON license_capacity_budgets FOR EACH ROW EXECUTE FUNCTION license_capacity_budget_guard();
DROP TRIGGER IF EXISTS license_capacity_budget_changed ON license_capacity_budgets;
CREATE TRIGGER license_capacity_budget_changed AFTER INSERT ON license_capacity_budgets FOR EACH ROW EXECUTE FUNCTION license_capacity_budget_changed();
DROP TRIGGER IF EXISTS license_capacity_budget_commit_guard ON license_capacity_budgets;
CREATE CONSTRAINT TRIGGER license_capacity_budget_commit_guard AFTER INSERT ON license_capacity_budgets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION license_capacity_budget_commit_guard();
DROP TRIGGER IF EXISTS license_capacity_intent_guard ON license_fulfillment_targets;
CREATE TRIGGER license_capacity_intent_guard BEFORE INSERT OR UPDATE ON license_fulfillment_targets FOR EACH ROW EXECUTE FUNCTION license_capacity_intent_guard();
DROP TRIGGER IF EXISTS license_capacity_reservation_guard ON license_capacity_reservations;
CREATE TRIGGER license_capacity_reservation_guard BEFORE INSERT OR UPDATE OR DELETE ON license_capacity_reservations FOR EACH ROW EXECUTE FUNCTION license_capacity_reservation_guard();
DROP TRIGGER IF EXISTS license_capacity_reservation_changed ON license_capacity_reservations;
CREATE TRIGGER license_capacity_reservation_changed AFTER INSERT OR UPDATE ON license_capacity_reservations FOR EACH ROW EXECUTE FUNCTION license_capacity_reservation_changed();
DROP TRIGGER IF EXISTS license_capacity_admission_commit_guard ON license_capacity_reservations;
CREATE CONSTRAINT TRIGGER license_capacity_admission_commit_guard AFTER INSERT OR UPDATE ON license_capacity_reservations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION license_capacity_admission_commit_guard();
DO $$ DECLARE table_name TEXT;function_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_capacity_admission_events','license_capacity_admission_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS license_capacity_evidence_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_capacity_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_capacity_evidence_guard()',table_name);
 END LOOP;
 FOREACH function_name IN ARRAY ARRAY['license_capacity_admission_state(uuid,uuid)','license_capacity_budget_guard()','license_capacity_budget_changed()','license_capacity_budget_commit_guard()','license_capacity_intent_guard()',
  'license_capacity_reservation_guard()','license_capacity_reservation_changed()','license_capacity_dispatch(uuid,uuid)','license_capacity_admission_commit_guard()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path=%I,pg_catalog,pg_temp',function_name,current_schema());EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',function_name);
 END LOOP;
END; $$;
