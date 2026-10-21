CREATE TABLE IF NOT EXISTS company_license_groups (
 id UUID PRIMARY KEY, tenant_id UUID NOT NULL, group_id UUID NOT NULL, pool_id UUID NOT NULL REFERENCES license_catalog(id),
 blueprint_id UUID NOT NULL UNIQUE REFERENCES company_blueprints(id), status TEXT NOT NULL CHECK(status IN('active','unlinked')),
 revision BIGINT NOT NULL CHECK(revision IN(1,2)), created_by UUID NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
 operation_id UUID NOT NULL UNIQUE, CHECK((status='active' AND revision=1) OR(status='unlinked' AND revision=2))
);
CREATE UNIQUE INDEX IF NOT EXISTS company_license_group_active ON company_license_groups(tenant_id,group_id,pool_id) WHERE status='active';
CREATE TABLE IF NOT EXISTS company_license_group_events (
 id UUID PRIMARY KEY, rule_id UUID NOT NULL REFERENCES company_license_groups(id), tenant_id UUID NOT NULL, action TEXT NOT NULL CHECK(action IN('linked','unlinked')),
 actor_user_id UUID NOT NULL, request JSONB NOT NULL, proof JSONB NOT NULL, result JSONB NOT NULL, transaction_id BIGINT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS company_license_group_outbox (
 id UUID PRIMARY KEY REFERENCES company_license_group_events(id), status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'), created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS company_license_group_effects (
 id UUID PRIMARY KEY REFERENCES company_blueprint_assignment_operations(id), rule_id UUID NOT NULL REFERENCES company_license_groups(id),
 user_id UUID NOT NULL, action TEXT NOT NULL CHECK(action IN('assigned','removed')), snapshot JSONB NOT NULL, valid_until TIMESTAMPTZ NOT NULL,
 transaction_id BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS company_license_group_receiver_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);

CREATE OR REPLACE FUNCTION company_license_group_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE event company_license_group_events; parent company_blueprint_assignment_operations; rule company_license_groups;
BEGIN
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM company_license_groups) OR EXISTS(SELECT 1 FROM company_license_group_events)
    OR EXISTS(SELECT 1 FROM company_license_group_effects) OR EXISTS(SELECT 1 FROM company_license_group_outbox)
    THEN RAISE EXCEPTION 'License group history is retained' USING ERRCODE='42501';END IF;
  RETURN NULL;
 END IF;
 IF TG_TABLE_NAME='company_license_groups' THEN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'License group history is retained' USING ERRCODE='42501';END IF;
  IF TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['status','revision','updated_at'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['status','revision','updated_at']
    OR OLD.status<>'active' OR NEW.status<>'unlinked' OR NEW.revision<>OLD.revision+1) THEN RAISE EXCEPTION 'Immutable license group linkage' USING ERRCODE='42501';END IF;
  IF TG_WHEN='BEFORE' THEN RETURN NEW;END IF;
  SELECT * INTO event FROM company_license_group_events WHERE rule_id=NEW.id AND transaction_id=txid_current() AND result=to_jsonb(NEW);
  IF NOT FOUND OR event.tenant_id<>NEW.tenant_id OR event.actor_user_id<>(event.proof#>>'{context,userId}')::uuid
    OR NOT license_company_proof_retained(event.proof,jsonb_build_object('id',event.id,'correlationId',event.id,'licenseId',NEW.pool_id,'action','create','expectedVersion','0','reason',event.request->>'reason','values',jsonb_build_object('name','License group','vendor','OpenDirectory','description','','totalSeats',1),'assignmentId',NULL))
    OR event.proof#>>'{tenant,id}'<>NEW.tenant_id::text
    OR NOT EXISTS(SELECT 1 FROM company_license_group_outbox WHERE id=event.id AND status='pending')
    THEN RAISE EXCEPTION 'Original license group evidence required' USING ERRCODE='42501';END IF;
  IF event.proof->>'validUntil' IS NULL OR (event.proof->>'validUntil')::bigint<=EXTRACT(EPOCH FROM clock_timestamp()) THEN RAISE EXCEPTION 'Original license group deadline expired' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='company_license_group_effects' THEN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Immutable license group effects' USING ERRCODE='42501';END IF;
  SELECT * INTO parent FROM company_blueprint_assignment_operations WHERE id=NEW.id;
  SELECT * INTO rule FROM company_license_groups WHERE id=NEW.rule_id;
  IF parent.id IS NULL OR rule.id IS NULL OR parent.transaction_id<>txid_current() OR NEW.transaction_id<>txid_current() OR parent.tenant_id<>rule.tenant_id OR parent.user_id<>NEW.user_id OR parent.action<>NEW.action
    OR NEW.valid_until<=clock_timestamp() OR NEW.valid_until>clock_timestamp()+interval '65 seconds'
    OR parent.action='assigned' AND (rule.status<>'active' OR parent.command->>'blueprintId' IS DISTINCT FROM rule.blueprint_id::text OR parent.command->>'version' IS DISTINCT FROM '1'
      OR NEW.snapshot->>'groupId' IS DISTINCT FROM rule.group_id::text OR NEW.snapshot->'memberIds' IS NULL OR NOT (NEW.snapshot->'memberIds' ? NEW.user_id::text)
      OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.snapshot->'memberships') member WHERE member->>'userId'=NEW.user_id::text AND member->>'eligibilityRevision'=parent.command->>'eligibilityRevision'
        AND (member->>'reviewDeadlineAt' IS NULL OR (member->>'reviewDeadlineAt')::timestamptz>=NEW.valid_until)))
    OR parent.action='removed' AND NOT EXISTS(SELECT 1 FROM company_blueprint_user_assignments WHERE id=parent.assignment_id AND blueprint_id=rule.blueprint_id)
    OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(parent.command->'pools') capture WHERE capture->>'poolId'=rule.pool_id::text)
    THEN RAISE EXCEPTION 'Original current group effect required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME IN('company_license_group_events','company_license_group_outbox') AND TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'Immutable license group evidence' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS company_license_group_before ON company_license_groups;
CREATE TRIGGER company_license_group_before BEFORE INSERT OR UPDATE OR DELETE ON company_license_groups FOR EACH ROW EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_commit ON company_license_groups;
CREATE CONSTRAINT TRIGGER company_license_group_commit AFTER INSERT OR UPDATE ON company_license_groups DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_effect_before ON company_license_group_effects;
CREATE TRIGGER company_license_group_effect_before BEFORE INSERT OR UPDATE OR DELETE ON company_license_group_effects FOR EACH ROW EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_effect_commit ON company_license_group_effects;
CREATE CONSTRAINT TRIGGER company_license_group_effect_commit AFTER INSERT ON company_license_group_effects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_event_guard ON company_license_group_events;
CREATE TRIGGER company_license_group_event_guard BEFORE UPDATE OR DELETE ON company_license_group_events FOR EACH ROW EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_outbox_guard ON company_license_group_outbox;
CREATE TRIGGER company_license_group_outbox_guard BEFORE UPDATE OR DELETE ON company_license_group_outbox FOR EACH ROW EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_truncate ON company_license_groups;
CREATE TRIGGER company_license_group_truncate BEFORE TRUNCATE ON company_license_groups FOR EACH STATEMENT EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_event_truncate ON company_license_group_events;
CREATE TRIGGER company_license_group_event_truncate BEFORE TRUNCATE ON company_license_group_events FOR EACH STATEMENT EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_outbox_truncate ON company_license_group_outbox;
CREATE TRIGGER company_license_group_outbox_truncate BEFORE TRUNCATE ON company_license_group_outbox FOR EACH STATEMENT EXECUTE FUNCTION company_license_group_guard();
DROP TRIGGER IF EXISTS company_license_group_effect_truncate ON company_license_group_effects;
CREATE TRIGGER company_license_group_effect_truncate BEFORE TRUNCATE ON company_license_group_effects FOR EACH STATEMENT EXECUTE FUNCTION company_license_group_guard();

CREATE OR REPLACE FUNCTION company_license_group_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 PERFORM company_blueprint_assignment_receiving();
 IF (SELECT count(*) FROM company_license_group_receiver_manifest)<>3 OR EXISTS(SELECT 1 FROM company_license_group_receiver_manifest manifest
  WHERE to_regprocedure(manifest.signature) IS NULL OR md5(pg_get_functiondef(to_regprocedure(manifest.signature)))<>manifest.digest)
  OR (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgfoid='company_license_group_guard()'::regprocedure AND
   ((tgrelid='company_license_groups'::regclass AND (tgname='company_license_group_before' AND tgtype=31 AND NOT tgdeferrable OR tgname='company_license_group_commit' AND tgtype=21 AND tgdeferrable AND tginitdeferred))
    OR(tgrelid='company_license_group_effects'::regclass AND (tgname='company_license_group_effect_before' AND tgtype=31 AND NOT tgdeferrable OR tgname='company_license_group_effect_commit' AND tgtype=5 AND tgdeferrable AND tginitdeferred))
    OR(tgrelid='company_license_group_events'::regclass AND tgname='company_license_group_event_guard' AND tgtype=27 AND NOT tgdeferrable)
    OR(tgrelid='company_license_group_outbox'::regclass AND tgname='company_license_group_outbox_guard' AND tgtype=27 AND NOT tgdeferrable)
    OR(tgtype=34 AND NOT tgdeferrable AND ((tgrelid='company_license_groups'::regclass AND tgname='company_license_group_truncate')
      OR(tgrelid='company_license_group_events'::regclass AND tgname='company_license_group_event_truncate')
      OR(tgrelid='company_license_group_outbox'::regclass AND tgname='company_license_group_outbox_truncate')
      OR(tgrelid='company_license_group_effects'::regclass AND tgname='company_license_group_effect_truncate')))))<>10
 THEN RAISE EXCEPTION 'License group receiving evidence unavailable' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION company_license_group_write(source JSONB,operation UUID,rule_id UUID,request JSONB,blueprint UUID DEFAULT NULL) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE original company_license_group_events; current_rule company_license_groups; result JSONB; action_name TEXT;
BEGIN
 PERFORM company_license_group_receiving();
 IF NOT license_company_proof_valid(source,jsonb_build_object('id',operation,'correlationId',operation,'licenseId',COALESCE((request->>'poolId')::uuid,rule_id),'action','create','expectedVersion','0','reason',request->>'reason','values',jsonb_build_object('name','License group','vendor','OpenDirectory','description','','totalSeats',1),'assignmentId',NULL))
   OR request->'confirm' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'Original company license authority required' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(operation::text,0));
 SELECT * INTO original FROM company_license_group_events WHERE id=operation;
 IF FOUND THEN
  IF original.rule_id<>rule_id OR original.request<>request OR original.tenant_id<>(source#>>'{tenant,id}')::uuid OR original.actor_user_id<>(source->>'actorUserId')::uuid THEN RAISE EXCEPTION 'License group operation mismatch' USING ERRCODE='40001';END IF;
  RETURN original.result;
 END IF;
 IF blueprint IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM license_catalog WHERE id=(request->>'poolId')::uuid AND business_tenant_id=(source#>>'{tenant,id}')::uuid)
   OR NOT EXISTS(SELECT 1 FROM company_blueprint_versions WHERE blueprint_id=blueprint AND version=1 AND tenant_id=(source#>>'{tenant,id}')::uuid
     AND draft->'configurations'='[]'::jsonb AND draft->'appPoolIds'=jsonb_build_array(request->>'poolId')) THEN RAISE EXCEPTION 'Own immutable license-only blueprint required' USING ERRCODE='P0002';END IF;
  INSERT INTO company_license_groups VALUES(rule_id,(source#>>'{tenant,id}')::uuid,(request->>'groupId')::uuid,(request->>'poolId')::uuid,blueprint,'active',1,(source->>'actorUserId')::uuid,clock_timestamp(),clock_timestamp(),operation) RETURNING * INTO current_rule;
  action_name='linked';
 ELSE
  SELECT * INTO current_rule FROM company_license_groups WHERE id=rule_id AND tenant_id=(source#>>'{tenant,id}')::uuid FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Own license group not found' USING ERRCODE='P0002';END IF;
  IF current_rule.status<>'active' OR request->>'revision'<>current_rule.revision::text THEN RAISE EXCEPTION 'License group version changed' USING ERRCODE='40001';END IF;
  UPDATE company_license_groups SET status='unlinked',revision=revision+1,updated_at=clock_timestamp() WHERE id=rule_id RETURNING * INTO current_rule;
  action_name='unlinked';
 END IF;
 result=to_jsonb(current_rule);
 INSERT INTO company_license_group_events(id,rule_id,tenant_id,action,actor_user_id,request,proof,result,transaction_id)
  VALUES(operation,rule_id,current_rule.tenant_id,action_name,(source->>'actorUserId')::uuid,request,source,result,txid_current());
 INSERT INTO company_license_group_outbox(id) VALUES(operation);
 RETURN result;
END; $$;
INSERT INTO company_license_group_receiver_manifest(signature,digest)
 SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY['company_license_group_guard()','company_license_group_receiving()','company_license_group_write(jsonb,uuid,uuid,jsonb,uuid)']) signature
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
