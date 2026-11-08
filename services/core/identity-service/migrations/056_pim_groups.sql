ALTER TABLE identity_pim_eligibilities DROP CONSTRAINT IF EXISTS identity_pim_eligibilities_max_duration_seconds_check;
ALTER TABLE identity_pim_eligibilities ADD CONSTRAINT identity_pim_eligibilities_max_duration_seconds_check CHECK(max_duration_seconds BETWEEN 60 AND 36000);
ALTER TABLE identity_pim_requests DROP CONSTRAINT IF EXISTS identity_pim_requests_duration_seconds_check;
ALTER TABLE identity_pim_requests ADD CONSTRAINT identity_pim_requests_duration_seconds_check CHECK(duration_seconds BETWEEN 60 AND 36000);
ALTER TABLE identity_role_activation_policies DROP CONSTRAINT IF EXISTS identity_role_activation_policies_max_duration_seconds_check;
ALTER TABLE identity_role_activation_policies ADD CONSTRAINT identity_role_activation_policies_max_duration_seconds_check CHECK(max_duration_seconds BETWEEN 60 AND 36000);
ALTER TABLE identity_owned_role_activation DROP CONSTRAINT IF EXISTS identity_owned_role_activation_max_duration_seconds_check;
ALTER TABLE identity_owned_role_activation ADD CONSTRAINT identity_owned_role_activation_max_duration_seconds_check CHECK(max_duration_seconds BETWEEN 60 AND 36000);
DO $$ DECLARE definition TEXT; BEGIN
 definition=pg_get_functiondef('identity_authority_policy(jsonb,uuid,text,uuid)'::regprocedure);
 definition=replace(definition,$old$(activation->>'maxDurationSeconds')::numeric NOT BETWEEN 60 AND 28800$old$,$new$(activation->>'maxDurationSeconds')::numeric NOT BETWEEN 60 AND 36000$new$);
 EXECUTE definition;
END $$;

CREATE TABLE IF NOT EXISTS identity_pim_groups (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 name TEXT NOT NULL CHECK(length(btrim(name)) BETWEEN 2 AND 80), description TEXT NOT NULL CHECK(length(description)<=500),
 role TEXT NOT NULL REFERENCES identity_role_activation_policies(role) CHECK(role<>'user'),
 max_duration_seconds INTEGER NOT NULL CHECK(max_duration_seconds BETWEEN 60 AND 36000),
 created_by UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), disabled_at TIMESTAMPTZ,
 reason TEXT NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 500)
);
CREATE UNIQUE INDEX IF NOT EXISTS identity_pim_group_name ON identity_pim_groups(tenant_id,lower(name)) WHERE disabled_at IS NULL;
CREATE TABLE IF NOT EXISTS identity_pim_group_eligibilities (
 eligibility_id UUID PRIMARY KEY REFERENCES identity_pim_eligibilities(id),group_id UUID NOT NULL REFERENCES identity_pim_groups(id),user_id UUID NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS identity_pim_group_eligibility_user ON identity_pim_group_eligibilities(group_id,user_id);
CREATE TABLE IF NOT EXISTS identity_pim_group_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),group_id UUID NOT NULL REFERENCES identity_pim_groups(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action IN('created','disabled')),actor JSONB NOT NULL,details JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION identity_pim_group_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE actor JSONB;home UUID;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PIM groups are retained evidence' USING ERRCODE='23514';END IF;
 IF current_setting('opendirectory.pim_group_seed',true)='on' AND TG_OP='INSERT' AND NEW.created_by IS NULL THEN
  NEW.created_at=clock_timestamp();RETURN NEW;
 END IF;
 actor=NULLIF(current_setting('opendirectory.actor',true),'')::jsonb;home=identity_authority_actor_home(actor);
 IF NEW.tenant_id IS DISTINCT FROM home THEN RAISE EXCEPTION 'Owned PIM group required' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.created_by IS DISTINCT FROM (actor->>'userId')::uuid OR NEW.disabled_at IS NOT NULL THEN RAISE EXCEPTION 'Original PIM group creator required' USING ERRCODE='23514';END IF;
  NEW.created_at=clock_timestamp();
 ELSE
  IF to_jsonb(NEW)-ARRAY['disabled_at','reason'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['disabled_at','reason'] OR OLD.disabled_at IS NOT NULL OR NEW.disabled_at IS NULL
   THEN RAISE EXCEPTION 'PIM group duty is immutable; only disable is permitted' USING ERRCODE='23514';END IF;
  NEW.disabled_at=clock_timestamp();
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_pim_group_guard ON identity_pim_groups;
CREATE TRIGGER identity_pim_group_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_pim_groups FOR EACH ROW EXECUTE FUNCTION identity_pim_group_guard();
CREATE OR REPLACE FUNCTION identity_pim_group_changed() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE actor JSONB;
BEGIN
 IF TG_OP='INSERT' AND NEW.created_by IS NULL THEN actor='{"type":"bootstrap"}'::jsonb;ELSE actor=NULLIF(current_setting('opendirectory.actor',true),'')::jsonb;END IF;
 INSERT INTO identity_pim_group_audit(group_id,tenant_id,action,actor,details) VALUES(NEW.id,NEW.tenant_id,CASE WHEN TG_OP='INSERT' THEN 'created' ELSE 'disabled' END,actor,to_jsonb(NEW));
 IF TG_OP='UPDATE' THEN UPDATE identity_pim_eligibilities SET revoked_at=clock_timestamp() WHERE id IN(SELECT eligibility_id FROM identity_pim_group_eligibilities WHERE group_id=NEW.id) AND revoked_at IS NULL AND expires_at>clock_timestamp();END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_pim_group_changed ON identity_pim_groups;
CREATE TRIGGER identity_pim_group_changed AFTER INSERT OR UPDATE ON identity_pim_groups FOR EACH ROW EXECUTE FUNCTION identity_pim_group_changed();
DROP TRIGGER IF EXISTS identity_pim_group_audit_immutable ON identity_pim_group_audit;
CREATE TRIGGER identity_pim_group_audit_immutable BEFORE UPDATE OR DELETE ON identity_pim_group_audit FOR EACH ROW EXECUTE FUNCTION identity_user_evidence_immutable();
CREATE OR REPLACE FUNCTION identity_pim_group_eligibility_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE duty identity_pim_groups;eligibility identity_pim_eligibilities;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PIM group eligibility binding is immutable' USING ERRCODE='23514';END IF;
 SELECT * INTO duty FROM identity_pim_groups WHERE id=NEW.group_id FOR SHARE;
 SELECT * INTO eligibility FROM identity_pim_eligibilities WHERE id=NEW.eligibility_id FOR SHARE;
 IF duty.id IS NULL OR duty.disabled_at IS NOT NULL OR eligibility.id IS NULL OR eligibility.revoked_at IS NOT NULL
  OR eligibility.expires_at<=clock_timestamp() OR eligibility.user_id IS DISTINCT FROM NEW.user_id
  OR duty.tenant_id IS DISTINCT FROM identity_tenant_id('user',NEW.user_id) OR duty.role IS DISTINCT FROM eligibility.role
  OR eligibility.max_duration_seconds>duty.max_duration_seconds
  THEN RAISE EXCEPTION 'Live owned PIM group and bounded eligibility required' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS identity_pim_group_eligibility_guard ON identity_pim_group_eligibilities;
CREATE TRIGGER identity_pim_group_eligibility_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_pim_group_eligibilities FOR EACH ROW EXECUTE FUNCTION identity_pim_group_eligibility_guard();
CREATE OR REPLACE FUNCTION identity_pim_seed_groups(owner UUID,creator UUID DEFAULT NULL) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE original TEXT;
BEGIN
 original=current_setting('opendirectory.pim_group_seed',true);PERFORM set_config('opendirectory.pim_group_seed','on',true);
 INSERT INTO identity_pim_groups(tenant_id,name,description,role,max_duration_seconds,reason,created_by)
 SELECT owner,name,description,role,36000,'Initiale PIM-Aufgabengruppe; keine Benutzerrechte vergeben',creator FROM(VALUES
 ('Engineering','Geräte aufnehmen und die Bereitstellung vorbereiten','device-enrollment-operator'),
 ('Lizenzen','Lizenzbestand, Zuweisungen und Freigaben verwalten','license-administrator'),
 ('Benutzerverwaltung','Verzeichnisbenutzer und Konten verwalten','user-administrator'),
 ('Apps & SSO','Registrierte Anwendungen und Verbindungen verwalten','application-administrator'),
 ('Richtlinien-Rollout','Richtlinienbereitstellung ausführen und verfolgen','policy-deployment-operator'),
 ('Global Security','Vollständige Administration; unabhängige Genehmigung erforderlich','admin')) AS templates(name,description,role)
 WHERE NOT EXISTS(SELECT 1 FROM identity_pim_groups existing WHERE existing.tenant_id=owner AND existing.name=templates.name);
 PERFORM set_config('opendirectory.pim_group_seed',COALESCE(original,''),true);
END $$;
DO $$ DECLARE owner UUID;BEGIN FOR owner IN SELECT id FROM identity_tenants LOOP PERFORM identity_pim_seed_groups(owner);END LOOP;END $$;
REVOKE ALL ON FUNCTION identity_pim_seed_groups(uuid,uuid) FROM PUBLIC;

DO $$ DECLARE relation TEXT;hook RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_pim_groups','identity_pim_group_eligibilities','identity_pim_group_audit'] LOOP
  REVOKE ALL ON identity_pim_groups,identity_pim_group_eligibilities,identity_pim_group_audit FROM PUBLIC;
  FOR hook IN SELECT * FROM identity_license_user_source_hooks()
   UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_groups_fence','identity_company_offboarding_groups_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_access_fence','identity_company_offboarding_access_fence'
   UNION ALL SELECT 'aaa_identity_company_automation_fence','identity_automation_fence'
   UNION ALL SELECT 'zzz_company_group_rule_fence','identity_company_group_rule_fence'
   UNION ALL SELECT 'zzz_company_group_rule_work_fence','identity_company_group_rule_work_fence' LOOP
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,relation,hook.routine);
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',CASE hook.trigger_name WHEN 'zzz_company_group_rule_fence' THEN 'zzz_company_group_rule_no_truncate' WHEN 'zzz_company_group_rule_work_fence' THEN 'zzz_company_group_rule_work_truncate' ELSE regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate') END,relation,hook.routine);
  END LOOP;
  EXECUTE format('DROP TRIGGER IF EXISTS zzz_company_group_rule_commit_fence ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER zzz_company_group_rule_commit_fence AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS zzz_company_group_rule_work_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER zzz_company_group_rule_work_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_group_rule_work_fence()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER aaa_identity_employee_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_employee_fence()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_employee_effect_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_employee_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_employee_effect_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_employee_effect_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_employee_fence()',relation);
 END LOOP;
END; $$;
