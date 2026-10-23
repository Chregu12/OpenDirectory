ALTER TABLE identity_automation_enrollments ADD COLUMN IF NOT EXISTS company_tenant JSONB;
CREATE OR REPLACE FUNCTION identity_automation_snapshot(data JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT (data-'artifact_content')-CASE WHEN data->'rule_id'='null'::jsonb THEN 'rule_id' ELSE '' END-CASE WHEN data->'progress'='null'::jsonb THEN 'progress' ELSE '' END
 -CASE WHEN data->'on_change'='false'::jsonb THEN 'on_change' ELSE '' END-CASE WHEN data->'source_checkpoint'='null'::jsonb THEN 'source_checkpoint' ELSE '' END
 -CASE WHEN data->'source_job_id'='null'::jsonb THEN 'source_job_id' ELSE '' END-CASE WHEN data->'event_source'='null'::jsonb THEN 'event_source' ELSE '' END
 -CASE WHEN data->'company_tenant'='null'::jsonb THEN 'company_tenant' ELSE '' END;
$$;
CREATE OR REPLACE FUNCTION identity_automation_company_app_guard() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE binding JSONB;actor JSONB;
BEGIN
 actor=NULLIF(current_setting('opendirectory.company_automation',true),'')::jsonb;
 IF TG_TABLE_NAME='identity_automation_enrollments' THEN
  IF NEW.company_tenant IS DISTINCT FROM actor->'companyTenant' THEN RAISE EXCEPTION 'Original app company binding required' USING ERRCODE='42501';END IF;binding=NEW.company_tenant;
 ELSE
  SELECT company_tenant INTO binding FROM identity_automation_enrollments WHERE id=NEW.enrollment_id;
  IF binding IS NOT NULL AND(binding IS DISTINCT FROM NEW.approval->'tenant' OR binding->>'id' IS DISTINCT FROM NEW.tenant_id::text) THEN RAISE EXCEPTION 'Company app cannot acquire a foreign grant' USING ERRCODE='42501';END IF;
 END IF;
 IF binding IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identity_tenants tenant WHERE tenant.enabled AND binding=jsonb_build_object('id',tenant.id,'version',tenant.version::text,'generation',tenant.generation::text))
  THEN RAISE EXCEPTION 'Current original company app tenant required' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_automation_company_app_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgname='identity_automation_company_app_before' AND tgtype=23
  AND tgfoid='identity_automation_company_app_guard()'::regprocedure AND tgrelid IN('identity_automation_enrollments'::regclass,'identity_automation_grants'::regclass))<>2
  THEN RAISE EXCEPTION 'Original company app binding receiving unavailable' USING ERRCODE='42501';END IF;
END; $$;
DO $$ DECLARE relation TEXT;signature TEXT;definition TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_automation_enrollments','identity_automation_grants'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_automation_company_app_before BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION identity_automation_company_app_guard()',relation);
 END LOOP;
 definition=pg_get_functiondef('identity_automation_receiving()'::regprocedure);
 definition=replace(definition,'identity_automation_receiver_manifest)<>12','identity_automation_receiver_manifest)<>14');
 IF strpos(definition,'PERFORM identity_automation_company_app_receiving();')=0 THEN definition=replace(definition,E'BEGIN\n',E'BEGIN\n PERFORM identity_automation_company_app_receiving();\n');END IF;EXECUTE definition;
 FOREACH signature IN ARRAY ARRAY['identity_automation_snapshot(jsonb)','identity_automation_company_app_guard()','identity_automation_company_app_receiving()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
END; $$;
INSERT INTO identity_automation_receiver_manifest SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY['identity_automation_company_app_guard()','identity_automation_company_app_receiving()']) signature ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
UPDATE identity_automation_receiver_manifest SET digest=md5(pg_get_functiondef(to_regprocedure(signature)));
