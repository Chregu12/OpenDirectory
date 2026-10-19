CREATE OR REPLACE FUNCTION identity_authority_actor_home(proof JSONB) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE owner UUID;
BEGIN
 IF jsonb_typeof(proof) IS DISTINCT FROM 'object' OR COALESCE(proof->>'userId','')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  OR jsonb_typeof(proof->'issuer') IS DISTINCT FROM 'string' OR length(proof->>'issuer') NOT BETWEEN 8 AND 2048
  OR jsonb_typeof(proof->'subject') IS DISTINCT FROM 'string' OR length(proof->>'subject') NOT BETWEEN 1 AND 255
  THEN RAISE EXCEPTION 'Canonical authority actor required' USING ERRCODE='42501';END IF;
 SELECT tenant.id INTO owner FROM users account JOIN identity_subject_links link ON link.user_id=account.id
  JOIN identity_tenants tenant ON tenant.id=identity_tenant_id('user',account.id)
  JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=tenant.id
  WHERE account.id=(proof->>'userId')::uuid AND link.issuer=proof->>'issuer' AND link.subject=proof->>'subject' AND account.enabled AND tenant.enabled
   AND (NOT(proof ? 'revision') OR account.authorization_revision::text=proof->>'revision')
   AND (NOT(proof ? 'linkRevision') OR link.authorization_revision::text=proof->>'linkRevision');
 IF owner IS NULL THEN RAISE EXCEPTION 'Current owned authority actor required' USING ERRCODE='42501';END IF;
 RETURN owner;
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_target_tenant_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor JSONB;owner UUID;recipient UUID;row_owner NAME;rule identity_role_review_policies;data JSONB;
BEGIN
 SELECT pg_catalog.pg_get_userbyid(relowner) INTO row_owner FROM pg_catalog.pg_class WHERE oid=TG_RELID;
 IF NOT pg_catalog.pg_has_role(session_user,row_owner,'USAGE') OR current_setting('role')<>'none'
  THEN RAISE EXCEPTION 'Actual receiving database owner required for legacy authority writes' USING ERRCODE='42501';END IF;
 BEGIN actor=NULLIF(current_setting('opendirectory.actor',true),'')::jsonb;EXCEPTION WHEN invalid_text_representation THEN actor=NULL;END;
 IF actor IS NULL OR jsonb_typeof(actor)<>'object' OR NOT(actor ?| ARRAY['userId','issuer','subject']) THEN
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 owner=identity_authority_actor_home(actor-ARRAY['revision','linkRevision']);data=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;recipient=(data->>'user_id')::uuid;
 IF identity_tenant_id('user',recipient) IS DISTINCT FROM owner
  THEN RAISE EXCEPTION 'Owned authority target not found' USING ERRCODE='23503';END IF;
 PERFORM id FROM identity_tenants WHERE id=owner AND enabled FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Current owned authority tenant required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_pim_requests' THEN
  IF TG_OP='INSERT' OR NEW.state IN('approved','active') THEN
   IF NEW.request_authority->>'userId' IS DISTINCT FROM recipient::text OR identity_authority_actor_home(NEW.request_authority-ARRAY['revision','linkRevision']) IS DISTINCT FROM owner
    OR NEW.decision_authority IS NOT NULL AND identity_authority_actor_home(NEW.decision_authority-ARRAY['revision','linkRevision']) IS DISTINCT FROM owner
    THEN RAISE EXCEPTION 'Owned PIM lineage required' USING ERRCODE='23503';END IF;
  END IF;
 END IF;
 IF TG_TABLE_NAME='identity_role_review_leases' AND TG_OP<>'DELETE' THEN
  SELECT * INTO rule FROM identity_role_review_policies WHERE id=NEW.policy_id;
  IF rule.id IS NULL OR EXISTS(SELECT 1 FROM unnest(rule.reviewer_user_ids) reviewer WHERE identity_tenant_id('user',reviewer) IS DISTINCT FROM owner)
   THEN RAISE EXCEPTION 'Owned authority review recipients required' USING ERRCODE='23503';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;

DO $$ DECLARE relation TEXT;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_role_assignments','identity_pim_eligibilities','identity_pim_requests','identity_role_review_leases'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_target_tenant ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_authority_target_tenant BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_target_tenant_guard()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_authority_actor_home(jsonb)','identity_authority_target_tenant_guard()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
