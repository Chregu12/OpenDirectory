-- Current local entitlement is checked independently from stored provider links.
CREATE TABLE IF NOT EXISTS company_microsoft_delivery_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);

CREATE OR REPLACE FUNCTION company_microsoft_local(pool_identity UUID,authority JSONB) RETURNS JSONB LANGUAGE plpgsql VOLATILE AS $$
DECLARE catalog license_catalog;allocation license_assignments;origins JSONB;
BEGIN
 PERFORM license_company_receiving();PERFORM company_blueprint_assignment_retirement_receiving();
 SELECT * INTO catalog FROM license_catalog WHERE id=pool_identity AND business_tenant_id=(authority#>>'{tenant,id}')::uuid;
 IF catalog.id IS NULL OR NOT license_company_pool_valid(catalog.id) OR authority->'target' IS NULL OR authority->'target'='null'::jsonb THEN
  RAISE EXCEPTION 'Current own company pool and canonical target required' USING ERRCODE='42501';END IF;
 SELECT * INTO allocation FROM license_assignments WHERE license_id=pool_identity AND assignee_type='user' AND assignee_id=authority#>>'{target,id}';
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sourceType',origin.source_type,'sourceId',origin.source_id,'grantId',origin.grant_id,
  'eligibilityRevision',grant_row.eligibility_revision::text,'live',expiry.value IS NULL OR expiry.value>clock_timestamp(),
  'deadline',CASE WHEN isfinite(expiry.value) THEN to_char(expiry.value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') ELSE NULL END,
  'bindingValid',CASE WHEN origin.source_type='direct' THEN true ELSE binding.id IS NOT NULL AND binding.status='active' AND company_blueprint_assignment_binding_valid(binding) END,
  'rule',CASE WHEN rule.id IS NULL THEN NULL ELSE jsonb_build_object('id',rule.id,'groupId',rule.group_id,'revision',rule.revision::text,'status',rule.status) END)
  ORDER BY origin.source_type,origin.source_id,origin.grant_id),'[]'::jsonb) INTO origins
 FROM license_assignment_sources origin JOIN license_grants grant_row ON grant_row.id=origin.grant_id
 CROSS JOIN LATERAL(SELECT license_member_source_expiry(origin.grant_id,origin.user_id,origin.expires_at) AS value) expiry
 LEFT JOIN company_blueprint_user_assignments binding ON origin.source_type='blueprint' AND binding.id::text=origin.source_id
  AND binding.tenant_id=catalog.business_tenant_id AND binding.user_id::text=origin.user_id
 LEFT JOIN company_license_groups rule ON rule.blueprint_id=binding.blueprint_id AND rule.tenant_id=catalog.business_tenant_id AND rule.pool_id=pool_identity
 WHERE origin.license_id=pool_identity AND origin.user_id=authority#>>'{target,id}';
 IF jsonb_array_length(origins)>10000 THEN RAISE EXCEPTION 'Bounded complete company origins required' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('poolId',catalog.id,'poolRevision',catalog.business_revision::text,'target',authority->'target',
  'assignment',CASE WHEN allocation.id IS NULL THEN NULL ELSE jsonb_build_object('id',allocation.id,'eligibilityRevision',allocation.eligibility_revision::text) END,'origins',origins);
END $$;

CREATE OR REPLACE FUNCTION company_microsoft_delivery_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 PERFORM company_microsoft_receiving();
 IF (SELECT count(*) FROM company_microsoft_delivery_manifest)<>2 OR EXISTS(SELECT 1 FROM company_microsoft_delivery_manifest manifest
  WHERE to_regprocedure(manifest.signature) IS NULL OR manifest.digest<>md5(pg_get_functiondef(to_regprocedure(manifest.signature)))) THEN
  RAISE EXCEPTION 'Company Microsoft delivery evidence unavailable' USING ERRCODE='42501';END IF;
END $$;

INSERT INTO company_microsoft_delivery_manifest(signature,digest)
 SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY[
 'company_microsoft_local(uuid,jsonb)','company_microsoft_delivery_receiving()']) signature
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
REVOKE ALL ON FUNCTION company_microsoft_local(uuid,jsonb),company_microsoft_delivery_receiving() FROM PUBLIC;
