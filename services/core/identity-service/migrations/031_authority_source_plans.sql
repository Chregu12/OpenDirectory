CREATE OR REPLACE FUNCTION identity_authority_candidate_snapshot(identifier UUID,owner UUID,authority TEXT) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE candidate identity_authority_candidates;inventory JSONB;scope JSONB;relation TEXT;routine TEXT;
BEGIN
 PERFORM identity_authority_owner();
 SELECT * INTO candidate FROM identity_authority_candidates WHERE id=identifier AND tenant_id=owner AND manifest->>'issuer'=authority;
 IF NOT FOUND THEN RAISE EXCEPTION 'Owned authority candidate not found' USING ERRCODE='23503';END IF;
 IF candidate.transaction_id=txid_current() THEN RAISE EXCEPTION 'A committed authority draft is required' USING ERRCODE='42501';END IF;
 FOREACH relation IN ARRAY ARRAY['identity_authority_candidates','identity_authority_candidate_events','identity_authority_candidate_outbox'] LOOP
  routine=CASE WHEN relation='identity_authority_candidates' THEN 'identity_authority_candidate_guard' ELSE 'identity_authority_candidate_evidence' END;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname=routine AND tgenabled='O' AND tgtype=31 AND tgfoid=(routine||'()')::regprocedure)
   OR relation='identity_authority_candidates' AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_authority_candidate_commit'
    AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_authority_candidate_commit()'::regprocedure)
   THEN RAISE EXCEPTION 'Authority candidate receiving guards unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 inventory=identity_authority_inventory(owner,authority);
 scope=jsonb_build_object('id',candidate.id,'tenantId',owner,'tenantVersion',candidate.tenant_version::text,'tenantGeneration',candidate.tenant_generation::text,
  'manifestSha256',candidate.manifest_sha256,'inventorySha256',candidate.inventory_sha256,'createdAt',candidate.created_at);
 IF candidate.state<>'draft' OR candidate.valid_until<=clock_timestamp() OR inventory->'tenant'->'enabled' IS DISTINCT FROM 'true'::jsonb
  OR inventory->'tenant'->>'version' IS DISTINCT FROM candidate.tenant_version::text OR inventory->'tenant'->>'generation' IS DISTINCT FROM candidate.tenant_generation::text
  OR candidate.inventory IS DISTINCT FROM inventory OR candidate.inventory_sha256 IS DISTINCT FROM identity_authority_hash(inventory)
  OR candidate.manifest_sha256 IS DISTINCT FROM identity_authority_hash(candidate.manifest)
  OR candidate.valid_until IS DISTINCT FROM identity_authority_stage_until(candidate.manifest,candidate.inventory,candidate.created_at)
  OR NOT EXISTS(SELECT 1 FROM identity_authority_candidate_events event JOIN identity_authority_candidate_outbox outbox USING(id)
   WHERE event.id=candidate.id AND event.tenant_id=owner AND outbox.tenant_id=owner AND event.action='migration-staged' AND outbox.action=event.action AND outbox.status='pending'
    AND event.scope_sha256=identity_authority_hash(scope)
    AND event.actor=jsonb_build_object('kind','offline-authority-stage','databaseRole',candidate.reviewed_by,'reviewAnchorUserId',candidate.manifest->>'reviewAnchorUserId')
    AND event.details=jsonb_build_object('reason',candidate.manifest->>'reason','manifestSha256',candidate.manifest_sha256,'inventorySha256',candidate.inventory_sha256,'state','draft','canAuthorize',false))
  THEN RAISE EXCEPTION 'Current exact committed draft and receiving evidence required' USING ERRCODE='42501';END IF;
 PERFORM identity_authority_manifest(candidate.manifest,inventory);
 RETURN jsonb_build_object('schemaVersion',1,'canAuthorize',false,'candidateId',candidate.id,'tenant',inventory->'tenant','issuer',authority,
  'manifestSha256',candidate.manifest_sha256,'inventorySha256',candidate.inventory_sha256,'validUntil',candidate.valid_until,'manifest',candidate.manifest,'inventory',inventory);
END; $$;
DO $$ BEGIN
 EXECUTE format('ALTER FUNCTION identity_authority_candidate_snapshot(uuid,uuid,text) SET search_path TO %I,pg_catalog,pg_temp',current_schema());
 ALTER FUNCTION identity_authority_candidate_snapshot(uuid,uuid,text) SET timezone TO 'UTC';
 REVOKE ALL ON FUNCTION identity_authority_candidate_snapshot(uuid,uuid,text) FROM PUBLIC;
END; $$;
