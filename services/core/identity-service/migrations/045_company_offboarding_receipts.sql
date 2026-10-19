CREATE TABLE IF NOT EXISTS identity_company_offboarding_receipts (
 tenant_id UUID NOT NULL REFERENCES identity_tenants(id),workflow_id UUID NOT NULL,user_id UUID NOT NULL,
 expected_revision BIGINT NOT NULL CHECK(expected_revision>0),actor_user_id UUID NOT NULL,
 operation_id UUID UNIQUE REFERENCES identity_directory_user_events(id),action TEXT NOT NULL CHECK(action IN('disabled','already_disabled')),
 before_revision BIGINT NOT NULL CHECK(before_revision>0),after_revision BIGINT NOT NULL CHECK(after_revision>0),
 before_eligibility_revision BIGINT NOT NULL CHECK(before_eligibility_revision>0),after_eligibility_revision BIGINT NOT NULL CHECK(after_eligibility_revision>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),source JSONB NOT NULL,
 transaction_id BIGINT NOT NULL DEFAULT txid_current(),PRIMARY KEY(tenant_id,workflow_id),
 CHECK(user_id<>actor_user_id AND expected_revision=before_revision),
 CHECK(action='disabled' AND operation_id IS NOT NULL AND after_revision>before_revision AND after_eligibility_revision>before_eligibility_revision
  OR action='already_disabled' AND operation_id IS NULL AND after_revision=before_revision AND after_eligibility_revision=before_eligibility_revision)
);
CREATE TABLE IF NOT EXISTS identity_company_offboarding_outbox (
 tenant_id UUID NOT NULL,workflow_id UUID NOT NULL,status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),
 created_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(tenant_id,workflow_id),
 FOREIGN KEY(tenant_id,workflow_id) REFERENCES identity_company_offboarding_receipts(tenant_id,workflow_id)
);
CREATE TABLE IF NOT EXISTS identity_company_offboarding_commit_checks (
 transaction_id BIGINT PRIMARY KEY DEFAULT txid_current(),source JSONB NOT NULL
);

CREATE OR REPLACE FUNCTION identity_company_offboarding_actor(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_authority_owner();PERFORM identity_directory_creation_actor(proof);
 IF proof->>'userId' IS NULL OR proof->>'userId'=proof->'context'->>'userId'
  OR identity_tenant_id('user',(proof->>'userId')::uuid)::text IS DISTINCT FROM proof->'tenant'->>'id'
  OR NOT EXISTS(SELECT 1 FROM identity_company_activations owner WHERE owner.user_id=(proof->'context'->>'userId')::uuid
   AND owner.issuer=proof->>'issuer' AND owner.subject=proof->>'subject' AND owner.tenant_id::text=proof->'tenant'->>'id' AND identity_company_owner_active(owner))
   AND NOT EXISTS(SELECT 1 FROM identity_role_assignments assignment
    JOIN identity_role_activation_policies policy ON policy.role=assignment.role
    LEFT JOIN identity_role_review_leases review ON review.target_kind='assignment' AND review.target_id=assignment.id
    LEFT JOIN identity_pim_requests request ON request.id=assignment.activation_request_id
    LEFT JOIN identity_role_review_leases eligible_review ON eligible_review.target_kind='eligibility' AND eligible_review.target_id=request.eligibility_id
    WHERE assignment.user_id=(proof->'context'->>'userId')::uuid AND assignment.role='admin' AND assignment.revoked_at IS NULL
    AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp()) AND assignment.policy_version=policy.version
    AND (NOT policy.activation_required OR assignment.activation_request_id IS NOT NULL)
    AND (review.id IS NULL OR review.state<>'denied' AND (review.deadline_at IS NULL OR review.deadline_at>identity_role_review_now()))
    AND (eligible_review.id IS NULL OR eligible_review.state<>'denied' AND (eligible_review.deadline_at IS NULL OR eligible_review.deadline_at>identity_role_review_now())))
  THEN RAISE EXCEPTION 'Actual current own-company offboarding authority required' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_authority_owner();
 IF EXISTS(SELECT 1 FROM (VALUES
  ('identity_company_offboarding_receipts','identity_company_offboarding_guard',31,false,'identity_company_offboarding_guard()'),
  ('identity_company_offboarding_outbox','identity_company_offboarding_guard',31,false,'identity_company_offboarding_guard()'),
  ('identity_company_offboarding_receipts','identity_company_offboarding_commit',29,true,'identity_company_offboarding_commit()'),
  ('identity_company_offboarding_outbox','identity_company_offboarding_commit',29,true,'identity_company_offboarding_commit()'),
  ('identity_company_offboarding_commit_checks','identity_company_offboarding_guard',31,false,'identity_company_offboarding_guard()'),
  ('identity_company_offboarding_commit_checks','identity_company_offboarding_commit',29,true,'identity_company_offboarding_commit()'),
  ('users','identity_company_offboarding_commit',25,true,'identity_company_offboarding_commit()')) expected(relation,name,kind,deferred,routine)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(expected.relation) AND tgname=expected.name AND tgenabled='O'
   AND tgtype=expected.kind AND tgdeferrable=expected.deferred AND tginitdeferred=expected.deferred AND tgfoid=to_regprocedure(expected.routine)))
  THEN RAISE EXCEPTION 'Company offboarding receiving guards unavailable' USING ERRCODE='55000';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_validate(tenant UUID,workflow UUID,target UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt identity_company_offboarding_receipts;account users;event identity_directory_user_events;mutation JSONB;
BEGIN
 PERFORM identity_company_offboarding_receiving();
 SELECT * INTO receipt FROM identity_company_offboarding_receipts WHERE tenant_id=tenant AND workflow_id=workflow AND user_id=target;
 SELECT * INTO account FROM users WHERE id=target AND identity_tenant_id('user',id)=tenant;
 IF receipt.workflow_id IS NULL OR account.id IS NULL OR account.enabled OR account.eligibility_revision<>receipt.after_eligibility_revision
  OR receipt.tenant_id::text IS DISTINCT FROM receipt.source->'tenant'->>'id' OR receipt.workflow_id::text IS DISTINCT FROM receipt.source->>'workflowId'
  OR receipt.user_id::text IS DISTINCT FROM receipt.source->>'userId' OR receipt.actor_user_id::text IS DISTINCT FROM receipt.source->'context'->>'userId'
  OR receipt.expected_revision::text IS DISTINCT FROM receipt.source->>'expectedRevision'
  OR receipt.before_eligibility_revision::text IS DISTINCT FROM receipt.source->>'beforeEligibilityRevision'
  OR COALESCE(to_jsonb(receipt.operation_id),'null'::jsonb) IS DISTINCT FROM receipt.source->'operationId'
  OR account.record_revision<receipt.after_revision OR NOT EXISTS(SELECT 1 FROM identity_company_offboarding_outbox
   WHERE tenant_id=tenant AND workflow_id=workflow AND status='pending' AND created_at=receipt.created_at)
  THEN RAISE EXCEPTION 'Exact retained disabled company offboarding generation and pending outbox required' USING ERRCODE='23514';END IF;
 IF receipt.operation_id IS NOT NULL THEN
  SELECT * INTO event FROM identity_directory_user_events WHERE id=receipt.operation_id AND tenant_id=tenant AND user_id=target AND action='update';
  IF event.id IS NULL OR event.actor IS DISTINCT FROM jsonb_build_object('issuer',receipt.source->>'issuer','subject',receipt.source->>'subject','userId',receipt.actor_user_id)
   OR event.details->>'beforeRevision' IS DISTINCT FROM receipt.before_revision::text OR event.details->>'afterRevision' IS DISTINCT FROM receipt.after_revision::text
   OR event.transaction_id<>receipt.transaction_id OR NOT EXISTS(SELECT 1 FROM identity_directory_user_outbox WHERE id=event.id AND tenant_id=tenant AND action='update' AND status='pending')
   OR NOT EXISTS(SELECT 1 FROM identity_user_audit audit JOIN identity_user_outbox outbox ON outbox.user_id=audit.user_id AND outbox.revision=audit.revision
    WHERE audit.user_id=target AND audit.revision=receipt.after_eligibility_revision AND audit.actor=receipt.source->>'subject'
    AND audit.details->'enabled'='false'::jsonb AND outbox.payload->'enabled'='false'::jsonb AND outbox.payload->'deleted'='false'::jsonb)
   THEN RAISE EXCEPTION 'Actual original user mutation and eligibility outbox required' USING ERRCODE='23514';END IF;
 END IF;
 IF receipt.transaction_id=txid_current() THEN
  IF receipt.source IS DISTINCT FROM NULLIF(current_setting('opendirectory.company_offboarding',true),'')::jsonb
   OR account.record_revision<>receipt.after_revision THEN RAISE EXCEPTION 'Original immutable offboarding command required through commit' USING ERRCODE='23514';END IF;
  PERFORM identity_company_offboarding_actor(receipt.source);
  IF receipt.operation_id IS NOT NULL THEN
   mutation=NULLIF(current_setting('opendirectory.user_mutation',true),'')::jsonb;
   IF mutation->>'operationId' IS DISTINCT FROM receipt.operation_id::text OR mutation->'target'->>'id' IS DISTINCT FROM target::text
    OR mutation->'target'->'before'->>'record_revision' IS DISTINCT FROM receipt.before_revision::text
    OR mutation->'target'->'before'->>'eligibility_revision' IS DISTINCT FROM receipt.before_eligibility_revision::text
    OR mutation->'target'->'before'->'enabled' IS DISTINCT FROM 'true'::jsonb OR mutation->'target'->'expectedValues'->'enabled' IS DISTINCT FROM 'false'::jsonb
    THEN RAISE EXCEPTION 'Bound original UserMutator status transition required' USING ERRCODE='23514';END IF;
  ELSIF EXISTS(SELECT 1 FROM identity_directory_user_events WHERE user_id=target AND transaction_id=txid_current()) THEN
   RAISE EXCEPTION 'Already disabled observation cannot fabricate a user mutation' USING ERRCODE='23514';
  END IF;
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;receipt identity_company_offboarding_receipts;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_TABLE_NAME='identity_company_offboarding_commit_checks' THEN
  IF TG_OP='DELETE' AND pg_trigger_depth()>1 AND OLD.transaction_id=txid_current() THEN RETURN OLD;END IF;
  IF TG_OP='TRUNCATE' AND NOT EXISTS(SELECT 1 FROM identity_company_offboarding_commit_checks) THEN RETURN NULL;END IF;
  IF TG_OP<>'INSERT' OR NEW.transaction_id<>txid_current() THEN RAISE EXCEPTION 'Original offboarding commit check required' USING ERRCODE='42501';END IF;
  PERFORM identity_company_offboarding_actor(NEW.source);RETURN NEW;
 END IF;
 IF TG_OP='TRUNCATE' AND NOT EXISTS(SELECT 1 FROM identity_company_offboarding_receipts)
  AND NOT EXISTS(SELECT 1 FROM identity_company_offboarding_outbox) THEN RETURN NULL;END IF;
 proof=NULLIF(current_setting('opendirectory.company_offboarding',true),'')::jsonb;
 IF TG_OP<>'INSERT' OR proof IS NULL THEN RAISE EXCEPTION 'Company offboarding evidence is immutable' USING ERRCODE='42501';END IF;
 PERFORM identity_company_offboarding_actor(proof);
 IF NEW.tenant_id::text IS DISTINCT FROM proof->'tenant'->>'id' OR NEW.workflow_id::text IS DISTINCT FROM proof->>'workflowId'
  THEN RAISE EXCEPTION 'Exact original company workflow required' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='identity_company_offboarding_receipts' THEN
  IF NEW.source IS DISTINCT FROM proof OR NEW.transaction_id<>txid_current() OR NEW.user_id::text IS DISTINCT FROM proof->>'userId'
   OR NEW.actor_user_id::text IS DISTINCT FROM proof->'context'->>'userId' OR NEW.expected_revision::text IS DISTINCT FROM proof->>'expectedRevision'
   OR NEW.before_eligibility_revision::text IS DISTINCT FROM proof->>'beforeEligibilityRevision' OR COALESCE(to_jsonb(NEW.operation_id),'null'::jsonb) IS DISTINCT FROM proof->'operationId'
   THEN RAISE EXCEPTION 'Exact original company offboarding receipt required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO receipt FROM identity_company_offboarding_receipts WHERE tenant_id=NEW.tenant_id AND workflow_id=NEW.workflow_id;
  IF receipt.workflow_id IS NULL OR receipt.source IS DISTINCT FROM proof OR NEW.created_at<>receipt.created_at OR NEW.status<>'pending'
   THEN RAISE EXCEPTION 'Exact pending company offboarding outbox required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.company_offboarding',true),'')::jsonb;
 IF TG_TABLE_NAME='identity_company_offboarding_commit_checks' THEN
  IF TG_OP<>'INSERT' THEN RETURN NULL;END IF;
  PERFORM identity_company_offboarding_actor(NEW.source);
  PERFORM identity_company_offboarding_validate((NEW.source->'tenant'->>'id')::uuid,(NEW.source->>'workflowId')::uuid,(NEW.source->>'userId')::uuid);
  IF NOT EXISTS(SELECT 1 FROM identity_company_offboarding_receipts WHERE tenant_id=(NEW.source->'tenant'->>'id')::uuid
   AND workflow_id=(NEW.source->>'workflowId')::uuid AND expected_revision::text=NEW.source->>'expectedRevision')
   THEN RAISE EXCEPTION 'Original workflow request required at commit' USING ERRCODE='23514';END IF;
  DELETE FROM identity_company_offboarding_commit_checks WHERE transaction_id=NEW.transaction_id;
 ELSIF TG_TABLE_NAME='users' THEN
  IF proof IS NOT NULL AND OLD.id::text=proof->>'userId' THEN
   PERFORM identity_company_offboarding_validate((proof->'tenant'->>'id')::uuid,(proof->>'workflowId')::uuid,OLD.id);
  END IF;
 ELSE
  PERFORM identity_company_offboarding_validate(NEW.tenant_id,NEW.workflow_id,
   (SELECT user_id FROM identity_company_offboarding_receipts WHERE tenant_id=NEW.tenant_id AND workflow_id=NEW.workflow_id));
 END IF;RETURN NULL;
END; $$;

CREATE OR REPLACE FUNCTION identity_company_offboarding_check(proof JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM identity_company_offboarding_receiving();PERFORM identity_company_offboarding_actor(proof);
 INSERT INTO identity_company_offboarding_commit_checks(source) VALUES(proof);
 IF NOT EXISTS(SELECT 1 FROM identity_company_offboarding_commit_checks WHERE transaction_id=txid_current() AND source=proof)
  THEN RAISE EXCEPTION 'Actual deferred company offboarding check required' USING ERRCODE='23514';END IF;
END; $$;

DROP TRIGGER IF EXISTS identity_company_offboarding_commit ON users;
CREATE CONSTRAINT TRIGGER identity_company_offboarding_commit AFTER UPDATE OR DELETE ON users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_commit();
DO $$ DECLARE relation TEXT;hook RECORD;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_company_offboarding_receipts','identity_company_offboarding_outbox','identity_company_offboarding_commit_checks'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_offboarding_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_company_offboarding_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_offboarding_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_company_offboarding_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_company_offboarding_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_company_offboarding_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_company_offboarding_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_company_offboarding_commit()',relation);
  FOR hook IN SELECT * FROM identity_license_user_source_hooks() UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence' LOOP
   EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',hook.trigger_name,relation);
   EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,relation,hook.routine);
   EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation);
   EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation,hook.routine);
  END LOOP;
  EXECUTE format('REVOKE ALL ON TABLE %I FROM PUBLIC',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_company_offboarding_actor(jsonb)','identity_company_offboarding_receiving()',
  'identity_company_offboarding_validate(uuid,uuid,uuid)','identity_company_offboarding_guard()','identity_company_offboarding_commit()','identity_company_offboarding_check(jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
