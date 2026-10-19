CREATE TABLE IF NOT EXISTS identity_authority_candidates (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),tenant_version BIGINT NOT NULL,tenant_generation BIGINT NOT NULL,
 state TEXT NOT NULL DEFAULT 'draft' CHECK(state='draft'),manifest JSONB NOT NULL,inventory JSONB NOT NULL,
 manifest_sha256 TEXT NOT NULL CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$'),inventory_sha256 TEXT NOT NULL CHECK(inventory_sha256 ~ '^[a-f0-9]{64}$'),
 reviewed_by NAME NOT NULL DEFAULT session_user,created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL CHECK(valid_until>created_at),
 transaction_id BIGINT NOT NULL DEFAULT txid_current(),UNIQUE(tenant_id,manifest_sha256,inventory_sha256)
);
CREATE INDEX IF NOT EXISTS identity_authority_candidates_transaction ON identity_authority_candidates(transaction_id);
CREATE INDEX IF NOT EXISTS identity_authority_role_origin ON identity_role_audit(assignment_id,created_at,id);
CREATE INDEX IF NOT EXISTS identity_authority_pim_origin ON identity_pim_audit(entity_id,created_at,id);
CREATE INDEX IF NOT EXISTS identity_authority_review_origin ON identity_role_review_audit(lease_id,created_at,id);
CREATE INDEX IF NOT EXISTS identity_authority_review_policy_origin ON identity_role_review_audit(policy_id,created_at,id) WHERE lease_id IS NULL;
CREATE OR REPLACE FUNCTION identity_authority_catalog() RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT '{"roles":["access-review-administrator","access-review-reader","access-reviewer","admin","application-access-administrator","application-access-reader","application-administrator","application-authentication-administrator","application-authentication-reader","application-reader","authentication-policy-administrator","authentication-policy-reader","compliance-reader","device-enrollment-operator","directory-reader","gateway-administrator","gateway-key-administrator","gateway-reader","gateway-webhook-administrator","group-administrator","group-review-administrator","group-review-reader","group-reviewer","license-administrator","license-approver","license-delegate","license-delegation-review-administrator","license-delegation-review-reader","license-delegation-reviewer","license-eligibility-reader","license-fulfillment-operator","license-fulfillment-reader","license-group-reader","license-manager","license-provider-administrator","license-reader","license-review-administrator","license-review-reader","license-reviewer","license-scope-activation-reviewer","license-scope-administrator","license-scope-policy-administrator","license-scope-policy-reader","license-scope-reader","operations-reader","ou-administrator","pim-administrator","pim-approver","pim-reader","policy-administrator","policy-deployment-operator","policy-publication-reviewer","policy-reader","privileged-access-policy-administrator","privileged-access-policy-reader","role-administrator","role-reader","session-administrator","user","user-administrator","user-lifecycle-operator","user-profile-editor"],"lockedMfaRoles":["access-review-administrator","access-reviewer","authentication-policy-administrator","group-review-administrator","group-reviewer","license-delegate","license-delegation-review-administrator","license-delegation-reviewer","license-review-administrator","license-reviewer","license-scope-activation-reviewer","license-scope-administrator","license-scope-policy-administrator","policy-administrator","policy-publication-reviewer","privileged-access-policy-administrator"],"protectedRoles":["access-review-administrator","access-reviewer","admin","application-authentication-administrator","authentication-policy-administrator","group-review-administrator","group-reviewer","license-delegate","license-delegation-review-administrator","license-delegation-reviewer","license-fulfillment-operator","license-provider-administrator","license-review-administrator","license-reviewer","license-scope-activation-reviewer","license-scope-administrator","license-scope-policy-administrator","pim-administrator","pim-approver","policy-administrator","policy-publication-reviewer","privileged-access-policy-administrator","role-administrator"]}'::jsonb;
$$;
CREATE TABLE IF NOT EXISTS identity_authority_candidate_events (
 id UUID PRIMARY KEY REFERENCES identity_authority_candidates(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action='migration-staged'),actor JSONB NOT NULL,details JSONB NOT NULL,scope_sha256 TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS identity_authority_candidate_outbox (
 id UUID PRIMARY KEY REFERENCES identity_authority_candidate_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 action TEXT NOT NULL CHECK(action='migration-staged'),status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION identity_authority_hash(data JSONB) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT encode(sha256(convert_to(data::text,'UTF8')),'hex');
$$;
CREATE OR REPLACE FUNCTION identity_authority_owner() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE owner_role NAME;
BEGIN
 SELECT pg_catalog.pg_get_userbyid(relowner) INTO owner_role FROM pg_catalog.pg_class WHERE oid='identity_authority_candidates'::regclass;
 IF NOT pg_catalog.pg_has_role(session_user,owner_role,'USAGE') OR current_setting('role')<>'none'
  THEN RAISE EXCEPTION 'Actual database owner required for offline authority review' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_actor(data TEXT,owner UUID,authority TEXT) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor JSONB;identifier UUID;
BEGIN
 BEGIN actor=data::jsonb;EXCEPTION WHEN OTHERS THEN RETURN 2;END;
 IF jsonb_typeof(actor)<>'object' THEN RETURN 2;END IF;
 IF actor->>'kind'='offline-bootstrap' AND (SELECT count(*) FROM jsonb_object_keys(actor))=2 AND actor ? 'reason'
  AND jsonb_typeof(actor->'reason')='string' AND length(btrim(actor->>'reason')) BETWEEN 10 AND 500 AND actor->>'reason'!~'[[:cntrl:]]' THEN RETURN 1;END IF;
 IF actor ? 'kind' THEN RETURN 2;END IF;
 IF COALESCE(actor->>'userId','')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  OR jsonb_typeof(actor->'issuer') IS DISTINCT FROM 'string' OR jsonb_typeof(actor->'subject') IS DISTINCT FROM 'string'
  OR COALESCE(actor->>'issuer','')='' OR COALESCE(actor->>'subject','')='' THEN RETURN 2;END IF;
 identifier=(actor->>'userId')::uuid;
 IF actor->>'issuer'<>authority OR identity_tenant_id('user',identifier) IS DISTINCT FROM owner
  OR NOT EXISTS(SELECT 1 FROM identity_subject_tenant_bindings binding WHERE binding.issuer=authority AND binding.subject=actor->>'subject' AND binding.tenant_id=owner)
  THEN RETURN 3;END IF;
 RETURN 0;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_state(data JSONB) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT data||COALESCE((SELECT jsonb_object_agg(field,data->>field) FROM unnest(ARRAY['version','cycle','policy_version','authorization_revision','eligibility_revision','tenant_generation']) field WHERE data ? field),'{}'::jsonb);
$$;
CREATE OR REPLACE FUNCTION identity_authority_legacy_live(kind TEXT,data JSONB,authority TEXT) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE identifier UUID;recipient UUID;parent JSONB;
BEGIN
 identifier=(data->>'id')::uuid;recipient=(data->>'user_id')::uuid;
 IF NOT identity_tenant_user_enabled(recipient) OR NOT EXISTS(SELECT 1 FROM identity_subject_links link JOIN identity_subject_tenant_bindings binding
  ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=identity_tenant_id('user',recipient) WHERE link.issuer=authority AND link.user_id=recipient) THEN RETURN false;END IF;
 IF kind='assignment' THEN
  RETURN data->'revoked_at'='null'::jsonb AND (data->'expires_at'='null'::jsonb OR (data->>'expires_at')::timestamptz>clock_timestamp())
   AND EXISTS(SELECT 1 FROM identity_role_activation_policies policy WHERE policy.role=data->>'role' AND policy.version=(data->>'policy_version')::bigint
    AND (NOT policy.activation_required OR data->'activation_request_id'<>'null'::jsonb))
   AND NOT EXISTS(SELECT 1 FROM identity_role_review_leases lease WHERE lease.target_kind='assignment' AND lease.target_id=identifier
    AND (lease.state='denied' OR lease.deadline_at<=identity_role_review_now()))
   AND (data->'activation_request_id'='null'::jsonb OR EXISTS(SELECT 1 FROM identity_pim_requests request JOIN identity_pim_eligibilities eligibility ON eligibility.id=request.eligibility_id
    WHERE request.id=(data->>'activation_request_id')::uuid AND request.user_id=recipient AND request.state='active'
     AND eligibility.user_id=recipient AND eligibility.revoked_at IS NULL AND eligibility.expires_at>clock_timestamp() AND identity_role_review_eligible(eligibility.id)));
 ELSIF kind='eligibility' THEN
  RETURN data->'revoked_at'='null'::jsonb AND (data->>'expires_at')::timestamptz>clock_timestamp() AND identity_role_review_eligible(identifier);
 ELSIF kind='request' THEN
  SELECT to_jsonb(assignment) INTO parent FROM identity_role_assignments assignment WHERE activation_request_id=identifier AND user_id=recipient;
  RETURN data->>'state'='active' AND parent IS NOT NULL AND identity_authority_legacy_live('assignment',parent,authority);
 ELSE
  IF data->>'state'='denied' OR data->'deadline_at'<>'null'::jsonb AND (data->>'deadline_at')::timestamptz<=identity_role_review_now() THEN RETURN false;END IF;
  IF data->>'target_kind'='assignment' THEN SELECT to_jsonb(assignment) INTO parent FROM identity_role_assignments assignment WHERE id=(data->>'target_id')::uuid AND user_id=recipient;
  ELSE SELECT to_jsonb(eligibility) INTO parent FROM identity_pim_eligibilities eligibility WHERE id=(data->>'target_id')::uuid AND user_id=recipient;END IF;
  RETURN parent IS NOT NULL AND identity_authority_legacy_live(data->>'target_kind',parent,authority);
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_inventory(owner UUID,authority TEXT) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE tenant JSONB;accounts JSONB;profiles JSONB;activation JSONB;rules JSONB;catalog JSONB;family TEXT;relation TEXT;source JSONB;audits JSONB;related JSONB;result JSONB='[]';
 actor JSONB;origin INTEGER;role_name TEXT;policy identity_role_review_policies;amount INTEGER=0;
BEGIN
 PERFORM identity_authority_owner();
 IF authority IS NULL OR length(authority) NOT BETWEEN 8 AND 2048 OR authority!~'^https?://[^/?#@[:space:]]+([^?#[:space:]]*)$'
  THEN RAISE EXCEPTION 'Explicit bounded authority issuer required' USING ERRCODE='23514';END IF;
 SELECT jsonb_build_object('id',id,'version',version::text,'generation',generation::text,'enabled',enabled) INTO tenant FROM identity_tenants WHERE id=owner;
 IF tenant IS NULL THEN RAISE EXCEPTION 'Authority review tenant not found' USING ERRCODE='23503';END IF;
 catalog=identity_authority_catalog();
 IF (SELECT jsonb_agg(role ORDER BY role COLLATE "C") FROM identity_role_authentication) IS DISTINCT FROM catalog->'roles'
  OR (SELECT jsonb_agg(role ORDER BY role COLLATE "C") FROM identity_role_activation_policies) IS DISTINCT FROM catalog->'roles'
  THEN RAISE EXCEPTION 'Complete supported legacy role catalog required' USING ERRCODE='23514';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',account.id,'enabled',account.enabled,'canonical',EXISTS(SELECT 1 FROM identity_subject_links link JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=owner WHERE link.user_id=account.id AND link.issuer=authority),'authorityRevision',account.authorization_revision::text,
  'eligibilityRevision',account.eligibility_revision::text,'tenantGeneration',account.tenant_generation::text,
  'linkCount',(SELECT count(*) FROM (SELECT 1 FROM identity_subject_links WHERE user_id=account.id LIMIT 1001) links),
  'linksSha256',identity_authority_hash(COALESCE((SELECT jsonb_agg(to_jsonb(link) ORDER BY link.issuer,link.subject) FROM (SELECT * FROM identity_subject_links WHERE user_id=account.id ORDER BY issuer,subject LIMIT 1001) link),'[]'))) ORDER BY account.id),'[]') INTO accounts
 FROM (SELECT account.* FROM users account JOIN identity_tenant_ownership ownership ON ownership.resource_kind='user' AND ownership.resource_id=account.id WHERE ownership.tenant_id=owner ORDER BY account.id LIMIT 1001) account;
 IF jsonb_array_length(accounts)>1000 THEN RAISE EXCEPTION 'Authority review user boundary exceeded' USING ERRCODE='54000';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(accounts) account WHERE (account->>'linkCount')::integer>1000) THEN RAISE EXCEPTION 'Authority review link boundary exceeded' USING ERRCODE='54000';END IF;
 SELECT jsonb_agg(jsonb_build_object('role',role,'version',version::text,'required',mfa_required,'maxAgeSeconds',max_age_seconds,'beforeSha256',identity_authority_hash(to_jsonb(setting))) ORDER BY role COLLATE "C") INTO profiles FROM identity_role_authentication setting;
 SELECT jsonb_agg(jsonb_build_object('role',role,'version',version::text,'required',activation_required,'maxDurationSeconds',max_duration_seconds,
  'reviewerCount',cardinality(reviewer_user_ids),'reviewerHomesCoherent',NOT EXISTS(SELECT 1 FROM unnest(reviewer_user_ids) reviewer WHERE identity_tenant_id('user',reviewer) IS DISTINCT FROM owner),'beforeSha256',identity_authority_hash(to_jsonb(setting))) ORDER BY role COLLATE "C") INTO activation FROM identity_role_activation_policies setting;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',setting.id,'role',setting.role,'version',setting.version::text,'intervalSeconds',setting.interval_seconds,'windowSeconds',setting.window_seconds,
  'retired',setting.retired_at IS NOT NULL,'reviewerCount',cardinality(setting.reviewer_user_ids),'reviewerHomesCoherent',NOT EXISTS(SELECT 1 FROM unnest(setting.reviewer_user_ids) reviewer WHERE identity_tenant_id('user',reviewer) IS DISTINCT FROM owner),'beforeSha256',identity_authority_hash(to_jsonb(setting))) ORDER BY setting.id),'[]') INTO rules
 FROM (SELECT * FROM identity_role_review_policies WHERE retired_at IS NULL OR id IN(SELECT lease.policy_id FROM identity_role_review_leases lease JOIN identity_tenant_ownership ownership ON ownership.resource_kind='user' AND ownership.resource_id=lease.user_id WHERE ownership.tenant_id=owner) ORDER BY id LIMIT 1001) setting;
 IF jsonb_array_length(rules)>1000 THEN RAISE EXCEPTION 'Authority review policy boundary exceeded' USING ERRCODE='54000';END IF;
 FOREACH family IN ARRAY ARRAY['assignment','eligibility','request','review'] LOOP
  relation=CASE family WHEN 'assignment' THEN 'identity_role_assignments' WHEN 'eligibility' THEN 'identity_pim_eligibilities' WHEN 'request' THEN 'identity_pim_requests' ELSE 'identity_role_review_leases' END;
  FOR source IN EXECUTE format('SELECT to_jsonb(source) FROM %I source JOIN identity_tenant_ownership ownership ON ownership.resource_kind=''user'' AND ownership.resource_id=source.user_id WHERE ownership.tenant_id=$1 ORDER BY source.id LIMIT 1001',relation) USING owner LOOP
   amount=amount+1;IF amount>1000 THEN RAISE EXCEPTION 'Authority source graph boundary exceeded' USING ERRCODE='54000';END IF;
   IF family='assignment' THEN
    SELECT COALESCE(jsonb_agg(to_jsonb(evidence) ORDER BY evidence.created_at,evidence.id),'[]') INTO audits FROM (SELECT * FROM identity_role_audit WHERE assignment_id=(source->>'id')::uuid ORDER BY created_at,id LIMIT 1001) evidence;
   ELSIF family IN ('eligibility','request') THEN
    SELECT COALESCE(jsonb_agg(to_jsonb(evidence) ORDER BY evidence.created_at,evidence.id),'[]') INTO audits FROM (SELECT * FROM identity_pim_audit WHERE entity_id=(source->>'id')::uuid ORDER BY created_at,id LIMIT 1001) evidence;
   ELSE
    SELECT COALESCE(jsonb_agg(to_jsonb(evidence) ORDER BY evidence.created_at,evidence.id),'[]') INTO audits FROM (SELECT * FROM identity_role_review_audit WHERE lease_id=(source->>'id')::uuid OR policy_id=(source->>'policy_id')::uuid AND lease_id IS NULL ORDER BY created_at,id LIMIT 1001) evidence;
   END IF;
   IF jsonb_array_length(audits)>1000 THEN RAISE EXCEPTION 'Authority source evidence boundary exceeded' USING ERRCODE='54000';END IF;
   origin=CASE WHEN jsonb_array_length(audits)=0 THEN 2 ELSE 0 END;
   FOR actor IN SELECT value FROM jsonb_array_elements(audits) LOOP origin=greatest(origin,identity_authority_actor(actor->>'actor',owner,authority));END LOOP;
   related='[]';role_name=source->>'role';
   IF family IN ('assignment','eligibility') THEN
    SELECT COALESCE(jsonb_agg(jsonb_build_object('kind','review','id',id) ORDER BY id),'[]') INTO related FROM identity_role_review_leases WHERE target_kind=family AND target_id=(source->>'id')::uuid;
    IF family='assignment' AND source->'activation_request_id'<>'null'::jsonb THEN related=related||jsonb_build_array(jsonb_build_object('kind','request','id',source->>'activation_request_id'));END IF;
   ELSIF family='request' THEN
    related=jsonb_build_array(jsonb_build_object('kind','eligibility','id',source->>'eligibility_id'));
    SELECT role INTO role_name FROM identity_pim_eligibilities WHERE id=(source->>'eligibility_id')::uuid;
    related=related||COALESCE((SELECT jsonb_agg(jsonb_build_object('kind','assignment','id',id) ORDER BY id) FROM identity_role_assignments WHERE activation_request_id=(source->>'id')::uuid),'[]');
    origin=greatest(origin,identity_authority_actor((source->'request_authority')::text,owner,authority));
    IF source->'decision_authority'<>'null'::jsonb THEN origin=greatest(origin,identity_authority_actor((source->'decision_authority')::text,owner,authority));END IF;
   ELSE
    related=jsonb_build_array(jsonb_build_object('kind',source->>'target_kind','id',source->>'target_id'));
    SELECT * INTO policy FROM identity_role_review_policies WHERE id=(source->>'policy_id')::uuid;role_name=policy.role;
    IF EXISTS(SELECT 1 FROM unnest(policy.reviewer_user_ids) reviewer WHERE identity_tenant_id('user',reviewer) IS DISTINCT FROM owner) THEN origin=3;END IF;
   END IF;
   result=result||jsonb_build_array(jsonb_build_object('kind',family,'id',source->>'id','userId',source->>'user_id','role',role_name,
    'state',identity_authority_state(source-ARRAY['reason','request_authority','decision_authority']),
    'beforeSha256',identity_authority_hash(jsonb_build_object('source',source,'audits',audits)),
    'origin',CASE origin WHEN 0 THEN 'canonical-home-coherent' WHEN 1 THEN 'offline-review-required' WHEN 2 THEN 'unresolved' ELSE 'foreign' END,
    'live',COALESCE(identity_authority_legacy_live(family,source,authority),false),'relatedSources',related));
  END LOOP;
 END LOOP;
 RETURN jsonb_build_object('schemaVersion',1,'tenant',tenant,'issuer',authority,'catalogSha256',identity_authority_hash(catalog),'legacyPolicyMode','global-not-owned-authority',
  'users',accounts,'authenticationPolicies',profiles,'activationPolicies',activation,'reviewPolicies',rules,'sources',result);
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_reviewers(data JSONB,owner UUID,authority TEXT,configurer UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE identifier TEXT;previous TEXT;
BEGIN
 IF jsonb_typeof(data) IS DISTINCT FROM 'array' OR jsonb_array_length(data)>20 THEN RAISE EXCEPTION 'Bounded named authority reviewers required' USING ERRCODE='23514';END IF;
 FOR identifier IN SELECT jsonb_array_elements_text(data) LOOP
  IF identifier IS NULL OR identifier!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' OR previous>=identifier OR identifier=configurer::text
   OR NOT EXISTS(SELECT 1 FROM users WHERE id=identifier::uuid AND identity_tenant_id('user',id)=owner AND enabled
    AND EXISTS(SELECT 1 FROM identity_subject_links link JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=owner WHERE link.user_id=users.id AND link.issuer=authority))
   THEN RAISE EXCEPTION 'Independent canonical same-tenant reviewer required' USING ERRCODE='23514';END IF;previous=identifier;
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_policy(profile JSONB,owner UUID,authority TEXT,configurer UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE authentication JSONB;activation JSONB;review JSONB;role_name TEXT;legacy_auth identity_role_authentication;legacy_activation identity_role_activation_policies;legacy_review identity_role_review_policies;catalog JSONB;
BEGIN
 catalog=identity_authority_catalog();role_name=profile->>'role';authentication=profile->'authentication';activation=profile->'activation';review=profile->'review';
 IF jsonb_typeof(profile) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(profile))<>4
  OR NOT(profile ?& ARRAY['role','authentication','activation','review']) OR NOT(catalog->'roles' ? role_name)
  OR jsonb_typeof(authentication) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(authentication))<>2
  OR NOT(authentication ?& ARRAY['required','maxAgeSeconds']) OR jsonb_typeof(authentication->'required') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(authentication->'maxAgeSeconds') IS DISTINCT FROM 'number' OR COALESCE(authentication->>'maxAgeSeconds','')!~'^[0-9]+$' OR (authentication->>'maxAgeSeconds')::numeric NOT BETWEEN 300 AND 86400
  OR jsonb_typeof(activation) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(activation))<>3
  OR NOT(activation ?& ARRAY['required','maxDurationSeconds','reviewerUserIds']) OR jsonb_typeof(activation->'required') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(activation->'maxDurationSeconds') IS DISTINCT FROM 'number' OR COALESCE(activation->>'maxDurationSeconds','')!~'^[0-9]+$' OR (activation->>'maxDurationSeconds')::numeric NOT BETWEEN 60 AND 28800
  THEN RAISE EXCEPTION 'Complete typed tenant role policy proposal required' USING ERRCODE='23514';END IF;
 SELECT * INTO legacy_auth FROM identity_role_authentication WHERE role=role_name;SELECT * INTO legacy_activation FROM identity_role_activation_policies WHERE role=role_name;
 IF legacy_auth.role IS NULL OR legacy_activation.role IS NULL OR legacy_auth.mfa_required AND authentication->'required'<>'true'::jsonb
  OR (authentication->>'maxAgeSeconds')::integer>legacy_auth.max_age_seconds OR legacy_activation.activation_required AND activation->'required'<>'true'::jsonb
  OR (activation->>'maxDurationSeconds')::integer>legacy_activation.max_duration_seconds
  OR catalog->'lockedMfaRoles' ? role_name AND (authentication->'required'<>'true'::jsonb OR authentication->>'maxAgeSeconds'<>'300')
  THEN RAISE EXCEPTION 'Migration cannot weaken existing or fixed authority policy' USING ERRCODE='23514';END IF;
 PERFORM identity_authority_reviewers(activation->'reviewerUserIds',owner,authority,configurer);
 IF activation->'required'='false'::jsonb AND jsonb_array_length(activation->'reviewerUserIds')<>0
  OR NOT(catalog->'protectedRoles' ? role_name) AND jsonb_array_length(activation->'reviewerUserIds')<>0
  OR role_name='admin' AND activation->'required'='true'::jsonb AND jsonb_array_length(activation->'reviewerUserIds')=0
  OR role_name='user' AND (activation->'required'<>'false'::jsonb OR activation->>'maxDurationSeconds'<>'28800' OR review<>'null'::jsonb)
  THEN RAISE EXCEPTION 'Consistent protected authority policy required' USING ERRCODE='23514';END IF;
 SELECT * INTO legacy_review FROM identity_role_review_policies WHERE role=role_name AND retired_at IS NULL;
 IF review='null'::jsonb THEN IF legacy_review.id IS NOT NULL THEN RAISE EXCEPTION 'Migration cannot remove an active review policy' USING ERRCODE='23514';END IF;
 ELSE
  IF jsonb_typeof(review) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(review))<>3 OR NOT(review ?& ARRAY['intervalSeconds','windowSeconds','reviewerUserIds'])
   OR jsonb_typeof(review->'intervalSeconds') IS DISTINCT FROM 'number' OR COALESCE(review->>'intervalSeconds','')!~'^[0-9]+$' OR (review->>'intervalSeconds')::numeric NOT BETWEEN 3600 AND 31536000
   OR jsonb_typeof(review->'windowSeconds') IS DISTINCT FROM 'number' OR COALESCE(review->>'windowSeconds','')!~'^[0-9]+$' OR (review->>'windowSeconds')::numeric NOT BETWEEN 60 AND least(604800,(review->>'intervalSeconds')::numeric-1)
   OR legacy_review.id IS NOT NULL AND ((review->>'intervalSeconds')::numeric>legacy_review.interval_seconds OR (review->>'windowSeconds')::numeric>legacy_review.window_seconds)
   THEN RAISE EXCEPTION 'Bounded non-weaker recurring review policy required' USING ERRCODE='23514';END IF;
  PERFORM identity_authority_reviewers(review->'reviewerUserIds',owner,authority,configurer);
  IF jsonb_array_length(review->'reviewerUserIds')=0 THEN RAISE EXCEPTION 'Named independent role reviewers required' USING ERRCODE='23514';END IF;
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_manifest(body JSONB,inventory JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE owner UUID;configurer UUID;entry JSONB;source JSONB;reference JSONB;profile JSONB;catalog JSONB;
BEGIN
 IF jsonb_typeof(body) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(body))<>10
  OR NOT(body ?& ARRAY['schemaVersion','tenantId','expectedTenantVersion','expectedTenantGeneration','issuer','reviewAnchorUserId','inventorySha256','policies','sources','reason'])
  OR body->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR COALESCE(body->>'tenantId','')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  OR COALESCE(body->>'reviewAnchorUserId','')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  OR jsonb_typeof(body->'expectedTenantVersion') IS DISTINCT FROM 'string' OR COALESCE(body->>'expectedTenantVersion','')!~'^[1-9][0-9]{0,18}$'
  OR jsonb_typeof(body->'expectedTenantGeneration') IS DISTINCT FROM 'string' OR COALESCE(body->>'expectedTenantGeneration','')!~'^[1-9][0-9]{0,18}$'
  OR jsonb_typeof(body->'reason') IS DISTINCT FROM 'string' OR length(btrim(body->>'reason')) NOT BETWEEN 10 AND 500 OR body->>'reason' ~ '[[:cntrl:]]'
  OR jsonb_typeof(body->'policies') IS DISTINCT FROM 'array' OR jsonb_typeof(body->'sources') IS DISTINCT FROM 'array'
  OR body->'tenantId' IS DISTINCT FROM inventory->'tenant'->'id' OR body->'issuer' IS DISTINCT FROM inventory->'issuer'
  OR body->'expectedTenantVersion' IS DISTINCT FROM inventory->'tenant'->'version' OR body->'expectedTenantGeneration' IS DISTINCT FROM inventory->'tenant'->'generation'
  OR body->>'inventorySha256' IS DISTINCT FROM identity_authority_hash(inventory)
  THEN RAISE EXCEPTION 'Exact complete content-bound authority migration manifest required' USING ERRCODE='23514';END IF;
 owner=(body->>'tenantId')::uuid;configurer=(body->>'reviewAnchorUserId')::uuid;catalog=identity_authority_catalog();
 IF inventory->'tenant'->'enabled' IS DISTINCT FROM 'true'::jsonb OR NOT EXISTS(SELECT 1 FROM users WHERE id=configurer AND enabled AND identity_tenant_id('user',id)=owner
  AND EXISTS(SELECT 1 FROM identity_subject_links link JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=owner WHERE link.user_id=users.id AND link.issuer=body->>'issuer'))
  THEN RAISE EXCEPTION 'Enabled owned canonical review anchor required' USING ERRCODE='23514';END IF;
 IF jsonb_array_length(body->'policies')<>jsonb_array_length(catalog->'roles')
  OR (SELECT jsonb_agg(value->>'role' ORDER BY (value->>'role') COLLATE "C") FROM jsonb_array_elements(body->'policies')) IS DISTINCT FROM catalog->'roles'
  THEN RAISE EXCEPTION 'One explicit proposal for every supported role required' USING ERRCODE='23514';END IF;
 FOR profile IN SELECT value FROM jsonb_array_elements(body->'policies') LOOP PERFORM identity_authority_policy(profile,owner,body->>'issuer',configurer);END LOOP;
 IF jsonb_array_length(body->'sources')<>jsonb_array_length(inventory->'sources')
  OR (SELECT count(DISTINCT (value->>'kind',value->>'id')) FROM jsonb_array_elements(body->'sources'))<>jsonb_array_length(body->'sources')
  THEN RAISE EXCEPTION 'Complete unique authority source classification required' USING ERRCODE='23514';END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(body->'sources') LOOP
  IF jsonb_typeof(entry) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(entry)) NOT IN(3,4)
   OR NOT(entry ?& ARRAY['kind','id','disposition']) OR EXISTS(SELECT 1 FROM jsonb_object_keys(entry) field WHERE field NOT IN('kind','id','disposition','acceptOfflineOrigin'))
   OR entry->>'disposition' NOT IN('adopt','quarantine') OR jsonb_typeof(entry->'disposition') IS DISTINCT FROM 'string'
   THEN RAISE EXCEPTION 'Explicit bounded source disposition required' USING ERRCODE='23514';END IF;
  SELECT value INTO source FROM jsonb_array_elements(inventory->'sources') WHERE value->>'kind'=entry->>'kind' AND value->>'id'=entry->>'id';
  IF source IS NULL THEN RAISE EXCEPTION 'Source outside the exact owned inventory' USING ERRCODE='23514';END IF;
  IF entry ? 'acceptOfflineOrigin' AND (entry->'acceptOfflineOrigin' IS DISTINCT FROM 'true'::jsonb OR entry->>'disposition'<>'adopt' OR source->>'origin'<>'offline-review-required')
   THEN RAISE EXCEPTION 'Specific reviewed offline origin acknowledgement required' USING ERRCODE='23514';END IF;
  IF entry->>'disposition'='adopt' THEN
   IF source->'live' IS DISTINCT FROM 'true'::jsonb OR source->>'origin' NOT IN('canonical-home-coherent','offline-review-required')
    OR source->>'origin'='offline-review-required' AND entry->'acceptOfflineOrigin' IS DISTINCT FROM 'true'::jsonb
    OR NOT COALESCE(catalog->'roles' ? (source->>'role'),false)
    THEN RAISE EXCEPTION 'Foreign unresolved inactive or unreviewed source cannot be adopted' USING ERRCODE='23514';END IF;
   FOR reference IN SELECT value FROM jsonb_array_elements(source->'relatedSources') LOOP
    IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(body->'sources') selected WHERE selected->>'kind'=reference->>'kind' AND selected->>'id'=reference->>'id' AND selected->>'disposition'='adopt')
     THEN RAISE EXCEPTION 'Complete coherent adopted authority component required' USING ERRCODE='23514';END IF;
   END LOOP;
  END IF;
 END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_stage_until(body JSONB,inventory JSONB,observed TIMESTAMPTZ) RETURNS timestamptz LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE source JSONB;deadline TIMESTAMPTZ=observed+interval '15 minutes';
BEGIN
 FOR source IN SELECT item FROM jsonb_array_elements(inventory->'sources') item WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(body->'sources') selected
  WHERE selected->>'kind'=item->>'kind' AND selected->>'id'=item->>'id' AND selected->>'disposition'='adopt') LOOP
  IF source->>'kind' IN('assignment','eligibility') AND source->'state'->'expires_at'<>'null'::jsonb THEN deadline=least(deadline,(source->'state'->>'expires_at')::timestamptz);END IF;
  IF source->>'kind'='review' AND source->'state'->'deadline_at'<>'null'::jsonb THEN deadline=least(deadline,(source->'state'->>'deadline_at')::timestamptz);END IF;
 END LOOP;
 RETURN deadline;
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_candidate_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Authority migration candidates are retained immutable drafts' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.authority_stage',true),'')::jsonb;
 IF scope IS NULL OR current_setting('opendirectory.authority_review',true) IS DISTINCT FROM 'explicit-offline-authority-review'
  OR NEW.id::text IS DISTINCT FROM scope->>'id' OR NEW.tenant_id::text IS DISTINCT FROM scope->>'tenantId' OR NEW.state<>'draft'
  OR NEW.tenant_version::text IS DISTINCT FROM scope->>'tenantVersion' OR NEW.tenant_generation::text IS DISTINCT FROM scope->>'tenantGeneration'
  OR NEW.manifest_sha256 IS DISTINCT FROM identity_authority_hash(NEW.manifest) OR NEW.inventory_sha256 IS DISTINCT FROM identity_authority_hash(NEW.inventory)
  OR NEW.manifest_sha256 IS DISTINCT FROM scope->>'manifestSha256' OR NEW.inventory_sha256 IS DISTINCT FROM scope->>'inventorySha256'
  OR to_jsonb(NEW.created_at) IS DISTINCT FROM scope->'createdAt' OR NEW.reviewed_by<>session_user OR NEW.transaction_id<>txid_current()
  OR NEW.valid_until IS DISTINCT FROM identity_authority_stage_until(NEW.manifest,NEW.inventory,NEW.created_at) OR NEW.valid_until<=clock_timestamp()
  THEN RAISE EXCEPTION 'Actual reviewed inactive authority staging root required' USING ERRCODE='42501';END IF;
 IF NEW.inventory IS DISTINCT FROM identity_authority_inventory(NEW.tenant_id,NEW.manifest->>'issuer') THEN RAISE EXCEPTION 'Authority inventory changed during staging' USING ERRCODE='23514';END IF;
 PERFORM identity_authority_manifest(NEW.manifest,NEW.inventory);
 PERFORM set_config('opendirectory.authority_stage_admitted',NEW.id::text,true);RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_candidate_evidence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;candidate identity_authority_candidates;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Authority candidate evidence is immutable' USING ERRCODE='42501';END IF;
 scope=NULLIF(current_setting('opendirectory.authority_stage',true),'')::jsonb;
 SELECT * INTO candidate FROM identity_authority_candidates WHERE id=NEW.id AND transaction_id=txid_current();
 IF scope IS NULL OR candidate.id IS NULL OR current_setting('opendirectory.authority_stage_admitted',true) IS DISTINCT FROM candidate.id::text
  OR scope->>'id' IS DISTINCT FROM candidate.id::text OR NEW.tenant_id<>candidate.tenant_id OR NEW.action<>'migration-staged'
  THEN RAISE EXCEPTION 'Exact admitted authority staging evidence required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_authority_candidate_events' THEN
  IF NEW.actor IS DISTINCT FROM jsonb_build_object('kind','offline-authority-stage','databaseRole',session_user,'reviewAnchorUserId',candidate.manifest->>'reviewAnchorUserId')
   OR NEW.scope_sha256 IS DISTINCT FROM identity_authority_hash(scope)
   OR NEW.details IS DISTINCT FROM jsonb_build_object('reason',candidate.manifest->>'reason','manifestSha256',candidate.manifest_sha256,'inventorySha256',candidate.inventory_sha256,'state','draft','canAuthorize',false)
   THEN RAISE EXCEPTION 'Exact non-authorizing authority review evidence required' USING ERRCODE='23514';END IF;
 ELSE
  IF NEW.status<>'pending' OR NOT EXISTS(SELECT 1 FROM identity_authority_candidate_events WHERE id=candidate.id AND tenant_id=candidate.tenant_id AND scope_sha256=identity_authority_hash(scope))
   THEN RAISE EXCEPTION 'Exact pending authority review outbox required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_stage_no_effects() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.authority_stage',true),'') IS NOT NULL OR EXISTS(SELECT 1 FROM identity_authority_candidates WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Draft authority staging cannot change live identity or governance' USING ERRCODE='42501';END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_authority_candidate_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;candidate identity_authority_candidates;
BEGIN
 PERFORM identity_authority_owner();scope=NULLIF(current_setting('opendirectory.authority_stage',true),'')::jsonb;
 SELECT * INTO candidate FROM identity_authority_candidates WHERE id=NEW.id;
 IF scope IS NULL OR current_setting('opendirectory.authority_review',true) IS DISTINCT FROM 'explicit-offline-authority-review'
  OR scope->>'id' IS DISTINCT FROM candidate.id::text OR candidate.state<>'draft' OR candidate.valid_until<=clock_timestamp()
  OR scope->>'tenantId' IS DISTINCT FROM candidate.tenant_id::text OR scope->>'tenantVersion' IS DISTINCT FROM candidate.tenant_version::text
  OR scope->>'tenantGeneration' IS DISTINCT FROM candidate.tenant_generation::text OR scope->'createdAt' IS DISTINCT FROM to_jsonb(candidate.created_at)
  OR scope->>'manifestSha256' IS DISTINCT FROM candidate.manifest_sha256 OR scope->>'inventorySha256' IS DISTINCT FROM candidate.inventory_sha256
  OR candidate.reviewed_by<>session_user OR candidate.transaction_id<>txid_current()
  OR candidate.valid_until IS DISTINCT FROM identity_authority_stage_until(candidate.manifest,candidate.inventory,candidate.created_at)
  OR candidate.manifest_sha256 IS DISTINCT FROM identity_authority_hash(candidate.manifest) OR candidate.inventory_sha256 IS DISTINCT FROM identity_authority_hash(candidate.inventory)
  OR candidate.inventory IS DISTINCT FROM identity_authority_inventory(candidate.tenant_id,candidate.manifest->>'issuer')
  OR NOT EXISTS(SELECT 1 FROM identity_authority_candidate_events event JOIN identity_authority_candidate_outbox outbox USING(id)
   WHERE event.id=candidate.id AND event.tenant_id=candidate.tenant_id AND outbox.tenant_id=candidate.tenant_id AND event.action='migration-staged' AND outbox.action=event.action
    AND outbox.status='pending' AND event.scope_sha256=identity_authority_hash(scope)
    AND event.actor=jsonb_build_object('kind','offline-authority-stage','databaseRole',session_user,'reviewAnchorUserId',candidate.manifest->>'reviewAnchorUserId')
    AND event.details=jsonb_build_object('reason',candidate.manifest->>'reason','manifestSha256',candidate.manifest_sha256,'inventorySha256',candidate.inventory_sha256,'state','draft','canAuthorize',false))
  THEN RAISE EXCEPTION 'Current exact inactive candidate and durable receiving evidence required' USING ERRCODE='42501';END IF;
 PERFORM identity_authority_manifest(candidate.manifest,candidate.inventory);RETURN NULL;
END; $$;

CREATE OR REPLACE FUNCTION identity_authority_stage(body JSONB) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE owner UUID;inventory JSONB;scope JSONB;identifier UUID=gen_random_uuid();observed TIMESTAMPTZ=clock_timestamp();until TIMESTAMPTZ;relation TEXT;trigger_name TEXT;locked_count INTEGER;
BEGIN
 PERFORM identity_authority_owner();
 IF current_setting('opendirectory.authority_review',true) IS DISTINCT FROM 'explicit-offline-authority-review'
  OR EXISTS(SELECT 1 FROM identity_authority_candidates WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'One explicit offline authority review per transaction required' USING ERRCODE='42501';END IF;
 IF COALESCE(body->>'tenantId','')!~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN RAISE EXCEPTION 'Explicit canonical review tenant required' USING ERRCODE='23514';END IF;owner=(body->>'tenantId')::uuid;
 FOREACH relation IN ARRAY ARRAY['identity_authority_candidates','identity_authority_candidate_events','identity_authority_candidate_outbox'] LOOP
  trigger_name=CASE WHEN relation='identity_authority_candidates' THEN 'identity_authority_candidate_guard' ELSE 'identity_authority_candidate_evidence' END;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname=trigger_name AND tgenabled='O' AND tgtype=31
    AND tgfoid=(trigger_name||'()')::regprocedure)
   OR relation='identity_authority_candidates' AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='identity_authority_candidate_commit' AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='identity_authority_candidate_commit()'::regprocedure)
   THEN RAISE EXCEPTION 'Complete authority staging receiver required' USING ERRCODE='42501';END IF;
 END LOOP;
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')
  AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) ORDER BY relname LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_authority_stage_no_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='identity_authority_stage_no_effects()'::regprocedure)
   THEN RAISE EXCEPTION 'Complete non-authorizing truncate boundary required' USING ERRCODE='42501';END IF;
  IF relation IN('identity_authority_candidates','identity_authority_candidate_events','identity_authority_candidate_outbox') THEN CONTINUE;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=relation::regclass AND tgname='aaa_identity_authority_stage_no_effects' AND tgenabled='O' AND tgtype=31 AND tgfoid='identity_authority_stage_no_effects()'::regprocedure)
   THEN RAISE EXCEPTION 'Complete non-authorizing staging boundary required' USING ERRCODE='42501';END IF;
 END LOOP;
 PERFORM id FROM identity_tenants WHERE id=owner AND enabled FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Enabled explicit authority tenant required' USING ERRCODE='23514';END IF;
 PERFORM account.id FROM users account JOIN identity_tenant_ownership ownership ON ownership.resource_kind='user' AND ownership.resource_id=account.id
  WHERE ownership.tenant_id=owner ORDER BY account.id LIMIT 1001 FOR UPDATE OF account;
 GET DIAGNOSTICS locked_count=ROW_COUNT;
 IF locked_count>1000 THEN RAISE EXCEPTION 'Authority review user lock boundary exceeded' USING ERRCODE='54000';END IF;
 inventory=identity_authority_inventory(owner,body->>'issuer');PERFORM identity_authority_manifest(body,inventory);until=identity_authority_stage_until(body,inventory,observed);
 scope=jsonb_build_object('id',identifier,'tenantId',owner,'tenantVersion',inventory->'tenant'->>'version','tenantGeneration',inventory->'tenant'->>'generation',
  'manifestSha256',identity_authority_hash(body),'inventorySha256',identity_authority_hash(inventory),'createdAt',observed);
 PERFORM set_config('opendirectory.authority_stage',scope::text,true);
 INSERT INTO identity_authority_candidates(id,tenant_id,tenant_version,tenant_generation,manifest,inventory,manifest_sha256,inventory_sha256,created_at,valid_until)
  VALUES(identifier,owner,(inventory->'tenant'->>'version')::bigint,(inventory->'tenant'->>'generation')::bigint,body,inventory,identity_authority_hash(body),identity_authority_hash(inventory),observed,until);
 IF current_setting('opendirectory.authority_stage_admitted',true) IS DISTINCT FROM identifier::text THEN RAISE EXCEPTION 'Authority staging root admission missing' USING ERRCODE='42501';END IF;
 INSERT INTO identity_authority_candidate_events(id,tenant_id,action,actor,details,scope_sha256)
  VALUES(identifier,owner,'migration-staged',jsonb_build_object('kind','offline-authority-stage','databaseRole',session_user,'reviewAnchorUserId',body->>'reviewAnchorUserId'),
   jsonb_build_object('reason',body->>'reason','manifestSha256',identity_authority_hash(body),'inventorySha256',identity_authority_hash(inventory),'state','draft','canAuthorize',false),identity_authority_hash(scope));
 INSERT INTO identity_authority_candidate_outbox(id,tenant_id,action) VALUES(identifier,owner,'migration-staged');
 RETURN jsonb_build_object('id',identifier,'tenantId',owner,'state','draft','canAuthorize',false,'validUntil',until,'manifestSha256',identity_authority_hash(body),'inventorySha256',identity_authority_hash(inventory),
  'policyCount',jsonb_array_length(body->'policies'),'adoptionIntentCount',(SELECT count(*) FROM jsonb_array_elements(body->'sources') entry WHERE entry->>'disposition'='adopt'),
  'quarantineIntentCount',(SELECT count(*) FROM jsonb_array_elements(body->'sources') entry WHERE entry->>'disposition'='quarantine'));
END; $$;

DROP TRIGGER IF EXISTS identity_authority_candidate_guard ON identity_authority_candidates;
CREATE TRIGGER identity_authority_candidate_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_authority_candidates FOR EACH ROW EXECUTE FUNCTION identity_authority_candidate_guard();
DROP TRIGGER IF EXISTS identity_authority_candidate_commit ON identity_authority_candidates;
CREATE CONSTRAINT TRIGGER identity_authority_candidate_commit AFTER INSERT OR UPDATE ON identity_authority_candidates DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_authority_candidate_commit();
DO $$ DECLARE relation TEXT;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_authority_candidate_events','identity_authority_candidate_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_authority_candidate_evidence ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_authority_candidate_evidence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_candidate_evidence()',relation);
 END LOOP;
 FOR relation IN SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p')
  AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) ORDER BY relname LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_stage_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_authority_stage_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_authority_stage_no_effects()',relation);
  IF relation IN('identity_authority_candidates','identity_authority_candidate_events','identity_authority_candidate_outbox') THEN CONTINUE;END IF;
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_authority_stage_no_effects ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_authority_stage_no_effects BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_authority_stage_no_effects()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_authority_catalog()','identity_authority_hash(jsonb)','identity_authority_owner()',
  'identity_authority_actor(text,uuid,text)','identity_authority_state(jsonb)','identity_authority_legacy_live(text,jsonb,text)',
  'identity_authority_inventory(uuid,text)','identity_authority_reviewers(jsonb,uuid,text,uuid)','identity_authority_policy(jsonb,uuid,text,uuid)',
  'identity_authority_manifest(jsonb,jsonb)','identity_authority_stage_until(jsonb,jsonb,timestamp with time zone)',
  'identity_authority_candidate_guard()','identity_authority_candidate_evidence()','identity_authority_stage_no_effects()',
  'identity_authority_candidate_commit()','identity_authority_stage(jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
