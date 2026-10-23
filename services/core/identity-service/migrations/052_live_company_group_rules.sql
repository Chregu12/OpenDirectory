CREATE OR REPLACE FUNCTION identity_membership_review_base_allowed(identity UUID) RETURNS BOOLEAN LANGUAGE sql VOLATILE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id
  LEFT JOIN users ON users.id=origin.user_id WHERE lease.membership_id=identity AND(lease.state='denied' OR lease.deadline_at<=identity_membership_review_now()
   OR NOT(lease.initial_grace OR lease.cycle>1) OR users.id IS NULL OR NOT users.enabled OR users.eligibility_revision<>origin.eligibility_revision
   OR NOT EXISTS(SELECT 1 FROM group_members WHERE membership_id=identity)))
 AND NOT EXISTS(SELECT 1 FROM identity_membership_origins origin WHERE origin.membership_id=identity AND origin.application_grant_id IS NOT NULL AND NOT identity_membership_application_origin(identity));
$$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_dynamic(setting identity_company_group_rules,target UUID) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
DECLARE account RECORD;condition JSONB;actual TEXT;wanted TEXT;
BEGIN
 IF NOT setting.enabled OR NOT identity_company_group_rule_draft_valid(setting.draft) OR setting.draft->'dynamic'='null'::jsonb OR setting.draft->'excludedUserIds' ? target::text THEN RETURN false;END IF;
 SELECT id,department,title,email,username,display_name INTO account FROM users WHERE id=target AND identity_tenant_id('user',id)=setting.tenant_id AND identity_tenant_user_enabled(id);
 IF account.id IS NULL THEN RETURN false;END IF;
 FOR condition IN SELECT value FROM jsonb_array_elements(setting.draft#>'{dynamic,all}') LOOP
  actual=lower(COALESCE(CASE condition->>'attribute' WHEN 'department' THEN account.department WHEN 'title' THEN account.title WHEN 'email' THEN account.email WHEN 'username' THEN account.username WHEN 'displayName' THEN account.display_name END,''));wanted=lower(condition->>'value');
  IF NOT(CASE condition->>'operator' WHEN 'equals' THEN actual=wanted WHEN 'startsWith' THEN starts_with(actual,wanted) WHEN 'endsWith' THEN right(actual,length(wanted))=wanted ELSE false END) THEN RETURN false;END IF;
 END LOOP;RETURN true;
END; $$;

CREATE OR REPLACE FUNCTION identity_membership_rule_resolve(identity UUID,path UUID[],budget INTEGER) RETURNS TABLE(deadline_at TIMESTAMPTZ,remaining INTEGER) LANGUAGE plpgsql VOLATILE SECURITY DEFINER AS $$
DECLARE origin identity_membership_origins;effect identity_company_group_rule_effects;setting identity_company_group_rules;original identity_company_group_rule_events;child RECORD;resolved RECORD;own_deadline TIMESTAMPTZ;best TIMESTAMPTZ='-infinity';
BEGIN
 IF budget<=0 OR COALESCE(cardinality(path),0)>16 THEN RAISE EXCEPTION 'Complete group-rule resolution exceeds its bound' USING ERRCODE='42501';END IF;
 remaining=budget-1;deadline_at='-infinity';
 IF NOT identity_membership_review_base_allowed(identity) THEN RETURN NEXT;RETURN;END IF;
 SELECT COALESCE(lease.deadline_at,'infinity'::timestamptz) INTO own_deadline FROM(SELECT 1) singleton LEFT JOIN identity_membership_review_leases lease ON lease.membership_id=identity;
 SELECT * INTO origin FROM identity_membership_origins WHERE membership_id=identity;
 SELECT * INTO effect FROM identity_company_group_rule_effects actual WHERE actual.membership_id=identity AND actual.group_id=origin.group_id AND actual.action='member-add';
 IF effect.id IS NULL THEN deadline_at=own_deadline;RETURN NEXT;RETURN;END IF;
 IF (SELECT count(*) FROM identity_company_group_rule_effects actual WHERE actual.membership_id=identity AND actual.action='member-add')<>1
  OR origin.user_id<>effect.user_id OR identity_tenant_id('user',origin.user_id) IS DISTINCT FROM effect.tenant_id OR identity_tenant_id('group',origin.group_id) IS DISTINCT FROM effect.tenant_id
  OR origin.created_by::text IS DISTINCT FROM effect.source#>>'{authority,actorUserId}' OR origin.application_grant_id::text IS DISTINCT FROM effect.source#>>'{authority,grantId}'
  OR NOT EXISTS(SELECT 1 FROM identity_company_group_rule_effect_outbox box WHERE box.id=effect.id AND box.status='pending' AND box.created_at=effect.created_at AND box.fingerprint=encode(sha256(convert_to(to_jsonb(effect)::text,'UTF8')),'hex'))
  OR NOT EXISTS(SELECT 1 FROM identity_directory_group_events actual JOIN identity_directory_group_outbox box ON box.id=actual.id AND box.status='pending'
   WHERE actual.id=effect.id AND actual.group_id=effect.group_id AND actual.tenant_id=effect.tenant_id AND actual.action=effect.action AND actual.transaction_id=effect.transaction_id AND actual.scope_sha256=effect.group_scope_sha256 AND actual.actor=identity_company_group_rule_effect_actor(effect.source))
  THEN RAISE EXCEPTION 'Original canonical rule membership source unavailable' USING ERRCODE='42501';END IF;
 SELECT * INTO setting FROM identity_company_group_rules WHERE group_id=origin.group_id AND tenant_id=effect.tenant_id;
 SELECT * INTO original FROM identity_company_group_rule_events WHERE id=setting.last_event_id;
 IF setting.group_id IS NULL OR original.id IS NULL OR original.result IS DISTINCT FROM to_jsonb(setting)
  OR NOT EXISTS(SELECT 1 FROM identity_company_group_rule_outbox box WHERE box.id=original.id AND box.status='pending' AND box.fingerprint=encode(sha256(convert_to(to_jsonb(original)::text,'UTF8')),'hex'))
  THEN RAISE EXCEPTION 'Original current group-rule configuration unavailable' USING ERRCODE='42501';END IF;
 IF origin.group_id=ANY(path) THEN RAISE EXCEPTION 'Cyclic live group-rule source' USING ERRCODE='42501';END IF;
 IF NOT setting.enabled OR setting.revision<>effect.rule_revision OR NOT identity_company_group_rule_draft_valid(setting.draft) OR setting.draft->'excludedUserIds' ? origin.user_id::text
  OR NOT EXISTS(SELECT 1 FROM group_members WHERE membership_id=identity AND group_id=origin.group_id AND user_id=origin.user_id::text)
  OR NOT EXISTS(SELECT 1 FROM users WHERE id=origin.user_id AND eligibility_revision=origin.eligibility_revision AND identity_tenant_user_enabled(id)) THEN RETURN NEXT;RETURN;END IF;
 IF identity_company_group_rule_dynamic(setting,origin.user_id) THEN deadline_at=own_deadline;RETURN NEXT;RETURN;END IF;
 FOR child IN SELECT member.membership_id FROM group_members member JOIN groups collection ON collection.id=member.group_id
  WHERE member.user_id=origin.user_id::text AND identity_tenant_id('group',collection.id)=setting.tenant_id AND setting.draft->'childGroupIds' ? collection.id::text ORDER BY collection.id LOOP
  SELECT * INTO resolved FROM identity_membership_rule_resolve(child.membership_id,path||origin.group_id,remaining);remaining=resolved.remaining;best=GREATEST(best,resolved.deadline_at);
  EXIT WHEN best='infinity'::timestamptz;
 END LOOP;
 deadline_at=LEAST(own_deadline,best);RETURN NEXT;
END; $$;

CREATE OR REPLACE FUNCTION identity_membership_rule_deadline(identity UUID) RETURNS TIMESTAMPTZ LANGUAGE sql VOLATILE AS $$
 SELECT deadline_at FROM identity_membership_rule_resolve(identity,ARRAY[]::uuid[],1024);
$$;
CREATE OR REPLACE FUNCTION identity_membership_review_allowed(identity UUID) RETURNS BOOLEAN LANGUAGE sql VOLATILE AS $$
 SELECT identity_membership_rule_deadline(identity)>identity_membership_review_now();
$$;
CREATE OR REPLACE FUNCTION identity_company_group_rule_wants(setting identity_company_group_rules,target UUID) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 IF NOT setting.enabled OR NOT identity_company_group_rule_draft_valid(setting.draft) OR setting.draft->'excludedUserIds' ? target::text
  OR NOT EXISTS(SELECT 1 FROM users WHERE id=target AND identity_tenant_id('user',id)=setting.tenant_id AND identity_tenant_user_enabled(id)) THEN RETURN false;END IF;
 RETURN identity_company_group_rule_dynamic(setting,target) OR EXISTS(SELECT 1 FROM group_members membership JOIN groups collection ON collection.id=membership.group_id
  WHERE membership.user_id=target::text AND identity_tenant_id('group',collection.id)=setting.tenant_id AND setting.draft->'childGroupIds' ? collection.id::text AND identity_membership_review_allowed(membership.membership_id));
END; $$;

CREATE OR REPLACE FUNCTION identity_company_group_rule_live_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN PERFORM identity_company_group_rule_app_receiving();END; $$;
CREATE OR REPLACE FUNCTION identity_group_source_revision(identity UUID,captured_physical BIGINT DEFAULT NULL) RETURNS TEXT LANGUAGE plpgsql VOLATILE SECURITY DEFINER AS $$
DECLARE tenant UUID;physical BIGINT;result NUMERIC;review_now TIMESTAMPTZ;
BEGIN
 PERFORM identity_company_group_rule_live_receiving();
 tenant=identity_tenant_id('group',identity);
 SELECT revision INTO physical FROM groups WHERE id=identity;
 IF physical IS NULL THEN SELECT revision INTO physical FROM identity_deleted_groups WHERE group_id=identity;END IF;
 IF physical IS NULL OR tenant IS NULL THEN RAISE EXCEPTION 'Actual retained group source required' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM identity_company_group_rules WHERE group_id=identity) THEN RETURN COALESCE(captured_physical,physical)::text;END IF;
 review_now=identity_membership_review_now();
 SELECT COALESCE(captured_physical,physical)::numeric+COALESCE((SELECT sum(latest.revision) FROM(SELECT user_id,max(revision)::numeric AS revision FROM identity_user_record_audit GROUP BY user_id) latest WHERE identity_tenant_id('user',latest.user_id)=tenant),0)
  +COALESCE((SELECT sum(latest.revision) FROM(SELECT group_id,max(revision)::numeric AS revision FROM identity_group_audit GROUP BY group_id) latest WHERE identity_tenant_id('group',latest.group_id)=tenant),0)
  +COALESCE((SELECT sum(revision::numeric) FROM identity_company_group_rules WHERE tenant_id=tenant),0)
  +(SELECT version::numeric FROM identity_tenants WHERE id=tenant)
  +(SELECT count(*) FROM identity_membership_review_audit audit JOIN identity_membership_review_policies policy ON policy.id=audit.policy_id
    WHERE identity_tenant_id('group',policy.group_id)=tenant AND jsonb_typeof(audit.details->'deadline_at')='string' AND (audit.details->>'deadline_at')::timestamptz<=review_now)
 INTO result;
 IF result NOT BETWEEN 1 AND 9223372036854775807 THEN RAISE EXCEPTION 'Exact effective group source revision unavailable' USING ERRCODE='42501';END IF;RETURN result::text;
END; $$;

DO $$ DECLARE definition TEXT;signature TEXT;BEGIN
 definition=pg_get_functiondef('identity_company_group_rule_app_receiving()'::regprocedure);
 definition=replace(definition,'identity_company_group_rule_app_manifest)<>21','identity_company_group_rule_app_manifest)<>27');EXECUTE definition;
 FOREACH signature IN ARRAY ARRAY['identity_membership_review_base_allowed(uuid)','identity_company_group_rule_dynamic(identity_company_group_rules,uuid)','identity_membership_rule_resolve(uuid,uuid[],integer)','identity_membership_rule_deadline(uuid)','identity_membership_review_allowed(uuid)','identity_company_group_rule_wants(identity_company_group_rules,uuid)','identity_company_group_rule_live_receiving()','identity_group_source_revision(uuid,bigint)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
END; $$;
ALTER TABLE identity_company_group_rule_app_manifest DISABLE TRIGGER company_group_rule_app_manifest_guard;
INSERT INTO identity_company_group_rule_app_manifest SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY[
 'identity_membership_review_base_allowed(uuid)','identity_company_group_rule_dynamic(identity_company_group_rules,uuid)','identity_membership_rule_resolve(uuid,uuid[],integer)','identity_membership_rule_deadline(uuid)','identity_company_group_rule_live_receiving()','identity_group_source_revision(uuid,bigint)']) signature ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
UPDATE identity_company_group_rule_app_manifest SET digest=md5(pg_get_functiondef(to_regprocedure(signature)));
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE identity_company_group_rule_app_manifest ENABLE TRIGGER company_group_rule_app_manifest_guard;
ALTER TABLE identity_company_group_rule_manifest DISABLE TRIGGER company_group_rule_manifest_guard;
UPDATE identity_company_group_rule_manifest SET digest=md5(pg_get_functiondef(to_regprocedure(signature)));
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE identity_company_group_rule_manifest ENABLE TRIGGER company_group_rule_manifest_guard;
