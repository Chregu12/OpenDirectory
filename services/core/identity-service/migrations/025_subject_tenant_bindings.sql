CREATE TABLE IF NOT EXISTS identity_subject_tenant_bindings (
 issuer TEXT NOT NULL,subject VARCHAR(255) NOT NULL,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(issuer,subject)
);

CREATE OR REPLACE FUNCTION identity_subject_tenant_binding_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Subject tenant ownership is retained and immutable' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM identity_subject_links link WHERE link.issuer=NEW.issuer AND link.subject=NEW.subject
  AND identity_tenant_id('user',link.user_id)=NEW.tenant_id)
  THEN RAISE EXCEPTION 'An actual explicitly owned subject link is required' USING ERRCODE='23514';END IF;
 NEW.created_at=clock_timestamp();RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION identity_subject_tenant_claim(authority TEXT,identity TEXT,owner UUID) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE retained UUID;
BEGIN
 IF owner IS NULL THEN
  IF EXISTS(SELECT 1 FROM identity_subject_tenant_bindings WHERE issuer=authority AND subject=identity)
   THEN RAISE EXCEPTION 'A retained subject cannot become unowned' USING ERRCODE='23514';END IF;
  RETURN;
 END IF;
 INSERT INTO identity_subject_tenant_bindings(issuer,subject,tenant_id) VALUES(authority,identity,owner) ON CONFLICT DO NOTHING;
 SELECT tenant_id INTO retained FROM identity_subject_tenant_bindings WHERE issuer=authority AND subject=identity;
 IF retained IS DISTINCT FROM owner THEN RAISE EXCEPTION 'A subject cannot cross its retained tenant boundary' USING ERRCODE='23514';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_subject_link_role_state(identity UUID) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER AS $$
 WITH grants AS (SELECT * FROM identity_role_assignments WHERE user_id=identity AND revoked_at IS NULL),
 reviews AS (SELECT review.* FROM identity_role_review_leases review WHERE
  review.target_kind='assignment' AND review.target_id IN(SELECT id FROM grants)
  OR review.target_kind='eligibility' AND review.target_id IN(SELECT request.eligibility_id FROM identity_pim_requests request WHERE request.id IN(SELECT activation_request_id FROM grants)))
 SELECT jsonb_build_object(
  'grants',COALESCE((SELECT jsonb_agg(jsonb_build_array(to_jsonb(assignment),assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp()) ORDER BY assignment.id) FROM grants assignment),'[]'::jsonb),
  'reviews',COALESCE((SELECT jsonb_agg(jsonb_build_array(to_jsonb(review),review.deadline_at IS NULL OR review.deadline_at>identity_role_review_now()) ORDER BY review.id) FROM reviews review),'[]'::jsonb),
  'authentication',COALESCE((SELECT jsonb_agg(to_jsonb(policy) ORDER BY policy.role) FROM identity_role_authentication policy WHERE policy.role IN(SELECT role FROM grants)),'[]'::jsonb),
  'activation',COALESCE((SELECT jsonb_agg(to_jsonb(policy) ORDER BY policy.role) FROM identity_role_activation_policies policy WHERE policy.role IN(SELECT role FROM grants)),'[]'::jsonb));
$$;

CREATE OR REPLACE FUNCTION identity_subject_link_admission() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;actor UUID;owner UUID;
BEGIN
 IF NULLIF(current_setting('opendirectory.subject_link_admission',true),'') IS NULL THEN RETURN;END IF;
 proof=current_setting('opendirectory.subject_link_admission')::jsonb;
 actor=(proof->'context'->>'userId')::uuid;owner=(proof->'tenant'->>'id')::uuid;
 IF proof->>'issuer' IS NULL OR proof->>'subject' IS NULL OR proof->>'validUntil' IS NULL
  OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  OR NOT EXISTS(SELECT 1 FROM users account JOIN identity_subject_links link ON link.user_id=account.id
   JOIN identity_tenants tenant ON tenant.id=identity_tenant_id('user',account.id)
   JOIN identity_subject_tenant_bindings binding ON binding.issuer=link.issuer AND binding.subject=link.subject AND binding.tenant_id=tenant.id
   WHERE account.id=actor AND link.issuer=proof->>'issuer' AND link.subject=proof->>'subject' AND account.enabled AND tenant.enabled
   AND tenant.id=owner AND tenant.version::text=proof->'tenant'->>'version' AND tenant.generation::text=proof->'tenant'->>'generation'
   AND account.authorization_revision::text=proof->'context'->>'revision' AND link.authorization_revision::text=proof->'context'->>'linkRevision')
  OR identity_subject_link_role_state(actor) IS DISTINCT FROM proof->'rolesSnapshot'
  THEN RAISE EXCEPTION 'Original subject-link authority is no longer current' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION identity_subject_tenant_transition() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE link RECORD;owner UUID;retained UUID;proof JSONB;event UUID;transition TEXT;
BEGIN
 IF TG_TABLE_NAME='identity_tenant_ownership' THEN
  IF NEW.resource_kind='user' THEN
   FOR link IN SELECT * FROM identity_subject_links WHERE user_id=NEW.resource_id LOOP
    PERFORM identity_subject_tenant_claim(link.issuer,link.subject,NEW.tenant_id);
   END LOOP;
  END IF;RETURN NULL;
 END IF;
 IF TG_OP='DELETE' THEN link=OLD;ELSE link=NEW;END IF;
 owner=identity_tenant_id('user',link.user_id);
 IF TG_WHEN='BEFORE' THEN
  PERFORM identity_subject_link_admission();
  proof=NULLIF(current_setting('opendirectory.subject_link_admission',true),'')::jsonb;
  IF proof IS NOT NULL AND (owner IS NULL OR owner::text IS DISTINCT FROM proof->'tenant'->>'id')
   THEN RAISE EXCEPTION 'Same-tenant subject-link target required' USING ERRCODE='42501';END IF;
  SELECT tenant_id INTO retained FROM identity_subject_tenant_bindings WHERE issuer=link.issuer AND subject=link.subject;
  IF retained IS NOT NULL AND retained IS DISTINCT FROM owner THEN RAISE EXCEPTION 'A subject cannot cross its retained tenant boundary' USING ERRCODE='23514';END IF;
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 IF TG_OP='INSERT' THEN PERFORM identity_subject_tenant_claim(link.issuer,link.subject,owner);END IF;
 IF owner IS NOT NULL THEN
  transition=CASE TG_OP WHEN 'INSERT' THEN 'subject-linked' ELSE 'subject-unlinked' END;
  proof=NULLIF(current_setting('opendirectory.subject_link_admission',true),'')::jsonb;
  INSERT INTO identity_tenant_events(tenant_id,action,actor,details) VALUES(owner,transition,
   CASE WHEN proof IS NULL THEN jsonb_build_object('databaseRole',session_user) ELSE jsonb_build_object('issuer',proof->>'issuer','subject',proof->>'subject','userId',proof->'context'->>'userId') END,
   jsonb_build_object('issuer',link.issuer,'subject',link.subject,'userId',link.user_id,'linkRevision',link.authorization_revision::text)) RETURNING id INTO event;
  INSERT INTO identity_tenant_outbox(id,tenant_id,action) VALUES(event,owner,transition);
 END IF;RETURN NULL;
END; $$;

CREATE OR REPLACE FUNCTION identity_subject_link_commit_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN PERFORM identity_subject_link_admission();RETURN NULL;END; $$;

DROP TRIGGER IF EXISTS identity_subject_tenant_binding_guard ON identity_subject_tenant_bindings;
CREATE TRIGGER identity_subject_tenant_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON identity_subject_tenant_bindings FOR EACH ROW EXECUTE FUNCTION identity_subject_tenant_binding_guard();
DROP TRIGGER IF EXISTS identity_subject_tenant_guard ON identity_subject_links;
CREATE TRIGGER identity_subject_tenant_guard BEFORE INSERT OR DELETE ON identity_subject_links FOR EACH ROW EXECUTE FUNCTION identity_subject_tenant_transition();
DROP TRIGGER IF EXISTS identity_subject_tenant_changed ON identity_subject_links;
CREATE TRIGGER identity_subject_tenant_changed AFTER INSERT OR DELETE ON identity_subject_links FOR EACH ROW EXECUTE FUNCTION identity_subject_tenant_transition();
DROP TRIGGER IF EXISTS identity_subject_tenant_adopted ON identity_tenant_ownership;
CREATE TRIGGER identity_subject_tenant_adopted AFTER INSERT ON identity_tenant_ownership FOR EACH ROW EXECUTE FUNCTION identity_subject_tenant_transition();
DROP TRIGGER IF EXISTS identity_subject_link_commit_guard ON identity_subject_links;
CREATE CONSTRAINT TRIGGER identity_subject_link_commit_guard AFTER INSERT OR DELETE ON identity_subject_links DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_subject_link_commit_guard();

DO $$ DECLARE routine TEXT;BEGIN
 FOREACH routine IN ARRAY ARRAY['identity_subject_tenant_binding_guard()','identity_subject_tenant_claim(text,text,uuid)',
  'identity_subject_link_role_state(uuid)','identity_subject_link_admission()','identity_subject_tenant_transition()','identity_subject_link_commit_guard()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;

DO $$ DECLARE link RECORD;BEGIN
 FOR link IN SELECT issuer,subject,identity_tenant_id('user',user_id) AS tenant_id FROM identity_subject_links LOOP
  PERFORM identity_subject_tenant_claim(link.issuer,link.subject,link.tenant_id);
 END LOOP;
END; $$;
