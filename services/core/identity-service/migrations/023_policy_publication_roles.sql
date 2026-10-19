INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
 ('policy-publication-reviewer',true,300) ON CONFLICT(role) DO NOTHING;
INSERT INTO identity_role_activation_policies(role) VALUES('policy-publication-reviewer') ON CONFLICT(role) DO NOTHING;
CREATE OR REPLACE FUNCTION identity_policy_publication_authentication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.role='policy-publication-reviewer' THEN RAISE EXCEPTION 'Policy publication review requires fixed fresh MFA' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS identity_policy_publication_authentication_guard ON identity_role_authentication;
CREATE TRIGGER identity_policy_publication_authentication_guard BEFORE UPDATE OR DELETE ON identity_role_authentication
 FOR EACH ROW EXECUTE FUNCTION identity_policy_publication_authentication_guard();
