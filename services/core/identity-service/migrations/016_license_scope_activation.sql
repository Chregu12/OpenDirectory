INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
 ('license-scope-activation-reviewer',true,300) ON CONFLICT(role) DO NOTHING;
INSERT INTO identity_role_activation_policies(role) VALUES ('license-scope-activation-reviewer') ON CONFLICT(role) DO NOTHING;
