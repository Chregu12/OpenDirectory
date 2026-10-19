INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
 ('license-scope-policy-administrator',true,300),('license-scope-policy-reader',false,3600) ON CONFLICT(role) DO NOTHING;
INSERT INTO identity_role_activation_policies(role) VALUES
 ('license-scope-policy-administrator'),('license-scope-policy-reader') ON CONFLICT(role) DO NOTHING;
