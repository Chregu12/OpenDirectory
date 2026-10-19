INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
 ('license-scope-administrator',true,300),('license-delegate',true,300),('license-scope-reader',false,3600)
ON CONFLICT(role) DO NOTHING;
INSERT INTO identity_role_activation_policies(role) VALUES
 ('license-scope-administrator'),('license-delegate'),('license-scope-reader') ON CONFLICT(role) DO NOTHING;
