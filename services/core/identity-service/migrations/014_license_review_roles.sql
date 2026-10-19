INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
 ('license-review-administrator',true,300),('license-reviewer',true,300),('license-review-reader',false,3600)
ON CONFLICT(role) DO NOTHING;
INSERT INTO identity_role_activation_policies(role) VALUES
 ('license-review-administrator'),('license-reviewer'),('license-review-reader') ON CONFLICT(role) DO NOTHING;
