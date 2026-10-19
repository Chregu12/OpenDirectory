INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
 ('license-delegation-review-administrator',true,300),('license-delegation-reviewer',true,300),('license-delegation-review-reader',false,3600) ON CONFLICT(role) DO NOTHING;
INSERT INTO identity_role_activation_policies(role) VALUES
 ('license-delegation-review-administrator'),('license-delegation-reviewer'),('license-delegation-review-reader') ON CONFLICT(role) DO NOTHING;
