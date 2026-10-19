INSERT INTO identity_role_authentication(role,mfa_required,max_age_seconds) VALUES
  ('license-provider-administrator',true,300),
  ('license-fulfillment-reader',false,3600),
  ('license-fulfillment-operator',true,300)
ON CONFLICT(role) DO NOTHING;
