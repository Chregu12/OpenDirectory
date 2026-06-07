CREATE TABLE IF NOT EXISTS scim_catalog (
  app_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  username VARCHAR(255),
  email VARCHAR(255),
  display_name VARCHAR(255),
  external_id VARCHAR(255),
  active BOOLEAN DEFAULT true,
  synced_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (app_id, user_id)
);
