CREATE TABLE IF NOT EXISTS laps_passwords (
  computer_name VARCHAR(255) PRIMARY KEY,
  encrypted_password TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  set_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS laps_access_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  computer_name VARCHAR(255) NOT NULL,
  retrieved_by VARCHAR(255) NOT NULL,
  retrieved_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS bitlocker_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  computer_name VARCHAR(255) NOT NULL,
  volume_type VARCHAR(50) NOT NULL,
  recovery_key_id VARCHAR(255) NOT NULL UNIQUE,
  encrypted_recovery_key TEXT NOT NULL,
  tpm_thumbprint VARCHAR(255),
  escrowed_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS bitlocker_key_access_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  recovery_key_id VARCHAR(255) NOT NULL,
  retrieved_by VARCHAR(255) NOT NULL,
  retrieved_at TIMESTAMPTZ DEFAULT NOW()
);
