-- Protected Users group: members receive additional security restrictions
-- Restrictions enforced:
--   - No NTLM, Digest, or CredSSP authentication
--   - Kerberos tickets not renewable beyond 4 hours
--   - No delegation allowed
--   - Kerberos AES encryption only (no RC4, DES)
CREATE TABLE IF NOT EXISTS protected_users (
  user_principal VARCHAR(255) PRIMARY KEY,
  added_at TIMESTAMPTZ DEFAULT NOW(),
  added_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_protected_users_added_at ON protected_users(added_at DESC);
