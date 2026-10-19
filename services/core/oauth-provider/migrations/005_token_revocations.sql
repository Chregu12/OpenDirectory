CREATE TABLE IF NOT EXISTS oauth_token_revocations (
  token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  client_id VARCHAR(255) NOT NULL,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_token_revocations_expiry_idx ON oauth_token_revocations(expires_at);
