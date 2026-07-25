-- Root CA private key persistence (P0 fix).
--
-- Before this migration, the root CA signing key was generated fresh in
-- memory on every process boot (src/index.js initCA()) and never stored
-- anywhere. Every certificate ever issued by this service is signed by that
-- key and recorded in ca_certificates — so on every restart, the entire
-- previously-issued certificate population silently became untrusted
-- garbage (signed by a root nothing can verify against anymore).
--
-- This is a singleton table: exactly one row, id = 1, holds the current
-- root CA key/cert pair. src/services/rootCaService.js reads this row on
-- boot and only generates + inserts a new key pair when the table is empty
-- (true first boot), so the root CA identity now survives restarts.
--
-- CONFIDENTIALITY (im Klartext dokumentiert, siehe Auftrag):
-- private_key_pem is stored ENCRYPTED via src/crypto/fieldEncryption.js
-- (AES-256-GCM, key from the ENCRYPTION_KEY env var — 64 hex chars / 32
-- bytes). This mirrors the existing field-encryption mechanism already used
-- by services/core/conditional-access and services/core/samba-ad-dc.
--
-- FOLLOW-UP / KNOWN GAP: if ENCRYPTION_KEY is not set in a given deployment,
-- fieldEncryption.js transparently falls back to base64 encoding — which is
-- NOT encryption — and logs a loud warning at boot. That fallback exists so
-- the service still starts in dev, but it means the private key can end up
-- stored effectively in the clear (base64) in this table if operators don't
-- set ENCRYPTION_KEY. This is a repo-wide gap (the other two services using
-- fieldEncryption.js have the same exposure) and is being flagged here
-- prominently rather than silently accepted: ENCRYPTION_KEY MUST be set,
-- rotated via a proper secrets manager, and this table's row-level access
-- restricted, before this service holds production secrets. Persisting the
-- key (even before that follow-up lands) is still strictly better than the
-- previous behavior of regenerating it — and silently destroying trust in
-- every issued certificate — on every restart.
CREATE TABLE IF NOT EXISTS ca_root_key (
  id INTEGER PRIMARY KEY DEFAULT 1,
  common_name VARCHAR(255) NOT NULL,
  private_key_pem TEXT NOT NULL,
  certificate_pem TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT ca_root_key_singleton CHECK (id = 1)
);
