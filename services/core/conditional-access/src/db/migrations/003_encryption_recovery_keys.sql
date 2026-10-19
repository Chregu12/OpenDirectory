-- Migration: 003_encryption_recovery_keys.sql
-- Purpose: Persist BitLocker/FileVault/LUKS disk-encryption recovery keys.
-- Compliance: Recovery keys must survive a service restart (unlike audit
--             trails, this is mutable *current-state* secret material —
--             rotation/revocation legitimately UPDATEs a device's row, so
--             this table is intentionally NOT WORM-protected, unlike
--             break_glass_audit / pim_session_activities).
--
-- Values in key_encrypted are AES-256-GCM ciphertext produced by
-- src/crypto/fieldEncryption.js (iv:authTag:ciphertext, base64 parts) —
-- the plaintext recovery key is never written to the database.

CREATE TABLE IF NOT EXISTS encryption_recovery_keys (
    device_id      TEXT        PRIMARY KEY,
    key_encrypted  TEXT        NOT NULL,
    stored_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed  TIMESTAMPTZ,
    access_count   INTEGER     NOT NULL DEFAULT 0,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_encryption_recovery_keys_stored_at
    ON encryption_recovery_keys (stored_at DESC);
