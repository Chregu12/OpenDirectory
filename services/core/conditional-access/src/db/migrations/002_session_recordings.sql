-- Migration: 002_session_recordings.sql
-- Purpose: Separate append-only store for PIM session recordings
-- Compliance: PIM session recordings must be stored independently of the
--             operational DB and must not be mutable after insertion.
-- Retention:  90-day active window; records are ARCHIVED (flagged), never
--             deleted.  See getRetentionPolicy() in sessionRecorder.js.

-- ---------------------------------------------------------------------------
-- Table: pim_sessions
-- One row per privileged-access elevation session.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pim_sessions (
    id          TEXT        PRIMARY KEY,
    user_id     TEXT,
    role        TEXT,
    started_at  TIMESTAMPTZ,
    ended_at    TIMESTAMPTZ,
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pim_sessions_user_id
    ON pim_sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_pim_sessions_started_at
    ON pim_sessions (started_at DESC);

-- ---------------------------------------------------------------------------
-- Table: pim_session_activities
-- Append-only activity log for each PIM session.
-- details_encrypted stores the AES-256-GCM blob produced by fieldEncryption.js.
--
-- Retention policy (90 days):
--   Records older than 90 days are ARCHIVED (archived_at is set) but never
--   deleted.  Application code must honour getRetentionPolicy() from
--   sessionRecorder.js: { retentionDays: 90, deleteAfter: false, archiveAfter: 90 }
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pim_session_activities (
    id                 BIGSERIAL   PRIMARY KEY,
    session_id         TEXT        NOT NULL REFERENCES pim_sessions(id),
    timestamp          TIMESTAMPTZ NOT NULL,
    type               TEXT        NOT NULL,
    details_encrypted  TEXT,           -- AES-256-GCM encrypted blob (base64)
    created_at         TIMESTAMPTZ DEFAULT NOW(),
    archived_at        TIMESTAMPTZ     -- Set when archived after 90 days; NULL = active
);

CREATE INDEX IF NOT EXISTS idx_pim_session_activities_session_id
    ON pim_session_activities (session_id);

CREATE INDEX IF NOT EXISTS idx_pim_session_activities_timestamp
    ON pim_session_activities (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_pim_session_activities_archived_at
    ON pim_session_activities (archived_at)
    WHERE archived_at IS NULL;   -- Partial index: fast active-record queries

-- ---------------------------------------------------------------------------
-- WORM enforcement for activities: no UPDATE or DELETE allowed.
-- Sessions themselves may have ended_at set (that is a legitimate append-style
-- completion update), so we do NOT apply WORM rules to pim_sessions.
-- ---------------------------------------------------------------------------
CREATE RULE no_update_pim_session_activities
    AS ON UPDATE TO pim_session_activities
    DO INSTEAD NOTHING;

CREATE RULE no_delete_pim_session_activities
    AS ON DELETE TO pim_session_activities
    DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- Optional: revoke UPDATE/DELETE privileges from the application role.
-- Replace 'app_role' with the actual DB role used by the service.
-- ---------------------------------------------------------------------------
-- REVOKE UPDATE, DELETE ON pim_session_activities FROM app_role;
