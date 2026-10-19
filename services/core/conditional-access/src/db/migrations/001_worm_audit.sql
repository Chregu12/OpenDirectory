-- Migration: 001_worm_audit.sql
-- Purpose: Create WORM (Write Once Read Many) break-glass audit table
-- Compliance: PAM requirement — break-glass records must be append-only
-- Break-glass events must never be UPDATE'd or DELETE'd once written.

-- ---------------------------------------------------------------------------
-- Table: break_glass_audit
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS break_glass_audit (
    id          BIGSERIAL      PRIMARY KEY,
    session_id  TEXT           NOT NULL,
    user_id     TEXT           NOT NULL,
    reason      TEXT           NOT NULL,
    approver_id TEXT,
    started_at  TIMESTAMPTZ    NOT NULL,
    ended_at    TIMESTAMPTZ,
    actions     JSONB          DEFAULT '[]',
    created_at  TIMESTAMPTZ    DEFAULT NOW()
);

-- Index for efficient per-user and per-session lookups (read path only).
CREATE INDEX IF NOT EXISTS idx_break_glass_audit_user_id
    ON break_glass_audit (user_id);

CREATE INDEX IF NOT EXISTS idx_break_glass_audit_session_id
    ON break_glass_audit (session_id);

CREATE INDEX IF NOT EXISTS idx_break_glass_audit_started_at
    ON break_glass_audit (started_at DESC);

-- ---------------------------------------------------------------------------
-- WORM enforcement: deny UPDATE and DELETE at the rule level.
-- Rules fire INSTEAD OF the original statement, so the rows are never
-- touched after insertion.
-- ---------------------------------------------------------------------------
CREATE RULE no_update_break_glass
    AS ON UPDATE TO break_glass_audit
    DO INSTEAD NOTHING;

CREATE RULE no_delete_break_glass
    AS ON DELETE TO break_glass_audit
    DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- Optional: revoke UPDATE/DELETE privileges from the application role so
-- that the rules are backed by an additional permission boundary.
-- Replace 'app_role' with the actual DB role used by the service.
-- ---------------------------------------------------------------------------
-- REVOKE UPDATE, DELETE ON break_glass_audit FROM app_role;
