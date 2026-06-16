/**
 * PIM Session Recorder
 *
 * Persistent, append-only recording of privileged sessions using the
 * separate `pim_sessions` / `pim_session_activities` store defined in
 * migration 002_session_recordings.sql.
 *
 * Compliance notes:
 *  - `pim_session_activities` is WORM-protected at the DB level via
 *    no_update_pim_session_activities / no_delete_pim_session_activities rules.
 *  - Activity details are stored as an AES-256-GCM encrypted blob
 *    (details_encrypted column) produced by fieldEncryption.js.
 *  - Retention policy: 90 days active, then ARCHIVED (archived_at set).
 *    Records are NEVER deleted — see getRetentionPolicy().
 *  - Falls back to in-memory storage when no db pool is provided
 *    (useful for tests and development without a database).
 */

'use strict';

const crypto = require('crypto');
const { encrypt, decrypt } = require('../crypto/fieldEncryption');

class SessionRecorder {
    /**
     * @param {import('pg').Pool|null} db - PostgreSQL pool (optional; uses in-memory fallback)
     */
    constructor(db) {
        this.db = db || null;
        // In-memory fallback when no DB is wired up
        this._records = new Map();       // id → session header
        this._activities = new Map();    // id → activity[]
    }

    // -------------------------------------------------------------------------
    // Retention policy
    // -------------------------------------------------------------------------

    /**
     * Return the retention policy for PIM session recordings.
     *
     * `deleteAfter: false`  — records are NEVER deleted.
     * `archiveAfter: 90`    — records older than 90 days have `archived_at` set
     *                          by a scheduled archival job; they remain queryable.
     *
     * @returns {{ retentionDays: number, deleteAfter: false, archiveAfter: number }}
     */
    getRetentionPolicy() {
        return {
            retentionDays: 90,
            deleteAfter: false,
            archiveAfter: 90
        };
    }

    // -------------------------------------------------------------------------
    // Session lifecycle
    // -------------------------------------------------------------------------

    /**
     * Start a new session recording for a PIM elevation.
     * Inserts a row into `pim_sessions`.
     *
     * @param {string} elevationId - Unique ID of the PIM elevation (used as session id).
     * @param {string} userId      - ID of the elevated user.
     * @param {string} roleId      - Role that was activated.
     * @returns {Promise<string>} sessionRecordId
     */
    async startRecording(elevationId, userId, roleId) {
        const id = crypto.randomUUID();

        if (this.db) {
            const result = await this.db.query(
                `INSERT INTO pim_sessions (id, user_id, role, started_at, metadata)
                 VALUES ($1, $2, $3, NOW(), $4)
                 RETURNING id`,
                [id, userId, roleId, JSON.stringify({ elevationId })]
            );
            return result.rows[0].id;
        }

        // In-memory fallback
        this._records.set(id, {
            id,
            elevationId,
            userId,
            roleId,
            startedAt: new Date(),
            endedAt: null,
            endReason: null,
            totalRiskScore: 0
        });
        this._activities.set(id, []);
        return id;
    }

    /**
     * Mark a session recording as complete.
     * Sets `ended_at` on `pim_sessions` (legitimate completion update;
     * NOT WORM-protected — only pim_session_activities is append-only).
     *
     * @param {string} sessionRecordId
     * @param {{ reason: string }} options
     */
    async stopRecording(sessionRecordId, { reason }) {
        if (this.db) {
            await this.db.query(
                `UPDATE pim_sessions
                 SET ended_at = NOW(),
                     metadata = jsonb_set(
                         COALESCE(metadata, '{}'::jsonb),
                         '{endReason}',
                         to_jsonb($1::text)
                     )
                 WHERE id = $2 AND ended_at IS NULL`,
                [reason, sessionRecordId]
            );
            return;
        }

        const record = this._records.get(sessionRecordId);
        if (!record) throw new Error(`Session record ${sessionRecordId} not found`);
        record.endedAt = new Date();
        record.endReason = reason;
    }

    // -------------------------------------------------------------------------
    // Activity recording (append-only)
    // -------------------------------------------------------------------------

    /**
     * Append a single activity entry to `pim_session_activities`.
     *
     * The `details` object is encrypted with AES-256-GCM before storage
     * (details_encrypted column) via fieldEncryption.js.
     *
     * @param {string} sessionRecordId
     * @param {{ activityType: string, details: object, riskScore: number, timestamp?: Date }} activity
     */
    async recordActivity(sessionRecordId, { activityType, details, riskScore, timestamp }) {
        const ts = timestamp || new Date();
        // Encrypt the details payload before storing to protect sensitive session data.
        const detailsEncrypted = encrypt(JSON.stringify(details));

        if (this.db) {
            await this.db.query(
                `INSERT INTO pim_session_activities
                     (session_id, timestamp, type, details_encrypted)
                 VALUES ($1, $2, $3, $4)`,
                [sessionRecordId, ts, activityType, detailsEncrypted]
            );
            return;
        }

        let activities = this._activities.get(sessionRecordId);
        if (!activities) {
            // Lazily initialise if startRecording was not called first
            const record = this._records.get(sessionRecordId);
            if (!record) throw new Error(`Session record ${sessionRecordId} not found`);
            this._activities.set(sessionRecordId, []);
            activities = this._activities.get(sessionRecordId);
        }
        activities.push({
            activityType,
            detailsEncrypted,
            riskScore: riskScore || 0,
            timestamp: ts,
            createdAt: new Date()
        });

        // Update rolling average risk score on the session header
        const record = this._records.get(sessionRecordId);
        if (record) {
            const total = activities.reduce((s, a) => s + (a.riskScore || 0), 0);
            record.totalRiskScore = Math.min(1.0, total / activities.length);
        }
    }

    // -------------------------------------------------------------------------
    // Read path
    // -------------------------------------------------------------------------

    /**
     * Decrypt the `detailsEncrypted` field of an activity entry.
     * Used internally when returning activities to callers.
     *
     * @param {object} activity - Raw activity entry from storage.
     * @returns {object} Activity with a `details` property added (decrypted).
     */
    _decryptActivity(activity) {
        if (!activity) return activity;
        const blob = activity.detailsEncrypted || activity.details_encrypted;
        if (blob === null || blob === undefined) {
            return { ...activity, details: null };
        }
        try {
            const decryptedStr = decrypt(blob);
            return {
                ...activity,
                details: decryptedStr ? JSON.parse(decryptedStr) : null
            };
        } catch {
            // If decryption or parsing fails return the raw value rather than crashing.
            return { ...activity, details: blob };
        }
    }

    /**
     * Retrieve a full session record including all activities.
     * Activity `details_encrypted` fields are decrypted before being returned.
     *
     * @param {string} sessionRecordId
     * @returns {Promise<object|null>}
     */
    async getSessionRecord(sessionRecordId) {
        if (this.db) {
            const sessionResult = await this.db.query(
                `SELECT id,
                        user_id            AS "userId",
                        role               AS "roleId",
                        started_at         AS "startedAt",
                        ended_at           AS "endedAt",
                        metadata->>'endReason'       AS "endReason",
                        (metadata->>'elevationId')   AS "elevationId",
                        created_at         AS "createdAt"
                 FROM pim_sessions WHERE id = $1`,
                [sessionRecordId]
            );
            if (!sessionResult.rows.length) return null;

            const activitiesResult = await this.db.query(
                `SELECT id, session_id AS "sessionId", timestamp,
                        type AS "activityType",
                        details_encrypted AS "detailsEncrypted",
                        created_at AS "createdAt"
                 FROM pim_session_activities
                 WHERE session_id = $1
                 ORDER BY timestamp ASC`,
                [sessionRecordId]
            );

            const row = sessionResult.rows[0];
            row.activities = activitiesResult.rows.map(a => this._decryptActivity(a));
            row.totalRiskScore = 0; // risk scoring lives in application layer
            return row;
        }

        const record = this._records.get(sessionRecordId);
        if (!record) return null;
        const activities = (this._activities.get(sessionRecordId) || [])
            .map(a => this._decryptActivity(a));
        return { ...record, activities };
    }

    /**
     * List session records with optional filters.
     *
     * @param {{ userId?: string, roleId?: string, from?: Date, to?: Date, limit?: number }} filters
     * @returns {Promise<object[]>}
     */
    async listSessionRecords({ userId, roleId, from, to, limit = 100 } = {}) {
        if (this.db) {
            const conditions = [];
            const values = [];
            let idx = 1;

            if (userId) { conditions.push(`user_id = $${idx++}`); values.push(userId); }
            if (roleId) { conditions.push(`role = $${idx++}`);    values.push(roleId); }
            if (from)   { conditions.push(`started_at >= $${idx++}`); values.push(from); }
            if (to)     { conditions.push(`started_at <= $${idx++}`); values.push(to); }

            const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
            values.push(limit);

            const result = await this.db.query(
                `SELECT id,
                        user_id        AS "userId",
                        role           AS "roleId",
                        started_at     AS "startedAt",
                        ended_at       AS "endedAt",
                        metadata->>'endReason'  AS "endReason",
                        created_at     AS "createdAt"
                 FROM pim_sessions ${where}
                 ORDER BY started_at DESC
                 LIMIT $${idx}`,
                values
            );
            return result.rows;
        }

        let records = Array.from(this._records.values());
        if (userId) records = records.filter(r => r.userId === userId);
        if (roleId) records = records.filter(r => r.roleId === roleId);
        if (from)   records = records.filter(r => r.startedAt >= from);
        if (to)     records = records.filter(r => r.startedAt <= to);
        return records
            .sort((a, b) => b.startedAt - a.startedAt)
            .slice(0, limit);
    }

    /**
     * Return all activities for a session ordered by timestamp (for replay).
     * Activity details are decrypted before returning.
     *
     * @param {string} sessionRecordId
     * @returns {Promise<object[]>}
     */
    async replaySession(sessionRecordId) {
        if (this.db) {
            const result = await this.db.query(
                `SELECT id, session_id AS "sessionId", timestamp,
                        type AS "activityType",
                        details_encrypted AS "detailsEncrypted",
                        created_at AS "createdAt"
                 FROM pim_session_activities
                 WHERE session_id = $1
                 ORDER BY timestamp ASC`,
                [sessionRecordId]
            );
            return result.rows.map(a => this._decryptActivity(a));
        }

        const record = this._records.get(sessionRecordId);
        if (!record) throw new Error(`Session record ${sessionRecordId} not found`);
        const activities = this._activities.get(sessionRecordId) || [];
        return [...activities]
            .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
            .map(a => this._decryptActivity(a));
    }

    // -------------------------------------------------------------------------
    // Archival (retention enforcement — never deletes)
    // -------------------------------------------------------------------------

    /**
     * Archive activity records older than `archiveAfter` days by setting
     * `archived_at = NOW()`.  Records remain in the table (no DELETE).
     *
     * This method is intended to be called by a scheduled job (e.g. daily cron).
     *
     * @returns {Promise<number>} Number of rows archived.
     */
    async archiveExpiredActivities() {
        const { archiveAfter } = this.getRetentionPolicy();

        if (this.db) {
            const result = await this.db.query(
                `UPDATE pim_session_activities
                 SET archived_at = NOW()
                 WHERE archived_at IS NULL
                   AND created_at < NOW() - ($1 || ' days')::interval`,
                [archiveAfter]
            );
            return result.rowCount || 0;
        }

        // In-memory: mark activities older than the threshold as archived
        let count = 0;
        const cutoff = new Date(Date.now() - archiveAfter * 24 * 60 * 60 * 1000);
        for (const activities of this._activities.values()) {
            for (const a of activities) {
                if (!a.archivedAt && a.createdAt < cutoff) {
                    a.archivedAt = new Date();
                    count++;
                }
            }
        }
        return count;
    }
}

module.exports = SessionRecorder;
