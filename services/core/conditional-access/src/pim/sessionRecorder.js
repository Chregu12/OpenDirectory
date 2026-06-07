/**
 * PIM Session Recorder
 * Persistent recording and replay of privileged sessions using PostgreSQL.
 * Falls back to in-memory storage when no db pool is provided (test/dev mode).
 *
 * Sensitive activity details (commands, keystrokes, etc.) are encrypted at rest
 * using AES-256-GCM via the shared fieldEncryption utility.
 */

const crypto = require('crypto');
const { encrypt, decrypt } = require('../crypto/fieldEncryption');

class SessionRecorder {
    /**
     * @param {import('pg').Pool|null} db - PostgreSQL pool (optional; uses in-memory fallback)
     */
    constructor(db) {
        this.db = db || null;
        // In-memory fallback when no DB is wired up
        this._records = new Map();
    }

    /**
     * Start a new session recording for a PIM elevation.
     * @returns {Promise<string>} sessionRecordId
     */
    async startRecording(elevationId, userId, roleId) {
        const id = crypto.randomUUID();

        if (this.db) {
            const result = await this.db.query(
                `INSERT INTO pim_session_records (id, elevation_id, user_id, role_id)
                 VALUES ($1, $2, $3, $4)
                 RETURNING id`,
                [id, elevationId, userId, roleId]
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
            activities: [],
            totalRiskScore: 0
        });
        return id;
    }

    /**
     * Append a single activity entry to an existing session record.
     * The `details` field is encrypted before persistence to protect sensitive
     * data such as commands, keystrokes, or file paths captured during the session.
     *
     * @param {string} sessionRecordId
     * @param {{ activityType: string, details: object, riskScore: number, timestamp?: Date }} activity
     */
    async recordActivity(sessionRecordId, { activityType, details, riskScore, timestamp }) {
        const ts = timestamp || new Date();
        // Encrypt the details payload before storing to protect sensitive session data.
        const encryptedDetails = encrypt(JSON.stringify(details));
        const entry = { activityType, details: encryptedDetails, riskScore, timestamp: ts };

        if (this.db) {
            // Append to JSONB array and update rolling risk score
            await this.db.query(
                `UPDATE pim_session_records
                 SET activities = activities || $1::jsonb,
                     total_risk_score = LEAST(1.0,
                         (total_risk_score * (jsonb_array_length(activities))::numeric + $2) /
                         GREATEST(1, (jsonb_array_length(activities) + 1)::numeric)
                     )
                 WHERE id = $3`,
                [JSON.stringify(entry), riskScore || 0, sessionRecordId]
            );
            return;
        }

        const record = this._records.get(sessionRecordId);
        if (!record) throw new Error(`Session record ${sessionRecordId} not found`);
        record.activities.push(entry);
        // Recalculate rolling average risk score
        const total = record.activities.reduce((s, a) => s + (a.riskScore || 0), 0);
        record.totalRiskScore = Math.min(1.0, total / record.activities.length);
    }

    /**
     * Decrypt the `details` field of an activity entry.
     * Used internally when returning activities to callers.
     * @param {object} activity - Raw activity entry from storage
     * @returns {object} Activity with `details` decrypted and parsed back to an object
     */
    _decryptActivity(activity) {
        if (!activity || activity.details === null || activity.details === undefined) {
            return activity;
        }
        try {
            const decryptedStr = decrypt(activity.details);
            return { ...activity, details: decryptedStr ? JSON.parse(decryptedStr) : null };
        } catch {
            // If decryption or parsing fails return the raw value rather than crashing.
            return activity;
        }
    }

    /**
     * Mark a session recording as complete.
     * @param {string} sessionRecordId
     * @param {{ reason: string }} options
     */
    async stopRecording(sessionRecordId, { reason }) {
        if (this.db) {
            await this.db.query(
                `UPDATE pim_session_records
                 SET ended_at = NOW(), end_reason = $1
                 WHERE id = $2`,
                [reason, sessionRecordId]
            );
            return;
        }

        const record = this._records.get(sessionRecordId);
        if (!record) throw new Error(`Session record ${sessionRecordId} not found`);
        record.endedAt = new Date();
        record.endReason = reason;
    }

    /**
     * Retrieve a full session record including all activities.
     * Activity `details` fields are decrypted before being returned.
     * @returns {Promise<object>}
     */
    async getSessionRecord(sessionRecordId) {
        if (this.db) {
            const result = await this.db.query(
                `SELECT id, elevation_id AS "elevationId", user_id AS "userId",
                        role_id AS "roleId", started_at AS "startedAt",
                        ended_at AS "endedAt", end_reason AS "endReason",
                        activities, total_risk_score AS "totalRiskScore"
                 FROM pim_session_records WHERE id = $1`,
                [sessionRecordId]
            );
            if (!result.rows.length) return null;
            const row = result.rows[0];
            row.activities = (row.activities || []).map(a => this._decryptActivity(a));
            return row;
        }

        const record = this._records.get(sessionRecordId);
        if (!record) return null;
        return {
            ...record,
            activities: (record.activities || []).map(a => this._decryptActivity(a))
        };
    }

    /**
     * List session records with optional filters.
     * @param {{ userId?: string, roleId?: string, from?: Date, to?: Date, limit?: number }} filters
     * @returns {Promise<object[]>}
     */
    async listSessionRecords({ userId, roleId, from, to, limit = 100 } = {}) {
        if (this.db) {
            const conditions = [];
            const values = [];
            let idx = 1;

            if (userId) { conditions.push(`user_id = $${idx++}`); values.push(userId); }
            if (roleId) { conditions.push(`role_id = $${idx++}`); values.push(roleId); }
            if (from)   { conditions.push(`started_at >= $${idx++}`); values.push(from); }
            if (to)     { conditions.push(`started_at <= $${idx++}`); values.push(to); }

            const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
            values.push(limit);

            const result = await this.db.query(
                `SELECT id, elevation_id AS "elevationId", user_id AS "userId",
                        role_id AS "roleId", started_at AS "startedAt",
                        ended_at AS "endedAt", end_reason AS "endReason",
                        total_risk_score AS "totalRiskScore"
                 FROM pim_session_records ${where}
                 ORDER BY started_at DESC
                 LIMIT $${idx}`,
                values
            );
            return result.rows;
        }

        let records = Array.from(this._records.values());
        if (userId)  records = records.filter(r => r.userId === userId);
        if (roleId)  records = records.filter(r => r.roleId === roleId);
        if (from)    records = records.filter(r => r.startedAt >= from);
        if (to)      records = records.filter(r => r.startedAt <= to);
        return records
            .sort((a, b) => b.startedAt - a.startedAt)
            .slice(0, limit);
    }

    /**
     * Return all activities for a session ordered by timestamp (for replay).
     * @param {string} sessionRecordId
     * @returns {Promise<object[]>}
     */
    async replaySession(sessionRecordId) {
        const record = await this.getSessionRecord(sessionRecordId);
        if (!record) throw new Error(`Session record ${sessionRecordId} not found`);
        const activities = record.activities || [];
        return [...activities].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    }
}

module.exports = SessionRecorder;
