/**
 * PIM Session Recorder
 * Persistent recording and replay of privileged sessions using PostgreSQL.
 * Falls back to in-memory storage when no db pool is provided (test/dev mode).
 */

const crypto = require('crypto');

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
     * @param {string} sessionRecordId
     * @param {{ activityType: string, details: object, riskScore: number, timestamp?: Date }} activity
     */
    async recordActivity(sessionRecordId, { activityType, details, riskScore, timestamp }) {
        const ts = timestamp || new Date();
        const entry = { activityType, details, riskScore, timestamp: ts };

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
            return result.rows[0];
        }

        return this._records.get(sessionRecordId) || null;
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
