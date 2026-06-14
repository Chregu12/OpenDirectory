/**
 * Break-Glass Audit Repository
 *
 * Provides append-only persistence for break-glass (emergency-access) events
 * in the `break_glass_audit` table defined in migration 001_worm_audit.sql.
 *
 * Compliance notes:
 *  - INSERT is the ONLY write operation exposed by this class.
 *  - No update() or delete() methods exist intentionally; the PostgreSQL WORM
 *    rules (no_update_break_glass, no_delete_break_glass) enforce the same
 *    constraint at the database level as a second layer of defence.
 *  - getBreakGlassAuditLog() is a read-only query with optional filters.
 */

'use strict';

class BreakGlassAuditRepository {
    /**
     * @param {object} db - A pg (node-postgres) Pool or Client instance.
     */
    constructor(db) {
        if (!db) {
            throw new Error('BreakGlassAuditRepository requires a database connection');
        }
        this._db = db;
    }

    /**
     * Record a break-glass event.
     *
     * This is the ONLY write path.  It maps directly to an INSERT so that
     * the PostgreSQL WORM rules have nothing to intercept for legitimate writes.
     *
     * @param {object} event
     * @param {string}   event.sessionId   - Unique ID for this break-glass session.
     * @param {string}   event.userId      - ID of the user who activated break-glass.
     * @param {string}   event.reason      - Business justification.
     * @param {string}   [event.approverId] - ID of the approver (null for self-approved).
     * @param {Date}     event.startedAt   - When the session started.
     * @param {Date}     [event.endedAt]   - When the session ended (null if still active).
     * @param {Array}    [event.actions]   - Array of activity objects recorded during session.
     * @returns {Promise<object>} The inserted row.
     */
    async recordBreakGlassEvent(event) {
        const {
            sessionId,
            userId,
            reason,
            approverId = null,
            startedAt,
            endedAt = null,
            actions = []
        } = event;

        const result = await this._db.query(
            `INSERT INTO break_glass_audit
                (session_id, user_id, reason, approver_id, started_at, ended_at, actions)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *`,
            [
                sessionId,
                userId,
                reason,
                approverId,
                startedAt,
                endedAt,
                JSON.stringify(actions)
            ]
        );

        return result.rows[0];
    }

    /**
     * Read break-glass audit records.  This is a read-only operation.
     *
     * @param {object} [filters]
     * @param {string}  [filters.userId]      - Filter by user ID.
     * @param {string}  [filters.sessionId]   - Filter by session ID.
     * @param {string}  [filters.approverId]  - Filter by approver ID.
     * @param {Date}    [filters.startedAfter] - Only rows with started_at >= this date.
     * @param {Date}    [filters.startedBefore] - Only rows with started_at <= this date.
     * @param {number}  [filters.limit=100]   - Maximum rows to return (capped at 1000).
     * @param {number}  [filters.offset=0]    - Pagination offset.
     * @returns {Promise<{rows: object[], total: number}>}
     */
    async getBreakGlassAuditLog(filters = {}) {
        const {
            userId,
            sessionId,
            approverId,
            startedAfter,
            startedBefore,
            limit = 100,
            offset = 0
        } = filters;

        const conditions = [];
        const params = [];

        if (userId) {
            params.push(userId);
            conditions.push(`user_id = $${params.length}`);
        }
        if (sessionId) {
            params.push(sessionId);
            conditions.push(`session_id = $${params.length}`);
        }
        if (approverId) {
            params.push(approverId);
            conditions.push(`approver_id = $${params.length}`);
        }
        if (startedAfter) {
            params.push(startedAfter);
            conditions.push(`started_at >= $${params.length}`);
        }
        if (startedBefore) {
            params.push(startedBefore);
            conditions.push(`started_at <= $${params.length}`);
        }

        const whereClause = conditions.length > 0
            ? `WHERE ${conditions.join(' AND ')}`
            : '';

        const safeLimit = Math.min(Number(limit) || 100, 1000);
        const safeOffset = Math.max(Number(offset) || 0, 0);

        // Count query (no LIMIT/OFFSET)
        const countResult = await this._db.query(
            `SELECT COUNT(*) AS total FROM break_glass_audit ${whereClause}`,
            params
        );
        const total = parseInt(countResult.rows[0].total, 10);

        // Data query
        params.push(safeLimit, safeOffset);
        const dataResult = await this._db.query(
            `SELECT id, session_id, user_id, reason, approver_id,
                    started_at, ended_at, actions, created_at
             FROM break_glass_audit
             ${whereClause}
             ORDER BY started_at DESC
             LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );

        return {
            rows: dataResult.rows,
            total,
            limit: safeLimit,
            offset: safeOffset
        };
    }
}

module.exports = BreakGlassAuditRepository;
