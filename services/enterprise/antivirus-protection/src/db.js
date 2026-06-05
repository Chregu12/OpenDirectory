'use strict';

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    database: process.env.DB_NAME || 'antivirus_db',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

/**
 * Run SQL migrations from the migrations directory.
 */
async function initDb() {
    const migrationPath = path.join(__dirname, '../migrations/001_antivirus.sql');
    const sql = fs.readFileSync(migrationPath, 'utf8');
    await pool.query(sql);
}

/**
 * Upsert device AV status row.
 */
async function upsertDeviceStatus(deviceId, platform, clamavVersion, sigVersion, realtimeEnabled) {
    await pool.query(
        `INSERT INTO av_devices (device_id, platform, clamav_version, signature_version, realtime_enabled, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW())
         ON CONFLICT (device_id) DO UPDATE SET
           platform          = EXCLUDED.platform,
           clamav_version    = EXCLUDED.clamav_version,
           signature_version = EXCLUDED.signature_version,
           realtime_enabled  = EXCLUDED.realtime_enabled,
           updated_at        = NOW()`,
        [deviceId, platform, clamavVersion || null, sigVersion || null, realtimeEnabled || false]
    );
}

/**
 * Insert threats detected during a scan.
 * Returns the inserted rows.
 */
async function saveThreats(deviceId, threats, scannedAt) {
    if (!threats || threats.length === 0) return [];
    const rows = [];
    for (const t of threats) {
        const res = await pool.query(
            `INSERT INTO av_threats (device_id, threat_name, threat_path, detected_at)
             VALUES ($1, $2, $3, $4)
             RETURNING *`,
            [deviceId, t.signature || t.threat_name || 'Unknown', t.path || t.threat_path || null, scannedAt || new Date()]
        );
        rows.push(res.rows[0]);
    }
    return rows;
}

/**
 * Record a completed scan and update device last_scan timestamp.
 */
async function saveScanResult(deviceId, scanId, threats, rawOutput, scannedAt) {
    const threatCount = threats ? threats.length : 0;
    const scanAt = scannedAt || new Date();

    // Ensure device row exists before inserting scan (FK constraint)
    await pool.query(
        `INSERT INTO av_devices (device_id, updated_at)
         VALUES ($1, NOW())
         ON CONFLICT (device_id) DO NOTHING`,
        [deviceId]
    );

    const res = await pool.query(
        `INSERT INTO av_scans (id, device_id, threats_found, raw_output, completed_at, started_at)
         VALUES ($1, $2, $3, $4, $5, $5)
         RETURNING *`,
        [scanId || require('crypto').randomUUID(), deviceId, threatCount, rawOutput || null, scanAt]
    );

    await pool.query(
        `UPDATE av_devices SET last_scan = $1, threats_found = threats_found + $2, updated_at = NOW()
         WHERE device_id = $3`,
        [scanAt, threatCount, deviceId]
    );

    return res.rows[0];
}

/**
 * Get recent threats (latest first).
 */
async function getThreats(limit = 100) {
    const res = await pool.query(
        `SELECT * FROM av_threats ORDER BY detected_at DESC LIMIT $1`,
        [limit]
    );
    return res.rows;
}

/**
 * Get all AV-tracked devices.
 */
async function getDevices() {
    const res = await pool.query(
        `SELECT * FROM av_devices ORDER BY updated_at DESC`
    );
    return res.rows;
}

/**
 * Get recent scans (latest first).
 */
async function getScans(limit = 50) {
    const res = await pool.query(
        `SELECT * FROM av_scans ORDER BY completed_at DESC LIMIT $1`,
        [limit]
    );
    return res.rows;
}

/**
 * Mark a threat as quarantined and add a quarantine record.
 */
async function quarantineFile(deviceId, threatId) {
    const threatRes = await pool.query(
        `UPDATE av_threats SET quarantined = true, status = 'quarantined'
         WHERE id = $1 RETURNING *`,
        [threatId]
    );
    if (threatRes.rows.length === 0) {
        throw new Error(`Threat ${threatId} not found`);
    }
    const threat = threatRes.rows[0];
    const qRes = await pool.query(
        `INSERT INTO av_quarantine (device_id, threat_id, file_path, threat_name)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [deviceId, threatId, threat.threat_path || '', threat.threat_name]
    );
    await pool.query(
        `UPDATE av_devices SET quarantined_files = quarantined_files + 1, updated_at = NOW()
         WHERE device_id = $1`,
        [deviceId]
    );
    return qRes.rows[0];
}

/**
 * Get all quarantined files.
 */
async function getQuarantine() {
    const res = await pool.query(
        `SELECT * FROM av_quarantine ORDER BY quarantined_at DESC`
    );
    return res.rows;
}

/**
 * Aggregate statistics for the dashboard.
 */
async function getStatistics() {
    const [threatsRes, devicesRes, scansRes, quarantineRes] = await Promise.all([
        pool.query(`SELECT COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE status = 'active') AS active,
                           COUNT(*) FILTER (WHERE status = 'quarantined') AS quarantined
                    FROM av_threats`),
        pool.query(`SELECT COUNT(*) AS total FROM av_devices`),
        pool.query(`SELECT COUNT(*) AS total FROM av_scans`),
        pool.query(`SELECT COUNT(*) AS total FROM av_quarantine`),
    ]);
    return {
        threats: {
            total: parseInt(threatsRes.rows[0].total, 10),
            active: parseInt(threatsRes.rows[0].active, 10),
            quarantined: parseInt(threatsRes.rows[0].quarantined, 10),
        },
        devices: {
            total: parseInt(devicesRes.rows[0].total, 10),
        },
        scans: {
            total: parseInt(scansRes.rows[0].total, 10),
        },
        quarantine: {
            total: parseInt(quarantineRes.rows[0].total, 10),
        },
    };
}

/**
 * Health check — returns true if DB is reachable.
 */
async function isAvailable() {
    try {
        await pool.query('SELECT 1');
        return true;
    } catch {
        return false;
    }
}

module.exports = {
    initDb,
    upsertDeviceStatus,
    saveThreats,
    saveScanResult,
    getThreats,
    getDevices,
    getScans,
    quarantineFile,
    getQuarantine,
    getStatistics,
    isAvailable,
};
