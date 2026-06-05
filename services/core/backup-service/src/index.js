#!/usr/bin/env node

/**
 * OpenDirectory Backup Scheduler Service
 * Manages backup jobs, scheduling via cron, and run history
 * Port: 3011  (proxied by api-gateway from /api/backup)
 */

'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const client = require('prom-client');

// ─── PostgreSQL (optional) ────────────────────────────────────────────────────
let pg = null;
let pgPool = null;
let dbAvailable = false;

try {
  pg = require('pg');
  pgPool = new pg.Pool({
    host: process.env.POSTGRES_HOST || 'postgresql',
    port: parseInt(process.env.POSTGRES_PORT || '5432'),
    database: process.env.POSTGRES_DB || 'opendirectory',
    user: process.env.POSTGRES_USER || 'opendirectory',
    password: process.env.POSTGRES_PASSWORD || 'opendirectory',
    connectionTimeoutMillis: 3000,
    idleTimeoutMillis: 10000,
    max: 5,
  });
} catch (_) {
  // pg not installed — use in-memory store
}

// ─── In-memory store (fallback) ───────────────────────────────────────────────
const memoryStore = {
  jobs: [],
  runs: [],
};

// Pre-seed default backup jobs
const defaultJobs = [
  {
    id: uuidv4(),
    name: 'Tägliche LLDAP-Sicherung',
    type: 'full',
    schedule: '0 2 * * *',
    target: 'lldap',
    retention_days: 30,
    enabled: true,
    last_run: null,
    next_run: getNextRun('0 2 * * *'),
    last_status: null,
    created_at: new Date().toISOString(),
  },
  {
    id: uuidv4(),
    name: 'Stündliche Konfig-Sicherung',
    type: 'incremental',
    schedule: '0 * * * *',
    target: 'config',
    retention_days: 7,
    enabled: true,
    last_run: null,
    next_run: getNextRun('0 * * * *'),
    last_status: null,
    created_at: new Date().toISOString(),
  },
  {
    id: uuidv4(),
    name: 'Wöchentliche Vollsicherung',
    type: 'full',
    schedule: '0 3 * * 0',
    target: 'all',
    retention_days: 90,
    enabled: true,
    last_run: null,
    next_run: getNextRun('0 3 * * 0'),
    last_status: null,
    created_at: new Date().toISOString(),
  },
];

memoryStore.jobs = defaultJobs;

// ─── Prometheus metrics ───────────────────────────────────────────────────────
const register = new client.Registry();
client.collectDefaultMetrics({ register });

const backupJobsTotal = new client.Gauge({
  name: 'backup_jobs_total',
  help: 'Total number of backup jobs',
  registers: [register],
});

const backupRunsTotal = new client.Counter({
  name: 'backup_runs_total',
  help: 'Total number of backup runs',
  labelNames: ['status'],
  registers: [register],
});

const backupSizeBytes = new client.Gauge({
  name: 'backup_size_bytes_total',
  help: 'Total size of all backups in bytes',
  registers: [register],
});

const backupDurationSeconds = new client.Histogram({
  name: 'backup_duration_seconds',
  help: 'Duration of backup runs in seconds',
  buckets: [1, 2, 5, 10, 30, 60, 120, 300],
  registers: [register],
});

const httpRequestDuration = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register],
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function getNextRun(schedule) {
  try {
    const parts = schedule.split(' ');
    // Simple approximation — real implementation would parse cron properly
    const now = new Date();
    now.setMinutes(now.getMinutes() + 10);
    return now.toISOString();
  } catch (_) {
    return null;
  }
}

function randomBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function simulateBackupSize(target) {
  const sizes = {
    lldap: randomBetween(50 * 1024 * 1024, 200 * 1024 * 1024),      // 50–200 MB
    config: randomBetween(1 * 1024 * 1024, 10 * 1024 * 1024),        // 1–10 MB
    postgresql: randomBetween(200 * 1024 * 1024, 1024 * 1024 * 1024), // 200 MB–1 GB
    all: randomBetween(500 * 1024 * 1024, 2 * 1024 * 1024 * 1024),   // 500 MB–2 GB
  };
  return sizes[target] || randomBetween(10 * 1024 * 1024, 100 * 1024 * 1024);
}

function generateChecksum() {
  const chars = '0123456789abcdef';
  return Array.from({ length: 64 }, () => chars[Math.floor(Math.random() * 16)]).join('');
}

// ─── Database initialisation ──────────────────────────────────────────────────
async function initDatabase() {
  if (!pgPool) return;
  try {
    const client = await pgPool.connect();
    await client.query(`
      CREATE TABLE IF NOT EXISTS backup_jobs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        schedule VARCHAR(100) NOT NULL,
        target VARCHAR(255) NOT NULL,
        retention_days INTEGER DEFAULT 30,
        enabled BOOLEAN DEFAULT true,
        last_run TIMESTAMPTZ,
        next_run TIMESTAMPTZ,
        last_status VARCHAR(50),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS backup_runs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        job_id UUID REFERENCES backup_jobs(id) ON DELETE CASCADE,
        started_at TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        status VARCHAR(50) DEFAULT 'running',
        size_bytes BIGINT,
        file_path TEXT,
        error TEXT,
        checksum VARCHAR(64)
      );
    `);

    // Seed defaults if table is empty
    const { rows } = await client.query('SELECT COUNT(*) FROM backup_jobs');
    if (parseInt(rows[0].count) === 0) {
      for (const job of defaultJobs) {
        await client.query(
          `INSERT INTO backup_jobs (id,name,type,schedule,target,retention_days,enabled,next_run,created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [job.id, job.name, job.type, job.schedule, job.target,
           job.retention_days, job.enabled, job.next_run, job.created_at]
        );
      }
    }

    client.release();
    dbAvailable = true;
    console.log('[backup-service] PostgreSQL connected and schema initialised');
  } catch (err) {
    console.warn('[backup-service] PostgreSQL unavailable, using in-memory store:', err.message);
    dbAvailable = false;
  }
}

// ─── Data-access helpers (DB or in-memory) ────────────────────────────────────
async function getAllJobs() {
  if (dbAvailable) {
    const { rows } = await pgPool.query('SELECT * FROM backup_jobs ORDER BY created_at DESC');
    return rows;
  }
  return [...memoryStore.jobs];
}

async function getJobById(id) {
  if (dbAvailable) {
    const { rows } = await pgPool.query('SELECT * FROM backup_jobs WHERE id=$1', [id]);
    return rows[0] || null;
  }
  return memoryStore.jobs.find(j => j.id === id) || null;
}

async function createJob(data) {
  const id = uuidv4();
  const now = new Date().toISOString();
  const job = {
    id,
    name: data.name,
    type: data.type,
    schedule: data.schedule,
    target: data.target,
    retention_days: data.retention_days || 30,
    enabled: data.enabled !== false,
    last_run: null,
    next_run: getNextRun(data.schedule),
    last_status: null,
    created_at: now,
  };
  if (dbAvailable) {
    await pgPool.query(
      `INSERT INTO backup_jobs (id,name,type,schedule,target,retention_days,enabled,next_run,created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [job.id, job.name, job.type, job.schedule, job.target,
       job.retention_days, job.enabled, job.next_run, job.created_at]
    );
  } else {
    memoryStore.jobs.push(job);
  }
  return job;
}

async function updateJob(id, data) {
  const job = await getJobById(id);
  if (!job) return null;
  const updated = {
    ...job,
    ...data,
    id,
    updated_at: new Date().toISOString(),
  };
  if (dbAvailable) {
    await pgPool.query(
      `UPDATE backup_jobs SET name=$2,type=$3,schedule=$4,target=$5,
       retention_days=$6,enabled=$7,next_run=$8 WHERE id=$1`,
      [id, updated.name, updated.type, updated.schedule, updated.target,
       updated.retention_days, updated.enabled, getNextRun(updated.schedule)]
    );
  } else {
    const idx = memoryStore.jobs.findIndex(j => j.id === id);
    if (idx !== -1) memoryStore.jobs[idx] = updated;
  }
  return updated;
}

async function deleteJob(id) {
  if (dbAvailable) {
    const { rowCount } = await pgPool.query('DELETE FROM backup_jobs WHERE id=$1', [id]);
    return rowCount > 0;
  }
  const idx = memoryStore.jobs.findIndex(j => j.id === id);
  if (idx === -1) return false;
  memoryStore.jobs.splice(idx, 1);
  return true;
}

async function getAllRuns(jobId) {
  if (dbAvailable) {
    if (jobId) {
      const { rows } = await pgPool.query(
        'SELECT * FROM backup_runs WHERE job_id=$1 ORDER BY started_at DESC', [jobId]);
      return rows;
    }
    const { rows } = await pgPool.query('SELECT * FROM backup_runs ORDER BY started_at DESC LIMIT 200');
    return rows;
  }
  let runs = [...memoryStore.runs];
  if (jobId) runs = runs.filter(r => r.job_id === jobId);
  return runs.sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
}

async function getRunById(id) {
  if (dbAvailable) {
    const { rows } = await pgPool.query('SELECT * FROM backup_runs WHERE id=$1', [id]);
    return rows[0] || null;
  }
  return memoryStore.runs.find(r => r.id === id) || null;
}

async function createRun(jobId) {
  const run = {
    id: uuidv4(),
    job_id: jobId,
    started_at: new Date().toISOString(),
    completed_at: null,
    status: 'running',
    size_bytes: null,
    file_path: null,
    error: null,
    checksum: null,
  };
  if (dbAvailable) {
    await pgPool.query(
      `INSERT INTO backup_runs (id,job_id,started_at,status) VALUES ($1,$2,$3,$4)`,
      [run.id, run.job_id, run.started_at, run.status]
    );
  } else {
    memoryStore.runs.push(run);
  }
  return run;
}

async function finaliseRun(runId, jobId, success, sizeBytes, filePath, error) {
  const completedAt = new Date().toISOString();
  const checksum = success ? generateChecksum() : null;
  const status = success ? 'success' : 'failed';

  if (dbAvailable) {
    await pgPool.query(
      `UPDATE backup_runs SET completed_at=$2,status=$3,size_bytes=$4,file_path=$5,error=$6,checksum=$7
       WHERE id=$1`,
      [runId, completedAt, status, sizeBytes, filePath, error, checksum]
    );
    await pgPool.query(
      `UPDATE backup_jobs SET last_run=$2,last_status=$3,next_run=$4 WHERE id=$5`,
      [completedAt, status, getNextRun(''), jobId]
    );
  } else {
    const run = memoryStore.runs.find(r => r.id === runId);
    if (run) {
      run.completed_at = completedAt;
      run.status = status;
      run.size_bytes = sizeBytes;
      run.file_path = filePath;
      run.error = error || null;
      run.checksum = checksum;
    }
    const job = memoryStore.jobs.find(j => j.id === jobId);
    if (job) {
      job.last_run = completedAt;
      job.last_status = status;
      job.next_run = getNextRun(job.schedule);
    }
  }
}

// ─── Backup execution (simulated) ────────────────────────────────────────────
async function executeBackup(jobId) {
  const job = await getJobById(jobId);
  if (!job) return;

  const run = await createRun(jobId);
  backupRunsTotal.inc({ status: 'started' });
  const startTime = Date.now();

  console.log(`[backup-service] Starting backup: ${job.name} (run ${run.id})`);

  // Simulate backup duration (2–5 seconds)
  const durationMs = randomBetween(2000, 5000);
  await new Promise(resolve => setTimeout(resolve, durationMs));

  // 95% success rate
  const success = Math.random() < 0.95;
  const sizeBytes = success ? simulateBackupSize(job.target) : null;
  const filePath = success
    ? `/backups/${job.target}/${new Date().toISOString().split('T')[0]}-${run.id.slice(0, 8)}.tar.gz`
    : null;
  const error = success ? null : 'Simulated backup failure: disk I/O error';

  await finaliseRun(run.id, jobId, success, sizeBytes, filePath, error);

  const elapsed = (Date.now() - startTime) / 1000;
  backupDurationSeconds.observe(elapsed);
  backupRunsTotal.inc({ status: success ? 'success' : 'failed' });
  if (sizeBytes) backupSizeBytes.inc(sizeBytes);

  console.log(`[backup-service] Backup ${success ? 'succeeded' : 'FAILED'}: ${job.name} in ${elapsed.toFixed(1)}s`);
}

// ─── Active cron tasks registry ───────────────────────────────────────────────
const cronTasks = new Map(); // jobId -> cron.ScheduledTask

async function scheduleCronJob(job) {
  if (!job.enabled) return;
  if (!cron.validate(job.schedule)) {
    console.warn(`[backup-service] Invalid cron expression for job ${job.id}: "${job.schedule}"`);
    return;
  }
  const task = cron.schedule(job.schedule, () => executeBackup(job.id));
  cronTasks.set(job.id, task);
  console.log(`[backup-service] Scheduled: "${job.name}" @ "${job.schedule}"`);
}

function destroyCronJob(jobId) {
  const task = cronTasks.get(jobId);
  if (task) {
    task.destroy();
    cronTasks.delete(jobId);
  }
}

async function initCronJobs() {
  const jobs = await getAllJobs();
  for (const job of jobs) {
    await scheduleCronJob(job);
  }
  console.log(`[backup-service] ${jobs.length} cron job(s) scheduled`);
}

// ─── Express app ─────────────────────────────────────────────────────────────
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());

// Request duration middleware
app.use((req, res, next) => {
  const end = httpRequestDuration.startTimer({
    method: req.method,
    route: req.path,
  });
  res.on('finish', () => end({ status_code: res.statusCode }));
  next();
});

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const jobs = await getAllJobs();
  backupJobsTotal.set(jobs.length);
  res.json({
    status: 'healthy',
    service: 'backup-service',
    version: '1.0.0',
    database: dbAvailable ? 'postgresql' : 'in-memory',
    scheduled_jobs: cronTasks.size,
    timestamp: new Date().toISOString(),
  });
});

// ─── Prometheus metrics endpoint ──────────────────────────────────────────────
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// ─── GET /api/backup/jobs ─────────────────────────────────────────────────────
app.get('/api/backup/jobs', async (req, res) => {
  try {
    const jobs = await getAllJobs();
    backupJobsTotal.set(jobs.length);
    res.json({ jobs, total: jobs.length });
  } catch (err) {
    console.error('[backup-service] GET /api/backup/jobs error:', err);
    res.status(500).json({ error: 'Failed to retrieve backup jobs' });
  }
});

// ─── POST /api/backup/jobs ────────────────────────────────────────────────────
app.post('/api/backup/jobs', async (req, res) => {
  try {
    const { name, type, schedule, target, retention_days } = req.body;
    if (!name || !type || !schedule || !target) {
      return res.status(400).json({ error: 'Missing required fields: name, type, schedule, target' });
    }
    if (!cron.validate(schedule)) {
      return res.status(400).json({ error: `Invalid cron expression: "${schedule}"` });
    }
    const validTypes = ['full', 'incremental', 'differential'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `Invalid type. Must be one of: ${validTypes.join(', ')}` });
    }

    const job = await createJob({ name, type, schedule, target, retention_days });
    await scheduleCronJob(job);
    res.status(201).json({ job });
  } catch (err) {
    console.error('[backup-service] POST /api/backup/jobs error:', err);
    res.status(500).json({ error: 'Failed to create backup job' });
  }
});

// ─── PUT /api/backup/jobs/:id ─────────────────────────────────────────────────
app.put('/api/backup/jobs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await getJobById(id);
    if (!existing) return res.status(404).json({ error: 'Job not found' });

    if (req.body.schedule && !cron.validate(req.body.schedule)) {
      return res.status(400).json({ error: `Invalid cron expression: "${req.body.schedule}"` });
    }

    const updated = await updateJob(id, req.body);

    // Reschedule cron
    destroyCronJob(id);
    await scheduleCronJob(updated);

    res.json({ job: updated });
  } catch (err) {
    console.error('[backup-service] PUT /api/backup/jobs/:id error:', err);
    res.status(500).json({ error: 'Failed to update backup job' });
  }
});

// ─── DELETE /api/backup/jobs/:id ─────────────────────────────────────────────
app.delete('/api/backup/jobs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await deleteJob(id);
    if (!deleted) return res.status(404).json({ error: 'Job not found' });
    destroyCronJob(id);
    res.json({ message: 'Job deleted successfully', id });
  } catch (err) {
    console.error('[backup-service] DELETE /api/backup/jobs/:id error:', err);
    res.status(500).json({ error: 'Failed to delete backup job' });
  }
});

// ─── POST /api/backup/jobs/:id/run ───────────────────────────────────────────
app.post('/api/backup/jobs/:id/run', async (req, res) => {
  try {
    const { id } = req.params;
    const job = await getJobById(id);
    if (!job) return res.status(404).json({ error: 'Job not found' });

    // Fire and forget — return immediately with the run ID
    const run = await createRun(id);
    res.json({
      message: 'Backup triggered',
      run_id: run.id,
      job_id: id,
      started_at: run.started_at,
    });

    // Execute in background
    executeBackup(id).catch(err =>
      console.error(`[backup-service] executeBackup error for job ${id}:`, err)
    );
  } catch (err) {
    console.error('[backup-service] POST /api/backup/jobs/:id/run error:', err);
    res.status(500).json({ error: 'Failed to trigger backup' });
  }
});

// ─── GET /api/backup/runs ─────────────────────────────────────────────────────
app.get('/api/backup/runs', async (req, res) => {
  try {
    const { jobId } = req.query;
    const runs = await getAllRuns(jobId || null);
    res.json({ runs, total: runs.length });
  } catch (err) {
    console.error('[backup-service] GET /api/backup/runs error:', err);
    res.status(500).json({ error: 'Failed to retrieve backup runs' });
  }
});

// ─── GET /api/backup/runs/:id ─────────────────────────────────────────────────
app.get('/api/backup/runs/:id', async (req, res) => {
  try {
    const run = await getRunById(req.params.id);
    if (!run) return res.status(404).json({ error: 'Run not found' });
    res.json({ run });
  } catch (err) {
    console.error('[backup-service] GET /api/backup/runs/:id error:', err);
    res.status(500).json({ error: 'Failed to retrieve run' });
  }
});

// ─── GET /api/backup/stats ───────────────────────────────────────────────────
app.get('/api/backup/stats', async (req, res) => {
  try {
    const [jobs, runs] = await Promise.all([getAllJobs(), getAllRuns(null)]);

    const successfulRuns = runs.filter(r => r.status === 'success');
    const failedRuns = runs.filter(r => r.status === 'failed');
    const totalSizeBytes = successfulRuns.reduce((sum, r) => sum + (r.size_bytes || 0), 0);
    const lastSuccessful = successfulRuns.sort((a, b) =>
      new Date(b.completed_at) - new Date(a.completed_at)
    )[0] || null;

    const enabledJobs = jobs.filter(j => j.enabled);
    const nextScheduled = enabledJobs
      .filter(j => j.next_run)
      .sort((a, b) => new Date(a.next_run) - new Date(b.next_run))[0] || null;

    backupJobsTotal.set(jobs.length);

    res.json({
      stats: {
        total_jobs: jobs.length,
        enabled_jobs: enabledJobs.length,
        total_runs: runs.length,
        successful_runs: successfulRuns.length,
        failed_runs: failedRuns.length,
        total_size_bytes: totalSizeBytes,
        total_size_human: formatBytes(totalSizeBytes),
        last_successful_run: lastSuccessful,
        next_scheduled_job: nextScheduled,
        database: dbAvailable ? 'postgresql' : 'in-memory',
      },
    });
  } catch (err) {
    console.error('[backup-service] GET /api/backup/stats error:', err);
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

// ─── POST /api/backup/restore/:runId ─────────────────────────────────────────
app.post('/api/backup/restore/:runId', async (req, res) => {
  try {
    const run = await getRunById(req.params.runId);
    if (!run) return res.status(404).json({ error: 'Run not found' });
    if (run.status !== 'success') {
      return res.status(400).json({ error: 'Cannot restore from a failed backup run' });
    }

    const restoreId = uuidv4();
    const estimatedDuration = randomBetween(30, 300); // seconds

    console.log(`[backup-service] Restore initiated: run=${run.id}, restore_id=${restoreId}`);

    res.json({
      message: 'Restore initiated',
      restore_id: restoreId,
      run_id: run.id,
      file_path: run.file_path,
      checksum: run.checksum,
      estimated_duration_seconds: estimatedDuration,
      status: 'in_progress',
      initiated_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[backup-service] POST /api/backup/restore/:runId error:', err);
    res.status(500).json({ error: 'Failed to initiate restore' });
  }
});

// ─── Utilities ────────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

// ─── Start server ─────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3011');

async function start() {
  await initDatabase();
  await initCronJobs();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[backup-service] Listening on port ${PORT}`);
    console.log(`[backup-service] Database: ${dbAvailable ? 'PostgreSQL' : 'in-memory'}`);
    console.log(`[backup-service] Cron tasks active: ${cronTasks.size}`);
  });
}

start().catch(err => {
  console.error('[backup-service] Fatal startup error:', err);
  process.exit(1);
});

module.exports = app; // for testing
