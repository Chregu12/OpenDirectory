'use strict';

/**
 * A small STATEFUL fake `pg` Pool for the `alerts` table, shared by
 * alertStore.dbFirst.test.js and api.e2e.test.js.
 *
 * Deliberately more realistic than the "always resolve `{rows: [],
 * rowCount: 0}`" mock shape: that shape makes db.isAvailable() true
 * (SELECT 1 resolves) while every subsequent SELECT still comes back
 * empty, which would make a create -> findById roundtrip look like
 * persistence when it's actually silently falling through to the
 * in-memory Map (see src/database/alertStore.js's findById/findAll,
 * which only fall back to `_alerts` when the DB helper returns
 * `undefined`/`null`, NOT when it returns an empty array). This fake
 * actually stores rows in a JS Map and answers the exact SQL src/db/client.js
 * and src/database/alertStore.js issue, so a passing roundtrip test proves
 * the DB code path itself works.
 *
 * It also mimics the two node-postgres type-parsing behaviors relevant to
 * the createdAt/updatedAt type-regression test:
 *   - DOUBLE PRECISION columns (created_at, updated_at, ...) come back as
 *     JS `number` — modeled here simply by storing/returning whatever
 *     numeric value the caller passed in (AlertStore always passes
 *     Date.now() numbers), i.e. no stringification happens anywhere in
 *     this fake, matching real pg's float8 OID parser.
 *   - JSONB columns (labels, notifications_sent) come back already parsed
 *     into a JS object/array, NOT as the raw string — modeled by
 *     JSON.parse()-ing the stringified param on write.
 */
function makeFakeAlertsPool() {
  const alertsTbl = new Map();

  function query(sql, params = []) {
    const s = sql.trim();

    if (/^SELECT 1\b/i.test(s)) return Promise.resolve({ rows: [{ '?column?': 1 }], rowCount: 1 });

    // Migrations run as one multi-statement query against the whole .sql
    // file body (see src/db/client.js#runMigrations) — no-op them here.
    if (/CREATE TABLE|CREATE INDEX/i.test(s)) return Promise.resolve({ rows: [], rowCount: 0 });

    if (/^INSERT INTO alerts/i.test(s)) {
      const [
        id, name, service, severity, status, message, metric, threshold, current_value,
        labels, notifications_sent, created_at, updated_at, acknowledged_at, acknowledged_by, resolved_at,
      ] = params;
      if (!alertsTbl.has(id)) {
        alertsTbl.set(id, {
          id, name, service, severity, status, message, metric, threshold, current_value,
          labels: JSON.parse(labels),
          notifications_sent: JSON.parse(notifications_sent),
          created_at, updated_at, acknowledged_at, acknowledged_by, resolved_at,
        });
      }
      return Promise.resolve({ rows: [], rowCount: 1 });
    }

    if (/^UPDATE alerts/i.test(s)) {
      const [
        id, name, service, severity, status, message, metric, threshold, current_value,
        labels, notifications_sent, updated_at, acknowledged_at, acknowledged_by, resolved_at,
      ] = params;
      const row = alertsTbl.get(id);
      if (row) {
        Object.assign(row, {
          name, service, severity, status, message, metric, threshold, current_value,
          labels: JSON.parse(labels),
          notifications_sent: JSON.parse(notifications_sent),
          updated_at, acknowledged_at, acknowledged_by, resolved_at,
        });
      }
      return Promise.resolve({ rows: [], rowCount: row ? 1 : 0 });
    }

    if (/^DELETE FROM alerts/i.test(s)) {
      const [id] = params;
      const existed = alertsTbl.delete(id);
      return Promise.resolve({ rows: [], rowCount: existed ? 1 : 0 });
    }

    if (/FROM alerts WHERE id=/i.test(s)) {
      const [id] = params;
      const row = alertsTbl.get(id);
      return Promise.resolve({ rows: row ? [row] : [], rowCount: row ? 1 : 0 });
    }

    if (/FROM alerts/i.test(s)) {
      return Promise.resolve({ rows: [...alertsTbl.values()], rowCount: alertsTbl.size });
    }

    return Promise.resolve({ rows: [], rowCount: 0 });
  }

  return {
    query: jest.fn(query),
    connect: jest.fn().mockResolvedValue({ query: jest.fn(query), release: jest.fn() }),
    end: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
    _table: alertsTbl,
  };
}

module.exports = { makeFakeAlertsPool };
