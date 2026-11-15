'use strict';
const path = require('node:path');
const { AsyncLocalStorage } = require('node:async_hooks');
const root = process.env.OD_DIAGNOSTIC_SOURCE_ROOT;
if (!root || !process.env.OAUTH_TEST_DATABASE_URL) throw new Error('Explicit disposable test source and database required');
const { Pool } = require(require.resolve('pg', { paths: [path.join(root, 'services/core/oauth-provider')] }));
const trace = new AsyncLocalStorage();
const load = file => require(path.join(root, 'services/core/policy-service/src/licenses', file));
function emit(value) { process.stdout.write('OD_OFFBOARDING_DIAGNOSTIC ' + JSON.stringify(value) + '\n'); }
function wrap(Type, methods) {
  for (const name of methods) {
    const original = Type.prototype[name];
    if (typeof original !== 'function') throw new Error('Unknown diagnostic phase: ' + name);
    Type.prototype[name] = async function (...args) {
      const state = trace.getStore();
      if (!state) return original.apply(this, args);
      const id = ++state.sequence, phase = Type.name + '.' + name, start = Date.now();
      state.active.set(id, { phase, start });
      try { return await original.apply(this, args); }
      finally {
        state.active.delete(id);
        state.finished.push({ phase, durationMs: Date.now() - start });
      }
    };
  }
}
const { CompanyOffboarding } = load('CompanyOffboarding');
wrap(CompanyOffboarding, ['source', 'view', 'execute', 'capture', 'observe']);
wrap(load('CompanyOffboardingJournal').CompanyOffboardingJournal, ['ready', 'load', 'create', 'save']);
wrap(load('CompanyOffboardingIdentity').CompanyOffboardingIdentity, ['user', 'disable']);
const original = CompanyOffboarding.prototype.create;
CompanyOffboarding.prototype.create = async function (...args) {
  const state = { sequence: 0, active: new Map(), finished: [], start: Date.now() };
  const observer = new Pool({ connectionString: process.env.OAUTH_TEST_DATABASE_URL, max: 1, connectionTimeoutMillis: 1500, statement_timeout: 1500, query_timeout: 2000, allowExitOnIdle: true, application_name: 'od-ci-offboarding-observer' });
  async function snapshot() {
    const active = [...state.active.values()].map(value => ({ phase: value.phase, durationMs: Date.now() - value.start }));
    let databases;
    try {
      databases = (await observer.query(`SELECT regexp_replace(application_name, '[0-9a-f]{32}$', '<fixture>') AS application,
        pid,state,wait_event_type,wait_event,round(extract(epoch FROM clock_timestamp()-query_start)*1000)::bigint::text AS query_ms,
        substring(ltrim(query) FROM '^([A-Za-z]+)') AS sql_verb,pg_blocking_pids(pid) AS blockers
        FROM pg_stat_activity WHERE application_name LIKE 'od-native-%' AND state<>'idle' ORDER BY pid`)).rows;
    } catch (error) { databases = { unavailable: true, code: error.code || error.name }; }
    emit({ event: 'snapshot', durationMs: Date.now() - state.start, active, finished: state.finished, databases });
  }
  const timers = [20000, 40000, 55000].map(delay => setTimeout(() => { void snapshot(); }, delay).unref());
  return trace.run(state, async () => {
    try { return await original.apply(this, args); }
    finally {
      timers.forEach(clearTimeout);
      emit({ event: 'complete', durationMs: Date.now() - state.start, finished: state.finished });
      await observer.end();
    }
  });
};
