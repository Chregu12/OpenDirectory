'use strict';

const { ROLES } = require('../../../../packages/directory-role-contract');

function argumentsForBootstrap(args) {
  const [userId, role, lifetime, reason, ...extra] = args;
  const permanent = lifetime === '--permanent';
  const duration = Number(lifetime);
  if (extra.length || typeof userId !== 'string' || userId.length !== 36 || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(userId)
    || !ROLES.includes(role) || (permanent ? !['admin', 'role-administrator'].includes(role) : !Number.isInteger(duration) || duration < 60 || duration > 28800)
    || typeof reason !== 'string' || reason.trim().length < 10 || reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason)) {
    throw new Error('Usage: bootstrap-role.js USER_UUID CATALOG_ROLE SECONDS|--permanent "reviewed reason (10–500 characters)"; permanent is restricted to offline admin/role-administrator recovery');
  }
  return { userId, role, duration: permanent ? null : duration, reason: reason.trim() };
}

async function bootstrapRole(database, options) {
  const validated = argumentsForBootstrap([options.userId, options.role, options.duration === null ? '--permanent' : String(options.duration), options.reason]);
  return database.transaction(async client => {
    if (!(await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [validated.userId])).rows.length) throw new Error('Canonical user not found');
    const count = Number((await client.query(`SELECT COUNT(*) AS count FROM identity_role_assignments assignment
      JOIN identity_role_activation_policies policy ON policy.role=assignment.role AND policy.version=assignment.policy_version
      WHERE user_id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())
      AND NOT EXISTS(SELECT 1 FROM identity_role_review_leases review WHERE review.target_kind='assignment' AND review.target_id=assignment.id AND (review.state='denied' OR review.deadline_at<=identity_role_review_now()))
      AND (activation_request_id IS NULL OR identity_role_review_eligible((SELECT eligibility_id FROM identity_pim_requests WHERE id=activation_request_id)))`, [validated.userId])).rows[0].count);
    if (count >= 100) throw new Error('Active role-assignment limit reached');
    const result = await client.query(`INSERT INTO identity_role_assignments(user_id,role,reason,expires_at)
      VALUES($1,$2,$3,CASE WHEN $4::int IS NULL THEN NULL ELSE clock_timestamp()+$4*interval '1 second' END) RETURNING id,user_id,role,expires_at`,
    [validated.userId, validated.role, validated.reason, validated.duration]);
    return result.rows[0];
  }, { actor: JSON.stringify({ kind: 'offline-bootstrap', reason: validated.reason }) });
}

if (require.main === module) {
  (async () => {
    const options = argumentsForBootstrap(process.argv.slice(2));
    if (!process.env.IDENTITY_BOOTSTRAP_DATABASE_URL) throw new Error('Explicit IDENTITY_BOOTSTRAP_DATABASE_URL is required; no credential or demo fallback');
    process.env.DATABASE_URL = process.env.IDENTITY_BOOTSTRAP_DATABASE_URL;
    const database = require('../src/db');
    try {
      if (!await database.initDb()) throw new Error('A migrated persistent identity database is required');
      process.stdout.write(JSON.stringify(await bootstrapRole(database, options)) + '\n');
    } finally { await database.pool.end(); }
  })().catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
}
module.exports = { argumentsForBootstrap, bootstrapRole };
