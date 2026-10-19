'use strict';

const fs = require('node:fs');
const { Client } = require('pg');
const { validUuid } = require('../../../../packages/identity-authorization-contract');
const { ROLES } = require('../../../../packages/directory-role-contract');
const { resolveOwnedAuthorityPlan } = require('../src/OwnedAuthorityPlan');

function reviewSettings(args, environment) {
  const [mode, first, second, third, ...extra] = args;
  const issuer = mode === 'plan' ? third : second;
  const tenantId = mode === 'plan' ? second : first;
  if (!['inventory', 'stage', 'plan'].includes(mode) || !first || extra.length || mode !== 'plan' && third !== undefined || mode === 'stage' && second !== undefined) {
    throw new Error('Usage: authority-review.js inventory TENANT_UUID ISSUER | stage MANIFEST_FILE | plan CANDIDATE_UUID TENANT_UUID ISSUER');
  }
  const schema = environment.IDENTITY_AUTHORITY_REVIEW_SCHEMA;
  const connectionString = environment.IDENTITY_AUTHORITY_REVIEW_DATABASE_URL;
  if (!schema || !/^[a-z_][a-z0-9_]{0,62}$/.test(schema) || !connectionString) {
    throw new Error('Explicit IDENTITY_AUTHORITY_REVIEW_DATABASE_URL and IDENTITY_AUTHORITY_REVIEW_SCHEMA are required');
  }
  const address = new URL(connectionString);
  if (!['postgres:', 'postgresql:'].includes(address.protocol) || !address.hostname || address.pathname.length < 2 || address.hash) {
    throw new Error('Explicit PostgreSQL review database required');
  }
  if (mode !== 'stage') {
    if (!validUuid(tenantId) || tenantId !== tenantId.toLowerCase() || mode === 'plan' && (!validUuid(first) || first !== first.toLowerCase()) || !issuer) throw new Error('Canonical tenant/candidate UUID and explicit issuer required');
    const authority = new URL(issuer);
    if (!['http:', 'https:'].includes(authority.protocol) || authority.username || authority.password || authority.search || authority.hash || issuer.length > 2048) {
      throw new Error('Bounded HTTP authority issuer without credentials, query or fragment required');
    }
  }
  return { mode, schema, connectionString, first, issuer, tenantId };
}

function readManifest(filename) {
  const stat = fs.statSync(filename);
  if (!stat.isFile() || !stat.size || stat.size > 2 * 1024 * 1024) throw new Error('A nonempty manifest file of at most 2 MiB is required');
  const manifest = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('An explicit JSON migration manifest is required');
  return manifest;
}

function confirmCandidate(candidate, manifest) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate) || Object.keys(candidate).length !== 10
    || !validUuid(candidate.id) || candidate.id !== candidate.id.toLowerCase() || !validUuid(candidate.tenantId) || candidate.tenantId !== manifest.tenantId
    || candidate.state !== 'draft' || candidate.canAuthorize !== false || typeof candidate.validUntil !== 'string' || !Number.isFinite(Date.parse(candidate.validUntil))
    || !/^[a-f0-9]{64}$/.test(candidate.manifestSha256) || !/^[a-f0-9]{64}$/.test(candidate.inventorySha256)
    || candidate.policyCount !== ROLES.length || !Array.isArray(manifest.policies) || manifest.policies.length !== ROLES.length || !Array.isArray(manifest.sources)
    || !Number.isInteger(candidate.adoptionIntentCount) || candidate.adoptionIntentCount < 0 || !Number.isInteger(candidate.quarantineIntentCount) || candidate.quarantineIntentCount < 0
    || candidate.adoptionIntentCount + candidate.quarantineIntentCount !== manifest.sources.length) {
    throw new Error('Authority staging response did not confirm an exact non-authorizing draft');
  }
  return candidate;
}

async function runReview(args, environment = process.env) {
  const settings = reviewSettings(args, environment);
  const manifest = settings.mode === 'stage' ? readManifest(settings.first) : null;
  const client = new Client({ connectionString: settings.connectionString, connectionTimeoutMillis: 3000 });
  try {
    await client.connect();
    await client.query(settings.mode === 'stage' ? 'BEGIN' : 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await client.query("SET LOCAL lock_timeout='5s';SET LOCAL statement_timeout='15s'");
    let result;
    if (settings.mode === 'inventory') {
      const inventory = (await client.query(`SELECT "${settings.schema}".identity_authority_inventory($1,$2) AS inventory`, [settings.first, settings.issuer])).rows[0].inventory;
      const digest = (await client.query(`SELECT "${settings.schema}".identity_authority_hash($1::jsonb) AS digest`, [JSON.stringify(inventory)])).rows[0].digest;
      result = { inventory, inventorySha256: digest, canAuthorize: false };
    } else if (settings.mode === 'plan') {
      const snapshot = (await client.query(`SELECT "${settings.schema}".identity_authority_candidate_snapshot($1,$2,$3) AS snapshot`, [settings.first, settings.tenantId, settings.issuer])).rows[0].snapshot;
      if (snapshot?.candidateId !== settings.first || snapshot?.tenant?.id !== settings.tenantId || snapshot?.issuer !== settings.issuer) throw new Error('Owned source-plan selector confirmation unavailable');
      result = resolveOwnedAuthorityPlan(snapshot);
      const receipt = await client.query(`SELECT candidate.id FROM "${settings.schema}".identity_authority_candidates candidate
        JOIN "${settings.schema}".identity_authority_candidate_events event USING(id) JOIN "${settings.schema}".identity_authority_candidate_outbox outbox USING(id)
        WHERE candidate.id=$1 AND candidate.tenant_id=$2 AND candidate.manifest->>'issuer'=$3 AND candidate.state='draft' AND candidate.transaction_id<>txid_current()
          AND candidate.manifest=$4::jsonb AND candidate.inventory=$5::jsonb AND candidate.manifest_sha256=$6 AND candidate.inventory_sha256=$7
          AND candidate.manifest_sha256="${settings.schema}".identity_authority_hash(candidate.manifest)
          AND candidate.inventory_sha256="${settings.schema}".identity_authority_hash(candidate.inventory)
          AND candidate.inventory="${settings.schema}".identity_authority_inventory($2,$3) AND candidate.valid_until=$8::timestamptz AND candidate.valid_until>clock_timestamp()
          AND event.tenant_id=candidate.tenant_id AND outbox.tenant_id=candidate.tenant_id AND event.action='migration-staged' AND outbox.action=event.action AND outbox.status='pending'
          AND event.details->>'manifestSha256'=candidate.manifest_sha256 AND event.details->>'inventorySha256'=candidate.inventory_sha256 AND event.details->'canAuthorize'='false'::jsonb`,
      [settings.first, settings.tenantId, settings.issuer, JSON.stringify(snapshot.manifest), JSON.stringify(snapshot.inventory), snapshot.manifestSha256, snapshot.inventorySha256, snapshot.validUntil]);
      if (receipt.rows.length !== 1) throw new Error('Owned source-plan receiving receipt unavailable');
      if (Date.parse(result.validUntil) <= Date.now()) throw new Error('Authority source plan expired before confirmation');
    } else {
      await client.query("SELECT set_config('opendirectory.authority_review','explicit-offline-authority-review',true)");
      result = confirmCandidate((await client.query(`SELECT "${settings.schema}".identity_authority_stage($1::jsonb) AS candidate`, [JSON.stringify(manifest)])).rows[0].candidate, manifest);
      const receipt = await client.query(`SELECT candidate.id FROM "${settings.schema}".identity_authority_candidates candidate
        JOIN "${settings.schema}".identity_authority_candidate_events event USING(id) JOIN "${settings.schema}".identity_authority_candidate_outbox outbox USING(id)
        WHERE candidate.id=$1 AND candidate.tenant_id=$2 AND candidate.manifest=$3::jsonb AND candidate.state='draft' AND candidate.transaction_id=txid_current()
          AND candidate.manifest_sha256=$4 AND candidate.inventory_sha256=$5 AND candidate.valid_until=$6::timestamptz AND candidate.valid_until>clock_timestamp()
          AND event.tenant_id=candidate.tenant_id AND outbox.tenant_id=candidate.tenant_id AND event.action='migration-staged' AND outbox.action=event.action AND outbox.status='pending'
          AND event.actor->>'databaseRole'=session_user AND event.details->'canAuthorize'='false'::jsonb
          AND event.scope_sha256="${settings.schema}".identity_authority_hash(NULLIF(current_setting('opendirectory.authority_stage',true),'')::jsonb)`,
      [result.id, result.tenantId, JSON.stringify(manifest), result.manifestSha256, result.inventorySha256, result.validUntil]);
      if (receipt.rows.length !== 1) throw new Error('Authority staging receiving receipt unavailable');
    }
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end(); }
}

if (require.main === module) {
  runReview(process.argv.slice(2)).then(result => process.stdout.write(JSON.stringify(result, null, 2) + '\n')).catch(error => {
    process.stderr.write('Authority review failed: ' + error.message.slice(0, 500) + '\n');
    process.exitCode = 1;
  });
}

module.exports = { reviewSettings, readManifest, confirmCandidate, runReview };
