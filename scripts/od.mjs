#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { createClient } from './lib/opendirectory-client.mjs';
import { createGroupClient } from './lib/license-groups.mjs';
import { createAutomationClient, runAutomationWorker } from './lib/company-automation.mjs';

const usage = `OpenDirectory app accounts and API automation (Node.js 20+)

  node scripts/od.mjs app create "Name" ["scope.one scope.two"]
  node scripts/od.mjs app enable CLIENT_ID
  node scripts/od.mjs app disable CLIENT_ID
  node scripts/od.mjs app rotate CLIENT_ID
  node scripts/od.mjs group create "Name"
  node scripts/od.mjs group member add|remove GROUP_ID USER_ID
  node scripts/od.mjs license-group list [GROUP_ID]
  node scripts/od.mjs license-group link GROUP_ID POOL_ID "Reason (10–500 characters)"
  node scripts/od.mjs license-group sync RULE_ID "Reason (10–500 characters)"
  node scripts/od.mjs license-group unlink RULE_ID "Reason (10–500 characters)"
  node scripts/od.mjs automation enroll "Name"
  node scripts/od.mjs automation approve ENROLLMENT_ID CLIENT_ID CLIENT_REVISION "directory.users.export directory.groups.export" [HOURS]
  node scripts/od.mjs automation grants
  node scripts/od.mjs automation queue GRANT_ID ACTION [json|csv]
  node scripts/od.mjs automation schedule GRANT_ID ACTION INTERVAL_SECONDS [json|csv]
  node scripts/od.mjs automation jobs GRANT_ID
  node scripts/od.mjs automation result JOB_ID
  node scripts/od.mjs automation history JOB_ID
  node scripts/od.mjs automation revoke GRANT_ID REVISION
  node scripts/od.mjs automation worker GRANT_ID [--once]
  node scripts/od.mjs check
  node scripts/od.mjs request GET /api/path
  node scripts/od.mjs request POST /api/path body.json [--if-match ETAG]

OPENDIRECTORY_ISSUER      HTTPS issuer origin (HTTP loopback for local use)
OPENDIRECTORY_API_URL     API origin; defaults to the issuer
OPENDIRECTORY_CLIENT_ID   App client ID
OPENDIRECTORY_CLIENT_SECRET App secret from your secret store
OPENDIRECTORY_SCOPES      Approved scopes for this run; defaults to empty
OPENDIRECTORY_ADMIN_ACCESS_TOKEN Original human token for app/group management

Creation starts disabled and prints the secret once. Activation is separate.
No automatic write retries. Inspect the current state after an uncertain result.
Workload tokens do not inherit human, tenant, Graph or mailbox permissions.`;

const [command, action, ...args] = process.argv.slice(2);
if (!command || command === '--help' || command === 'help') { console.log(usage); process.exit(0); }
try {
  const client = createClient({ issuer: process.env.OPENDIRECTORY_ISSUER, apiUrl: process.env.OPENDIRECTORY_API_URL || process.env.OPENDIRECTORY_ISSUER,
    clientId: process.env.OPENDIRECTORY_CLIENT_ID, clientSecret: process.env.OPENDIRECTORY_CLIENT_SECRET, scopes: process.env.OPENDIRECTORY_SCOPES || '', adminToken: process.env.OPENDIRECTORY_ADMIN_ACCESS_TOKEN });
  let result;
  const groups = createGroupClient(client);
  const automation = createAutomationClient(client);
  if (command === 'app' && action === 'create' && args.length >= 1 && args.length <= 2) result = await client.createApp(args[0], (args[1] || '').split(/\s+/).filter(Boolean));
  else if (command === 'app' && ['enable', 'disable'].includes(action) && args.length === 1) result = await client.enableApp(args[0], action === 'enable');
  else if (command === 'app' && action === 'rotate' && args.length === 1) result = await client.rotateApp(args[0]);
  else if (command === 'group' && action === 'create' && args.length === 1) result = await groups.create(args[0]);
  else if (command === 'group' && action === 'member' && args.length === 3) result = await groups.member(args[0], args[1], args[2]);
  else if (command === 'license-group' && action === 'list' && args.length <= 1) result = await groups.list(args[0]);
  else if (command === 'license-group' && action === 'link' && args.length === 3) result = await groups.linkPool(...args);
  else if (command === 'license-group' && action === 'sync' && args.length === 2) result = await groups.sync(...args);
  else if (command === 'license-group' && action === 'unlink' && args.length === 2) result = await groups.unlink(...args);
  else if (command === 'automation' && action === 'enroll' && args.length === 1) result = await automation.enroll(args[0]);
  else if (command === 'automation' && action === 'approve' && args.length >= 4 && args.length <= 5) result = await automation.approve(args[0], args[1], args[2], args[3].split(/\s+/).filter(Boolean), Number(args[4] || 24) * 3600);
  else if (command === 'automation' && action === 'grants' && !args.length) result = await automation.grants();
  else if (command === 'automation' && action === 'queue' && args.length >= 2 && args.length <= 3) result = await automation.enqueue(args[0], args[1], args[2]);
  else if (command === 'automation' && action === 'schedule' && args.length >= 3 && args.length <= 4) result = await automation.schedule(args[0], args[1], Number(args[2]), args[3]);
  else if (command === 'automation' && action === 'jobs' && args.length === 1) result = await automation.jobs(args[0]);
  else if (command === 'automation' && action === 'result' && args.length === 1) result = await automation.result(args[0]);
  else if (command === 'automation' && action === 'history' && args.length === 1) result = await automation.history(args[0]);
  else if (command === 'automation' && action === 'revoke' && args.length === 2) result = await automation.revoke(args[0], args[1]);
  else if (command === 'automation' && action === 'worker' && (args.length === 1 || args.length === 2 && args[1] === '--once')) {
    const controller = new AbortController(); const stop = () => controller.abort(); process.once('SIGINT', stop); process.once('SIGTERM', stop);
    try { await runAutomationWorker(automation, args[0], { once: args[1] === '--once', signal: controller.signal, onResult: value => { console.log(JSON.stringify(value)); if (args[1] === '--once' && value.job?.status !== 'succeeded') process.exitCode = 2; }, onRetry: seconds => console.error(JSON.stringify({ event: 'automation.retry', retrySeconds: seconds })) }); }
    finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
    result = { workerStopped: true };
  }
  else if (command === 'check' && !action && args.length === 0) result = await client.check();
  else if (command === 'request' && action && args.length >= 1 && args.length <= 4) {
    const conditional = args.indexOf('--if-match'); let etag;
    if (conditional !== -1) {
      if (conditional < 1 || conditional !== args.length - 2 || !args[conditional + 1]) throw new Error('Expected --if-match ETAG');
      etag = args[conditional + 1]; args.splice(conditional, 2);
    }
    if (args.length > 2) throw new Error('Unexpected request arguments');
    const body = args[1] ? JSON.parse(await readFile(args[1], 'utf8')) : undefined;
    result = await client.request(action.toUpperCase(), args[0], body, { etag });
  } else throw new Error('Invalid command; use --help');
  console.log(JSON.stringify(result, null, command === 'automation' && action === 'worker' ? undefined : 2));
  if (result?.hasBlocked) process.exitCode = 2;
} catch (error) {
  // Never include request bodies, credentials or provider responses in diagnostics.
  console.error(error?.name === 'ApiError' ? error.message : 'Operation failed or is unconfirmed. Check configuration, authorization and current state; use --help.');
  process.exitCode = 1;
}
