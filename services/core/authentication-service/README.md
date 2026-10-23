# Authentication credential service

The service on port **3002** verifies local credentials for the central [OAuth/OIDC/SAML provider](../oauth-provider/README.md). OAuth uses `AUTH_SERVICE_URL=http://auth-service:3002` and `POST /api/auth/login`. A successful password check returns the exact `security_revision` captured by that database write. The provider compares that snapshot with this private live reader and Identity’s canonical user/tenant eligibility before issuing or validating tokens. A directory record alone does not provision this account or link its subject.

OIDC discovery, authorization, token, JWKS and interaction endpoints on this service return **410 `legacy_oidc_retired`**. Configure relying parties against the actual central OAuth issuer and register their clients there. Previous alternate clients, default client secrets, signing keys and subject mappings are not automatically adopted. [Migration from the former OIDC configuration](OIDC_ENV.md).

## Persistence and startup

- Set `AUTH_DATABASE_URL`, or the existing `DATABASE_URL`; otherwise configure `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`. `AUTH_DATABASE_URL` takes precedence. Use the dedicated authentication database.
- Apply the shipped SQL files through **010**, including both existing `005_*` files. Startup runs them in one transaction under a database migration lock. Any failure prevents listening; `/health` returns 503 when the actual credential columns cannot be read.
- `REDIS_URL` is supported by the HTTP session store, token service and session manager. Without it, the existing `REDIS_HOST`/`REDIS_PORT`/`REDIS_PASSWORD`/`REDIS_DB` configuration applies. Production requires a configured `JWT_SECRET` of at least 32 characters and rejects the former default. Optional `SESSION_SECRET` has the same minimum; otherwise a separate stable HTTP-session key is derived from the configured JWT key with a fixed HMAC purpose. Generate strong random secrets and retain them across restarts.
- The existing `users.is_locked` and `users.locked_until` remain authoritative. Repository writes use a physical `record_revision` to reject stale login/profile/password writes. A later password or suspension cannot be overwritten by a previously loaded aggregate. Conflict responses require a fresh read; writes are not automatically retried.
- A self-service password change rechecks the supplied current password against the exact record saved by that operation. Administrative resets remain a separate existing permission path.
- Migration 005 preserves original `password_history.created_at` values in the required `changed_at` column. Replay preserves account IDs, hashes, locks and history timestamps. No credential, role or account is seeded.
- A configured credential repository never falls back to process-local users after a miss or SQL failure. The local login strategy keeps canonical rejection, suspension and revision conflicts authoritative. Authentication audit writes use the existing serial audit ID and required message field; a failed persistent write is not reported as successful production audit.

The Docker build context is now the repository root; use `docker build -f services/core/authentication-service/Dockerfile .`. Both Compose definitions copy the actual service and required shared invitation/identity/tenant/credential contracts. Auth explicitly declares JOSE 5 for private RS256 receivers. The service lockfile also prunes the former OIDC issuer's unused dependencies. The health command needs Node, which is already in the image.

## Employee invitation receiving — in progress

The [internal invitation receiver](../../../docs/features/employee-invitations.md) supports actual own-Owner authority, original one-time tokens, retained revocation reasons and recipient-created **locked** credentials with initial password history. SQL guards prevent ordinary reset/unlock/delete routes from bypassing an unfinished or revoked enrollment. Events and pending fingerprints commit with the original account, and stale/expired admissions roll back. Private HTTP requests require a narrow RS256 issuer assertion; Owner operations also require the original independently verified human bearer.

Configure `OIDC_ISSUER`, `JWKS_URI` and the pinned `IDENTITY_SERVICE_URL` origin. Identity **055** implements actual canonical acceptance, its read-only confirmation and negative withdrawal of an unchanged partial enrollment. Identity uses `AUTH_SERVICE_URL` to independently verify the retained original credential or revocation through the delegated `identity-source`/`revoked-source` callbacks. Auth unlocks only the exact original credential after confirming the actual Identity receipt. The two databases do not share an atomic transaction; partial states and later authorized edits remain explicit.

The private `POST /internal/auth/credential-state` reader returns an explicit subject status, the current security revision only when the account is eligible, and original accepted invitation metadata where applicable. It uses the OAuth issuer’s short-lived RS256 proof and reads the actual Auth tables and invitation evidence. OAuth compares the exact revision returned by password verification with the live reader, stores the five-field `credential_authorization` claim, and rechecks it for access, refresh and MFA enrollment/recovery. Previously issued local tokens without this binding do not gain it during refresh. Public employee invitation endpoints, UI/CLI, the complete first mandatory MFA browser login and controlled credential namespace reuse remain open; canonical employee MFA and original-console restrictions are already enforced.

## Verification and remaining work

From the repository root:

```sh
npm test --prefix services/core/authentication-service -- --runInBand
node services/core/authentication-service/scripts/test-postgres.js
```

The native runner creates and removes a disposable PostgreSQL cluster unless `AUTH_TEST_DATABASE_URL` explicitly points to a disposable test database. The cold-start case additionally requires `redis-server` on PATH, or `REDIS_SERVER` pointing to that binary. It launches the actual production service twice against the same credential database and isolated Redis processes, authenticates through the shipped OAuth password adapter, verifies persisted audit/session evidence, then denies real suspension and SQL loss.

The native runner also checks the actual invitation/Identity activation kernels and four HTTP definitions against the shipped private Identity router on a local transport fixture. The current OAuth credential-revision and challenge-binding changes have only received JavaScript syntax and diff checks so far; their test suites and full production service chain have not been run. Public enrollment, the full first mandatory MFA browser login, SCIM and the complete Joiner/Mover/Leaver workflow remain open. Existing legacy auth-service MFA/reset/session routes are not a new accepted employee workflow or a production recovery/security audit. The canonical OAuth MFA store remains separate. [Results and limits](../../../docs/testing/test-results.md#23-oktober-2026--kanonische-mitarbeiteraktivierung), [full implementation worklist](../../../docs/implementation-worklist.md).
