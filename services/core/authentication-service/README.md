# Authentication credential service

The service on port **3002** verifies existing local credentials for the central [OAuth/OIDC/SAML provider](../oauth-provider/README.md). OAuth uses `AUTH_SERVICE_URL=http://auth-service:3002` and the existing `POST /api/auth/login` contract. A successful password check identifies a credential subject; Identity still decides its canonical user/tenant eligibility, application access and MFA. A directory record alone does not provision this account or link its subject.

OIDC discovery, authorization, token, JWKS and interaction endpoints on this service return **410 `legacy_oidc_retired`**. Configure relying parties against the actual central OAuth issuer and register their clients there. Previous alternate clients, default client secrets, signing keys and subject mappings are not automatically adopted. [Migration from the former OIDC configuration](OIDC_ENV.md).

## Persistence and startup

- Set `AUTH_DATABASE_URL`, or the existing `DATABASE_URL`; otherwise configure `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`. `AUTH_DATABASE_URL` takes precedence. Use the dedicated authentication database.
- Apply the shipped SQL files through **009**, including both existing `005_*` files. Startup runs them in one transaction under a database migration lock. Any failure prevents listening; `/health` returns 503 when the actual credential columns cannot be read.
- `REDIS_URL` is supported by the HTTP session store, token service and session manager. Without it, the existing `REDIS_HOST`/`REDIS_PORT`/`REDIS_PASSWORD`/`REDIS_DB` configuration applies. Production requires a configured `JWT_SECRET` of at least 32 characters and rejects the former default. Optional `SESSION_SECRET` has the same minimum; otherwise a separate stable HTTP-session key is derived from the configured JWT key with a fixed HMAC purpose. Generate strong random secrets and retain them across restarts.
- The existing `users.is_locked` and `users.locked_until` remain authoritative. Repository writes use a physical `record_revision` to reject stale login/profile/password writes. A later password or suspension cannot be overwritten by a previously loaded aggregate. Conflict responses require a fresh read; writes are not automatically retried.
- A self-service password change rechecks the supplied current password against the exact record saved by that operation. Administrative resets remain a separate existing permission path.
- Migration 005 preserves original `password_history.created_at` values in the required `changed_at` column. Replay preserves account IDs, hashes, locks and history timestamps. No credential, role or account is seeded.
- A configured credential repository never falls back to process-local users after a miss or SQL failure. The local login strategy keeps canonical rejection, suspension and revision conflicts authoritative. Authentication audit writes use the existing serial audit ID and required message field; a failed persistent write is not reported as successful production audit.

The Docker build context remains this service directory. Both Compose definitions use the actual service path; the health command needs Node, which is already in the image. No new runtime dependency is introduced.

## Verification and remaining work

From the repository root:

```sh
npm test --prefix services/core/authentication-service -- --runInBand
node services/core/authentication-service/scripts/test-postgres.js
```

The native runner creates and removes a disposable PostgreSQL cluster unless `AUTH_TEST_DATABASE_URL` explicitly points to a disposable test database. The cold-start case additionally requires `redis-server` on PATH, or `REDIS_SERVER` pointing to that binary. It launches the actual production service twice against the same credential database and isolated Redis processes, authenticates through the shipped OAuth password adapter, verifies persisted audit/session evidence, then denies real suspension and SQL loss.

This is a prerequisite for employee onboarding. Owner-created invitations, credential-to-directory enrollment, first mandatory MFA, SCIM and the complete Joiner/Mover/Leaver workflow remain open. Existing legacy auth-service MFA/reset/session routes are not a new accepted employee workflow or a production recovery/security audit. The canonical OAuth MFA store remains separate. [Results and limits](../../../docs/testing/test-results.md#23-oktober-2026--persistente-credential-grundlage), [full implementation worklist](../../../docs/implementation-worklist.md).
