# Canonical License Compatibility Adapter

`license-management` no longer runs an independent entitlement database or in-memory license allocator. The authoritative implementation is policy-service at `/api/licenses`, including directory identity binding, delegated permissions, independent review, capacity checks, group/direct sources, lifecycle recovery, and transactional audit.

The old prototype entry point did not initialize reliably: its route registrar bound methods that were not present on the service class. It also maintained separate assignments and emitted unauthenticated WebSocket data, including complete license objects. Those runtime paths have been removed, not enabled behind a second set of authorization rules. Historical controller/service modules remain unregistered and are not a supported runtime or migration tool.

## Run

Use Node.js 18+ with native fetch, a reachable persistent policy-service, and its configured authoritative identity service.

```sh
npm ci --ignore-scripts
POLICY_SERVICE_URL=http://localhost:3004 npm start
npm test
```

`LICENSE_SERVICE_PORT` defaults to `3018`. `POLICY_SERVICE_URL` must be a fixed HTTP(S) origin without credentials, query, fragment, or path prefix. `CORS_ORIGINS` is a comma-separated browser-origin allowlist; wildcard origins are not enabled. The standalone Compose file binds to loopback by default and uses the existing `opendirectory-network`. It does not create a second database, Redis, mobile synchronizer, broker consumer, or background grant job.

Both root Compose variants offer the optional `license-compat` profile on their own policy-service network; start it only after upgrading/migrating policy-service and identity-service. It is not required by the modern kiosk. For the core gateway's old prefix, also enable the `license-management` module; the canonical `/api/licenses` registry is never replaced by it. With standalone Compose, set `OPENDIRECTORY_NETWORK` to the actual existing network name. Profiles/config validation do not constitute a deployment or migration.

`GET /health` is liveness only and does not claim that dependencies are available. It exposes no license statistics or process/configuration details. Importing the module starts no server, timer, or broker connection. `createApp`/`createService` are available for integration tests; the CLI is the only automatic start path.

## Contract and Migration

Supported paths accept **canonical policy-service JSON fields and response envelopes**, not the previous procurement/SAM data model. The adapter forwards the original bearer token, never a broader service credential. Its capability lookup and the actual operation are independently verified by policy-service. Unlinked/disabled users, invalid/expired tokens, missing permissions, source failures, and storage outages cannot fall back to old maps. Policy demo mode is not accepted through the compatibility adapter.

| Compatibility path | Canonical policy-service path |
| --- | --- |
| `GET /api/license/access`, `GET /api/license/kiosk` | `/api/licenses/access`, `/api/licenses/kiosk` |
| `GET/POST /api/license/licenses` | `/api/licenses` |
| `GET/PUT/DELETE /api/license/licenses/:id` | `/api/licenses/:id` |
| `GET /api/license/licenses/:id/assignments` | `/api/licenses/:id/assignments` |
| `POST /api/license/licenses/:id/assign` | `/api/licenses/:id/assign` |
| `DELETE /api/license/licenses/:id/assignments/:assigneeId?assignee_type=user` | Same suffix under `/api/licenses/:id` |
| `POST /api/license/licenses/:id/request` | `/api/licenses/:id/request` |
| `GET /api/license/requests`, `POST /api/license/requests/:id/approve` or `/deny` | Same suffix under `/api/licenses` |
| `GET /api/license/groups`, `GET /api/license/users` | Same suffix under `/api/licenses` |
| `POST /api/license/licenses/:id/groups/:groupId/reconcile` | `/api/licenses/:id/groups/:groupId/reconcile` |
| `POST /api/license/users/:id/reconcile`, `/offboard`, `/activate` | Same suffix under `/api/licenses/users/:id` |
| `GET /api/license/licenses/:id/audit` | `/api/licenses/:id/audit` |

Example direct grant: `{ "assignee_type": "user", "assignee_id": "the-canonical-directory-UUID" }`. Actor/body role fields are discarded; ownership and decision makers come from the canonical verified principal. `status` is the only request-list filter; `assignee_type` disambiguates revocation. Unsupported fields/filters return `422` rather than silently changing semantics. For example, `licenseKey`, `assignments`, `quantity`, `vendorId`, `softwareId`, procurement terms, and old renewal requests are not imported, guessed, or acknowledged as saved. Canonical `total_seats: 0` means explicitly unlimited; a legacy quantity is not silently converted to that meaning.

Existing prototype IDs, license keys, contracts, vendors, usage/asset records, and assignment aliases require a separately reviewed migration with backups, canonical user/group mapping, seat/source reconciliation, and secret handling. This adapter does not run a data migration or purchase/provision vendor licenses.

Prototype types, software/vendors, usage/compliance/optimization, asset discovery, mobile sync, reports/dashboard, old `POST .../renew`/`.../revoke`, and old global audit exports return authenticated `410 Gone`. They are not presented as completed enterprise features. Unknown methods/paths are default-denied. Successful core operations retain canonical statuses, including `202` blocked group allocation, `204` revocation, and `409` capacity conflicts.

The legacy `/ws/license` stream is retired. No WebSocket handshake is accepted and no cached objects, keys, or broadcasts are emitted. A header bearer is checked against canonical capabilities before returning `410`; unauthenticated/invalid/unlinked/dependency-failure attempts fail closed. Query-string credentials are not accepted. Realtime notifications need an independently authorized canonical event feed/outbox implementation, not the former unrestricted broadcaster.

Transport uses fixed destinations, no redirects/cookies/caller-supplied service headers, bounded 10-second requests and 2-MiB JSON responses, and no cached authorization. A failed upstream mutation is never retried or replayed automatically: its outcome can be uncertain after a network timeout and must be reconciled at the canonical API.
