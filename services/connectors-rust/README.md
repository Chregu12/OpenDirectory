# OpenDirectory Rust connectors

The Rust readers cover Microsoft Graph `subscribedSkus`, the license state of
one explicitly mapped Microsoft user, Google Workspace license assignments and
GitHub Copilot seats, Adobe product-profile members, Slack SCIM users, Atlassian directory users and
GitLab.com billable group members.
They do not assign
licenses, change users, import billing, infer identity matches, or perform JML.
The existing capacity observer remains the only writer of capacity observations
and still requires its reviewed connection, protected credential file, dedicated
database role and explicit enablement. The existing JavaScript token client obtains
the Graph application token; the Rust process receives that token over stdin, reads
Graph and returns a bounded snapshot over stdout. Secrets are not command-line
arguments, environment variables, logs or browser data. Errors and 429 retry
intervals remain subject to the existing observer and database contracts.

Set `LICENSE_CAPACITY_ENGINE=rust` on an explicitly configured capacity observer.
Its default binary path in the policy-service container is
`/usr/local/bin/opendirectory-connectors`. The Helm capacity observer is disabled
unless explicitly configured; the k3s values select the Rust-capable image and
engine when it is enabled. Selecting Rust does not create a provider connection
or grant consent. Outside Helm, leaving the setting unset retains the existing
JavaScript client. An unknown engine or an unavailable Rust binary fails closed.

Run `cargo test --locked` here and the policy-service
`src/licenses/__tests__/RustGraphCapacityClient.test.js`,
`RustGraphLicenseClient.test.js`, and `fulfillmentProbe.test.js` suites. Tests use local
fixtures, not a Microsoft tenant. A live tenant requires a separately reviewed
application permission and admin consent; Microsoft documents
`LicenseAssignment.Read.All` as the least-privileged application permission for
this endpoint. See [Microsoft Graph subscribedSkus](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0)
and [Graph throttling](https://learn.microsoft.com/en-us/graph/throttling).

## Provenance and scope

This implementation was written independently against Microsoft's published API
and OpenDirectory's existing Graph capacity contract. No source code was copied
from the following projects. Their separation of provider capabilities,
connection lifecycle and business inventory informed the design:

- [Nango](https://github.com/NangoHQ/nango), inspected at
  `f198c45a56b9a6b5de4d093b6177a1ccbf326ba8`, Elastic License 2.0.
- [SaaSLens](https://github.com/Wondermove-Inc/saaslens), inspected at
  `10a93ea490d1d7d98df041b368d04d292096c7f5`, MIT.
- [Ampersand Connectors](https://github.com/amp-labs/connectors), inspected at
  `dfc81ccede88097c45bb82069de5aef082c446fd`, MIT.

An attribution comment alone is not a substitute for the applicable license if
source is copied or adapted later. In particular, Nango's license places limits
on providing its software as a hosted service. This project does not bundle it.
General tenant-wide user discovery, provider writes in Rust, connection
UI, cross-provider reconciliation and SaaSLens-style contract/cost management
are not implemented by this connector. They require their own contracts,
permissions, persistence, review and tests.

## Bound Microsoft user reads (8 November 2026)

`LICENSE_FULFILLMENT_READ_ENGINE=rust` selects the Rust read transport in the
existing fulfillment worker. Unset/`javascript` keeps the original client;
unknown values and a missing binary reject the read. The shared Node observation
parser and existing write transport remain in use. The worker still needs its
protected credential file, dedicated database identity, reviewed immutable
connector/product/subject bindings, eligibility and capacity admission. Both Helm
workers stay disabled by default. k3s selects Rust when explicitly enabled.

Private stdin protocol (never put a real token into a command argument):

```json
{"operation":"microsoft.user","accessToken":"<private token>","objectId":"<bound canonical UUID>"}
```

Success is `{ "ok": true, "user": ... }`, containing only `id`, `accountEnabled`,
`assignedLicenses` and `licenseAssignmentStates`. The old `{ "accessToken": ... }`
capacity request and `{ "ok": true, "rows": ... }` reply remain compatible.
Missing nullable fields, incomplete/paged objects, mismatched IDs, duplicate
sources, unknown assignment states and invalid plans reject the whole response.
Redirects are never followed; body size, process output and duration are bounded.
429 preserves a bounded Retry-After. Errors contain codes, never response bodies.

[Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
documents `User.Read.All` as the least-privileged application permission for this
user endpoint. The separately configured capacity collector only requires
`LicenseAssignment.Read.All`; do not expand its consent for this feature.
[Assignment-state semantics](https://learn.microsoft.com/en-us/graph/api/resources/licenseassignmentstate?view=graph-rest-1.0)
provide the direct/group source and provisioning errors. A successful read does
not grant permission to assign licenses or prove that a commercial quota exists.
The existing fulfillment application's separately reviewed write consent applies
to its Node write path; selecting Rust adds no write capability.

For a real **read-only** smoke test, use a one-off container from the policy-service
image with the existing reviewed fulfillment configuration mounted at mode 0600,
`LICENSE_FULFILLMENT_CONFIG_FILE` and its dedicated `DATABASE_URL`. Run:

```sh
node scripts/license-fulfillment-probe.js <existing-target-UUID>
```

The probe validates storage privileges and the existing target/connector/tenant
binding, excludes company pools, respects stored backoff, obtains a token and
uses Rust to inspect only that mapped user/SKU. It prints observation booleans
and IDs; it neither starts the worker nor persists observations or assigns/removes
licenses. A 429 is returned with Retry-After; wait that duration before another
manual probe. Configure reviewed bindings through the existing administrator
workflow; do not manufacture database rows for the test. No real provider
credentials or target existed during development, so live consent and live
Microsoft behavior remain unverified.

Tests cover Rust HTTP fixtures and the Node process boundary separately. The
PostgreSQL fulfillment regression additionally exercises the Rust client adapter
with a process-contract fixture, including assignment, subsequent verification
and removal; that fixture does not claim to execute Rust against Microsoft.

## Google Workspace and GitHub Copilot reads (8 November 2026)

Both providers have fixed-host Rust readers and a protected-file Node connection
probe. Google authenticates with a signed service-account JWT and domain-wide
delegation; GitHub uses an explicitly supplied organization token. No new SDK or
Rust dependency was added. The probe emits counts and the selected provider
binding, without user emails, logins, tokens or keys. It never runs a worker or
writes the database. Existing Microsoft stdin/stdout requests remain compatible.

See [configuration and live-test instructions](READ_PROVIDERS.md). These readers
are not yet automatic catalog imports or allocation/fulfillment connectors in
`/licenses`. Purchased quota is not inferred from assigned or billed seats.
No real Google or GitHub credentials, consent or live read were tested during
development.

## Adobe and Slack reads (8 November 2026)

Adobe now has a fixed-host UMAPI reader that confirms one explicit product profile
by ID/name/type before reading its members. OAuth Server-to-Server uses Adobe's
current v3 token endpoint; no deprecated JWT authentication or action API is used.
Slack now has a SCIM 2.0 user reader that verifies token identity before accepting
the configured workspace or Enterprise directory scope. `auth.test` is the only
non-GET Rust call and does not mutate an account or send a message.

Both run through the same protected-file manual probe and Node snapshot checks.
Neither adds a catalog import, local identity mapping, account provisioning or
purchased-capacity inference. Administrative provider scopes can also authorize
writes even though these implementations only observe. Configuration, limits and
live-test steps are in [READ_PROVIDERS.md](READ_PROVIDERS.md). No real Adobe or
Slack credential, consent or tenant connection was tested. JetBrains remains dependent on its actual instance/API variant, and is not an
implemented capability.

## Atlassian and GitLab.com reads (8 November 2026)

Atlassian uses the current POST directory-user search with the directory UUID
explicitly repeated in every body; deprecated GET and all-directory wildcard
bindings are not used. Account/membership statuses remain distinct observations.
GitLab.com confirms the exact top-level group before reading billable members,
validates supplied pagination links and count headers, and never substitutes a
public member list for billing permission. Both use the existing protected-file
manual probe and snapshot validation. No new dependency, import worker or cloud
write capability was added. See [READ_PROVIDERS.md](READ_PROVIDERS.md).

No real Atlassian or GitLab token or live connection was tested. JetBrains still
requires the selected Vault/IDE Services instance and public Swagger contract.
