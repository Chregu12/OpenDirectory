# OpenDirectory

OpenDirectory is a self-hosted business-management platform in development. Its direction is an approachable Apple Business-style portal, with Entra-inspired identity governance and least-privilege access.

## Current scope

Implemented slices include company profiles and directory, groups and organizational units, device inventory, immutable blueprints, and source-aware application licensing. See the [implementation status](docs/implementation-status.md) for what works and what remains open.

Own company owners can configure [dynamic and nested group rules](docs/features/company-group-rules.md), preview real canonical results and explicitly reconcile memberships through the UI or CLI. Existing manual origins and independent reviews remain distinct. Saved rules also support [explicitly delegated app jobs and schedules](docs/features/company-group-rule-automation.md), with actual app provenance. Existing rule links use [live source checks and inherited review deadlines](docs/features/company-group-live-sources.md) before worker cleanup. [Source-change subscriptions](docs/features/company-automation-changes.md) now reconcile saved rules and local group licenses when their actual sources or free capacity change. Cross-service cached invalidation, generic event delivery and external events remain open.

**Not production-ready:** OpenDirectory is not yet a complete SaaS platform or Apple Business replacement. Device inventory does not mean MDM enrollment or remote device control. External integrations and unfinished workflows are clearly marked in the documentation.

## Get started

See the [installation guide](docs/operations/installation.md) for the current local setup and prerequisites. The product and integration boundaries are described in the [architecture](docs/architecture/architecture.md) and [Apple capability matrix](docs/integrations/apple-capability-matrix.md).

The central login supports an [external OIDC adapter and authenticated SAML IdP launches](services/core/oauth-provider/README.md). Both need explicit configuration; SAML currently supports IdP-initiated HTTP-POST. [Apple ADE setup](docs/integrations/apple-automated-device-enrollment.md) is separate: there is no accepted ABM/ASM connector, and unavailable enrollment APIs no longer report demo devices or successful assignments.

The [password credential service](services/core/authentication-service/README.md) uses its actual PostgreSQL schema, retains suspensions and rejects stale writes. Its former alternate OIDC issuer is retired. Central OAuth tokens and MFA challenges now bind the original password-check revision to live credential state. Company owners can manage [employee invitations](docs/features/employee-invitations.md); recipients set their password on a public page and then continue to MFA setup. The owner must distribute the one-time link and assign an MFA-required app. Mail/Graph delivery, group/license assignment, owner CLI and a full first-login browser acceptance remain open in the [implementation worklist](docs/implementation-worklist.md).

Company owners can create and manage [their own tenant-bound app accounts](docs/features/company-apps.md) under **Firmen-Apps**, with one-time secrets, separate activation, rotation and retained history. The [automation CLI](docs/features/app-accounts-automation.md) supports the same owner operations without global application roles. Explicit [company app grants and durable jobs](docs/features/company-automation.md) support unattended directory exports, [saved group-rule execution](docs/features/company-group-rule-automation.md) and [group license reconciliation](docs/features/company-license-automation.md), with schedules, worker leases, recoverable progress and retained history. Licensing uses existing finite local pools; mail provisioning and manufacturer activation still need provider connectors.

[License groups](docs/features/company-license-groups.md) link ordinary directory groups to finite license pools. UI and script reconciliation allocate one seat per user/pool, retain separate origins and release only the departing group's source.

The [full implementation worklist](docs/implementation-worklist.md) tracks the remaining requested capabilities and their acceptance evidence.

## Development

Run tests for the component you change; setup and test commands are in the [test strategy](docs/testing/test-strategy.md) and [test results](docs/testing/test-results.md). Contributions are welcome—please open an issue for substantial changes.

## License

[MIT](LICENSE)
