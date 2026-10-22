# OpenDirectory

OpenDirectory is a self-hosted business-management platform in development. Its direction is an approachable Apple Business-style portal, with Entra-inspired identity governance and least-privilege access.

## Current scope

Implemented slices include company profiles and directory, groups and organizational units, device inventory, immutable blueprints, and source-aware application licensing. See the [implementation status](docs/implementation-status.md) for what works and what remains open.

**Not production-ready:** OpenDirectory is not yet a complete SaaS platform or Apple Business replacement. Device inventory does not mean MDM enrollment or remote device control. External integrations and unfinished workflows are clearly marked in the documentation.

## Get started

See the [installation guide](docs/operations/installation.md) for the current local setup and prerequisites. The product and integration boundaries are described in the [architecture](docs/architecture/architecture.md) and [Apple capability matrix](docs/integrations/apple-capability-matrix.md).

The central login supports an [external OIDC adapter and authenticated SAML IdP launches](services/core/oauth-provider/README.md). Both need explicit configuration; SAML currently supports IdP-initiated HTTP-POST. [Apple ADE setup](docs/integrations/apple-automated-device-enrollment.md) is separate: there is no accepted ABM/ASM connector, and unavailable enrollment APIs no longer report demo devices or successful assignments.

App accounts can be created directly in the UI and managed from scripts with the [automation CLI](docs/features/app-accounts-automation.md). Explicit [company app grants and durable jobs](docs/features/company-automation.md) support unattended directory exports with schedules, worker leases and retained history. Mail provisioning still needs a provider connector.

[License groups](docs/features/company-license-groups.md) link ordinary directory groups to finite license pools. UI and script reconciliation allocate one seat per user/pool, retain separate origins and release only the departing group's source.

The [full implementation worklist](docs/implementation-worklist.md) tracks the remaining requested capabilities and their acceptance evidence.

## Development

Run tests for the component you change; setup and test commands are in the [test strategy](docs/testing/test-strategy.md) and [test results](docs/testing/test-results.md). Contributions are welcome—please open an issue for substantial changes.

## License

[MIT](LICENSE)
