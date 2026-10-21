# OpenDirectory

OpenDirectory is a self-hosted business-management platform in development. Its direction is an approachable Apple Business-style portal, with Entra-inspired identity governance and least-privilege access.

## Current scope

Implemented slices include company profiles and directory, groups and organizational units, device inventory, immutable blueprints, and source-aware application licensing. See the [implementation status](docs/implementation-status.md) for what works and what remains open.

**Not production-ready:** OpenDirectory is not yet a complete SaaS platform or Apple Business replacement. Device inventory does not mean MDM enrollment or remote device control. External integrations and unfinished workflows are clearly marked in the documentation.

## Get started

See the [installation guide](docs/operations/installation.md) for the current local setup and prerequisites. The product and integration boundaries are described in the [architecture](docs/architecture/architecture.md) and [Apple capability matrix](docs/integrations/apple-capability-matrix.md).

The central login supports an [external OIDC adapter and authenticated SAML IdP launches](services/core/oauth-provider/README.md). Both need explicit configuration; SAML currently supports IdP-initiated HTTP-POST. [Apple ADE setup](docs/integrations/apple-automated-device-enrollment.md) is separate: there is no accepted ABM/ASM connector, and unavailable enrollment APIs no longer report demo devices or successful assignments.

## Development

Run tests for the component you change; setup and test commands are in the [test strategy](docs/testing/test-strategy.md) and [test results](docs/testing/test-results.md). Contributions are welcome—please open an issue for substantial changes.

## License

[MIT](LICENSE)
