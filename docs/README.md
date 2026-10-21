# OpenDirectory Wiki

Welcome to the OpenDirectory documentation. OpenDirectory is a self-hosted, open-source enterprise platform combining Active Directory, Mobile Device Management, and Privileged Identity Management.

## Contents

### Business Platform Direction
- [Product Vision](business/product-vision.md)
- [Business Requirements](business/business-requirements.md)
- [Actual Implementation Status and Gap Analysis](implementation-status.md)
- [Tenant-Bound License and Policy Sources](features/tenant-license-sources.md)
- [Own-Company Local License Inventory and Allocation](features/company-licenses.md)
- [Normale Gruppen, Lizenzgruppen und Skript-Verknüpfungen](features/company-license-groups.md)
- [Dauerhaftes lokales Mitarbeiter-Offboarding](features/company-offboarding.md)
- [Unabhängig berechtigter Rollen-/PIM-Entzug beim Austritt](features/company-offboarding-access.md)
- [Geräterückgabe anfordern und manuell bestätigen](features/device-returns.md)
- [Architecture](architecture/architecture.md)
- [Architecture Decisions](architecture/architecture-decisions.md)
- [Implemented Organization Profile](features/organization-profile.md)
- [Scoped Profile Delegation](features/organization-delegations.md)
- [Pending Company Registration](features/company-registration.md)
- [Interne Firmenprüfung](features/company-registration-reviews.md)
- [Firmenaktivierung und erste Owner-Anmeldung](features/company-activation.md)
- [Actual Domain Model](architecture/domain-model.md)
- [Actual ERD](architecture/erd.md)
- [Generated Organization OpenAPI](api/openapi.yaml)
- [Local Organization Setup](operations/installation.md)
- [Apple Capability Matrix](integrations/apple-capability-matrix.md)
- [Apple ADE, supplier setup and Configurator](integrations/apple-automated-device-enrollment.md)
- [External OIDC adapter and SAML IdP launches](../services/core/oauth-provider/README.md)
- [Test Strategy](testing/test-strategy.md)
- [Current Test Results](testing/test-results.md)

### Getting Started
- [What is OpenDirectory?](getting-started/overview.md)
- [Architecture](getting-started/architecture.md)
- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quick-start.md)
- [Configuration](getting-started/configuration.md)

### Features
- [Active Directory & Identity](features/active-directory.md)
- [Device Management (MDM)](features/device-management.md)
- [Group Policy](features/group-policy.md)
- [Privileged Identity Management](features/pim.md)
- [Security & Compliance](features/security-compliance.md)
- [Authentication & SSO](features/authentication-sso.md)
- [App-Konten und Skript-Automationen](features/app-accounts-automation.md)
- [Audit & Logging](features/audit-logging.md)

### Services Reference
- [Service Overview](services/README.md)
- [authentication-service](services/authentication-service.md)
- [enterprise-directory](services/enterprise-directory.md)
- [device-service](services/device-service.md)
- [policy-service](services/policy-service.md)
- [conditional-access](services/conditional-access.md)
- [samba-ad-dc](services/samba-ad-dc.md)
- [kerberos-kdc](services/kerberos-kdc.md)
- [ldap-proxy](services/ldap-proxy.md)
- [quick-actions](services/quick-actions.md)

### UI Guide
- [Overview](ui/overview.md)
- [Device Fleet](ui/device-fleet.md)
- [Service Principals](ui/service-principals.md)
- [PIM View](ui/pim.md)

### API Reference
- [Quick Actions API](api/quick-actions.md)
- [Device API](api/device-api.md)
- [Directory API](api/directory-api.md)

### Development
- [Contributing](development/contributing.md)
- [Testing](development/testing.md)
- [Event Bus](development/event-bus.md)
- [Adding a Service](development/adding-a-service.md)

### Deployment
- [Docker Compose](deployment/docker-compose.md)
- [Kubernetes / Helm](deployment/kubernetes.md)
- [Environment Variables](deployment/environment-variables.md)
