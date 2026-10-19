# What is OpenDirectory?

OpenDirectory is a self-hosted, open-source enterprise IT platform that replaces the combination of Microsoft Active Directory, Microsoft Intune, Azure AD, and Jamf Pro. It gives organisations complete control over their directory, device fleet, and identity infrastructure without per-seat licensing fees or vendor lock-in.

## The Problem

Enterprise IT teams today rely on a fragmented stack of cloud services to manage their workforce:

- **Azure Active Directory / Entra ID** for identity and authentication
- **Microsoft Intune** for device management and policy enforcement
- **Jamf Pro** for macOS and iOS management
- **Azure AD Premium P2** for Privileged Identity Management (PIM) and Conditional Access

This stack costs $15–30 per user per month, requires a cloud connection for all management operations, and keeps your directory data in someone else's infrastructure. Regulated industries, security-conscious organisations, and teams in air-gapped or low-connectivity environments cannot accept these constraints.

## What OpenDirectory Provides

OpenDirectory runs on your own infrastructure — a single server, a Kubernetes cluster, or anywhere you can run Docker — and delivers the full capability of the above stack from one platform:

- **Active Directory** — Samba 4 domain controller, LDAP, Kerberos KDC, forest trusts, fine-grained password policies, LAPS, BitLocker key escrow
- **MDM** — Unified management for Windows, macOS, Linux, iOS, and Android devices; zero-touch enrollment, compliance scanning, remote actions, app deployment
- **Group Policy** — GPO engine compatible with Windows Group Policy concepts; RSoP calculation, inheritance, Block Inheritance, policy baselines
- **PIM** — Just-in-time privileged access with multi-level approvals, risk scoring, session recording and replay, break-glass emergency access
- **Conditional Access** — Zero-trust policy evaluation based on device health, user identity, location, and time of day
- **Certificate Authority** — Built-in PKI; issue, renew, and revoke certificates for users, devices, and services
- **Audit** — Append-only audit trail covering every directory change, authentication event, device action, and GPO application

## Who Is It For?

OpenDirectory is designed for:

- **IT and infrastructure teams** who need an Intune/Azure AD replacement they can run on-premises or in a private cloud
- **Security-conscious organisations** that cannot store directory data in a public cloud
- **Regulated industries** (finance, healthcare, government) with data residency requirements
- **Self-hosted / homelab enthusiasts** who want enterprise-grade identity management without subscription costs
- **Developers** building integrations against a fully open REST and gRPC API

## Comparison

| Feature | OpenDirectory | Microsoft Intune + Entra ID | Jamf Pro |
|---|---|---|---|
| Cost | Free (open-source) | ~$12/user/month | ~$15/device/month |
| Self-hosted | Yes | No (cloud-only) | No (cloud-only) |
| Active Directory compatible | Yes (Samba 4) | Yes | No |
| MDM — Windows | Yes | Yes | No |
| MDM — macOS / iOS | Yes | Yes (Intune) | Yes |
| MDM — Linux | Yes | Limited | No |
| MDM — Android | Yes | Yes | No |
| PIM / JIT Access | Yes | Yes (P2 license) | No |
| GPO enforcement | Yes | Yes | No |
| Kerberos KDC | Yes | Yes (Azure AD Kerberos) | No |
| Open REST API | Yes (400+ endpoints) | Partial (MS Graph) | Partial |
| Certificate Authority | Yes (built-in) | Yes (ADCS, external) | Partial |
| Data residency | Full control | Microsoft datacentres | Jamf datacentres |
| Air-gap support | Yes | No | No |

## How It Works

OpenDirectory is composed of approximately 30 microservices organised into three layers. All services expose a REST API and emit Prometheus metrics. They communicate asynchronously through a pluggable gRPC event bus (RabbitMQ by default, with in-memory and direct-gRPC transports available for testing and constrained environments).

The frontend is a Next.js / React 18 single-page application using an Apple Business Manager-style three-column layout. It communicates with services through the API gateway on port 8080.

For a deeper look at the internal structure, see [Architecture](architecture.md).

## Maturity and Status

The core features are fully implemented with 780+ automated tests (unit, integration, E2E, and component). Several UI surfaces for less common operations (remote command console, certificate lifecycle, geofencing configuration) are still in progress. For a complete picture of what is done and what is not, see the [ROADMAP](../../ROADMAP.md).

> **Security note:** The quick-actions service (port 3950) does not yet enforce authentication on its endpoints. It should not be exposed to untrusted networks until this is resolved. See the ROADMAP for the full list of items that must be addressed before a production deployment.
