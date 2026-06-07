# Contributing to OpenDirectory

## Prerequisites

- Node.js 20+
- Docker and Docker Compose (for the full stack)
- Git

## Fork and clone

```bash
git clone https://github.com/your-org/OpenDirectory.git
cd OpenDirectory
```

## Running services locally

Each microservice is an independent Node.js application. To run one service in isolation:

```bash
cd services/core/<service-name>
npm install
npm run dev
```

To run the full platform:

```bash
cp .env.example .env
# Edit .env and set all required secrets (DB_PASSWORD, RABBITMQ_PASSWORD, etc.)
docker compose up -d
```

The web app is available at `http://localhost:3000`.

## Port reference

All services expose a `/health` endpoint on their primary port.

### Infrastructure

| Service | Port |
|---|---|
| PostgreSQL | 5432 |
| Redis | 6379 |
| MongoDB | 27017 |
| RabbitMQ AMQP | 5672 |
| RabbitMQ Management UI | 15672 |
| LLDAP web | 3890 |
| LLDAP LDAP | 17170 |
| LDAP proxy | 1389 |
| Grafana | 3500 |
| Prometheus | 9090 |
| Vault | 8200 |

### Core services

| Service | Port | Directory |
|---|---|---|
| identity-service | 3001 | `services/core/identity-service` |
| auth-service (authentication-service) | 3002 | `services/core/authentication-service` |
| device-service | 3003 | `services/core/device-service` |
| policy-service | 3004 | `services/core/policy-service` |
| oauth-provider | 3010 | `services/core/oauth-provider` |
| printer-service | 3006 | `services/core/printer-service` |
| network-infrastructure | 3007 | `services/core/network-infrastructure` |
| least-privilege | 3011 | `services/core/least-privilege` |
| certificate-authority | 3012 | `services/core/certificate-authority` |
| kerberos-kdc | 3013 | `services/core/kerberos-kdc` |
| apple-mdm | 3014 | `services/core/apple-mdm` |

### Platform services

| Service | Port | Directory |
|---|---|---|
| api-gateway | 8080 | `services/platform/api-gateway` |
| integration-service | 4000 | `services/platform/integration-service` |

### Enterprise services

| Service | Port | Directory |
|---|---|---|
| graph-explorer | 3900 | `services/enterprise/graph-explorer` |
| policy-simulator | 3901 | `services/enterprise/policy-simulator` |
| security-scanner | 3902 | `services/enterprise/security-scanner` |
| device-lifecycle | 3903 | `services/enterprise/device-lifecycle` |
| auto-remediation | 3904 | `services/enterprise/auto-remediation` |
| antivirus-protection | 3905 | `services/enterprise/antivirus-protection` |
| app-store | 3906 | `services/enterprise/app-store` |

### Frontend

| Service | Port |
|---|---|
| web-app (Next.js) | 3000 |

## Running tests

Run tests in a single service:

```bash
cd services/core/<service-name>
npx jest --no-coverage --forceExit
```

Run tests in a package:

```bash
cd packages/grpc-event-bus
npx jest --no-coverage --forceExit
```

See [testing.md](./testing.md) for a full breakdown of test types and patterns.

## Pull request requirements

Before opening a PR:

1. All tests must pass (`npx jest --no-coverage --forceExit` in each modified service/package).
2. No new raw `amqplib` usage. Use `EventBusClient` from `@opendirectory/grpc-event-bus` instead. See [event-bus.md](./event-bus.md).
3. Commit messages follow the format `type(scope): description` where type is one of `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.
4. The PR description explains *why* the change is needed, not just what changed.

## Code style

- No unnecessary comments. Code should explain itself.
- No backwards-compatibility hacks for hypothetical future callers.
- Prefer functional, direct code over unnecessary abstractions.
- Inline CSS in the frontend — do not introduce class-based styling or CSS files.
- Do not add `console.log` to production code. Use `winston` in backend services.
