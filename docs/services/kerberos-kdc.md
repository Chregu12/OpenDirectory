# kerberos-kdc

**Port:** 3013  
**Database:** PostgreSQL (ticket policies, delegation config, Protected Users group)  
**Language:** Node.js 18+

## Overview

The Kerberos KDC service is a REST management API layered over MIT Kerberos (`kadmin.local`). It exposes endpoints for principal CRUD, keytab generation, ticket policy management (realm-wide defaults and per-principal overrides), delegation configuration (constrained KCD, RBCD, unconstrained), S4U2Self/S4U2Proxy simulation for testing, and Protected Users group enforcement.

Principal operations run synchronously via `kadmin.local` shell invocations, so they require the Kerberos admin service to be available on the same host. Ticket policy, delegation, and Protected Users data are stored in PostgreSQL; those endpoints return `503` if the database is unreachable (`requireDb` middleware). The Kerberos realm is set via the `KRB5_REALM` environment variable (default `OPENDIRECTORY.LOCAL`).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `KDC_API_PORT` | `3013` | HTTP listen port |
| `KRB5_REALM` | `OPENDIRECTORY.LOCAL` | Kerberos realm name |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` / `POSTGRES_DB` | `kerberos` | PostgreSQL database |
| `DB_USER` / `POSTGRES_USER` | `postgres` | PostgreSQL user |
| `DB_PASSWORD` / `POSTGRES_PASSWORD` | — | PostgreSQL password |

## API Endpoints

### Principal Management

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/kerberos/principals` | List all principals in the realm | Yes |
| GET | `/api/kerberos/principals/:name` | Get principal details | Yes |
| POST | `/api/kerberos/principals` | Create principal | Yes |
| PUT | `/api/kerberos/principals/:name/password` | Change principal password | Yes |
| DELETE | `/api/kerberos/principals/:name` | Delete principal | Yes |
| POST | `/api/kerberos/keytabs/:name` | Generate and download keytab | Yes |
| POST | `/api/kerberos/sync-user` | Create or update principal from OpenDirectory user | Internal |

**Create principal body:**
```json
{
  "name": "HTTP/webserver.corp.example.com",
  "password": "optional-password",
  "noexpiry": true
}
```

If `password` is omitted, the principal is created with a random key (`-randkey`), suitable for service accounts that use keytab authentication. Set `noexpiry: true` to disable password expiration.

**Keytab download:**

```bash
curl -X POST http://localhost:3013/api/kerberos/keytabs/HTTP%2Fwebserver.corp.example.com \
  -H "Authorization: Bearer $TOKEN" \
  --output webserver.keytab
```

Returns the keytab as an `application/octet-stream` binary. The keytab is generated in `/tmp` and immediately deleted after streaming.

### Ticket Policies

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/ticket-policy` | Get realm-wide ticket policy | Yes |
| PUT | `/api/ticket-policy` | Update realm-wide ticket policy | Admin |
| GET | `/api/principals/:name/ticket-policy` | Get per-principal policy override | Yes |
| PUT | `/api/principals/:name/ticket-policy` | Set per-principal policy override | Admin |
| DELETE | `/api/principals/:name/ticket-policy` | Remove per-principal override | Admin |

**Ticket policy fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `maxTicketLife` | integer (seconds) | `36000` (10h) | Maximum TGT lifetime |
| `maxRenewLife` | integer (seconds) | `604800` (7d) | Maximum renewable lifetime |
| `forwardable` | boolean | `true` | Allow forwardable tickets |
| `proxiable` | boolean | `false` | Allow proxiable tickets |
| `renewable` | boolean | `true` | Allow ticket renewal |
| `noAddress` | boolean | `true` | Disable address restrictions |

```bash
# Set realm-wide policy
curl -X PUT http://localhost:3013/api/ticket-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"maxTicketLife":28800,"maxRenewLife":604800,"forwardable":true}'

# Set stricter policy for a privileged account
curl -X PUT "http://localhost:3013/api/principals/admin/ticket-policy" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"maxTicketLife":3600,"forwardable":false,"renewable":false}'
```

### Delegation

#### Constrained Delegation (KCD)

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/delegation` | List all delegation configurations | Admin |
| GET | `/api/delegation/constrained/:principal` | Get KCD config for a service principal | Admin |
| POST | `/api/delegation/constrained` | Configure KCD for a principal | Admin |
| DELETE | `/api/delegation/constrained/:principal` | Remove KCD configuration | Admin |

**KCD body:**
```json
{
  "servicePrincipal": "HTTP/webapp.corp.example.com",
  "allowedTargets": [
    "MSSQLSvc/db01.corp.example.com:1433",
    "HTTP/api.corp.example.com"
  ],
  "protocol": "kerberos-only"
}
```

`protocol`: `kerberos-only` (traditional KCD) or `any` (protocol transition, enables S4U2Self).

#### Resource-Based Constrained Delegation (RBCD)

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/delegation/rbcd/:resource` | Get RBCD config for a resource | Admin |
| POST | `/api/delegation/rbcd` | Set RBCD on a resource | Admin |
| DELETE | `/api/delegation/rbcd/:resource` | Remove RBCD configuration | Admin |

**RBCD body:**
```json
{
  "resourcePrincipal": "MSSQLSvc/db01.corp.example.com:1433",
  "allowedDelegators": ["HTTP/webapp.corp.example.com"]
}
```

#### Unconstrained Delegation

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/delegation/unconstrained` | Security audit: list all unconstrained delegations | Admin |
| POST | `/api/delegation/unconstrained` | Set or unset unconstrained delegation | Admin |

**Warning:** Unconstrained delegation allows any service with a TGT to impersonate any user to any service. Use only in legacy environments and restrict with Protected Users group membership.

#### S4U2 Simulation

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/delegation/simulate/s4u2self` | Simulate S4U2Self protocol transition | Admin |
| POST | `/api/delegation/simulate/s4u2proxy` | Validate S4U2Proxy delegation chain | Admin |

```bash
# Simulate S4U2Self — can this service get a ticket on behalf of user?
curl -X POST http://localhost:3013/api/delegation/simulate/s4u2self \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"servicePrincipal":"HTTP/webapp.corp.example.com","userPrincipal":"alice@CORP.EXAMPLE.COM"}'

# Validate S4U2Proxy chain
curl -X POST http://localhost:3013/api/delegation/simulate/s4u2proxy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "servicePrincipal": "HTTP/webapp.corp.example.com",
    "targetServiceSPN": "MSSQLSvc/db01.corp.example.com:1433"
  }'
```

#### Delegation Audit

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/delegation/audit` | Query delegation audit log (`?from=&to=&servicePrincipal=&limit=`) | Admin |

### Protected Users

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/protected-users` | List Protected Users group members | Admin |
| POST | `/api/protected-users` | Add principal to Protected Users | Admin |
| DELETE | `/api/protected-users/:principal` | Remove principal from Protected Users | Admin |
| GET | `/api/protected-users/report` | Get protection enforcement report | Admin |
| POST | `/api/protected-users/:principal/check` | Check if an operation is allowed for a protected user | Yes |

Membership in Protected Users enforces: no NTLM auth, no RC4 or DES encryption, no unconstrained delegation, no delegation at all, and ticket lifetimes capped at 4 hours non-renewable.

```bash
# Add admin account to Protected Users
curl -X POST http://localhost:3013/api/protected-users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userPrincipal":"admin@CORP.EXAMPLE.COM","addedBy":"security-team"}'
```

### Health Check

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/health` | Health check including kadmin.local connectivity | No |

```json
{
  "status": "ok",
  "realm": "OPENDIRECTORY.LOCAL",
  "db": "connected"
}
```

Returns `500` if `kadmin.local listprincs` fails (Kerberos admin service down).

## Events Published

The kerberos-kdc service does not currently publish to the event bus. Callers receive synchronous HTTP responses.

## Events Subscribed

| Routing Key | Action |
|---|---|
| `identity.user.created` | Sync new user principal via `POST /api/kerberos/sync-user` (called by authentication-service at registration) |
