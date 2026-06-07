# enterprise-directory

**Port:** 3000  
**Database:** MongoDB (directory objects, GPO data), Redis (cache)  
**Language:** Node.js 18+

## Overview

The enterprise directory service is the core Active Directory replacement in OpenDirectory. It provides a full LDAP-backed directory of users, groups, organisational units, and computer accounts using MongoDB for object storage, and exposes REST APIs for every AD operation. Group Policy is implemented through a built-in GPO enforcement engine that compiles and applies policies for Windows, macOS, and Linux targets.

The service hosts multiple protocol endpoints: REST at port 3000, LDAP at the configured `ldap.port`, and Kerberos KDC at `kerberos.kdcPort`. SSO is supported via OAuth2, OIDC, and SAML through dedicated route groups. Every mutating operation is recorded in a directory audit trail backed by MongoDB, with events published to the gRPC event bus.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP listen port |
| `MONGODB_URL` | `mongodb://mongodb:27017/opendirectory` | MongoDB connection string |
| `REDIS_HOST` | `redis` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `LDAP_PORT` | `389` | LDAP protocol port |
| `LDAP_SECURE_PORT` | `636` | LDAPS port |
| `LDAP_BASE_DN` | `dc=opendirectory,dc=local` | Directory base DN |
| `KERBEROS_REALM` | `OPENDIRECTORY.LOCAL` | Kerberos realm |
| `KERBEROS_KDC_PORT` | `88` | KDC port |
| `KERBEROS_ADMIN_PORT` | `749` | Kadmin port |
| `DNS_PORT` | `53` | DNS service port |
| `DNS_ENABLED` | `true` | Enable DNS integration |
| `GPO_WINDOWS_ENABLED` | `true` | Enable Windows GPO |
| `GPO_MACOS_ENABLED` | `true` | Enable macOS profiles |
| `GPO_LINUX_ENABLED` | `true` | Enable Linux policies |
| `SSO_OAUTH2_ENABLED` | `true` | Enable OAuth2 SSO |
| `SSO_OIDC_ENABLED` | `true` | Enable OIDC SSO |
| `SSO_SAML_ENABLED` | `true` | Enable SAML SSO |
| `PKI_ENABLED` | `true` | Enable built-in CA |
| `AD_BASE_DN` | `dc=opendirectory,dc=local` | Active Directory base DN |

## API Endpoints

### Directory

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/directory/users` | List directory users | Yes |
| POST | `/api/directory/users` | Create user | Yes |
| GET | `/api/directory/users/:id` | Get user by ID or DN | Yes |
| PUT | `/api/directory/users/:id` | Update user attributes | Yes |
| DELETE | `/api/directory/users/:id` | Delete user | Yes |
| GET | `/api/directory/groups` | List groups | Yes |
| POST | `/api/directory/groups` | Create group | Yes |
| GET | `/api/directory/groups/:id` | Get group | Yes |
| PUT | `/api/directory/groups/:id` | Update group | Yes |
| DELETE | `/api/directory/groups/:id` | Delete group | Yes |
| POST | `/api/directory/groups/:id/members` | Add member to group | Yes |
| DELETE | `/api/directory/groups/:id/members` | Remove member from group | Yes |
| GET | `/api/directory/ous` | List organisational units | Yes |
| POST | `/api/directory/ous` | Create OU | Yes |
| DELETE | `/api/directory/ous/:dn` | Delete OU | Yes |
| GET | `/api/directory/computers` | List computer accounts | Yes |
| POST | `/api/directory/computers` | Create computer account | Yes |

### Authentication

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/auth/authenticate` | Authenticate against directory | No |
| POST | `/api/auth/validate-token` | Validate an existing token | No |
| GET | `/api/auth/domain-info` | Domain metadata | No |

### Group Policy (GPO)

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/gpo/:id/apply` | Apply a GPO to linked OUs immediately | Yes |
| GET | `/api/gpo/:id/status` | Get GPO application status | Yes |
| GET | `/api/ou/:dn/rsop` | Compute RSoP for an OU (DN is base64-encoded) | Yes |
| GET | `/api/users/:id/rsop` | Compute RSoP for a user | Yes |
| POST | `/api/domain/password-policy` | Set domain password policy | Yes |
| POST | `/api/domain/lockout-policy` | Set domain account lockout policy | Yes |

### SSO / OAuth2 / OIDC / SAML

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/sso/providers` | List enabled SSO providers | No |
| GET | `/oauth2/authorize` | OAuth2 authorization endpoint | No |
| POST | `/oauth2/token` | OAuth2 token endpoint | No |
| GET | `/oidc/.well-known/openid-configuration` | OIDC discovery document | No |
| POST | `/saml/sso` | SAML SSO initiation | No |
| POST | `/saml/acs` | SAML assertion consumer service | No |

### Devices

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/devices` | List domain-joined devices | Yes |
| POST | `/api/devices/join` | Join a device to the domain | Yes |
| DELETE | `/api/devices/:id` | Remove device from domain | Yes |

### Certificates

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/certificates/issue` | Issue a certificate from the internal CA | Yes |
| POST | `/api/certificates/:id/revoke` | Revoke a certificate | Yes |
| GET | `/api/certificates` | List issued certificates | Yes |

### Audit

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/audit/log` | Query audit log (params: from, to, actorId, targetDn, operation, limit, offset) | Yes |
| GET | `/api/audit/objects/:dn/history` | Full change history for a DN (base64-encoded) | Yes |
| GET | `/api/audit/actors/:id/activity` | Activity report for an actor | Yes |

### System

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/health` | Service health check | No |
| GET | `/status` | Detailed status including sub-service states | No |
| GET | `/info` | Service capabilities and protocol ports | No |

### GPO Apply Example

```bash
# Apply GPO to a specific OU
curl -X POST http://localhost:3000/api/gpo/gpo-uuid/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ouDn": "OU=Workstations,DC=opendirectory,DC=local", "dryRun": false}'
```

Response:
```json
{
  "gpoId": "gpo-uuid",
  "linkedOUs": ["OU=Workstations,DC=opendirectory,DC=local"],
  "dryRun": false,
  "results": {
    "applied": ["CN=PC001,OU=Workstations,..."],
    "skipped": [],
    "errors": []
  }
}
```

### RSoP Example

The `:dn` parameter must be base64-encoded to avoid URL encoding issues with DN separators:

```bash
DN="OU=Engineering,DC=opendirectory,DC=local"
ENCODED=$(echo -n "$DN" | base64)
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3000/api/ou/${ENCODED}/rsop"
```

### Password Policy Example

```bash
curl -X POST http://localhost:3000/api/domain/password-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "minLength": 12,
    "complexity": true,
    "maxAge": 90,
    "minAge": 1,
    "historyCount": 24
  }'
```

## Events Published

| Routing Key | Trigger |
|---|---|
| `directory.user.created` | User created in directory |
| `directory.user.updated` | User attributes changed |
| `directory.user.deleted` | User removed |
| `directory.group.created` | Group created |
| `directory.group.membership.changed` | Member added or removed |
| `directory.gpo.applied` | GPO enforcement applied to OU |
| `directory.policy.changed` | Domain password or lockout policy changed |

## Events Subscribed

| Routing Key | Action |
|---|---|
| `identity.user.created` | Create corresponding directory object |
| `device.enrolled` | Create computer account for new device |

## Health Check

`GET /health` checks MongoDB, Redis, and the event bus connection, and polls each sub-service (activeDirectory, ldap, kerberos, groupPolicy, sso, deviceJoin, certificateAuthority, dnsIntegration) via their `healthCheck()` methods.

```json
{
  "status": "healthy",
  "timestamp": "2026-06-07T12:00:00.000Z",
  "uptime": 3600,
  "mongodb": "healthy",
  "redis": "healthy",
  "rabbitmq": "healthy",
  "services": {
    "activeDirectory": "healthy",
    "ldap": "healthy",
    "kerberos": "healthy",
    "groupPolicy": "healthy"
  }
}
```

Returns `503` if any critical dependency is unhealthy.
