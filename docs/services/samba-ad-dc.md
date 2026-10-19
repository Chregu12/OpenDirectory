# samba-ad-dc

**Port:** 3010  
**Database:** PostgreSQL + Samba (sysvol, LDAP backend)  
**Language:** Node.js 18+

## Overview

The Samba AD DC service wraps a Samba 4 domain controller and exposes a REST API for all domain management operations. It handles domain provisioning, user and group CRUD via LDAP, organisational unit management, computer account creation with one-time join tokens, DNS record management, Kerberos SPN creation and keytab export, and bidirectional sync between the Samba LDAP directory and OpenDirectory's LLDAP instance.

GPO creation, linking, enforcement ordering, and backup/restore are also exposed through this service via the sysvol manager and GPO linker. FSMO role management (view holders, transfer roles) and replication status are surfaced for multi-DC environments.

All routes are prefixed with `/api/samba/`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3010` | HTTP listen port |
| `LLDAP_URL` | `ldap://lldap:3890` | LLDAP backend URL for sync |
| `LLDAP_BASE_DN` | `dc=opendirectory,dc=local` | Base DN |
| `LLDAP_ADMIN_USER` | `admin` | LLDAP admin username |
| `LLDAP_ADMIN_PASSWORD` | — | LLDAP admin password |
| `SAMBA_TOOL` | `/usr/bin/samba-tool` | Path to samba-tool binary |

## API Endpoints

### Domain Provisioning

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/samba/domain/provision` | Provision a new Samba AD domain | Admin |
| GET | `/api/samba/domain/status` | Get domain provisioning status | Yes |
| GET | `/api/samba/domain/info` | Forest and domain info including functional levels | Yes |

**Provision body:**
```json
{
  "realm": "CORP.EXAMPLE.COM",
  "domain": "CORP",
  "adminPassword": "Admin1234!",
  "dnsBackend": "SAMBA_INTERNAL"
}
```

### Domain Controller

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/dc/status` | DC health status | Yes |
| GET | `/api/samba/dc/fsmo` | FSMO role holders | Yes |
| POST | `/api/samba/dc/fsmo/transfer` | Transfer an FSMO role | Admin |
| GET | `/api/samba/dc/replication` | Replication status | Yes |
| GET | `/api/samba/dc/level` | Domain/forest functional levels | Yes |

**FSMO transfer body:**
```json
{
  "role": "PDCEmulator",
  "targetDC": "dc02.corp.example.com"
}
```

Valid roles: `PDCEmulator`, `RIDMaster`, `InfrastructureMaster`, `DomainNamingMaster`, `SchemaMaster`.

### Users

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/users` | List AD users (supports `?search=`, `?filter=`, `?page=`, `?limit=`) | Yes |
| POST | `/api/samba/users` | Create AD user | Yes |
| PUT | `/api/samba/users/:dn` | Modify user attributes (DN URL-encoded) | Yes |
| DELETE | `/api/samba/users/:dn` | Delete AD user | Yes |

**Create user body:**
```json
{
  "username": "jsmith",
  "password": "Pass1234!",
  "firstName": "John",
  "lastName": "Smith",
  "email": "jsmith@corp.example.com",
  "displayName": "John Smith",
  "department": "Engineering",
  "title": "Senior Engineer",
  "ou": "OU=Engineering,DC=corp,DC=example,DC=com"
}
```

```bash
curl -X POST http://localhost:3010/api/samba/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"jsmith","password":"Pass1234!","firstName":"John","lastName":"Smith"}'
```

### Groups

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/groups` | List AD groups (supports `?search=`, `?filter=`) | Yes |
| POST | `/api/samba/groups` | Create group | Yes |
| POST | `/api/samba/groups/:dn/members` | Add member to group | Yes |
| DELETE | `/api/samba/groups/:dn/members` | Remove member from group | Yes |

**Create group body:**
```json
{
  "name": "DevOps Engineers",
  "description": "DevOps team security group",
  "groupType": "security",
  "groupScope": "global",
  "ou": "OU=Groups,DC=corp,DC=example,DC=com"
}
```

`groupType`: `security` or `distribution`. `groupScope`: `global`, `universal`, `domainlocal`.

### Organisational Units

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/ous` | List OUs (supports `?baseDn=`) | Yes |
| POST | `/api/samba/ous` | Create OU | Yes |
| DELETE | `/api/samba/ous/:dn` | Delete OU (DN URL-encoded) | Yes |

### Computer Accounts

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/computers` | List computer accounts | Yes |
| POST | `/api/samba/computers/join-token` | Generate one-time domain join token | Yes |
| DELETE | `/api/samba/computers/:dn` | Remove computer account | Yes |

**Join token body:**
```json
{
  "computerName": "WORKSTATION01",
  "ou": "OU=Workstations,DC=corp,DC=example,DC=com"
}
```

Returns:
```json
{
  "computerName": "WORKSTATION01",
  "joinPassword": "AbCdEf1234!",
  "ou": "OU=Workstations,...",
  "expiresAt": "2026-06-08T12:00:00.000Z",
  "createdAt": "2026-06-07T12:00:00.000Z"
}
```

The token is valid for 24 hours.

### DNS Management

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/dns/zones` | List DNS zones | Yes |
| GET | `/api/samba/dns/records` | List records in a zone (`?zone=CORP.EXAMPLE.COM`) | Yes |
| POST | `/api/samba/dns/records` | Add DNS record | Yes |
| DELETE | `/api/samba/dns/records/:id` | Delete DNS record | Yes |
| GET | `/api/samba/dns/forwarders` | Get DNS forwarders | Yes |
| PUT | `/api/samba/dns/forwarders` | Set DNS forwarders | Yes |

**Add record body:**
```json
{
  "zone": "CORP.EXAMPLE.COM",
  "name": "www",
  "type": "A",
  "data": "10.0.0.50",
  "ttl": 3600
}
```

### Kerberos

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/kerberos/config` | Get Kerberos configuration | Yes |
| GET | `/api/samba/kerberos/principals` | List Kerberos principals | Yes |
| POST | `/api/samba/kerberos/spn` | Create SPN (`{ service, hostname }`) | Yes |
| POST | `/api/samba/kerberos/keytab` | Export keytab (`{ principal, path }`) | Yes |
| POST | `/api/samba/kerberos/test` | Test Kerberos authentication | Yes |

### GPO Management

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/gpo` | List all GPOs | Yes |
| POST | `/api/samba/gpo` | Create GPO | Yes |
| GET | `/api/samba/gpo/:id` | Get GPO settings | Yes |
| PUT | `/api/samba/gpo/:id` | Update GPO settings | Yes |
| DELETE | `/api/samba/gpo/:id` | Delete GPO | Yes |
| POST | `/api/samba/gpo/:id/link` | Link GPO to OU/domain/site | Yes |
| DELETE | `/api/samba/gpo/:id/link` | Unlink GPO from target | Yes |
| GET | `/api/samba/gpo/:id/links` | Get GPO link locations | Yes |
| PUT | `/api/samba/gpo/:id/link/enforce` | Set enforced flag on link | Yes |
| PUT | `/api/samba/gpo/link-order` | Set GPO processing order | Yes |
| GET | `/api/samba/gpo/:id/report` | Generate GPO settings report | Yes |
| POST | `/api/samba/gpo/:id/backup` | Backup GPO | Yes |
| POST | `/api/samba/gpo/restore` | Restore GPO from backup | Yes |

**Link GPO body:**
```json
{
  "targetDn": "OU=Workstations,DC=corp,DC=example,DC=com",
  "enforced": false,
  "disabled": false
}
```

```bash
# Create and link a GPO
curl -X POST http://localhost:3010/api/samba/gpo \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"BitLocker Policy","settings":{"encryption":{"bitlocker":true}}}'

curl -X POST http://localhost:3010/api/samba/gpo/gpo-uuid/link \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targetDn":"OU=Workstations,DC=corp,DC=example,DC=com","enforced":true}'
```

### LDAP/Samba Sync

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/samba/sync/status` | Sync engine status | Yes |
| POST | `/api/samba/sync/lldap-to-samba` | Sync from LLDAP to Samba AD | Admin |
| POST | `/api/samba/sync/samba-to-lldap` | Sync from Samba AD to LLDAP | Admin |
| POST | `/api/samba/sync/continuous/start` | Start continuous sync (`{ intervalMs }`) | Admin |
| POST | `/api/samba/sync/continuous/stop` | Stop continuous sync | Admin |

## Events Published

| Routing Key | Trigger |
|---|---|
| `directory.samba.user.created` | AD user created via samba-tool |
| `directory.samba.user.deleted` | AD user deleted |
| `directory.samba.gpo.created` | GPO created |
| `directory.samba.gpo.linked` | GPO linked to target |
| `directory.samba.domain.provisioned` | Domain provisioning completed |

## Events Subscribed

| Routing Key | Action |
|---|---|
| `identity.user.created` | Create corresponding AD object |
| `device.enrolled` | Create computer account |

## Health Check

`GET /health` returns `{ "status": "ok", "timestamp": "..." }`.
