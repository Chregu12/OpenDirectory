# Directory API Reference

This document covers the REST APIs for directory management across two services:

- **enterprise-directory** — `http://enterprise-directory:3000` — AD-compatible directory (MongoDB backend)
- **samba-ad-dc** — `http://samba-ad-dc:3010` — Samba 4 domain controller (real LDAP/Kerberos backend)

Both services expose complementary APIs. The enterprise-directory handles the OpenDirectory-native object model and GPO enforcement. The samba-ad-dc wraps the actual Samba AD instance for domain-joined Windows/Linux clients.

**Authentication:** `Authorization: Bearer <token>` on all protected routes.

---

## enterprise-directory API

Base URL: `http://enterprise-directory:3000`

### Organisational Units

#### GET /api/directory/ous

List all organisational units.

**Query parameters:** `?baseDn=` — restrict search to a sub-tree.

**Response 200:**

```json
{
  "ous": [
    {
      "id": "ou-uuid",
      "name": "Engineering",
      "dn": "OU=Engineering,DC=corp,DC=example,DC=com",
      "description": "Engineering department",
      "parentDn": "DC=corp,DC=example,DC=com",
      "createdAt": "2026-01-01T00:00:00.000Z"
    }
  ],
  "total": 12
}
```

```bash
curl http://localhost:3000/api/directory/ous \
  -H "Authorization: Bearer $TOKEN"
```

---

#### POST /api/directory/ous

Create an organisational unit.

**Request body:**

```json
{
  "name": "DevOps",
  "parentDn": "OU=Engineering,DC=corp,DC=example,DC=com",
  "description": "DevOps sub-team"
}
```

**Response 201:** Created OU object with generated `id` and `dn`.

```bash
curl -X POST http://localhost:3000/api/directory/ous \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DevOps",
    "parentDn": "OU=Engineering,DC=corp,DC=example,DC=com",
    "description": "DevOps sub-team"
  }'
```

---

#### DELETE /api/directory/ous/:dn

Delete an OU. The OU must be empty. The `:dn` path parameter should be URL-encoded.

```bash
curl -X DELETE \
  "http://localhost:3000/api/directory/ous/OU%3DDevOps%2COU%3DEngineering%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Group Management

#### GET /api/directory/groups

List groups.

**Query parameters:** `?search=`, `?type=security|distribution`, `?page=`, `?limit=`

**Response 200:**

```json
{
  "groups": [
    {
      "id": "group-uuid",
      "name": "Engineering-Security",
      "dn": "CN=Engineering-Security,OU=Groups,DC=corp,DC=example,DC=com",
      "groupType": "security",
      "groupScope": "global",
      "memberCount": 28,
      "createdAt": "2026-01-15T00:00:00.000Z"
    }
  ],
  "total": 35
}
```

---

#### POST /api/directory/groups

Create a group.

**Request body:**

```json
{
  "name": "SRE-Team",
  "description": "Site reliability engineers",
  "groupType": "security",
  "groupScope": "global",
  "ouDn": "OU=Groups,OU=Engineering,DC=corp,DC=example,DC=com",
  "managedBy": "user-uuid"
}
```

`groupType`: `security` or `distribution`. `groupScope`: `global`, `universal`, `domainlocal`.

```bash
curl -X POST http://localhost:3000/api/directory/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"SRE-Team","groupType":"security","groupScope":"global"}'
```

---

#### POST /api/directory/groups/:id/members

Add a user or nested group to a group.

**Request body:**

```json
{
  "memberDn": "CN=Alice Smith,OU=Engineering,DC=corp,DC=example,DC=com",
  "memberType": "user"
}
```

---

#### DELETE /api/directory/groups/:id/members

Remove a member from a group.

**Request body:**

```json
{
  "memberDn": "CN=Alice Smith,OU=Engineering,DC=corp,DC=example,DC=com"
}
```

---

### GPO Operations

#### POST /api/gpo/:id/apply

Apply a GPO to all linked OUs immediately, without waiting for the next group policy refresh cycle.

**Path parameter:** `id` — GPO UUID.

**Request body:**

```json
{
  "ouDn": "OU=Workstations,DC=corp,DC=example,DC=com",
  "dryRun": false
}
```

If `ouDn` is omitted, the GPO is applied to all OUs it is currently linked to.

**Response 200:**

```json
{
  "gpoId": "gpo-uuid",
  "linkedOUs": ["OU=Workstations,DC=corp,DC=example,DC=com"],
  "dryRun": false,
  "results": {
    "applied": ["CN=PC001,OU=Workstations,...", "CN=PC002,OU=Workstations,..."],
    "skipped": [],
    "errors": []
  }
}
```

```bash
curl -X POST http://localhost:3000/api/gpo/gpo-uuid/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"dryRun": true}'
```

---

#### GET /api/gpo/:id/status

Returns which OUs and objects the GPO is currently applied to, along with version and last-applied timestamps.

```bash
curl http://localhost:3000/api/gpo/gpo-uuid/status \
  -H "Authorization: Bearer $TOKEN"
```

---

#### GET /api/ou/:dn/rsop

Compute the Resultant Set of Policy (RSoP) for an OU — the merged effective policy after applying GPO inheritance and precedence rules.

The `:dn` parameter must be **base64-encoded** to avoid URL encoding issues with DN separators (commas and equals signs).

```bash
DN="OU=Engineering,DC=corp,DC=example,DC=com"
ENCODED=$(echo -n "$DN" | base64)
curl "http://localhost:3000/api/ou/${ENCODED}/rsop" \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "targetDn": "OU=Engineering,DC=corp,DC=example,DC=com",
  "effectiveSettings": {
    "passwordPolicy.minLength": { "value": 12, "source": "gpo-uuid-domain-policy" },
    "encryption.bitlocker": { "value": true, "source": "gpo-uuid-security" }
  },
  "appliedGPOs": [
    { "id": "gpo-uuid-domain-policy", "name": "Default Domain Policy", "order": 1 },
    { "id": "gpo-uuid-security", "name": "Security Baseline", "order": 2 }
  ],
  "inheritance": "normal"
}
```

---

#### GET /api/users/:id/rsop

Compute RSoP for a specific user. The `:id` is the user's sAMAccountName or base64-encoded DN.

```bash
curl "http://localhost:3000/api/users/alice/rsop" \
  -H "Authorization: Bearer $TOKEN"
```

---

#### POST /api/domain/password-policy

Set the domain-wide password policy.

**Request body:**

| Field | Type | Description |
|---|---|---|
| `domainDn` | string | Target domain DN (defaults to base DN) |
| `minLength` | integer | Minimum password length |
| `complexity` | boolean | Require complexity (upper, lower, digit, special) |
| `maxAge` | integer | Maximum password age in days |
| `minAge` | integer | Minimum password age in days |
| `historyCount` | integer | Number of previous passwords to remember |

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

---

#### POST /api/domain/lockout-policy

Set the domain-wide account lockout policy.

**Request body:**

| Field | Type | Description |
|---|---|---|
| `domainDn` | string | Target domain DN |
| `threshold` | integer | Failed attempts before lockout |
| `observationWindow` | integer | Failed attempt observation window (minutes) |
| `lockoutDuration` | integer | Lockout duration in minutes (0 = manual unlock required) |

```bash
curl -X POST http://localhost:3000/api/domain/lockout-policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"threshold": 5, "observationWindow": 15, "lockoutDuration": 30}'
```

---

### Audit Log

#### GET /api/audit/log

Query the directory audit log.

**Query parameters:**

| Parameter | Description |
|---|---|
| `from` | ISO 8601 start time |
| `to` | ISO 8601 end time |
| `actorId` | Filter by actor user ID |
| `targetDn` | Filter by target object DN |
| `operation` | Filter by operation type: `create`, `modify`, `delete`, `link`, `apply` |
| `limit` | Max results (default: 100) |
| `offset` | Pagination offset (default: 0) |

```bash
curl "http://localhost:3000/api/audit/log?from=2026-06-01T00:00:00Z&operation=delete&limit=50" \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "entries": [
    {
      "id": "audit-uuid",
      "timestamp": "2026-06-07T11:30:00.000Z",
      "actorId": "admin-uuid",
      "operation": "delete",
      "targetDn": "CN=Bob Smith,OU=Engineering,...",
      "objectType": "user",
      "changes": null,
      "ipAddress": "10.0.0.5"
    }
  ],
  "total": 142,
  "limit": 50,
  "offset": 0
}
```

---

#### GET /api/audit/objects/:dn/history

Full change history for a specific directory object. The `:dn` is base64-encoded.

```bash
DN="CN=Alice Smith,OU=Engineering,DC=corp,DC=example,DC=com"
ENCODED=$(echo -n "$DN" | base64)
curl "http://localhost:3000/api/audit/objects/${ENCODED}/history" \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "targetDn": "CN=Alice Smith,OU=Engineering,...",
  "history": [
    {
      "timestamp": "2026-06-07T09:00:00.000Z",
      "operation": "modify",
      "actorId": "admin-uuid",
      "changes": {
        "mail": { "before": "alice@old.com", "after": "alice@corp.example.com" }
      }
    }
  ]
}
```

---

#### GET /api/audit/actors/:id/activity

Activity report for a specific actor (admin user).

**Query parameters:** `?from=`, `?to=`

---

## samba-ad-dc API

Base URL: `http://samba-ad-dc:3010`

All routes are prefixed with `/api/samba/`.

### OU Management

#### GET /api/samba/ous

List all Organisational Units in the domain.

**Query parameters:** `?baseDn=` — restrict to a sub-tree.

**Response 200:**

```json
{
  "ous": [
    {
      "dn": "OU=Workstations,DC=corp,DC=example,DC=com",
      "name": "Workstations",
      "description": "Company workstations"
    }
  ],
  "total": 8
}
```

---

#### POST /api/samba/ous

Create an OU via Samba LDAP.

```bash
curl -X POST http://localhost:3010/api/samba/ous \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Servers",
    "parentDn": "DC=corp,DC=example,DC=com",
    "description": "Server infrastructure"
  }'
```

**Response 201:**

```json
{
  "success": true,
  "dn": "OU=Servers,DC=corp,DC=example,DC=com",
  "name": "Servers",
  "createdAt": "2026-06-07T12:00:00.000Z"
}
```

---

#### DELETE /api/samba/ous/:dn

Delete an OU. The OU must be empty. URL-encode the `:dn` parameter.

---

### Group Management

#### GET /api/samba/groups

List AD groups.

**Query parameters:** `?search=`, `?filter=` (raw LDAP filter), `?page=`, `?limit=`

---

#### POST /api/samba/groups

Create a security or distribution group.

```bash
curl -X POST http://localhost:3010/api/samba/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DevOps-Engineers",
    "description": "DevOps team",
    "groupType": "security",
    "groupScope": "global",
    "ou": "OU=Groups,DC=corp,DC=example,DC=com"
  }'
```

---

#### POST /api/samba/groups/:dn/members

Add a member to a group. The `:dn` is the group's DN (URL-encoded).

**Request body:**

```json
{ "userDn": "CN=Alice Smith,OU=Engineering,DC=corp,DC=example,DC=com" }
```

---

#### DELETE /api/samba/groups/:dn/members

Remove a member from a group.

**Request body:**

```json
{ "userDn": "CN=Alice Smith,OU=Engineering,DC=corp,DC=example,DC=com" }
```

---

### Computer Account Management

#### GET /api/samba/computers

List computer accounts.

**Query parameters:** `?search=` (matches CN and dNSHostName), `?filter=` (raw LDAP filter)

```bash
curl "http://localhost:3010/api/samba/computers?search=PC001" \
  -H "Authorization: Bearer $TOKEN"
```

---

#### POST /api/samba/computers/join-token

Generate a one-time domain join token for a computer. The token is valid for 24 hours. Use this as the machine account password during domain join.

**Request body:**

```json
{
  "computerName": "WORKSTATION01",
  "ou": "OU=Workstations,DC=corp,DC=example,DC=com"
}
```

`computerName` must be 1–15 alphanumeric characters (NetBIOS format).

**Response 201:**

```json
{
  "computerName": "WORKSTATION01",
  "joinPassword": "AbCdEf1234567890A1!",
  "ou": "OU=Workstations,DC=corp,DC=example,DC=com",
  "expiresAt": "2026-06-08T12:00:00.000Z",
  "createdAt": "2026-06-07T12:00:00.000Z"
}
```

```bash
# On Windows, use the join password with netdom or PowerShell:
# Add-Computer -DomainName corp.example.com -OUPath "OU=Workstations,..."
#   -Credential (New-Object PSCredential "WORKSTATION01$", (ConvertTo-SecureString "AbCdEf..." -AsPlainText -Force))

curl -X POST http://localhost:3010/api/samba/computers/join-token \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"computerName":"WORKSTATION01","ou":"OU=Workstations,DC=corp,DC=example,DC=com"}'
```

---

#### DELETE /api/samba/computers/:dn

Remove a computer account. URL-encode the `:dn`.

---

### Replication Status

#### GET /api/samba/dc/replication

Get domain controller replication status and health.

```bash
curl http://localhost:3010/api/samba/dc/replication \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "replicationPartners": [
    {
      "partner": "dc02.corp.example.com",
      "lastReplication": "2026-06-07T11:55:00.000Z",
      "consecutiveFailures": 0,
      "status": "healthy",
      "usnDelta": 0
    }
  ],
  "overallHealth": "healthy",
  "checkedAt": "2026-06-07T12:00:00.000Z"
}
```

---

#### GET /api/samba/dc/status

Current DC operational status, including LDAP service health and FSMO role holding status.

---

#### GET /api/samba/dc/fsmo

FSMO role assignment. Returns which DC holds each role.

```bash
curl http://localhost:3010/api/samba/dc/fsmo \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "PDCEmulator": "dc01.corp.example.com",
  "RIDMaster": "dc01.corp.example.com",
  "InfrastructureMaster": "dc01.corp.example.com",
  "DomainNamingMaster": "dc01.corp.example.com",
  "SchemaMaster": "dc01.corp.example.com"
}
```

---

#### POST /api/samba/dc/fsmo/transfer

Transfer an FSMO role to another DC.

```bash
curl -X POST http://localhost:3010/api/samba/dc/fsmo/transfer \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "PDCEmulator", "targetDC": "dc02.corp.example.com"}'
```

---

### LAPS (Local Administrator Password Solution)

LAPS passwords are stored as computer account attributes in the Samba AD. Query them via the user list endpoint with a custom LDAP filter:

```bash
# Retrieve LAPS password for a specific computer
curl "http://localhost:3010/api/samba/computers?filter=(%26(objectClass=computer)(cn=WORKSTATION01))" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The `ms-Mcs-AdmPwd` attribute contains the current LAPS password and `ms-Mcs-AdmPwdExpirationTime` contains the expiry timestamp.

---

### GPO Management (via samba-ad-dc)

#### GET /api/samba/gpo

List all GPOs in the domain.

```bash
curl http://localhost:3010/api/samba/gpo \
  -H "Authorization: Bearer $TOKEN"
```

---

#### POST /api/samba/gpo

Create a new GPO.

```bash
curl -X POST http://localhost:3010/api/samba/gpo \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Workstation Security Baseline",
    "settings": {
      "computer": {
        "security": { "passwordMinLength": 12 }
      }
    }
  }'
```

---

#### POST /api/samba/gpo/:id/link

Link a GPO to an OU, domain, or site.

```bash
curl -X POST http://localhost:3010/api/samba/gpo/gpo-uuid/link \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targetDn": "OU=Workstations,DC=corp,DC=example,DC=com",
    "enforced": false,
    "disabled": false
  }'
```

---

#### GET /api/samba/gpo/:id/report

Generate a human-readable GPO settings report.

```bash
curl http://localhost:3010/api/samba/gpo/gpo-uuid/report \
  -H "Authorization: Bearer $TOKEN"
```

**Response 200:**

```json
{
  "id": "gpo-uuid",
  "name": "Workstation Security Baseline",
  "version": 3,
  "machineVersion": 2,
  "userVersion": 1,
  "enabled": true,
  "machineEnabled": true,
  "userEnabled": true,
  "machineSettings": { "security": { "passwordMinLength": 12 } },
  "userSettings": {},
  "generatedAt": "2026-06-07T12:00:00.000Z"
}
```

---

## Health Checks

| Service | Endpoint | Expected Response |
|---|---|---|
| enterprise-directory | `GET http://enterprise-directory:3000/health` | `{ "status": "healthy" \| "unhealthy" }` with 200/503 |
| samba-ad-dc | `GET http://samba-ad-dc:3010/health` | `{ "status": "ok" }` |
