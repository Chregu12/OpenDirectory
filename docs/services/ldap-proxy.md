# ldap-proxy

**Ports:**
- `1389` (or `389` when running as root) — LDAP protocol proxy  
- `8389` — REST API (schema management + LDAP gateway)  
- `9091` — Prometheus metrics  

**Database:** None (stateless proxy over LLDAP)  
**Language:** Node.js 18+

## Overview

The LDAP proxy service has two distinct functions:

1. **LDAP pass-through proxy** — listens on port 1389/389 and forwards all LDAP bind and search operations to the upstream LLDAP instance. Clients speak standard LDAP and are unaware of the proxy. Anonymous binds are passed through; authenticated binds use admin credentials for upstream searches.

2. **REST management API** — listens on port 8389 and provides schema introspection (object classes, attribute types), schema extension (adding custom attributes and object classes), entry validation, and a full LDAP REST gateway for search, add, modify, move, delete, compare, and password-change operations using RFC 4515 filter syntax.

The REST API requires authentication via `Authorization: Bearer <token>` (matched against `LLDAP_API_TOKEN`) or per-request LDAP bind credentials (`X-Bind-DN` + `X-Bind-Password` headers). Schema read endpoints (GET) are public; write endpoints require auth.

Prometheus metrics (bind counts, search counts, request duration) are on port 9091 at `/metrics`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `LLDAP_URL` | `ldap://localhost:3890` | Upstream LLDAP server URL |
| `LLDAP_BASE_DN` | `dc=opendirectory,dc=local` | Base DN for all operations |
| `LLDAP_ADMIN_USER` | `admin` | LLDAP admin username |
| `LLDAP_ADMIN_PASSWORD` | — | LLDAP admin password |
| `LLDAP_ADMIN_DN` | `uid=admin,ou=people,<BASE_DN>` | Full DN for admin bind |
| `LLDAP_API_TOKEN` | — | Bearer token for REST API auth |
| `LDAP_PROXY_PORT` | `389` | LDAP protocol listen port |
| `LDAP_REST_PORT` | `8389` | REST API listen port |
| `METRICS_PORT` | `9091` | Prometheus metrics port |

In non-root environments the LDAP port is automatically elevated to `1389` if the configured port is below 1024.

## Authentication

The REST API accepts two auth mechanisms:

| Mechanism | Headers |
|---|---|
| API token | `Authorization: Bearer <LLDAP_API_TOKEN>` |
| LDAP bind | `X-Bind-DN: uid=admin,ou=people,dc=...` and `X-Bind-Password: password` |

Read-only schema endpoints (`GET /api/schema/*`) do not require authentication.

## API Endpoints

### Schema — Object Classes

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/schema/object-classes` | List object classes (`?filter=`, `?page=`, `?limit=`) | No |
| GET | `/api/schema/object-classes/:name` | Get object class definition | No |
| POST | `/api/schema/object-classes` | Add custom object class | Yes |

```bash
# List object classes
curl "http://localhost:8389/api/schema/object-classes?filter=person&limit=10"

# Add custom object class
curl -X POST http://localhost:8389/api/schema/object-classes \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "organizationDevice",
    "oid": "1.3.6.1.4.1.99999.1",
    "superClass": "top",
    "kind": "AUXILIARY",
    "must": ["cn"],
    "may": ["description", "serialNumber", "owner"]
  }'
```

### Schema — Attribute Types

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/schema/attribute-types` | List attribute types (`?filter=`, `?page=`, `?limit=`) | No |
| GET | `/api/schema/attribute-types/:name` | Get attribute type definition | No |
| POST | `/api/schema/attribute-types` | Add custom attribute type | Yes |

```bash
# Add custom attribute
curl -X POST http://localhost:8389/api/schema/attribute-types \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "deviceSerialNumber",
    "oid": "1.3.6.1.4.1.99999.2",
    "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
    "singleValue": true,
    "description": "Hardware serial number"
  }'
```

### Schema — Validation

| Method | Path | Description | Auth Required |
|---|---|---|---|
| GET | `/api/schema/validate` | Validate an LDAP entry against schema | No |
| GET | `/api/dn/:dn/schema` | Get applicable schema for a DN | No |

**Validate body (sent as GET with body):**
```json
{
  "dn": "uid=alice,ou=people,dc=opendirectory,dc=local",
  "attributes": {
    "objectClass": ["inetOrgPerson", "person"],
    "cn": "Alice Smith",
    "sn": "Smith",
    "uid": "alice",
    "mail": "alice@example.com"
  }
}
```

### LDAP REST Gateway

All LDAP operations require authentication.

| Method | Path | Description | Auth Required |
|---|---|---|---|
| POST | `/api/ldap/search` | LDAP search with RFC 4515 filter | Yes |
| POST | `/api/ldap/add` | Add a new LDAP entry | Yes |
| PUT | `/api/ldap/modify` | Modify attributes of an entry | Yes |
| PUT | `/api/ldap/move` | Rename or move an entry (modifyDN) | Yes |
| DELETE | `/api/ldap/delete` | Delete an LDAP entry | Yes |
| POST | `/api/ldap/compare` | Compare attribute value | Yes |
| POST | `/api/ldap/password-change` | Change LDAP password (RFC 3062) | Yes |

#### POST /api/ldap/search

```json
{
  "baseDn": "ou=people,dc=opendirectory,dc=local",
  "filter": "(&(objectClass=inetOrgPerson)(mail=*@example.com))",
  "scope": "sub",
  "attributes": ["cn", "mail", "uid"],
  "sizeLimit": 100,
  "timeLimit": 10
}
```

The filter is validated against RFC 4515 syntax and sanitised before being forwarded upstream. `scope` accepts `base`, `one`, or `sub`.

```bash
curl -X POST http://localhost:8389/api/ldap/search \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "baseDn": "ou=people,dc=opendirectory,dc=local",
    "filter": "(uid=alice)",
    "scope": "sub",
    "attributes": ["cn","mail","memberOf"]
  }'
```

#### PUT /api/ldap/modify

```json
{
  "dn": "uid=alice,ou=people,dc=opendirectory,dc=local",
  "changes": [
    { "operation": "replace", "attribute": "mail", "values": ["alice-new@example.com"] },
    { "operation": "add", "attribute": "description", "values": ["Updated by provisioning"] }
  ]
}
```

`operation` values: `add`, `delete`, `replace`.

#### PUT /api/ldap/move

```json
{
  "dn": "uid=alice,ou=people,dc=opendirectory,dc=local",
  "newRDN": "uid=alice-smith",
  "deleteOldRDN": true,
  "newSuperior": "ou=staff,dc=opendirectory,dc=local"
}
```

#### POST /api/ldap/password-change

```json
{
  "userDn": "uid=alice,ou=people,dc=opendirectory,dc=local",
  "oldPassword": "oldPass123",
  "newPassword": "NewPass456!"
}
```

#### POST /api/ldap/compare

```json
{
  "dn": "uid=alice,ou=people,dc=opendirectory,dc=local",
  "attribute": "mail",
  "value": "alice@example.com"
}
```

Returns `{ "dn": "...", "attribute": "mail", "value": "alice@example.com", "matches": true }`.

## LDAP Proxy Protocol

Clients connect to `ldap://ldap-proxy:1389` (or `:389`) and use standard LDAP operations:

- **Bind:** Credentials are forwarded to LLDAP. Anonymous binds succeed without upstream validation.
- **Search:** The proxy binds upstream as admin, then executes the client's search operation with the same filter, scope, and attribute list.
- **Unsupported operations:** Add, modify, delete, modifyDN over the LDAP protocol are not proxied. Use the REST gateway for those operations.

## Events Published

The ldap-proxy service does not publish domain events. It is a stateless proxy.

## Events Subscribed

None.

## Health Check

`GET /healthz` on port 9091 returns `200 ok` (plain text). There is no `/health` endpoint on the REST API port.

Prometheus metrics at `http://localhost:9091/metrics` include:

- `ldap_binds_total` — label `result`: `success`, `failure`, `anonymous`
- `ldap_searches_total`
- `http_requests_total` — labels `method`, `route`, `status`
- `http_request_duration_seconds`
