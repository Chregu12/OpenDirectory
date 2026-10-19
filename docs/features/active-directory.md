# Active Directory

OpenDirectory ships a full Samba 4-based domain controller, exposed through the `samba-ad-dc` service (port **3010**). It provides LDAP, Kerberos, DNS, SYSVOL, trust management, LAPS, BitLocker key escrow, multi-DC replication, and LDAP schema management.

---

## 1. Domain Controller

The domain controller is powered by Samba 4 and offers complete AD DS compatibility.

| Protocol | Port | Notes |
|----------|------|-------|
| LDAP | 389 | Cleartext; use LDAPS in production |
| LDAPS | 636 | TLS-wrapped LDAP |
| Kerberos | 88 | KDC ticket issuance |
| DNS | 53 | AD-integrated DNS zones |
| SYSVOL | 445 (SMB) | GPO file store |

### Provision a new domain

```bash
curl -X POST http://samba-ad-dc:3010/api/samba/domain/provision \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "CORP.EXAMPLE.COM",
    "domain": "CORP",
    "adminPassword": "P@ssw0rd!",
    "dnsBackend": "SAMBA_INTERNAL"
  }'
```

### Check domain status

```bash
curl http://samba-ad-dc:3010/api/samba/domain/status
curl http://samba-ad-dc:3010/api/samba/domain/info   # forest/functional levels
curl http://samba-ad-dc:3010/api/samba/dc/status      # DC health
curl http://samba-ad-dc:3010/api/samba/dc/fsmo        # FSMO role holders
```

---

## 2. Users

User objects are stored in LDAP with `objectClass: user`. Key attributes:

| Attribute | Description |
|-----------|-------------|
| `sAMAccountName` | Pre-Windows 2000 logon name (max 20 chars) |
| `userPrincipalName` | UPN in `user@domain.com` format |
| `displayName` | Full display name |
| `mail` | Email address |
| `department`, `title` | Organisational attributes |
| `telephoneNumber` | Phone number |
| `userAccountControl` | Bitfield controlling account state |

### Create a user

```bash
curl -X POST http://samba-ad-dc:3010/api/samba/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jsmith",
    "password": "TempP@ss1!",
    "firstName": "John",
    "lastName": "Smith",
    "email": "jsmith@corp.example.com",
    "displayName": "John Smith",
    "department": "Engineering",
    "title": "Software Engineer",
    "ou": "OU=Engineering,DC=corp,DC=example,DC=com"
  }'
```

### Modify a user

```bash
# DN must be URL-encoded
curl -X PUT "http://samba-ad-dc:3010/api/samba/users/CN%3DJohn%20Smith%2COU%3DEngineering%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom" \
  -H "Content-Type: application/json" \
  -d '{"title": "Senior Software Engineer", "department": "Platform"}'
```

### Disable / lock / unlock

Use the authentication-service (port **3001**) for account state operations:

```bash
# Lock a user
curl -X POST http://authentication-service:3001/api/auth/users/<userId>/lock

# Unlock a user
curl -X POST http://authentication-service:3001/api/auth/users/<userId>/unlock
```

### Delete a user

```bash
curl -X DELETE "http://samba-ad-dc:3010/api/samba/users/CN%3DJohn%20Smith%2COU%3DEngineering%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom"
```

### Search users

```bash
# Free-text search across cn, sAMAccountName, mail, displayName
curl "http://samba-ad-dc:3010/api/samba/users?search=smith&page=1&limit=25"

# Raw LDAP filter
curl "http://samba-ad-dc:3010/api/samba/users?filter=(department=Engineering)"

# Select specific attributes
curl "http://samba-ad-dc:3010/api/samba/users?search=smith&attributes=cn,mail,department"
```

---

## 3. Groups

### Group types and scopes

| Scope | Code | Description |
|-------|------|-------------|
| Global | `global` | Members from same domain; visible forest-wide |
| Domain Local | `domainlocal` | Members from any domain; used to assign permissions |
| Universal | `universal` | Members from any domain in the forest |

| Type | Code | Description |
|------|------|-------------|
| Security | `security` | Used for access control and permissions |
| Distribution | `distribution` | Email distribution lists only |

### Create a group

```bash
curl -X POST http://samba-ad-dc:3010/api/samba/groups \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering-Admins",
    "description": "Engineering department administrators",
    "groupType": "security",
    "groupScope": "global",
    "ou": "OU=Groups,DC=corp,DC=example,DC=com"
  }'
```

### Manage membership

```bash
# Add member
curl -X POST "http://samba-ad-dc:3010/api/samba/groups/CN%3DEngineering-Admins%2COU%3DGroups%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom/members" \
  -H "Content-Type: application/json" \
  -d '{"userDn": "CN=John Smith,OU=Engineering,DC=corp,DC=example,DC=com"}'

# Remove member
curl -X DELETE "http://samba-ad-dc:3010/api/samba/groups/CN%3DEngineering-Admins%2COU%3DGroups%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom/members" \
  -H "Content-Type: application/json" \
  -d '{"userDn": "CN=John Smith,OU=Engineering,DC=corp,DC=example,DC=com"}'
```

**Group nesting:** Add a group as a member of another group using the same endpoints, passing a group DN as `userDn`. Universal groups can nest global groups from any domain in the forest.

---

## 4. Computers

Computer accounts are created in `CN=Computers,<base DN>` by default. The `sAMAccountName` is `COMPUTERNAME$`.

### Domain join

```bash
# Generate a one-time join token (valid 24 hours)
curl -X POST http://samba-ad-dc:3010/api/samba/computers/join-token \
  -H "Content-Type: application/json" \
  -d '{"computerName": "WORKSTATION01", "ou": "OU=Workstations,DC=corp,DC=example,DC=com"}'
# Returns: computerName, joinPassword, ou, expiresAt
```

On the client machine (Windows), use the returned credentials with `netdom join` or the system dialog.

### Machine password reset

```bash
curl -X POST http://samba-ad-dc:3010/api/samba/computers/WORKSTATION01/machine-password
# Returns: newPassword, expiresAt (30 days)
```

### Remove a computer account

```bash
# Delete
curl -X DELETE "http://samba-ad-dc:3010/api/samba/computers/CN%3DWORKSTATION01%2CCN%3DComputers%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom"
```

---

## 5. Organisational Units

OUs provide a hierarchy for delegation, GPO application, and object containment.

### Create an OU

```bash
curl -X POST http://samba-ad-dc:3010/api/samba/ous \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering",
    "parentDn": "DC=corp,DC=example,DC=com",
    "description": "Engineering department"
  }'
```

### List OUs

```bash
curl "http://samba-ad-dc:3010/api/samba/ous"
curl "http://samba-ad-dc:3010/api/samba/ous?baseDn=OU%3DEngineering%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom"
```

### Delete an OU

```bash
curl -X DELETE "http://samba-ad-dc:3010/api/samba/ous/OU%3DEngineering%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom"
```

### GPO links and Block Inheritance

GPO links and Block Inheritance are managed through the enterprise-directory service. See [Group Policy](./group-policy.md) for details.

**Delegation:** Use the LDAP proxy (port **8389**) to set access control entries on OU objects, granting users or groups the right to manage specific object types within that OU.

---

## 6. Forest and Trust Management

### Trust types

| Type | Code | Description |
|------|------|-------------|
| External | `external` | One-way or two-way trust with a domain in another forest |
| Forest | `forest` | Full forest-to-forest trust; allows all domains in both forests to trust each other |
| Shortcut | `shortcut` | Shortcut within a forest to reduce Kerberos referral hops |
| Kerberos Realm | `kerberos-realm` | Trust with a non-Windows Kerberos realm (e.g. MIT Kerberos) |

### Trust directions

| Direction | Code | Description |
|-----------|------|-------------|
| Inbound | `inbound` | Remote domain trusts this domain (they can log in here) |
| Outbound | `outbound` | This domain trusts the remote domain (our users can log in there) |
| Bidirectional | `bidirectional` | Mutual trust in both directions |

### Transitivity

- **Transitive:** Trust flows through trust paths. If A trusts B and B trusts C, A can reach C. Forest trusts are always transitive within the forest.
- **Non-transitive:** Trust is limited to the two parties. External trusts are non-transitive by default.

### How to create a trust (step by step)

1. Ensure DNS resolution works between both domains (add conditional forwarders or delegations on each side).
2. Agree on a shared trust password with the administrator of the remote domain.
3. Create the trust on this side:

```bash
curl -X POST http://samba-ad-dc:3010/api/trusts \
  -H "Content-Type: application/json" \
  -d '{
    "trustedDomain": "partner.corp",
    "trustType": "forest",
    "trustDirection": "bidirectional",
    "trustPassword": "Shared$ecret123!",
    "transitivity": "transitive"
  }'
```

4. The administrator of `partner.corp` creates the reciprocal trust with the same password.
5. Verify the trust is healthy:

```bash
curl -X POST http://samba-ad-dc:3010/api/trusts/partner.corp/verify
# Returns: healthy, latencyMs, lastVerified, errors
```

6. List all trusts:

```bash
curl http://samba-ad-dc:3010/api/trusts
```

### Trust credential rotation

```bash
curl -X POST http://samba-ad-dc:3010/api/trusts/partner.corp/rotate-password
# Returns: trustedDomain, newPassword, rotatedAt
# Coordinate with the partner admin to update the password on their side.
```

### Remove a trust

```bash
curl -X DELETE http://samba-ad-dc:3010/api/trusts/partner.corp
```

### Transitive closure graph

Query the full reachability graph — which domains are accessible via trust chains:

```bash
curl http://samba-ad-dc:3010/api/trusts/closure
# Returns: [{domain: "corp.example.com", reachableVia: ["partner.corp", "subsidiary.local"]}, ...]
```

The UI exposes this as a visual forest trust graph under **Settings → Trust Management**, with verify, rotate, and remove actions inline.

---

## 7. LAPS (Local Administrator Password Solution)

LAPS ensures every managed Windows machine has a unique, randomly generated local administrator password. Passwords are encrypted at rest using AES-256-GCM and stored in both the LDAP attribute `ms-Mcs-AdmPwd` on the computer object and a PostgreSQL-backed secrets store.

### How LAPS works

1. When a computer joins the domain, LAPS is configured via GPO or MDM policy.
2. The LAPS agent on the computer generates a random password and escrows it to OpenDirectory.
3. The password is rotated on a schedule (default: every 24 hours) or on demand.
4. Only authorised users (scoped by RBAC role) can retrieve the password.
5. Every retrieval is logged with `computerName`, `retrievedBy`, and `retrievedAt`.

### Retrieve a LAPS password

```bash
# UI: Device detail → LAPS tab → "Reveal Password"

# API
curl "http://samba-ad-dc:3010/api/computers/DESKTOP-001/laps-password?requestingUserId=alice"
# Returns: computerName, password, expiresAt, retrievedBy, retrievedAt
```

### Set or update a LAPS password

```bash
curl -X POST http://samba-ad-dc:3010/api/computers/DESKTOP-001/laps-password \
  -H "Content-Type: application/json" \
  -d '{
    "password": "Str0ngP@ss!",
    "expiresAt": "2026-06-08T00:00:00Z"
  }'
```

### Rotate (generate new) LAPS password on demand

```bash
curl -X POST http://samba-ad-dc:3010/api/computers/DESKTOP-001/laps-password/rotate
# Returns: computerName, newPassword, expiresAt, rotatedAt
```

### Audit

Every retrieval inserts a row into `laps_access_log`:

| Column | Description |
|--------|-------------|
| `computer_name` | Uppercase computer name |
| `retrieved_by` | User ID / username of the requestor |
| `retrieved_at` | Timestamp |

---

## 8. BitLocker Recovery Keys

OpenDirectory is a BitLocker key escrow store. When a Windows device encrypts its OS or data volume, the recovery key is escrowed via API (or via GPO-triggered script) and stored encrypted at rest.

### Escrow a key

```bash
curl -X POST http://samba-ad-dc:3010/api/computers/LAPTOP-002/bitlocker-keys \
  -H "Content-Type: application/json" \
  -d '{
    "volumeType": "os",
    "recoveryKeyId": "550e8400-e29b-41d4-a716-446655440000",
    "recoveryKey": "123456-789012-345678-901234-567890-123456-789012-345678",
    "tpmThumbprint": "A1B2C3D4..."
  }'
```

Volume types: `os`, `data`, `removable`.

### List keys for a computer (metadata only — no key material exposed)

```bash
curl http://samba-ad-dc:3010/api/computers/LAPTOP-002/bitlocker-keys
```

### Retrieve a key

```bash
# UI: Device detail → BitLocker tab → "Recover Key"

# API
curl "http://samba-ad-dc:3010/api/computers/LAPTOP-002/bitlocker-keys/550e8400-e29b-41d4-a716-446655440000?requestingUserId=helpdesk01"
# Returns: recoveryKeyId, recoveryKey, volumeType, tpmThumbprint, escrowedAt
```

Every retrieval is logged in `bitlocker_key_access_log` with `recovery_key_id`, `retrieved_by`, and timestamp.

---

## 9. Multi-DC Replication

### How replication works

Samba uses **USN (Update Sequence Number)** tracking. Each object change increments the originating DC's USN. Partner DCs periodically query for changes with USNs higher than the last known value, pulling only the delta. The `highestCommittedUSN` returned from rootDSE indicates the current frontier for a DC.

### Replication health dashboard

The UI shows a **Replication Dashboard** under **Settings → Replication** with:
- Per-DC health status and `highestCommittedUSN`
- Last successful sync timestamp
- 30-second auto-refresh

```bash
# Query replication status
curl http://samba-ad-dc:3010/api/samba/dc/replication

# Query current USN on this DC
curl http://samba-ad-dc:3010/api/samba/dc/usn
```

### Force sync

```bash
curl -X POST http://samba-ad-dc:3010/api/samba/dc/replication/sync \
  -H "Content-Type: application/json" \
  -d '{"targetDC": "dc02.corp.example.com"}'
```

### Detecting lingering objects and USN rollback

- **Lingering objects:** Objects deleted on one DC but still present on another due to replication failures. Detected by comparing object lists across DCs. Use the Replication Dashboard's "Check for lingering objects" action.
- **USN rollback:** Occurs when a DC is restored from an outdated backup and its USN counter goes backwards. OpenDirectory detects this and raises an `ad.replication.usn_rollback` event on the event bus (severity: critical). Resolve by demoting and re-promoting the affected DC.

---

## 10. LDAP Schema

The LDAP proxy service (port **8389**) provides a REST gateway to browse and extend the LDAP schema.

### Browse object classes and attribute types

```bash
# List all object classes
curl http://ldap-proxy:8389/api/schema/objectclasses

# Get a specific object class
curl http://ldap-proxy:8389/api/schema/objectclasses/user

# List all attribute types
curl http://ldap-proxy:8389/api/schema/attributetypes
```

### Add a custom attribute

Custom attributes require an OID, a syntax, and a scope (single-value or multi-value).

```bash
curl -X POST http://ldap-proxy:8389/api/schema/attributetypes \
  -H "Content-Type: application/json" \
  -d '{
    "name": "employeeCode",
    "oid": "1.3.6.1.4.1.99999.1.1",
    "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
    "singleValue": true,
    "description": "Internal employee code"
  }'
```

Common LDAP syntaxes:

| Syntax OID | Type |
|------------|------|
| `1.3.6.1.4.1.1466.115.121.1.15` | DirectoryString (UTF-8) |
| `1.3.6.1.4.1.1466.115.121.1.27` | Integer |
| `1.3.6.1.4.1.1466.115.121.1.24` | GeneralizedTime |
| `1.3.6.1.4.1.1466.115.121.1.26` | IA5String |

### Add the custom attribute to an object class

```bash
curl -X PATCH http://ldap-proxy:8389/api/schema/objectclasses/user \
  -H "Content-Type: application/json" \
  -d '{"mayAttributes": ["employeeCode"]}'
```

### Validate entries against schema

```bash
curl -X POST http://ldap-proxy:8389/api/schema/validate \
  -H "Content-Type: application/json" \
  -d '{
    "dn": "CN=Test User,OU=Engineering,DC=corp,DC=example,DC=com",
    "attributes": {"objectClass": ["user"], "employeeCode": "EMP-12345"}
  }'
```
