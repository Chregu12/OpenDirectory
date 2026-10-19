# Audit Logging

OpenDirectory maintains a comprehensive, tamper-evident audit trail of all significant actions across every service. The primary audit store is the `audit-service` (port **3908**), which receives events from all services via the RabbitMQ event bus and exposes a query API. The `enterprise-directory` service (port **3000**) also provides a directory-specific audit log.

---

## 1. What is Logged

### Active Directory changes

| Event | Details logged |
|-------|---------------|
| Object created | Object DN, object class, initial attributes, actor |
| Object modified | Changed attributes (old + new values), actor |
| Object deleted | Object DN, object class, actor |
| Object moved | Old DN, new DN, actor |
| Object renamed | Old CN, new CN, actor |
| Group membership changed | Group DN, member DN, add/remove, actor |

### Group Policy events

| Event | Details logged |
|-------|---------------|
| GPO created | GPO ID, name, settings summary, actor |
| GPO modified | Changed settings, actor |
| GPO deleted | GPO ID, name, actor |
| GPO applied | GPO ID, target OU DN, applied settings, success/failure |
| RSoP computed | Target DN, applied GPO list |

### Authentication events

| Event | Severity | Details logged |
|-------|----------|---------------|
| Successful login | info | User ID, IP address, device ID, session ID |
| Failed login | warning | User ID, IP address, failure reason |
| Logout | info | User ID, session ID |
| Account locked | warning | User ID, IP address, failure count |
| Account unlocked | info | User ID, unlocked-by |
| MFA setup | info | User ID |
| MFA verification failed | warning | User ID, IP address |
| Password changed | info | User ID |
| Password reset | info | User ID, reset-by |

### PIM events

| Event | Severity | Details logged |
|-------|----------|---------------|
| Elevation requested | info | Request ID, requester, role ID, justification, risk score |
| Elevation approved | info | Request ID, elevation ID, approver, role ID, duration |
| Elevation denied | warning | Request ID, denier, role ID, reason |
| Elevation expired | info | Request ID, role ID, requester |
| Elevation revoked | warning | Elevation ID, revoked-by, reason |
| Session activity | info | Elevation ID, activity type, risk score, success |
| Break-glass requested | warning | Event ID, requester, reason, systems affected |
| Break-glass activated | **critical** | Event ID, activating manager, requester |
| Break-glass terminated | warning | Event ID, terminated-by, outcome |

### Key retrieval events

| Event | Severity |
|-------|----------|
| LAPS password retrieved | warning |
| BitLocker key retrieved | warning |

### Trust changes

| Event | Severity |
|-------|----------|
| Trust created | info |
| Trust verified | info |
| Trust removed | warning |
| Trust password rotated | info |

### Kerberos delegation events

| Event | Severity |
|-------|----------|
| Constrained delegation configured | info |
| RBCD configured | info |
| Unconstrained delegation detected | **critical** |
| Delegation audit record | info |
| S4U2Self simulation | info |
| S4U2Proxy simulation | info |

---

## 2. Audit Log Schema

Every audit event has the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `event_time` | ISO 8601 timestamp | When the event occurred |
| `actor_id` | string | ID of the user or service principal that performed the action |
| `actor_dn` | string | Distinguished Name of the actor (if an AD object) |
| `target_dn` | string | Distinguished Name of the affected object |
| `target_type` | string | Object class or resource type (e.g. `user`, `group`, `gpo`, `device`) |
| `operation` | string | Action performed (e.g. `create`, `modify`, `delete`, `login`, `elevation.approved`) |
| `attributes_changed` | object | Key-value pairs of `{attribute: {old, new}}` for modification events |
| `severity` | string | `info`, `warning`, `error`, `critical` |
| `routing_key` | string | Event bus routing key (e.g. `directory.object.modify`) |
| `correlation_id` | string | Ties related events across services |
| `service` | string | Originating service name |
| `ip_address` | string | Source IP address (for authentication/access events) |
| `session_id` | string | Session identifier |

---

## 3. Querying the Audit Log

### Via UI

The **Audit Log** view (accessible from the sidebar) provides a filterable, paginated list with severity colour coding. Filters available:

- Date range (from / to)
- Actor (user ID or service)
- Target DN (exact or prefix match)
- Operation type
- Severity level

### Via API

```bash
# List events with optional filters
curl "http://audit-service:3908/api/audit/events?from=2026-06-01&to=2026-06-07&severity=critical"

# Filter by actor
curl "http://audit-service:3908/api/audit/events?actorId=alice"

# Filter by target DN (URL-encoded)
curl "http://audit-service:3908/api/audit/events?targetDn=CN%3DJohn%20Smith%2COU%3DEngineering%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom"

# Filter by operation type
curl "http://audit-service:3908/api/audit/events?operation=elevation.approved"

# Full-text search
curl -X POST http://audit-service:3908/api/audit/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "domain-admin",
    "from": "2026-06-01T00:00:00Z",
    "to": "2026-06-07T23:59:59Z",
    "severity": ["warning", "critical"],
    "limit": 100,
    "offset": 0
  }'

# Get a single event
curl http://audit-service:3908/api/audit/events/<eventId>

# Events with the same correlation ID (related events across services)
curl http://audit-service:3908/api/audit/events/correlation/<correlationId>

# Timeline for a specific object (all changes over time)
curl http://audit-service:3908/api/audit/timeline/user/<userId>
curl http://audit-service:3908/api/audit/timeline/device/LAPTOP-ALICE

# Audit statistics
curl http://audit-service:3908/api/audit/stats
# Returns: event counts by severity, top actors, top operations, events per day
```

### Enterprise-directory audit log

The enterprise-directory service also exposes a directory-focused audit API:

```bash
# Paginated audit log
curl "http://enterprise-directory:3000/api/audit/log?limit=50&offset=0"

# Full history of changes to a specific DN
curl "http://enterprise-directory:3000/api/audit/objects/CN%3DJohn%20Smith%2COU%3DEngineering%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom/history"

# All activity by a specific actor
curl "http://enterprise-directory:3000/api/audit/actors/<actorId>/activity"
```

---

## 4. Severity Levels

| Level | Colour | When used |
|-------|--------|-----------|
| `info` | Grey | Normal operations (login, object create, policy apply) |
| `warning` | Amber | Potentially significant events (failed login, lockout, elevation denied, key retrieval) |
| `error` | Red | Failures with operational impact (replication failure, service error) |
| `critical` | Red (bold) | Security-significant events requiring immediate attention (break-glass activated, unconstrained delegation detected, USN rollback) |

---

## 5. Retention

OpenDirectory does not enforce a maximum retention period. Recommended policies by industry:

| Regulation | Recommended retention |
|------------|----------------------|
| General corporate | 1 year |
| ISO 27001 | 1 year minimum |
| PCI-DSS | 1 year (3 months immediately accessible) |
| SOC 2 | 1 year |
| GDPR (EU) | Delete personal data after retention period; anonymise event records |
| HIPAA (US) | 6 years |

### Configure retention

```bash
# Get current retention policy
curl http://audit-service:3908/api/audit/retention

# Set retention period
curl -X POST http://audit-service:3908/api/audit/retention \
  -H "Content-Type: application/json" \
  -d '{
    "retentionDays": 365,
    "archiveAfterDays": 90,
    "deleteAfterDays": 365
  }'
```

### Integrity verification

The audit service maintains an integrity hash chain. Verify that audit records have not been tampered with:

```bash
curl http://audit-service:3908/api/audit/integrity
# Returns: chainValid: true/false, lastVerifiedAt, recordCount
```

---

## 6. Export

> **Roadmap** — bulk export (CSV, JSON) is planned but not yet implemented. The API currently supports paginated reads and PDF/CSV compliance reports.

### Compliance reports (currently available)

```bash
# Generate a PDF audit report
curl -X POST http://audit-service:3908/api/audit/reports/pdf \
  -H "Content-Type: application/json" \
  -d '{"from": "2026-05-01", "to": "2026-05-31", "severity": ["warning", "critical"]}'

# Generate a CSV audit report
curl -X POST http://audit-service:3908/api/audit/reports/csv \
  -H "Content-Type: application/json" \
  -d '{"from": "2026-05-01", "to": "2026-05-31"}'

# Framework-specific compliance report (e.g. SOC2, PCI-DSS)
curl -X POST http://audit-service:3908/api/audit/reports/compliance/soc2 \
  -H "Content-Type: application/json" \
  -d '{"from": "2026-01-01", "to": "2026-06-07"}'
```

---

## 7. Event Bus

All audit events are published to the RabbitMQ event bus **in addition to** being stored in the audit database. This allows downstream systems (SIEM, alerting, compliance tools) to consume events in real time.

### Key routing keys

| Routing key | Source | Events |
|-------------|--------|--------|
| `directory.object.create` | enterprise-directory | AD object created |
| `directory.object.modify` | enterprise-directory | AD object modified |
| `directory.object.delete` | enterprise-directory | AD object deleted |
| `directory.group.member.add` | enterprise-directory | Member added to group |
| `directory.group.member.remove` | enterprise-directory | Member removed from group |
| `identity.login.success` | authentication-service | Successful login |
| `identity.login.failed` | authentication-service | Failed login |
| `identity.account.locked` | authentication-service | Account locked |
| `security.elevation.requested` | conditional-access | PIM elevation requested |
| `security.elevation.approved` | conditional-access | PIM elevation approved |
| `security.elevation.denied` | conditional-access | PIM elevation denied |
| `security.elevation.revoked` | conditional-access | PIM elevation revoked |
| `security.breakglass.activated` | conditional-access | Break-glass activated |
| `security.breakglass.terminated` | conditional-access | Break-glass ended |
| `ad.trust.create` | samba-ad-dc | Trust created |
| `ad.trust.remove` | samba-ad-dc | Trust removed |
| `ad.replication.usn_rollback` | samba-ad-dc | USN rollback detected |
| `kerberos.delegation.unconstrained` | kerberos-kdc | Unconstrained delegation detected |

### SIEM integration

Configure a SIEM connection to receive all events:

```bash
curl -X POST http://audit-service:3908/api/audit/siem/test \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "https://siem.corp.example.com/api/events",
    "format": "cef",
    "apiKey": "<siemApiKey>"
  }'
```

### Alerts

```bash
# Create an alert rule
curl -X POST http://audit-service:3908/api/audit/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Break-glass activated",
    "condition": {"severity": "critical", "operation": "breakglass.activated"},
    "channels": ["email", "slack"],
    "recipients": ["security-team@corp.example.com"]
  }'

# List active alerts
curl http://audit-service:3908/api/audit/alerts

# Update an alert
curl -X PUT http://audit-service:3908/api/audit/alerts/<alertId> \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```
