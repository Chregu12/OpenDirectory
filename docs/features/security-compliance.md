# Security and Compliance

OpenDirectory provides a layered security stack that combines conditional access policies, zero-trust scoring, compliance baselines, vulnerability assessment, certificate management, and Kerberos security hardening. The primary services are `conditional-access` (port **3007**), `compliance-engine` (port **3907**), `kerberos-kdc` (port **3013**), and `certificate-authority` (port **3015**).

---

## 1. Conditional Access Policies

Conditional access policies evaluate every access attempt and decide whether to allow, challenge, or block it based on a combination of signals.

### Policy signals

| Signal category | Examples |
|----------------|---------|
| **Device health** | Compliance status, OS version, encryption state, managed/unmanaged |
| **User identity** | Role, clearance level, MFA registered, account risk |
| **Location** | IP address, geolocation, named location (office, VPN) |
| **Time** | Business hours, weekends, holidays |
| **Behavioural** | Login frequency, anomaly score, previous violations |

### Create a conditional access policy

```bash
curl -X POST http://conditional-access:3007/api/v1/conditional-access/policies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Require MFA from untrusted networks",
    "conditions": {
      "userGroups": ["All Users"],
      "locations": {"exclude": ["CorpNetwork", "VPN"]},
      "platforms": ["windows", "macos", "linux"]
    },
    "controls": {
      "requireMFA": true,
      "blockIfNonCompliant": false
    },
    "enabled": true
  }'
```

### Evaluate a policy for a session

```bash
curl -X POST http://conditional-access:3007/api/v1/conditional-access/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "alice",
    "deviceId": "LAPTOP-ALICE",
    "ipAddress": "203.0.113.45",
    "timestamp": "2026-06-07T14:30:00Z"
  }'
# Returns: decision (allow/challenge/block), policies evaluated, required controls
```

---

## 2. Zero-Trust Scoring

The authentication service computes a **trust score** between 0.0 (no trust) and 1.0 (full trust) for every session. Conditional access policies and PIM decisions can reference this score.

### Score components

| Component | Weight | Signals |
|-----------|--------|---------|
| **Device health** | 30% | Compliance status, encryption, OS currency, managed flag, EDR status |
| **Identity strength** | 30% | MFA registered, recent password change, no active account risk, clearance level |
| **Network** | 20% | Known IP, corporate network, VPN connection, geolocation consistency |
| **Behavioural history** | 20% | Login frequency, time-of-day patterns, access anomalies, failed auth count |

```bash
curl "http://authentication-service:3001/api/auth/trust-score?userId=alice&deviceId=LAPTOP-ALICE"
# Returns: score, breakdown {device, identity, network, behavioural}, recommendation
```

---

## 3. Compliance Engine

The `compliance-engine` service (port **3907**) evaluates devices against security baselines and tracks trends over time.

### Baseline definitions

OpenDirectory ships with CIS and NIST baseline templates. Custom baselines can be created:

```bash
# List available baselines
curl http://compliance-engine:3907/api/baselines

# Create a custom baseline
curl -X POST http://compliance-engine:3907/api/baselines \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Corp Security Baseline",
    "framework": "custom",
    "rules": [
      {"id": "disk-encrypt", "check": "encryptionEnabled == true", "severity": "critical"},
      {"id": "os-current",   "check": "osVersionCurrent == true",  "severity": "high"},
      {"id": "av-active",    "check": "antivirusStatus == active",  "severity": "high"},
      {"id": "screen-lock",  "check": "screenLockTimeout <= 300",   "severity": "medium"}
    ]
  }'
```

### Evaluate a device against baselines

```bash
curl -X POST http://compliance-engine:3907/api/evaluate/LAPTOP-ALICE
# Returns: score, violations[], compliantRules[], evaluatedAt
```

### Trend analysis (30-day compliance trend)

```bash
curl http://compliance-engine:3907/api/trend/LAPTOP-ALICE
# Returns: daily compliance scores for the last 30 days
```

### Waivers

Waivers grant temporary exemptions for specific violations with an expiry date.

```bash
# Create a waiver
curl -X POST http://compliance-engine:3907/api/waivers \
  -H "Content-Type: application/json" \
  -d '{
    "deviceId": "LAPTOP-ALICE",
    "ruleId": "os-current",
    "reason": "Awaiting application compatibility certification for OS 16",
    "expiresAt": "2026-09-30T00:00:00Z",
    "requestedBy": "alice",
    "approvedBy": "it-manager"
  }'

# List active waivers
curl http://compliance-engine:3907/api/waivers?status=active

# Revoke a waiver
curl -X DELETE http://compliance-engine:3907/api/waivers/<waiverId>
```

### Compliance dashboard

```bash
curl http://compliance-engine:3907/api/dashboard
# Returns: fleet compliance percentage, top violations, devices needing attention, donut chart data
```

---

## 4. Security Scanner

The `security-scanner` service runs vulnerability assessments against devices.

```bash
# Trigger a scan for a device
curl -X POST http://security-scanner/api/scans \
  -H "Content-Type: application/json" \
  -d '{"deviceId": "LAPTOP-ALICE", "scanType": "full"}'

# Get scan results
curl http://security-scanner/api/scans/LAPTOP-ALICE/latest
# Returns: vulnerabilities[], riskScore, scanCompletedAt

# Get vulnerability details
curl http://security-scanner/api/vulnerabilities/LAPTOP-ALICE
```

---

## 5. Antivirus Management

```bash
# Get antivirus status for a device
curl http://conditional-access:3007/api/v1/device-compliance/antivirus/LAPTOP-ALICE
# Returns: status (active/inactive/error), definitionVersion, lastScan, engineVersion

# List devices with outdated definitions
curl "http://conditional-access:3007/api/v1/device-compliance/antivirus?status=definitions_outdated"

# Trigger definition update
curl -X POST http://device-service:3003/api/devices/LAPTOP-ALICE/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "Update-MpSignature", "shell": "powershell"}'
```

---

## 6. Auto-Remediation

The `auto-remediation` service monitors compliance violations and executes automated fix workflows when a violation is detected.

```bash
# Configure an auto-remediation rule
curl -X POST http://auto-remediation/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "trigger": {"ruleId": "screen-lock", "severity": "medium"},
    "action": {
      "type": "push-policy",
      "policyId": "<screenLockPolicyId>"
    },
    "enabled": true,
    "notifyUser": true
  }'

# List active remediation jobs
curl http://auto-remediation/api/jobs?status=running
```

---

## 7. Certificate Authority

The `certificate-authority` service (port **3015**) is a built-in PKI for issuing device, user, and service certificates.

### Issue a certificate

```bash
# Device certificate
curl -X POST http://certificate-authority:3015/api/certificates/issue \
  -H "Content-Type: application/json" \
  -d '{
    "type": "device",
    "subject": "CN=LAPTOP-ALICE,OU=Laptops,DC=corp,DC=example,DC=com",
    "san": ["laptop-alice.corp.example.com"],
    "validityDays": 365,
    "profile": "device-auth"
  }'

# User certificate
curl -X POST http://certificate-authority:3015/api/certificates/issue \
  -H "Content-Type: application/json" \
  -d '{
    "type": "user",
    "subject": "CN=Alice Smith,DC=corp,DC=example,DC=com",
    "san": ["alice@corp.example.com"],
    "validityDays": 365,
    "profile": "user-auth"
  }'

# Service certificate
curl -X POST http://certificate-authority:3015/api/certificates/issue \
  -H "Content-Type: application/json" \
  -d '{
    "type": "service",
    "subject": "CN=api.corp.example.com",
    "san": ["api.corp.example.com", "api-internal.corp.example.com"],
    "validityDays": 90,
    "profile": "tls-server"
  }'
```

### Certificate renewal automation

Certificates nearing expiry (default: 30 days) are flagged and renewal can be triggered:

```bash
# List certificates expiring within 30 days
curl "http://certificate-authority:3015/api/certificates?expiringWithin=30"

# Renew a certificate
curl -X POST http://certificate-authority:3015/api/certificates/<serialNumber>/renew
```

### Revocation (CRL)

```bash
# Revoke a certificate
curl -X POST http://certificate-authority:3015/api/certificates/<serialNumber>/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "keyCompromise"}'

# Download the Certificate Revocation List
curl http://certificate-authority:3015/api/crl/latest.crl
```

---

## 8. Kerberos Security

The `kerberos-kdc` service (port **3013**) manages Kerberos security hardening.

### Protected Users group

The Protected Users security group applies strict restrictions to its members:

| Restriction | Effect |
|-------------|--------|
| No NTLM | NTLM authentication is blocked; Kerberos required |
| No RC4 | RC4 encryption (DES-based weak cipher) is disabled |
| No delegation | No delegation of any type is permitted |
| Max ticket lifetime | Ticket-Granting Ticket (TGT) lifetime is capped at 4 hours |

```bash
# Add a user to Protected Users
curl -X POST http://kerberos-kdc:3013/api/protected-users \
  -H "Content-Type: application/json" \
  -d '{"principal": "alice@corp.example.com"}'

# List members of Protected Users
curl http://kerberos-kdc:3013/api/protected-users

# Check a user's Protected Users status and restrictions
curl -X POST http://kerberos-kdc:3013/api/protected-users/alice@corp.example.com/check

# Remove from Protected Users
curl -X DELETE http://kerberos-kdc:3013/api/protected-users/alice@corp.example.com
```

### Constrained delegation (KCD)

Kerberos Constrained Delegation allows service A to impersonate a user **only** when calling specific back-end services. Uses S4U2Self and S4U2Proxy extensions.

```bash
curl -X POST http://kerberos-kdc:3013/api/delegation/constrained \
  -H "Content-Type: application/json" \
  -d '{
    "servicePrincipal": "http/webapp.corp.example.com",
    "allowedTargets": [
      "cifs/fileserver.corp.example.com",
      "ldap/dc01.corp.example.com"
    ],
    "protocol": "kerberos-only"
  }'
# protocol: "kerberos-only" or "any" (any enables S4U2Self for NTLM→Kerberos transition)

# Get constrained delegation config for a service
curl http://kerberos-kdc:3013/api/delegation/constrained/http%2Fwebapp.corp.example.com

# Remove constrained delegation
curl -X DELETE http://kerberos-kdc:3013/api/delegation/constrained/http%2Fwebapp.corp.example.com
```

### Resource-Based Constrained Delegation (RBCD)

RBCD flips the control model: the **resource** (back-end service) decides which front-end services are allowed to delegate to it, rather than the front-end being configured by a domain admin.

```bash
# Configure RBCD on the resource
curl -X POST http://kerberos-kdc:3013/api/delegation/rbcd \
  -H "Content-Type: application/json" \
  -d '{
    "resourcePrincipal": "cifs/fileserver.corp.example.com",
    "allowedDelegators": [
      "http/webapp.corp.example.com",
      "http/webapp2.corp.example.com"
    ]
  }'

# Get RBCD config for a resource
curl http://kerberos-kdc:3013/api/delegation/rbcd/cifs%2Ffileserver.corp.example.com

# Remove RBCD
curl -X DELETE http://kerberos-kdc:3013/api/delegation/rbcd/cifs%2Ffileserver.corp.example.com
```

### Unconstrained delegation (audit and prevent)

Unconstrained delegation is dangerous — it stores a copy of the user's TGT in the service's memory, enabling full impersonation. OpenDirectory audits all accounts with unconstrained delegation and allows you to enumerate and remediate them.

```bash
# List all principals with unconstrained delegation
curl http://kerberos-kdc:3013/api/delegation/unconstrained
# Returns: list of principals with unconstrained delegation configured — treat each as a finding

# Audit log for delegation events
curl http://kerberos-kdc:3013/api/delegation/audit
```

To remove unconstrained delegation, switch the service to constrained or RBCD delegation, or disable delegation entirely.

---

## 9. Password Security

Password security is enforced by the GPO engine (enterprise-directory) and the authentication service.

### Fine-grained password policies

See [Group Policy — Password Policy](./group-policy.md#8-password-policy) for FGPP configuration. Fine-grained policies apply per security group with a configurable precedence and override the domain default policy.

### Password history enforcement

OpenDirectory stores a hash of the last 1–24 passwords (configurable). Attempts to reuse a password in the history are rejected. The history length is set in the password policy.

### Lockout after N failures

The domain lockout policy (threshold, observation window, duration) applies to all accounts. Fine-grained lockout policies can be applied per group.

```bash
# View current lockout policy
curl http://enterprise-directory:3000/api/domain/lockout-policy

# Check if an account is locked
curl http://authentication-service:3001/api/auth/users/<userId>

# Unlock an account immediately
curl -X POST http://authentication-service:3001/api/auth/users/<userId>/unlock
```
