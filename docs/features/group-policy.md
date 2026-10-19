# Group Policy

OpenDirectory includes a Group Policy engine that is conceptually compatible with Windows Group Policy Objects (GPOs). Policies are managed by the `enterprise-directory` service (port **3000**) and compiled into platform-specific deployment artefacts by the integration-service policy compilers.

---

## 1. What is Group Policy in OpenDirectory

Group Policy in OpenDirectory follows the same mental model as Windows GPO:

- Policies are objects (GPOs) that contain Computer Configuration and User Configuration sections.
- GPOs are linked to Organisational Units (OUs). Objects inside the OU inherit the GPO.
- Multiple GPOs can be linked to a single OU; they are applied in a defined precedence order.
- OpenDirectory extends the Windows model to cover macOS, Linux, iOS, and Android by compiling GPO settings into platform-native artefacts (`.mobileconfig` profiles, bash scripts, systemd services).

---

## 2. GPO Structure

### Computer Configuration

Applied when the computer starts up (before user logon).

| Category | Contents |
|----------|----------|
| **SecuritySettings** | Password policy, account lockout, audit policy, firewall rules, user rights |
| **SoftwareInstallation** | MSI/EXE packages assigned to computers |
| **RegistrySettings** | Registry policies and preferences (Administrative Templates) |
| **Scripts** | Startup and shutdown scripts (PowerShell, batch, shell) |
| **NetworkDrives** | Drive mappings via Computer Preferences |
| **PowerManagement** | Power plans, sleep/hibernate timeouts |

### User Configuration

Applied when a user logs on.

| Category | Contents |
|----------|----------|
| **FolderRedirection** | Redirect Documents, Desktop, Pictures, AppData to network share |
| **Logon Scripts** | Scripts executed at user logon/logoff |
| **SoftwareInstallation** | Published packages available to users |
| **Preferences** | Drive mappings, printers, shortcuts, environment variables, desktop settings |

---

## 3. Creating a GPO

### Via API

```bash
curl -X POST http://enterprise-directory:3000/api/gpo \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering Baseline",
    "description": "Security and software baseline for Engineering OU",
    "createdBy": "it-admin",
    "computerConfiguration": {
      "windowsSettings": {
        "securitySettings": {
          "passwordPolicy": {
            "minimumLength": 12,
            "complexity": true,
            "maxAge": 90,
            "minAge": 1,
            "history": 24
          },
          "accountLockout": {
            "threshold": 5,
            "duration": 30,
            "resetAfter": 30
          }
        }
      }
    },
    "scope": {
      "links": {
        "organizationalUnits": ["OU=Engineering,DC=corp,DC=example,DC=com"]
      },
      "securityFiltering": {
        "applyTo": {"groups": ["Domain Users"]}
      }
    }
  }'
# Returns: policyId, name, deployments (platform-specific artefacts)
```

### Via UI

1. Navigate to **Group Policy → New GPO**.
2. Enter a name and description.
3. Configure Computer and User settings using the tabbed editor.
4. Under **Scope**, link the GPO to one or more OUs.
5. Set Security Filtering to control which users and computers receive the policy.
6. Click **Save**. The engine generates deployment artefacts immediately.

---

## 4. Linking a GPO to an OU

A GPO is linked by including the OU DN in `scope.links.organizationalUnits` at creation time, or by updating the GPO:

```bash
curl -X PATCH http://enterprise-directory:3000/api/gpo/<policyId>/links \
  -H "Content-Type: application/json" \
  -d '{
    "add": ["OU=Finance,DC=corp,DC=example,DC=com"],
    "remove": []
  }'
```

A GPO can be linked to multiple OUs simultaneously.

---

## 5. Inheritance and Precedence

OpenDirectory follows the standard LGPO processing order:

```
Local GPO → Site GPOs → Domain GPO → Parent OU GPO → Child OU GPO
```

Later entries override earlier entries (child OU wins over parent OU). Within a single OU, GPOs are applied in link order; lower link order = higher precedence.

### Enforced GPOs

An **Enforced** GPO cannot be overridden by GPOs at lower levels and is immune to Block Inheritance. Set `scope.options.enforced: true` when creating or updating the GPO.

```bash
curl -X PATCH http://enterprise-directory:3000/api/gpo/<policyId> \
  -H "Content-Type: application/json" \
  -d '{"scope": {"options": {"enforced": true}}}'
```

### Block Inheritance per OU

Block Inheritance prevents non-Enforced GPOs from higher levels from flowing into an OU:

```bash
curl -X PATCH http://enterprise-directory:3000/api/gpo/<policyId> \
  -H "Content-Type: application/json" \
  -d '{"scope": {"options": {"inheritanceBlocked": true}}}'
```

---

## 6. Applying a GPO

### Trigger application via API

```bash
curl -X POST http://enterprise-directory:3000/api/gpo/<policyId>/apply \
  -H "Content-Type: application/json" \
  -d '{"ouDn": "OU=Engineering,DC=corp,DC=example,DC=com", "dryRun": false}'
```

**What happens during application:**

1. The engine resolves the OU hierarchy, respecting Block Inheritance and Enforced flags.
2. For each target OU, it iterates the **Computer Configuration** processing order:
   `SecuritySettings → SoftwareInstallation → RegistrySettings → NetworkDrives → PowerManagement → Scripts`
3. It then iterates the **User Configuration** processing order:
   `FolderRedirection → NetworkDrives → DesktopSettings → SoftwareInstallation → PrinterDeployment → Scripts`
4. Each applied setting is recorded in the `gpo_application_log` MongoDB collection.
5. Platform-specific artefacts (PowerShell scripts, `.mobileconfig` profiles, bash scripts) are pushed to device agents.

### Check application status

```bash
curl http://enterprise-directory:3000/api/gpo/<policyId>/status
# Returns: applications[], lastApplied, successCount, failureCount, policyInfo
```

---

## 7. Resultant Set of Policy (RSoP)

RSoP is the **effective merged policy** that applies to a specific user or computer after all GPO inheritance and precedence rules have been evaluated. It answers the question: "What settings will actually be enforced on this user/computer?"

### How RSoP is calculated

1. All enabled GPOs are collected.
2. Non-enforced GPOs are processed first (Local → Domain → Parent OU → Child OU).
3. Enforced GPOs are processed last (they always win).
4. Block Inheritance is respected for non-enforced policies.
5. Settings are deep-merged; later entries override earlier ones.
6. The final merged Computer and User configuration is the RSoP.

### Query RSoP for an OU

```bash
curl "http://enterprise-directory:3000/api/ou/OU%3DEngineering%2CDC%3Dcorp%2CDC%3Dexample%2CDC%3Dcom/rsop"
# Returns: computerConfig, userConfig, appliedGPOs[]
```

### Query RSoP for a user

```bash
curl "http://enterprise-directory:3000/api/users/<userId>/rsop"
# Returns: computerConfig, userConfig, appliedGPOs[]
```

### Reading RSoP output

```json
{
  "computerConfig": {
    "windowsSettings": {
      "securitySettings": {
        "passwordPolicy": {
          "minimumLength": 12,
          "complexity": true,
          "maxAge": 90
        }
      }
    }
  },
  "userConfig": {
    "preferences": {
      "driveMappings": [{"letter": "H:", "path": "\\\\fileserver\\users\\%USERNAME%"}]
    }
  },
  "appliedGPOs": ["<policyId-1>", "<policyId-2>"]
}
```

The `appliedGPOs` array lists GPOs in the order they were merged. Settings from GPOs later in the list take precedence.

---

## 8. Password Policy

### Domain-wide password policy

The domain password policy applies to all users who are not covered by a Fine-Grained Password Policy (FGPP).

```bash
curl -X POST http://enterprise-directory:3000/api/domain/password-policy \
  -H "Content-Type: application/json" \
  -d '{
    "minLength": 12,
    "complexity": true,
    "maxAge": 90,
    "minAge": 1,
    "historyCount": 24
  }'
```

| Setting | Description |
|---------|-------------|
| `minLength` | Minimum password length (1-128) |
| `complexity` | Require uppercase, lowercase, digit, symbol |
| `maxAge` | Days until password expires (0 = never) |
| `minAge` | Minimum days before password can be changed |
| `historyCount` | Number of previous passwords remembered (0-24) |

### Fine-grained password policies (FGPP)

FGPPs override the domain policy for specific groups and have a **precedence** value (lower = higher priority).

```bash
curl -X POST http://enterprise-directory:3000/api/domain/fgpp \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Admins-PasswordPolicy",
    "targetGroup": "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com",
    "precedence": 1,
    "minLength": 16,
    "complexity": true,
    "maxAge": 60,
    "minAge": 1,
    "historyCount": 24
  }'
```

---

## 9. Account Lockout Policy

```bash
curl -X POST http://enterprise-directory:3000/api/domain/lockout-policy \
  -H "Content-Type: application/json" \
  -d '{
    "threshold": 5,
    "observationWindow": 30,
    "lockoutDuration": 30
  }'
```

| Setting | Description |
|---------|-------------|
| `threshold` | Failed attempts before lockout (0 = disabled) |
| `observationWindow` | Window (minutes) in which failures are counted |
| `lockoutDuration` | Lock duration (minutes; 0 = requires manual unlock) |

After `threshold` failed logon attempts within `observationWindow` minutes, the account is locked for `lockoutDuration` minutes. An administrator can unlock the account immediately via the UI or API:

```bash
curl -X POST http://authentication-service:3001/api/auth/users/<userId>/unlock
```
