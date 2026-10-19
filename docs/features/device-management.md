# Device Management (MDM)

OpenDirectory provides unified Mobile Device Management across Windows, macOS, Linux, iOS, and Android through the `device-service` (port **3003**) and `mobile-management` services, supplemented by `remote-control`, `app-store`, `compliance-engine` (port **3907**), and `backup-service`.

---

## 1. Supported Platforms

| Platform | Minimum Version | Enrollment Method |
|----------|----------------|-------------------|
| Windows | 10 (1903+) / 11 | WinRM, domain join, enrollment script |
| macOS | 12 (Monterey) | APNS-based MDM profile |
| Ubuntu / Debian | 20.04 / 11 | SSSD + Kerberos bash script |
| RHEL / CentOS | 8+ | SSSD + Kerberos bash script |
| iOS | 15+ | QR code → OpenDirectory app → MDM profile |
| Android | 10+ | QR code → OpenDirectory app → MDM profile |

---

## 2. Enrollment

### macOS

macOS enrollment uses Apple Push Notification Service (APNS). OpenDirectory acts as an MDM server and pushes a configuration profile.

1. Generate an APNS certificate in **Settings → Certificates → Apple Push**.
2. In the UI, go to **Devices → Enroll → macOS** and follow the 4-step Enrollment Wizard.
3. The wizard generates a `.mobileconfig` profile. The user installs it via **System Settings → Profiles**.
4. Once installed, OpenDirectory can push policies, apps, and remote commands via APNS.

```bash
# Create enrollment profile for macOS
curl -X POST http://device-service:3003/api/devices/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "macos",
    "deviceName": "MacBook-Alice",
    "userId": "alice",
    "ouDn": "OU=Laptops,DC=corp,DC=example,DC=com"
  }'
```

### Windows

```bash
# Generate enrollment script and token
curl -X POST http://device-service:3003/api/devices/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "windows",
    "deviceName": "LAPTOP-ALICE",
    "userId": "alice"
  }'
# Returns: enrollmentToken, scriptUrl
```

Run the returned script on the Windows device:

```powershell
# odm-enroll.ps1
irm https://opendirectory.corp.example.com/enroll/<token> | iex
```

The script installs the OpenDirectory Windows agent, registers the device with WinRM, creates the computer account in AD (if not already joined), and applies the initial GPO set.

### Linux (Ubuntu/Debian/RHEL)

```bash
# Get enrollment script
curl http://device-service:3003/api/devices/enroll \
  -H "Content-Type: application/json" \
  -d '{"platform": "linux", "deviceName": "srv-web-01", "userId": "sysadmin"}'
# Returns: enrollmentToken, scriptUrl
```

Run on the Linux machine:

```bash
curl -fsSL https://opendirectory.corp.example.com/enroll/<token> | sudo bash
# Installs: sssd, realmd, krb5-user, opendirectory-agent
# Joins the Kerberos realm and configures SSSD for AD authentication
```

### iOS and Android

1. Open the OpenDirectory app (available on App Store / Play Store).
2. Tap **Enroll Device** and scan the QR code shown in the Enrollment Wizard.
3. Approve the MDM profile installation prompt.
4. The device appears in the fleet within 30 seconds.

### Zero-touch / Bulk enrollment

For fleet operations, generate a bulk enrollment manifest:

```bash
curl -X POST http://device-service:3003/api/devices/bulk-enroll \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "windows",
    "count": 50,
    "ouDn": "OU=Workstations,OU=Engineering,DC=corp,DC=example,DC=com",
    "assignedUserId": null
  }'
# Returns: tokens[], manifestUrl (for Autopilot/DEP import)
```

---

## 3. Device Inventory

Every enrolled device reports the following attributes:

| Attribute | Description |
|-----------|-------------|
| `platform` | `windows`, `macos`, `linux`, `ios`, `android` |
| `osVersion` | Full OS version string |
| `hardwareModel` | Device model (e.g. `MacBookPro18,3`) |
| `serialNumber` | Hardware serial number |
| `hostname` | DNS hostname |
| `ipAddress` | Primary IP address |
| `macAddress` | Primary NIC MAC address |
| `lastSeen` | Timestamp of last check-in |
| `complianceStatus` | `compliant`, `non_compliant`, `pending`, `unknown` |
| `enrolledAt` | Enrollment timestamp |
| `assignedUserId` | Primary user |

```bash
# List all devices
curl http://device-service:3003/api/devices

# Filter by platform
curl "http://device-service:3003/api/devices?platform=macos"

# Get a single device
curl http://device-service:3003/api/devices/LAPTOP-ALICE

# Update inventory attributes (called by device agent)
curl -X PATCH http://device-service:3003/api/devices/LAPTOP-ALICE/inventory \
  -H "Content-Type: application/json" \
  -d '{"osVersion": "15.4.1", "ipAddress": "10.0.1.45", "lastSeen": "2026-06-07T10:00:00Z"}'
```

---

## 4. Remote Actions

### Lock

```bash
curl -X POST http://device-service:3003/api/devices/LAPTOP-ALICE/lock \
  -H "Content-Type: application/json" \
  -d '{"message": "Device locked by IT. Contact helpdesk."}'
```

### Wipe

```bash
curl -X POST http://device-service:3003/api/devices/LAPTOP-ALICE/wipe \
  -H "Content-Type: application/json" \
  -d '{"reason": "Device reported lost", "authorisedBy": "it-admin"}'
```

### Restart

```bash
curl -X POST http://device-service:3003/api/devices/LAPTOP-ALICE/restart
```

### Remote command execution

Execute arbitrary shell commands on a device. Every execution is logged with the command, output, operator identity, and timestamp.

```bash
curl -X POST http://device-service:3003/api/devices/LAPTOP-ALICE/execute \
  -H "Content-Type: application/json" \
  -d '{
    "command": "Get-Service | Where-Object {$_.Status -eq \"Stopped\"}",
    "shell": "powershell",
    "authorisedBy": "it-admin"
  }'
# Returns: jobId, stdout, stderr, exitCode, executedAt
```

### Push notification

```bash
curl -X POST http://device-service:3003/api/devices/LAPTOP-ALICE/notify \
  -H "Content-Type: application/json" \
  -d '{"title": "Action Required", "body": "Please restart your device."}'
```

---

## 5. Compliance

The `compliance-engine` service (port **3907**) evaluates devices against configurable baseline rules.

### Define compliance rules

```bash
curl -X POST http://compliance-engine:3907/api/baselines \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Corporate Baseline",
    "framework": "CIS",
    "rules": [
      {"id": "os-version", "description": "OS must be current", "check": "osVersion >= 14.0"},
      {"id": "disk-encryption", "description": "Disk encryption required", "check": "encryptionEnabled == true"},
      {"id": "antivirus", "description": "Antivirus active", "check": "antivirusStatus == active"},
      {"id": "screen-lock", "description": "Screen lock timeout <= 5 min", "check": "screenLockTimeout <= 300"}
    ]
  }'
```

### Run a compliance scan

```bash
# On-demand scan for a device
curl -X POST http://compliance-engine:3907/api/evaluate/LAPTOP-ALICE

# Get latest results for a device
curl http://compliance-engine:3907/api/results/LAPTOP-ALICE
```

### View violations

```bash
curl "http://compliance-engine:3907/api/results/LAPTOP-ALICE?status=violation"
```

### Remediate a violation

```bash
curl -X POST http://compliance-engine:3907/api/results/LAPTOP-ALICE/remediate \
  -H "Content-Type: application/json" \
  -d '{"ruleId": "screen-lock", "action": "enforce"}'
```

### Request a waiver

```bash
curl -X POST http://compliance-engine:3907/api/waivers \
  -H "Content-Type: application/json" \
  -d '{
    "deviceId": "LAPTOP-ALICE",
    "ruleId": "os-version",
    "reason": "Pending application compatibility testing",
    "expiresAt": "2026-09-01T00:00:00Z",
    "requestedBy": "alice"
  }'
```

---

## 6. App Management

The `app-store` service provides an enterprise app catalogue and deployment engine.

### Enterprise app store

Browse available apps in the UI under **Apps → Store**, or via API:

```bash
curl http://app-store/api/apps
curl http://app-store/api/apps?platform=windows
```

### Deploy an app to devices or groups

```bash
curl -X POST http://app-store/api/deployments \
  -H "Content-Type: application/json" \
  -d '{
    "appId": "slack-desktop",
    "targetType": "group",
    "targetId": "Engineering",
    "installMode": "required",
    "deadline": "2026-06-14T00:00:00Z"
  }'
```

`installMode`: `required` (forced) or `available` (user can install from self-service portal).

### Track install jobs

```bash
curl http://app-store/api/deployments/<deploymentId>/jobs
# Returns per-device install status: pending, installing, installed, failed
```

---

## 7. Configuration Profiles

Configuration profiles are delivered via the `policy-service` (port **3004**) and pushed to devices via platform-specific mechanisms (MDM for Apple, GPO/WinRM for Windows, SSSD for Linux).

### Wi-Fi profile

```bash
curl -X POST http://policy-service:3004/api/profiles \
  -H "Content-Type: application/json" \
  -d '{
    "type": "wifi",
    "name": "Corporate-WiFi",
    "platforms": ["macos", "ios", "android", "windows"],
    "settings": {
      "ssid": "CorpNet",
      "security": "WPA2-Enterprise",
      "eapType": "PEAP",
      "identity": "user@corp.example.com"
    }
  }'
```

### VPN profile

```bash
curl -X POST http://policy-service:3004/api/profiles \
  -H "Content-Type: application/json" \
  -d '{
    "type": "vpn",
    "name": "Corporate-VPN",
    "platforms": ["macos", "windows", "ios"],
    "settings": {
      "vpnType": "IKEv2",
      "server": "vpn.corp.example.com",
      "authMethod": "certificate",
      "splitTunneling": false
    }
  }'
```

### Email configuration

```bash
curl -X POST http://policy-service:3004/api/profiles \
  -H "Content-Type: application/json" \
  -d '{
    "type": "email",
    "name": "Corporate-Email",
    "platforms": ["ios", "android"],
    "settings": {
      "accountType": "exchange",
      "server": "mail.corp.example.com",
      "domain": "corp.example.com",
      "smimeSigning": true
    }
  }'
```

---

## 8. Certificates

The `certificate-authority` service (port **3015**) issues device, user, and service certificates.

### Issue a device certificate

```bash
curl -X POST http://certificate-authority:3015/api/certificates/issue \
  -H "Content-Type: application/json" \
  -d '{
    "type": "device",
    "subject": "CN=LAPTOP-ALICE,OU=Laptops,DC=corp,DC=example,DC=com",
    "san": ["laptop-alice.corp.example.com"],
    "validityDays": 365,
    "profile": "device-auth"
  }'
# Returns: certificatePem, privateKeyPem, serialNumber, expiresAt
```

### Renew a certificate

```bash
curl -X POST http://certificate-authority:3015/api/certificates/<serialNumber>/renew
```

### Revoke a certificate

```bash
curl -X POST http://certificate-authority:3015/api/certificates/<serialNumber>/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "keyCompromise"}'
```

---

## 9. Backup and Disaster Recovery

The `backup-service` provides per-device and domain-wide backup, with failover managed by `disaster-recovery`.

### Per-device backup

```bash
# Create a backup for a device
curl -X POST http://backup-service/api/backups/device \
  -H "Content-Type: application/json" \
  -d '{"deviceId": "LAPTOP-ALICE", "type": "full"}'

# List backups for a device
curl http://backup-service/api/backups/device/LAPTOP-ALICE

# Restore a device from backup
curl -X POST http://backup-service/api/backups/<backupId>/restore \
  -H "Content-Type: application/json" \
  -d '{"targetDeviceId": "LAPTOP-ALICE-NEW"}'
```

### Domain backup

```bash
# Full domain backup (AD objects, GPOs, DNS, SYSVOL)
curl -X POST http://backup-service/api/backups/domain \
  -H "Content-Type: application/json" \
  -d '{"type": "full", "includeSystemState": true}'
```

### Disaster recovery failover

```bash
# Promote a secondary DC to primary
curl -X POST http://disaster-recovery/api/failover \
  -H "Content-Type: application/json" \
  -d '{
    "targetDC": "dc02.corp.example.com",
    "reason": "Primary DC failure",
    "authorisedBy": "it-director"
  }'
```
