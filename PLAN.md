# Implementierungsplan: Samba AD DC, GPO Engine, App Store, Compliance & Audit

## Architektur-Kontext

**Bestehendes System:**
- 26 Microservices (Node.js/Express), Docker Compose orchestriert
- Infra: PostgreSQL, MongoDB, Redis, RabbitMQ, lldap
- Frontend: Next.js + Tailwind (UniFi-Style)
- Agents: Windows (PS1), macOS/Linux (Bash) mit WebSocket-Push
- Bestehende GPO-Engine in `enterprise-directory/src/policies/groupPolicyEngine.js` (Cross-Platform-Templates, aber kein echtes AD-Backend)
- Policy-Service auf Port 3004 (In-Memory Maps, kein DB-Backend)

---

## Phase 1: Samba AD DC Integration

### 1.1 Neuer Service: `services/core/samba-ad-dc/`

**Zweck:** Samba 4 als echten Active Directory Domain Controller bereitstellen - Windows-Clients koennen nativ joinen, echte Kerberos-Tickets, DNS-Integration.

**Dateien:**
```
services/core/samba-ad-dc/
  Dockerfile              # samba4 + node.js sidecar
  package.json
  src/
    index.js              # Express API + WebSocket
    samba/
      provisioner.js      # Domain-Provisioning (samba-tool domain provision)
      domainController.js # DC-Management (dcpromo, replication)
      dnsBackend.js       # Samba-internes DNS oder BIND9 DLZ
      kerberosManager.js  # Kerberos KDC Config + Keytab-Management
    ldap/
      sambaLdap.js        # LDAP-Zugriff auf Samba AD (ldapjs gegen samba)
      schemaExtensions.js # Custom Schema-Attribute fuer OpenDirectory
      syncEngine.js       # Sync zwischen lldap ↔ Samba AD (bidirektional)
    gpo/
      sysvolManager.js    # SYSVOL-Share verwalten (smb.conf + Verzeichnis)
      gpoLinker.js        # GPO-Linking an OUs/Sites/Domain
      gpoReplicator.js    # SYSVOL-DFS-R Replikation (Multi-DC)
    api/
      routes.js           # REST API Endpunkte
      domainRoutes.js     # Domain-Join/Leave API
      gpoRoutes.js        # GPO CRUD + Linking
```

**Dockerfile-Strategie:**
```dockerfile
FROM ubuntu:22.04
RUN apt-get install -y samba samba-ad-dc winbind krb5-user nodejs
# Samba als AD DC + Node.js Sidecar-API
```

**API-Endpunkte:**
- `POST /api/samba/domain/provision` - Neue Domain erstellen
- `POST /api/samba/domain/join` - Existierender Domain beitreten (als DC)
- `GET /api/samba/domain/status` - DC-Status, FSMO-Rollen
- `POST /api/samba/computers/join-token` - Join-Token fuer Client generieren
- `GET /api/samba/users` - AD-User auflisten (via samba LDAP)
- `POST /api/samba/users` - AD-User erstellen
- `GET /api/samba/ous` - Organizational Units
- `POST /api/samba/ous` - OU erstellen
- `GET /api/samba/gpo` - GPOs auflisten
- `POST /api/samba/gpo` - GPO erstellen
- `PUT /api/samba/gpo/:id/link` - GPO an OU linken
- `GET /api/samba/gpo/:id/settings` - GPO-Settings lesen
- `PUT /api/samba/gpo/:id/settings` - GPO-Settings schreiben
- `GET /api/samba/dns/records` - DNS-Records aus Samba-DNS
- `GET /api/samba/replication/status` - Replikationsstatus

**Docker-Compose Eintrag:**
```yaml
samba-ad-dc:
  build: ./services/core/samba-ad-dc
  container_name: od-samba-ad-dc
  hostname: dc1
  domainname: opendirectory.local
  environment:
    - SAMBA_REALM=OPENDIRECTORY.LOCAL
    - SAMBA_DOMAIN=OPENDIRECTORY
    - SAMBA_ADMIN_PASSWORD=${SAMBA_ADMIN_PASSWORD}
    - SAMBA_DNS_BACKEND=SAMBA_INTERNAL  # oder BIND9_DLZ
    - NODE_API_PORT=3008
    - IDENTITY_SERVICE_URL=http://identity-service:3001
    - RABBITMQ_URL=amqp://opendirectory:${RABBITMQ_PASSWORD}@rabbitmq:5672
  ports:
    - "3008:3008"   # API
    - "389:389"     # LDAP (ersetzt lldap im AD-Modus)
    - "636:636"     # LDAPS
    - "88:88"       # Kerberos
    - "464:464"     # Kerberos kpasswd
    - "135:135"     # RPC
    - "3268:3268"   # Global Catalog
  volumes:
    - samba-data:/var/lib/samba
    - samba-sysvol:/var/lib/samba/sysvol
    - samba-private:/var/lib/samba/private
  networks:
    - opendirectory
  privileged: true
  cap_add:
    - SYS_ADMIN
    - NET_ADMIN
```

### 1.2 Identity-Sync Engine

**In `services/core/samba-ad-dc/src/ldap/syncEngine.js`:**

- Bidirektionale Synchronisation: lldap (leichtgewichtig) ↔ Samba AD (vollwertig)
- Bei Domain-Provision werden alle lldap-User nach Samba migriert
- Danach: Samba AD ist "Source of Truth", lldap wird read-only Mirror
- Konfigurierbarer Modus: `standalone` (nur lldap) vs. `domain` (Samba AD + lldap Mirror)

### 1.3 Agent-Erweiterung: Domain-Join

**Windows Agent (`clients/windows/OpenDirectoryAgent.ps1`):**
Neuer Command-Handler `domain_join`:
```powershell
function Invoke-DomainJoin {
    param($Data)
    $token = $Data.joinToken
    $domain = $Data.domain  # "OPENDIRECTORY.LOCAL"
    # 1. DNS auf Samba-DC setzen
    # 2. Computer-Account via Token erstellen (REST-Call an samba-ad-dc)
    # 3. Add-Computer -DomainName $domain -Credential $cred
    # 4. Compliance-Report zurueck
}
```

---

## Phase 2: Echte GPO Engine

### 2.1 Erweiterung `services/core/policy-service/src/index.js`

Der bestehende Policy-Service ist zu simpel (In-Memory Maps, keine echte GPO-Logik). Erweiterung zu einer vollwertigen GPO-Engine:

**Neue Dateien:**
```
services/core/policy-service/src/
  index.js                    # Erweitert mit DB-Backend + GPO-Routing
  db/
    postgres.js               # PostgreSQL-Anbindung (Sequelize/Knex)
    migrations/
      001_policies.js          # policies, policy_settings, policy_links Tabellen
      002_gpo_templates.js     # Vordefinierte GPO-Templates
      003_audit_trail.js       # Policy-Aenderungs-Audit
  engines/
    gpoProcessor.js           # Resultant Set of Policy (RSoP) Berechnung
    conflictResolver.js       # Policy-Konflikt nach Prioritaet/Vererbung
    inheritanceEngine.js      # OU-basierte Vererbung (Block/Enforce)
    filterEngine.js           # WMI-Filter-Equivalent + Security Filtering
  compilers/
    windowsCompiler.js        # GPO → Registry.pol + Scripts
    macosCompiler.js          # GPO → .mobileconfig Profile
    linuxCompiler.js          # GPO → systemd/PAM/sysctl Configs
  templates/
    security-baseline.json    # CIS Level 1 Windows
    macos-hardening.json      # CIS macOS
    linux-server.json         # CIS Linux
    password-policy.json      # Passwort-Richtlinien
    firewall-standard.json    # Firewall-Standards
    bitlocker-enforcement.json
    screen-lock.json
  sysvol/
    sysvolSync.js             # SYSVOL-Sync mit Samba AD DC
```

### 2.2 RSoP (Resultant Set of Policy) Engine

**`engines/gpoProcessor.js`:**
```
Verarbeitungsreihenfolge (wie echtes Windows GPO):
1. Local Policy
2. Site-Policies
3. Domain-Policies
4. OU-Policies (verschachtelt, unterste OU gewinnt)

Jede Ebene:
- Enforce-Flag ueberschreibt Blockierung
- Security-Filter (nur bestimmte Gruppen)
- WMI-Filter (nur wenn Bedingung erfuellt)
- Disabled-Flag (Computer/User-Haelfte einzeln deaktivierbar)

Output: Merged Policy-Objekt pro Device/User Kombination
```

**API-Erweiterungen im policy-service:**
- `POST /api/policies/rsop` - RSoP fuer Device/User berechnen
- `GET /api/policies/templates` - Verfuegbare GPO-Templates
- `POST /api/policies/from-template` - Policy aus Template erstellen
- `POST /api/policies/:id/compile/:platform` - Policy fuer Plattform kompilieren
- `GET /api/policies/inheritance/:ouId` - Vererbungskette anzeigen
- `POST /api/policies/:id/link` - Policy an OU/Site/Domain linken
- `POST /api/policies/:id/wmi-filter` - WMI-Filter setzen
- `GET /api/policies/conflicts` - Aktive Policy-Konflikte anzeigen

### 2.3 Policy-Distribution an Agents

**Flow:**
```
Admin erstellt/aendert GPO → policy-service speichert in DB
  → RabbitMQ Event: "policy.updated"
  → device-service empfaengt Event
  → Berechnet RSoP fuer betroffene Devices
  → Pushed kompilierte Policy via WebSocket an jeden Agent
  → Agent wendet Policy an (Registry/Profile/sysctl)
  → Agent meldet Compliance-Status zurueck
```

---

## Phase 3: Web-basierter App Store

### 3.1 Neuer Service: `services/enterprise/app-store/`

**Dateien:**
```
services/enterprise/app-store/
  package.json
  Dockerfile
  src/
    index.js                  # Express + WebSocket Server
    db/
      postgres.js             # DB-Anbindung
      migrations/
        001_apps.js           # apps, app_versions, app_assignments Tabellen
        002_categories.js     # Kategorien + Tags
        003_install_history.js # Installations-Historie pro Device
    catalog/
      catalogManager.js       # App-Katalog CRUD
      versionManager.js       # Versionen + Changelogs
      packageResolver.js      # Plattform-spezifische Pakete aufloesen
    assignment/
      assignmentEngine.js     # Apps an Gruppen/OUs/Devices zuweisen
      requirementChecker.js   # Voraussetzungen pruefen (OS, RAM, Disk)
      licenseManager.js       # Lizenz-Tracking pro App
    distribution/
      distributionEngine.js   # Push-Installation via Agent-WebSocket
      installTracker.js       # Installationsstatus tracken
      updateScheduler.js      # Automatische Updates (Ring-basiert)
    detection/
      clientDetector.js       # Client-Erkennung (User-Agent, Device-ID, Domain)
      platformMapper.js       # Device → Plattform → Package-Typ
      domainResolver.js       # Domain-Membership → verfuegbare Apps
    api/
      routes.js               # Admin-API
      storeRoutes.js          # Client-facing Store API (Self-Service)
```

### 3.2 Client-Erkennung (Domain-basiert)

**`detection/clientDetector.js`:**
```javascript
// Agent verbindet sich mit Device-ID + Domain-Info im WebSocket-Handshake
// Store erkennt:
// 1. device_id → Geraetetyp (Windows/Mac/Linux)
// 2. domain → Zugehoerigkeit (opendirectory.local, sub.opendirectory.local)
// 3. user → Gruppenmitgliedschaften
// 4. OU → Organisatorische Einheit
//
// Daraus: Personalisierter App-Katalog
//   - IT-Abteilung sieht Dev-Tools
//   - Marketing sieht Adobe-Suite
//   - Alle sehen Standard-Apps
//   - Windows-Geraete sehen .msi/.exe, Macs sehen .dmg/brew
```

### 3.3 Store-Frontend (neues View im Web-App)

**`frontend/web-app/src/components/views/AppStoreView.tsx`:**
- App-Grid mit Kategorien (Produktivitaet, Sicherheit, Entwicklung, Kommunikation)
- Suchfunktion mit Filtern
- App-Detailseite: Beschreibung, Screenshots, Versionen, Bewertungen
- "Installieren"-Button → pushed via WebSocket an den Agent
- Admin-Ansicht: Apps hinzufuegen, Zuweisungen verwalten, Lizenzen tracken
- Installations-Status live (Fortschrittsbalken via WebSocket)
- "Pflicht-Apps" vs. "Optionale Apps" Unterscheidung

**`frontend/web-app/src/lib/api.ts`** - Neue API-Funktionen:
```typescript
export const appStoreApi = {
  // Admin
  getCatalog: () => api.get('/api/store/catalog'),
  addApp: (app) => api.post('/api/store/catalog', app),
  updateApp: (id, app) => api.put(`/api/store/catalog/${id}`, app),
  deleteApp: (id) => api.delete(`/api/store/catalog/${id}`),
  assignApp: (appId, targets) => api.post(`/api/store/catalog/${appId}/assign`, targets),

  // Client/Self-Service
  getMyApps: (deviceId) => api.get(`/api/store/my-apps/${deviceId}`),
  getAvailableApps: (deviceId) => api.get(`/api/store/available/${deviceId}`),
  requestInstall: (appId, deviceId) => api.post(`/api/store/install`, { appId, deviceId }),
  getInstallStatus: (installId) => api.get(`/api/store/install/${installId}/status`),

  // Reporting
  getInstallHistory: (filters) => api.get('/api/store/history', { params: filters }),
  getLicenseUsage: () => api.get('/api/store/licenses'),
  getCategories: () => api.get('/api/store/categories'),
};
```

### 3.4 Agent-Erweiterung: App-Installation

**Neuer Command-Handler in allen Agents:**
```
Command: "store_install"
Data: { appId, packageInfo: { type: "winget|msi|brew|dmg|apt|snap", name, version, args } }

Windows: winget install --id $name --version $version --silent
         oder: msiexec /i $url /qn
macOS:   brew install --cask $name
         oder: installer -pkg $path -target /
Linux:   apt install -y $name=$version
         oder: snap install $name
```

**Docker-Compose:**
```yaml
app-store:
  build: ./services/enterprise/app-store
  container_name: od-app-store
  environment:
    PORT: 3906
    DATABASE_URL: postgres://opendirectory:${DB_PASSWORD}@postgres/appstore
    REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
    DEVICE_SERVICE_URL: http://device-service:3003
    IDENTITY_SERVICE_URL: http://identity-service:3001
    SAMBA_AD_URL: http://samba-ad-dc:3008
    RABBITMQ_URL: amqp://opendirectory:${RABBITMQ_PASSWORD}@rabbitmq:5672
  ports:
    - "3906:3906"
  networks:
    - opendirectory
  depends_on:
    - postgres
    - redis
    - device-service
```

---

## Phase 4: Compliance Engine vervollstaendigen

### 4.1 Neuer Service: `services/enterprise/compliance-engine/`

**Konsolidiert verstreute Compliance-Logik in einen zentralen Service:**

**Dateien:**
```
services/enterprise/compliance-engine/
  package.json
  Dockerfile
  src/
    index.js
    db/
      postgres.js
      migrations/
        001_compliance_results.js    # Ergebnisse pro Device/Policy
        002_compliance_baselines.js  # CIS/NIST/STIG Baselines
        003_compliance_waivers.js    # Ausnahmen/Waivers
        004_compliance_history.js    # Historische Trends
    engines/
      complianceEvaluator.js    # Zentraler Evaluator
      baselineManager.js        # CIS/NIST/STIG/BSI Baselines laden + verwalten
      waiverManager.js          # Ausnahmen mit Ablaufdatum + Genehmigung
      scoreCalculator.js        # Compliance-Score (0-100) pro Device/OU/Domain
      trendAnalyzer.js          # Compliance-Trends ueber Zeit
      remediationPlanner.js     # Auto-Remediation Plaene erstellen
    scanners/
      windowsScanner.js         # Windows-spezifische Checks
      macosScanner.js           # macOS-spezifische Checks
      linuxScanner.js           # Linux-spezifische Checks
      networkScanner.js         # Netzwerk-Compliance (Firewall, Ports)
    reports/
      reportGenerator.js        # PDF/CSV/JSON Compliance-Reports
      dashboardAggregator.js    # Dashboard-Daten aggregieren
      regulatoryMapper.js       # Mapping: technische Checks → Regulierung (DSGVO, ISO27001, SOC2)
    api/
      routes.js
```

### 4.2 Compliance-Bewertungs-Flow

```
Agent-Heartbeat (alle 30s)
  → device-service empfaengt Inventar
  → RabbitMQ Event: "device.heartbeat"
  → compliance-engine empfaengt Event
  → Evaluiert Device gegen:
      1. Zugewiesene Policies (aus policy-service)
      2. Aktive Baselines (CIS/NIST/BSI)
      3. Geltende Waivers (Ausnahmen)
  → Berechnet Compliance-Score
  → Speichert Ergebnis in DB (History)
  → Bei Verstoessen:
      a) Alert via monitoring-service
      b) Conditional-Access Update
      c) Optional: Auto-Remediation triggern
  → Dashboard-Update via WebSocket
```

### 4.3 Compliance-Baselines

**Vordefinierte Baselines als JSON:**
```
services/enterprise/compliance-engine/baselines/
  cis-windows-11-l1.json      # CIS Windows 11 Level 1
  cis-windows-11-l2.json      # CIS Windows 11 Level 2
  cis-macos-14-l1.json        # CIS macOS Sonoma Level 1
  cis-ubuntu-22-l1.json       # CIS Ubuntu 22.04 Level 1
  nist-800-171.json           # NIST SP 800-171
  bsi-grundschutz.json        # BSI IT-Grundschutz
  iso-27001-annex-a.json      # ISO 27001 Annex A Controls
  dsgvo-technical.json        # DSGVO technische Massnahmen
```

**Jede Baseline enthaelt:**
```json
{
  "id": "cis-win11-l1",
  "name": "CIS Windows 11 Level 1",
  "version": "1.0.0",
  "platform": "windows",
  "checks": [
    {
      "id": "1.1.1",
      "title": "Ensure 'Enforce password history' is set to '24 or more'",
      "category": "Account Policies/Password Policy",
      "severity": "high",
      "check": {
        "type": "registry",
        "path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
        "key": "PasswordHistorySize",
        "operator": ">=",
        "value": 24
      },
      "remediation": {
        "type": "registry_set",
        "path": "...",
        "key": "PasswordHistorySize",
        "value": 24
      }
    }
  ]
}
```

---

## Phase 5: Agent Compliance-Scanning

### 5.1 Windows Agent Erweiterung

**Neue Funktion in `clients/windows/OpenDirectoryAgent.ps1`:**
```powershell
function Invoke-ComplianceScan {
    param($Data)
    # $Data.baseline = Baseline-Definition vom Server
    # $Data.checks = Array von Checks die ausgefuehrt werden sollen

    $results = @()
    foreach ($check in $Data.checks) {
        switch ($check.type) {
            "registry" {
                $actual = Get-ItemPropertyValue -Path $check.path -Name $check.key
                $pass = Compare-Value $actual $check.operator $check.value
            }
            "service" {
                $svc = Get-Service -Name $check.serviceName
                $pass = ($svc.Status -eq $check.expectedStatus)
            }
            "file_exists" { $pass = Test-Path $check.path }
            "gpo_setting" {
                # gpresult /scope:computer /v → parse
            }
            "firewall" {
                $fw = Get-NetFirewallProfile -Name $check.profile
                $pass = ($fw.Enabled -eq $check.expected)
            }
            "bitlocker" {
                $bl = Get-BitLockerVolume -MountPoint $check.drive
                $pass = ($bl.ProtectionStatus -eq "On")
            }
            "windows_update" {
                $updates = Get-HotFix | Sort-Object InstalledOn -Descending
                $daysSince = ((Get-Date) - $updates[0].InstalledOn).Days
                $pass = ($daysSince -le $check.maxDays)
            }
            "antivirus" {
                $av = Get-MpComputerStatus
                $pass = ($av.RealTimeProtectionEnabled -eq $true)
            }
        }
        $results += @{
            checkId = $check.id
            title = $check.title
            passed = $pass
            actual = $actual
            expected = $check.value
            severity = $check.severity
            timestamp = (Get-Date -Format "o")
        }
    }

    # Ergebnis an Server senden
    Send-WebSocketMessage @{
        type = "compliance_scan_result"
        data = @{
            deviceId = $script:DeviceId
            baselineId = $Data.baselineId
            results = $results
            score = ($results | Where-Object { $_.passed } | Measure-Object).Count / $results.Count * 100
            scannedAt = (Get-Date -Format "o")
        }
    }
}
```

### 5.2 macOS Agent Erweiterung

**Neue Funktion in `clients/macos/OpenDirectoryAgent.sh`:**
```bash
run_compliance_scan() {
    local checks="$1"
    # Checks ausfuehren:
    # - defaults read (Preferences)
    # - csrutil status (SIP)
    # - fdesetup status (FileVault)
    # - systemsetup -getremotelogin (SSH)
    # - spctl --status (Gatekeeper)
    # - pfctl -s info (Firewall)
    # - softwareupdate -l (Updates)
    # - profiles -P (MDM Profiles)
}
```

### 5.3 Linux Agent Erweiterung

**Neue Funktion in `clients/linux/OpenDirectoryAgent.sh`:**
```bash
run_compliance_scan() {
    # Checks:
    # - sysctl -a | grep <key> (Kernel-Parameter)
    # - systemctl is-active <service> (Service-Status)
    # - cat /etc/login.defs (Passwort-Policy)
    # - iptables -L / nft list ruleset (Firewall)
    # - lsblk + cryptsetup status (LUKS)
    # - apt list --upgradable (Updates)
    # - auditctl -l (Audit-Rules)
    # - sestatus / aa-status (SELinux/AppArmor)
}
```

### 5.4 Scheduled Compliance Scans

**compliance-engine orchestriert:**
```
Scan-Schedule (konfigurierbar, Default: alle 4 Stunden):
1. compliance-engine sendet via device-service WebSocket:
   { type: "run_compliance_scan", data: { baselineId, checks: [...] } }
2. Agent fuehrt Scan aus
3. Agent sendet Ergebnis zurueck via WebSocket
4. compliance-engine speichert + aggregiert
5. Bei Compliance-Aenderung: Event via RabbitMQ
```

---

## Phase 6: Audit-System

### 6.1 Neuer Service: `services/enterprise/audit-service/`

**Dateien:**
```
services/enterprise/audit-service/
  package.json
  Dockerfile
  src/
    index.js
    db/
      postgres.js
      migrations/
        001_audit_events.js       # Haupt-Audit-Tabelle (partitioniert nach Monat)
        002_audit_retention.js    # Retention-Policies
        003_audit_search_idx.js   # GIN-Index fuer Volltextsuche
    collectors/
      eventCollector.js       # RabbitMQ Consumer: sammelt Events von allen Services
      agentCollector.js       # Agent-Events (Login, App-Install, Policy-Change)
      adminCollector.js       # Admin-Aktionen (UI + API)
      systemCollector.js      # System-Events (Service Start/Stop, Errors)
    storage/
      eventStore.js           # PostgreSQL-basierter Event-Store
      archiver.js             # Archivierung nach Retention (7 Jahre fuer Compliance)
      integrityChecker.js     # SHA-256 Hash-Chain (Tamper-Detection)
    query/
      searchEngine.js         # Volltextsuche ueber Audit-Events
      filterEngine.js         # Komplexe Filter (Zeitraum, User, Device, Event-Typ)
      correlator.js           # Event-Korrelation (z.B. Login → Policy Change → App Install)
    reports/
      auditReportGenerator.js # Audit-Reports fuer Revisoren
      complianceReporter.js   # Compliance-Audit-Reports (ISO, SOC2)
      exportEngine.js         # Export: PDF, CSV, SIEM-Format (CEF, LEEF)
    siem/
      syslogForwarder.js      # Syslog-Forwarding an externe SIEM
      webhookNotifier.js      # Webhook fuer kritische Events
    api/
      routes.js
```

### 6.2 Event-Taxonomie

```
Audit-Event-Kategorien:
├── identity.*
│   ├── identity.user.created/modified/deleted/locked/unlocked
│   ├── identity.group.created/modified/deleted/member_added/member_removed
│   ├── identity.ou.created/modified/deleted
│   └── identity.auth.login/logout/failed/mfa_setup/mfa_verified/password_changed
├── device.*
│   ├── device.enrolled/unenrolled/wiped/locked/unlocked
│   ├── device.compliance.passed/failed/waiver_granted/waiver_expired
│   ├── device.heartbeat.missed/resumed
│   └── device.inventory.changed
├── policy.*
│   ├── policy.created/modified/deleted/activated/deactivated
│   ├── policy.assigned/unassigned
│   ├── policy.applied.success/failure
│   └── policy.gpo.linked/unlinked/enforced/blocked
├── app.*
│   ├── app.installed/uninstalled/updated/failed
│   ├── app.assigned/unassigned
│   └── app.license.allocated/revoked/expired
├── security.*
│   ├── security.threat.detected/resolved
│   ├── security.scan.started/completed
│   ├── security.encryption.enabled/disabled
│   └── security.firewall.changed
├── admin.*
│   ├── admin.login/logout/action
│   ├── admin.config.changed
│   └── admin.role.assigned/revoked
└── system.*
    ├── system.service.started/stopped/error
    ├── system.backup.created/restored
    └── system.certificate.issued/renewed/revoked/expired
```

### 6.3 Audit-Event-Struktur

```json
{
  "id": "uuid",
  "timestamp": "2026-03-16T10:00:00Z",
  "category": "policy.applied.success",
  "severity": "info",
  "actor": {
    "type": "user|system|agent",
    "id": "user-uuid",
    "name": "admin@opendirectory.local",
    "ip": "192.168.1.100"
  },
  "target": {
    "type": "device|user|policy|app",
    "id": "device-uuid",
    "name": "WORKSTATION-01"
  },
  "action": "Policy 'CIS-Win11-L1' applied successfully",
  "details": { "policyId": "...", "settingsApplied": 42, "settingsFailed": 0 },
  "result": "success",
  "correlationId": "deployment-batch-uuid",
  "hash": "sha256-of-previous-event+this-event",
  "source": "policy-service"
}
```

### 6.4 Frontend: Audit-View

**`frontend/web-app/src/components/views/AuditView.tsx`:**
- Timeline-Ansicht mit Filtern (Zeitraum, Kategorie, Schweregrad, User, Device)
- Live-Stream neuer Events via WebSocket
- Korrelationsansicht: verwandte Events gruppiert
- Export-Buttons: PDF, CSV, SIEM
- Compliance-Audit-Report Generator
- Tamper-Detection Anzeige (Hash-Chain-Integritaet)

**Navigation erweitern in `UnifiLayout.tsx`:**
```typescript
{ id: 'app-store', name: 'App Store', icon: ShoppingBagIcon },
{ id: 'compliance', name: 'Compliance', icon: ClipboardDocumentCheckIcon },
{ id: 'audit', name: 'Audit Log', icon: DocumentMagnifyingGlassIcon },
{ id: 'domain', name: 'Domain (AD)', icon: BuildingOfficeIcon },
```

### 6.5 Docker-Compose Eintraege

```yaml
compliance-engine:
  build: ./services/enterprise/compliance-engine
  container_name: od-compliance-engine
  environment:
    PORT: 3907
    DATABASE_URL: postgres://opendirectory:${DB_PASSWORD}@postgres/compliance
    REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
    RABBITMQ_URL: amqp://opendirectory:${RABBITMQ_PASSWORD}@rabbitmq:5672
    DEVICE_SERVICE_URL: http://device-service:3003
    POLICY_SERVICE_URL: http://policy-service:3004
  ports:
    - "3907:3907"
  networks:
    - opendirectory

audit-service:
  build: ./services/enterprise/audit-service
  container_name: od-audit-service
  environment:
    PORT: 3908
    DATABASE_URL: postgres://opendirectory:${DB_PASSWORD}@postgres/audit
    REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
    RABBITMQ_URL: amqp://opendirectory:${RABBITMQ_PASSWORD}@rabbitmq:5672
  ports:
    - "3908:3908"
  networks:
    - opendirectory
```

---

## Phase 7: Integration & Wiring

### 7.1 RabbitMQ Event-Bus

**Alle neuen Services publizieren und konsumieren Events:**
```
Exchange: "opendirectory.events" (topic)

Routing Keys:
  policy.#     → compliance-engine, audit-service
  device.#     → compliance-engine, audit-service, app-store
  identity.#   → samba-ad-dc sync, audit-service
  app.#        → audit-service, compliance-engine
  security.#   → audit-service, compliance-engine
  compliance.# → audit-service, auto-remediation
  admin.#      → audit-service
```

### 7.2 PostgreSQL Datenbanken erweitern

**In docker-compose.yml, postgres environment:**
```yaml
POSTGRES_MULTIPLE_DATABASES: identity,auth,policy,audit,integration,printers,network,appstore,compliance
```

### 7.3 API-Gateway Routen

**Neue Routen im api-gateway registrieren:**
```
/api/samba/*      → samba-ad-dc:3008
/api/store/*      → app-store:3906
/api/compliance/* → compliance-engine:3907
/api/audit/*      → audit-service:3908
```

---

## Implementierungsreihenfolge

| Schritt | Phase | Aufwand | Abhaengigkeiten |
|---------|-------|---------|-----------------|
| 1 | Policy-Service DB-Backend + RSoP Engine | Mittel | Keine |
| 2 | Audit-Service (Event-Sammlung) | Mittel | RabbitMQ |
| 3 | Compliance-Engine + Baselines | Hoch | Policy-Service |
| 4 | Agent Compliance-Scanning | Mittel | Compliance-Engine |
| 5 | App Store Service | Hoch | Device-Service |
| 6 | App Store Frontend | Mittel | App Store Service |
| 7 | Samba AD DC Service | Hoch | Identity-Service |
| 8 | GPO SYSVOL Sync | Mittel | Samba AD DC + Policy-Service |
| 9 | Frontend Views (Audit, Compliance, Domain, Store) | Mittel | Alle Backend-Services |
| 10 | Agent Domain-Join + Store-Install Commands | Mittel | Samba AD DC + App Store |

**Empfehlung:** Mit Schritt 1-4 beginnen (Policy + Audit + Compliance), da diese die Grundlage fuer alles weitere bilden und sofort Mehrwert liefern, auch ohne Samba AD DC.
