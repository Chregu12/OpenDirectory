# Plan: 5 neue Setup-Wizards für OpenDirectory

## Übersicht

Erstellung von 5 neuen Wizard-Komponenten nach dem bestehenden Pattern (fullscreen modal, step indicator, navigation footer, API-Anbindung mit localStorage-Fallback). Alle Wizards werden in `frontend/web-app/src/components/setup/` angelegt und in die UniFi-Seite (`app/unifi/page.tsx`) integriert.

---

## 1. SecuritySetupWizard.tsx

**Farbe:** Rot-Gradient (red-600 → rose-600)
**5 Schritte:**

| Step | Titel | Inhalt |
|------|-------|--------|
| 1 | Übersicht | Security-Dashboard: aktuelle Bedrohungen, Compliance-Score, offene Alerts anzeigen (`securityApi.getThreatIntel()`, `securityApi.getComplianceStatus()`) |
| 2 | Antivirus (ClamAV) | Aktivieren/Deaktivieren, Scan-Typ wählen (Quick/Full/Custom), Zeitplan erstellen (täglich/wöchentlich), Signatur-Update triggern |
| 3 | DLP-Richtlinien | DLP-Policies anzeigen (`securityApi.getDLPPolicies()`), vordefinierte Templates aktivieren (PII-Schutz, Kreditkarten, Passwörter), E-Mail/Cloud/USB-Überwachung konfigurieren |
| 4 | Compliance | Framework wählen (CIS, NIST, ISO 27001, DSGVO, BSI), Baseline erstellen, automatische Scans aktivieren, Schwellwerte setzen |
| 5 | Zusammenfassung | Gewählte Einstellungen reviewen, "Aktivieren"-Button |

**API-Erweiterungen in `api.ts`:**
```typescript
securityApi erweitern um:
  - scanAntivirus(config) → POST /api/antivirus/scan
  - scheduleAntivirusScan(schedule) → POST /api/antivirus/schedule
  - updateSignatures() → POST /api/antivirus/signatures/update
  - getAntivirusStats() → GET /api/antivirus/statistics
  - createDLPPolicy(policy) → POST /api/security/dlp/policies
  - getComplianceFrameworks() → GET /api/compliance/frameworks
  - createComplianceBaseline(baseline) → POST /api/compliance/baselines
  - evaluateCompliance(deviceId) → POST /api/compliance/evaluate/{deviceId}
```

---

## 2. MonitoringAlertingWizard.tsx

**Farbe:** Cyan-Gradient (cyan-600 → teal-600)
**5 Schritte:**

| Step | Titel | Inhalt |
|------|-------|--------|
| 1 | Übersicht | Aktueller Monitoring-Status anzeigen (`monitoringApi.getSystemStatus()`), Prometheus/Grafana Erreichbarkeit prüfen |
| 2 | Metriken | Metriken auswählen die überwacht werden sollen: CPU, RAM, Disk, Netzwerk, Service-Health, Auth-Events. Toggle-Liste mit Kategorien |
| 3 | Alert-Regeln | Schwellwerte konfigurieren: CPU > X%, Disk > X%, Latenz > Xms, Error-Rate > X%. Vorgefüllte Defaults (90%/80%/5s/5%) |
| 4 | Benachrichtigungen | Kanäle einrichten: E-Mail (SMTP-Config), Slack-Webhook, PagerDuty-Key. Severity-Routing (Critical → PagerDuty, Warning → E-Mail) |
| 5 | Dashboard & Fertig | Grafana-Dashboard automatisch erstellen (`grafanaApi.setupOpenDirectory()`), Zusammenfassung, Embed-URL anzeigen |

**API-Erweiterungen in `api.ts`:**
```typescript
monitoringApi erweitern um:
  - configureAlerts(rules) → POST /api/monitoring/alerts/configure
  - configureNotifications(channels) → POST /api/monitoring/notifications
  - getAlertRules() → GET /api/prometheus/rules

grafanaApi erweitern um:
  - setupOpenDirectory() → POST /api/grafana/setup/opendirectory
```

---

## 3. BackupRecoveryWizard.tsx

**Farbe:** Emerald-Gradient (emerald-600 → green-600)
**5 Schritte:**

| Step | Titel | Inhalt |
|------|-------|--------|
| 1 | Übersicht | Backup-Status anzeigen (`backupApi.getBackupStatus()`), letztes Backup, Speicherverbrauch |
| 2 | Backup-Quellen | Was sichern: Checkboxen für Konfiguration, LDAP-Daten, Policies, Applikationen, Zertifikate. Geschätzte Grösse anzeigen |
| 3 | Zeitplan | Backup-Typ wählen (Full/Inkrementell/Differentiell), Zeitplan konfigurieren (Full: wöchentlich, Inkrementell: alle 6h), Retention-Policy (30/60/90 Tage) |
| 4 | Speicherort | Lokaler Pfad, oder Cloud: AWS S3 / Azure Blob / GCS. Zugangsdaten eingeben, Verschlüsselung aktivieren (AES-256) |
| 5 | Test & Fertig | Zusammenfassung, Test-Backup starten (`backupApi.createBackup()`), Verifizierung, DR-Status anzeigen |

**API-Erweiterungen in `api.ts`:**
```typescript
backupApi erweitern um:
  - configureSchedule(schedule) → POST /api/backup/schedule
  - configureStorage(storage) → POST /api/backup/storage
  - validateBackup(backupId) → POST /api/backup/backups/{id}/validate
  - getRecoveryPoints() → GET /api/backup/recovery-points
```

---

## 4. AppDeploymentWizard.tsx

**Farbe:** Violet-Gradient (violet-600 → purple-600)
**5 Schritte:**

| Step | Titel | Inhalt |
|------|-------|--------|
| 1 | Katalog | App-Katalog anzeigen oder Seed starten (`appStoreApi.seedCatalog()`), Kategorien anzeigen, Suche |
| 2 | Apps auswählen | Apps aus dem Katalog wählen die verteilt werden sollen, Required vs. Optional markieren |
| 3 | Zielgruppen | Zuweisungsziele wählen: Domain, OU, Gruppe, einzelne Geräte. Multi-Select mit Suchfeld |
| 4 | Lizenzen | Lizenzverwaltung: Lizenztyp (Unlimited/Per-Device/Per-User), Anzahl eingeben, Ablaufdatum |
| 5 | Deployment & Fertig | Zusammenfassung der Zuweisungen, "Verteilen"-Button (`appStoreApi.assignApp()`), Status anzeigen |

**API:** Bestehende `appStoreApi` reicht aus, keine Erweiterungen nötig.

---

## 5. PolicyCreationWizard.tsx

**Farbe:** Amber-Gradient (amber-500 → orange-500)
**5 Schritte:**

| Step | Titel | Inhalt |
|------|-------|--------|
| 1 | Template | Policy-Template wählen aus vordefinierten Kategorien: Passwort, Bildschirmsperre, Firewall, Verschlüsselung, Software-Restriction, Netzwerk, Compliance |
| 2 | Konfiguration | Template-spezifische Einstellungen: z.B. Passwort-Länge, Komplexität, Max-Alter, Lockout. Dynamisches Formular je nach Typ |
| 3 | Plattformen | Ziel-Plattformen wählen (Windows/macOS/Linux), plattformspezifische Optionen anzeigen |
| 4 | Zuweisung | Policy zuweisen an: Domain, OU, Sicherheitsgruppe, einzelne Geräte. Priorität/Reihenfolge festlegen |
| 5 | Review & Aktivieren | Zusammenfassung, Policy erstellen (`policyApi`), optional sofort aktivieren, Konflikte anzeigen |

**API-Erweiterungen in `api.ts`:**
```typescript
policyApi hinzufügen:
  - getPolicies(params) → GET /api/policies
  - createPolicy(data) → POST /api/policies
  - getTemplates() → GET /api/policies/templates
  - createFromTemplate(data) → POST /api/policies/from-template
  - assignPolicy(id, targets) → POST /api/policies/{id}/assign
  - activatePolicy(id) → POST /api/policies/{id}/activate
  - getConflicts() → GET /api/policies/conflicts
  - linkPolicy(id, link) → POST /api/policies/{id}/link
```

---

## Integration in die UI

### `app/unifi/page.tsx` — WizardsView erweitern

Die bestehende `WizardsView`-Komponente (3 Karten: Netzwerk, Benutzer, Drucker) wird um 5 neue Karten erweitert:

| Karte | Farbe | Icon | Beschreibung |
|-------|-------|------|-------------|
| Security-Setup | Rot | ShieldExclamationIcon | Antivirus, DLP, Compliance konfigurieren |
| Monitoring & Alerting | Cyan | ChartBarSquareIcon | Metriken, Alerts, Dashboards einrichten |
| Backup & Recovery | Grün | CloudArrowUpIcon | Backup-Plan erstellen, Speicher konfigurieren |
| App-Verteilung | Violet | SquaresPlusIcon | App-Katalog befüllen, Apps zuweisen |
| Policy-Erstellung | Amber | DocumentCheckIcon | Richtlinien erstellen und zuweisen |

State-Variablen hinzufügen:
```typescript
const [showSecurityWizard, setShowSecurityWizard] = useState(false);
const [showMonitoringWizard, setShowMonitoringWizard] = useState(false);
const [showBackupWizard, setShowBackupWizard] = useState(false);
const [showAppDeployWizard, setShowAppDeployWizard] = useState(false);
const [showPolicyWizard, setShowPolicyWizard] = useState(false);
```

### `lib/api.ts` — Neue API-Endpunkte

Alle oben genannten API-Erweiterungen in die bestehenden API-Objekte einfügen + neues `policyApi`-Objekt.

---

## Reihenfolge der Umsetzung

1. **API-Erweiterungen** in `api.ts` (alle auf einmal)
2. **SecuritySetupWizard.tsx** erstellen
3. **MonitoringAlertingWizard.tsx** erstellen
4. **BackupRecoveryWizard.tsx** erstellen
5. **AppDeploymentWizard.tsx** erstellen
6. **PolicyCreationWizard.tsx** erstellen
7. **WizardsView** in `unifi/page.tsx` um alle 5 Karten + State + Modals erweitern
8. **Build-Test** — `npm run build` zur Verifikation

Geschätzter Umfang: ~5 Dateien neu, 2 Dateien geändert.
