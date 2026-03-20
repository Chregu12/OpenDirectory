# OpenDirectory vs. Microsoft Intune / Active Directory / Entra ID

Vollständige Vergleichsanalyse — Stand: März 2026

---

## Executive Summary

OpenDirectory deckt **~80% der Funktionalität** von Microsoft Intune + Active Directory + Entra ID ab. Für Self-Hosted-Umgebungen mit Datensouveränitäts-Anforderungen und gemischten OS-Flotten ist es eine **ernsthafte Alternative**. Für Microsoft-365-zentrierte Umgebungen fehlt die SaaS-Federation (OAuth/SAML).

---

## 1. Feature-Matrix: Detailvergleich

### Identitäts- & Zugriffsverwaltung

| Feature | Intune/Entra ID | OpenDirectory | Status |
|---------|----------------|---------------|--------|
| Benutzerverzeichnis (LDAP) | Active Directory / Entra ID | LLDAP (leichtgewichtig) | ✅ Vollständig |
| Gruppen & OUs | AD-Gruppen, Dynamic Groups | LDAP-Gruppen, Policy-basiert | ✅ Vollständig |
| Single Sign-On (SSO) | SAML 2.0, OAuth 2.0, OIDC | JWT-basiert | ⚠️ Nur intern |
| Multi-Faktor (MFA) | Microsoft Authenticator, FIDO2 | TOTP, SMS | ⚠️ Basis |
| Conditional Access | Risk-based, Device Compliance | Risk-Scoring, Policy-basiert | ✅ Vollständig |
| Passwordless (FIDO2/Hello) | Ja (Windows Hello for Business) | Nein | ❌ Fehlt |
| External Identity Federation | Azure B2B/B2C | Nein | ❌ Fehlt |
| Privileged Identity (PIM) | Azure AD PIM | Nein | ❌ Fehlt |
| Self-Service Password Reset | Ja | Nein | ❌ Fehlt |

### Geräteverwaltung

| Feature | Intune | OpenDirectory | Status |
|---------|--------|---------------|--------|
| Windows Enrollment | Autopilot, Bulk, Manual | Agent-basiert, API | ✅ Vollständig |
| macOS Enrollment | DEP, Manual | Agent-basiert, API | ✅ Vollständig |
| Linux Enrollment | Eingeschränkt (nur Edge/Teams) | Agent-basiert, API | ✅ **Besser** |
| iOS/Android MDM | Ja (vollständig) | NanoMDM (Apple), teilweise | ⚠️ Basis |
| Hardware-Inventar | Ja | Ja (CPU, RAM, Disk, Netzwerk) | ✅ Vollständig |
| Software-Inventar | Ja | Ja (installierte Pakete) | ✅ Vollständig |
| Geräte-Compliance | Ja (Compliance Policies) | Ja (CIS/NIST/BSI Baselines) | ✅ **Besser** |
| Remote Lock/Wipe | Ja | Ja (Lock, Wipe, Lost Mode) | ✅ Vollständig |
| Remote Restart | Ja | Ja (mit Grace Period) | ✅ Vollständig |
| Remote Shell | Nein (nur Remediation Scripts) | Ja (SSH/PowerShell/Bash) | ✅ **Besser** |
| BitLocker/FileVault Key Escrow | Ja | Ja (mit Rotation) | ✅ Vollständig |
| Geräte-Kategorien & Tags | Ja | Ja (Labels, Gruppen) | ✅ Vollständig |

### Konfigurationsmanagement

| Feature | Intune/GPO | OpenDirectory | Status |
|---------|-----------|---------------|--------|
| Group Policy (GPO) | Vollständig (ADMX) | JSON-basiert, kein ADMX-Import | ⚠️ Anders |
| Configuration Profiles | Ja (>300 Settings) | Ja (Policy-Engine) | ✅ Vollständig |
| Security Baselines | CIS, DISA STIG | CIS, NIST, BSI, ISO 27001, DSGVO, HIPAA | ✅ **Besser** |
| Policy Simulator | Nein | Ja (What-If Analyse) | ✅ **Besser** |
| Policy Conflicts | Basic Conflict Resolution | Graph-basierte Visualisierung | ✅ **Besser** |
| RSoP (Resultant Set of Policy) | Ja (gpresult) | Engine vorhanden, kein Frontend | ⚠️ Teilweise |
| Loopback Processing | Ja | Nein | ❌ Fehlt |

### Software-Verteilung

| Feature | Intune | OpenDirectory | Status |
|---------|--------|---------------|--------|
| Win32-Apps (.intunewin) | Ja | Nein (eigenes Format) | ⚠️ Anders |
| Winget | Ja (seit 2024) | Ja (Winget Auto-Update) | ✅ Vollständig |
| Microsoft Store | Ja | Via Winget | ✅ Vollständig |
| Homebrew (macOS) | Nein | Ja | ✅ **Besser** |
| APT/DNF/Zypper (Linux) | Nein | Ja | ✅ **Besser** |
| Snap/Flatpak | Nein | Ja | ✅ **Besser** |
| App Store (Self-Service) | Company Portal | Eigener App Store | ✅ Vollständig |
| Auto-Update Policies | Ja | Ja (Whitelist/Blacklist, Zeitpläne) | ✅ Vollständig |
| Dependency Management | Basic | Basic | ✅ Gleichwertig |

### Update-Management

| Feature | Intune/WSUS | OpenDirectory | Status |
|---------|------------|---------------|--------|
| Windows Update for Business | Ja | Ja (Deferral, Ringe) | ✅ Vollständig |
| Feature Update Deferral | Ja | Ja (0-365 Tage) | ✅ Vollständig |
| Quality Update Deferral | Ja | Ja (0-30 Tage) | ✅ Vollständig |
| Maintenance Windows | Ja | Ja (Tag + Zeitfenster) | ✅ Vollständig |
| macOS Updates | Ja (DDM) | Ja (softwareupdate + Homebrew) | ✅ Vollständig |
| Linux Updates | Nein | Ja (APT/DNF/Zypper/Snap) | ✅ **Besser** |
| Update Compliance | Ja | Ja (pro Gerät + Dashboard) | ✅ Vollständig |
| Driver Updates | Ja (seit 2023) | Nein | ❌ Fehlt |

### Netzwerk & Infrastruktur

| Feature | Microsoft | OpenDirectory | Status |
|---------|----------|---------------|--------|
| DNS-Server | Windows DNS | Eigener DNS (Port 53) | ✅ Vollständig |
| DHCP-Server | Windows DHCP | Eigener DHCP (Port 67/68) | ✅ Vollständig |
| File Shares (SMB) | Windows File Server | Samba (SMB + NFS) | ✅ Vollständig |
| VPN-Profile | Ja (Always On VPN) | Ja (OpenVPN, WireGuard) | ✅ Vollständig |
| WiFi-Profile | Ja (802.1X, WPA) | Ja (mit Zertifikaten) | ✅ Vollständig |
| Network Discovery | Nein | Ja (automatisch) | ✅ **Besser** |
| Netzwerk-Topologie | Nein | Ja (Visualisierung) | ✅ **Besser** |

### Drucker-Management

| Feature | Intune/GPO | OpenDirectory | Status |
|---------|-----------|---------------|--------|
| Drucker-Deployment | Ja (GPO/Universal Print) | Ja (CUPS + Auto-Discovery) | ✅ Vollständig |
| Universal Print (Cloud) | Ja | Nein (lokal via CUPS) | ⚠️ Anders |
| Drucker-Quotas | Nein (nativ) | Ja | ✅ **Besser** |
| Scanner-Integration | Nein | Ja | ✅ **Besser** |
| Print-Job-Tracking | Nein (nativ) | Ja | ✅ **Besser** |

### Sicherheit & Compliance

| Feature | Microsoft | OpenDirectory | Status |
|---------|----------|---------------|--------|
| Compliance Policies | Intune Compliance | CIS/NIST/BSI/ISO/DSGVO | ✅ **Breiter** |
| Security Scanner | Defender for Endpoint | Eigener Scanner (STIG/CIS) | ✅ Vollständig |
| Antivirus-Management | Defender AV | EDR-Integration (ClamAV etc.) | ⚠️ Basis |
| Attack Path Analysis | Nein (nur mit Defender XDR) | Graph Explorer mit Visualisierung | ✅ **Besser** |
| Auto-Remediation | Limited | Vollständig mit Approval-Workflow | ✅ **Besser** |
| Audit-Logging | Ja (Unified Audit Log) | Ja (Hash-Chain, manipulationssicher) | ✅ Vollständig |
| Zertifikats-Management | SCEP, PKCS | Step-CA, SCEP, eigene PKI | ✅ Vollständig |
| Application Control | AppLocker, WDAC | Nein | ❌ Fehlt |

### Monitoring & Reporting

| Feature | Microsoft | OpenDirectory | Status |
|---------|----------|---------------|--------|
| Geräte-Dashboard | Intune Portal | Web-Dashboard (13 Views) | ✅ Vollständig |
| Compliance Reports | Ja | Ja (pro Gerät + aggregiert) | ✅ Vollständig |
| Custom Reports | Power BI Integration | Grafana + Prometheus | ✅ Vollständig |
| Alerting | Email + Teams | AlertManager + Webhooks | ✅ Vollständig |
| Log Analytics | Azure Log Analytics | Prometheus + Structured Logs | ✅ Vollständig |
| Real-Time Monitoring | Nein (15 Min Delay) | Ja (WebSocket, Echtzeit) | ✅ **Besser** |

### Automatisierung & IaC

| Feature | Microsoft | OpenDirectory | Status |
|---------|----------|---------------|--------|
| Terraform Provider | AzureRM, AzureAD | Eigener Provider (8 Ressourcen) | ✅ Vollständig |
| Ansible Collection | Community | Eigene Collection | ✅ Vollständig |
| REST-API | Microsoft Graph API | Eigene REST-API | ✅ Vollständig |
| PowerShell Module | Az, Microsoft.Graph | Nein | ⚠️ Fehlt |
| Remediation Scripts | Ja (Intune) | Ja (SSH/PS/Bash + Approval) | ✅ **Besser** |

---

## 2. Kostenvergleich (13 Geräte)

### Microsoft-Lösung

| Komponente | Preis/Monat | Jährlich |
|-----------|-------------|----------|
| 13x Microsoft 365 E3 (inkl. Intune) | 13 × €36 = €468 | €5.616 |
| oder: 13x Intune Plan 1 (standalone) | 13 × €8 = €104 | €1.248 |
| Azure AD Premium P1 (für Conditional Access) | 13 × €6 = €78 | €936 |
| **Gesamt (E3)** | **€468/Monat** | **€5.616/Jahr** |
| **Gesamt (Intune standalone)** | **€182/Monat** | **€2.184/Jahr** |

### OpenDirectory

| Komponente | Preis/Monat | Jährlich |
|-----------|-------------|----------|
| Server (8GB RAM VPS, z.B. Hetzner) | ~€15 | €180 |
| Strom / Hosting | ~€10 | €120 |
| Admin-Aufwand (Wartung, Updates) | Eigenleistung | Eigenleistung |
| **Gesamt** | **~€25/Monat** | **~€300/Jahr** |

**Ersparnis: €1.884 - €5.316 pro Jahr** (abhängig von Microsoft-Lizenz)

---

## 3. Stärken-Schwächen-Analyse

### Wo OpenDirectory GEWINNT

1. **Kosten**: 85-95% günstiger als Microsoft-Lizenzen
2. **Linux-Support**: Vollwertiges Management (Intune kann fast nichts mit Linux)
3. **Datensouveränität**: Keine Daten in der Cloud, DSGVO-konform by design
4. **Remote Shell**: Direkter SSH/PowerShell-Zugriff auf jedes Gerät
5. **Policy Simulator**: "Was passiert wenn..." — Intune hat das nicht
6. **Drucker-Management**: Quotas, Scanner, Job-Tracking — besser als Universal Print
7. **Compliance-Breite**: 8 Frameworks (CIS, NIST, BSI, ISO, DSGVO, HIPAA, SOC2, PCI-DSS)
8. **IaC**: Terraform + Ansible nativ integriert
9. **Netzwerk-Topologie**: Visualisierung des gesamten Netzwerks
10. **Angriffspfad-Analyse**: Graph Explorer zeigt Schwachstellen-Ketten

### Wo Microsoft GEWINNT

1. **SaaS-Federation**: OAuth/SAML für alle Cloud-Apps (Google, Salesforce, etc.)
2. **Zero-Touch Enrollment**: Autopilot/DEP out-of-the-box
3. **Mobile (iOS/Android)**: Vollwertiges MDM
4. **Ökosystem**: Teams, Exchange, SharePoint-Integration
5. **FIDO2/Passwordless**: Windows Hello for Business
6. **Support**: Enterprise-Support mit SLA
7. **ADMX-Templates**: Tausende granulare Windows-GPO-Einstellungen
8. **Application Control**: AppLocker/WDAC für Whitelisting
9. **Driver Updates**: Automatische Treiber-Verwaltung
10. **Skalierung**: Getestet mit Millionen von Geräten

---

## 4. Empfehlung nach Szenario

### Szenario A: Kleines Büro, 13 Geräte, kein M365

**→ OpenDirectory (Lite-Modus) ist die BESSERE Wahl**

- Keine laufenden Lizenzkosten
- Volle Kontrolle über alle 3 Plattformen
- DNS/DHCP/File Shares inklusive
- Setup: 1 Server, 30 Minuten

### Szenario B: Kleines Büro, 13 Geräte, mit M365

**→ Hybrid-Ansatz empfohlen**

- Microsoft 365 für Email/Teams/Office
- OpenDirectory für Geräte-Management (ersetzt Intune-Lizenz)
- LLDAP als Identity-Source, Sync zu Entra ID für M365

### Szenario C: Wachsendes Unternehmen, 50-500 Geräte

**→ OpenDirectory (Full-Modus) + OAuth/SAML-Erweiterung**

- Full-Stack mit allen Enterprise-Services
- OAuth 2.0 / OIDC muss implementiert werden
- Kubernetes-Deployment für Hochverfügbarkeit
- Monitoring mit Grafana/Prometheus

### Szenario D: Enterprise, 1000+ Geräte, M365-zentriert

**→ Microsoft Intune bleibt die bessere Wahl**

- Tiefe Microsoft-365-Integration nicht ersetzbar
- Autopilot/DEP für Massen-Enrollment
- Enterprise-Support und SLAs erforderlich
- OpenDirectory ggf. als Ergänzung für Linux-Server

---

## 5. Roadmap: Was noch fehlt

### Priorität 1 (für produktiven Einsatz)

| Feature | Aufwand | Impact |
|---------|---------|--------|
| Unit Tests | 2-3 Wochen | Produktionsreife |
| OAuth 2.0 / OIDC Provider | 1-2 Wochen | SaaS-Federation |
| SAML 2.0 Support | 1 Woche | Enterprise-SSO |
| Zero-Touch Enrollment CLI | 3-5 Tage | Onboarding |

### Priorität 2 (Enterprise-Features)

| Feature | Aufwand | Impact |
|---------|---------|--------|
| FIDO2/WebAuthn | 1 Woche | Passwordless Auth |
| Self-Service Password Reset | 3-5 Tage | User-Self-Service |
| ADMX-Template Import | 1-2 Wochen | GPO-Kompatibilität |
| Application Whitelisting | 1 Woche | Security |

### Priorität 3 (Nice-to-Have)

| Feature | Aufwand | Impact |
|---------|---------|--------|
| PowerShell-Modul | 1 Woche | Admin-Tooling |
| Driver Update Management | 1-2 Wochen | Windows UX |
| RSoP-Frontend | 3-5 Tage | Policy-Debugging |
| Mobile App (Admin) | 2-3 Wochen | Mobiles Management |

---

## 6. Fazit

**OpenDirectory ist für das beschriebene Szenario (3 Linux + 5 Windows + 5 macOS) ein GUTER Ersatz für Intune/AD**, besonders mit dem neuen Lite-Modus (`docker-compose.lite.yml`).

Die Hauptvorteile:
- **Gleichwertiges Cross-Platform-Management** (Linux besser als Intune)
- **85-95% Kostenersparnis** gegenüber Microsoft-Lizenzen
- **Volle Datensouveränität** (Self-Hosted, DSGVO)
- **Mehr Compliance-Frameworks** als Intune
- **Besseres Remote-Management** (direkte Shell-Zugriffe)

Die verbleibenden Lücken (OAuth/SAML, FIDO2, Tests) sind adressierbar und stehen auf der Roadmap.
