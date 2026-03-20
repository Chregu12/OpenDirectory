# Settings Wizards — Implementierungsplan

## Konzept

Drei neue Step-basierte Wizards im gleichen Design wie SetupWizard/DeviceEnrollmentWizard, erreichbar über:
- **UniFi Sidebar** → Settings-Bereich (Unterpunkte)
- **Classic Dashboard** → Quick Actions oder Tabs
- **ServicesDashboard** → Direkt-Links bei den jeweiligen Modulen

Jeder Wizard ist ein eigenständiges Component unter `components/setup/` und kann sowohl als Modal-Overlay als auch eingebettet verwendet werden.

---

## 1. NetworkConfigWizard — Netzwerk-Konfiguration

**Datei**: `components/setup/NetworkConfigWizard.tsx`

**Steps**:
1. **Netzwerk-Übersicht** — Zeigt aktuelle Konfiguration (erkannte Interfaces, IP-Bereiche, Status)
2. **DNS konfigurieren** — DNS-Server aktivieren/deaktivieren, Zonen anlegen, Records hinzufügen (A, AAAA, CNAME, MX, TXT) mit Formular + Live-Vorschau
3. **DHCP konfigurieren** — Scopes erstellen (Start-IP, End-IP, Subnet, Gateway, Lease-Time), Reservierungen anlegen
4. **File Shares** — SMB/NFS/AFP Shares erstellen, Pfad + Protokoll + Berechtigungen setzen
5. **Zusammenfassung & Anwenden** — Übersicht aller Änderungen, "Anwenden"-Button

**APIs** (bereits vorhanden):
- `GET/POST /api/network/dns/records`
- `GET/POST /api/network/dhcp/scopes`
- `GET/POST /api/network/shares`
- `POST /api/network/discovery/scan`

**Besonderheiten**:
- Netzwerk-Scan im ersten Step als Hilfe zur Orientierung
- Validierung von IP-Adressen/Subnets im Frontend
- Optionaler "Quick Setup"-Modus: nur Subnet eingeben → DNS + DHCP werden automatisch konfiguriert

---

## 2. UserManagementWizard — Benutzer-Verwaltung

**Datei**: `components/setup/UserManagementWizard.tsx`

**Steps**:
1. **Verzeichnis-Übersicht** — Zeigt aktuelle User/Gruppen-Statistik, LLDAP-Status
2. **Gruppen erstellen** — Neue Gruppen anlegen (Name, Beschreibung), vordefinierte Templates (Admins, Users, Gäste, Abteilungen)
3. **Benutzer anlegen** — Einzeln: Formular (Vorname, Nachname, E-Mail, Passwort, Gruppenzuweisung) — Bulk: CSV-Import mit Vorschau-Tabelle
4. **Berechtigungen** — Gruppen-basierte Zuweisungen zu Services (welche Gruppe darf auf welchen Service zugreifen)
5. **Zusammenfassung** — Übersicht aller neuen User/Gruppen, Bestätigung

**APIs** (bereits vorhanden):
- `lldapApi.getUsers()`, `lldapApi.getGroups()`, `lldapApi.getStats()`
- `lldapApi.searchUsers(query)`

**Neue API-Endpoints** (Backend):
- `POST /api/users` — Einzelnen User erstellen
- `POST /api/users/bulk` — CSV/Batch-Import
- `POST /api/groups` — Gruppe erstellen
- `PUT /api/groups/:id/members` — Mitglieder einer Gruppe verwalten

**Besonderheiten**:
- CSV-Import mit Drag&Drop + Spalten-Mapping
- Passwort-Generierung (zufällig oder Muster-basiert)
- Gruppen-Templates für typische Unternehmensstrukturen
- Validierung: E-Mail-Duplikate, Passwort-Stärke

---

## 3. PrinterSetupWizard — Drucker-Setup

**Datei**: `components/setup/PrinterSetupWizard.tsx`

**Steps**:
1. **Drucker finden** — Auto-Discovery im Netzwerk (Subnet-Scan) + manuelle Eingabe (IP, Name, Protokoll)
2. **Drucker konfigurieren** — Für jeden gefundenen/hinzugefügten Drucker: Name, Standort, Protokoll (IPP/LPD/SMB/Raw), Treiber-Auswahl, Standardeinstellungen (Duplex, Farbe, Papierformat)
3. **Drucker-Gruppen** — Drucker in logische Gruppen einteilen (z.B. "Büro EG", "IT-Abteilung")
4. **Benutzer-Zuordnung** — Welche Benutzergruppen dürfen welche Drucker nutzen, Druck-Kontingente setzen
5. **Deployment** — Zusammenfassung, plattformspezifische Verteilung generieren (Windows GPO, macOS CUPS, Linux CUPS), "Bereitstellen"-Button

**APIs** (bereits vorhanden):
- `GET /api/printers/discover`
- `POST /api/printers`
- Backend: PrinterManager, PrinterAgentService, PrintersCompiler

**Neue API-Endpoints**:
- `GET /api/printers` — Alle Drucker auflisten
- `PUT /api/printers/:id` — Drucker aktualisieren
- `POST /api/printers/groups` — Drucker-Gruppe erstellen
- `GET /api/printers/:id/status` — Live-Status (Toner, Papier, Jobs)
- `POST /api/printers/deploy` — Deployment-Konfiguration generieren

**Besonderheiten**:
- Live-Status-Anzeige (Toner-Level, Papier, Fehlerstatus)
- Testdruck-Button pro Drucker
- Plattform-spezifische Deployment-Scripts (wie beim DeviceEnrollmentWizard, mit Copy-Button)
- Drucker-Vorschau mit Icon basierend auf Typ (Laser, Tintenstrahl, Multifunktion)

---

## 4. Integration in Navigation

### UniFi Layout (Sidebar)
- Neuer Bereich "Wizards" oder Integration unter "Settings":
  - Netzwerk-Konfiguration
  - Benutzer-Verwaltung
  - Drucker-Setup

### Classic Dashboard (page.tsx)
- Quick Actions erweitern um Wizard-Buttons
- Oder eigener Tab "Wizards"

### Shared Pattern
Alle Wizards teilen:
- Gleiche Step-Navigation (Fortschrittsbalken oben)
- Modal-Overlay oder Vollbild-Ansicht
- `onClose` / `onComplete` Callbacks
- Toast-Benachrichtigungen bei Erfolg/Fehler
- Responsives Layout (Mobile-fähig)

---

## Reihenfolge der Implementierung

1. **NetworkConfigWizard** — Nutzt existierende Network-APIs direkt, geringster Backend-Aufwand
2. **PrinterSetupWizard** — Backend-Infrastruktur (PrinterManager) existiert bereits, braucht nur REST-Endpunkte
3. **UserManagementWizard** — Braucht neue Backend-Endpoints für User/Group-CRUD + CSV-Import

Pro Wizard: ~400-500 Zeilen Frontend + ~50-80 Zeilen neue Backend-Endpoints + API-Client-Erweiterung
