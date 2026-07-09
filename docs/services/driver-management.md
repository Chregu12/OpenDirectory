# Driver Management — Architektur & Bounded Contexts

Dieses Dokument beschreibt die Architektur der Treiberverwaltung
(automatische Treibererkennung beim Domain-Join, Treiberkatalog, Import
und Deployment) und die bewussten Kontextgrenzen.

## Zielbild

Generischer Kern, plattformspezifische Logik ausschließlich an den
Rändern (Client-Connectoren und Plattform-Matcher):

```
Client-Connectoren (plattformspezifisch)
  scripts/Join-OpenDirectory.ps1     Windows: WMI (Win32_ComputerSystem, PnP-IDs)
  scripts/Join-OpenDirectory.sh      Linux: dmidecode, lspci -n, lsusb
        │  POST /api/samba/computers/join
        │  POST /api/devices/report-hardware
        ▼
Next.js-Rewrites (de-facto API-Gateway für Browser + Scripts)
  frontend/web-app/next.config.js    Contract-Tests: __tests__/apiRewrites.test.js
        ▼
Services (generisch, DDD)
  device-service                      Hardware-Reports, Matching, Treiber, Deployments
  printer-service                     Druckertreiber, Katalog, Dell-Live-Katalog
  samba-ad-dc                         Computer-Konten; benachrichtigt device-service (fire-and-forget)
        ▼
Shared Package (reine Domänenlogik, kein I/O)
  @opendirectory/driver-catalog
    src/index.js                      DriverCatalog-Orchestrator (Provider-Injection)
    src/scoring.js                    Vendor-/OS-Normalisierung, Modell-Scoring
    src/platforms/WindowsMatcher.js   PnP-ID-Parsing (VEN_/DEV_/CC_, VID_/PID_)
    src/platforms/LinuxMatcher.js     lspci/lsusb → apt-Pakete (PCI-/USB-Regeln)
    src/vendors/HpProvider.js         statische HP-Einträge (Windows + Linux)
    src/vendors/LenovoProvider.js     statische Lenovo-Einträge
```

## Bounded Contexts und ihre Grenzen

### 1. Hardware-Matching (Shared Kernel)

`@opendirectory/driver-catalog` ist bewusst **I/O-frei**: keine
HTTP-Aufrufe, kein Dateisystem, keine Service-URLs. Live-Datenquellen
werden vom konsumierenden Service **injiziert**:

```js
const catalog = new DriverCatalog();
catalog.registerProvider('dell', fetchDellDrivers); // HTTP lebt im Service
```

Neue Hersteller → neuer `vendors/<X>Provider.js`.
Neue Plattform → neuer `platforms/<X>Matcher.js`.

### 2. Dell-Live-Katalog (Owning Service: printer-service)

Der Dell-Katalog (`CatalogPC.cab` von downloads.dell.com, 55 MB UTF-16-XML,
24-h-Cache) gehört **einem** Service: dem printer-service
(`src/services/dellCatalogService.js`). Gründe:

- Das Runtime-Image des printer-service enthält bereits `cabextract`/`p7zip`.
- Genau ein Cache, genau ein Refresh-Zyklus, genau eine Parser-Implementierung.

Der device-service konsumiert ihn ausschließlich über die HTTP-API
(`GET /api/printer/catalog/dell`) via injizierten Provider — das ist die
**Anti-Corruption-Layer**: Ändert sich der Dell-Katalog intern, ändert
sich für den device-service nichts, solange der API-Vertrag hält
(abgesichert durch `printer-service/src/__tests__/driversE2E.test.js`).

Bewusste Entscheidung: Der Katalog wird NICHT ins Shared Package gezogen
(es bliebe sonst nicht I/O-frei) und bekommt KEINEN eigenen Microservice
(unnötige Betriebskomplexität für einen einzelnen Cronjob-artigen Cache).

### 3. Treiber & Deployments (device-service, DDD)

```
domain/aggregates/DriverAggregate.js        Treiber + Deployments (Statusmaschine)
domain/value-objects/DriverFormat.js        valide Formate, Normalisierung
domain/value-objects/HardwareProfile.js     Report-Normalisierung, Key-Ableitung
domain/repositories/IDriverRepository.js    Interface
domain/repositories/IHardwareReportRepository.js
domain/events/DeviceEvents.js               DRIVER_IMPORTED, DRIVER_DEPLOYED,
                                            HARDWARE_REPORTED
application/DriverApplicationService.js     Use-Cases (Upload, Import, Deploy,
                                            Empfehlungen); publiziert Events
infrastructure/repositories/File*.js        JSON-Datei-Implementierungen
                                            (env-überschreibbar für Tests)
routes/driverRoutes.js                      dünn: HTTP ↔ ApplicationService
routes/deviceDetectionRoutes.js             dünn
```

Die File-Repositories sind bewusst hinter Interfaces: ein Wechsel auf
Postgres (analog `PostgresDeviceRepository`) ändert nur die
Infrastruktur-Schicht.

### 4. Geräteliste (Single Source of Truth: device-service)

`api-backend` hielt historisch eine eigene In-Memory-Geräteliste
(`deviceStore`). Die lesenden Routen (`GET /api/devices`,
`GET /api/devices/:id`) **delegieren jetzt** an den device-service:

- **Domänendaten**: Das `DeviceAggregate` wurde um `os`, `osVersion`,
  `ipAddress`, `kernel`, `packageManager` erweitert (additive Migration
  `002_device_system_info.sql`) und leitet einen numerischen
  `complianceScore` ab (compliant → 100, sonst −25 pro Violation).
- **Service-zu-Service-Auth**: api-backend holt sich per
  Client-Credentials-Flow ein Token vom oauth-provider
  (`utils/serviceClient.js`, Token-Caching mit 30-s-Refresh-Puffer,
  Cache-Drop bei 401/403). `docker-compose.yml` setzt für device-service
  jetzt `OIDC_ISSUER` (Default `https://opendirectory.local`, der
  Issuer-Claim des oauth-provider) und
  `JWKS_URI=http://oauth-provider:3010/.well-known/jwks.json`.
- **Shape-Adapter**: `hostname`→`name`; neue Felder werden nur
  durchgereicht, wenn vorhanden (ältere device-service-Versionen
  degradieren sauber).
- **Fallback**: Bei Timeout/401/5xx/Nichterreichbarkeit antwortet
  api-backend aus dem lokalen `deviceStore` (Warn-Log, gedrosselt auf
  1×/Minute) — die Delegation kann nie einen Ausfall verursachen.

**Offene Betriebsaufgabe**: Der oauth-provider seedet keinen
`api-backend`-Client (nur `grafana-od-client`/`devportal-od-client`).
Bis ein Client `api-backend` mit Secret `API_BACKEND_CLIENT_SECRET`
registriert ist (z. B. via `POST /api/clients`), greift dauerhaft der
Fallback. In `docker-compose.lite.yml` existiert kein oauth-provider —
dort bleibt der Fallback bewusst der Normalpfad.

Schreibende Routen (`enroll`, `refresh`, `apps/install`) sind noch
lokal und als `TODO(device-service delegation)` markiert.

## Testabdeckung als Architektur-Vertrag

| Schicht | Suite |
|---|---|
| Shared Package | `packages/driver-catalog/test/` (node --test) |
| device-service HTTP-Verträge | `src/__tests__/driversE2E.test.js` |
| printer-service HTTP-Verträge inkl. Dell-Fixture | `src/__tests__/driversE2E.test.js` |
| Next.js-Rewrites (Routing-Contract) | `frontend/web-app/__tests__/apiRewrites.test.js` |
| platform api-gateway | `src/__tests__/gatewayE2E.test.js` + serviceDiscovery-Unit-Tests |

Die E2E-Suiten definieren die API-Verträge: Refactorings der inneren
Schichten müssen sie unverändert grün halten.
