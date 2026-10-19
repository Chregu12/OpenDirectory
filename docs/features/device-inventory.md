# Eigenes Geräteinventar und Mitarbeitenden-Zuweisung

Stand: 19. Oktober 2026. Begrenzter vertikaler Slice für BR-003: reale Unternehmensgeräte erfassen, eigene Mitarbeitende auswählen, genau eine aktuelle Benutzerzuweisung verwalten und die tatsächliche Historie sehen. Keine MDM-, Enrollment-, Compliance- oder Lizenzwirkung wird aus einer Inventarzeile abgeleitet.

Der anschliessende [Geräterückgabe-Teilprozess](device-returns.md) verbindet echte negative Account-Checkpoints mit ausdrücklichen Rückgabeanforderungen. Erst eine gesonderte manuelle Bestätigung verwendet denselben kanonischen Inventar-Entzug. Anfordern oder Abbrechen allein ändert die Zuweisung nicht; normale Neuzuweisung wird nie als physische Rückgabe ausgegeben.

## Nutzbarer Weg

1. Mit dem aktivierten ursprünglichen Company-Owner und frischer Pflicht-MFA `/devices` öffnen.
2. **Gerät erfassen**: Inventarnummer, Seriennummer, Hersteller, Modell, Klasse und Plattform eingeben. OS-Version, Eigentumsart, Kauf-/Garantieangaben und Beschreibung sind optional.
3. **Im Inventar speichern** erzeugt eine echte PostgreSQL-Zeile mit servergenerierter UUID und unveränderlichem Tenant. Das Gerät ist **verfügbar**, **nicht enrolled**, Compliance **unbekannt**; Last Seen, Provider und Telemetrie sind nicht vorhanden.
4. Die Inventarnummer öffnen. Mit separat bestätigtem `users.read` tatsächliche eigene Mitarbeitende suchen/auswählen; auch gesperrte Verzeichniseinträge können bereits ein Inventargerät erhalten. Ohne Profilrecht bleibt nur die bekannte kanonische UUID-Eingabe.
5. **Benutzer zuweisen** ausdrücklich bestätigen. Neuzuweisung schliesst die alte Beziehung und erzeugt genau eine neue aktive Zuweisungs-ID atomar; **Zuweisung aufheben** schliesst nur die aktuelle Beziehung. Historische Datensätze bleiben erhalten.
6. Die echte paginierte **Gerätehistorie** zeigt ursprünglichen Actor, Correlation-ID, Revision, Zuweisungswechsel und tatsächliche **ausstehende Ereigniszustellung**. Das ist keine bestätigte Provider-Ausführung.

Keine dekorativen Wipe-/Lock-/Restart-/Enroll-Buttons. Der kanonische Receiver antwortet bei nicht implementierten Device-/Provider-Aktionen mit `501 unsupported`, statt lokale Gerätezustände als externe Erfolge zu ändern. Zuweisen aktiviert weder die Person noch deren Zugang, Rollen, Gruppen, Blueprints oder Lizenzen.

## Berechtigung und Live-Quelle

`GET/POST /api/identity/device-inventory` löst den **ursprünglichen** menschlichen Bearer in der tatsächlichen Identity-Hoheit auf. Signatur/Zweck/Audience/RS256 und laufender Issuer-Status werden geprüft. Canonical Context, Home-Tenant, aktuelle Rollen-/Authentifizierungspolitik, aktuelle ursprüngliche Company-Ownership und unabhängig gebundene MFA werden erneut in der Identity-Datenbank geprüft. MFA darf höchstens 300 Sekunden alt sein; ein längeres allgemeines Rollenfenster verlängert das Inventarfenster nicht.

Nur tatsächliches kanonisches `admin` oder der aktuelle ursprüngliche eigene Company-Owner erhalten die drei begrenzten Rechte:

- `devices.inventory.read`
- `devices.inventory.create`
- `devices.inventory.assign`

Auch `admin` arbeitet nur im eigenen tatsächlichen Home-Tenant. Kein neuer globaler Rollenname, keine Aktivierung der versiegelten allgemeinen eigenen Rollenquelle und kein Rollen-/Providerrecht wird hinzugefügt. Behauptete Owner-/Permission-Claims, API Keys, Workloads oder gemeinsame Enrollment-Tokens ersetzen die Live-Quelle nicht. Generische `gateway.proxies.devices.access`-Claims sind kein Inventarrecht. Vollständige delegierte Geräte-Rollen/Scopes sind noch offen.

Der Device-Receiver liest dieselbe originale Quelle vor der Operation, nach Locks und am letzten Application-Checkpoint. Empfänger werden mit der echten eigenen kanonischen ID und aktuellen Autorisierungsrevision aufgelöst, ohne Passwort oder Profilfreigabe. Die private Quellantwort ist an Issuer, Subject, Token-ID, Ablauf, Context, Tenant und ursprünglichen MFA-Deadline gebunden; kein neuer Service-Token wird erzeugt. Benutzerprofile für den Picker kommen ausschliesslich aus der separat berechtigten vorhandenen Personen-API.

Der Gateway verifiziert vor dem Weiterleiten mit demselben Bearer die tatsächliche neue Receiver-Capability. Ein alter Receiver ohne `inventoryProtocol:1` darf keine Operation erhalten; eine alte ungescopte Geräte-API wird nicht durch pauschales Gateway-Passthrough freigegeben. Die direkte Next.js-Verbindung landet ebenfalls am kanonischen Receiver mit eigener unabhängiger Prüfung.

## Datenhoheit und Commit

Device-Service bleibt Datenhoheit; seine bestehende PostgreSQL-Tabelle `devices` wird durch **005_device_inventory.sql** additiv erweitert. Kein zweites Inventar im Identity-Service, keine Framework-Migration, kein Default-Tenant und keine automatische Adoption alter Geräte. Legacy-Zeilen mit `tenant_id IS NULL` bleiben physisch erhalten, aber ausserhalb des kanonischen eigenen Inventars.

Inventarnummer und Seriennummer sind innerhalb eines Tenants case-insensitiv eindeutig. Eine aktuelle exklusive Beziehung je Gerät wird zusätzlich durch einen partiellen Unique-Index erzwungen. Die neue `device_inventory_assignments`-Historie hält User-ID, damaligen kanonischen Ziel-Snapshot, Start/Ende und beide Commands. `device_inventory_events` enthält Typ/Version, Tenant, Actor, Correlation-ID, exakte vollständige Before-/After-Gerätezeilen und alte/neue Zuweisung. Die gleichnamige `device_inventory_outbox` ist obligatorisch und bleibt tatsächlich `pending`.

Jede Zuweisungsänderung verlangt den exakten starken `"device-UUID-revision"`-ETag und erhöht den positiven BIGINT-String um eins. Missing `If-Match`: `428`; stale: `412`; doppelte Inventarnummer/Seriennummer bzw. bereits gleicher Empfänger: `409`; fremde/fehlende eigene Ziele: `404`. Kein automatischer Write-Retry und kein allgemeines Idempotency-Key-Journal; verlorene Antworten müssen durch Nachlesen abgeglichen werden.

Device-Row-Locks serialisieren tatsächliche konkurrierende Zuweisungen. Private ownergebundene SQL-Admission, aktive Row-/Truncate-Guards, ursprünglicher Proof und physische Deadline, tatsächliche exklusive Zuweisung, ursprüngliche Receipt und Deferred-Commit-Receiver müssen exakt zusammenpassen. Fehlende Rows/Events/Outbox/Receiver, spätere Row-/Target-Drift, Raw-Write-/`SET ROLE`-Ersatz oder gelöschte Scope-GUCs dürfen keinen erfolgreichen Commit erzeugen. Snapshots werden in UTC erzeugt. Der privilegierte DB-Operator bleibt eine Betriebsvertrauensgrenze; dies ist kein fertiggestelltes Least-Privilege-DB-Loginmodell.

**Servicegrenze:** User und Device liegen in unabhängigen Datenbanken. Es wird kein unmöglicher datenbankübergreifender FK bzw. atomarer distributed Commit behauptet. Der Ziel-Snapshot beweist die eigene Identität zum letzten Live-Checkpoint, nicht dauerhafte zukünftige Existenz. Unmittelbare Löschung/Widerruf nach diesem Check ist noch kein durchgängiger JML-/Reconciliation-Prozess. Eine lokale Zuweisung erteilt keinen effektiven Geräte-/Anwendungszugang. Kontrollierte Dependenz-, Offboarding-, Privacy-/Retention- und Delivery-Prozesse bleiben erforderlich.

## Runtime und kompatibler Rollout

`npm start`, `npm run dev` und Docker verwenden jetzt **`src/inventoryServer.js`** im vorhandenen Device-Service. Der frühere `src/index.js` enthält einen nicht startfähigen Legacy-Pfad mit fehlendem `database/manager` und simulierten/best-effort Bereichen; er ist **kein alternativer produktiver Einstiegspunkt**. Vorhandene Legacy-Quelldateien/Tests bleiben zur Nachverfolgung erhalten, nicht als angeblich fertiger Provider. `/devices` verwendet die neue echte Inventaransicht.

PostgreSQL ist zwingend. Fehlende Verbindung oder eine fehlgeschlagene Migration lässt den neuen Prozess nicht erfolgreich starten; es gibt keinen In-memory-Schreib-Fallback. `DATABASE_URL` oder die vorhandenen `DB_HOST/PORT/NAME/USER/PASSWORD` konfigurieren Storage. Erforderlich sind `OIDC_ISSUER`, `JWKS_URI`, `OIDC_ACCESS_STATE_URL` und `IDENTITY_SERVICE_URL`. Keine neuen Credentials; bestehende Tokens/Secrets werden nicht geloggt. Health meldet ausdrücklich den lokalen Storage-Zustand, nicht erfolgreiche externe Provider.

Beide Compose-Varianten nutzen den Repository-Root als Device-Buildkontext, kopieren die gemeinsamen Verträge und verwenden PostgreSQL; der neue Runtime benötigt weder Mongo-/Redis-/RabbitMQ-Zugangsdaten noch den gemeinsamen Enrollment-/Appstore-Token. Bestehende Driver-/Hardware-Volumes bleiben als historische Daten erhalten. Identity-/Device-/Gateway-/Frontend-Images müssen koordiniert aktualisiert werden; alte direkte Caller müssen den neuen JSON-/Capability-/ETag-Vertrag übernehmen. Alte produktive Instanzen dürfen nicht parallel ungescopte Legacy-Reads auf dieselbe Datenbank anbieten. Kein tatsächlicher Image-Build oder Rollout wurde damit abgenommen.

## API und noch offen

[Gemeinsamer generierter OpenAPI-3.1-Vertrag](../api/openapi.yaml): `GET /api/devices/capabilities`, `GET/POST /api/devices`, `GET /api/devices/{id}`, `PUT /api/devices/{id}/assignment`, `GET /api/devices/{id}/history` sowie die zwei Original-Identity-Quelloperationen. Page/limit, literale Suche und Counts sind serverseitig; Daten und Counts kommen aus demselben read-only Repeatable-Read-Snapshot.

[Abnahme](../testing/test-results.md#business-slice-10-geräteinventar-und-zuweisung) umfasst den begrenzten Inventarweg, nicht den ganzen BR-003. Noch offen: weitere Ordered/Received/Enrolling/Maintenance/Retired-Zustände, Standort-/OU-Zuweisung, CSV/Bulk, kontrollierte Legacy-Adoption, Gerätescopes, Enrollments und geprüfte Providerverträge, Telemetrie/Compliance, sichere Remote-Aktionen sowie verbundene Blueprints/Apps/Lizenzen/JML. Die vorhandene separate Issuer-Policy-Agent-Plane wird nicht allein durch gleiche IDs zu einer Integration mit diesem Inventar. Übrige Master-Prompt-Domains und Produktions-/Betriebsabnahmen bleiben aktiv.
