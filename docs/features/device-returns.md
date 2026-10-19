# Geräterückgabe beim Mitarbeiter-Austritt

Status: **Tested, begrenzter Teilprozess** — Business-Slice 19, Teil von BR-003/WF-004. Der vorhandene [lokale Austritt](company-offboarding.md) kann die Rückgabe tatsächlicher eigener Inventarzuweisungen anfordern. Eine Anforderung ist keine physische Rückgabe und hebt keine Zuweisung auf. Keine MDM-, Wipe-, Lock-, Enrollment-, Compliance- oder Lizenzwirkung wird behauptet. [Tatsächliche SQL-/HTTP-/Browserabnahme](../testing/test-results.md#business-slice-19-geräterückgabe-beim-austritt).

## Zwei getrennte Arbeitsschritte

Nach dem wirklichen negativen Account-Checkpoint im gespeicherten Austritt den ausdrücklich eingeklappten Geräte-Folgeschritt öffnen. Die Vorschau zeigt bis zu 25 aktuelle eigene Gerätezuweisungen dieser Person, Inventarnummer, Seriennummer, genaue Geräteversion und ursprüngliche Assignment-ID. Bestehende offene Anforderungen bleiben sichtbar und werden nicht still dupliziert. Offene oder pausierte lokale Lizenzrückgaben blockieren diesen getrennten Schritt nicht.

Die gewünschten Zuweisungen auswählen, begründen und genau diese Auswahl ausdrücklich bestätigen. Stabile clientseitige Request-UUIDs werden einmal beim Erfassen des Intents erzeugt; sie sind Idempotenzselektoren, keine Berechtigung. Der Server prüft das gesamte Manifest read-only vor der ersten Wirkung. Jeder Child besitzt danach seinen eigenen atomaren Request-/Event-/Pending-Outbox-Commit. Geräte bleiben tatsächlich **zugewiesen**.

Unter **Geräterückgaben** (`/device-returns`) die wirklichen Aufträge lesen, ein Gerät öffnen und entweder:

- **Rückgabe manuell bestätigen:** Nur bei tatsächlich erfolgter Übergabe. Die genaue noch aktive ursprüngliche Zuweisung und beide Versionen werden geprüft. Der vorhandene kanonische Inventar-Mutator gibt diese eine Beziehung frei. Tatsächlicher Inventory-Release-Event/-Outbox und Rückgabeentscheidung/-Event/-Outbox gehören zu derselben Device-Transaktion.
- **Anforderung abbrechen:** Begründete explizite Entscheidung, die nur den Auftrag schliesst. Das Gerät und seine Zuweisung bleiben unverändert. Danach kann eine neue bewusste Anforderung mit neuer Request-UUID für dieselbe noch aktive Beziehung erstellt werden.

Die manuelle Bestätigung belegt die Erklärung des berechtigten Bearbeitenden, keine automatisch verifizierte physische Übergabe oder externe Provider-Ausführung. Historisch zurückgegeben bedeutet nicht, dass ein inzwischen neu zugewiesenes Gerät heute noch verfügbar ist.

## Zustände und Nebenläufigkeit

| Sichtbarer Auftragsstatus | Tatsächliche Bedeutung |
| --- | --- |
| `requested` | Rückgabe angefordert; ursprüngliche Zuweisung noch aktiv |
| `returned` | Manuelle Rückgabeentscheidung mit tatsächlichem kanonischen Entzug der ursprünglichen Zuweisung |
| `cancelled` | Nur der Auftrag wurde ausdrücklich abgebrochen |
| `assignment_changed` | Die ursprüngliche Beziehung wurde über den normalen Inventarweg geändert/aufgehoben; **keine Rückgabe bestätigt** |

Normale bedingte Inventar-Neuzuweisungen und Entzüge bleiben möglich. `assignment_changed` wird aus deren tatsächlichem alten Assignment und Inventory-Event abgeleitet; es wird kein zusätzlicher Rückgabe-Event erfunden. Ein solcher alter Auftrag darf keine spätere Zuweisung entziehen. Neue Beziehungen besitzen neue Assignment-UUIDs.

Der starke `"device-return-UUID-requestRevision-currentDeviceRevision"`-ETag bindet sowohl den Auftrag als auch den tatsächlichen aktuellen Gerätestand. Alle Revisionen bleiben exakte positive PostgreSQL-BIGINT-Strings. Vor Entscheidung ist der exakte `If-Match` erforderlich; eine veränderte Darstellung oder neue Zuweisung wird nicht still durch eine frische Version ersetzt.

Verlorener HTTP-Erfolg ist kein Rollback. Tatsächliche Vorschau/Details/Historie bewusst neu laden, dann gegebenenfalls den **ursprünglichen** Intent explizit wiederaufnehmen. Request-Recovery prüft alte Request-/Assignment-/Device-UUID, Version, Workflow und Begründung gegen den tatsächlichen Originalbeleg. Entscheidungs-Recovery prüft den alten kombinierten ETag, Aktion und Begründung gegen den tatsächlichen Abschlussbeleg. `already_requested`, `already_returned` oder `already_cancelled` sind historische Bestätigungen ohne neue Wirkung. Eine später neu zugewiesene Beziehung bleibt unberührt. Kein automatisches POST-Retry oder unbeaufsichtigter Worker.

## Least Privilege und Kontogeneration

Aktueller eigener Company-Owner oder tatsächlicher kanonischer Home-Tenant-Admin mit ursprünglichem menschlichem Bearer und unabhängig bestätigter MFA innerhalb von 300 Sekunden. Dieselben drei bisherigen Inventarfähigkeiten bleiben unverändert: `devices.inventory.read`, `devices.inventory.create`, `devices.inventory.assign`. Keine globale Rolle, neue Company-App-Fähigkeit, Service-Credential oder aus JWT-Behauptungen abgeleitete Ownership entsteht. Allgemeine delegierte Geräte-Rollen/OU-Scopes bleiben offen.

Anfordern und Anforderungs-Recovery benötigen den echten ursprünglichen Identity-045-Account-Beleg für genau Tenant/Vorgang/Benutzer und weiterhin dieselbe negative Eligibility-Generation. Selbst-Offboarding, gelöschte/fremde Ziele, Reaktivierung oder erneutes Sperren in einer späteren Generation sperren. Ein legitimer Authorization-Revision-Wechsel durch Rollenentzug ist keine andere negative Eligibility und wird nicht dafür gehalten.

Allgemeine Rückgabeansicht und operative Entscheidungen benötigen unabhängig aktuelle Inventarhoheit, aber nicht erneut einen noch gesperrten Mitarbeitenden. Ein tatsächliches Gerät darf auch nach späterer Reaktivierung oder Löschung der Person manuell zurückgenommen werden. Das ist eine eigenständig autorisierte Inventarhandlung an genau der alten noch aktiven Beziehung, keine Wiederverwendung des alten Austritts auf ein neues Konto. Der normale Console-Anwendungszugang und eigene MFA-Einrichtung bleiben erforderlich; `users.read` und lokale Lizenzrechte sind nicht nötig.

## API und Quellen

Die zehn neuen [OpenAPI-Operationen](../api/openapi.yaml) trennen tatsächliche Herkunft, Anforderung und Entscheidung:

- `POST /api/identity/device-offboarding` akzeptiert nur `{workflowId,userId}`. Die ursprüngliche Identity-Hoheit liefert genau 13 Quellfelder: bisherige Inventarquelle, Protokoll 1, negative Ziel-Eligibility und minimalen realen Parent-Beleg. Die bestehende 11-Feld-Inventarquelle bleibt unverändert.
- `GET /api/devices/returns/capabilities` bestätigt `deviceReturnsProtocol:1`; ein alter Inventarreceiver genügt nicht. Gateway und direkter Receiver prüfen unabhängig, kein Legacy-Fallback.
- `GET /api/devices/returns`, `GET /api/devices/returns/{id}` und `GET /api/devices/returns/{id}/history` liefern wirkliche eigene Aufträge, beide Versionen und retained Events/Pending-Zustellung.
- `POST /api/devices/returns/{id}/decision` verlangt exakten ETag und `{action:"returned"|"cancelled",reason,confirm:true}`.
- `GET /api/devices/users/{userId}/offboarding-returns/capabilities`, `GET`/`POST` auf der Basis ohne `/capabilities` und `GET /history` verbinden genau den ursprünglichen negativen Account-Checkpoint mit tatsächlichen Zuweisungen und Anforderungsbelegen.

Listen haben feste Seiten von 25 und optionalen expliziten Auftragsstatus. Der Anforderungs-POST enthält nur `{workflowId,eligibilityRevision,reason,confirm:true,items:[{deviceId,deviceRevision,assignmentId,requestId}]}` mit 1–25 eindeutigen IDs. `200` bestätigt angeforderte alte Aufträge, **nicht** ihre Rückgabe. Bei `207` stoppt ein `unconfirmed`-Child weitere Arbeit; frühere Commits bleiben und spätere sind `not_attempted`. Nach Authority-Verlust kann selbst eine Teilantwort ausbleiben.

## Datenhoheit und Grenzen

Device-Migration **006** ergänzt `device_return_requests`, `device_return_events` und `device_return_outbox`. Geräte/Assignments und bestehender Mutator aus 005 bleiben die einzigen Inventar-Schreiber; kein zweiter Gerätebestand, keine neue Identity-Migration. Lokale FKs, eindeutige offene Beziehung, append-only Event-/Outbox-Belege und physische Receiving-/Original-Intent-/Deadline-/No-extra-effects-Prüfungen gehören zum Commit. [Modell](../architecture/domain-model.md), [ERD](../architecture/erd.md), [Entscheidung](../architecture/architecture-decisions.md).

Identity- und Device-Datenbanken bleiben getrennt. Der Parent wird mit demselben ursprünglichen menschlichen Bearer live in Identity geprüft; es gibt keinen falschen Cross-DB-FK oder verteilten atomaren Commit. Nach dem letzten Live-Checkpoint ist keine sofortige dienstübergreifende Revocation-Garantie behauptet. SQL-/DDL-Besitzer bleiben explizite Vertrauensgrenze; getrennte Runtime-/Migrationslogins, unabhängige Retention, Privacy-Löschung und Backup/Restore bleiben Betriebsabnahmen.

Dieser Schritt ändert weder den historischen Account-/Lizenzabschluss noch führt er den vollständigen Leaver-Prozess zu Ende. Vollständige Sessions/externen Credentials, OU-Bereinigung, Provideraktionen, Blueprint-/Lizenzkomposition und übrige BRs bleiben offen. Pending ist ausstehende lokale Zustellung, keine erfolgreiche Cloud-Verarbeitung.
