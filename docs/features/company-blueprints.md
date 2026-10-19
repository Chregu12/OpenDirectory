# Firmen-Blueprints: Entwürfe und lokale Freigabeversionen

Status: **Tested**, begrenzter Business-Slice 21. Dies ist der eigene mandantengebundene Blueprint-Prozess, nicht der bisherige globale Platform-Policy-Katalog unter `/blueprints`.

## Fachlicher Umfang

Unter `/company-blueprints` können aktuell autorisierte Firmeninhaber beziehungsweise kanonische Administratoren ihres eigenen Home-Tenants echte Entwürfe erstellen, ändern, lokal versioniert freigeben, unveränderliche frühere Versionen lesen und eine frühere Version ausdrücklich als neuen Entwurf wiederherstellen.

Jeder Entwurf enthält Name, Beschreibung, Plattform, höchstens 25 Sicherheitsvorgaben und höchstens 25 gewünschte Apps aus dem tatsächlichen eigenen Firmen-Lizenzkatalog. Die App-Referenzen sind ein gewünschter Inhalt des Blueprints: Es werden dadurch keine Lizenzen reserviert, zugewiesen, gekauft, installiert oder zurückgegeben.

Eine lokale Freigabe friert einen nicht leeren, intern konfliktfreien Entwurf als nächste Version ein. Sie ist **keine unabhängige Deployment-Genehmigung oder bestätigte Geräteaktion**. Der globale Geräte-/Publikationspfad akzeptiert die separaten Firmen-Blueprint-IDs nicht als vorhandene globale Blueprints.

## Einfacher, nicht geheimnistragender Editor

Der erste Editor unterstützt ausdrücklich drei lokale Sollvorgaben:

| Art | Zugelassene Werte |
| --- | --- |
| `screen_lock` | `minutes`: Ganzzahl 1–1440; `requirePassword`: Boolean |
| `filevault` | `enabled`: Boolean |
| `software_update` | `automatic`: Boolean; `deferralDays`: Ganzzahl 0–365 |

Andere Felder, doppelte JSON-Schlüssel, verschachtelte Daten, Zeichenketten statt Zahlen/Booleans sowie Dezimal-/Exponent-Zahlenliterale werden abgewiesen. Der Editor erzeugt diese Werte über beschriftete Formularfelder, nicht über eine freie Credential-/JSON-Eingabe. Die Werte sind eigene Sollvorgaben, noch keine validierten Apple-MDM-Payloads oder Compliance-Nachweise.

WLAN-/VPN-Passwörter, Zertifikatsschlüssel und andere Secrets gehören nicht in unveränderliche unverschlüsselte Blueprint-Payloads. Solche Konfigurationen bleiben bis zu einem geeigneten Secret-Referenz-/Provider-Vertrag unsupported. Vorhandene globale Legacy-Konfigurationen werden dadurch nicht stillschweigend migriert oder als sicher abgenommen.

## Versionen und Wiederherstellung

- `revision` ist eine exakte PostgreSQL-int8-Zeichenkette und steigt bei jeder tatsächlichen Änderung dieses Aggregats um eins.
- `publishedVersion` ist eine getrennte lokale Versionsnummer. Ein Speichern des Entwurfs verändert eine bereits freigegebene Version nicht.
- Eine freigegebene Version enthält den ursprünglichen Entwurf und tatsächliche App-Metadaten zum Freigabezeitpunkt: Pool-ID, Name, Hersteller und damalige Pool-Revision. Eine spätere normale Lizenzzuweisung oder Katalogänderung schreibt diese Momentaufnahme nicht um. Die Pool-Revision ist Herkunft, keine dauerhafte Gültigkeitslease.
- Wiederherstellen setzt nur den aktuellen Entwurf auf den Inhalt der ausgewählten unveränderlichen Version. Die aktuelle Freigabe bleibt unverändert. Erst eine gesonderte Freigabe erzeugt die nächste Versionsnummer.
- Gleiche Konfigurationen einer Art behalten ihre ursprünglichen Quellen. Unterschiedliche vollständige Profile derselben Art bleiben ein Konflikt ohne erfundenen Gewinner. Ein solcher Entwurf darf gespeichert, aber nicht freigegeben werden.

## Berechtigungen und Isolation

Der neue private Source `/api/identity/company-blueprints` hat genau elf Felder und die drei festen Rechte `company.blueprints.read`, `company.blueprints.manage`, `company.blueprints.publish`. Er prüft tatsächlichen aktuellen `AuthorizationState`, ursprünglichen menschlichen Bearer, wirkliche Ownership/Home-Administration, kanonischen Tenant und unabhängige MFA höchstens 300 Sekunden alt – auch beim Lesen.

Die bisherigen Rollen-/Verzeichnis-/Lizenz-/Inventarquellen und die versiegelte Company-Policy-Quelle 036 bleiben unverändert. Der neue Prozess prägt keine globalen Policy-, PIM-, Review-, Gateway- oder Lizenzberechtigungen aus.

Neue Schreiboperationen mit App-Referenzen benötigen zusätzlich die unabhängig bestätigte bestehende Firmen-App-Authority für denselben ursprünglichen Actor und Tenant. Tatsächliche Pool-Herkunft, eigener Tenant, endlicher lokaler Bestand und retained Pool-Evidenz werden in derselben Policy-Transaktion geprüft; der bestehende Allocator wird nicht als zweiter Schreiber umgangen.

Alle eigenen Daten liegen in separaten `company_blueprint_*`-Relationen. Globale Blueprint-Abfragen erhalten keine neuen tenantgebundenen Zeilen. Tenant- und Actor-IDs sind ausschliesslich Quelle der aktuellen Autorisierung, keine frei wählbaren Body-/Query-Scopes.

## API und zuverlässige Bestätigung

Die API verwendet `/api/company-blueprints`, nicht einen Alias `/list`. Listen, Versionen und Historie sind serverseitig mit festen 25 Einträgen pro Seite paginiert. Details liefern einen exakten `ETag` der aktuellen Aggregat-Revision.

Jede Schreiboperation verlangt einen einmal erfassten `Idempotency-Key`; Änderungen bestehender Blueprints verlangen zusätzlich den ursprünglichen `If-Match`. Begründung und explizite Bestätigung sind verpflichtend. Source, Version, Operation, Metadaten-Event und tatsächliche Pending-Outbox werden atomar gehalten; physische Commit-Guards begrenzen auch bekannte Source-/App-Fristen nach Wartezeiten.

Nach unklarer Antwort wird nur auf ausdrückliche Anforderung dieselbe Originalabsicht mit demselben Schlüssel, Body und ETag wiederholt. Eine erfolgreiche historische Recovery liefert `already_applied` und die damalige Revision. Sie behauptet keinen aktuellen Kopf und verändert keine späteren Entwürfe oder Versionen. Bei Actor-/Tenant-/Sitzungswechsel werden nicht mehr bestätigte UI-Zustände verworfen. Kein automatisches Aktualisieren des ETags vor einer Wiederholung.

Die zwingende Outbox steht derzeit auf `pending`; das ist kein Zustell- oder Provider-Erfolgsbeleg. Audit-/History-Antworten enthalten Metadaten und Begründung, nicht rohe Konfigurationen, Bearer oder private Source-Proofs.

## Daten- und Betriebsgrenzen

### Anforderungsabgleich

| Master-Anforderung | Tatsächlicher Stand dieses Slices |
| --- | --- |
| FR-004.01/.02/.08/.09 | Eigene Entwürfe, versionierte lokale Freigaben und unveränderliche historische Inhalte getestet |
| FR-004.04 | Drei sichere Sollschemas und tatsächliche gewünschte App-Referenzen; übrige Konfigurationen/Secrets/Provider bleiben offen |
| FR-004.06/.07 | Interne Konflikte werden sichtbar und blockieren die Freigabe; keine automatische Prioritätsauflösung behauptet |
| FR-004.10 | Konfigurationsvorschau vorhanden; tatsächliche Auswirkungsberechnung auf Benutzer/Geräte noch nicht implementiert |
| FR-004.11 | Historische Version als Entwurf wiederherstellen und neu freigeben getestet; kein Rollback eines Geräte-Deployments |
| FR-004.03/.05/.12 | Eigene Ziel-/Mehrfachzuweisungen und Provider-Drift weiterhin offen |

Migration 025 führt Tenant-/Blueprint-FKs, immutable Freigaben sowie Originaloperation-/Event-/Pending-Belege ein. Die begrenzte Konfigurationssammlung bleibt ein versioniertes JSONB-Aggregat; sie ist keine zweite Geräte-, Lizenz- oder Benutzerprojektion. Identity besitzt weiterhin die Tenant-/Ownership-Daten; es gibt bewusst keinen datenbankübergreifenden Foreign Key und keine behauptete atomare Identity-/Policy-Transaktion.

SQL-/DDL-Owner und unveränderte Guard-Funktionen bleiben eine ausdrückliche Vertrauensgrenze. Getrennte produktive Runtime-/Migrationslogins, unabhängige Retention, Backup/Restore, Verschlüsselung der Betriebsdatenträger und vollständige Betriebsabnahme sind nicht durch lokale Tests bewiesen.

Offen bleiben vollständige Company-Rollen/OU-Scopes und Delegation, unabhängige Company-Deployment-Reviews/PIM, Ziel-/Gruppen-/Benutzerzuweisungen, Blueprint-basierte tatsächliche Lizenzverteilung, Onboarding, Secret-Referenzen und echte Provider-Ausführung. Das Gesamtziel bleibt aktiv.

Verträge: [OpenAPI](../api/openapi.yaml), [ADR 024](../architecture/adr-024-company-blueprints.md), [Datenmodell](../architecture/domain-model.md), [ERD](../architecture/erd.md), [Prüfbelege](../testing/test-results.md).
