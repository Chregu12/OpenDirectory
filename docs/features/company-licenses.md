# Eigenes Firmen-Lizenzinventar und lokale Zuweisung

Stand: 19. Oktober 2026. Begrenzter BR-005-Slice: Ein tatsächlicher Company-Owner kann einen eigenen endlichen Software-Lizenzbestand erfassen, einem freigegebenen eigenen Mitarbeitenden einen Platz zuweisen und diese lokale Zuweisung ausdrücklich zurücknehmen. **Der vorhandene Allocator bleibt der einzige Allokationspfad.** Kein zweiter Poolbestand, keine neue globale Rolle und kein erfundener Cloud-/Installations-/Kauferfolg.

## Nutzbarer Weg

1. Als aktivierter eigener Company-Owner mit frischer Pflicht-MFA **Anwendungen** öffnen. `/applications` verwendet jetzt den echten Firmen-Lizenzkatalog; der alte SSO-Verbindungswizard mit simuliertem Erfolg ist nicht mehr der normale Anwendungseinstieg.
2. **Lizenzpool erstellen**: Anwendungsname, Hersteller, Beschreibung, endlicher Bestand von **1 bis 10'000** und Begründung erfassen. Der Bestand ist eine ausdrücklich manuell erfasste lokale Inventarangabe, keine vom Hersteller bestätigte Lizenzbeschaffung.
3. Den eigenen Pool öffnen. Bestand, belegt und verfügbar werden aus den tatsächlichen Datensätzen berechnet. Es gibt keine erfundene Reservation, Installation oder Preiskalkulation.
4. Einen freigegebenen eigenen Mitarbeitenden auswählen, Grund eingeben und **Lizenz zuweisen** bestätigen. Profilsuche benötigt separat tatsächliches `users.read`; andernfalls bleibt die bekannte eigene UUID-Eingabe. Ein neuer gesperrter Verzeichniseintrag muss zuerst bewusst über **Konto freigeben** freigegeben werden. Das erzeugt noch keine Employee-Credentials oder externe Identität.
5. Der bestehende Allocator erzeugt die reale Direct-Source, immutable Grant-Historie und genau eine effektive Zuordnung im selben bestehenden `license_catalog`/`license_assignments`-Modell. Der endliche Bestand kann auch mit konkurrierenden Anfragen nicht überbucht werden.
6. **Lizenz freigeben** bestätigt die genaue aktuelle Zuweisungs-ID und Poolversion. Der Platz wird tatsächlich frei; Ursprung und Entzug bleiben nachvollziehbar. Auch ein inzwischen gesperrter oder retained gelöschter eigener Mitarbeiter kann ausdrücklich freigegeben werden.
7. Die paginierte **Lizenzhistorie** zeigt ursprünglichen Actor, Ziel, Version, Correlation-ID und wirkliche **ausstehende Zustellung**. `pending` ist keine bestätigte Provider-Ausführung.

**Wichtig:** Eine Kontosperre gibt diese neuen lokalen Firmenlizenzen noch nicht automatisch zurück. Die unten beschriebene bestätigte Sammelrückgabe unterstützt den Lizenzschritt für bereits gesperrte Mitarbeitende; der vollständige dauerhafte Leaver-Prozess ist weiterhin offen. Dafür wird keine Legacy-Worker-Nebenwirkung als erfolgreiche Firmen-Automation ausgegeben. Reaktivierung stellt keinen alten Grant wieder her. Zurzeit sind nur direkte Benutzerzuweisungen ohne Ablaufdatum unterstützt, nicht Gruppen, Geräte, Blueprints oder tatsächliche App-Installation. Es gibt keine dekorativen Edit-/Delete-/Deploy-Buttons für noch fehlende Funktionen.

## Kontrollierte Lizenzrückgabe beim Austritt

Unter **Anwendungen & Lizenzen** ermöglicht die eigene Mitarbeiter-UUID eine echte Rückgabevorschau: aktueller Kontostatus, Anwendungsnamen und genau die bestehenden Zuweisungen aus einem gemeinsamen Read-only-Snapshot. Profilrechte werden dadurch nicht erweitert. Ein aktives Konto bleibt aktiv; vor einer Sammelrückgabe muss es ausdrücklich im Personenbereich gesperrt werden. Auch eine retained eigene Löschung kann noch lokale Lizenzen besitzen.

Die Bestätigung betrifft **höchstens die angezeigten 25 Zuweisungen**, nicht unsichtbare weitere Seiten oder künftige Grants. Begründung, aktueller Poolstand und unveränderliche Zuweisungs-ID werden pro Zeile erfasst. Fremde Pools, veraltete Versionen, ersetzte Zuweisungen und nicht unterstützte Governance werden für das gesamte Manifest vor dem ersten Schreibvorgang abgeprüft. Erst danach wird die ursprüngliche eigene negative Benutzerquelle aufgelöst.

Jeder Entzug läuft durch den bestehenden Allocator in **seiner eigenen vollständigen Datenbanktransaktion**. Ursprüngliche Authority, gesperrte Benutzerinkarnation, Deadline und exakte Poolversion bleiben für jeden Schritt verbindlich; kein globaler Worker, neues Service-Secret oder zweiter Allokationspfad wird eingeführt. Die bestehenden tatsächlichen Release-Ereignisse und Pending-Outbox-Einträge teilen eine servergenerierte Correlation-ID. Keine neue Datenbankmigration ist nötig.

Diese Sammeloperation ist **nicht atomar über mehrere Pools**. Bei einem späten Konflikt oder ungewissen Ergebnis bleiben bereits bestätigte Freigaben bestehen; spätere Einträge werden nicht versucht. `200` bestätigt alle angeforderten lokalen Schritte, `207` unterscheidet `released`, `unconfirmed` und `not_attempted`. Unbestätigt heisst nicht zurückgerollt: bei verlorener Antwort aktuelle Zuweisungen und Historie lesen, nicht automatisch wiederholen. Entfällt die ursprüngliche Leseberechtigung, wird auch eine teilweise bereits ausgeführte Antwort zurückgehalten. Eine reaktivierte Person oder neu zugewiesene Lizenz wird nicht anhand eines alten Manifests erneut bearbeitet.

Dies ist der nutzbare lokale Lizenzschritt von WF-004, **keine abgeschlossene Offboarding-Automation**: keine implizite Kontosperre, kein eigenständiger Session-/Rollenentzug, keine Geräte-Rückgabemarkierung und keine externe Lizenzentfernung. Ein dauerhaftes dienstübergreifendes Workflow-Journal mit Wiederaufnahme ohne offenen Browser bleibt offen.

## Berechtigung und ursprüngliche Live-Quelle

`GET/POST /api/identity/company-licenses` löst den originalen signierten menschlichen Bearer auf. Aktuelle kanonische Identität, Home-Tenant mit Version/Generation, tatsächliche ursprüngliche Company-Ownership bzw. kanonisches Home-Admin und aktuelle Authentifizierungsregeln werden in der Identity-Datenbank geprüft. Unabhängig gebundene MFA darf höchstens 300 Sekunden alt sein; strengere aktuelle Regeln verkürzen die Frist. Rollen-/Permission-Claims, API Keys, Workloads und callergewählte Tenant-IDs ersetzen die Live-Quelle nicht.

Die drei tatsächlichen eigenen Fähigkeiten sind ausschliesslich:

- `company.apps.read`
- `company.apps.create`
- `company.apps.assign`

Die feste 62-Rollen-/Schema-6-Quelle bleibt unverändert. Ein Company-Owner wird **nicht** zum globalen `license-manager` oder Scope-/Provideradministrator. Auch tatsächliches `admin` bleibt bei diesen Quellen im eigenen Home-Tenant. Profilsuche und Verzeichnisstatusänderung behalten ihre eigenständige Berechtigung.

Die private Zielprojektion enthält nur UUID, Autorisierungs-/Eligibility-Revision, Enabled und Deleted. Retained Löschung ist ausdrücklich negativ mit `revision=null`; keine Profile oder Credentials werden geliefert. Die Policy-Seite bindet Issuer, Subject, Token-ID, Ablauf, Canonical Context, Tenant und ursprüngliche Deadline exakt an denselben Bearer. Revalidierung vor/nach Locks und DML verhindert Quellenersatz oder nachträgliche Erfolgsbehauptung. Dies ist kein dauerhaftes Zukunftsversprechen nach dem letzten Check oder ein atomarer Commit über zwei Datenbanken.

## Ein vorhandener Allocator, kein Governance-Bypass

Vor **jeder** Recipient-Eligibility wird der eigene Pool, die genaue Version und der unterstützte Zustand geprüft. Negative Company-Eligibility darf nicht den bisherigen globalen All-Pool-Reconciliation-Pfad auslösen. Innerhalb der Transaktion werden Ursprung, Subject-Locks, Pool-Lock, Quelle und Frist erneut bestätigt; erst danach arbeitet der unveränderte Allokationsmechanismus mit seinen Kapazitäts-, Grant- und Audit-Receivern.

Auch die Pool-Vorprüfung ausserhalb eines bestehenden Clients verwendet einen echten **Read-only-Repeatable-Read-Snapshot**. Die vorhandene volatile SQL-Receiptprüfung darf nicht einen gerade neu bestätigten Eventstand mit einer älteren Katalogzeile aus einem anderen Read-committed-Snapshot kombinieren. Ein paralleler gültiger Commit ist kein beschädigter Pool. Die wirkliche Schreibtransaktion prüft die erfasste Version weiterhin nach dem tatsächlichen Lock; diese Leseverbesserung schwächt keine Receiving-/Kapazitätsregel ab.

Der neue Company-Kontext ist **kein** Ersatz für einen bestehenden delegierten `LicenseScopeContext`. Beide Kontexte dürfen nicht zusammengesetzt werden. Bereits PIM-/Review-/Provider-/Gruppen-/Request-governierte Pools benötigen einen gesondert unterstützten Workflow und liefern hier `409`, statt bestehende Regeln zu löschen, eine Scope-Freigabe zu erfinden oder unabhängige Prüfungen zu umgehen. Die bisherigen SQL-PIM-/Review-/Kapazitätsprüfungen bleiben aktiv. Eigene Company-Governance und kombinierte Blueprints sind noch nicht fertig.

## Datenhoheit und Commit

**Policy-Migration 022** erweitert den vorhandenen `license_catalog` um nullable `business_tenant_id` und exakte BIGINT-`business_revision`. Neue Firmenpools erhalten eigene servergenerierte UUIDs und eine unveränderliche explizite Firma. Bestehende NULL-Pools bleiben Legacy; sie werden nicht aus Namen, Actor, Graph-Tenant oder aktuellem Login adoptiert. Ein Microsoft-Graph-Tenant ist kein OpenDirectory-Business-Tenant.

`license_subjects.business_tenant_id` schützt auch den gemeinsamen lokalen Eligibility-Spiegel vor fremder Lifecycle-/Error-Upsert-/Provider-Fan-out-Nebenwirkung. Ein vollständig unbenutzter leerer Legacy-Platzhalter kann anhand der ursprünglichen eigenen Quelle einmalig gebunden werden. Frühere Sperren, Directory-Zustände, Grants, Anträge, Provider- oder andere historische Legacy-Beteiligungen brauchen dagegen eine kontrollierte Migration. Nichts wird automatisch zurückgesetzt oder umgehängt.

`license_company_commands` hält die immutable ursprüngliche Quelle, Aktion, exakte Version, Deadline und Vorzustand. `license_company_origins` registriert die wirklichen SQL-Effekte des vorhandenen Allocators. Das abschliessende `license_company_events` enthält Typ/Version, Tenant, ursprünglichen Actor, Ziel, Correlation-ID und Before/After; die gleichnamige `license_company_outbox` ist zwingend tatsächlich `pending`.

Originaladmission, bestehende Receiver, tatsächliche Source-/Grant-/Projektions-/Audit-Effekte, einmalige Revisionserhöhung, historische Kette und ursprüngliche Deadline müssen am **physischen** Commit übereinstimmen. Fehlende/unterdrückte Effekte, Raw-DML, fremde Ziele, verlorene Receiver, gelöschte Scope-GUCs, frühere/spätere fremde Transaktionseffekte oder ein ausgelassenes finales Receipt erzeugen keinen erfolgreichen Commit. Reads prüfen retained Receipt und Kette, nicht nur das Vorhandensein einer Tabelle.

Tenant/User bleiben in der separaten Identity-Hoheit; es wird kein Cross-Database-FK behauptet. Der tatsächliche SQL-Owner bleibt ausdrücklich eine Betriebsvertrauensgrenze. Die Datenbank authentifiziert den Remote-Identity-Proof nicht unabhängig kryptografisch. Getrennte Least-Privilege-Runtime-/Operator-Logins, unabhängige Off-Host-Retention, kontrollierte Datenschutzlöschung und Produktionsabnahme sind weiterhin offen. Aktuelle Pools und Historie besitzen deshalb noch keinen allgemeinen Löschendpunkt.

## Legacy-Abgrenzung und Rollout

Die Legacy-Routen, Kompatibilitätsaliase, delegierten Scopes/Reviews und Hintergrund-/Fulfillment-Worker dürfen die neuen Firmenpools und gebundenen Subjects weder projizieren noch verändern. Poolprüfung erfolgt vor Quellzugriffen und Subject-Mutation; Listen, Child-ID-Lookups, Kandidaten und Error-Upserts besitzen eigene explizite NULL-Grenzen. Bisherige globale NULL-Ressourcen bleiben separat erhalten, nicht als jetzt vollständig mandantenfähige Company-Verwaltung erklärt. Der bisherige **Lizenz-Kiosk** ist kein Ersatz für den neuen eigenen Firmenkatalog.

Der ursprüngliche Katalog benötigt mindestens Policy **001–022** und Identity **001–044**. App-/Bestandskorrekturen verlangen zusätzlich Policy **024**, verbundenes lokales Offboarding Identity **045** und Policy **023**. Beide Images kopieren `packages/company-license-contract`; Policy zusätzlich den bestehenden Tenant-Vertrag. PostgreSQL, Original-Issuer-/Access-State-Konfiguration und `IDENTITY_SERVICE_URL` sind erforderlich; keine neuen Secrets oder Abhängigkeiten. `/api/licenses/company/capabilities` bestätigt weiterhin unverändert `companyLicenseProtocol:1`; der Client schreibt niemals über einen unbestätigten alten Receiver und wiederholt Schreibbefehle nicht automatisch.

Alle direkten Policy-/Identity-Consumer und betroffenen Images koordiniert aktualisieren; alte ungescopte Instanzen nicht parallel freigeben. Eine verlorene Antwort durch Readback, Bestand und Historie abgleichen, nicht blind neu anlegen. Ein allgemeines Idempotency-Key-Journal für neue Poolanlage ist noch offen. Migrations-/Docker-Konfiguration ist keine bereits erfolgte Deployment-, Restore- oder Lastabnahme.

## API und offene Anforderungen

Der [gemeinsame OpenAPI-3.1-Vertrag](../api/openapi.yaml) dokumentiert Capabilities, eigene Pool-Liste/-Erstellung/-Details, Assignment-Liste/-Zuweisung/-Entzug und Historie unter `/api/licenses/company`, zusätzlich die beiden originalen Identity-Quelloperationen. Exakter starker `"company-pool-UUID-revision"`-ETag für Zuweisung/Freigabe, `428` bei fehlender und `412` bei veralteter Version. Kapazität, Duplikate und kontrollierte Migrations-/Governance-Grenzen liefern `409`; fehlende/fremde eigene Ziele `404`. Seiten/Counts kommen aus einem Read-only-Repeatable-Read-Snapshot, Suche verwendet literale Teilzeichenfolgen.

`GET /api/licenses/company/users/{userId}/license-returns` liefert die paginierte Rückgabevorschau mit eigener minimaler Eligibility. `POST` auf denselben Pfad erwartet exakt `{reason,confirm:true,assignments:[{poolId,assignmentId,poolRevision}]}` mit 1–25 eindeutigen Pools/Zuweisungen. Hier trägt jede Zeile die exakte Revision anstelle eines gemeinsamen `If-Match`. Aktive Ziele werden mit `403` abgewiesen; kein pauschaler erfolgreicher Workflow-Status wird daraus abgeleitet.

Noch offen: versionierte App-Pakete/-Installationsquellen, allgemeine Archivierung/Löschung, Lizenzmodelle ausser endlichem Per-User, Ablauf/Reservation, Gruppen-/Geräte-/Blueprint-Zuweisung und Konflikte, eigene Rollen-/Scope-/PIM-/Review-Governance, vollständige JML-Automation, Kosten/OU-Reporting und Exporte, Herstellerabnahme und reale Provideraktionen. BR-005 bleibt `In Progress`. Siehe [Teilmodell](../architecture/domain-model.md), [ERD](../architecture/erd.md#firmen-lizenzinventar-policy-migration-022), [erste Abnahme](../testing/test-results.md#business-slice-12-eigenes-firmen-lizenzinventar) und [vollständigen Implementierungsstand](../implementation-status.md).

## App- und Bestandskorrekturen

Ein eigener berechtigter Owner/Home-Admin kann im ausgewählten Pool **App und Lizenzbestand bearbeiten**: Name, Hersteller, Beschreibung und endlichen lokalen Bestand. Der vorhandene `company.apps.create`-Katalogschreibweg bleibt auf die ursprüngliche eigene Firma mit aktueller menschlicher MFA beschränkt; keine globale Lizenzrolle oder neue behauptete Token-Permission. Eigene Custom-Rollen mit getrennten Create-/Edit-Rechten sind noch nicht implementiert.

Vor dem Öffnen des Editors prüft `GET /api/licenses/company/pools/{id}/edit-capabilities` den tatsächlichen neuen SQL-Receiver, die aktuelle eigene Authority, den unterstützten Pool und seine exakte Revision. Das separate `companyPoolEditProtocol:1` ändert weder die ursprünglichen drei Capabilities noch deren Protokoll. Eine alte Instanz ohne Migration 024 darf keine Editierfähigkeit behaupten.

Der Editor übernimmt die tatsächlich gelesenen Werte. Vorher/Nachher und Begründung werden vor dem Schreiben ausdrücklich bestätigt. `PATCH /api/licenses/company/pools/{id}` erwartet exakt `{name,vendor,description,totalSeats,reason,confirm:true}` und den ursprünglichen starken `If-Match`. Keine Änderung ergibt 409 statt leerer zusätzlicher Historie; fehlende Version 428, veraltete Version 412. Der Bestand bleibt zwischen 1 und 10'000 und darf die **tatsächlich vergebenen Plätze unter dem kanonischen Pool-Lock nicht unterschreiten**. Eine Reduktion entzieht keine Lizenz. Neue Allokationen und Korrekturen serialisieren denselben Poolstand; kein verlorenes Update oder Umgehen bestehender Governance.

Eine Änderung verwendet dieselbe bestehende Allocator-Transaktion: bedingte Original-Admission, genaue Katalogwirkung, bestehendes `pool-updated`-Audit mit ursprünglichem Actor sowie Vorher/Nachher/Begründung, genau eine neue Poolrevision, `app.license.pool.updated`-Event und zwingende Pending-Outbox. Migration **024** erweitert die vorhandenen Contracts/Receiver, ohne 022/023 oder deren retained Daten umzuschreiben. Benutzer/Subjects, Zuweisungen, Direct-Sources, Grants, Rollen, PIM/Reviews, Provider und Finanzdaten bleiben unverändert; keine neue Tabelle oder zweiter Allocator.

Nach Erfolg werden tatsächlicher Katalog und Historie neu gelesen, damit Umbenennung/Suchfilter/Sortierung keine alte Position als aktuell ausgeben. Unbestätigte oder verlorene Antworten erfordern Readback und Historienprüfung, keinen automatischen Schreibretry mit neuem ETag. Bereits bestätigte alte Pool-Snapshots und gefälschte Clientobjekte dürfen nicht zum Editieren weiterverwendet werden. Ältere Frontends können den zusätzlichen Eventtyp nicht auswerten; deshalb Images/Clients koordiniert aktualisieren. Alle Beträge sind lokale Bestandskorrekturen, **kein Lizenzkauf, keine Abrechnung oder Cloud-Installation**.

Physische SQL-Besitzer bleiben die explizite Vertrauensgrenze; getrennte Runtime-/Migrationslogins, unabhängige Archivierung und kontrollierter Lösch-/Datenschutzbetrieb bleiben offen. [Abnahme dieses Schritts](../testing/test-results.md#business-slice-16-app--und-bestandskorrekturen).
