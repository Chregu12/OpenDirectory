# Eigener Mitarbeiter-Austritt: Konto und lokale Lizenzen

Stand: 19. Oktober 2026. **Tested, begrenzter Teil von WF-004**, kein vollständiger Austrittsprozess. Unter `/applications` verbindet „Mitarbeiter-Offboarding“ eine echte kanonische Kontosperre mit der Rückgabe der dabei erfassten eigenen lokalen Lizenzzuweisungen. Der Personenbereich verlinkt mit der Ziel-ID dorthin. Bestehender Identity-Mutator und Lizenz-Allocator bleiben die einzigen Schreiber ihrer jeweiligen Fachdaten.

Der anschliessende [Rollen-/PIM-Teilprozess](company-offboarding-access.md) verwendet denselben negativen Account-Checkpoint mit eigenständigen kanonischen Pflichten. Er ist auch separat für wirklich berechtigte Rollen-/PIM-Bearbeitende erreichbar; Firmen-Ownership gewährt diese Pflichten nicht. Dieser Folgeschritt ändert nicht den historischen Abschlussumfang von Konto und lokalen Lizenzen.

Ein weiterer [Geräte-Folgeschritt](device-returns.md) fordert die Rückgabe genau ausgewählter wirklicher Zuweisungen an. Die Zuweisung bleibt bis zur separat bestätigten manuellen Übergabe bestehen. Operative Rückgabeaufträge sind unabhängig unter `/device-returns` verwaltbar; auch dieser Schritt macht `completed_local` nicht zum vollständigen WF-004.

## Benutzerweg

1. Tatsächlicher eigener Company-Owner oder kanonisches Home-Admin meldet sich mit unabhängig bestätigter frischer MFA an. Keine neue globale Rolle; die drei bestehenden Company-App-Fähigkeiten bleiben unverändert.
2. Eigene Mitarbeiter-ID auswählen bzw. aus dem Personenbereich übernehmen. Vorschau lädt echten Namen, Kontostatus, Datensatz-/Eligibility-Version und Anzahl eigener lokaler Zuweisungen; keine Mutation.
3. Begründung eingeben und Kontosperre samt lokaler Rückgabe ausdrücklich bestätigen. Selbst-Offboarding wird abgewiesen; bereits gelöschte Ziele nutzen den bestehenden manuellen Rückgabeweg.
4. Der Server speichert den unveränderlichen Auftrag. Identity sperrt das kanonische Konto bedingt und liefert einen dauerhaft gespeicherten Beleg. Ein bereits gesperrtes Konto wird nur beobachtet, nicht erneut geändert.
5. Nach Bestätigung der unveränderten negativen Eligibility erfasst der Server die tatsächlich vorhandenen eigenen lokalen Assignment-/Grant-Inkarnationen. Höchstens 25 werden pro Aufruf über den bestehenden Allocator freigegeben; nach jedem bestätigten Schritt wird der Fortschritt gespeichert.
6. Weitere Seiten und pausierte Schritte benötigen erneute bewusste Bestätigung mit aktueller eigener Authority, frischer MFA, Vorgangs-ETag und den exakt sichtbaren Assignment-/Poolversionen. Kein unbeaufsichtigter Hintergrundschreiber.
7. Gespeicherte Vorgänge und ihre paginierte Historie lassen sich nach Neuladen bzw. neuer Anmeldung abrufen. Der lokale Abschluss ist historisch, kein vollständiges Offboarding oder für immer gesperrter Benutzer.

## Zustände und Wiederaufnahme

Zustände: `pending`, `licenses`, `paused`, `completed_local`. Fehler enthalten den tatsächlichen Schritt `account`, `capture`, `licenses` oder `verify` und Statuscode. Ein fortgesetzter Aufruf darf Fortschritt nicht zurücksetzen oder neue Grants stillschweigend übernehmen. Aktueller Zielstatus und historischer Abschluss werden getrennt dargestellt.

Die Client-UUID ist ein **tenantgebundener Idempotenzschlüssel, keine Berechtigung**. Erneutes Erstellen mit demselben unveränderten Intent liest nur den gespeicherten Stand; anderer Intent ergibt 409. Kein automatischer Schreibretry nach verlorenem Ergebnis. `localStorage` hält höchstens die undurchsichtige Wiederaufnahme-ID, keine Tokens oder Erfolgsmarker.

Ein unbekanntes Kontosperr-Ergebnis wird anhand der ursprünglichen Identity-Anfrage und ihres Belegs wiedergefunden. Nur ein belegter 412 vor dem Account-Checkpoint erlaubt eine ausdrücklich geprüfte neue Datensatzversion bei unveränderter ursprünglicher Eligibility. Autorisierungs-, Directory-Datensatz- und Eligibility-Revision sind unterschiedliche exakte BIGINT-Strings. Die globale Eligibility-Sequenz muss nicht um eins steigen.

Eine reale Lizenzfreigabe mit anschliessend verlorenem Journal-ACK wird anhand des retained Original-Events erkannt. Ursprüngliche Assignment-/Grant-Inkarnation und reale Release-Wirkung müssen übereinstimmen; ein späterer Regrant wird nicht freigegeben. Geänderte Pools benötigen sichtbare erneute Versionsbestätigung. `completed_local` verlangt zusätzlich tatsächlich keine verbleibende eigene lokale Zuweisung; unerfasst neue Zuweisungen verhindern den Abschluss. Über 10'000 zu erfassende Zuweisungen benötigen einen separat geprüften grösseren Prozess.

## API

Basis: `/api/licenses/company`.

| Methode/Pfad relativ zur Basis | Funktion |
| --- | --- |
| `GET /offboarding-workflows/capabilities` | Protokoll 1, Umfang `account-and-local-licenses` |
| `GET /users/{userId}/offboarding-preview` | Eigene aktuelle Person und tatsächlicher lokaler Lizenzbedarf |
| `POST /offboarding-workflows` | Bestätigten Auftrag anlegen und erste höchstens 25 Schritte ausführen |
| `GET /offboarding-workflows` | Eigene gespeicherte Vorgänge mit Pagination |
| `GET /offboarding-workflows/{id}` | Arbeitsstand und starker `company-offboarding-UUID-revision`-ETag |
| `POST /offboarding-workflows/{id}/continue` | Exakter `If-Match`, ursprüngliche unveränderliche Begründung und sichtbare nächste Seite |
| `GET /offboarding-workflows/{id}/history` | Retained Übergänge und tatsächlicher Pending-Status |

Identity stellt zusätzlich `POST /api/users/{id}/company-offboarding` für den internen Bridge-Aufruf mit ursprünglichem menschlichem Bearer bereit; kein Service-Account-Ersatz. Der Bridge verlangt auch die tatsächlichen kanonischen Rechte `users.update` und `users.status.manage`. Exakte DTOs/Fehler/Versionsheader stehen im generierten [OpenAPI-3.1-Vertrag](../api/openapi.yaml).

Alle Wege prüfen serverseitig eigene ursprüngliche Authority vor/nach der Arbeit. Body-Tenant, JWT-Rollenalias oder Vorgangsschlüssel gewähren keine Hoheit. MFA-Deadline höchstens 300 Sekunden, nie beim internen Hop verlängert. Fehlende/alte/fremde Quellen, Belege oder Receiver sperren; kein Downgrade/globaler Fallback.

## Datenhoheit und Transaktionen

- Identity **045**: `identity_company_offboarding_receipts`, zwingende Pending-Outbox und interne Commit-Checks. `(tenant_id,workflow_id)` ist eindeutig; tatsächliche Sperren referenzieren das bestehende Directory-User-Event. `already_disabled` besitzt keine erfundene Operation-ID. Original-Actor, Before-/After-Revisionen und Zeit bleiben unveränderlich.
- Policy **023**: `company_offboarding_jobs`, append-only `company_offboarding_events` und Pending-Outbox. Job-Schlüssel `(tenant_id,id)`, monotoner exakter Versionsstand, immutable Intent, erfasste Mitgliedschaft und pro Schritt tatsächliche Belege. JSON-Checkpoint ist ein Ausführungsjournal, kein zweiter Benutzer-/Lizenzbestand.
- Ein dedizierter Session-Advisory-Lock serialisiert denselben Tenant/Vorgang. Kurze Journal-Transaktionen prüfen Originalquelle, Deadline, physische Receiving-/Effect-/Commit-Grenzen und retained Kette. Unlock-Fehler zerstören die Verbindung statt einen Lock im Pool zu hinterlassen.
- Account-Sperre, jede Allocator-Freigabe und jeder Journalfortschritt sind **getrennte Commits**. Bereits committed Sperren/Freigaben bleiben bei späteren Fehlern wirksam und werden aus echten Belegen wiedergefunden. Bei verlorener Authority kann eine Antwort ausbleiben, obwohl ein früherer Schritt committed ist.
- Keine gespeicherten Bearer/Refresh-Tokens, automatisches Wiederanmelden oder unbeschränktes Workload-Konto. SQL-Besitzer ist die explizite Vertrauensgrenze; DDL-/Trigger-kontrollierende Datenbankbesitzer sind kein abgewehrter Angreifer. Getrennte Runtime-/Migrationslogins und unabhängige Archivierung bleiben Betriebsabnahmen.

Normale Raw-Änderungen/Löschungen/Truncate dürfen die retained Belegkette nicht entfernen. Allgemeiner Privacy-/Aufbewahrungs-/Löschworkflow bleibt offen. Pending-Outbox bedeutet lokal ausstehende Zustellung, keine bestätigte externe Verarbeitung.

## Bewusste Grenzen

Die kanonische Sperre macht Zugriffe an den vorhandenen aktuellen Account-/Authority-Fences ungültig; kein zusätzlicher vollständiger Session-Inventar-/Revocation-Workflow. Externe Credentials werden nicht gelöscht. Der ursprüngliche Account-/Lizenzablauf entfernt keine Gruppen automatisch; dafür gibt es den unten beschriebenen separat bestätigten Folgeschritt. Rollen/PIM, OU-Zuordnungen, Gerätezuweisungen, Rückgabe, Lock/Wipe, Providerlizenzen, App-Installationen und Abrechnung bleiben unverändert. Retained gelöschte Benutzer nutzen die getrennte [manuelle Lizenzrückgabe](company-licenses.md#kontrollierte-lizenzrückgabe-beim-austritt). Kein Remote-/Herstellererfolg wird simuliert.

[Abnahme](../testing/test-results.md#business-slice-15-dauerhaftes-lokales-mitarbeiter-offboarding), [ERD](../architecture/erd.md#dauerhaftes-lokales-offboarding-identity-045-und-policy-023), [Installation](../operations/installation.md#dauerhaftes-lokales-mitarbeiter-offboarding). WF-004 und BR-002/005 bleiben insgesamt `In Progress`.

## Gruppen beim Austritt entfernen

Nach der belegten kanonischen Kontosperre lässt sich im gespeicherten Austrittsprozess ein **separater bestätigter Gruppen-Folgeschritt** öffnen. Der Account-/Lizenz-Checkpoint bleibt unverändert: `completed_local` wird nicht nachträglich als vollständiger Berechtigungsentzug umgedeutet. Rollenentzug braucht eine eigenständige kanonische Berechtigung; ein Firmen-Owner erhält nicht stillschweigend globale Rollenadministration.

Der Gruppenschritt ist auch bei noch offenen oder pausierten lokalen Lizenzrückgaben verfügbar. Ein Lizenzkonflikt darf den separat autorisierten Gruppenentzug nicht blockieren. Umgekehrt wird keine Lizenzfreigabe aus einem erfolgreichen Gruppenentzug abgeleitet. Die geänderte kanonische Mitgliedschaft ist belegt; eine noch fehlende allgemeine gruppenbasierte Rollenberechnung wird dadurch nicht als implementiert behauptet.

1. Einen gespeicherten Vorgang mit weiterhin gesperrtem Benutzer und genau derselben ursprünglichen negativen Eligibility laden. Bei neuer Kontogeneration ist ein neuer geprüfter Vorgang erforderlich.
2. „Gruppen beim Austritt entfernen“ ausdrücklich öffnen. Die echte Vorschau zeigt bis zu 25 aktuelle eigene Gruppenlinks mit Name, genauer Gruppenrevision und Membership-ID. Die Vorschau schreibt nichts und bezieht keine fremden Gruppenprofile ein.
3. Begründung eingeben und genau diese sichtbaren Mitgliedschaftsinkarnationen bestätigen. Weitere Seiten werden nicht automatisch bearbeitet.
4. Der Server prüft zuerst das vollständige Manifest, bevor der erste Entzug beginnt. Jeder Child-Schritt verwendet den bestehenden kanonischen `GroupMutator`, ursprünglichen menschlichen Actor, aktuelle eigene Authority und unabhängig bestätigte MFA. Keine alternative direkte Löschroutine oder globale Rollenabkürzung.
5. Jeder erfolgreiche Child-Entzug speichert tatsächliche Gruppenereignisse/Outbox und einen unveränderlichen zum Account-Checkpoint gehörenden Beleg. Bei späteren Fehlern bleiben frühere Child-Commits wirksam. Nach ungewissem Ergebnis tatsächliche Vorschau und Historie neu laden, nicht automatisch wiederholen.

Ein verlorenes Ergebnis kann über den gültigen Original-Beleg der alten Membership-ID als `already_removed` wiedergefunden werden, ohne nochmals zu mutieren. Ein neuer Link ist eine andere Inkarnation und wird durch den alten Auftrag nicht entfernt. Gruppenrevision, Membership-ID und ursprüngliche negative Eligibility müssen stimmen; kein stilles Aktualisieren dieser Werte beim Schreiben.

Neue Identity-Operationen: `GET` und `POST /api/users/{id}/company-offboarding-groups`, `GET /api/users/{id}/company-offboarding-groups/history`. Lesen verlangt tatsächliches `groups.read`, Schreiben zusätzlich `groups.members.manage`, eigene Company-Hoheit und frische MFA. Pflichtselektor `workflowId` bindet Lesen/Schreiben an den echten unveränderten Identity-Account-Beleg aus Migration 045; eine UUID ist keine Berechtigung. Seiten haben genau 25 Plätze. [Exakte DTOs](../api/openapi.yaml).

POST erwartet nur `{workflowId,eligibilityRevision,reason,confirm:true,memberships:[{groupId,groupRevision,membershipId}]}` mit 1–25 eindeutigen Gruppen/Links. `200` bestätigt alle angeforderten alten Inkarnationen als `removed`/`already_removed`. Bei `207` ist ein Schritt `unconfirmed`, spätere sind `not_attempted`. Ein unbestätigter Schritt stoppt weitere Arbeit; nach verlorenem Originalzugriff darf selbst die Teilantwort ausbleiben. Kein verteilter Rollback und kein Hintergrundschreiber.

Identity **046** ergänzt zum tatsächlichen Gruppen-Child gehörende retained Belege und Pending-Zustellung. Gruppenbestand, Versionierung und Original-Effect-/Commit-Kernel bleiben die Datenhoheit. Originalquellenverlust, geänderte Kontogeneration, fremder Parent, überholte Gruppe oder ersetzte Membership sperren. SQL-Besitzer bleiben die explizite Vertrauensgrenze; DDL-kontrollierende Betreiber werden nicht als abgewehrte Angreifer ausgegeben. Aufbewahrungs-/Privacy-/Restore-/Runtime-Login-Abnahme bleibt offen.

Eine leere neue Vorschauseite bedeutet nur: derzeit keine weiteren sichtbaren Gruppenlinks im bestätigten Bereich. **Rollen, PIM-Eligibilities, OU-Zuordnungen, vollständige Sessions, externe Credentials, Geräte und Provider werden nicht entfernt.** Historie benötigt weiterhin einen eigenen live vorhandenen gesperrten Benutzer mit ursprünglichem Account-Checkpoint; spätere Gruppenlöschungen dürfen ursprüngliche Namen/Child-Belege nicht umschreiben. [Abnahme](../testing/test-results.md#business-slice-17-kontrollierter-gruppenentzug-beim-austritt).
