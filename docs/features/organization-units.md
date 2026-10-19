# Mandantengebundene Organisationseinheiten

Stand: 19. Oktober 2026. Dieser Slice ersetzt die alten ungescopten OU-PUT/DELETE-Handler durch tatsächliche kanonische Änderungen. Eigene Einheiten können erstellt, bearbeitet, verschoben und nach Bestätigung als Blatt gelöscht werden. Der anschliessende [Membership-Slice](organization-memberships.md) ergänzt echte mehrfache Mitarbeitenden-Zuordnungen; vollständige Organisations-/Scope-Governance und verbundene JML-Prozesse bleiben offen.

## Benutzerweg

1. Mit dem tatsächlichen [Company-Owner](company-activation.md) und Pflicht-MFA `/organization` öffnen.
2. In der **Organisationsstruktur** eine vorhandene eigene Einheit über **Bearbeiten / Verschieben** auswählen.
3. Namen/Beschreibung ändern oder eine eigene übergeordnete Einheit auswählen; **Keine** verschiebt sie auf die oberste Ebene. Selbst und Nachfahren werden nicht als Eltern angeboten. Der Server prüft die tatsächliche Hierarchie unabhängig davon erneut.
4. **Organisationseinheit speichern** bindet die angezeigte Version. Andere Bearbeitungen werden nicht still überschrieben; bei `412` ausdrücklich neu laden.
5. **Löschen** öffnet einen Bestätigungsdialog. Einheiten mit Kindern oder aktiven Mitarbeitenden-Zuordnungen sind gesperrt; die API verweigert deren Löschung ebenfalls. Kinder und Mitglieder werden weder automatisch umgehängt noch kaskadierend entfernt.

Schlägt die Bestätigung fehl, entfernt die Oberfläche alte Aktionsdaten und verlangt explizites Neuladen. Keine automatischen Schreibwiederholungen oder erfundenen Erfolge. Eine fehlende Mutation-Capability oder Datensatzversion aktiviert keine Legacy-Schreibabkürzung.

## Berechtigung und Grenzen

Der ursprüngliche aktive Owner erhält `ous.update` und `ous.delete` zusätzlich zu seinen [eigenen Verzeichnisrechten](company-directory.md), nicht als globale Rolle. Owner-Rechte kommen aus der aktuellen eigenen Ressource und benötigen unabhängig gebundene MFA höchstens 300 Sekunden alt. Bestehende explizite OU-Verzeichnisrollen folgen ihrer kanonischen Authentifizierungsrichtlinie. Profildelegierte erhalten weiterhin keinerlei Verzeichnisrechte.

Route-ACL, ursprüngliche Issuer-/Actor-/Tenant-Quelle, Controller und private SQL-Receiver bleiben getrennte Prüfungen. Auch `admin` kann über diese Endpunkte keine fremden OUs ändern oder fremde Eltern auswählen. Tenant-/Actor-Selektoren werden nicht aus einem Request übernommen. Behauptete Owner-/Permission-Claims ersetzen keinen tatsächlichen Nachweis. Die 62 Rollennamen und Schema 6 bleiben unverändert; der Membership-Slice ergänzt nur die präzise Aufgabe `ous.members.manage` beim tatsächlichen Owner und bestehenden OU-Verwalter. Die allgemeine versiegelte eigene Rollenquelle wird dadurch nicht aktiviert.

Alle kanonischen OU-Schreibaktionen benutzen denselben Tenant-Tree-Advisory-Lock vor dem Actor-Lock. Änderungen sperren die begrenzte eigene aktive OU-Menge in stabiler Reihenfolge. Erstellung prüft ihre tatsächlichen Ahnen zusätzlich unter Share-Locks. Gegenläufige Verschiebungen sowie konkurrierende Erstellung/Löschung werden nach tatsächlichem Warten erneut ausgewertet. Die eigene resultierende Gesamtstruktur muss vollständig, azyklisch und höchstens 256 Ebenen tief sein. Mehr als 10'000 aktive Einheiten werden nicht als unterstützte vollständige Mutation verarbeitet. Serverseitige OU-/Gruppenpagination und Lastabnahme bleiben offen.

## Migration und API

Der OU-Schreibkernel beginnt mit **042_directory_ou_mutations.sql**; der aktuelle kombinierte Stand benötigt Migrationen bis **043_ou_memberships.sql** und koordinierten Identity-/Web-Code. Keine neuen Secrets oder Betreiber-Flags. Registration/Activation bleiben separat standardmässig aus. Die Migrationen sind keine automatische Reparatur alter Hierarchien, Rehoming oder nachträgliche Rekonstruktion historischer Änderungen.

`ous.revision` ist ein positiver serverseitiger BIGINT. Bestehende Zeilen erhalten eine Anfangsversion; es wird keine frühere Audit-Historie erfunden. Versionen bleiben in API und ETag Strings. Clients müssen vor einer Änderung aktuell lesen und einen exakten starken `"ou-UUID-revision"`-ETag senden. Fehlender `If-Match` ergibt `428`, ein veralteter `412`; keine Wildcards. Die bisherigen internen unbenutzten OU-Methoden in `groupApi` sind entfernt, damit die Oberfläche nicht versehentlich den unversionierten Adapter wiederverwendet.

Tatsächlich implementiert und im gemeinsamen [OpenAPI 3.1, aktuell Version 1.8.0](../api/openapi.yaml) dokumentiert:

- `GET /api/ous`, `POST /api/ous`, `GET /api/ous/{id}`.
- `PUT /api/ous/{id}` mit einem oder mehreren exakten Feldern `name`, `description`, `parentId`; `null` entfernt einen Parent.
- `DELETE /api/ous/{id}` mit leerem Body/Query und exakter Version.
- `GET /api/identity/access` kündigt den neuen Vertrag als `directoryOuMutationProtocol:1` an. Aktuelle tatsächliche Receiving-Abhängigkeiten werden geprüft, bevor eigene Owner-Verzeichnisrechte freigegeben werden.

Erfolgreiche Reads/Änderungen liefern die aktuelle Revision; Detail, Creation und Update setzen den ETag. Ein fehlender oder fremder kanonischer Zielbezeichner wird nicht durch globale Suche aufgelöst. Es gibt keinen In-Memory-Schreibfallback.

## Tatsächlicher SQL-Commit und Historie

`identity_directory_ou_events` speichert Event-ID, Tenant, OU-ID, Typ (`organization-unit.updated`/`.deleted`), Version 1, Correlation-ID, ursprünglichen menschlichen Actor/Proof, genaue Vorher-/Nachherzustände, Frist und eindeutige Transaktion. Vor der tatsächlichen Änderung wird der unveränderliche Event-Origin persistiert. `identity_directory_ou_outbox` bindet dieselbe Event-ID als **pending**, nicht als behauptet zugestellt.

`identity_directory_ou_creations` hält zusätzlich den ursprünglichen Erstellungsnachweis, bevor der neue Namespace geschrieben wird. Das bestehende 026-Ownership-/Creation-Event-/Outbox-Protokoll bleibt erforderlich. Ein gelöschtes GUC, ausgelassener Beleg, falscher Effekt, unbestätigte Hierarchie oder die abgelaufene ursprüngliche Frist darf am tatsächlichen Commit keinen Erfolg erzeugen. Neue Canonical-No-effects-/Truncate-Grenzen verhindern, dass andere Änderungen die OU-Operation mitbenutzen. Die älteren Receiving-/No-effects-Grenzen gelten auch auf den neuen Tabellen.

OU-Row-Snapshots und der bereits gemeinsam verwendete SQL-Rollen-Snapshot werden in UTC erzeugt, nicht abhängig von der Session-Zeitzone. Der Inhalt bleibt genau gebunden; die Prüfung wird nicht durch Entfernen von Zeitstempeln oder Rollenbelegen abgeschwächt. Laufende alte Proof-Transaktionen dürfen beim Upgrade scheitern statt mit einem anderen Snapshot still fortzufahren.

Bei Retirement bleiben Eigentumsnamespace, negativer Tenant-Beleg, ursprüngliche Creation-Admission, Mutationsevent und Pending-Outbox erhalten. Es gibt keinen stillen UUID-Reuse. Das ist kein Off-host-Archiv, Datenschutz-/Retention-Löschprozess oder fertiggestelltes Least-Privilege-Datenbankloginmodell. Ein tatsächlich privilegierter Datenbankoperator bleibt eine Betriebsvertrauensgrenze; Roh-SQL ist keine Tenant-Administrator-API.

## Nachweis und nächste Arbeit

[Abnahme des begrenzten Slice](../testing/test-results.md#business-slice-8-kanonische-ou-änderungen): tatsächliche getrennte Mandanten, roleloser Owner, gerichtete Versionen und Eltern, reale Source-/Proof-/Belegverluste, physischer Ablauf und beobachtete konkurrierende SQL-Wartezustände. Zusätzlich führt ein echter frischer Chrome Änderungen, Verschiebungen, Stale-Write-Abweisung und bestätigte Blattlöschung über die bestehende Issuer-/Gateway-/Identity-/PostgreSQL-Kette aus. Das ist keine Produktions- oder vollständige WCAG-Abnahme.

Der anschliessende [Membership-Slice](organization-memberships.md) implementiert echte mehrfache Benutzer-OU-Beziehungen und kontrollierte Löschabhängigkeiten. Als Nächstes fehlen Rollen-/Scope-Vererbung und die verbundenen Mitarbeitenden-/Geräte-/Blueprint-/App-/Lizenzprozesse. Ein Freitextfeld `department` wird nicht als solche Mitgliedschaft ausgegeben. Weitere Master-Prompt-Domains und Betriebsabnahmen bleiben offen; 17 bekannte TypeScript-Diagnosen verhindern weiterhin die Build-Abnahme. Keine externe Produktivschreiboperation, kein Commit, Push oder Deployment ist Bestandteil dieses Slice.
