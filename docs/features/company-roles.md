# Eigene Firmenrollen und Bereiche

Unter `/company-roles` verwalten ursprüngliche Firmeninhaber und kanonische Rollenadministratoren die eigenen Firmenrollen. `role-reader` erlaubt lesenden Zugriff auf Definitionen, Vergaben und Historie. Rollenrechte und Zielressourcen bleiben im tatsächlichen Home-Tenant des ursprünglichen menschlichen Bearbeiters.

## Bedienung

1. **Rolle erstellen**: Name, Beschreibung, konkrete Aktionen und maximale Vergabedauer wählen. Unterstützt sind die vierzehn bestehenden Verzeichnisaktionen für Benutzer, Gruppen und Organisationseinheiten. Begründung und ausdrückliche Bestätigung sind erforderlich.
2. Rolle öffnen → **Rolle vergeben**: aktive eigene Person oder geschützte Rollengruppe wählen. Mit separatem `users.read` unterstützt der Personenpicker serverseitige Suche und Seiten; ohne Profilrecht ist die bekannte kanonische Benutzer-ID erforderlich.
3. **Eigene Firma** erlaubt die ausgewählten Aktionen im eigenen Verzeichnis. **Organisationseinheit mit Untereinheiten** unterstützt ausschließlich `users.read`, `users.update` und `users.status.manage`. Die OU-Hierarchie wird im Picker als Pfad angezeigt. Der Scope gewährt keine Verwaltung der OU selbst.
4. Die konkrete Vergabe gilt zwischen einer Minute und zehn Stunden, höchstens bis zur in der Rolle festgelegten Grenze. Sie ergänzt bestehende kanonische Rechte. Bestehende globale Verzeichnisrechte werden dadurch nicht eingeschränkt. Das aktuelle Konto kann sich selbst keine Rolle vergeben.
5. **Definition bearbeiten** erzeugt eine neue Version. Jede Änderung, auch eine Deaktivierung, macht die bisherigen Vergaben dieser Definition unwirksam. Erneute Vergaben benötigen eine ausdrückliche neue Entscheidung. Die Oberfläche zeigt diesen Effekt vor der Bestätigung.
6. **Widerrufen** beendet genau die ausgewählte Vergabe. Datum, Empfänger, Scope und unveränderliche Historie bleiben erhalten. Eine verlorene oder widersprüchliche Antwort löst keine automatische Schreibwiederholung aus; ausdrücklich neu laden und anhand des aktuellen Standes entscheiden.

**Rollengruppe erstellen** erzeugt eine neue statische Gruppe. Bestehende Gruppen werden nicht umgewandelt. Ihre Mitglieder lassen sich unter People → Gruppen mit zusätzlicher normaler Gruppenmitgliedschaftsberechtigung verwalten; außerdem sind ein tatsächlicher Rollenverwalter und frische MFA erforderlich. Auch ein Rollenverwalter darf sich nicht nachträglich selbst als Mitglied hinzufügen und damit die Selbstvergabe-Sperre umgehen. Dynamische Regeln für solche Gruppen werden abgewiesen.

Eine Gruppenvergabe ist eine aktuelle Vergabe an die Gruppe; individuelle Rechte entstehen über wirksame kanonische Mitgliedschaften und deren aktuelle Reviews. Abgelaufene, gesperrte, entfernte oder durch eine geänderte Eligibility-Generation ungültige Mitgliedschaften werden nicht als Rechtequelle verwendet. Eine direkte Benutzervergabe bindet die tatsächliche Eligibility-Revision und lebt nach einer Sperrung/Reaktivierung nicht automatisch wieder auf. Statusänderungen am eigenen Konto benötigen einen anderen berechtigten Bearbeiter.

Sobald eine OU als Rollenscope verwendet wird, benötigen Änderungen ihrer geschützten Hierarchie und Mitgliedschaften ebenfalls einen tatsächlichen Rollenverwalter mit frischer MFA. Ein gewöhnlicher OU- oder Gruppenadministrator kann seinen Bereich dadurch nicht selbst vergrößern. Die Marker bleiben auch nach Ablauf einer Vergabe erhalten; Schutzaufhebung und konvertierte Altgruppen sind nicht implementiert.

## Tatsächliche Autorisierung

Eigene Rollennamen erscheinen nicht als künstliche globale Rollen in OAuth-Tokens. Die API löst Definition, aktuelle Version, eigenen Tenant, unveränderte Zielgeneration, Ablauf, Widerruf und gegebenenfalls ursprüngliche Mitgliedschaft/Review live in der Identity-Datenbank auf. Bestehende globale `RoleState`-/Issuer-Verträge und ihre Rollenrevision bleiben unverändert.

Zusätzliche Firmen-Verzeichnisrechte verlangen eine unabhängig gebundene MFA-Anmeldung innerhalb der letzten fünf Minuten. Eine zehnstündige Vergabe verlängert dieses Authentifizierungsfenster nicht. Änderungen an Definitionen, Vergaben und geschützten Strukturen verlangen dieselbe frische MFA. Diese Version stellt zeitlich begrenzte aktive Vergaben bereit; selbst aktivierbare PIM-Eligibilities für eigene Rollendefinitionen sind noch offen. Die bestehenden PIM-Aufgaben für kanonische Plattformrollen bleiben getrennt.

Listen, Suchergebnisse, Gesamtzahlen und Details werden serverseitig nach dem tatsächlichen Benutzerbereich gefiltert. Ein fremdes Benutzerprofil außerhalb des Scopes wird nicht durch direkte IDs, Personen-Gruppenansichten oder die globale Suche lesbar. OU-Mitgliederprofile erscheinen nur bei zusätzlichem Profilrecht für die ganze angefragte Einheit; sonst bleiben die bereits separat erlaubten Mitgliedschaftsreferenzen ohne Profildaten. `groups.read` und `ous.read` sind weiterhin eigene, tenantweite Strukturrechte und dürfen nicht mit einem Benutzer-OU-Scope verwechselt werden.

Die vorhandenen `DirectoryCreator`-, `UserMutator`-, `GroupMutator`- und `OuMutator`-Kerne schreiben weiterhin ihre echten Ressourcen. Konfigurierte Firmenrollen ergänzen eine gemeinsame Tenant-Schreibgrenze vor den Benutzer-/Baum-Locks. Damit serialisieren Rollenänderungen und normale Verzeichnisänderungen desselben Tenants. Lastabnahme und eine feinere Lockaufteilung bleiben gesonderte Betriebsarbeit.

Jeder delegierte oder durch Rollengovernance geschützte Schreibzugriff erhält einen unveränderlichen `identity_company_role_uses`-Beleg mit ursprünglichem Proof, genauer Ressource und Transaktion. Am physischen Commit werden Quelle, unverlängerte ursprüngliche Deadline, tatsächliche bestehende Ressourceneffekte und deren Outbox-Belege erneut geprüft. Ein abgelaufener Nachweis, verschwundener Receiver, geänderter Quellzustand oder vorgetäuschter erfolgreicher Admission-Aufruf verhindert den Commit. Schutzmarker, Definitionen und Vergaben haben Row-/Truncate-Guards und versiegelte SQL-Receiver. Die neuen SQL-Hilfsfunktionen sind nicht öffentlich ausführbar. Der privilegierte Datenbankbetreiber bleibt eine Vertrauensgrenze; dies ersetzt kein vollständiges Least-Privilege-DB-Loginmodell.

## Versionierte Schnittstellen und Protokoll

Die [OpenAPI-3.1-Datei](../api/openapi.yaml) dokumentiert `companyRolesProtocol: 1` und die tatsächlichen Request-/Response-Schemata. Jede Verwaltungsroute verlangt den ursprünglichen menschlichen Bearer; Workload- und API-Key-Ersatz werden nicht akzeptiert.

- `GET/POST /api/identity/company-roles`: eigene Definitionen lesen/erstellen.
- `GET/PUT /api/identity/company-roles/:id`: Definition und paginierte Vergaben lesen bzw. Definition versionieren.
- `POST /api/identity/company-roles/:id/grants`: ursprüngliche Definitionsversion einer eigenen Person oder geschützten Gruppe befristet vergeben.
- `POST /api/identity/company-roles/grants/:id/revoke`: genaue Vergabe widerrufen.
- `GET /api/identity/company-roles/:id/history`: tatsächliche Kontrollhistorie, 25 Einträge je Seite.
- `POST /api/identity/company-roles/groups`: neue geschützte statische Rollengruppe erstellen.

Definitionen und Vergaben haben getrennte starke ETags: `"company-role-UUID-revision"` bzw. `"company-grant-UUID-revision"`. Beim Vergaben benötigt `If-Match` die aktuelle Definitionsversion; beim Widerruf die tatsächliche Vergabenversion. `428` bedeutet fehlende Vorbedingung/frische MFA, `412` eine veraltete Version, `404` ein fehlendes eigenes Ziel und `403` fehlende aktuelle Zuständigkeit. Kein Tenant-Override in Query oder Body.

Definition, Vergabe, Widerruf und Gruppenschutz speichern ursprünglichen Akteur, Begründung, Datum sowie tatsächliche Vorher-/Nachher-Stände gemeinsam mit obligatorischer lokaler Pending-Outbox. Die GUI-Historie zeigt die Kontrollaktion und den ausstehenden Zustellstatus. Pending ist keine ausgelieferte externe Wirkung. Fehlgeschlagene HTTP-Aufrufe bleiben Fehler und erzeugen keinen behaupteten erfolgreichen Rollenwechsel.

## Abgrenzung des Gesamtauftrags

Noch offen sind selbst aktivierbare eigene PIM-Rollen/-Bereiche, weitere delegierbare Dienstaktionen etwa für Lizenzen und Geräte, explizite Schutzaufhebung, vollständige delegierte Reviews, kontrollierte Altbestandsübernahme und Betriebs-/Lastabnahmen. SCIM, Provider-Provisionierung, vollständige JML-Prozesse und die übrigen Geschäftsanforderungen werden durch diese Rolle nicht als erledigt erklärt. Keine menschlichen Produktionsrechte oder MFA-Nachweise wurden für die Tests erfunden; positive OAuth-/Browser-/PostgreSQL-Prüfungen verwenden getrennte Testkonten und Datenbanken.
