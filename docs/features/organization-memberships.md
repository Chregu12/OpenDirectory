# Echte Mitarbeitenden-OU-Zuordnungen

Stand: 19. Oktober 2026. Begrenzter vertikaler Slice für BR-001.07: eine eigene Person kann mehreren eigenen Organisationseinheiten angehören. PostgreSQL-Beziehung, serverseitige Berechtigung, bedingte API, echte Namenssuche und bestätigter Entzug sind verbunden. Keine automatische Rollen-, Blueprint-, Geräte- oder Lizenzvererbung und kein vollständiger Joiner-Mover-Leaver-Prozess.

## Einfacher Benutzerweg

1. Mit dem tatsächlichen [Company-Owner](company-activation.md) und frischer Pflicht-MFA unter `/organization` die **Mitglieder** einer Einheit öffnen.
2. Nach Name, Benutzername oder E-Mail suchen, einen tatsächlichen eigenen Mitarbeitenden auswählen und **Zuordnung hinzufügen**. Auch gesperrte Verzeichniseinträge sind zuordenbar; sie werden dadurch nicht freigeschaltet.
3. Die gleiche Person einer zweiten Einheit zuordnen. Beide Beziehungen besitzen eigene servergenerierte IDs.
4. **Zuordnung entfernen** öffnet eine Bestätigung für genau diese Beziehung. Andere OU-Mitgliedschaften und separat verwaltete Gruppen, Rollen und Lizenzen bleiben unverändert.
5. Zur Struktur zurückkehren: echte Mitgliedszahlen werden neu geladen. Eine Einheit mit Kindern oder Mitgliedern kann nicht gelöscht werden. Auch die kanonische Benutzerlöschung verweigert aktive OU-Abhängigkeiten mit `409`, bis diese ausdrücklich entfernt sind.

Die Liste besitzt echte serverseitige Pagination mit 25 Einträgen je UI-Seite. Namenssuche verwendet die bestehende eigene Personen-API, nur nach Eingabe und nur mit unabhängigem `users.read`. Ohne dieses Recht werden keine Profile geladen oder ausgeliefert; ein berechtigter OU-Verwalter kann dann eine bekannte kanonische Benutzer-UUID verwenden. Keine globale Suche, erfundene Personen oder versteckte Profilrechtserweiterung.

## Präzise Rechte und API

- Lesen benötigt `ous.read`; Schreiben zusätzlich `ous.members.manage` und die kanonisch verlangte frische MFA. Der tatsächliche ursprüngliche Owner erhält nur dieses zusätzliche eigene Verzeichnisrecht. Die bestehende `ou-administrator`-Rolle erhält dieselbe präzise Aufgabe, **nicht** `users.read`, Rollen-, Geräte- oder Lizenzverwaltung. Die 62 Rollennamen und Schema 6 bleiben unverändert; der allgemeine eigene Rollenquellen-Cutover bleibt versiegelt.
- Profilinformationen in Mitgliedslisten benötigen separat tatsächlich aufgelöstes `users.read`. `profileAccess` ist eine Serverentscheidung, kein wählbares Requestfeld.
- `GET /api/ous/{id}/members` akzeptiert ausschliesslich `page` (1–1'000'000) und `limit` (1–100, Standard 25). Count, eigene Einheit, Revision und Seite stammen aus einem Snapshot. Antwort: `schemaVersion`, `actorUserId`, `unit`, `members`, `total`, `page`, `limit`, `profileAccess`; ETag und `no-store`.
- `POST /api/ous/{id}/members` akzeptiert exakt `{userId}` und einen aktuellen starken `If-Match: "ou-UUID-revision"`. Erfolg `201` enthält `{unit,membership,action:"member-add"}`.
- `DELETE /api/ous/{id}/members/{membershipId}` benötigt leeren Body/Query und denselben exakten OU-Versionsvertrag. Erfolg **200**, nicht 204, enthält die entfernte ursprüngliche Mitgliedschaft und die aktuelle Einheit mit `action:"member-remove"`.
- `GET /api/identity/access` kündigt `directoryOuMembershipProtocol:1` an. Alte Receiver bzw. unbekannte Bestände aktivieren keine Schreibabkürzung. Der gemeinsame [OpenAPI-3.1-Vertrag, aktuell Version 1.8.0](../api/openapi.yaml), wird deterministisch generiert.

Fehlende Version/frische MFA: `428`; stale Version: `412`; doppelte aktive Beziehung oder Löschabhängigkeit: `409`; fremdes/fehlendes Ziel: `404`; inkohärente Daten bzw. fehlende Receiving-Belege: fail closed. Nach unsicherem oder fehlgeschlagenem Schreiben verwirft die UI alte Aktionsdaten und verlangt bewusstes Neuladen. Keine automatischen Schreibwiederholungen; Sitzungsverlust invalidiert auch verspätete Lese-/Schreibergebnisse.

## Persistenz, Historie und Konkurrenz

Migration **043_ou_memberships.sql** erweitert den bestehenden OU-Command-/Event-/Outbox-Kernel von 042 statt einen zweiten Berechtigungsweg zu bauen. `identity_directory_ou_members` enthält aktive normalisierte Beziehungen mit UUID, Tenant-, OU- und User-FKs, `UNIQUE(ou_id,user_id)` und Indizes für Seiten sowie Benutzerabhängigkeiten. Direkte Retarget-/Update-Schreiboperationen sind nicht zulässig. Der alte Benutzer-Freitext `department` bleibt unverändert und ist kein Ersatz für diese Beziehung.

Eine Änderung erhöht genau die betroffene OU-Revision um eins, ohne Namen, Beschreibung oder Parent zu ändern. Der gemeinsame Tenant-Tree-Lock und stabil sortierte Actor-/Recipient-User-Locks koordinieren Zuordnung, Baumänderung und Benutzer-/OU-Retirement. Nach echtem Warten werden Existenz, eigene Hoheit und Originalberechtigung erneut geprüft. Maximal 10'000 aktive Zuordnungen je Einheit werden unterstützt; das ist keine Lastabnahme.

Der ursprüngliche menschliche Proof, physische Frist, exakte Membership-Inkarnation und tatsächliche Before-/After-Wirkung müssen am Commit mit unveränderlichem `organization-unit.member.added`/`organization-unit.member.removed`-Event und Pending-Outbox übereinstimmen. Aktive Rows werden bei kontrolliertem Unlink entfernt, aber der ursprüngliche Datensatz bleibt im Event-Proof erhalten. Wiederaufnahme derselben Person erzeugt eine neue ID; eine alte Löschanfrage kann diese nicht entfernen. Historische IDs dürfen nicht erneut verwendet werden. Ein Index auf dem retained Proof unterstützt die Prüfung.

Die älteren acht Canonical-No-effects-/Truncate-Grenzen sowie OU-Row-/Deferred-Commit-Receiver gelten auch für die neue Tabelle. Gelöschte GUCs, zusätzliche Canonical Writes, fehlende Guards/Events/Outbox, spätere Row-Manipulation, fremde Links, private Raw-SQL-/`SET ROLE`-Ersatzversuche und physisch abgelaufene Originalbelege ergeben keinen erfolgreichen Commit. UTC-Snapshots vermeiden callerabhängige Zeitdarstellung. Der privilegierte Datenbankoperator bleibt eine Betriebsvertrauensgrenze.

Aktive FKs blockieren lokale Ziel-Löschung. Historische Events besitzen bewusst keinen FK auf eine später entfernte User-/OU-Row; Audit und Ownership bleiben nach kontrolliertem Retirement erhalten. Noch kein kontrollierter Datenschutz-/Retention-Löschprozess, Off-host-Archiv oder fertiggestelltes Least-Privilege-DB-Loginmodell. Pending-Outbox bedeutet weder externe Zustellung noch JML-Erfolg.

## Abnahme und verbleibende Arbeit

[Begrenzte Abnahme](../testing/test-results.md#business-slice-9-mehrfache-benutzer-ou-zuordnungen): echte PostgreSQL-Mehrfachbeziehungen, getrennte Profilrechte, Mandantentrennung, exakte Incarnations, aktive Löschabhängigkeiten, beobachtete konkurrierende SQL-Wartezustände, Original-Proof-/Deadline-/Receiving-Ausfälle sowie signierter Gateway- und echter Chrome-Company-Workflow. Kein Mock-Provider wird als produktive Integration ausgegeben.

Offen bleiben primäre Beschäftigungszuordnung/Legal Entities, administrativ begrenzte OU-Scopes und Rollen-/Blueprint-/App-/Lizenzberechnung, zugangsfähiges Employee-Onboarding, Mover/Leaver-Entzüge und sämtliche übrigen Master-Prompt-Capabilities. Keine erfolgreiche Geräteaktion, Lizenzvergabe oder Apple-Publikation wird aus einer lokalen Mitgliedschaft abgeleitet. Die bekannten 17 TypeScript-Diagnosen und fehlende Produktions-/Betriebsabnahme bleiben separate Risiken; kein Deployment oder externer Produktiv-Write.
