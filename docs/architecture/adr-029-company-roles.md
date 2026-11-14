# ADR 029: Eigene Firmenrollen und begrenzte Verzeichnisrechte

Status: Implementierung mit begrenzter Verzeichnis-Capability, 14. November 2026. Teil von BR-002; das vollständige Plattformziel bleibt offen.

Eigene Rollennamen werden nicht als neue globale Rollen in Tokens oder in den vorhandenen Plattformrollenkatalog eingefügt. Definitionen und befristete Vergaben gehören zum ursprünglichen eigenen Tenant. Das erlaubte erste Aktionsverzeichnis sind die bereits vorhandenen vierzehn Firmen-Verzeichnisrechte. Rollenverwaltung, Passwort-/MFA-Reset, globale Administration und Providerrechte sind nicht delegierbar.

Vergaben gelten für eine eigene Person oder eine ausdrücklich bei der Erstellung geschützte Rollengruppe. Auf Organisationseinheiten begrenzte Vergaben erlauben Lesen, Profiländerung und Sperrstatus eigener Personen innerhalb der Einheit und ihrer Nachfahren. Sie erlauben keine Verwaltung des Containers oder beliebiger Gruppen. Eine Definition mit anderen Aktionen kann nicht versehentlich mit einem solchen Scope vergeben werden.

Angelehnt an [Entra-Rollengruppen](https://learn.microsoft.com/entra/identity/role-based-access-control/groups-concept) sind Rollengruppen statisch und gegen gewöhnliche Gruppenadministration, automatische Einladungseinträge und dynamische Regeln geschützt. Organisationseinheiten, die Rechte begrenzen, erhalten einen entsprechenden Schutz ihrer Mitgliedschaften und Hierarchie. Ein einfacher Gruppen-/OU-Verwalter darf seine eigenen Zuständigkeiten dadurch nicht erweitern. Rollenverwaltung verlangt einen aktuellen kanonischen Rollenverwalter oder tatsächlichen Firmeninhaber sowie frische unabhängig gebundene MFA.

Eine Vergabe bindet die konkrete Definitionsversion. Änderungen oder Deaktivierung einer Definition erteilen bestehenden Empfängern nicht still neue Aktionen: alte Vergaben werden unwirksam und benötigen eine ausdrückliche neue Entscheidung. Vergaben sind zeitlich begrenzt; Personen- und Mitgliedschaftsgeneration, eigener Tenant, Ablauf, aktuelle Reviews und Widerrufe bleiben live überprüfbar. Alte Vergaben leben nach Kontoreaktivierung nicht automatisch wieder auf.

Die bestehenden DirectoryCreator-, UserMutator-, GroupMutator- und OU-Kerne bleiben die Schreiber. Eigene Rechte ergänzen die originale Hoheit, ersetzen sie nicht. Ein ursprünglicher Delegationsbeleg und sein unverlängerter Deadline werden am physischen SQL-Commit erneut geprüft. Geschützte Gruppen-/Scope-Änderungen und Rollenänderungen verwenden eine gemeinsame Tenant-Schreibgrenze. Bestehende Plattformrechte bleiben davon unabhängig.

Lesefilter werden serverseitig auf die jeweilige Ressource angewendet. Zählungen, Seiten, Detailabfragen, Suche und indirekte Profilansichten dürfen aus einer begrenzten `users.read`-Vergabe keine vollständige Verzeichnisfreigabe machen. Ein zusätzlicher Browserfilter ist kein Zugriffsschutz.

Jede Definition, Änderung, Vergabe und Rücknahme benötigt exakte Felder, Begründung und Bestätigung. Änderungen verlangen aktuelle starke Objekt-ETags. Tatsächliche Vorher-/Nachher-Zeilen, ursprünglicher Akteur, verpflichtende lokale Historie und Pending-Outbox gehören zum selben Commit. Gelöschte oder ausgefallene Receiver ergeben keinen behaupteten Erfolg. Keine automatische externe Provisionierung oder neue gemeinsame Transaktion über unabhängige Dienste wird angenommen.

Abnahme verlangt reale PostgreSQL- und OAuth-Prozesse für erlaubte und fremde Ziele, Scope-Grenzen, Gruppen-/OU-Selbsterweiterung, Ablauf, Revisionen, Widerruf während gehaltener Schreibtransaktionen und unterdrückte Audit-/Outbox-Belege sowie vollständige Browserbedienung. Die begrenzte Implementierung und ihre Prüfungen sind im [Liefernachweis](../deployment/company-roles-2026-11-14.json) festgehalten; dies schließt das vollständige Governance-Ziel nicht ab.


Implementierungsbeleg: [Firmenrollen](../features/company-roles.md). Die erste Capability bleibt auf die vierzehn Verzeichnisaktionen begrenzt; eigene PIM-Selbstaktivierung und zusätzliche Dienstaktionen bleiben Teil des offenen Gesamtauftrags.
