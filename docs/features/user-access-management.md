# Benutzerbezogene Gruppen- und Rollenverwaltung

Stand: 14. November 2026. In **People → Mitarbeitende → Person auswählen** stehen Übersicht, Gruppen und Rollen & Rechte zur Verfügung. Gruppen- und Rollenbereiche erscheinen nur mit den jeweiligen bestätigten Leserechten. Die Tabs unterstützen Pfeiltasten, Pos1 und Ende.

Dieser Bedienweg orientiert sich an der [benutzerbezogenen Rollenansicht in Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/view-assignments). Er ist ein weiterer Teil von BR-002 und WF-002/004; vollständige Entra-Funktionsgleichheit, eigene Firmenrollen, OU-Rollenscopes und SCIM sind damit nicht abgeschlossen.

## Gruppen

`GET /api/users/{id}/groups` verlangt **users.read und groups.read**. Der originale menschliche Bearer, die aktuelle kanonische Identität und der eigene Home-Tenant werden über den bestehenden DirectoryReader vor und nach dem Lesen geprüft. Sowohl Zielperson als auch Gruppen müssen zum eigenen Tenant gehören. Fremde oder fehlende Zielpersonen ergeben 404. Weder Actor-, Tenant- noch Scope-Parameter werden akzeptiert.

Die neue Capability `directoryUserGroupsProtocol:1` bestätigt diesen Receiver. `membership=member` liefert gespeicherte Beziehungen; `membership=available` liefert eigene noch nicht zugewiesene Gruppen. Name/Beschreibung werden literal und ohne Beachtung der Grossschreibung gesucht. Page/limit sind serverseitig (Standard 25, höchstens 100). Zählung und Seite stammen aus derselben read-only Repeatable-Read-Transaktion. Andere Mitglieder-IDs oder Mitarbeiterprofile werden nicht mitgeliefert.

Die Ansicht unterscheidet manuelle und tatsächlich durch Gruppenregeln erzeugte Beziehungen. **Wirksam** verwendet denselben Benutzerfreigabe- und aktuellen Regel-/Review-Deadline-Nachweis wie die kanonischen Gruppensnapshots. Gespeicherte, aber veraltete oder noch nicht genehmigte Regelbeziehungen werden nicht als positive Zugriffsquelle dargestellt. Gesperrte Personen behalten ihre gespeicherten Beziehungen, erhalten daraus aber keinen wirksamen Zugang. Der Status beschreibt den Abrufzeitpunkt und bestätigt keine externe Provisionierung.

Hinzufügen und Entfernen verwenden den bestehenden GroupMutator. Vor der ausdrücklichen Bestätigung wird genau die dargestellte Gruppe mit ihrer Revision nachgelesen. Abweichungen führen zu einem Konflikt. Der eigentliche Schreibzugriff verlangt `groups.members.manage`, den exakten starken Gruppen-ETag, die ursprüngliche Hoheit und alle bestehenden SQL-/Audit-/Outbox-Guards. Vorgeschriebene unabhängige Zugriffsprüfungen bleiben bestehen. Die neue Personenansicht verweist für Regelbeziehungen auf die Regelverwaltung; die bestehenden API-Gruppenkernrechte bleiben unverändert. Nach Sitzungs-, Personen- oder Operatorwechsel verwirft die UI alte Daten und Bestätigungen. Es gibt keinen automatischen Schreib-Retry.

## Rollen

Der bereits bestehende Rollenbereich wird für die ausgewählte kanonische Person wiederverwendet. Die Eingabe oder das Kopieren einer UUID entfällt. `identities.roles.read` ist separat erforderlich; `identities.roles.manage` wird für Vergabe und Widerruf unabhängig geprüft. Weder Gruppenverwaltung noch Firmeninhaberschaft erzeugen dieses Recht automatisch.

Der reale Rollenkatalog bestimmt erlaubte Rollen. Direkte Vergaben benötigen eine Begründung, eine ausdrückliche Bestätigung und laufen spätestens nach acht Stunden aus. Aktivierungspflichtige PIM-Rollen lassen sich nicht über diesen Weg vergeben. Geschützte Rollen, aktuelle Authentifizierungsrichtlinien, Review-Fristen und das Verbot der Selbstadministration bleiben durch den bestehenden Backend-Kernel erhalten. Die vorhandene PIM-Verknüpfung der Person bleibt für berechtigte Bearbeiter verfügbar.

Die Ansicht zeigt tatsächliche aktive, abgelaufene, widerrufene oder durch Richtlinie/Review entzogene Vergaben. Rollenänderungen entziehen bisherigen Tokens ihre Hoheit; ein lokaler Rollenbeleg ist keine wiederhergestellte Benutzersitzung oder externe Bereitstellung.

## Prüfung und Grenzen

Automatische Prüfungen umfassen echte PostgreSQL-Gruppenregeln und Freigaben, unbekannte/fremde Ziele, unabhängige Lesepflichten, Seitenaufteilung, geänderte Originalhoheit und gesperrte Konten. Ein eigener Test durchläuft mit echten OAuth-Tokens den produktiven Gateway-Code, Gruppenänderungen mit Versionsprüfung sowie befristete Rollenvergabe und Widerruf. Browserprüfungen bedienen die Oberfläche mit ausdrücklich synthetischen lokalen API-Daten, zusätzlich zur realen Backend-Abnahme.

Produktive persönliche Konten, PIM-Zuweisungen, Passwörter und MFA-Registrierungen werden zur Abnahme nicht verändert. Ausstehende externe Ereigniszustellung, Herstellerlizenzen und externe Konten bleiben gesonderte Prozesse. Die restlichen Bereiche des vollständigen Umsetzungsauftrags bleiben offen.
