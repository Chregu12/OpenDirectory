# PIM auf der Übersicht

Die Übersicht zeigt auch für Benutzer ohne Adminrolle farblich getrennte Aufgabenkarten für Engineering, Lizenzen, Benutzerverwaltung, Apps & SSO, Richtlinien-Rollout und Global Security. Jede Karte nennt die tatsächliche Rolle, die zulässige Dauer und den aktuellen Status:

- **Nicht zugewiesen:** keine Gruppen-Eligibility für diese Person.
- **Berechtigt · inaktiv:** eine Aktivierung kann beantragt werden.
- **Wartet auf Freigabe:** der Antrag benötigt eine unabhängige Entscheidung.
- **Freigegeben · jetzt aktivieren:** die Person kann mit frischer MFA aktivieren.
- **Aktiv:** tatsächliches Ende und verbleibende Minuten werden angezeigt.
- **Dauerhaft aktiv:** die entsprechende Rolle ist bereits direkt vergeben; PIM begrenzt diese bestehende Vergabe nicht.
- **Deaktiviert:** die Gruppe erteilt keine neue Berechtigung.

**Aktivierung anfordern** öffnet ein Formular für Dauer und Begründung. Vor jedem Schreiben zeigt eine Bestätigung die konkrete Gruppe und Wirkung. Nach erfolgreicher eigener Aktivierung führt die Oberfläche zur neuen Anmeldung, damit geänderte kanonische Rechte auch im Zugriffstoken ankommen. Das Ablaufdatum löscht die alte private Anzeige; Schreibvorgänge werden dabei nicht automatisch wiederholt.

Unter **Gruppen & Zuweisungen** (`/pim`) können berechtigte Verwalter weitere Gruppen anlegen, Benutzer berechtigen, Zuweisungen entziehen und Gruppen deaktivieren. In den Benutzerdetails führt **PIM-Gruppen zuweisen** mit der konkreten Verzeichnis-ID in dieselbe Verwaltung. Die Benutzerwahl listet verfügbare Verzeichniseinträge; eine eigene Eligibility muss ein anderer berechtigter Verwalter vergeben.

**Protokoll** zeigt paginierte unveränderbare PIM-Ereignisse mit handelnder und betroffener Person, Begründung und geplantem Ablauf. PIM-Prüfer sehen außerdem Anträge und können sie unabhängig genehmigen, ablehnen oder eine Aktivierung widerrufen. Global Security unterliegt den Schutzregeln der vollständigen `admin`-Rolle.

Die separate Verwaltung von Einzelrollen und Rollenrichtlinien bleibt unterhalb der Gruppen verfügbar. Eine bestehende dauerhafte Adminrolle wird als Hinweis sichtbar gehalten. Höchstens zehn Stunden sind technisch erlaubt; die tatsächliche Auswahl berücksichtigt weiter die aktuelle Rollenrichtlinie und Benutzer-Eligibility.

[Rechte, Ablauf, API und Audit](../features/pim.md)
