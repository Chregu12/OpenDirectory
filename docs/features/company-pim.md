# Eigene Firmenrollen mit PIM aktivieren

Eigene [Firmen-Verzeichnisrollen](company-roles.md) haben neben direkten aktiven Vergaben jetzt getrennte **berechtigte Zuweisungen**. Eine berechtigte Person erhält erst nach eigener ausdrücklicher Aktivierung Rechte. Das folgt dem [Entra-Bedienprinzip mit berechtigten und aktiven Zuweisungen](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/groups-activate-roles); es verändert keine globalen Tokenrollen und behauptet keine vollständige Entra-Parität.

## Als Rollenverwalter

1. Unter **Administration → Firmenrollen** die eigene Definition erstellen oder öffnen. Ihre bestehenden vierzehn Verzeichnisaktionen und ihre maximale Aktivierungsdauer bleiben maßgebend.
2. **Rolle vergeben** → **Berechtigt · eigene PIM-Aktivierung erforderlich** wählen. Dieser Modus ist die Voreinstellung des aktualisierten Servers. Eine aktive eigene Person oder geschützte statische Rollengruppe, den Bereich und eine Gültigkeit zwischen einem und 365 Tagen auswählen. API-Clients können kürzere Gültigkeiten ab einer Minute vergeben.
3. Begründung eingeben und ausdrücklich bestätigen. Die Vergabe erzeugt noch keine Rechte. Sie bindet die aktuelle Definitionsversion und die aktuelle Empfänger-/Scope-Generation.
4. Unter **Berechtigt für PIM** stehen aktuelle und erhaltene Zuweisungen samt Ablauf. **Berechtigung entziehen** macht diese Zuweisung und alle daraus abgeleiteten Aktivierungen sofort unwirksam. Die vollständige lokale Historie bleibt erhalten.

Eine OU mit Untereinheiten unterstützt weiterhin ausschließlich Benutzer lesen, Profile ändern und Sperrstatus verwalten. Statische Rollengruppen und geschützte Scope-Hierarchien behalten ihre bestehende unabhängige Verwaltung. Rollenverwalter können sich weder direkt noch über nachträgliches eigenes Hinzufügen in eine solche Gruppe selbst berechtigen.

## Als berechtigte Person

1. Auf **Home** oder unter **PIM → Firmenrollen → Berechtigt** die tatsächlich zugewiesene Aufgabe auswählen.
2. **Aktivieren**: Dauer in Minuten und Begründung eingeben und bestätigen. Erforderlich ist eine unabhängig gebundene MFA-Anmeldung innerhalb der letzten fünf Minuten. Maximal gelten die Grenze der Definition, zehn Stunden und die verbleibende Zuweisungs-/Review-Dauer.
3. Die Aufgabe zeigt **Aktiv** und das tatsächliche Ende. Die Navigation lädt die aktuellen Verzeichnisrechte neu. Es ist keine künstliche globale Administratorrolle und kein zusätzlicher Tokenrollenwechsel nötig.
4. **Beenden** entzieht die eigene Aktivierung sofort. Dafür genügt der ursprüngliche aktuell angemeldete Benutzer unter seiner normalen Anmelderichtlinie; für das Zurückgeben eigener Rechte wird keine zusätzliche fünfminütige MFA verlangt. Erneutes Aktivieren benötigt erneut frische MFA.
5. **Mein Protokoll** zeigt ausschließlich die eigenen ursprünglichen Aktivierungs- und Beendigungsereignisse, Akteur, Begründung und Zeitpunkt, mit Seiten zu 25 Einträgen.

Ein aktiver PIM-Nachweis kann länger als fünf Minuten wirken. Die normale aktuelle Anmelderichtlinie bleibt verbindlich: Bestehende Owner-/globale Verwaltungsrollen mit einer strengeren MFA-Vorgabe erhalten dadurch kein größeres Fenster. Direkte Firmenrollenvergaben bleiben an ihre bestehende fünfminütige MFA-Grenze gebunden. Ein längeres PIM-Fenster öffnet keine zusätzlichen, nur direkt vergebenen Bereiche.

## Live-Quelle und Commit

Identity-Migration `058_company_pim.sql` ergänzt eigene Eligibility-/Aktivierungszeilen und acht versiegelte SQL-Helfer. Aktive Vergaben, kanonischer `RoleState`, Issuerrollen und bestehende PIM-Aufgabengruppen bleiben getrennt. Die tatsächlichen bisherigen Verzeichnis-Kerne verwenden die zusätzlich erfasste eigene Rollenquelle.

Jede Nutzung prüft aktuelle Definition/Revision, ursprünglichen Tenant, Empfänger-/OU-Generation, tatsächliche Gruppenmitgliedschaft und Review, Ablauf und Widerruf. Aktivierungen binden die konkrete Mitgliedschafts-Inkarnation, den ursprünglichen Benutzer-/Subject-/Link-Kontext und die unabhängig gebundene MFA-Revision. Entfernen und erneutes Hinzufügen eines Gruppenmitglieds, Sperren/Reaktivieren einer Person und geänderte Rollendefinitionen beleben alte Aktivierungen nicht wieder. Eine geänderte MFA-Revision wird nicht als weiterhin wirksame eigene Aktivierung angezeigt; erneute Aktivierung benötigt einen neuen bestätigten Nachweis. Bestehende globale Rechte bleiben unabhängig.

Serverseitige Benutzerfilter verwenden ausschließlich die für den aktuellen Originalbenutzer akzeptierten erfassten Quellen. Listen, Zählungen, Details, Suche und indirekte Profilansichten können dadurch eine veraltete direkte OU-Vergabe nicht über einen anderen aktiven PIM-Scope ausweiten.

Aktivierung, Zuweisung, Entzug und Beendigung speichern tatsächliche Vorher-/Nachher-Daten, Originalakteur, Begründung und lokale Pending-Outbox gemeinsam. Ein fehlender Receiver, unterdrückter Beleg oder vorgetäuschter positiver Admission-Aufruf bestätigt keine Wirkung. Unveränderte Aktivierungs-/Governance-Deadlines gelten bis zum physischen Commit. Eine Verzeichnisoperation erfasst ihren eigenen aktuellen Originaltoken und den tatsächlichen Aktivierungsablauf; sie verlängert nicht nachträglich den ursprünglichen Aktivierungsvorgang. Ein Ablauf während einer gehaltenen Schreibtransaktion verhindert die Ressourcenänderung.

Gemeinsame Tenant-Schreiblocks serialisieren Rechteänderungen und Verzeichnisänderungen. Historie und SQL-Belege sind unveränderlich; die neuen Hilfsfunktionen sind nicht öffentlich ausführbar. Der privilegierte Datenbankbetreiber und die vorhandene dienstübergreifende Issuer-Revalidierung bleiben Vertrauensgrenzen. Die lokale Outbox ist ausstehend und kein behaupteter ausgelieferter Provider-Effekt.

## Schnittstellen

Die [OpenAPI-Datei](../api/openapi.yaml) beschreibt `companyPimProtocol: 1`, exakte Felder, separate starke ETags, Seiten und tatsächlich geprüfte Rückgaben:

- `GET/POST /api/identity/company-roles/:id/eligibilities`: unabhängige Verwaltung berechtigter Zuweisungen; POST benötigt den aktuellen Rollen-ETag.
- `POST /api/identity/company-roles/eligibilities/:id/revoke`: aktuelle Eligibility-Version entziehen.
- `POST /api/identity/company-roles/activations/:id/revoke`: unabhängig als Rollenverwalter eine bestimmte Aktivierung entziehen.
- `GET /api/identity/company-pim?tab=eligible|active`: eigene Zuweisungen/laufende Aktivierungen, serverseitige Suche und Seiten.
- `GET /api/identity/company-pim/history`: eigene paginierte Kontrollhistorie.
- `POST /api/identity/company-pim/eligibilities/:id/activate`: nur die ursprünglich berechtigte Person, mit frischer MFA und Eligibility-ETag.
- `POST /api/identity/company-pim/activations/:id/end`: nur die ursprünglich aktivierte Person, mit Aktivierungs-ETag.

ETags sind `"company-eligibility-UUID-revision"` beziehungsweise `"company-activation-UUID-revision"`. Eigene Zuweisungen und Aktivierungen sind keine API-Key-/Workload-Befugnis. Tenant-/Benutzer-Overrides werden nicht übernommen. Versionskonflikte und verlorene Antworten lösen keine automatische Schreibwiederholung aus.

## Noch offen

Eigene Firmenrollen haben in dieser Lieferung keine unabhängige Aktivierungsgenehmigung, terminierten Aktivierungsanträge oder konfigurierbaren Review-/Benachrichtigungsregeln. Die bestehenden kanonischen PIM-Aufgaben mit Genehmigung bleiben verfügbar. Eine administrative Einzelaktivierungs-Rücknahme ist als API vorhanden; eine globale Aktivierungsqueue und zusätzliche Managerfilter sind noch offen. Zusätzliche delegierbare Aktionen für Lizenzen, Geräte und externe Anbieter sowie Last-/Betriebsabnahmen bleiben Teil des vollständigen Umsetzungsauftrags. Positive menschliche Tests verwenden isolierte Konten und Datenbanken; für die Lieferung werden keine persönlichen Produktions-MFA- oder PIM-Rechte erzeugt.
