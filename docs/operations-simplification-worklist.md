# Einfach bedienbare OpenDirectory-Abläufe

## Auftrag

Korrektur des Auftraggebers vom 17. November, gestartet am 18. November 2026: Die **Bedienung der bereits umgesetzten Funktionen** soll einfach, einheitlich und möglichst automatisch werden. Die Orientierung an Apple betrifft verständliche Entscheidungen, sinnvolle Vorgaben und zusammenhängende Abläufe. Ein optischer Umbau ist kein eigenes Ziel dieses Auftrags.

Der bestehende Funktionsumfang bleibt erhalten. Neue Anbieter, zusätzliche Verwaltungsfunktionen oder eine Entra-Kopie werden dadurch nicht zum Pflichtumfang. Die frühere Abnahme externer Anbieter wird durch diesen Auftrag nicht als erledigt erklärt.

## Anforderungen an jeden Ablauf

- Informationen einmal erfassen und den bestätigten Kontext in Folgeschritte übernehmen; Namen auswählen statt interne IDs eintippen.
- Vorhandene Vorlagen, Gruppenregeln, delegierte Automationen und APIs verwenden. Berechtigungen und Regeln werden nicht aus Bezeichnungen erraten.
- Den vollständigen Auftrag verständlich prüfen und bestätigen; anschließend zulässige Folgeschritte ohne erneute Dateneingabe ausführen.
- Ausgeführt, ausstehend, teilweise erledigt und ungeklärt unterscheiden. Eine gespeicherte Einladung, angenommene E-Mail oder lokale Lizenz ist keine bestätigte externe Zustellung.
- Bei Teilfehlern den bestätigten Zwischenstand erhalten. Unklare Schreibvorgänge werden nicht automatisch wiederholt; zwischenzeitliche fremde Änderungen werden nicht zurückgenommen.
- Aktuelle Mandantenrechte, MFA, unabhängige Freigaben, Versionsbindungen und Audit bleiben wirksam. Maschinen benötigen eine tatsächliche passende Delegation.
- Tastaturbedienung, kleine Bildschirme und verständliche Fehlermeldungen gehören zum vollständigen Ablauf.

## Umsetzungsfolge

Die Bestandsaufnahme umfasst die vorhandenen erreichbaren Funktionen und ihre Aufrufer; die folgenden Familien strukturieren die Arbeit, ohne einzelne bestehende Abläufe auszuschließen.

| Bereich | Zu vereinfachender Ablauf | Stand |
| --- | --- | --- |
| Mitarbeiteraufnahme | Person erfassen, Gruppen vorbereiten und Einladung in einem zusammenhängenden Auftrag erstellen; Passwort und MFA richtet die Person selbst ein | Umgesetzt und ausgerollt (1.0.56) |
| Benutzer, Gruppen und Organisation | Kontextbezogene Änderungen, Vorlagen und nachvollziehbare Mitgliedschafts-/Rollenwirkungen | Bestandsaufnahme |
| PIM und MFA | Passende Aufgabe finden, gezielt aktivieren, erforderliche Freigaben verstehen; Ablauf und Entzug automatisch verfolgen | Bestandsaufnahme |
| Apps, Lizenzen und Blueprints | Bestehende Regeln einmal einrichten, Zuweisungen und Bestände zusammen prüfen, erlaubte Folgeschritte mit klarer Herkunft | Bestandsaufnahme |
| Geräte | Registrierung, Benutzerzuordnung, automatische Inventar-/Statusmeldungen, Compliance, Synchronisierung und Rückgabe | Bestandsaufnahme |
| Austritt und Wiederherstellung | Bestehenden Austrittsablauf mit vollständiger Vorschau, nachvollziehbaren Teilständen und gezielter Wiederaufnahme bedienen | Bestandsaufnahme |
| App-Konten und Automationen | Delegationen und Zeitpläne verständlich einrichten; Ergebnisse und erforderliche Eingriffe statt technischer Einzelschritte zeigen | Bestandsaufnahme |
| Einstellungen, Richtlinien und Betrieb | Vorhandene Authentifizierungs-, Organisations-, Integrations-, Richtlinien-, Audit- und Betriebsaktionen anhand ihrer tatsächlichen Möglichkeiten vereinheitlichen | Bestandsaufnahme |

Ein Bereich ist erst erledigt, wenn seine tatsächlichen Aufrufer umgestellt sind, die vorhandenen Wirkungen erhalten bleiben und Erfolgs-, Teilfehler-, Rechte- und Wiederaufnahmefälle angemessen geprüft wurden. Ein neuer Dialog allein erfüllt den Auftrag nicht.

## Mitarbeiteraufnahme: umgesetzter Stand

Im produktiven System: **Mitarbeitende → Mitarbeiter aufnehmen** oder **Einladungen → Mitarbeiter aufnehmen**.

„Mitarbeiter aufnehmen“ ist für den aktuellen Firmeninhaber aus der Benutzerverwaltung, der Dashboard-Aktion und den Einladungen erreichbar. Name und E-Mail genügen für die Vorgaben; der vorgeschlagene Benutzername bleibt änderbar. Eigene Gruppen werden ausgewählt. Weitere Angaben bleiben optional. Vor dem Start zeigt eine gemeinsame Vorschau den vollständigen Auftrag.

Nach der Bestätigung werden die aktuelle Einladungsberechtigung mit frischer MFA, der gesperrte Verzeichniseintrag, die ausgewählten Gruppenstände und die ursprüngliche Einladung nacheinander geprüft beziehungsweise verarbeitet. Bereits vorhandene gesperrte Personen verwenden denselben Ablauf. Ein bestätigter Zwischenstand wird bei Fehlern beibehalten; ein unklarer Schreibausgang löst keinen erneuten Anlage- oder Versandversuch aus. Eine bestätigte Ablehnung erlaubt nach erneuter Prüfung die Fortsetzung für genau dieselbe Person. Die gesonderte Erstellung eines Verzeichniseintrags bleibt unter „Weitere Benutzeraktionen“ verfügbar.

Die eingeladene Person setzt ihr Passwort selbst und richtet bei der ersten Anmeldung die vorgeschriebene MFA ein. Die Aktivierung aktualisiert die Statusstände ihrer vorhandenen Gruppen mit Audit und Outbox. Mitgliedschaften und Gruppenmetadaten bleiben dabei erhalten. Diese automatische Folgeänderung war zuvor durch die Einladungs-Schutzregel blockiert; die Regel erlaubt jetzt nur diese überprüfte Folgeänderung. Ihre Empfänger und Funktionsdefinitionen werden ebenfalls geprüft. Die ursprüngliche Manifeststruktur bleibt für den Start der bisherigen Version bei einer Rückkehr erhalten.

Lokal geprüft am 19. November 2026 (Europe/Zurich):

- Frontend: 166 Jest-Suiten / 3.346 Tests erfolgreich; TypeScript ohne Fehler; beide Lockfiles konsistent, npm-ci-Trockenlauf erfolgreich.
- Einladungen: 39 PostgreSQL-Fälle erfolgreich, anschließend neun gezielte Fälle auf dem endgültigen Gruppen-Fix einschließlich Migration-Wiederholung, unterdrückter Outbox und veränderter Empfängerfunktionen; zusammen 43 unterschiedliche Fälle.
- Produktionsbuild mit Next.js 16.4.5 und tatsächlichem Chrome: vollständige Aufnahme mit bestehender Gruppe, Passwortvergabe, abgewiesenem falschem Passwort und erzwungener erster MFA-Anmeldung erfolgreich. Desktop- und Mobilvorschau geprüft.
- Der zusätzliche Browsertest der bestehenden Firmenverwaltung ist erfolgreich. [GitHub CI 44425660338](https://github.com/Chregu12/OpenDirectory/actions/runs/44425660338) ist mit allen 15 Jobs grün: zusätzlich 112 Playwright-Fälle und alle 62 tatsächlichen Browserfälle genau einmal in neun bereinigten Testgruppen; Identity 816, OAuth 306, Lizenzen 599 und Zugangsdaten/Einladungen 65 Fälle.
- Version 1.0.56 läuft unter Helm-Revision 89 mit elf bereiten Deployments. Web- und Identity-Dateien, Next.js 16.4.5, Einladungsfreigabe mit Pflicht-MFA, anonymer Zugriffsschutz und die tatsächliche Datenbank-Schutzregel sind geprüft. Neun andere Deployment-Spezifikationen bleiben gleich. [Release-Nachweis](deployment/employee-intake-1.0.56-2026-11-19.json).

Die Prüfung verwendet isolierte Datenbanken, Dienste und Testkonten. Ein tatsächlicher Mitarbeiterstart mit einem Firmenkonto, externe Mailzustellung und echte Herstellerlizenzen werden durch die isolierten fachlichen Testabläufe nicht bestätigt. Der produktive Rollout und seine Zustandsprüfungen sind im Release-Nachweis getrennt dokumentiert. Next.js und die passende ESLint-Konfiguration wurden auf die benötigte Sicherheitsversion 16.4.5 aktualisiert; beide Paket-Lockfiles sind mitgeführt.
