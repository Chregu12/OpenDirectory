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
| Mitarbeiteraufnahme | Person erfassen, Gruppen vorbereiten und Einladung in einem zusammenhängenden Auftrag erstellen; Passwort und MFA richtet die Person selbst ein | Umgesetzt, CI ausstehend |
| Benutzer, Gruppen und Organisation | Kontextbezogene Änderungen, Vorlagen und nachvollziehbare Mitgliedschafts-/Rollenwirkungen | Bestandsaufnahme |
| PIM und MFA | Passende Aufgabe finden, gezielt aktivieren, erforderliche Freigaben verstehen; Ablauf und Entzug automatisch verfolgen | Bestandsaufnahme |
| Apps, Lizenzen und Blueprints | Bestehende Regeln einmal einrichten, Zuweisungen und Bestände zusammen prüfen, erlaubte Folgeschritte mit klarer Herkunft | Bestandsaufnahme |
| Geräte | Registrierung, Benutzerzuordnung, automatische Inventar-/Statusmeldungen, Compliance, Synchronisierung und Rückgabe | Bestandsaufnahme |
| Austritt und Wiederherstellung | Bestehenden Austrittsablauf mit vollständiger Vorschau, nachvollziehbaren Teilständen und gezielter Wiederaufnahme bedienen | Bestandsaufnahme |
| App-Konten und Automationen | Delegationen und Zeitpläne verständlich einrichten; Ergebnisse und erforderliche Eingriffe statt technischer Einzelschritte zeigen | Bestandsaufnahme |
| Einstellungen, Richtlinien und Betrieb | Vorhandene Authentifizierungs-, Organisations-, Integrations-, Richtlinien-, Audit- und Betriebsaktionen anhand ihrer tatsächlichen Möglichkeiten vereinheitlichen | Bestandsaufnahme |

Ein Bereich ist erst erledigt, wenn seine tatsächlichen Aufrufer umgestellt sind, die vorhandenen Wirkungen erhalten bleiben und Erfolgs-, Teilfehler-, Rechte- und Wiederaufnahmefälle angemessen geprüft wurden. Ein neuer Dialog allein erfüllt den Auftrag nicht.

## Mitarbeiteraufnahme: umgesetzter Stand

„Mitarbeiter aufnehmen“ ist für den aktuellen Firmeninhaber aus der Benutzerverwaltung, der Dashboard-Aktion und den Einladungen erreichbar. Name und E-Mail genügen für die Vorgaben; der vorgeschlagene Benutzername bleibt änderbar. Eigene Gruppen werden ausgewählt. Weitere Angaben bleiben optional. Vor dem Start zeigt eine gemeinsame Vorschau den vollständigen Auftrag.

Nach der Bestätigung werden die aktuelle Einladungsberechtigung mit frischer MFA, der gesperrte Verzeichniseintrag, die ausgewählten Gruppenstände und die ursprüngliche Einladung nacheinander geprüft beziehungsweise verarbeitet. Bereits vorhandene gesperrte Personen verwenden denselben Ablauf. Ein bestätigter Zwischenstand wird bei Fehlern beibehalten; ein unklarer Schreibausgang löst keinen erneuten Anlage- oder Versandversuch aus. Eine bestätigte Ablehnung erlaubt nach erneuter Prüfung die Fortsetzung für genau dieselbe Person. Die gesonderte Erstellung eines Verzeichniseintrags bleibt unter „Weitere Benutzeraktionen“ verfügbar.

Die eingeladene Person setzt ihr Passwort selbst und richtet bei der ersten Anmeldung die vorgeschriebene MFA ein. Die Aktivierung aktualisiert die Statusstände ihrer vorhandenen Gruppen mit Audit und Outbox. Mitgliedschaften und Gruppenmetadaten bleiben dabei erhalten. Diese automatische Folgeänderung war zuvor durch die Einladungs-Schutzregel blockiert; die Regel erlaubt jetzt nur diese überprüfte Folgeänderung. Ihre Empfänger und Funktionsdefinitionen werden ebenfalls geprüft.

Lokal geprüft am 19. November 2026 (Europe/Zurich):

- Frontend: 166 Jest-Suiten / 3.346 Tests erfolgreich; TypeScript ohne Fehler; beide Lockfiles konsistent, npm-ci-Trockenlauf erfolgreich.
- Einladungen: 39 PostgreSQL-Fälle erfolgreich, anschließend sechs gezielte Fälle auf dem endgültigen Gruppen-Fix einschließlich Migration-Wiederholung und unterdrückter Outbox; zusammen 40 unterschiedliche Fälle.
- Produktionsbuild mit Next.js 16.4.5 und tatsächlichem Chrome: vollständige Aufnahme mit bestehender Gruppe, Passwortvergabe, abgewiesenem falschem Passwort und erzwungener erster MFA-Anmeldung erfolgreich. Desktop- und Mobilvorschau geprüft.
- Der zusätzliche Browsertest der bestehenden Firmenverwaltung sowie GitHub CI stehen für diesen Stand noch aus.

Die Prüfung verwendet isolierte Datenbanken, Dienste und Testkonten. Externe Mailzustellung, echte Herstellerlizenzen und die laufende Harbor-Installation werden damit nicht als geprüft erklärt. Next.js und die passende ESLint-Konfiguration wurden auf die benötigte Sicherheitsversion 16.4.5 aktualisiert; beide Paket-Lockfiles sind mitgeführt.
