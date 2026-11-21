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
| Benutzer, Gruppen und Organisation | Kontextbezogene Änderungen, Vorlagen und nachvollziehbare Mitgliedschafts-/Rollenwirkungen | Geprüft: Gruppenpflege per Namen und erklärende Formularhinweise offen (U04, U08) |
| PIM und MFA | Passende Aufgabe finden, gezielt aktivieren, erforderliche Freigaben verstehen; Ablauf und Entzug automatisch verfolgen | Firmenrollen-Kontext und Dauervorgaben ausgerollt (1.0.57); Anmeldung, MFA-Einrichtung und Rückkehr vereinfachen (U02, U03, U11) |
| Apps, Lizenzen und Blueprints | Bestehende Regeln einmal einrichten, Zuweisungen und Bestände zusammen prüfen, erlaubte Folgeschritte mit klarer Herkunft | Geprüft: Bestandsquellen klarer trennen und Wiederanmeldung vereinheitlichen (U07, U11) |
| Geräte | Registrierung, Benutzerzuordnung, automatische Inventar-/Statusmeldungen, Compliance, Synchronisierung und Rückgabe | Geprüft: Inventar und Agent-Verbindung führen; Homelab-Sonderanleitung abgrenzen (U10, U12) |
| Austritt und Wiederherstellung | Bestehenden Austrittsablauf mit vollständiger Vorschau, nachvollziehbaren Teilständen und gezielter Wiederaufnahme bedienen | Geprüft: ein personenbezogener Einstieg statt manueller Übernahme von Vorgangs-IDs (U05) |
| App-Konten und Automationen | Delegationen und Zeitpläne verständlich einrichten; Ergebnisse und erforderliche Eingriffe statt technischer Einzelschritte zeigen | Geprüft: App-/Regelauswahl und tatsächliche Worker-Bereitschaft führen (U06) |
| Einstellungen, Richtlinien und Betrieb | Vorhandene Authentifizierungs-, Organisations-, Integrations-, Richtlinien-, Audit- und Betriebsaktionen anhand ihrer tatsächlichen Möglichkeiten vereinheitlichen | Geprüft: fehlende Funktionen vor dem Klick erklären; technische Nachweise gezielt anbieten (U08, U09) |

Ein Bereich ist erst erledigt, wenn seine tatsächlichen Aufrufer umgestellt sind, die vorhandenen Wirkungen erhalten bleiben und Erfolgs-, Teilfehler-, Rechte- und Wiederaufnahmefälle angemessen geprüft wurden. Ein neuer Dialog allein erfüllt den Auftrag nicht.

## Bedienungsprüfung vom 21. November 2026

**Ergebnis: Die Bedienung ist noch nicht durchgängig einfach.** Mitarbeiteraufnahme, personenbezogene Gruppen-/PIM-Aufgaben und die Inventarformulare bieten eine gute Grundlage. Anmeldung, MFA-Einrichtung, die Gruppenansicht, Austritt und Automationsfreigaben verlangen weiterhin zu viel technisches Vorwissen.

Das aktuelle Inventar umfasst **60 registrierte Ansichten**, davon 43 grundsätzlich für die Navigation vorgesehen. Die tatsächlich sichtbaren Einträge bleiben von Rechten, Modulen und verfügbaren Diensten abhängig. Zusätzlich wurden elf öffentliche beziehungsweise weiterleitende Einstiege im Quelltext erfasst; die öffentliche Anmeldung und das tatsächliche Autorisierungsformular wurden im nativen Chrome betrachtet. Die Zuordnung verwendet die tatsächlich importierten Komponenten, auch bei Aliasnamen. Alte, nicht aufgerufene Komponenten wurden nicht als aktuelle Bedienoberfläche bewertet.

Der [strukturierte Prüfbericht](usability-audit-2026-11-21.json) enthält alle Routen, die Prüftiefe sowie zwölf belegte Punkte mit Fundstellen und Abnahmekriterien. U01 ist im Prüfbranch umgesetzt: **Übersicht, Personen, Geräte, Apps & Lizenzen** ersetzen die gemischten englischen Hauptbereichsnamen. Zielrouten, Kontexte und Rechtefilter bleiben gleich. Diese kleine Änderung ist geprüft und noch nicht produktiv ausgerollt. Elf Punkte bleiben offen.

| Reihenfolge | Zu verbessernder Ablauf | Konkrete Abnahme |
| --- | --- | --- |
| 1 | Anmeldung und MFA (U02, U03, U11) | Benötigten Code erkennen; Authenticator geführt einrichten; nach erneuter MFA zur ursprünglichen Aufgabe zurückkehren. |
| 2 | Gruppenpflege und Formulare (U04, U08) | Namen auswählen, sofern Profil-Leserecht vorhanden; gesperrte Bestätigung erklärt die fehlende Eingabe oder Berechtigung. |
| 3 | Austritt (U05) | Von der ausgewählten Person oder einem bestehenden Vorgang aus mit den ursprünglichen Nachweisen fortsetzen; keine IDs abschreiben. |
| 4 | Automationen (U06) | App, Aufgabe und Regel geführt wählen; gespeicherten Zeitplan von tatsächlich betriebsbereitem Worker und ausgeführtem Job unterscheiden. |
| 5 | Apps, Lizenzen und Geräte (U07, U10, U12) | Bestandsquelle und nächsten Verbindungsschritt erkennen; reguläre Geräteaufnahme von Homelab-DNS-/Zertifikatsänderungen trennen. |
| 6 | Erweiterte Verwaltung (U09) | Nicht unterstützte Bearbeitung vor dem Klick erkennen; Erreichbarkeitstest und produktive Webhook-Zustellung unterscheiden. |

Neu ausgeführt mit Next.js 16.4.5: **169 Frontend-Suiten / 3.367 Fälle**, **114 Playwright-Fälle** einschließlich aller 60 registrierten Seitenaufrufe, **75 Browser-Anmeldetests** und TypeScript erfolgreich. Die Hauptnavigation ist bei 320, 768, 1280 und 1920 Pixeln geprüft. Die Browserfälle verwenden einen echten Next-Server und Chrome mit abgefangenen API-Testantworten; sie prüfen nicht jede Aktion jeder Ansicht und bestätigen keine echten Anbieter-, Mail-, MDM- oder Hardwarewirkungen.

Eine angemeldete Produktivsitzung stand für diese Prüfung nicht zur Verfügung. Es wurden keine produktiven Konten, Berechtigungen, Geräte oder Einstellungen verändert. Ein vollständiger Screenreader-/Kontrasttest und eine formale WCAG-Abnahme sind nicht erfolgt. Die Prüfung und die kleine Navigationskorrektur sind kein Abschluss des gesamten Vereinfachungsauftrags.

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

## PIM: Personenkontext und passende Aktivierungsdauer

Fortsetzung am 19. November 2026: Aus den Details einer freigegebenen anderen Person führt „Firmenrolle zuweisen“ direkt zur Rollenverwaltung. Die Person wird über den kanonischen Verzeichnisdienst erneut gelesen und namentlich bestätigt. Die Zuweisung übernimmt genau diesen Empfänger; die erneute Suche und manuelle ID-Eingabe entfallen. Die Rolle wird direkt aus der Aufgabenliste gewählt. In diesem Personenkontext werden ausschließlich PIM-Berechtigungen vorbereitet; gemeinsame Rollendefinitionen, andere Empfänger und direkte aktive Vergaben bleiben über den ausdrücklich benannten Link zur allgemeinen Rollenverwaltung erreichbar. Firmenrollenverwaltung und Profil-Leserecht bleiben erforderlich. Gesperrte, fremde oder unbestätigte Personen sowie Selbstzuweisungen werden dadurch nicht freigegeben.

Eine erforderliche frische MFA-Anmeldung führt zur gleichen ausgewählten Person zurück. Dafür akzeptiert der Browser-Anmeldedienst zusätzlich nur die genaue lokale Route `/company-roles?userId=<kanonische UUID>`. Weitere Parameter, Fragmente, kodierte Zusätze, doppelte Ziele und fremde URLs bleiben abgewiesen. Die Rückkehr wird in der ursprünglichen geschützten Anmeldetransaktion gehalten; anschließend werden Person und Berechtigungen frisch gelesen.

Beide primären PIM-Aktivierungsbereiche verwenden dieselbe Dauerauswahl: 15 Minuten, eine Stunde, vier Stunden oder zehn Stunden, soweit die tatsächliche Zuweisung diese Dauer erlaubt. Die konkrete Höchstdauer wird zusätzlich angeboten. Andere Dauern bleiben möglich. Sekundenbegrenzungen werden erhalten und nicht auf eine längere Dauer aufgerundet. Die jeweilige serverseitige Freigabegrenze bleibt zusätzlich wirksam. Zuweisung, unabhängige Genehmigung und eigene Aktivierung behalten ihre getrennten Wirkungen; der tatsächliche Ablauf und der Entzug werden weiterhin aus dem bestehenden Dienstzustand verfolgt.

Lokal geprüft:

- Vollständige Frontend-Suite: 169 Suiten / 3.367 Fälle; zusätzliche gezielte Prüfungen für frische MFA, fehlende beziehungsweise geänderte Empfänger und exakte Freigabegrenzen erfolgreich.
- Browser-Anmeldedienst: 75 Fälle einschließlich zulässiger Personenrückkehr und abgewiesener zusätzlicher oder kodierter Ziele.
- 21 gezielte Playwright-Abläufe erfolgreich, einschließlich Desktop und Mobilansicht sowie zehn Stunden, eigener Dauer, unabhängiger Freigabe und Kontextübernahme.
- Tatsächlicher Produktionsbuild und Chrome mit isolierten OAuth-, Identity- und Datenbankdiensten: Benutzerdetails → Firmenrolle zuweisen → tatsächliche erneute MFA-Anmeldung mit Personenrückkehr → PIM-Berechtigung → Antrag → unabhängige Gruppenfreigabe → eigene Aktivierung erfolgreich. Vor der Bestätigung wurde keine Berechtigung geschrieben.

Version 1.0.57 wurde über [PR #13](https://github.com/Chregu12/OpenDirectory/pull/13) nach erfolgreicher [CI](https://github.com/Chregu12/OpenDirectory/actions/runs/44595144130) mit allen 15 Prüfungen ausgerollt. Geprüft sind 62 tatsächliche Browserfälle in neun frisch bereinigten Gruppen, 75 Browser-Anmeldetests, 3.367 Frontend-Fälle und 114 Playwright-Abläufe. Der erweiterte PIM-Test öffnet das Panel per Tastatur, damit nachladende Inhalte keinen Zeigerklick verschieben; die Selbstfreigabe bleibt abgewiesen. Die Blueprint-Auswahl wartet auf Bedienbereitschaft und überwacht Tastaturauswahl und Antwort gemeinsam, ohne unbehandelte Promise-Ablehnung.

Helm-Revision 90: alle elf Deployments bereit, die zehn übrigen Deployment-Spezifikationen unverändert; ausgeführter Produktionsbuild und genaue MFA-Rückkehrroute bestätigt. [Rolloutnachweis](deployment/pim-workflows-1.0.57-2026-11-19.json). Echte produktive Benutzerzuweisungen wurden nicht durchgeführt. Weitere MFA- und Verwaltungsabläufe bleiben im Arbeitsplan offen.
