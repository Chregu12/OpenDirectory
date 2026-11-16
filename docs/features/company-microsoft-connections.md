# Firmen-Lizenzpools mit Microsoft 365 verknüpfen

Dieser Entwicklungsstand ergänzt die vorhandene Bestandslesung um ausdrücklich bestätigte Verknüpfungen und einen manuell bestätigten Lizenzabgleich für eine eigene Firma. Er ist noch nicht produktiv ausgerollt. Die Wiederherstellung unterbrochener Vorgänge, die ausdrückliche Behandlung unbekannter Ergebnisse und die Abnahme mit einem echten Microsoft-Testtenant bleiben offen. Bis dahin ist dieser Schreibpfad nicht zur produktiven Aktivierung freigegeben.

Unter **Apps & Lizenzen → Lizenzpool → Microsoft 365 · Verknüpfungen dieses Lizenzpools** lässt sich der aktuelle Stand laden. Ein berechtigter Firmenbenutzer bestätigt zunächst das angezeigte Microsoft-Verzeichnis und die vorgesehenen Anwendungen. Danach kann er ein aktuell aktives Benutzerprodukt auswählen und eigene Mitarbeitende anhand ihrer geprüften Microsoft-Objekt-ID zuordnen. Die Anwendung errät keine Zuordnung aus E-Mail-Adressen.

Jede Änderung benötigt eine Begründung, ausdrückliche Bestätigung und einen aktuellen Firmen-Lizenznachweis mit tatsächlicher frischer MFA. Bestätigungen binden die angezeigten öffentlichen Microsoft-IDs, die Verbindungs-ID und deren Version. Änderungen zwischen Anzeige und Bestätigung werden abgelehnt. Verknüpfungen, ursprünglicher Akteur und Änderungsgrund bleiben im Protokoll erhalten. Der bestehende lokale Bestand und die Herkunft manueller, Blueprint- und Gruppenzuweisungen bleiben separat sichtbar.

Eine Verknüpfung allein vergibt oder entzieht **keine** Microsoft-Lizenz. Der globale Legacy-Worker darf Firmenpools weiterhin nicht übernehmen. Eine Anbieterannahme gilt erst nach unabhängiger Beobachtung als bestätigte Wirkung. Ein Verbindungsfehler löscht keine lokalen Lizenzplätze; eine ungültige eigene Sitzung räumt die privaten Ansichten auf.

## Aktuellen Lizenzabgleich prüfen

Bei einem verknüpften Benutzer lässt sich **Microsoft-Lizenzabgleich prüfen** öffnen. Die Vorschau vergleicht die aktuelle kanonische Benutzerberechtigung und alle tatsächlichen lokalen Quellen mit der beobachteten Microsoft-Zuweisung. Bei Lizenzgruppen wird die aktuelle berechtigte Mitgliedschaft erneut von Identity gelesen; ein veralteter materialisierter Gruppenplatz genügt nicht. Eine zusätzliche gültige manuelle Quelle kann den Anspruch aufrechterhalten.

Für eine vorgeschlagene neue Zuweisung wird außerdem der aktuelle Microsoft-SKU-Bestand gelesen. Fehlende, inaktive oder ausgeschöpfte Benutzerprodukte führen zu einem Konflikt. Bestandszahlen sind Anbieterbeobachtungen und werden nicht in lokale Plätze umgerechnet. Bestehende direkte oder gruppenbasierte Microsoft-Lizenzen werden durch die Vorschau nicht als eigene übernommen. Geänderte oder nicht erreichbare Gruppenquellen geben keine Änderung frei.

Die Vorschau ist rein lesend. Eine angezeigte mögliche Zuweisung oder Rückgabe ist noch kein Versand und keine Bestätigung einer Anbieterwirkung.

## Einen geprüften Lizenzabgleich bestätigen

Der anschließende Entwicklungsablauf verlangt einen eigenen Grund und eine Bestätigung der genau angezeigten Aktion. Zwischen Vorschau, dauerhafter Vorbereitung und Versand werden ursprüngliche Firmenberechtigung, frische MFA, lokale Quellen, Gruppenzugehörigkeit, Verknüpfungen und Anbieterbeobachtung erneut geprüft. Änderungen verhindern den Versand. Eine Sperre pro zugeordnetem Benutzer und Lizenzprodukt verhindert parallele Doppelaufrufe; Datenbanktransaktionen bleiben vor dem Anbieteraufruf abgeschlossen.

Microsoft erhält höchstens einen Schreibaufruf für den zugelassenen Vorgang. Eine verlorene HTTP-Antwort führt nicht zu einer automatischen Wiederholung. Dieselbe Vorgangs-ID liefert ausschließlich den vorhandenen Originalnachweis; eine noch offene Vorbereitung oder ein unterbrochener Versand verlangt eine gesonderte Wiederherstellung. Token und unverschlüsselte Versandberechtigung werden nicht im Vorgang gespeichert.

Eine positive Antwort bleibt **Bestätigung ausstehend**. Erst ein neuer, ausdrücklich bestätigter Abgleich kann eine aktive direkte Zuweisung mit genau den gebundenen Serviceplänen bzw. deren Abwesenheit bestätigen. Der ursprüngliche offene Anbieterversuch bleibt dabei erhalten. Eine geänderte lokale Anforderung führt zunächst zu einem sichtbaren Konflikt und löst keine automatische Gegenbuchung aus. Gruppenlizenzen und fremde direkte Lizenzen bleiben erhalten.

Eine eindeutige Ablehnung und eine Wartefrist bleiben im Originalnachweis sichtbar. Ein unbekanntes Ergebnis bleibt ungeklärt: Eine möglicherweise ausgeführte Ergänzung begründet keine neue Verwaltungsübernahme. Auch nach Ablauf der ursprünglichen MFA-Frist wird ein tatsächlich versandtes Ergebnis unter dem ursprünglichen Vorgang protokolliert; private Daten werden ohne weiterhin gültige Berechtigung nicht zurückgegeben. Fehlen später die Konfigurationsdateien, können berechtigte Benutzer historische Nachweise weiter lesen und unbenutzte Verknüpfungen entfernen.

## Geschützte Konfiguration

Die bestehende [Bestandslesung und Dateivorbereitung](../../services/connectors-rust/READ_PROVIDERS.md#show-the-selected-companys-microsoft-stock-in-the-gui) bleibt die Grundlage. Zusätzlich wird eine ausdrücklich geprüfte Konfiguration für die Benutzerprüfung und den späteren Schreibpfad benötigt:

```yaml
apps:
  policy-service:
    mountFiles: true
    mountFilesUID: 100
    filesSecretName: opendirectory-company-microsoft
    env:
      LICENSE_COMPANY_PROVIDER_TENANT_ID: YOUR-OPENDIRECTORY-COMPANY-UUID
      LICENSE_COMPANY_PROVIDER_CONFIG_FILE: /run/opendirectory/company-microsoft-read.json
      LICENSE_COMPANY_PROVIDER_WRITE_CONFIG_FILE: /run/opendirectory/company-microsoft-write.json
```

Beide Dateien verwenden das bestehende Microsoft-JSON-Format mit `schemaVersion`, `provider`, `consentReviewed`, `tenantId`, `clientId` und `clientSecret`. Sie müssen denselben Microsoft-Tenant auswählen; die Anwendungen können verschieden sein. Dateien und Secret-Werte gehören außerhalb von Git und Chat in den vorhandenen geschützten Secret-Mount. Nur Pfade werden als Umgebungsvariablen gesetzt. Andere OpenDirectory-Firmen erhalten `not_configured`, bevor eine Datei gelesen oder ein Anbieter aufgerufen wird.

Für den Bestandsabruf nennt Microsoft `LicenseAssignment.Read.All` als kleinste Anwendungsberechtigung. Die Benutzerabfrage und der spätere Lizenzschreibpfad verwenden gesondert geprüfte Graph-Anwendungsrechte: siehe [subscribedSkus](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0), [Benutzer lesen](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0) und [assignLicense](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0). Die tatsächlichen ausgewählten Benutzerfelder und Rechte müssen am Testtenant bestätigt werden. Eine Ablehnung führt zu keiner automatischen Erweiterung der Zustimmung.

Eine reine Secret-Rotation bei unveränderten öffentlichen IDs bleibt möglich. Geänderte Anwendungs-IDs oder eine neue Firmengeneration verlangen eine erneute Bestätigung. Der Microsoft-Tenant einer bestehenden Verbindung ist unveränderlich. Vor einer Trennung werden die zugehörigen Verknüpfungen entfernt; vorhandene verwaltete oder ungeklärte Lieferungen müssen zuerst bereinigt werden. Historische Belege bleiben bestehen.

## Prüfumfang und verbleibende Arbeit

Die SQL-Prüfungen verwenden echte temporäre PostgreSQL-Datenbanken und HTTP-Routen. Anbieterantworten sind darin ausdrücklich simuliert. Die Client- und Oberflächentests prüfen Bindungen, große Versionsnummern, Bestätigung, unveränderte Wiederaufnahme und Sitzungswechsel. Der tatsächliche Browserfall prüft mit zentraler TOTP-MFA und produktiv gebautem Next.js den unkonfigurierten Zustand ohne Anbieteränderung; sein Passwortanbieter ist eine ausdrückliche Test-Fixture.

Nativ geprüft sind Vorbereitung, einmaliger Versand, dauerhafter Originalnachweis, unabhängige Bestätigung, offene Anbieterversuche, Wartefristen, gleichzeitige Anfragen und MFA-Ablauf an den tatsächlichen SQL-Commitgrenzen. Anbieterantworten sind in diesen Fällen ausdrücklich simuliert; diese Prüfung ist keine echte Microsoft-Abnahme.

Offen sind die gesonderte Wiederherstellung nach Prozessverlust, die ausdrückliche Entscheidung zu unbekannten Ergänzungen, der konfigurierte Browserablauf, eine echte Microsoft-Tenant-Abnahme, die abschließende vollständige CI und der Rollout. Es wurden keine produktiven Anbieterzugänge, Zustimmungen oder Lizenzänderungen erzeugt. Dieser Entwicklungsstand allein schließt den Anbieterablauf des Kernumfangs nicht ab.
