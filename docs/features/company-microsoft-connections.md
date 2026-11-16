# Firmen-Lizenzpools mit Microsoft 365 verknüpfen

Dieser Entwicklungsstand ergänzt die vorhandene Bestandslesung um ausdrücklich bestätigte Verknüpfungen für eine eigene Firma. Er ist noch nicht produktiv ausgerollt. Der anschließende Cloud-Abgleich und die Abnahme mit einem echten Microsoft-Testtenant bleiben offen.

Unter **Apps & Lizenzen → Lizenzpool → Microsoft 365 · Verknüpfungen dieses Lizenzpools** lässt sich der aktuelle Stand laden. Ein berechtigter Firmenbenutzer bestätigt zunächst das angezeigte Microsoft-Verzeichnis und die vorgesehenen Anwendungen. Danach kann er ein aktuell aktives Benutzerprodukt auswählen und eigene Mitarbeitende anhand ihrer geprüften Microsoft-Objekt-ID zuordnen. Die Anwendung errät keine Zuordnung aus E-Mail-Adressen.

Jede Änderung benötigt eine Begründung, ausdrückliche Bestätigung und einen aktuellen Firmen-Lizenznachweis mit tatsächlicher frischer MFA. Bestätigungen binden die angezeigten öffentlichen Microsoft-IDs, die Verbindungs-ID und deren Version. Änderungen zwischen Anzeige und Bestätigung werden abgelehnt. Verknüpfungen, ursprünglicher Akteur und Änderungsgrund bleiben im Protokoll erhalten. Der bestehende lokale Bestand und die Herkunft manueller, Blueprint- und Gruppenzuweisungen bleiben separat sichtbar.

Eine Verknüpfung allein vergibt oder entzieht **keine** Microsoft-Lizenz. Der globale Legacy-Worker darf Firmenpools weiterhin nicht übernehmen. Die neue Oberfläche zeigt keine Cloud-Zuweisung als bestätigt an. Ein Verbindungsfehler löscht keine lokalen Lizenzplätze; eine ungültige eigene Sitzung räumt die privaten Ansichten auf.

## Aktuellen Lizenzabgleich prüfen

Bei einem verknüpften Benutzer lässt sich **Microsoft-Lizenzabgleich prüfen** öffnen. Die Vorschau vergleicht die aktuelle kanonische Benutzerberechtigung und alle tatsächlichen lokalen Quellen mit der beobachteten Microsoft-Zuweisung. Bei Lizenzgruppen wird die aktuelle berechtigte Mitgliedschaft erneut von Identity gelesen; ein veralteter materialisierter Gruppenplatz genügt nicht. Eine zusätzliche gültige manuelle Quelle kann den Anspruch aufrechterhalten.

Für eine vorgeschlagene neue Zuweisung wird außerdem der aktuelle Microsoft-SKU-Bestand gelesen. Fehlende, inaktive oder ausgeschöpfte Benutzerprodukte führen zu einem Konflikt. Bestandszahlen sind Anbieterbeobachtungen und werden nicht in lokale Plätze umgerechnet. Bestehende direkte oder gruppenbasierte Microsoft-Lizenzen werden durch die Vorschau nicht als eigene übernommen. Geänderte oder nicht erreichbare Gruppenquellen geben keine Änderung frei.

Die Vorschau ist rein lesend. Eine angezeigte mögliche Zuweisung oder Rückgabe ist noch kein Versand und keine Bestätigung einer Anbieterwirkung. Der anschließende dauerhaft protokollierte Schreibpfad mit gesonderter Rückbestätigung bleibt in Arbeit.

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

Offen sind der vollständige Firmen-Cloud-Abgleich mit dauerhaftem Versandnachweis, unabhängiger Bestätigung und Behandlung unklarer Ergebnisse, der konfigurierte Browserablauf sowie eine echte Microsoft-Tenant-Abnahme. Es wurden keine produktiven Anbieterzugänge, Zustimmungen oder Lizenzänderungen erzeugt. Diese Verknüpfungsverwaltung allein schließt den Anbieterablauf des Kernumfangs nicht ab.
