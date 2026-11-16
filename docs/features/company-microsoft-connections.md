# Firmen-Lizenzpools mit Microsoft 365 verknüpfen

Mit [Release 1.0.55](../deployment/core-1.0.55-2026-11-16.json) sind ausdrücklich bestätigte Verknüpfungen, ein manuell bestätigter Lizenzabgleich, die Wiederherstellung unterbrochener Vorgänge und die bewusste Prüfung unklarer Anbieterwirkungen für die eigene Firma in der GUI ausgeliefert. Die vollständige Linux-CI und die konfigurierte Browser-Gesamtkette mit ausdrücklich simulierter Microsoft-Grenze bestehen. Ohne die unten beschriebene geschützte Firmenkonfiguration bleibt die Verbindung deaktiviert. Die Abnahme mit einem echten Microsoft-Testtenant steht noch aus.

Unter **Apps & Lizenzen → Lizenzpool → Microsoft 365 · Verknüpfungen dieses Lizenzpools** lässt sich der aktuelle Stand laden. Ein berechtigter Firmenbenutzer bestätigt zunächst das angezeigte Microsoft-Verzeichnis und die vorgesehenen Anwendungen. Danach kann er ein aktuell aktives Benutzerprodukt auswählen und eigene Mitarbeitende anhand ihrer geprüften Microsoft-Objekt-ID zuordnen. Die Anwendung errät keine Zuordnung aus E-Mail-Adressen.

Jede Änderung benötigt eine Begründung, ausdrückliche Bestätigung und einen aktuellen Firmen-Lizenznachweis mit tatsächlicher frischer MFA. Bestätigungen binden die angezeigten öffentlichen Microsoft-IDs, die Verbindungs-ID und deren Version. Änderungen zwischen Anzeige und Bestätigung werden abgelehnt. Verknüpfungen, ursprünglicher Akteur und Änderungsgrund bleiben im Protokoll erhalten. Der bestehende lokale Bestand und die Herkunft manueller, Blueprint- und Gruppenzuweisungen bleiben separat sichtbar.

Eine Verknüpfung allein vergibt oder entzieht **keine** Microsoft-Lizenz. Der globale Legacy-Worker darf Firmenpools weiterhin nicht übernehmen. Eine Anbieterannahme gilt erst nach unabhängiger Beobachtung als bestätigte Wirkung. Ein Verbindungsfehler löscht keine lokalen Lizenzplätze; eine ungültige eigene Sitzung räumt die privaten Ansichten auf.

## Aktuellen Lizenzabgleich prüfen

Bei einem verknüpften Benutzer lässt sich **Microsoft-Lizenzabgleich prüfen** öffnen. Die Vorschau vergleicht die aktuelle kanonische Benutzerberechtigung und alle tatsächlichen lokalen Quellen mit der beobachteten Microsoft-Zuweisung. Bei Lizenzgruppen wird die aktuelle berechtigte Mitgliedschaft erneut von Identity gelesen; ein veralteter materialisierter Gruppenplatz genügt nicht. Eine zusätzliche gültige manuelle Quelle kann den Anspruch aufrechterhalten.

Für eine vorgeschlagene neue Zuweisung wird außerdem der aktuelle Microsoft-SKU-Bestand gelesen. Fehlende, inaktive oder ausgeschöpfte Benutzerprodukte führen zu einem Konflikt. Bestandszahlen sind Anbieterbeobachtungen und werden nicht in lokale Plätze umgerechnet. Bestehende direkte oder gruppenbasierte Microsoft-Lizenzen werden durch die Vorschau nicht als eigene übernommen. Geänderte oder nicht erreichbare Gruppenquellen geben keine Änderung frei.

Die Vorschau ist rein lesend. Eine angezeigte mögliche Zuweisung oder Rückgabe ist noch kein Versand und keine Bestätigung einer Anbieterwirkung.

## Einen geprüften Lizenzabgleich bestätigen

Der bestätigte Lizenzabgleich verlangt einen eigenen Grund und eine Bestätigung der genau angezeigten Aktion. Zwischen Vorschau, dauerhafter Vorbereitung und Versand werden ursprüngliche Firmenberechtigung, frische MFA, lokale Quellen, Gruppenzugehörigkeit, Verknüpfungen und Anbieterbeobachtung erneut geprüft. Änderungen verhindern den Versand. Eine Sperre pro zugeordnetem Benutzer und Lizenzprodukt verhindert parallele Doppelaufrufe; Datenbanktransaktionen bleiben vor dem Anbieteraufruf abgeschlossen.

Microsoft erhält höchstens einen Schreibaufruf für den zugelassenen Vorgang. Eine verlorene HTTP-Antwort führt nicht zu einer automatischen Wiederholung. Dieselbe Vorgangs-ID liefert ausschließlich den vorhandenen Originalnachweis; eine noch offene Vorbereitung oder ein unterbrochener Versand verlangt eine gesonderte Wiederherstellung. Token und unverschlüsselte Versandberechtigung werden nicht im Vorgang gespeichert.

Eine positive Antwort bleibt **Bestätigung ausstehend**. Erst ein neuer, ausdrücklich bestätigter Abgleich kann eine aktive direkte Zuweisung mit genau den gebundenen Serviceplänen bzw. deren Abwesenheit bestätigen. Der ursprüngliche offene Anbieterversuch bleibt dabei erhalten. Eine geänderte lokale Anforderung führt zunächst zu einem sichtbaren Konflikt und löst keine automatische Gegenbuchung aus. Gruppenlizenzen und fremde direkte Lizenzen bleiben erhalten.

Eine eindeutige Ablehnung und eine Wartefrist bleiben im Originalnachweis sichtbar. Ein unbekanntes Ergebnis bleibt ungeklärt: Eine möglicherweise ausgeführte Ergänzung begründet keine neue Verwaltungsübernahme. Auch nach Ablauf der ursprünglichen MFA-Frist wird ein tatsächlich versandtes Ergebnis unter dem ursprünglichen Vorgang protokolliert; private Daten werden ohne weiterhin gültige Berechtigung nicht zurückgegeben. Fehlen später die Konfigurationsdateien, können berechtigte Benutzer historische Nachweise weiter lesen und unbenutzte Verknüpfungen entfernen.

## Unterbrochenen Vorgang wiederherstellen

Bei einer gespeicherten Kontozuordnung öffnet **Unterbrochenen Lizenzvorgang prüfen** den ursprünglichen Vorgang mit Phase, Benutzer und Begründung. Die Prüfung benötigt keine Anbieterzugänge und ruft Microsoft nicht auf. Liegt keine Unterbrechung vor, erscheint ein leerer Zustand ohne Wiederherstellungsaktion.

Eine Wiederherstellung verlangt einen aktuell berechtigten Firmenbenutzer mit frischer MFA, eine eigene Begründung und eine zusätzliche ausdrückliche Bestätigung. Sie bindet genau den angezeigten ursprünglichen Vorgang und dessen Phase. Ein noch laufender Vorgang oder ein zwischenzeitlich geänderter Stand verhindert die Wiederherstellung. Sie erteilt keine neue Versandfreigabe.

War der Versand noch nicht freigegeben, wird der alte Versuch als **nicht versendet** abgeschlossen. Nach bereits erteilter Versandfreigabe bleibt das Ergebnis **unklar**. In beiden Fällen bleiben Eigentumsnachweis und ältere offene Anbieterversuche erhalten; es wird keine Lizenz zugewiesen, übernommen oder entzogen. Eine spätere neue Aktion verlangt erneut die aktuelle Abgleichvorschau und deren Bestätigung.

Der aktuelle Wiederherstellungsbenutzer wird separat protokolliert. Der alte Anmelde- und Änderungsnachweis wird nicht ersetzt, auch wenn dessen MFA inzwischen abgelaufen ist oder ein anderer Administrator übernimmt. Die Ergebnisquittung des alten Versuchs nennt den ursprünglichen Vorgang als Dienstakteur. Geht die Antwort auf die Wiederherstellung verloren, kann ihre ursprüngliche Vorgangs-ID ausdrücklich erneut geprüft werden; es entsteht keine automatische Wiederholung.

## Unklare Anbieterwirkung entscheiden

**Unklaren Lizenzversuch prüfen** zeigt den ursprünglichen unbekannten Schreibversuch, dessen Akteur und Begründung sowie den aktuell unabhängig gelesenen Microsoft-Bestand und lokalen Anspruch. Der Versuch muss zur gleichen gespeicherten Firma, Verbindung, Benutzer- und Produktverknüpfung gehören. Aktuelle Gruppenquellen werden erneut gelesen; geänderte oder nicht verfügbare Nachweise erlauben keine Entscheidung.

Vor einer Entscheidung gilt eine Wartefrist von mindestens 30 Sekunden nach Abschluss des ursprünglichen Versuchs. Eine längere gemeldete Anbieterwartezeit bleibt wirksam. Die Wartefrist beendet keinen Anbieterauftrag; eine verspätete Wirkung ist weiter möglich. **Prüfung aktualisieren** liest den Stand ausdrücklich erneut.

Es gibt zwei Entscheidungen:

- **Passende direkte Lizenz in die Verwaltung übernehmen:** nur für eine ursprüngliche unklare Ergänzung bei vorher unabhängig bestätigter Abwesenheit, aktuell passender direkter Lizenz und unveränderter Benutzer-/SKU-/Serviceplanzuordnung. Fremde oder geerbte Gruppenlizenzen werden nicht übernommen. Bei einem positiven lokalen Anspruch müssen direkte Lizenz und Konto aktuell aktiv bestätigt sein. Die aktuelle Firmengeneration muss zur bestätigten Verbindung passen.
- **Unklaren Versuch schließen · Bestand beibehalten:** beendet die ungeklärte Verwaltungssperre ohne neue Übernahme oder Anbieteränderung. Ein noch bestehender eigener Verwaltungsnachweis bleibt erhalten; unabhängig bestätigte direkte Abwesenheit gibt ihn frei. Eine neue Zuweisung oder Rückgabe erfordert anschließend einen neuen regulären Abgleich mit neuer Vorgangs-ID, aktueller Vorschau und eigener Bestätigung.

Ohne aktuellen lokalen Anspruch kann eine passende direkte Lizenz ausdrücklich **für kontrollierte Rückgabe** übernommen werden. Das Ergebnis bleibt als Rückgabebedarf sichtbar; diese Entscheidung erteilt keinen positiven lokalen Anspruch und führt keine automatische Rückgabe aus. Bei geänderter Firmengeneration ist zunächst nur das Schließen des alten Versuchs erlaubt; die Verbindung kann danach mit aktueller Berechtigung erneut bestätigt werden.

Beide Entscheidungen verlangen aktuelle Firmenberechtigung, tatsächliche frische MFA, eine eigene Begründung und eine zusätzliche Bestätigung. Der genau angezeigte Versuch, die Entscheidung und der aktuelle Stand bleiben gebunden. Der tatsächliche Datenbank-Commit prüft Berechtigung und lokale Nachweise erneut. Die Entscheidung erhält einen neuen menschlichen Audit-Beleg; der ursprüngliche unbekannte Ausgang bleibt unverändert und wird nicht nachträglich als erfolgreiche Anbieterantwort ausgegeben. Keine Prüfentscheidung versendet eine Lizenzanfrage. Eine verlorene Antwort wird ausschließlich über den ursprünglichen Entscheidungsnachweis ausdrücklich geprüft.

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

Die SQL-Prüfungen verwenden echte temporäre PostgreSQL-Datenbanken und HTTP-Routen. Anbieterantworten sind darin ausdrücklich simuliert. Die Client- und Oberflächentests prüfen Bindungen, große Versionsnummern, Bestätigung, unveränderte Wiederaufnahme und Sitzungswechsel. Der ursprüngliche Browserfall prüft mit zentraler TOTP-MFA und produktiv gebautem Next.js den unkonfigurierten Zustand ohne Anbieteränderung. Der zusätzliche [konfigurierte Browserablauf](../testing/company-microsoft-browser-2026-11-16.json) bedient Verbindung, Produkt-/Benutzerzuordnung, unterbrochenen Ergebnisbeleg, Wiederherstellung, bewusste Übernahme und separat bestätigte Rückgabe durch die echte Oberfläche. Originale BFF-Sitzung, aktuelle Firmenberechtigung, zentrale TOTP-MFA, SQL-Belege und reguläre JWT-Prüfung bleiben real; Passwortanbieter und externe Microsoft-Antworten sind ausdrückliche Test-Fixtures. Der Firmeninhaber erhält keine globale Administratorrolle. Der Ablauf löst genau eine simulierte Zuweisung und eine simulierte Rückgabe aus; Wiederherstellung und Prüfung versenden nichts erneut. Desktop- und mobile Ansichten wurden geprüft. Die dabei gefundenen internen Protokollformate und mehrdeutigen Feldnamen sind an API bzw. Oberfläche korrigiert.

Nativ geprüft sind Vorbereitung, einmaliger Versand, dauerhafter Originalnachweis, unabhängige Bestätigung, offene Anbieterversuche, Wartefristen, gleichzeitige Anfragen und MFA-Ablauf an den tatsächlichen SQL-Commitgrenzen. Anbieterantworten sind in diesen Fällen ausdrücklich simuliert; diese Prüfung ist keine echte Microsoft-Abnahme.

Die [Wiederherstellungsprüfung](../testing/company-microsoft-recovery-2026-11-16.json) umfasst tatsächliche SQL-Vorgänge vor und nach der Versandfreigabe, einen abgelaufenen ursprünglichen Nachweis, unabhängige aktuelle Administratoren, unveränderte ältere Anbieterversuche und eine Ablaufkontrolle beim tatsächlichen Commit. Die Oberfläche prüft leeren Zustand, Grund, Bestätigung, Zielbindung und unveränderte ausdrückliche Wiederaufnahme. Der konfigurierte Browserablauf prüft diese Wiederherstellung zusätzlich über die echte Oberfläche mit einer ausdrücklichen Störung des Ergebnisbelegs.

Die [Prüfung unbekannter Ergebnisse](../testing/company-microsoft-review-2026-11-16.json) umfasst tatsächliche SQL-Transaktionen, die Wartefrist, unabhängige aktuelle Anbieterbeobachtung, bewusste Übernahme, negative lokale Berechtigung mit später separat bestätigter Rückgabe, Ablauf beim physischen Commit, geänderte Firmengeneration, Zielkonkurrenz, unterdrückte tatsächliche Zieleffekte und unveränderte Originalbelege. Externe Antworten sind ausdrücklich simuliert; die Microsoft-Tenant-Abnahme wird dadurch nicht ersetzt.

Die vollständige Linux-CI mit allen 15 Jobs und der live geprüfte Rollout 1.0.55 sind abgeschlossen. Die echte Microsoft-Tenant-Abnahme bleibt offen; produktive Anbieterzugänge, Zustimmungen oder Lizenzänderungen wurden nicht erzeugt. Der ausgelieferte, noch unkonfigurierte Stand allein schließt den Anbieterablauf des Kernumfangs nicht ab.
