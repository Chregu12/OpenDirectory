# Rust-Connectoren: Bestandsaufnahme und erster Schritt

Stand: 3. November 2026. Der lokale Fachplan ist eine Zielbeschreibung; seine
Module und Fähigkeiten wurden vorliegend nicht als bereits vorhanden angenommen.

| Quelle | Codebefund | Entscheidung |
| --- | --- | --- |
| OpenDirectory | `GraphCapacityClient` liest begrenzte `subscribedSkus`; `CapacityObserver` bindet einen bestätigten Source, begrenzt parallele Läufe und speichert Beobachtungen transaktional. `GraphLicenseClient` und `FulfillmentWorker` behandeln direkte Zuweisungen separat. | Die Rust-Implementierung ersetzt zunächst nur den HTTP-Leseteil des bestehenden Kapazitätsbeobachters. Datenbank, Berechtigungen, Historie und lokale Vergabe bleiben dieselbe Quelle. |
| [SaaSLens `schema.prisma`](https://github.com/Wondermove-Inc/saaslens/blob/10a93ea490d1d7d98df041b368d04d292096c7f5/prisma/schema.prisma) | `Subscription` verbindet Organisation, App, Preis, Währung und optionale Seat-Zahlen; Personen- und Teamzuweisungen sind eigene Beziehungen. `@@unique([appId, organizationId])` lässt im dortigen Modell nur eine Subscription pro App und Organisation zu. | Fachliche Anregung für getrennte Beziehungen und Kosten, aber keine 1:1-Übernahme: OpenDirectory muss mehrere erhaltene Verträge/Pools für dieselbe Anwendung unterstützen und unterschiedliche Vergabequellen erklären. `seat-detector.ts` enthält Schätzungen aus Zahlungen; daraus wird kein bestätigter Bestand abgeleitet. |
| [Ampersand `providers/adobe.go`](https://github.com/amp-labs/connectors/blob/dfc81ccede88097c45bb82069de5aef082c446fd/providers/adobe.go) | Adobe ist dort mit Client-Credentials-Authentifizierung und expliziten Scopes registriert. Die ausgewiesenen allgemeinen Read-, Write- und Subscribe-Capabilities sind `false`; das [Beispiel](https://github.com/amp-labs/connectors/blob/dfc81ccede88097c45bb82069de5aef082c446fd/examples/auth_connectors/adobe/adobe.go) ruft Adobe Experience Platform auf. | Dies belegt keinen fertigen Adobe User-Management- oder Lizenzconnector. Dafür sind eigene API-Verträge, Enterprise-Berechtigung, sichere Organisationsbindung und Tests nötig. |
| [Nango](https://github.com/NangoHQ/nango/tree/f198c45a56b9a6b5de4d093b6177a1ccbf326ba8) | Plattform für Verbindungen und API-Integrationen; ihr [Hauptlizenztext](https://github.com/NangoHQ/nango/blob/f198c45a56b9a6b5de4d093b6177a1ccbf326ba8/LICENSE) ist Elastic License 2.0. | Architekturvergleich für Verbindung und Status, keine kopierten Komponenten und kein Nango-Dienst. Eine kommerzielle Einbettung von Nango müsste separat anhand der konkreten Nutzung und Lizenzbedingungen beurteilt werden. |

## Umgesetzt und überprüft

Der erste Rust-Connector ist ein eng begrenzter, lesender Microsoft-Graph-Abruf.
Der bestehende Node-Prozess bezieht das Token mit seiner geschützten Konfiguration
und gibt es nur über stdin an den kurzlebigen Rust-Prozess. Der Rust-Prozess
verwendet feste Microsoft-URLs, begrenzt Seiten und Datenmengen, prüft
Fortsetzungslinks und gibt keine fremden Felder weiter. Der bestehende Observer
validiert das Ergebnis erneut. Fehler, Abbruch und 429 werden nicht als Erfolg
gespeichert. Tests verwenden lokale HTTP-Fixtures; ein echter Microsoft-Tenant
und dessen Consent wurden nicht geprüft.

Der ergänzte Rust-Lesevertrag für explizit gebundene Microsoft-Benutzer ist
unten beschrieben. Offen bleiben vollständige Connector-Verwaltung, Adobe Enterprise, Vertrags- und
Kostenmodell, Mandantenbindung über alle neuen Daten sowie JML mit Nexpt. Weder
eine lokale Lizenzvergabe noch eine erfolgreiche Kapazitätsbeobachtung belegt
eine externe Bereitstellung.

## GitHub-Recherche für weitere Anbieter, 8. November 2026

Repository-Metadaten, konkrete Quelldateien, Paketmanifest und Lizenztexte wurden
gelesen. Kein fremder Connector wurde installiert oder ausgeführt. SDK-Methoden
sind Implementierungsbeispiele; ihre Existenz ersetzt weder den aktuellen
Herstellervertrag noch einen erfolgreichen Test gegen einen echten Mandanten.
Die Commit-Referenzen halten den tatsächlich geprüften Stand fest.

| Anbieter / Projekt | Geprüfter Code und Eignung | Lizenz / Wartungsstand |
| --- | --- | --- |
| Microsoft: [sreeise/graph-rs-sdk](https://github.com/sreeise/graph-rs-sdk/tree/5e3a7ffffcba660ed26a04efc566a253058aff6e) | Rust. `src/subscribed_skus/request.rs` und `src/users/request.rs` enthalten Bestandsabruf und `assign_license`; `src/users/license_details` enthält Benutzerlizenzabfragen. Als Endpunkt-/OAuth-Referenz verwenden. Der vorhandene enge OpenDirectory-`reqwest`-Connector bleibt der Ausgangspunkt. Generierte zusätzliche Schreibmethoden nicht als bestätigte API-Fähigkeiten übernehmen. | [MIT](https://github.com/sreeise/graph-rs-sdk/blob/5e3a7ffffcba660ed26a04efc566a253058aff6e/LICENSE.md); letzter geprüfter Commit 28.08.2025, nicht archiviert. |
| Google Workspace: [Byron/google-apis-rs, google-licensing1](https://github.com/Byron/google-apis-rs/tree/78b8ced0f9dd66a7673f45de74d5768f1bfc67c2/gen/licensing1) | Bereits Rust. Der konkrete Licensing-Client bietet `get`, `list_for_product`, `list_for_product_and_sku`, `insert`, `delete`, `patch` und `update`. Gute Grundlage für echte Lizenzzuweisungen. Das ist kein fertiger Connector für gekaufte Plätze, Rechnungen oder OpenDirectory-Benutzerbindungen. | Das [Crate-Manifest](https://github.com/Byron/google-apis-rs/blob/78b8ced0f9dd66a7673f45de74d5768f1bfc67c2/gen/licensing1/Cargo.toml) erklärt MIT; `google-licensing1` 7.0.0+20251215, Repository-Commit 17.10.2026. Nicht aus dem GitHub-Label `NOASSERTION` auf eine fehlende Lizenz schliessen. |
| GitHub Copilot: [XAMPPRocky/octocrab](https://github.com/XAMPPRocky/octocrab/tree/c2ede077f77d6b64a0bdd4b6e78e0a4714fc54e2) | Bereits Rust. `src/api/orgs/copilot.rs` liest Billing-/Seat-Daten; `copilot_seat_manager.rs` enthält Hinzufügen/Entfernen für Benutzer und Teams. Dazu existieren gezielte Seat-Tests. API-Version, Tarif und Abrechnungswirkung separat prüfen; Hinzufügen kann neue Kosten auslösen. | [MIT ODER Apache-2.0 laut Manifest](https://github.com/XAMPPRocky/octocrab/blob/c2ede077f77d6b64a0bdd4b6e78e0a4714fc54e2/Cargo.toml); letzter geprüfter Commit 31.10.2026, nicht archiviert. |
| Adobe: [adobe-apiplatform/user-sync.py](https://github.com/adobe-apiplatform/user-sync.py/tree/a6aad1155ad3930f32a3624f5fe8f9809d12d04f) und [umapi-client.py](https://github.com/adobe-apiplatform/umapi-client.py/tree/b9d0063825f3c6855144ed181d626f562ab8501c) | Offizieller Python-Code für Adobe-Benutzer, Gruppen und Produktzugriff. Der Client enthält `OAuthS2S` in `umapi_client/auth.py`; User Sync wählt ihn in `user_sync/connector/umapi_util.py`. Für Rust nur den benötigten OAuth-/UMAPI-Ablauf nach aktuellem Vertrag implementieren. Das ältere README erwähnt auch JWT; für die neue Verbindung den vorhandenen OAuth-S2S-Pfad prüfen. Kein belegter Kauf-/Rechnungsconnector. | MIT bei beiden Projekten. User-Sync-Commit 02.10.2026; Client-Default-Branch-Commit 20.07.2023, letzter Repository-Push 18.10.2023. |
| Slack: [slackapi/python-slack-sdk](https://github.com/slackapi/python-slack-sdk/tree/decc671fe8d309f0a25898f79ec356b6a7bda469) | Offizieller Python-Client. `slack_sdk/scim/v1/client.py` enthält Benutzer-/Gruppenabfragen und Kontenoperationen; `tests/slack_sdk/scim` enthält Mock-/Retry-Tests. Gute Vorlage für einen begrenzten Rust-SCIM-Client. Benutzerverwaltung bestätigt keinen gekauften Lizenzbestand. | [MIT](https://github.com/slackapi/python-slack-sdk/blob/decc671fe8d309f0a25898f79ec356b6a7bda469/LICENSE); letzter geprüfter Commit 06.11.2026, nicht archiviert. |
| Atlassian: [ConductorOne/baton-atlassian](https://github.com/ConductorOne/baton-atlassian/tree/beb315e0e6bbf0aa2b5f381d06c75cfa1912fba9) | Go. `pkg/connector/workspaces.go` implementiert Produkt-/Workspace-Zugriff mit `Grant`/`Revoke`; Gruppen und Benutzer sind gesonderte Ressourcen. Gute fachliche Referenz für Jira-/Confluence-Zugriff. Nicht die umfangreichen Admin-Berechtigungen oder Kontenlöschung pauschal übernehmen; gekauftes Kontingent und Vertragsdaten bleiben ein eigener Vertrag. | [Apache-2.0](https://github.com/ConductorOne/baton-atlassian/blob/beb315e0e6bbf0aa2b5f381d06c75cfa1912fba9/LICENSE); letzter geprüfter Commit 06.11.2026, nicht archiviert. |
| JetBrains: [scsitteam/checkmk_jetbrains_licensevault](https://github.com/scsitteam/checkmk_jetbrains_licensevault/tree/662d29c5a725c6fd94fa857d7def30022f33d9a5) | Kleiner Python-Monitoring-Connector. `lib/agent.py` liest `public-api/licenses/usage` und paginierte `public-api/denials/report` für eine License-Vault-Ausprägung mit Automation-Key. Keine Lizenzvergabe oder Entziehung implementiert. Den tatsächlichen Cloud-/IDE-Services-API-Vertrag des eigenen Vaults zuerst prüfen. | [GPL-2.0-or-later im Dateikopf](https://github.com/scsitteam/checkmk_jetbrains_licensevault/blob/662d29c5a725c6fd94fa857d7def30022f33d9a5/lib/agent.py); letzter geprüfter Commit 12.05.2026. Keine direkte Codeübernahme beschlossen. |

### Zusätzliche Vergleiche

- [Baton Slack](https://github.com/ConductorOne/baton-slack/tree/7d4b31b4b5c0dce13fda2fb0b6aa764dc30fbd39)
  und [Baton Slack Enterprise](https://github.com/ConductorOne/baton-slack-enterprise/tree/9a94b6cf4f4950a24c45e1a7217c94f1379e25dc)
  zeigen Go-Connectoren mit Ressourcen-/Berechtigungsmodell. Der allgemeine
  Connector verweist für Rollen-Provisionierung/Kontenverwaltung ausdrücklich
  auf die Enterprise-Variante. Beide sind Apache-2.0; daraus folgt kein
  universeller Slack-Vertrags-/Lizenzbestand.
- [Nango LICENSE](https://github.com/NangoHQ/nango/blob/ca937eecd79fa19b509c38df6a88a49f20e22fc6/LICENSE)
  bleibt im geprüften Stand Elastic License 2.0. Verbindungslifecycle und
  OAuth-Konfiguration sind Architekturvergleiche; kein Nango-Code wurde übernommen.
  Der dortige UMAPI-Verbindungseintrag ist kein Nachweis eines fertigen
  Lizenzallocators. Die konkrete Datei-/Paketlizenz vor jeder Übernahme prüfen.
- Ein Sprachwechsel beseitigt Lizenzpflichten einer Quellcodeübernahme nicht;
  die [GNU-FAQ zur Übersetzung in andere Programmiersprachen](https://www.gnu.org/licenses/gpl-faq.html#TranslateCode)
  beschreibt dies ausdrücklich für GPL-Code. Eine unabhängige Implementierung
  anhand des veröffentlichten Hersteller-API-Vertrags bleibt die geplante
  Vorgehensweise für JetBrains und gegebenenfalls weitere Quellen.

### Reihenfolge für OpenDirectory

1. Vorhandenen Microsoft-Rust-Leseconnector um bestätigte Benutzer-/Zuweisungs-
   Beobachtungen ergänzen. Die bereits getrennte externe Schreibfreigabe bleibt
   beim vorhandenen Fulfillment-Ablauf; keine automatische Kontoanlage oder
   Übernahme fremder Gruppenlizenzen.
2. Google-Workspace-Lizenzzuweisungen und GitHub-Copilot-Seats als nächste eng
   begrenzte Anbieter prüfen. Die vorhandenen Rust-Clients sind Kandidaten für
   gezielte Wiederverwendung, keine pauschale neue SDK-Abhängigkeit.
3. Adobe OAuth-S2S und Produktprofile gezielt in Rust implementieren. Danach
   Atlassian-/Slack-Produktzugriff und JetBrains-Nutzungsberichte separat angehen.

Jeder Anbieter braucht getrennte Fähigkeiten für Bestand, Zuweisungen lesen,
Zuweisen und Entziehen sowie einen eigenen echten Verbindungstest. Ein
erfolgreiches OAuth-Token ist keine bestätigte Lizenzberechtigung. Tests müssen
Paginierung, 401/403, 429/Retry-After, Teilantworten und unklare Schreibausgänge
abdecken. Zugangsdaten bleiben geschützt; Benutzer-/Mandantenbindungen werden
explizit geprüft. Die alten globalen Providerbindungen dürfen Firmenpools nicht
ohne deren bestehende Mandanten-/Governance-Prüfung übernehmen.

Diese Recherche implementiert und deployt keine weiteren Anbieter. Kein echter
Anbieterzugang, keine Live-Verteilung und kein Lasttest wurden ausgeführt.

## Erster Ausbau umgesetzt, 8. November 2026

Der Microsoft-Connector liest jetzt zusätzlich genau einen ausdrücklich
verknüpften Benutzer samt Lizenzzuweisungen und direkten/Gruppenquellen.
`RustGraphLicenseClient` ist über `LICENSE_FULFILLMENT_READ_ENGINE` im vorhandenen
Worker auswählbar; derselbe Beobachtungsparser und dieselben Vergabe-, Mandanten-,
Eigentums- und Budgetprüfungen gelten weiter. Rust führt keine Schreiboperation
aus. Ein separater `license-fulfillment-probe.js` prüft eine echte bestehende
Zielbindung ausschließlich lesend, ohne Worker-Schleife oder Datenbankänderung.
Protokoll, benötigte Berechtigung und Live-Test-Anleitung stehen in
[der Connector-Dokumentation](../../services/connectors-rust/README.md).

Implementierung anhand der offiziellen Microsoft-Verträge, ohne kopierten
SDK-Code und ohne neue Abhängigkeit. Google Workspace und GitHub Copilot bleiben
die nächsten Anbieter; sie sind durch diese Änderung noch nicht angebunden.

## Google und GitHub lesend umgesetzt, 8. November 2026

Beide Anbieter haben jetzt eigene Rust-Leseverträge und einen ausführbaren
`license-provider-probe.js` für eine ausdrücklich konfigurierte Verbindung.
Google nutzt Servicekonto-JWT, Domain-wide Delegation und die explizite
Kunden-/Produkt-/SKU-Bindung. GitHub nutzt ein hinterlegtes Organisationstoken,
feste Seiten-URLs und die API-Version 2026-03-10. Der gemeinsame HTTP-Teil hält
TLS-, Redirect-, Antwortgrössen- und Fehlergrenzen auch für Microsoft ein.

Die Prüfungen liefern nur lesende Beobachtungen. Es gibt noch keinen automatischen
Katalogimport, keine lokalen Identitätsbindungen und keine Vergabe durch diese
beiden Anbieter. Insbesondere wird aus gezählten Zuweisungen kein gekaufter oder
freier Bestand abgeleitet. Google benötigt den breiteren apps.licensing-Scope;
der Connector führt trotzdem ausschliesslich GET auf der Lizenz-API aus.
Konfiguration, Grenzen und echte Testschritte stehen in
[READ_PROVIDERS.md](../../services/connectors-rust/READ_PROVIDERS.md).
Adobe bleibt als nächster Anbieter offen; echte Zugänge wurden nicht getestet.

## Adobe und Slack lesend umgesetzt, 8. November 2026

Adobe bestätigt vor der Mitgliederabfrage das konfigurierte Produktprofil anhand
von Organisations-ID, Profil-ID, Name und Typ. OAuth Server-to-Server verwendet
den aktuellen IMS-v3-Vertrag; alte JWT-Beispiele wurden nicht übernommen. Slack
bestätigt vor der SCIM-2.0-Abfrage per auth.test die tatsächliche Workspace- oder
Enterprise-Bindung. Ein Enterprise-Verzeichnis kann nicht als einzelner Workspace
ausgegeben werden. Neue Parser, Tokenanforderungen und Fehlerausgänge werden mit
HTTP- und Prozess-Fixtures geprüft; fremder SDK-Code wurde nicht kopiert.

Beide Reader verwenden den bestehenden geschützten Probe-Befehl. Es gibt keinen
Datenbankimport, keine lokale Identitätsübernahme und keine Anbieter-Schreibaktion.
Insbesondere werden weder Adobe-Profilmitgliedschaften noch aktive Slack-Konten
als gekaufter oder freier Lizenzbestand übernommen. Administrative API-Scopes
bleiben breiter als die hier implementierten Leseoperationen. Einrichtung und
Live-Test-Anleitung: [READ_PROVIDERS.md](../../services/connectors-rust/READ_PROVIDERS.md).
Echte Zugänge und Consent wurden nicht getestet. Atlassian und JetBrains bleiben
offen und brauchen weiterhin ihre eigenen API- und Berechtigungsverträge.

## Atlassian und GitLab.com lesend umgesetzt, 8. November 2026

Die aktuelle Atlassian-OpenAPI-Spezifikation wurde geprüft. Der bisherige GET-
Verzeichnis-Endpunkt ist zum 30. Juni 2027 abgekündigt; der neue Reader verwendet
POST users/search und wiederholt den expliziten directoryIds-Filter auf jeder
Seite. Account- und Mitgliedschaftsstatus werden nicht zu einer Lizenzbehauptung
zusammengezogen. Cursor bleiben Daten und können keinen anderen Host auswählen.

GitLab.com ergänzt bestätigte oberste Gruppen mit ID/Pfad-Prüfung und dem echten
billable_members-Endpunkt. Mitgelieferte Folgelinks werden vor dem Abruf auf
Host, Gruppenpfad, Seitennummer und erlaubte Parameter geprüft; Headerzähler und
Duplikate verhindern einen erfolgreichen abgeschnittenen Bericht. Beide Reader
laufen über den bestehenden geschützten Prüfbefehl, ohne Datenbankimport,
Identitätsübernahme, gekauften Bestand oder automatische Vergabe.

Die JetBrains-Dokumentation verweist für License Vault und IDE Services auf die
instanzspezifischen öffentlichen Swagger-Verträge und unterschiedliche Token-
Konventionen. Die Produktvariante/URL bleibt offen; kein JetBrains-Connector wurde
auf Basis geratener Endpunkte implementiert. Konfiguration und Grenzen stehen in
[READ_PROVIDERS.md](../../services/connectors-rust/READ_PROVIDERS.md). Echte
Anbieterzugänge wurden für diesen Ausbau nicht getestet.
