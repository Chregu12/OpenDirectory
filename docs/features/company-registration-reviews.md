# Interne Firmenprüfung

Stand: 19. Oktober 2026. Dieser Slice ergänzt die [öffentliche Vormerkung](company-registration.md) um eine tatsächliche, endgültige interne Freigabe oder Ablehnung. **Freigabe ist keine Aktivierung und keine externe rechtliche Firmenverifizierung.** Mandant und vorgemerkter Erstadministrator bleiben gesperrt; keine Rolle, Console-App oder Lizenz wird vergeben. Der vollständige WF-001 bleibt `In Progress`.

## Least Privilege

`company.registrations.review` kommt ausschliesslich aus dem tatsächlichen, aktuellen SQL-Prüferregister. Weder globales `admin` noch gleichnamige Token-Scopes/-Permissions verleihen dieses Recht. Es öffnet nur die Antragsliste, Antragsdetails und eine einmalige Prüfentscheidung. Benutzer-, Rollen-, Geräte-, Profil- oder Tenant-Verwaltung sind nicht enthalten.

Nur ein tatsächlicher Datenbank-Owner kann eine kanonische, zu einem aktiven eigenen Management-Tenant gehörende Person ausdrücklich bestellen. Es gibt keinen Tenant-Admin-Endpunkt zur Selbstbestellung. Der separate Offline-Befehl benötigt eine explizite Verbindung ohne Credential-Fallback:

```sh
IDENTITY_OPERATOR_DATABASE_URL='postgres://OWNER@HOST/identity' \
  node services/core/identity-service/scripts/company-review-operator.js \
  'https://configured-issuer.example' USER_UUID 0 enable \
  'Unabhängige Bestellung für die interne Firmenprüfung'
```

`0` ist die erwartete Ausgangsversion für eine Erstbestellung. Der ausgegebene tatsächliche Datensatz enthält die neue Version. Ein Widerruf verwendet diese aktuelle Version und `disable`; ein veralteter Versionswert wird abgewiesen. Keine echten Zugangsdaten in Shell-Historie schreiben; für den Betrieb eine geschützte Secret-Zuführung verwenden. Der Befehl wurde nur gegen isolierte Testdatenbanken ausgeführt, nicht gegen eine bestehende produktive Datenbank.

Bestellung und Widerruf invalidieren atomar die kanonische Benutzer-Autorisierungsrevision. Alte Sessions/Tokens sind danach veraltet. Beide Änderungen erhalten einen unveränderlichen Vorher-/Nachher-Beleg und eine Pending-Outbox. Aktive Bestellung ist an Issuer, kanonische Person und Management-Tenant gebunden. Ein deaktivierter Prüfer kann durch den Owner widerrufen werden; eine Neubestellung setzt einen aktiven Benutzer/Tenant und dessen echten Subject-Link voraus.

## Bedienung und API

1. Nach Bestellung mit dem vorhandenen Konto und tatsächlich eingerichtetem MFA neu anmelden.
2. **Firmenprüfung** unter `/registration-reviews` öffnen. Der Menüpunkt erscheint nur bei serverbestätigtem Prüfrecht.
3. Tatsächliche Anträge nach Status filtern, gegebenenfalls seitenweise laden und einen Antrag öffnen.
4. Firmendaten und Antragsteller prüfen. Die gespeicherten Originaldaten sind hier schreibgeschützt.
5. Freigeben oder Ablehnen ausdrücklich auswählen, Begründung mit 10–500 Zeichen eingeben und die endgültige Entscheidung bestätigen.
6. Die Oberfläche sendet nur mit aktueller ETag und bestätigt die Entscheidung erst nach tatsächlichem Readback. Bei verlorener Antwort Status neu laden; keine automatische Wiederholung.

| Methode / Pfad | Wirkung |
| --- | --- |
| `GET /api/identity/company-registrations` | Eigene explizite Plattform-Prüferfähigkeit erlaubt die mandantenübergreifende echte Queue; `page` 1–10'000, `limit` 1–50, Statusfilter |
| `GET /api/identity/company-registrations/{id}` | Originalantrag, tatsächliche Entscheidung und ETag |
| `POST /api/identity/company-registrations/{id}/review` | `If-Match`, exakte Felder `decision`, `reason`, `confirm:true`; genau eine endgültige Entscheidung |

Statusfilter: `pending-verification`, `pending-activation`, `rejected`, `all`. Freie Tenant-Selektoren werden abgewiesen. Jede Queue-/Detailabfrage und jede Entscheidung braucht eine verifizierte MFA-Anmeldung, die höchstens 300 Sekunden alt ist. Ein Antragsteller darf nicht seinen eigenen Antrag prüfen. Alle Antworten sind `no-store`.

Die öffentliche credentialgebundene Statusabfrage bleibt vom Prüfer-Endpunkt getrennt: Ungeprüfte Anträge liefern unverändert Schema 1. Tatsächlich entschiedene Anträge liefern Schema 2 mit `reviewedAt` und entweder `pending-activation` oder `rejected`. Die vier Aktivierungs-/Profil-Flags bleiben `false`. Private Prüfbegründung und Prüfer-ID werden dem Antragsteller nicht übermittelt. Der Capability-Status `pending-verification` beschreibt weiterhin den Zustand eines neuen Antrags, nicht einen behaupteten Gesamtworkflow.

## Daten und Commit-Grenzen

Migration `040_company_registration_reviews.sql` ergänzt:

- `identity_company_review_operators`: aktuelles versioniertes Prüferregister; Source-of-Authority nur für diese eine Fähigkeit.
- `identity_company_registration_reviews`: genau eine unveränderliche Entscheidung pro Originalantrag mit Referenz auf den damaligen Bestellungsbeleg.
- `identity_company_review_events`: unveränderliche Operator-/Entscheidungsbelege, Grund, Actor, Original-Token-Hash, Zeitpunkt und Transaktion. Entscheidungs-Tenant ist der Ziel-Tenant; der Original-Checkpoint gehört zum eigenen Management-Tenant des Prüfers.
- `identity_company_review_outbox`: verpflichtender passender Pending-Beleg; keine behauptete Zustellung.

Entscheidungen verwenden die vorhandene Original-Authority-Command-Grenze: ursprünglicher Bearer vor/nach DML beim Issuer, tatsächlicher aktueller kanonischer Context, Prüfer-/Antragslocks, unveränderlicher Entscheidungsbeleg und finaler Original-Checkpoint. MFA-/Token-Fristen gelten bis zum physischen Commit. Zwei konkurrierende Prüfer können nicht beide gewinnen; nach dem ersten Commit erhält der zweite einen Versionskonflikt. Prüferentzug serialisiert über denselben kanonischen User-Lock. Ein späterer legitimer Widerruf verändert keine historische Prüfentscheidung.

Die ursprünglichen Pending-Tenant-/User-/Subject-/Audit-Snapshots aus Migration 039 bleiben unverändert gültig. Nach Prüfung werden diese Ressourcen nicht still aktiviert. Fehlende Original-/Review-/Outbox-Belege, deaktivierte Receiving-Trigger oder unerlaubte zusätzliche kanonische Effekte führen zum Abbruch statt zu einer plausiblen Erfolgsmeldung. SQL-Funktionen bleiben private Owner-Receivers, kein bereits fertiggestelltes Least-Privilege-Datenbankrollenmodell. Retention/Datenschutz-Löschung und off-host manipulationssichere Archivierung sind damit nicht implementiert.

## Offen

Die anschliessende [eigene Aktivierung mit Pflicht-MFA und erster Owner-Profilanmeldung](company-activation.md) ist inzwischen ein separater Teilprozess. Die Review-Fähigkeit selbst bekommt keine Aktivierungsbefugnis. Vollständige eigene Company-Administration, Account-Self-Signup, Domain-/externe Firmenverifizierung, Mehrstufenprüfung, Rückfrage/erneute Einreichung, allgemeine Workflow Engine, Outbox-Zustellung/Retry/DLQ und Produktions-/Last-/Backup-Abnahme bleiben offen. Keine unautorisierte externe Schreiboperation wurde eingeführt.

## Abnahme

Die [sieben abgegrenzten Test-Gates](../testing/test-results.md#business-slice-5-interne-firmenprüfung) bestehen mit insgesamt 2'842 Fällen. Die echte Chrome-Demo prüft Registrierung, optionales tatsächliches MFA-Setup des normalen Prüfers, interne Freigabe und anschliessende credentialgebundene Statusabfrage im anonymen Antragstellerbrowser. Der signierte Produktionsmodus-Test weist zusätzlich nach, dass auch eine freigegebene Firma noch keinen Erstadministrator-Login erhält. Dies ist die Abnahme dieses Teilprozesses, nicht der ganzen Plattform.
