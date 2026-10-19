# Mandantengebundene Lizenz- und Policy-Quellen

Stand: 19. Oktober 2026. Sicherheitsvoraussetzung für BR-002/005/012, **noch keine eigene Firmen-App-/Lizenzverteilung**. Bestehende lokale Pools, Allokation, Scope-/PIM-Prüfung, unabhängige Reviews, Kapazitätsgrenzen und Providerzustände bleiben unverändert. Der Company-Owner erhält dadurch keine globalen Lizenzrechte.

## Menschliche Quellen

Die sieben bestehenden `/api/{source}/{id}/snapshot`-Routen für `license-users`, `license-groups`, `license-reviewers`, `license-scope-reviewers`, `license-activation-reviewers`, `license-delegates` und `policy-publication-actors` verwenden eine gemeinsame tatsächliche Tenant-Grenze. Sie prüfen den originalen signierten Bearer, aktuelle kanonische Person, Home-Tenant samt Version/Generation, aktuelle Rolle und Authentifizierungsanforderung. Caller-Tenant, pauschale Permission-/Admin-Claims und bekannte fremde UUIDs ersetzen diese Prüfung nicht.

- Erst die aktuelle kanonische Quellberechtigung, dann der eigene retained Ziel-Namespace, dann die minimale Projektion. Auch `admin` besitzt keinen mandantenübergreifenden Quell-Bypass. Fremde/unowned/fehlende Ziele liefern `404`; fehlende aktuelle Pflicht `403`; ungültige ursprüngliche Authority `401`; fehlende nachweisbare Quelle `503`.
- Normale Personen dürfen weiterhin nur die eigene minimale Benutzer-Eligibility sowie die bisherigen eigenen Delegate-/Activation-Reviewer-Belege lesen. Daraus entstehen weder Profilzugriff noch Rechte anderer Personen.
- Die bisherigen DTO-Felder bleiben unverändert; keine Profile oder fremden Rollenlisten werden hinzugefügt. Benutzer-Eligibility bleibt Schema 1; Gruppen bleiben Schema 3 mit unveränderten Membership-/Lease-Belegen.
- Die reine Quellenabfrage ist physisch read-only. Nur der kontrollierte Refresh eigener Gruppenreviews benötigt eine schreibende Transaktion. Fremde Gruppen werden davor abgewiesen. Bekannte fremde retained Mitglieder, auch historische IDs, erzeugen `503` statt als inactive/unresolved in eine andere Quelle zu geraten.
- Originalzustand und Frist werden nach der SQL-Arbeit und vor Freigabe erneut bestätigt. Ein Widerruf während eines tatsächlichen Lock-Waits darf kein berechnetes Ergebnis freigeben. Der letzte Check ist kein unbegrenztes Zukunftsversprechen und kein verteilter Commit.

Alle Routen verlangen kanonische kleingeschriebene UUIDs, leere Query/Body und keinen API Key. `/api/identity/subject` bleibt die separate eigene Issuer-/Subject-Bindung; sie ist kein freier Fremdbenutzer-Lookup.

## Dedizierte maschinelle Benutzerquelle

Ein Client-Credentials-Token mit exakt `licenses.users.read` reicht **nicht mehr allein** zum Lesen beliebiger Benutzer. Zusätzlich ist eine bewusste offline geprüfte Bindung des konkreten `(issuer, client_id)` an genau einen bestehenden kanonischen Tenant und die aktuelle Issuer-Clientrevision nötig. Kein Default-Tenant, keine Wahl aus der Ziel-UUID und kein globaler Maschinen-Bypass.

`044_license_user_sources.sql` speichert die Bindung, unveränderliche Before-/After-Events und zwingende Pending-Outbox. Tenant, Issuer, Client und Source-ID bleiben nach Erstellung unveränderlich. Die Version und Clientrevision sind exakte BIGINT-Strings. Aktualisierungen erfordern die erwartete aktuelle Source-Version; eine Clientrevision darf nicht zurücklaufen. Rotation oder Reaktivierung eines OAuth-Clients aktualisiert die Source **nicht automatisch**.

Ein vorhandener Bound-Client kann eigene deaktivierte/gelöschte Benutzer und negative Eligibility eines pausierten Ziel-Tenants lesen, damit bestehende lokale Rechte sicher abgebaut werden können. Das aktiviert weder Tenant noch Benutzer. Ein Wechsel von Ziel-Tenant-Version/Generation, Bindung, Clientrevision oder Enabled-Zustand während der Beobachtung verwirft das Ergebnis; Client-Widerruf und Tokenablauf bleiben wirksam. Ein deaktivierter Bound-Client darf auch diese Negativquelle nicht lesen.

### Bewusste Offline-Bestellung

Zuerst Migrationen **001–044** im Identity-Service anwenden. Der Operator muss den tatsächlichen DB-Tabellenbesitzer verwenden; `SET ROLE`, PUBLIC-Zugriff, beliebige Raw-DML und ein gemeinsam genutzter HTTP-Admin-Endpunkt sind kein Ersatz. Danach bewusst die **eigene gewählte Tenant-UUID** und aktuell geprüfte Clientrevision eintragen:

```sh
IDENTITY_OPERATOR_DATABASE_URL="$REVIEWED_IDENTITY_OWNER_DATABASE_URL" \
  node services/core/identity-service/scripts/license-user-source-operator.js \
  "$OIDC_ISSUER" "$REVIEWED_CLIENT_ID" "$REVIEWED_TENANT_UUID" \
  "$REVIEWED_CLIENT_REVISION" 0 enable "Reviewed dedicated own-tenant eligibility source"
```

`0` gilt nur für erstmalige Erstellung. Weitere bewusste Updates verwenden die tatsächliche letzte `version` aus dem bestätigten Readback und `enable` oder `disable`; kein automatischer Retry bei Konflikt. Bei Clientrotation muss die aktuelle Issuer-Revision separat geprüft und mit genau dieser erwarteten Source-Version übernommen werden. Für einen anderen Tenant ist ein separater OAuth-Client erforderlich, nicht das Umhängen alter Herkunft.

`IDENTITY_OPERATOR_DATABASE_URL` ist verpflichtend und hat keinen Fallback auf das Runtime-Login. Keine echte URL, Zugangsdaten oder Tokens ins Repository/Logs schreiben. Die CLI-Antwort bestätigt nur die tatsächliche lokale Bestellung, **keine** Erreichbarkeit oder Berechtigung des externen Issuers. Die Laufzeit prüft den originalen Client/Token weiterhin live.

## Bestehende gruppenbezogene Maschinenquelle

Der bisherige dedizierte Group-Source-Consent bleibt separat und eng auf die konkrete Gruppe begrenzt. Menschliche List-/Read-/Create-/Revoke-Operationen brauchen aktuelle tatsächliche Rechte, originalen Bearer und dieselbe Home-Tenant-Hoheit wie die Gruppe; Verwaltung einer fremden Gruppe ist kein globales Administrationsrecht.

Auch bei Nutzung einer retained Maschinenfreigabe muss der ursprüngliche menschliche Ersteller zum retained Gruppen-Tenant gehören. Aktuelles Ziel-Tenant-ID/Version/Generation/Enabled werden vor und nach dem Refresh verglichen, ohne die DTO- oder Consent-Struktur umzuschreiben. Eine bereits pausierte eigene Gruppe kann ihre tatsächlichen negativen Belege liefern; ein Zustandswechsel während der Beobachtung führt zum Fehler. Die vorhandenen expliziten Clientrevisionen, Ablaufgrenzen und Grant-Locks gelten weiterhin.

## Koordinierter Receiver-Rollout

Erfolgreiche Snapshot-HTTP-Antworten liefern `X-OD-License-Snapshot-Protocol: 1` und `Cache-Control: no-store`. Identity-Metadaten melden `licenseSnapshotProtocol: 1`. Die tatsächlichen Policy-HTTP-Receiver akzeptieren `200` für `/snapshot` **nur** mit dem exakten Header `1`; fehlende/falsche Protokolle sind `503`, keine Kompatibilitätsfreigabe eines alten globalen Readers. Der eigene Subject-Endpoint ist kein Snapshot und benötigt diesen Header nicht.

Alle relevanten Identity-/Policy-Instanzen und direkte Consumer gemeinsam aktualisieren. Alte ungescopte Reader dürfen nicht parallel freigegeben bleiben. Vor Umschalten die dedizierten Benutzerquellen bewusst bestellen; sonst bleiben entsprechende Worker sicher gesperrt. Die Rollout-Sperre bedeutet Nichtverfügbarkeit statt stiller Tenant-Ausweitung. Es wurde kein produktiver Rollout ausgeführt.

## Datenhoheit, Aufbewahrung und offene Grenzen

Die drei neuen Tabellen gehören ausschliesslich zur Identity-Datenbank; Tenant-FKs sind echt, Clientreferenzen zum getrennten Issuer sind keine vorgetäuschten Cross-DB-FKs. Row-/Truncate-/Receiving-/Deferred-Commit-Guards binden exakte lokale Wirkung, ursprüngliche Betreiberentscheidung, Event und Pending-Outbox. Gemischte kanonische Writes im Offline-Source-Command, fehlende Receiver, gelöschte lokale Scope-GUCs und nachträgliches Rewrite dürfen keinen bestätigten Commit erzeugen. Leere, niemals konfigurierte Testschemata können bereinigt werden; konfigurierte Herkunft bleibt erhalten.

Die Pending-Outbox ist kein zugestelltes Ereignis oder externer Erfolg. Ein privilegierter DB-Owner bleibt eine Betriebsvertrauensgrenze; Least-Privilege-Runtime-/Operator-Loginmodell, unabhängige Off-Host-Retention, Datenschutzlöschung und Produktionsabnahme sind nicht gelöst.

Offen bleiben insbesondere tatsächliche Business-Tenant-Hoheit der bisherigen globalen App-/Lizenzpools, Company-App-/Pool-UI, sichere Verbindung zum **vorhandenen** Allocator vor allen Eligibility-/Reconciliation-Effekten, Geräte-/OU-/Blueprint-Zuweisung, JML, Kosten und reale Anbieterabnahme. Ein Microsoft-Graph-Tenant ist nicht automatisch ein OpenDirectory-Business-Tenant. Bestehende Scope-/PIM-/Vier-Augen-/Kapazitäts-/Original-Proof-Grenzen dürfen bei dieser späteren Verbindung nicht umgangen werden.

Siehe [API](../api/openapi.yaml), [Datenmodell](../architecture/erd.md#lizenz-benutzerquellen-migration-044), [Abnahme](../testing/test-results.md#business-slice-11-mandantengebundene-lizenzquellen) und [vollständige offene Anforderungen](../implementation-status.md).
