# Normale Gruppen und Lizenzgruppen

Stand: 22. Oktober 2026. Eine Lizenzgruppe ist eine normale kanonische Verzeichnisgruppe mit einer ausdrücklichen Verknüpfung zu einem eigenen Lizenzpool. Eine Gruppe kann mehrere Pools verwenden. Gruppen ohne Pool bleiben normale Gruppen.

## Oberfläche

Unter **Verzeichnisgruppen** eine Gruppe erstellen oder auswählen. Als tatsächlicher Company-Owner im Abschnitt **Lizenzgruppe** einen eigenen Pool auswählen, eine Begründung eingeben und **Pool verknüpfen und Mitglieder zuweisen** ausführen. Es werden die tatsächlichen freien Plätze angezeigt; weitere Pools sind paginiert erreichbar.

Die Verknüpfung startet den Abgleich. Bestätigte Mitgliedsänderungen in dieser Ansicht lösen ihn ebenfalls aus. **Mitglieder abgleichen** prüft einen bestehenden Link erneut, beispielsweise nachdem ein unabhängiges Membership-Review freigegeben wurde oder zusätzliche Plätze verfügbar sind. Beim Löschen einer Gruppe über diese Ansicht wird danach versucht, ihre lokalen Gruppenquellen zurückzunehmen. Ein gescheiterter Abgleich ändert die bereits bestätigte Mitgliedschaft oder Gruppenlöschung nicht zurück.

**Pool-Verknüpfung entfernen** verlangt eine zusätzliche Bestätigung, beendet die Verknüpfung und gleicht ihre bisherigen Benutzer ab. Die Historie bleibt erhalten. Ein bei der anschliessenden Vergabe gescheiterter neuer Link bleibt sichtbar und kann gezielt abgeglichen werden.

## Vergabeverhalten

- Nur effektive, aktive eigene Mitglieder mit aktueller Eligibility erhalten Lizenzen. Ausstehende, abgelaufene oder verweigerte unabhängige Gruppenfreigaben werden nicht umgangen.
- Pro Benutzer und Pool wird genau ein Platz belegt, auch bei einer direkten Vergabe oder mehreren Lizenzgruppen. Jede Herkunft bleibt nachvollziehbar.
- Beim Austritt oder Entfernen eines Links wird nur dessen Herkunft zurückgenommen. Andere Gruppen, manuelle Zuweisungen und andere Blueprints behalten ihre Quellen; der Platz wird erst nach der letzten Quelle frei.
- Ist der Pool voll, bleiben die betreffenden Benutzer `blocked`. Es gibt keine Überbuchung. Nach einer Freigabe oder Aufstockung erneut abgleichen. Da Benutzer in UUID-Reihenfolge verarbeitet werden, kann ein weiterer Durchlauf erforderlich sein, wenn ein später verarbeiteter Austritt erst im selben Lauf einen Platz freigibt.
- Ein neuer Eligibility-Stand ersetzt die alte Gruppenbindung beim nächsten bestätigten Abgleich. Ein alter Grant wird nicht stillschweigend auf eine reaktivierte Person übertragen.

Der Bestand und die Vergabe sind lokal. Eine erfolgreiche Zuweisung bestätigt keinen Herstellerlizenzkauf, keine Microsoft-365-Freischaltung, kein Postfach und keine App-Installation.

## Skripte

Node.js 20+ und die vorhandene [CLI-Konfiguration](app-accounts-automation.md) verwenden. `OPENDIRECTORY_ADMIN_ACCESS_TOKEN` ist der ursprüngliche menschliche Zugriffstoken mit aktuellen eigenen Rechten und MFA. Ein `client_credentials`-App-Konto erhält damit keine Firmenlizenzrechte. Token nicht als Befehlsargument oder im Repository ablegen.

```bash
node scripts/od.mjs group create 'Engineering'
# Die tatsächliche Gruppen-ID aus der Antwort verwenden.
node scripts/od.mjs license-group link GROUP_ID POOL_ID 'Engineering erhält die Entwicklungssoftware'
node scripts/od.mjs group member add GROUP_ID USER_ID
node scripts/od.mjs group member remove GROUP_ID USER_ID
node scripts/od.mjs license-group list GROUP_ID
# RULE_ID bezeichnet die Pool-Verknüpfung aus list/link, nicht die Gruppen-ID.
node scripts/od.mjs license-group sync RULE_ID 'Freigegebene Mitglieder erneut abgleichen'
node scripts/od.mjs license-group unlink RULE_ID 'Softwarepaket für diese Gruppe beenden'
```

`link`, `unlink` und die Mitgliedsbefehle gleichen die betroffenen Verknüpfungen selbst ab. `list` liest nur. Bei normalen Gruppenadministratoren ohne Company-Ownership ändern die Mitgliedsbefehle ausschliesslich die Mitgliedschaft; der aktuelle Company-Owner führt den Lizenzabgleich separat aus.

Exit-Code **0** bestätigt den ausgegebenen Ablauf, **2** meldet bestätigte Teilresultate mit blockierten Benutzern, **1** einen abgelehnten oder unbestätigten Ablauf. Bei Code 1 können frühere Schritte bereits gespeichert sein. Erst `list`, `sync` und den tatsächlichen Gruppen-/Poolstand prüfen, bevor eine Mitgliedschaft oder Verknüpfung erneut angelegt wird. Schreibfehler werden nicht automatisch wiederholt. Ein `sync` ist eine neue Prüfung des aktuellen Zustands, kein erneutes Ausstellen bereits vorhandener Quellen.

Eigene Skripte verwenden denselben Client:

```js
import { createClient } from './scripts/lib/opendirectory-client.mjs';
import { createGroupClient } from './scripts/lib/license-groups.mjs';
const groups = createGroupClient(createClient({
  issuer: process.env.OPENDIRECTORY_ISSUER,
  apiUrl: process.env.OPENDIRECTORY_API_URL || process.env.OPENDIRECTORY_ISSUER,
  adminToken: process.env.OPENDIRECTORY_ADMIN_ACCESS_TOKEN,
}));
const ordinary = await groups.create('Engineering');
const result = await groups.linkPool(ordinary.id, process.env.POOL_ID,
  'Engineering erhält die Entwicklungssoftware');
console.log({ ruleId: result.rule.id, blocked: result.hasBlocked });
```

Externe Gruppen- oder Reviewänderungen starten keinen unbeaufsichtigten Firmenlizenz-Worker. Die Integration muss `sync` mit einer weiterhin gültigen ursprünglichen menschlichen Sitzung auslösen. Eine dauerhafte appgebundene Schreibdelegation ist nicht implementiert; vorhandene Legacy-Gruppenworker bleiben für Firmenpools gesperrt.

## API und Datenmodell

Alle Antworten verwenden `schemaVersion:1`, `companyLicenseGroupsProtocol:1`, tatsächlichen Actor/Tenant und `allocationMode:local-only`. Keine frei gewählte Tenant-ID und keine API-Key-Autorisierung. Der ursprüngliche Bearer wird an Identity weitergegeben und vor/nach tatsächlichen Mutationen erneut geprüft. MFA darf höchstens 300 Sekunden alt sein.

| Methode | Pfad | Inhalt |
| --- | --- | --- |
| GET | `/api/licenses/company/groups?groupId=UUID` | Eigene Verknüpfungen, bis 100; `truncated` ausdrücklich beachten |
| POST | `/api/licenses/company/groups` | `{groupId,poolId,reason,confirm:true}`; UUID-`Idempotency-Key` erforderlich |
| GET | `/api/licenses/company/groups/:id/preview` | Aktuelle Gruppenrevision, Link und Anzahl gewünschter/bestehender Änderungen |
| POST | `/api/licenses/company/groups/:id/sync` | `{groupRevision,cursor,reason,confirm:true}`; erster Cursor `null` |
| POST | `/api/licenses/company/groups/:id/unlink` | `{reason,confirm:true}`; UUID-`Idempotency-Key` und aktueller starker `If-Match` erforderlich |
| GET | `/api/identity/company-license-groups/:id/snapshot` | Private eigene, aktuelle Gruppenquelle; ursprünglicher menschlicher Bearer und Snapshot-Protokoll 1 |

`sync` verarbeitet höchstens 25 aufsteigend sortierte Benutzer-UUIDs pro Aufruf. Alle Seiten müssen dieselbe erfasste Gruppenrevision verwenden; `nextCursor:null` beendet den Durchlauf. Änderungen am Gruppeninhalt, Link, Benutzerstand, Pool oder an der ursprünglichen Authority können den Lauf stoppen. CLI und Oberfläche prüfen die Antworten und verarbeiten die Seiten nacheinander. Ein Durchlauf umfasst höchstens 20'000 unterschiedliche bisherige/aktuelle Benutzer; jede Ausgangsgruppe und jeder aktive Bindungsbestand ist auf 10'000 begrenzt.

**Keine Atomarität über die ganze Gruppe:** Jeder Benutzer läuft durch eine vollständige bestehende Allocator-Transaktion. Ein späterer Fehler rollt frühere Benutzer nicht zurück. `hasBlocked` und Einzelresultate beachten; auch nach einem HTTP-Fehler tatsächliche Zuordnungen lesen. Die Verknüpfung, ihre Lizenz-Blueprint-Erstellung und der erste Benutzerabgleich sind ebenfalls getrennte Schritte. Scheitert ein Link nach der Blueprint-Erstellung, kann ein unverknüpfter lizenzreiner Blueprint zurückbleiben; er vergibt ohne Benutzerbindung keine Plätze. Bei eigener API-Recovery den ursprünglichen Idempotency-Key und Inhalt beibehalten.

Policy-Migration **028** ergänzt `company_license_groups`, unveränderliche Events/Pending-Outbox und tatsächliche Gruppeneffekte. Jeder Link pinnt Version 1 eines eigenen lizenzreinen Blueprints; die vorhandenen Quellen-, Grant-, Kapazitäts- und Commit-Prüfungen aus 026/027 übernehmen die Vergabe. Der Zusammenhang ist über `blueprintId` und die tatsächlichen Benutzerbindungen nachvollziehbar. Es entsteht kein zweiter Lizenzbestand und kein neuer globaler Rollenvertrag. Gruppenquelle und Policy-Commit bleiben getrennte Dienste; die erneuten Prüfungen sind kein verteilter atomarer Commit. Ein Gruppen-/Reviewwechsel nach dem letzten Check erfordert den nächsten Abgleich.

## Installation und Prüfung

Identity mit aktuellem Code und Migrationen 001–047, Policy mit **001–028**, Gateway und Frontend koordiniert aktualisieren. Die neue Identity-Route benötigt keine zusätzliche Identity-Migration. Policy-Dockerfile kopiert den gemeinsamen `packages/company-license-group-contract.js` im bestehenden Repository-Root-Buildkontext. Keine neuen Dependencies oder Secrets.

```bash
npm run test:automation-client
npm test --prefix frontend/web-app -- --runInBand companyLicenseGroups CompanyLicenseGroupsPanel UserGroupsView
npm run type-check --prefix frontend/web-app
npm test --prefix services/core/identity-service -- --runInBand CompanyLicenseGroupRouting SnapshotBoundary
npm test --prefix services/core/policy-service -- --runInBand companyGroupRoutes GroupSnapshotClient
TMPDIR=/tmp npm run test:licenses:integration --prefix services/core/policy-service
```

Native PostgreSQL-Regressionen prüfen die tatsächlichen Migrationen, mehrere Mitglieder, Herkunftsüberlappung, knappen Bestand, parallele Vergabe, Paginierung, Eligibility-Wechsel, Unlink/Recovery, fehlende Commit-Guards und Ablauf vor physischem Commit. Die Identity-Registrierungsregression prüft den tatsächlichen rollenlosen Company-Owner, fremde Gruppen, retained Löschung und MFA-Ablauf. Kein produktiver Rollout oder Herstellerzugriff wurde ausgeführt.
