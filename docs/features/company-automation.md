# Eigene App-Freigaben und dauerhafte Jobs

Stand: 22. Oktober 2026. Die neue Jobbasis verbindet ein ausdrücklich freigegebenes App-Konto mit dem eigenen Mandanten. Sie speichert Jobs, Worker-Leases, begrenzte Wiederholungen, Zeitpläne und unveränderliche Historie in PostgreSQL. Der erste ausführbare Handler exportiert tatsächliche eigene Benutzer, Gruppen oder Organisationseinheiten. Weitere Aktionen – insbesondere automatischer Firmenlizenzabgleich und Provider-Schreiboperationen – gehören zum [Gesamtauftrag](../implementation-worklist.md) und sind noch offen.

## App anmelden und ausdrücklich freigeben

1. Ein dediziertes vertrauliches OAuth-App-Konto mit `client_credentials` und ausschliesslich dem Scope **`company.automation`** erstellen und aktivieren. Die bestehende App-Registerverwaltung benötigt weiterhin ihre eigenen `applications.*`-Rechte. Eine eigene tenantgebundene App-Registerverwaltung ist noch nicht umgesetzt.
2. Auf dem Runner `OPENDIRECTORY_ISSUER`, gegebenenfalls `OPENDIRECTORY_API_URL`, `OPENDIRECTORY_CLIENT_ID`, `OPENDIRECTORY_CLIENT_SECRET` und `OPENDIRECTORY_SCOPES=company.automation` über die geschützte Laufzeitkonfiguration setzen.
3. Die tatsächliche App meldet sich mit `automation enroll` an. Die Antwort nennt ihre Client-ID, aktuelle Clientgeneration und eine fünf Minuten gültige Anmeldungs-ID. Eine Anmeldung gewährt noch keinen Tenant-Zugriff.
4. Als tatsächlicher Firmeninhaber mit ursprünglicher Sitzung und frischer MFA unter **Automationen** diese ID prüfen. Client-ID und Generation mit dem eigenen App-Register vergleichen; der angegebene Name stammt von der App. Nur benötigte Aktionen und eine Laufzeit von höchstens 30 Tagen auswählen und ausdrücklich bestätigen.
5. Die genehmigte Grant-ID auf dem Runner verwenden. Ein App-Token übernimmt weder die menschliche Identität noch MFA- oder globale Administratorrechte. Es gelten ausschliesslich die genehmigten Aktionen dieses Mandanten.

```bash
# Mit dem bereits dafür autorisierten Verwaltungstoken:
node scripts/od.mjs app create 'Eigener Export-Worker' 'company.automation'
node scripts/od.mjs app enable CLIENT_ID

# Auf dem Runner mit den eigenen App-Zugangsdaten:
export OPENDIRECTORY_SCOPES='company.automation'
node scripts/od.mjs automation enroll 'Eigener Export-Worker'

# Als tatsächlicher Company-Owner, alternativ zur Oberfläche:
node scripts/od.mjs automation approve ENROLLMENT_ID CLIENT_ID CLIENT_REVISION \
  'directory.users.export directory.groups.export' 24
```

`approve` verwendet `OPENDIRECTORY_ADMIN_ACCESS_TOKEN` als ursprünglichen Eigentümertoken. Der App-Worker benötigt diesen Token nicht. Den menschlichen Verwaltungstoken nicht auf dem unbeaufsichtigten Runner aufbewahren. Client-Secret und Bearer nicht als Befehlsargumente, in Git oder in Job-Logs ablegen.

Die Freigabe bindet Issuer, Client-ID, tatsächliche Clientgeneration, eigenen Tenant samt Version/Generation, genehmigte Aktionen, ursprünglichen Eigentümer und Ablauf. Rotation oder Deaktivierung des OAuth-Clients, Widerruf/Ablauf des Grants, ein Tenant-Inkarnationswechsel oder der Verlust der ursprünglichen Eigentümerschaft verhindern weitere Ausführung. Nach Clientrotation sind neue Anmeldung und ausdrückliche Freigabe nötig. Die menschliche MFA muss beim Genehmigen und Verwalten frisch sein; während einer gültigen expliziten Delegation wird keine offene menschliche Sitzung benötigt.

## Jobs und Zeitpläne ausführen

Aktuell ausführbare Aktionen:

| Aktion | Tatsächliche Daten |
| --- | --- |
| `directory.users.export` | Eigene Benutzer-ID, Benutzername, E-Mail, Anzeigename, Abteilung, Funktion und Enabled; keine Passwörter, Token oder MFA-Secrets |
| `directory.groups.export` | Eigene Gruppen, Beschreibung, Revision und kanonische eigene Mitglieder-IDs |
| `directory.ous.export` | Eigene Einheiten, Beschreibung, Parent-ID und Revision |

Ein Export umfasst vollständig höchstens 10'000 Zeilen und vier MiB. Überschreitung ist ein sichtbarer Fehler, kein abgeschnittener erfolgreicher Bericht. CSV maskiert Formeleinstiege und zitiert Sonderzeichen. JSON/CSV sind personenbezogene Daten; die Freigabe benennt den Export ausdrücklich. Ergebnisse werden erst nach bestätigtem lokalem Commit angeboten und beim Download gegen ihren SHA-256 geprüft.

```bash
node scripts/od.mjs automation grants
node scripts/od.mjs automation queue GRANT_ID directory.users.export csv
node scripts/od.mjs automation schedule GRANT_ID directory.groups.export 3600 json

# Dauerhaft auf dem eigenen Runner; SIGINT/SIGTERM stoppt weitere Polls.
node scripts/od.mjs automation worker GRANT_ID
# Oder einmal prüfen, beispielsweise aus einem externen Scheduler:
node scripts/od.mjs automation worker GRANT_ID --once

node scripts/od.mjs automation jobs GRANT_ID
node scripts/od.mjs automation history JOB_ID
# Ergebnis enthält die tatsächlichen Exportdaten: Ausgabe geschützt übernehmen.
node scripts/od.mjs automation result JOB_ID
```

Die Oberfläche kann Jobs einreihen, Zeitpläne erstellen/stoppen, bestätigte Artefakte herunterladen, einzelne Jobs abbrechen und fehlgeschlagene Jobs ausdrücklich erneut einreihen. Freigaben, Jobs, Zeitpläne und Historie sind paginiert. Ein fehlender oder gestoppter Runner lässt Jobs dauerhaft eingereiht; ein Browser meldet deshalb nur die tatsächliche Einreihung. Ein aktivierter Zeitplan ist keine Behauptung, dass ein Runner bereits läuft.

Der Worker fragt fällige Jobs mit seinem aktuellen App-Token ab. Jeder Claim erhält einen eigenen zufälligen Lease-Token und höchstens 45 Sekunden Laufzeit, zusätzlich begrenzt durch Token und Grant. Verlorene/abgelaufene Claims können von einem frischen Worker derselben genehmigten Clientgeneration aufgenommen werden. Ein alter Claim kann keinen späteren Claim abschliessen. Parallele Worker verwenden PostgreSQL-Row-Locks und eine eigene Grant-Quota; doppelte Ausführung eines bereits beanspruchten Jobs wird verhindert.

Fehlerhafte lokale Leseexporte warten nach dem ersten bis vierten Versuch 30, 60, 120 und 240 Sekunden. Nach fünf Versuchen bleibt der Job sichtbar `failed` und benötigt eine ausdrückliche neue Versuchsfolge. Frühere Versuche und Actor-/Clientgenerationen bleiben in der Historie. Diese automatische Wiederholung gilt für die angebotenen lokalen Lesehandler; sie erteilt keine Wiederholungserlaubnis für unbekannte externe Schreibwirkungen. Netzwerk-/Serverfehler des Runners haben ebenfalls begrenztes exponentielles Backoff; ungültige oder widerrufene Berechtigungen stoppen den Runner.

Zeitpläne benötigen Intervalle von 60 Sekunden bis 30 Tagen. Nach längerer Unterbrechung wird kein unkontrollierter Nachholstapel erzeugt: ein fälliger Lauf wird mit stabiler Schedule-/Zeit-ID erzeugt und der nächste Termin fortgeschrieben. Pro Grant gelten höchstens 100 aktive Zeitpläne und 1'000 wartende/laufende Jobs.

`worker` schreibt JSON-Zeilen mit Job-Metadaten, keine Exportinhalte. `--once` endet bei einem bestätigten nicht erfolgreichen Jobergebnis mit Code 2. Andere CLI-Befehle geben ein JSON-Ergebnis aus. Code 1 bedeutet abgelehnt oder unbestätigt; gespeicherten Stand lesen, bevor ein Auftrag erneut erstellt wird. Ein verlorener HTTP-Erfolg kann bereits committed sein. API-Create-Aufträge besitzen ihre ursprüngliche UUID im Body; eine unveränderte Wiederholung derselben UUID liest den vorhandenen Stand statt einen zweiten Job anzulegen.

## Widerruf und Datenhoheit

**App-Freigabe widerrufen** bestätigt die genaue Grant-Version, stoppt zugehörige Zeitpläne und bricht wartende/laufende Jobs in derselben Transaktion ab. Weitere App-Ausführung und App-Downloads sind gesperrt. Bereits heruntergeladene Dateien lassen sich beim Empfänger dadurch nicht zurückholen. Der aktuelle Eigentümer behält Zugriff auf eigene historische Belege. **Zeitplan stoppen** verhindert künftige Einreihungen; bestehende Jobs werden separat behandelt.

Identity-Migration **048** speichert Anmeldungen, Grants, Jobs, Schedules, Originalevents und Pending-Outbox. Originale Firmenhoheit, aktuelle App-Autorisierung, Claim-/Grant-Deadline und tatsächliche Effekte werden vor/nach Operationen und durch SQL-Commit-Guards bestätigt. Globale Rollen und frühere menschliche Directory-/Lizenzpfade bleiben unverändert. Ein neuer Automationsscope kann keine kanonischen Benutzer, Gruppen oder fremden Authority-Tabellen nebenbei ändern; die vorhandenen Receiving-Fences werden auf die neuen Tabellen erweitert. Fehlendes Schema, deaktivierte Guards oder abweichende Originalbelege sperren die Aktion.

Artefakte und Metadaten liegen in der eigenen Identity-Datenbank. Ein vollständiger automatischer Retention-/Lösch- und Betriebsprozess gehört weiterhin zum offenen Gesamtauftrag. Hier wurden keine Produktivdaten, externen Postfächer oder Herstellerlizenzen verändert.

## Installation, API und Prüfung

Identity **001–048**, aktueller OAuth-Code mit dem neuen festen Workload-Scope und aktuelles Frontend koordiniert ausrollen. Der vorhandene Gateway-/Next-Prefix `/api/identity/*` reicht den ursprünglichen Bearer unverändert an Identity weiter. Keine neue Datenbank, Runtime-Dependency oder Server-Maschinen-Secret-Art. Der Runner verwendet reguläre Client-Credentials; das Identity-Dockerfile kopiert `packages/company-automation-contract.js` im vorhandenen Root-Buildkontext.

Die generierte [OpenAPI](../api/openapi.yaml) enthält die tatsächlichen Routen unter `/api/identity/automation`: App-Anmeldung, Grant-Approval/-Widerruf, Jobs, Schedules, Worker-Run, Resultate und Historie. `run` ist ausschliesslich für die tatsächlich genehmigte App erreichbar; `204` bestätigt, dass gerade kein Job fällig ist. Menschliche Verwaltungsänderungen benötigen aktuelle Eigentümerhoheit/MFA. API-Keys, Query-Bearer, fremde Tenant-Selektoren und nicht unterstützte Aktionen werden nicht als Ersatz akzeptiert.

```bash
npm run test:automation-client
npm test --prefix services/core/identity-service -- --runInBand CompanyAutomation
npm test --prefix services/core/oauth-provider -- --runInBand workloadPermissions tokenSecurity
npm test --prefix services/core/api-gateway -- --runInBand companyAutomationRouting
npm test --prefix frontend/web-app -- --runInBand companyAutomation CompanyAutomationView
npm run type-check --prefix frontend/web-app
TMPDIR=/tmp npm run test:groups:integration --prefix services/core/identity-service
```

Die nativen PostgreSQL-Fälle prüfen echte Owner-Aktivierung und Daten, Fremdmandanten, Widerruf, Generationen, parallele Claims, reale Artefakte aller angebotenen Typen, physische Deadlines, abgebrochene Worker, begrenzte Versuche, historische Wiederaufnahme, Migration-Replay und beschädigte ursprüngliche Belege. Die OU-Ausgabe verwendet den bestehenden Verzeichnisleser und verweigert inkohärente fremde Parent-Bezüge.

Ein echter lokaler Chrome-Durchlauf gegen einen frisch gebauten Produktionsserver verbindet die tatsächliche App-Erstellung und Anmeldung mit Owner-MFA, expliziter UI-Freigabe, dem CLI-Worker, geprüftem eigenem CSV-Download und Widerruf samt Abbruch wartender Jobs. [Testresultate und Grenzen](../testing/test-results.md#22-oktober-2026--eigene-app-freigaben-und-dauerhafte-exportjobs). Provider-, Last-, Restore- und produktive Betriebsabnahme bleiben offen.
