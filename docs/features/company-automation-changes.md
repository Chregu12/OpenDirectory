# Gruppen und Lizenzpools bei Quellenänderungen abgleichen

Stand: 23. Oktober 2026. Ein ausdrücklich genehmigter App-Worker kann gespeicherte Gruppenregeln und lokale Lizenzgruppen nach Änderungen ihrer tatsächlichen Quellen abgleichen. Der erste Lauf erfasst den aktuellen Stand; weitere Jobs entstehen bei einem geänderten Quellenstand. Es muss kein 60-Sekunden-Intervall abgewartet werden. Der bestehende Runner beobachtet die Quellen normalerweise alle fünf Sekunden; Last, laufende Jobs und Backoff können die Ausführung verzögern. Das ist eine lokale Quellenbeobachtung, keine allgemeine Event-Bus- oder Webhook-Zustellung.

## Einrichtung

Die [App-Freigabe](company-automation.md) bleibt unverändert: ein dediziertes Konto mit exakt `company.automation`, tatsächliche Client-Credentials, eigener Firmeninhaber mit frischer MFA bei der ausdrücklichen Genehmigung und nur die benötigten Aktionen. Laufende Worker benötigen keine menschliche Sitzung. `directory.groups.reconcile` und `licenses.groups.reconcile` bleiben getrennte Rechte.

In **Automationen** die Freigabe und Aktion auswählen, die konkrete Gruppenregel bzw. Lizenzverknüpfung prüfen und **Bei Quellenänderungen abgleichen** wählen. Die Oberfläche zeigt den Modus und die zuletzt erfasste Quellenrevision. Öffnen oder Prüfen einer Seite führt keinen Abgleich aus.

```bash
# Gespeicherte Attribut-/Untergruppenregel: GROUP_ID ist die kanonische Gruppe.
node scripts/od.mjs automation group-watch GRANT_ID GROUP_ID

# Bestehende Gruppen-/Pool-Verknüpfung: RULE_ID aus license-group list GROUP_ID.
node scripts/od.mjs automation license-watch GRANT_ID RULE_ID

# Derselbe bestehende App-Runner verarbeitet beide Arten von Aufträgen.
node scripts/od.mjs automation worker GRANT_ID
```

App-Erstellung und ausdrückliche Grant-Genehmigung benötigen den ursprünglichen menschlichen Verwaltungstoken. Die obigen `group-watch`-/`license-watch`-Befehle verwenden wie der Worker eigene App-Zugangsdaten und die bereits genehmigte Freigabe. Auf dem Runner keinen menschlichen Token hinterlegen. Node-Skripte verwenden `createAutomationClient(client).watch(grantId, action, ruleId)`. Beim API-Aufruf an `POST /api/identity/automation/schedules` ersetzt `onChange:true` das Feld `intervalSeconds`. Das Ergebnis hat `intervalSeconds:null`, `onChange:true`, `lastSourceRevision` und `lastDeadlineRevision`; beide letzten Felder sind vor der ersten Erfassung `null`. Exportaktionen unterstützen diesen Modus nicht. Bestehende Intervallzeitpläne und einzelne Jobs funktionieren weiter.

Höchstens 25 aktive Änderungsbeobachtungen je Freigabe und eine aktive Beobachtung je Aktion/Ziel sind erlaubt. Die bestehende Obergrenze von 100 aktiven Zeitplänen gilt zusätzlich. Ein Worker-Aufruf reiht höchstens fünf neue Änderungsjobs ein; weitere Ziele folgen in späteren Aufrufen. Pro Zeitplan bleibt höchstens ein unfertiger Job bestehen. **Zeitplan stoppen** beendet weitere Erfassungen; bereits angelegte Jobs besitzen ihre eigenen Abbruchaktionen. Widerruf der App-Freigabe stoppt wie bisher auch wartende/laufende Jobs.

## Tatsächliche Quellen und Wirkung

- Identity prüft die aktuelle eigene Gruppenquellenrevision und tatsächliche abgelaufene Review-Fristen. Attribut-, Regel-, Untergruppen-, Eligibility- und Reviewänderungen können neue Jobs auslösen. Die [aktuelle Quellenprüfung](company-group-live-sources.md) sperrt ungültige bestehende Regelquellen weiterhin schon vor physischer Bereinigung.
- Bei Lizenzgruppen kommt eine private aktuelle Policy-Beobachtung hinzu: ursprünglicher Link samt Status/Revision, eigener Pool, tatsächliche Poolrevision und freie lokale Sitze. Eine Bestandserhöhung oder Sitzrückgabe kann deshalb blockierte Mitglieder erneut abgleichen, auch wenn die Gruppe unverändert ist.
- Die Ausführung verwendet dieselben kanonischen Membership-Kernel und denselben endlichen Allocator. Manuelle Quellen, ursprüngliche Membership-Inkarnationen, unabhängige Reviews und ein gemeinsamer Sitz bei überlappenden Lizenzquellen bleiben erhalten. Ein Worker kann eine unabhängige menschliche Freigabe nicht selbst erteilen.
- Eltern- und Kindgruppen sowie Lizenzgruppen bleiben getrennte Ziele. Änderungen können mehrere aufeinanderfolgende Worker-Schritte benötigen. Eine eigene Membership-/Poolwirkung kann einen weiteren idempotenten Bestätigungslauf auslösen; es entsteht dadurch kein zusätzlicher Sitz.

Die lokale Zuweisung bleibt ausdrücklich `allocationMode:local-only`. Sie bestätigt keine Microsoft-/Apple-Freischaltung, Mailbox, App-Installation oder Geräteaktion.

## Originalbelege, Fehler und Wiederaufnahme

Identity 053 erweitert die bestehenden Zeitplan- und Jobtabellen. Ein Zeitplan hält `source_checkpoint` und den tatsächlichen FK `source_job_id`; der neue Job hält seine unveränderliche `event_source`. Quellencheckpoint, konkreter Job und ursprüngliche Pending-Belege müssen in derselben Transaktion committen. Fehlt einer dieser Teile, wird die gesamte Einreihung zurückgerollt. Gleichzeitige Worker serialisieren die bestehende Grant-Quote; eine bereits erfasste unveränderte Quelle erzeugt keinen weiteren Job.

Während ein Job unfertig ist, werden weitere Änderungen zusammengefasst. Nach dessen Abschluss wird der dann aktuelle Zustand neu beobachtet. Ein fehlgeschlagener oder teilweise abgeschlossener Job erhält durch eine unveränderte Quelle keine neue Versuchsfolge. Eine tatsächliche weitere Quellenänderung kann einen neuen Job auslösen; die explizite manuelle Wiederholung bleibt verfügbar. Bestehende Leases, Seiten, fünf begrenzte Transportversuche, Backoff und Historie bleiben erhalten. Kein unbestätigter Aufruf gilt als erfolgreicher Abgleich.

Eine nicht verfügbare Quelle setzt ihren Checkpoint nicht fort. Andere bestätigte Quellen und bereits eingereihte Jobs können weiterlaufen. Wenn nichts ausgeführt werden kann und Quellen nicht verfügbar sind, liefert der Worker-Aufruf 503 statt eines angeblich unauffälligen 204; der Runner verwendet seinen bestehenden Backoff. Es wird hier kein neuer dauerhafter allgemeiner Delivery-/Fehlerjournal-Dienst eingeführt.

Jobantworten zeigen den ursprünglichen Auslöser als `trigger` mit `kind:change`, Gruppen-ID, Quellenrevision und Review-Zähler. Lizenzjobs zeigen zusätzlich die erfasste Pool-ID/-Revision und damaligen freien Sitze. Diese Angaben sind Beobachtungen bei Einreihung; der tatsächliche ausführende Kernel prüft die dann gültigen Quellen erneut. Öffentliche Antworten enthalten keine Bearer oder Token-Hashes.

## Interne Empfänger und Betrieb

`POST /api/identity/automation/watch-source` bestätigt ausschliesslich eine tatsächliche aktuelle genehmigte Lizenzbeobachtung. `POST /api/licenses/automation/groups/observe` liest den eigenen Link/Pool in einer Read-only-Repeatable-Read-Transaktion und prüft die ursprüngliche Identity-Hoheit vor und nach dem Lesen. Beide verwenden denselben originalen aktuellen App-Bearer und feste Betreiber-Ursprünge. Die minimalen privaten Antworten enthalten keine Mitgliederprofile; sie erteilen weder allgemeine Poolverwaltung noch menschliche Rechte. Transaktionen vergleichen gespeicherte Originalzeitpunkte in UTC, unabhängig von der Connection-Zeitzone.

Die ausschliesslich maschinellen POST-Pfade besitzen begrenzte getrennte Admission-Budgets: 4'000 rohe Anfragen je IP/Minute und 1'200 verifizierte Anfragen je Issuer/Client/Generation/Minute. Die allgemeinen API-Limits bleiben bestehen. Exakte App-Purpose-Prüfung erfolgt nach der normalen JWT-/Live-Access-State-Prüfung; ein menschlicher Token erhält diesen Zugriff nicht. Die Budgets sind keine Last- oder Verfügbarkeitszusage.

Koordinierter Stand: **Identity 001–053**, **Policy 001–029**, aktuelle Server, Frontend und CLI. Bei Wiederholung älterer Automations-/Gruppenmigrationen auch 051/052 und zuletzt **053** anwenden. Originale historische Events werden über Snapshot-Kompatibilität gelesen, nicht umgeschrieben. Beide Dockerfiles kopieren die gemeinsamen Verträge und Admission-Funktionen im vorhandenen Repository-Root-Buildkontext. Keine neue Dependency, Datenbank oder Art von Service-Secret. Identity benötigt den tatsächlichen `POLICY_SERVICE_URL`, Policy den tatsächlichen `IDENTITY_SERVICE_URL` sowie die vorhandenen gültigen Issuer-/JWKS-/Access-State-Einstellungen.

Der generierte [OpenAPI-Vertrag](../api/openapi.yaml) ist **1.26.0**. [Testresultate](../testing/test-results.md#23-oktober-2026--abgleich-bei-quellen--und-bestandsänderungen) belegen echte lokale Datenbank-, HTTP- und Produktionsbrowserabläufe. Dienstübergreifende sofortige Cache-Invalidierung, generische Outbox-Zustellung, externe Webhooks, tenantgebundene App-Registerverwaltung, Provider und sämtliche übrigen BR-/WF-/Betriebsabnahmen bleiben im [vollständigen Auftrag](../implementation-worklist.md) offen.
