# Automatischer Lizenzgruppenabgleich

Stand: 23. Oktober 2026. Eine ausdrücklich freigegebene App kann bestehende eigene Gruppen-/Pool-Verknüpfungen ohne eine offene menschliche Sitzung abgleichen. Normale Gruppen bleiben normale Gruppen; die [Pool-Verknüpfung](company-license-groups.md) bestimmt die Lizenzgruppe. Der bestehende Allocator bleibt die einzige Sitzverwaltung. Eine lokale Zuweisung bestätigt keine Herstellerfreischaltung, kein Postfach und keine Installation.

## Einrichtung in der Oberfläche

1. Eigene Gruppe und eigenen endlichen Lizenzpool anlegen und verknüpfen. Bei der Verknüpfung **Automatischen Abgleich einrichten** öffnen.
2. Ein dediziertes App-Konto mit `client_credentials` und ausschliesslich `company.automation` anmelden. Als tatsächlicher Company-Owner mit frischer MFA die exakte Client-ID und Generation prüfen und **Gruppenlizenzen zuweisen und entziehen** ausdrücklich freigeben. Die Freigabe gilt höchstens 30 Tage.
3. Unter **Automationen** den Grant, die Lizenzaktion und die übernommene Verknüpfungs-ID wählen. **Lizenzgruppe prüfen** zeigt die tatsächliche eigene Gruppe, den Pool und die berechtigte Mitgliederzahl.
4. Einen Lizenzabgleich einreihen oder einen Zeitplan erstellen. Die Oberfläche schlägt eine Minute vor. Ein aktiver Zeitplan braucht einen laufenden App-Worker auf dem eigenen Runner.
5. Nach Ausführung neu laden. Fortschritt und blockierte Mitglieder werden angezeigt. Der geprüfte JSON-Lizenzbericht nennt die ausführende App und jedes bestätigte lokale Einzelresultat. Bei vollem Pool ist der Job **teilweise abgeschlossen**, nicht erfolgreich abgeschlossen.

Die App darf bestehende Verknüpfungen abgleichen. Diese Freigabe erlaubt weder Poolkäufe/-änderungen, neue Links oder Gruppenänderungen noch allgemeine Blueprint-, Rollen-, Benutzer- oder Policy-Verwaltung. Die OAuth-App-Registerverwaltung bleibt gesondert berechtigt; eigene tenantgebundene Registerverwaltung ist weiterhin offen.

## CLI und Zeitpläne

Die [App-Konfiguration](app-accounts-automation.md) verwenden. Auf dem Runner liegen ausschliesslich die eigenen App-Zugangsdaten, kein menschlicher Bearer. `approve` wird separat mit dem originalen aktuellen Eigentümertoken und MFA ausgeführt.

```bash
node scripts/od.mjs automation enroll 'Lizenzgruppen-Worker'
# Als tatsächlicher Firmeninhaber, alternativ in der Oberfläche:
node scripts/od.mjs automation approve ENROLLMENT_ID CLIENT_ID CLIENT_REVISION \
  'licenses.groups.reconcile' 24

# Mit den freigegebenen App-Zugangsdaten:
node scripts/od.mjs automation license-sync GRANT_ID RULE_ID
node scripts/od.mjs automation license-sync GRANT_ID RULE_ID 60
node scripts/od.mjs automation worker GRANT_ID

node scripts/od.mjs automation jobs GRANT_ID
node scripts/od.mjs automation history JOB_ID
node scripts/od.mjs automation result JOB_ID
```

Ohne Intervall entsteht ein Job; mit Intervall ein dauerhafter Zeitplan. `RULE_ID` bezeichnet den konkreten Link aus `license-group list GROUP_ID`, nicht die Gruppe oder den Pool. Das Ergebnisformat ist immer JSON. Eigene Skripte verwenden `createAutomationClient(client).enqueue(grantId, 'licenses.groups.reconcile', 'json', ruleId)` oder `.schedule(grantId, 'licenses.groups.reconcile', 60, 'json', ruleId)`.

Intervalle liegen zwischen 60 Sekunden und 30 Tagen. Ein noch wartender/laufender Lizenzjob desselben Zeitplans wird weitergeführt, statt für jedes verstrichene Intervall einen weiteren Abgleich aufzustapeln. Zeitpläne erfassen spätere Mitglieds-/Reviewänderungen und wieder freien Bestand beim nächsten Lauf. Externe Änderungsereignisse werden noch nicht zugestellt; dynamische und verschachtelte Gruppen sind weiterhin offen.

`worker` verarbeitet jeweils höchstens 25 erfasste Benutzer. Er protokolliert Job-Metadaten und seinen tatsächlichen App-Principal. `--once` führt genau einen Schritt aus: Code 0 bestätigt einen abgeschlossenen erfolgreichen Job oder keine fällige Arbeit, Code 2 meldet einen anderen bestätigten Jobzustand, auch eine noch eingereihte Folgeseite oder ein Teilresultat. Code 1 bedeutet abgelehnt/unbestätigt. Ein einmaliger Runner-Aufruf verarbeitet deshalb nicht automatisch alle Seiten einer grossen Gruppe.

## Sitzregeln, Wiederaufnahme und Entzug

- Aktive berechtigte eigene Mitglieder erhalten die bestehende Gruppenquelle. Mehrere Gruppen, Blueprints und direkte Quellen teilen pro Benutzer/Pool genau einen effektiven Sitz.
- Gruppen-/Review-Austritt, deaktivierte/gelöschte Empfänger und beendete Links entfernen ausschliesslich diese Gruppenquelle. Andere Herkünfte bleiben erhalten. Erst die letzte Herkunft gibt den Sitz frei.
- Ein voller Pool wird nicht überbucht. Der Bericht enthält `blocked` mit Code 409. Gesperrte oder nicht auflösbare individuelle Ziele können ebenfalls blockiert bleiben. Ein verweigerter Grant oder eine ungültige Quelle wird nicht als harmlos blockiertes Mitglied umgedeutet.
- Die App-Freigabe ist eine tatsächliche maschinelle Delegation. Die App übernimmt weder die menschliche Identität noch deren MFA oder globale Rollen. Clientrotation/-deaktivierung, Grantwiderruf/-ablauf, Tenant-Inkarnationswechsel oder Verlust der ursprünglichen Eigentümerschaft sperren weitere Schritte.
- Der Grant ist die App-Principal-ID der lokalen Wirkung. Öffentliche Bindungen und Poolhistorie kennzeichnen ihn ausdrücklich mit `actor.kind:application`, Client-ID/-Generation und `actorUserId:null`.

Jeder Job pinnt genau eine Verknüpfung. Policy erfasst deren aktuellen Stand samt vollständiger sortierter Zielmenge, anschliessend unveränderliche Seiten und verpflichtende Pending-Outbox. Eine neue Worker-Instanz setzt beim gespeicherten Stand fort. Ein verlorener HTTP-Erfolg darf keine zweite Sitzbelegung erzeugen. Fehlende oder korrupte Originalbelege sperren die Fortsetzung; sie werden nicht repariert oder als Erfolg rekonstruiert.

Ein Durchlauf umfasst höchstens 10'000 Ziele. Ändert sich die Gruppe oder werden während des Durchlaufs Plätze frei, sind höchstens fünf neue Erfassungen je manueller Versuchsfolge möglich. Danach ist ein neuer expliziter Versuch erforderlich. Einzelne Mitglieder committen unabhängig; ein Fehler oder Abbruch rollt bereits bestätigte Zuweisungen/Entzüge nicht zurück. Fortschritt, Poolstand und Poolhistorie vor einer Wiederholung prüfen. Die Jobhistorie bewahrt frühere Versuche. Ein manueller Retry beginnt eine neue Versuchsfolge und entfernt das alte Ergebnis aus dem aktuellen Download; die ursprünglichen Policy-Seiten und Jobbelege bleiben erhalten.

Eine endgültige Antwort mit blockierten Mitgliedern wird `partial`, einschliesslich bestätigtem JSON-Bericht und SHA-256. Noch nicht abgeschlossene Seiten bleiben beim selben Job `queued`. Unklare Transportfehler benutzen die vorhandenen fünf begrenzten Versuche/Backoff; dauerhaft abgelehnte Abgleiche bleiben sichtbar `failed`. Ein Job- oder Grantabbruch verhindert weitere Schritte, zieht aber keine schon gespeicherten Gruppenquellen pauschal zurück. Dafür die tatsächliche Gruppe/Verknüpfung ändern und unter aktueller eigener Hoheit abgleichen.

Identity und Policy bleiben getrennte Datenbanken. Quellen werden vor/nach den Operationen und an lokalen Commit-Grenzen erneut geprüft; das ist kein verteilter atomarer Commit oder eine Zusage sofortiger Cross-Service-Sperrung. Die ursprüngliche Job-Lease läuft höchstens 45 Sekunden, zusätzlich begrenzt durch App-Token, Grant und Membership-Reviewdeadline. Ein eingereihter Job oder Pending-Beleg ist keine externe Zustellung.

## Installation und API

Identity **001–049**, Policy **001–029**, aktueller OAuth-Code, Frontend und CLI koordiniert aktualisieren. Identity braucht den tatsächlichen `POLICY_SERVICE_URL`, Policy den tatsächlichen `IDENTITY_SERVICE_URL`; beide behalten den konfigurierten Issuer/JWKS/live Access-State. Die beiden internen Ursprünge gehören in geschützte Betreiberkonfiguration, nicht in Jobdaten. Docker-Buildkontext bleibt die Repository-Wurzel; beide Services kopieren die gemeinsamen Verträge. Keine neue Dependency oder zusätzliche Art von Service-Secret.

Migration 049 erweitert den ursprünglichen Automationsreceiver und dessen Manifest. Bei einer vollständigen Migration-Wiederholung nach 048 auch 049 anwenden. Alte Originalereignisse werden durch die Snapshot-Kompatibilität gelesen, nicht umgeschrieben. Policy 029 erweitert den bestehenden source-aware Blueprint-/Allocator-Kernel um den engen maschinellen Pfad, echte App-Provenienz und die dauerhaften Abgleichseiten. Zeitzonenwechsel verändern die Bedeutung historischer Zeitpunkte nicht.

Der [OpenAPI-Vertrag](../api/openapi.yaml) dokumentiert Version 1.22.0:

| Methode | Pfad | Tatsächlicher Zweck |
| --- | --- | --- |
| POST | `/api/identity/automation/jobs` | Lizenzjob mit `action:licenses.groups.reconcile`, `ruleId`, `format:json` |
| POST | `/api/identity/automation/schedules` | Gleicher fester Auftrag mit `intervalSeconds` |
| POST | `/api/identity/automation/run` | Nur die freigegebene App; einen gespeicherten Schritt ausführen |
| POST | `/api/identity/automation/license-source` | Privater empfangsgebundener Grant-/Job-/Lease-Nachweis und kanonische Gruppe/Eligibility |
| POST | `/api/licenses/automation/groups/step` | Privater Policy-Empfänger; genau ein gebundener Abgleichschritt |
| GET | `/api/identity/automation/jobs/:id/result` | Vollständiger bestätigter JSON-Bericht bei `succeeded` oder `partial` |

Die privaten Empfänger akzeptieren keine API-Keys, beliebigen URLs, Tenant- oder Poolselektoren. Der originale aktuelle App-Bearer bleibt durchgehend erhalten. Allgemeine menschliche Policy-/Lizenzpfade bleiben für App-Tokens gesperrt. Konkrete Providerzugänge, Ereigniszustellung, Retention und die übrigen Punkte im [Gesamtauftrag](../implementation-worklist.md) bleiben offen.
