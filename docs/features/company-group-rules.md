# Dynamische und verschachtelte Gruppenregeln

Stand: 23. Oktober 2026. Der tatsächliche Firmeninhaber kann für eine eigene kanonische Gruppe Attributbedingungen und Untergruppen konfigurieren, deren Ergebnis prüfen und ausdrücklich abgleichen. Das erzeugt echte Mitgliedschaften über den vorhandenen `GroupMutator`. Es gibt kein zweites Verzeichnis und keine ausgedachten Membership-IDs. Die [unbeaufsichtigte Ausführung über App-Jobs](company-group-rule-automation.md) ist ebenfalls verfügbar; unmittelbare Quellenpropagation und externe Änderungsereignisse bleiben Teil des offenen [Gesamtauftrags](../implementation-worklist.md).

## Oberfläche

Unter **Verzeichnisgruppen** die eigene Gruppe wählen. Im Bereich **Dynamische und verschachtelte Gruppen**:

1. Optional **Attributbedingungen verwenden** wählen. Abteilung, Funktion, E-Mail, Benutzername und Anzeigename unterstützen **ist gleich**, **beginnt mit** und **endet mit**. Alle Bedingungen müssen gemeinsam zutreffen. Vergleiche ignorieren Gross-/Kleinschreibung; SQL-Wildcards oder ausführbare Ausdrücke werden nicht ausgewertet.
2. Eigene Untergruppen auswählen. Deren tatsächliche effektive Mitglieder kommen zusätzlich hinzu. Ausnahmen lassen sich als kanonische eigene Benutzer-IDs hinterlegen.
3. Begründung erfassen und **Gruppenregel speichern** ausdrücklich bestätigen. Dies speichert die Konfiguration; bestehende Mitgliedschaften werden dadurch noch nicht geändert. Auch das Deaktivieren entzieht noch keine Mitgliedschaft.
4. **Gespeicherte Regelvorschau prüfen** zeigt die tatsächliche gewünschte Menge und neue Verknüpfungen. Bei ungespeicherten Änderungen ist diese Vorschau gesperrt.
5. **Regelmitglieder abgleichen** gesondert bestätigen. Ergebnisse und **Gruppenregel-Historie** nennen echte Einzelschritte und die ursprünglichen Belege. Mehrere Ergebnisse/Historienseiten sind erreichbar.

Die neue Funktion braucht tatsächliche Company-Ownership und ursprüngliche frische MFA, auch zum Lesen. Ein globales Rollenwort oder eine blosse App-Registrierung ersetzt diese Hoheit nicht. Bestehende normale Gruppenadministration behält ihre eigenen Rechte; sie erhält dadurch keine neue Regelverwaltung.

## Herkunft, Review und Aktualisierung

- Bereits manuell verknüpfte Benutzer bleiben manuell. Der Abgleich erklärt sie nicht rückwirkend zu Regelmitgliedern und entfernt sie bei einer späteren Ausnahme/Deaktivierung nicht.
- Regelmitgliedschaften behalten die tatsächliche serverseitig erzeugte Membership-UUID und den kanonischen Gruppenereignis-FK. Nur diese ursprüngliche Inkarnation darf die Regel später entfernen. Eine manuell entfernte und neu angelegte andere Inkarnation wird nicht übernommen.
- Eine geänderte Regelversion oder Empfänger-Generation benötigt gegebenenfalls Entfernung und Neuausstellung der alten Regelquelle. Ein historischer Review wird nicht einfach auf eine neue Quelle übertragen.
- Hat die Zielgruppe eine unabhängige Mitgliedschaftsprüfung, entsteht die wirkliche erste ausstehende Review-Lease ohne anfängliche Freigabe. `awaiting-review` ist kein positiver App-/Lizenzzugriff. Eine übergeordnete Gruppe übernimmt diesen Benutzer erst nach tatsächlicher effektiver Freigabe im Kind.
- Attributänderungen, Child-Mitgliedschaften und Reviews werden beim nächsten manuellen oder ausdrücklich genehmigten zeitgesteuerten Abgleich neu ausgewertet. Beim manuellen Abgleich mehrerer Ebenen zuerst die Kinder, danach die Eltern abgleichen; Zeitpläne verwenden getrennte Kinder-/Elternläufe. Konfigurationsänderung, Kind-Entzug und Parent-Entzug sind keine gemeinsame atomare Operation.
- Ein eigener vorhandener [Lizenzgruppen-Link](company-license-groups.md) kann anschliessend manuell oder über den bereits verfügbaren [Lizenz-App-Worker](company-license-automation.md) abgeglichen werden. Gruppenmaterialisierung und Poolvergabe bleiben getrennte tatsächliche Schritte.

Höchstens acht Bedingungen, 25 unmittelbare Kinder, 16 Verschachtelungslinks und 10'000 gewünschte Benutzer/Abgleichziele sind zulässig. Zyklen und fremde/unowned Referenzen werden abgelehnt. Die bestehende kanonische Gruppe bleibt auf 10'000 physische Mitgliedschaften begrenzt; bestehende manuelle Mitglieder verbrauchen diese Grenze ebenfalls. Ein Abgleich verarbeitet höchstens 25 sortierte Benutzer pro API-Seite. Der gleiche erfasste `observation`-Hash bindet Regelversion, gewünschte IDs und Eligibility-Generationen. Geänderte Quellen stoppen die Fortsetzung.

Ein späterer Fehler rollt frühere bestätigte Mitglieder nicht zurück. `blocked` und Codes beachten; nach einem unbestätigten Ausgang zuerst Gruppe und Historie lesen. Eine neue Vorschau ist eine neue Beobachtung, keine automatische Wiederholung einer alten Schreibwirkung. Gruppen-/Review-Verknüpfung bestätigt keine Herstellerlizenz, Mailbox, App-Installation oder Geräteaktion.

## Skripte

Node.js 20+ und die [CLI-Konfiguration](app-accounts-automation.md) verwenden. Diese Befehle benötigen `OPENDIRECTORY_ADMIN_ACCESS_TOKEN` mit dem ursprünglichen aktuellen Eigentümertoken und MFA. Sie verwenden keinen App-Token als menschliche Identität. Zugangstoken gehören nicht in Dateien oder Befehlsargumente.

Beispiel `engineering-rule.json` mit einer tatsächlichen eigenen Child-UUID anstelle des Platzhalters oder leerer Child-Liste:

```json
{
  "enabled": true,
  "draft": {
    "dynamic": { "all": [{ "attribute": "department", "operator": "equals", "value": "Engineering" }] },
    "childGroupIds": [],
    "excludedUserIds": []
  },
  "reason": "Engineering anhand der eigenen kanonischen Abteilung verknüpfen",
  "confirm": true
}
```

```bash
node scripts/od.mjs group-rule get GROUP_ID
node scripts/od.mjs group-rule configure GROUP_ID engineering-rule.json
node scripts/od.mjs group-rule preview GROUP_ID
node scripts/od.mjs group-rule sync GROUP_ID 'Gespeicherte eigene Regel ausdrücklich abgleichen'
node scripts/od.mjs group-rule history GROUP_ID
```

`configure` liest die tatsächliche Version und übermittelt starken `If-Match` plus neue UUID als `Idempotency-Key`. Es gibt keine automatische Schreibwiederholung. Eigene Skripte verwenden `createGroupRuleClient(client)` aus `scripts/lib/company-group-rules.mjs`. `sync` folgt den erfassten Seiten; Exit-Code 2 meldet blockierte Mitglieder oder ausstehende unabhängige Freigaben, Code 1 abgelehnte/unbestätigte Ergebnisse. Frühere bestätigte Schreibwirkungen können bei Code 1 bestehen bleiben.

## Datenmodell, Installation und API

Identity **001–051**, aktueller Identity-Code, Frontend und CLI koordiniert ausrollen. Das Dockerfile kopiert `packages/company-group-rule-contract.js` im bestehenden Repository-Root-Buildkontext. Keine neue Dependency oder Secret-Art. Die vorhandenen `/api/groups/*`-Proxys reichen den originalen Bearer und die konditionalen Header weiter.

Migration 050 speichert die aktuelle versionierte Konfiguration in `identity_company_group_rules`, ihre ursprünglichen Events/Pending-Fingerprints und die kanonischen Membership-Effekte samt eigenem Pending-Fingerprint. Die Membership-Effekte referenzieren wirkliche `identity_directory_group_events` und `identity_membership_origins`, bleiben unveränderlich und können keine normale manuelle Membership adoptieren. Guards, Originalmanifest, tatsächlicher Owner, kanonische Wirkung und Deadline werden an der physischen Commit-Grenze geprüft. Neue Tabellen übernehmen die bestehenden No-extra-effects-Fences; die Konfiguration kann auch keine früheren oder späteren fremden Canonical-Writes mitnehmen. Retention, Veröffentlichung der Pending-Outbox und vollständiger Audit-/Recovery-Betrieb bleiben offen.

Der [OpenAPI-Vertrag](../api/openapi.yaml) ist Version **1.24.0**:

| Methode | Pfad | Wirkung |
| --- | --- | --- |
| GET | `/api/groups/:id/rule` | Aktuelle eigene Konfiguration oder ausdrücklich fehlende Regel mit `absent`-ETag |
| PUT | `/api/groups/:id/rule` | Exakte bestätigte Konfiguration mit `If-Match` und `Idempotency-Key`; kein Mitgliederabgleich |
| GET | `/api/groups/:id/rule/preview` | Vollständige begrenzte aktuelle gewünschte Menge und tatsächliche kanonische Mitgliedschaften |
| POST | `/api/groups/:id/rule/sync` | Bestätigte Seite mit `observation`, `cursor`, `reason`, `confirm:true` |
| GET | `/api/groups/:id/rule/history?page=1` | 25 ursprüngliche Konfigurations-/Membership-Belege der noch bestehenden eigenen Gruppe |

Konfiguration und einzelne Mitgliedschaften committen unabhängig. Bei tatsächlich gelöschten Gruppen bleiben die Belege in der Datenbank erhalten; diese Oberfläche/API setzt eine noch bestehende eigene Gruppe voraus. Ein fehlender Receiver oder beschädigter Original-/Pending-Beleg wird nicht durch eine erfolgreiche leere Antwort ersetzt. Die unbeaufsichtigte Ausführung verwendet den separat freigegebenen App-/Zeitplanweg. Unmittelbare Quellenpropagation bleibt offen; dies verkleinert den Gesamtauftrag nicht.
