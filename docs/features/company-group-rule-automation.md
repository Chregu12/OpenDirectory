# Unbeaufsichtigter Gruppenregel-Abgleich

Stand: 23. Oktober 2026. Eine ausdrücklich freigegebene App kann gespeicherte eigene [Attribut- und Untergruppenregeln](company-group-rules.md) über dauerhafte Jobs und Zeitpläne ausführen. Sie benötigt keine offene Eigentümersitzung. Die Aktion **`directory.groups.reconcile`** darf tatsächliche Regelmitgliedschaften hinzufügen und entziehen; sie darf keine Regeln konfigurieren, manuellen Mitgliedschaften übernehmen, Rollen vergeben oder Lizenzpools verändern.

## Einrichtung

1. Als tatsächlicher Firmeninhaber mit frischer MFA eine eigene Gruppenregel speichern. Speichern allein verändert weiterhin keine Mitgliedschaft.
2. Ein dediziertes [App-Konto](app-accounts-automation.md) mit exakt `company.automation` anmelden: `node scripts/od.mjs automation enroll 'Gruppenregel-Worker'`.
3. Unter **Automationen** die Anmeldungs-ID prüfen, **Gespeicherte Gruppenregeln ausführen** auswählen und die konkrete Freigabe samt Laufzeit bestätigen. Vorhandene Export- oder Lizenzfreigaben erhalten dieses zusätzliche Schreibrecht nicht automatisch.
4. Die Freigabe und Aktion auswählen, die tatsächliche **Gruppenregel-Gruppen-ID** prüfen und den Job oder Zeitplan anlegen. `ruleId` ist bei dieser Aktion die kanonische Gruppen-UUID, nicht die ID einer Lizenzpool-Verknüpfung. Auch eine deaktivierte gespeicherte Regel ist ein gültiges Entzugsziel.
5. Auf dem Runner ausschliesslich die eigenen App-Zugangsdaten konfigurieren und den Worker betreiben. Secret und Token gehören nicht ins Repository oder in Befehlsargumente.

```bash
node scripts/od.mjs automation group-sync GRANT_ID GROUP_ID
# Zeitplan mit tatsächlichem 60-Sekunden-Intervall:
node scripts/od.mjs automation group-sync GRANT_ID GROUP_ID 60
node scripts/od.mjs automation worker GRANT_ID
```

UI und CLI verwenden dieselbe persistente Queue. Ein Zeitplan bleibt ohne laufenden Runner gespeichert. Wartende/laufende Jobs desselben Zeitplans werden fortgesetzt; verpasste Intervalle erzeugen keine unbeschränkte Warteschlange. Freigaben sind höchstens 30 Tage gültig. Widerruf beendet wartende/laufende Jobs und stoppt deren Zeitpläne; bereits bestätigte Mitgliedschaften werden dadurch nicht rückwirkend gelöscht.

## Herkunft, Freigaben und Recovery

Die Ausführung bindet aktuellen ursprünglichen App-Bearer, Issuer/Clientgeneration, tatsächliche Freigabe, eigenen Tenant, festes Gruppenziel, Job, Retry-Epoche und aktuelle 45-Sekunden-Lease. Weder menschliche Rollen noch MFA- oder Benutzerkontexte werden hergestellt. Der kanonische Gruppen-Kernel prüft diesen eigenen Maschinenvertrag auch an der physischen Commit-Grenze.

Maschinelle Membership-Origins besitzen `created_by=NULL` und den tatsächlichen FK `application_grant_id`. Das Gruppenereignis nennt ausdrücklich die App und Freigabe. Effektive Quellen und positive Review-Entscheidungen verlangen den passenden Originaleffekt mit kanonischem Ereignis und Pending-Fingerprint; eine importierte fremde oder falsch zugeordnete Grant-ID wird nicht adoptiert. Gruppen-/Jobhistorie und geprüfte Gruppenberichte zeigen die wirklichen Belege. Die App erhält dadurch keine Benutzeridentität. Ein unabhängiger Reviewer darf weder der Empfänger noch der ursprüngliche App-Freigeber oder Policy-Konfigurierer sein und darf nicht selbst Mitglied der Zielgruppe sein.

Ein geschütztes neues Mitglied bleibt tatsächlich `awaiting-review`, ohne anfängliche Freigabe. Der Job meldet `partial`, bis ein berechtigter unabhängiger Mensch entscheidet. Eine erneute Ausführung setzt die Review-Lease nicht zurück. Eine übergeordnete Gruppe übernimmt nur tatsächlich effektive Child-Mitglieder. Änderungen an Regeln oder Eligibility können Entfernung und Neuausstellung der ursprünglichen Regelquelle erfordern; diese Schritte sind getrennte Commits.

Jeder Lauf erfasst höchstens 10'000 tatsächliche Ziele. Eine Worker-Anfrage verarbeitet höchstens 25 noch unbelegte Mitglieder und speichert jedes bestätigte Ergebnis mit eigenem Pending-Fingerprint. Echte Membership-Wirkung und der zugehörige Schritt committen gemeinsam. Nach verlorenem Job-Ergebnis oder Prozesswechsel werden vorhandene Originalbelege gelesen; derselbe kanonische Add wird nicht blind wiederholt. Der Bericht nennt die Ergebnisse der letzten tatsächlichen Erfassung; frühere Zyklen/Schritte bleiben als unveränderliche Datenbankbelege und die Membership-Effekte in der Gruppenhistorie erhalten. Ein paginierter allgemeiner Viewer sämtlicher früherer Zyklen ist damit nicht behauptet. Fortschritt, begrenzter Backoff, fünf Versuche und ausdrücklich neue Retry-Epochen verwenden die bestehende Jobverwaltung.

Bei geänderten Quellen oder nötiger Neuausstellung werden bis zu fünf neue tatsächliche Erfassungen je Retry-Epoche zugelassen. Danach bleibt der Job fehlgeschlagen, statt vollständige Konvergenz zu behaupten. Ausstehende Reviews und blockierte Mitglieder bleiben als `partial` sichtbar. Frühere bestätigte Mitgliedsschritte bleiben bei späteren Fehlern gespeichert. Fehlende oder beschädigte Receiver-/Event-/Pending-Belege führen zur Ablehnung und werden nicht automatisch repariert.

Kinder und Eltern besitzen getrennte Ziele und Zeitpläne. Läuft ein Parent vor dem Kind, wird dessen neue Wirkung erst in einem späteren Parent-Lauf erfasst. Unmittelbare effektive Quellenpropagation und externe Änderungsereignisse bleiben offen. Ebenso bleibt die [Lizenzvergabe](company-license-automation.md) ein eigener ausdrücklich delegierter Job über tatsächliche Gruppenquellen; dieser Worker bestätigt keine Herstellerlizenz, Mailbox, Installation oder Geräteaktion.

## Installation und Datenhoheit

Identity **001–051**, aktueller Identity-Code, Frontend und CLI koordiniert ausrollen; OAuth behält den vorhandenen festen Scope. Keine neue Dependency, Datenbank oder Secret-Art. Nach erneutem Anwenden von 048/049/050 anschliessend auch 051 anwenden, damit die geschützten Receiver und Manifeste den aktuellen Stand besitzen.

Identity 051 ergänzt `identity_company_group_rule_runs`, `identity_company_group_rule_steps`, `identity_company_group_rule_work_outbox` und ein geschütztes Empfangsmanifest. Die Tabellen referenzieren tatsächliche Identity-Jobs, Freigaben, Regeln und kanonische Effekte; es gibt keine zweite Membership-Datenbank. Originalquellen enthalten keinen Bearer. Update/Delete/Truncate von gespeicherten Arbeitsbelegen sind gesperrt. Keine Pending-Outbox-Zustellung oder produktive Retention-Abnahme wird damit behauptet.

Der [OpenAPI-Vertrag](../api/openapi.yaml) **1.24.0** dokumentiert die fünfte explizite Aktion, feste Gruppen-UUID, Seitenfortschritt und den Gruppenbericht. Ausführung erfolgt über das bestehende authentifizierte `/api/identity/automation/run`; die manuellen Gruppenregel-Endpunkte bleiben dem tatsächlichen menschlichen Owner vorbehalten. Der [Gesamtauftrag](../implementation-worklist.md) bleibt offen.
