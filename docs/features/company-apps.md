# Eigene Firmen-App-Konten

Stand: 23. Oktober 2026. Tatsächliche Firmeninhaber können unter **Firmen-Apps** eigene vertrauliche OAuth-App-Konten erstellen, lesen, bearbeiten, aktivieren/deaktivieren, deren Secret rotieren und sie mit erhaltener Historie löschen. Dafür werden keine globalen Anwendungsrollen vergeben. Die Konten liegen im bestehenden `oauth_clients`-Register; es gibt keine zweite Client- oder Secret-Datenbank.

## Oberfläche und Freigabe

1. Mit dem tatsächlichen Firmeninhaber und frischer verifizierter MFA anmelden. Auch Lesen, Listen und Historie benötigen MFA, die höchstens fünf Minuten alt ist.
2. **Firmen-Apps → Eigenes App-Konto erstellen** öffnen, Name, Zweck und Begründung angeben und ausdrücklich bestätigen. Standardzweck ist **Keine Berechtigungen**. Alle neuen Konten beginnen deaktiviert, ohne Redirects oder Benutzeranmeldung.
3. Das einmalige Secret geschützt übernehmen und ausblenden. Die Oberfläche speichert es nicht in Local-/Session-Storage. Client-ID, Name und Registerversion bleiben lesbar, das Secret und dessen Hash nicht.
4. Die konkrete App bearbeiten und ausdrücklich aktivieren. Zweck **Firmenautomationen** konfiguriert ausschliesslich `company.automation`; er genehmigt noch keinen Export, keine Gruppenänderung und keinen Lizenzabgleich.
5. Die App mit ihren eigenen Credentials [zur Automation anmelden](company-automation.md), danach konkrete eigene Aktionen und deren Laufzeit separat als Owner bestätigen. Der Worker verwendet ausschliesslich die App-Zugangsdaten und braucht keine offene menschliche Sitzung.

Ein Konto kann nur dem ursprünglichen Unternehmen gehören. Weder Formular/API-Tenantwerte noch globale Rollen ersetzen die tatsächliche Owner-Quelle. Die bestehenden globalen Register-, Authentifizierungs- und Zuweisungsrouten verwalten diese Firmenkonten nicht. Globale ungebundene Web-/Public-/sonstige Clients bleiben im bisherigen getrennt berechtigten Registerweg; sie werden nicht automatisch adoptiert. Eigene weitere App-Typen, benutzerdefinierte Scopes/Rollen und delegierte Appadministration bleiben weitere Anforderungen.

**Registeransicht → Gelöschte Apps und Historie** zeigt ursprüngliche archivierte Konten und deren Belege. Löschen deaktiviert das Konto und behält Namespace, Originalauftrag, Ereignisse und Pending-Belege. Es gibt hier keine stille Wiederherstellung einer gelöschten App. Eine neue App benötigt einen neuen ausdrücklichen Auftrag.

## Skripte

Die Verwaltung verwendet `OPENDIRECTORY_ADMIN_ACCESS_TOKEN` als ursprünglichen eigenen menschlichen Bearer mit frischer MFA. Der Name der vorhandenen Umgebungsvariablen verleiht keine globale Rolle. `OPENDIRECTORY_API_URL` muss auf den OAuth-Service oder auf den aktuellen Gateway mit aktiviertem `identity-service` zeigen. Der Gateway reicht `/api/clients/company` unverändert an `OAUTH_PROVIDER_URL` weiter. Der Browser nutzt den bestehenden `/api/clients/*`-Proxy.

```bash
node scripts/od.mjs company-app list

# REQUEST_UUID einmal erzeugen und für die Original-Recovery behalten.
node scripts/od.mjs company-app create REQUEST_UUID 'Gruppenworker' \
  'Eigene App für den bestätigten Gruppenabgleich' company-automation

node scripts/od.mjs company-app get CLIENT_ID
node scripts/od.mjs company-app enable CLIENT_ID 'Eigene App ausdrücklich aktivieren'
node scripts/od.mjs company-app rename CLIENT_ID 'Neuer App-Name' 'Eigene App nachvollziehbar umbenennen'
node scripts/od.mjs company-app purpose CLIENT_ID none 'Den bisherigen Automationszweck entziehen'
node scripts/od.mjs company-app rotate CLIENT_ID 'Originales App-Secret ausdrücklich ersetzen'
node scripts/od.mjs company-app disable CLIENT_ID 'Eigene App vorübergehend deaktivieren'
node scripts/od.mjs company-app delete CLIENT_ID 'Eigene App endgültig stilllegen'
node scripts/od.mjs company-app list 1 deleted
node scripts/od.mjs company-app history CLIENT_ID
```

`REQUEST_UUID` ist die tatsächliche Client-ID und ein unveränderlicher Originalauftrag. Die UI erzeugt ihn einmal pro neuem Formular. Skripte können ihn mit `crypto.randomUUID()` erzeugen und vor dem Aufruf geschützt aufbewahren. Ein unveränderter wiederholter Create-Aufruf gibt dasselbe ursprüngliche Konto mit `created:false` und `clientSecret:null` zurück. Er erzeugt kein zweites Konto und gibt kein früheres Secret erneut aus. Geänderter Name/Zweck/Grund unter derselben UUID wird abgelehnt. Nach verlorenem Secret den aktuellen Stand prüfen und ausdrücklich rotieren. Niemals einen unbestätigten Create-Aufruf automatisch unter einer neuen UUID wiederholen.

SDK: `createCompanyAppClient(client)` aus `scripts/lib/company-apps.mjs` unterstützt `list`, `get`, `create`, `update`, `rotate`, `remove` und `history`. Verwaltungsaufrufe verwenden den menschlichen Token, keine App-Credentials. Die SDK liest vor Änderungen den tatsächlichen ETag und bestätigt Ziel, Namespace, Generation und Ergebnis. Fehlende Berechtigung, alte Version, unbestätigte Antwort oder Transportfehler enden mit Fehler/CLI-Code 1; es gibt keine automatische Schreibwiederholung. Create/Rotation geben das einmalige Secret bewusst auf stdout aus; diese Ausgabe direkt geschützt übernehmen.

## Generationen und Unternehmensbindung

Jede Bearbeitung, Zweckänderung, Aktivierung/Deaktivierung, Rotation und Löschung erhöht dieselbe kanonische Clientgeneration. Alte Secrets werden bei Rotation ersetzt; alte Tokens bleiben auch nach erneutem Aktivieren ungültig. Bisherige Automationsfreigaben werden nicht auf neue Generationen übertragen. Für weitere Arbeit sind neue App-Anmeldung und ausdrückliche Freigabe erforderlich.

Firmen-App-Tokens enthalten ihre tatsächliche `company_tenant`-Bindung. OAuth prüft diese gegen das ursprüngliche Register und den aktuellen kanonischen Tenant. Eine Pause oder neue Tenantgeneration sperrt vorhandene Maschinenzugänge. Wiederaktivierung des Unternehmens erneuert keine alte Appbindung: Ein aktueller Owner muss das Konto unter aktueller Hoheit ausdrücklich bearbeiten/bestätigen. Die konkrete Tenant-ID kann auch dabei nicht wechseln. Der private Tenant-Check ist ein eng gebundener Read-only-Issuer-Workload, keine menschliche Sitzung und keine pauschale Firmenberechtigung.

Identity 054 übernimmt die ursprüngliche Appbindung in die tatsächliche Automationsanmeldung. Ein fremder Firmeninhaber kann diese weder lesen noch für seinen eigenen Tenant genehmigen. Die SQL-Grenze verhindert auch direkte Umgehung der HTTP-Vorprüfung. Bestehende ungebundene externe App-Anmeldungen behalten ihre bisherige ausdrückliche Owner-Freigabe; es entsteht keine automatische Adoption.

## Daten, Fehler und Grenzen

Die aktuellen Clientzeilen erhalten `company_tenant`, den unveränderlichen `company_request` und den tatsächlichen `company_event_id`-FK. Das bestehende Client-Audit enthält öffentliche Metadaten-Snapshots, ursprüngliche Hoheit, Grund und physische Transaktion. Ein neuer Pending-Outbox-FK und SHA-256-Fingerprint belegen den originalen Auditdatensatz. Secret und Secret-Hash gehören nicht in Audit, öffentliche DTOs, Historie oder Logs. Normale Schreib-/Lösch-/Truncate- und Commit-Guards schützen Namespace und Belege; fehlender Receiver oder fehlende Outbox verhindert den erfolgreichen Commit.

Die ursprüngliche menschliche Hoheit wird vor, vor dem Commit und nach dem Commit gelesen. Die physische MFA-/Tokenfrist gilt zusätzlich an der SQL-Commit-Grenze. Wird die Hoheit nach einem tatsächlichen Commit entzogen, wird kein Secret ausgeliefert; das ursprüngliche Konto kann trotzdem bereits existieren. Originalauftrag/aktuellen Stand prüfen und gegebenenfalls unter neuer bestätigter Version rotieren. Getrennte Identity- und OAuth-Datenbanken erhalten keine erfundene gemeinsame Transaktion.

Listen/Historie sind mit 25 Zeilen und `hasMore` paginiert. Höchstens 100 nicht gelöschte Konten je Unternehmen; deaktivierte Konten zählen dazu, archivierte Belege bleiben erhalten. Gleichzeitige Create-/Versionsänderungen werden serialisiert. Die JSON-Verträge lehnen freie Scopes, andere Grants, eigene Tenant-/Ownerwerte und API-Keys ab. Diese Konten provisionieren keine Mailboxen, Microsoft-Graph-/Google-Apps, Herstellerlizenzen oder Geräte.

## Installation und Abnahme

Koordiniert **OAuth 001–015**, **Identity 001–055**, aktuelle OAuth-/Identity-/Gateway-/Web-Images und CLI ausrollen. Alte Instanzen dürfen den neuen Namespace nicht weiter über alte globale Leser verwalten. Nach Replay älterer Identity-Automations-/Gruppenmigrationen 051/052/053 und zuletzt **054** anwenden; OAuth 014 bewahrt bestehende ungebundene Clients und deren ursprüngliche Secrets/IDs. OAuth 015 ist zusätzlich für Credentialgebundene MFA-Herausforderungen erforderlich. Keine Anbieter-Credentials oder neue Runtime-Dependency sind erforderlich.

OAuth verwendet weiterhin den konfigurierten `OAUTH_IDENTITY_AUTHORITY_URL` als tatsächlichen Identity-Ursprung. Identity behält gültige Issuer-/JWKS-/Access-State-/Tenant-State-Einstellungen. Docker-Buildkontext bleibt die Repository-Wurzel; gemeinsame Company-App- und Tenant-Verträge werden mitkopiert. Die neue Outbox ist ein Pending-Beleg, keine hier abgenommene externe Zustellung oder Retention-Abnahme.

Der [OpenAPI-Vertrag](../api/openapi.yaml) ist **1.30.0**. [Testresultate](../testing/test-results.md#23-oktober-2026--eigene-firmen-app-konten) trennen echte PostgreSQL-/Browserprüfungen und Transport-Fixtures. Eigene allgemeine Firmenrollen/Delegation, zusätzliche App-Typen/Scopes, externe Provider und die übrigen BR-/WF-/Betriebsanforderungen bleiben Teil des [vollständigen Auftrags](../implementation-worklist.md).
