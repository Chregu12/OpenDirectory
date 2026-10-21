# App-Konten und Skript-Automationen

Stand: 22. Oktober 2026. App-Konten verwenden das bestehende persistente OAuth-Register. Es gibt keine zweite Kontodatenbank und keine pauschale Übernahme von Benutzerrollen.

## App-Konto anlegen

In **Identity Provider → OAuth2/OIDC → App-Konto erstellen** genügt zunächst ein Name. Das Konto verwendet `client_credentials`, braucht keine Redirect-URL und erhält keine voreingestellten Login- oder Administrations-Scopes. Das Secret wird einmal angezeigt. Danach das Konto separat aktivieren und das Secret im verwendeten Secret-Store hinterlegen.

Erstellung, Aktivierung, Rotation und Deaktivierung sind auch über die mitgelieferte CLI möglich. Node.js 20 oder neuer genügt; zusätzliche Pakete sind nicht erforderlich. Die Verwaltungsaktionen verwenden den ursprünglichen menschlichen Zugriffstoken mit den vorhandenen `applications.*`-Rechten. App-Tokens erben diese Verwaltungsrechte nicht.

```bash
export OPENDIRECTORY_ISSUER='https://identity.example.com'
export OPENDIRECTORY_API_URL='https://directory.example.com'
# OPENDIRECTORY_ADMIN_ACCESS_TOKEN über die autorisierte Sitzung/Secret-Verwaltung setzen.
node scripts/od.mjs app create 'Nächtlicher Abgleich'
node scripts/od.mjs app enable 'CLIENT_ID_AUS_DER_ANTWORT'
```

Die erste Antwort enthält das einmalige Secret und bestätigt ein deaktiviertes Konto. Die separate Aktivierung bestätigt die dann aktuelle Registerversion. Keine Secrets als Kommandozeilenargumente, im Repository oder in normalen Job-Logs ablegen. Erstellung und Rotation geben das Secret bewusst auf stdout aus; diese Ausgabe direkt geschützt übernehmen. Bei einem unklaren Ergebnis zuerst den Registerstand prüfen, weil der Server die Operation bereits ausgeführt haben kann.

## Skripte starten

Für einen Automationslauf die folgenden Werte über den Secret-Store des Runners setzen:

- `OPENDIRECTORY_ISSUER`: öffentlich erreichbare HTTPS-Origin des OAuth-Dienstes.
- `OPENDIRECTORY_API_URL`: HTTPS-Origin des API-Gateways; standardmässig der Issuer.
- `OPENDIRECTORY_CLIENT_ID` und `OPENDIRECTORY_CLIENT_SECRET`: eigenes App-Konto.
- `OPENDIRECTORY_SCOPES`: für diesen Lauf beantragte und bereits ausdrücklich freigegebene Scopes; standardmässig leer.

```bash
# Funktioniert ohne Benutzeranmeldung und prüft den eigenen aktiven App-Zugang.
node scripts/od.mjs check

# Struktur eines API-Aufrufs; der konkrete Endpoint muss App-Zugriff unterstützen.
node scripts/od.mjs request GET '/api/DEIN_ENDPOINT'
node scripts/od.mjs request POST '/api/DEIN_ENDPOINT' auftrag.json
node scripts/od.mjs request PUT '/api/DEIN_ENDPOINT' aenderung.json --if-match '"BEOBACHTETER_ETAG"'

# Verwaltungsaktionen verwenden weiterhin den menschlichen Verwaltungstoken.
node scripts/od.mjs app rotate 'CLIENT_ID'
node scripts/od.mjs app disable 'CLIENT_ID'
```

PowerShell kann dieselben Befehle aufrufen; die Variablen werden dort mit `$env:OPENDIRECTORY_CLIENT_ID = '…'` gesetzt. Externe Runner wie Cron, Windows Aufgabenplanung oder CI starten die CLI; ein neuer serverseitiger Scheduler oder beliebiger Skript-Executor ist damit nicht implementiert. Ein nicht erfolgreicher oder unbestätigter Aufruf endet mit Exit-Code 1. Zeitüberschreitungen und Schreibfehler werden nicht automatisch wiederholt. Erfolgreiche Antworten enthalten HTTP-Status, Daten und gegebenenfalls den beobachteten ETag.

Eigene Node-Skripte können den Client direkt importieren:

```js
import { createClient } from './scripts/lib/opendirectory-client.mjs';
const directory = createClient({
  issuer: process.env.OPENDIRECTORY_ISSUER,
  apiUrl: process.env.OPENDIRECTORY_API_URL || process.env.OPENDIRECTORY_ISSUER,
  clientId: process.env.OPENDIRECTORY_CLIENT_ID,
  clientSecret: process.env.OPENDIRECTORY_CLIENT_SECRET,
  scopes: process.env.OPENDIRECTORY_SCOPES || '',
});
const app = await directory.check();
console.log({ active: app.active, clientId: app.client_id, scope: app.scope });
```

## Berechtigungsgrenzen

Ein App-Konto ist nach der Aktivierung authentifizierbar, erhält aber nicht automatisch Zugriff auf Benutzer, Firmen, Postfächer oder administrative Aktionen. Beliebiger Scope-Text ist keine Freigabe durch den jeweiligen Empfänger. Die bestehenden maschinellen Zwecke `licenses.users.read` und `licenses.groups.derive` brauchen zusätzlich ihre explizite Tenant-/Ressourcenbindung; siehe [Tenant-Lizenzquellen](tenant-license-sources.md). Menschengebundene Workflows mit ursprünglichem Bearer und eigener MFA werden durch dieses CLI nicht auf Maschinenrechte umgestellt.

Rotation, Deaktivierung und Konfigurationsänderungen invalidieren die vorherige Clientgeneration. Tenant-/Quellenbindungen werden dabei nicht stillschweigend auf die neue Generation übertragen. Die CLI liest vor Registeränderungen den aktuellen ETag; Versionskonflikte bleiben Fehler.

## Gruppen und Lizenzpools

Die CLI unterstützt auch `group create`, `group member add|remove` und `license-group list|link|sync|unlink`. Die [Lizenzgruppen-Anleitung](company-license-groups.md) beschreibt den vollständigen Ablauf. Normale Gruppen erhalten durch eine ausdrückliche eigene Pool-Verknüpfung eine Lizenzfunktion; die Mitgliedsbefehle gleichen diese Verknüpfungen als tatsächlicher Company-Owner ab. Diese Schreibaktionen verwenden `OPENDIRECTORY_ADMIN_ACCESS_TOKEN` mit aktuellen eigenen Rechten und MFA, keine App-Tokens. Exit-Code 2 meldet blockierte Benutzer; bereits bestätigte Mitgliederänderungen werden bei einem späteren Vergabefehler nicht zurückgerollt.

## E-Mail

Eine OpenDirectory-Appregistrierung ist keine Registrierung oder Einwilligung bei Microsoft, Google oder einem Mailserver. Der Mailanbieter für diesen Arbeitsauftrag ist noch nicht ausgewählt; ein neuer Mail-Connector oder Postfach-Provisionierungsablauf wurde deshalb nicht behauptet oder aktiviert.

Bei Microsoft 365 wäre Versand ein eigener Graph-Adapter: [sendMail](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0) verwendet unter anderem die Anwendungsberechtigung `Mail.Send`. Ein angenommener Versandauftrag ist kein Zustellnachweis. App-Zugriff auf erlaubte Postfächer lässt sich mit [Exchange Application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac) begrenzen. Postfachbereitstellung, Aliase und Lizenzierung müssen davon getrennt mit dem ausgewählten Anbieter geplant werden. Es wurden keine externen Konten erstellt und keine E-Mails versendet.

## Prüfung

`npm run test:automation-client` führt die Node-Regressionen für App-Konten und Lizenzgruppen aus; sie sind im Root-Runner und in CI eingebunden. Der OAuth-Service testet die tatsächlich ausgelieferte CLI als separaten Prozess gegen den echten lokalen HTTP-Server: Erstellung, separate Aktivierung, Introspection, fehlende Administrationsrechte, Rotation und Deaktivierung. Die Oberfläche testet den direkten App-Konto-Einstieg und leere Standardrechte.
