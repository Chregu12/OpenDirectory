# Firmenaktivierung und erste Owner-Anmeldung

Stand: 19. Oktober 2026. Dieser Teilprozess verbindet die [Registrierung](company-registration.md), [unabhängige interne Prüfung](company-registration-reviews.md), tatsächliche technische Aktivierung, Pflicht-MFA und die erste Anmeldung am eigenen Firmenprofil. Er benutzt den vorhandenen Credential-Provider und OAuth-/Identity-Stack, keine zweite Passwortdatenbank und keine globale Administratorrolle.

**Begrenzter Company-Owner:** Der erstmalige Owner kann das eigene Firmenprofil lesen/bearbeiten und dessen zeitlich begrenzte Profildelegationen verwalten. Der anschliessende [Verzeichnis-Slice](company-directory.md) ergänzt eigene Personen, Gruppen und OU-Lesen/-Erstellen. Es gibt weiterhin keine globale Rolle, Rollen-, Geräte-, Lizenz-, Plattformprüfer- oder beliebigen Anwendungsrechte. Das ist noch keine vollständige Company-Administration oder komplette WF-001-Abnahme.

## Einrichtung

Identity benötigt alle Migrationen bis `041_company_activations.sql`, der Issuer und das Frontend den koordinierten aktuellen Code. Nur beim OAuth-Provider konfigurieren:

```dotenv
COMPANY_REGISTRATION_ENABLED=true
COMPANY_ACTIVATION_ENABLED=true
COMPANY_CONSOLE_CLIENT_ID=web-app
```

Beide Mutations-Flags bleiben in Beispiel-/Compose-Konfiguration standardmässig `false`. Die eigene echte `.env` wurde nicht geändert. Der Console-Client muss bereits existieren, aktiviert und vertraulich sein, einen geschützten Scope besitzen und Authorization Code unterstützen. Die ID muss zum tatsächlichen Browser-BFF-Client passen. Client-ID, Scopes oder Tenant-IDs werden nicht aus einer öffentlichen Aktivierungsanfrage übernommen. Fehlende Konfiguration bzw. fehlende externe Credential-/MFA-Voraussetzungen sind keine erfolgreiche Aktivierung; als `External Dependency` behandeln, bis sie tatsächlich eingerichtet sind.

## Tatsächlicher Benutzerweg

1. Unternehmen mit einem bereits vorhandenen, noch nicht anderweitig kanonisch gebundenen Provider-Konto unter `/register` anmelden; Registrierungs-ID aufbewahren.
2. Ein ausdrücklich bestellter unabhängiger Plattformprüfer gibt den echten Originalantrag frei. Ablehnung oder ein unveränderter ungeprüfter Antrag erlauben keine Aktivierung.
3. Antragsteller fragt den eigenen Status mit erneut bestätigten Zugangsdaten ab. Der Zustand lautet `pending-activation`.
4. Zugangsdaten erneut eingeben, die Aktivierung ausdrücklich bestätigen und **Freigegebene Firma aktivieren** wählen. Es wird nur der aktuelle eigene bestätigte Request-Key akzeptiert.
5. Der tatsächliche Commit aktiviert Tenant/Kandidat, übernimmt den ursprünglichen Firmenentwurf als Organisationsprofil Version 1 und speichert den dauerhaften eigenen Owner-Nachweis mit Audit/Pending-Outbox. Keine Session oder Zugriffstokens werden zurückgegeben.
6. **Pflicht-MFA einrichten** öffnet den vorhandenen echten Ersteinrichtungsprozess. Der aktivierte Owner muss MFA für jeden Client und jeden angefragten Scope verwenden, nicht nur für einen ausgewählten privilegierten Token.
7. Danach normal mit MFA anmelden und `/organization` öffnen. Auch ein frischer Browser ohne `od_onboarded`-Flag erhält nach serverbestätigtem Owner-Nachweis die echte Firmenoberfläche statt des nicht passenden Legacy-System-Setup-Wizards. Firmendaten sind bereits vorhanden und können tatsächlich geändert werden.

Bei verlorenen Antworten den Status ausdrücklich neu abfragen, nicht automatisch erneut senden. Aktivierung ist unter demselben eigenen Request und derselben Console idempotent. Eine spätere Tenant-Pause oder Benutzersperrung wird als `suspended` ausgegeben; gespeicherte frühere Belege werden nicht als aktuelle Zugangserlaubnis ausgegeben. Passwörter/MFA-Codes bleiben Eingaben an den bestehenden Anmeldedienst und werden nicht in den Identity-Tabellen oder im Browser-Speicher abgelegt.

## Berechtigungs- und Integrationsgrenzen

- Die Aktivierungsbefugnis besteht aus tatsächlicher unabhängiger Freigabe und erneut credentialbestätigtem ursprünglichem Antragsteller. Das Plattform-Prüfrecht wurde nicht um eine implizite allgemeine Aktivierungs-/Tenant-Verwaltungsbefugnis erweitert.
- Der Issuer sendet einen separaten, auf `activate`, Pfad, Inhalt, Credential-Subject und höchstens 30 Sekunden gebundenen Workload-Proof. Der private Receiver nimmt keinen normalen Human-/API-Bearer als Ersatz. Die ursprüngliche Frist gilt bis zum physischen Commit; es wird kein erfundener menschlicher Rollen-Checkpoint erzeugt.
- `identity_company_activations` ist gleichzeitig der unveränderliche ursprüngliche Own-Company-Owner-Nachweis. Es wird kein neues Wort in den bestehenden 62-Rollen-/Schema-6-Vertrag eingeschleust. Kanonischer MFA-Zwang und Rollen-Fingerprint berücksichtigen den tatsächlichen Owner; Profile-Rechte kommen bei jeder Anfrage aus der serverseitigen eigenen Ressource, nie aus behaupteten JWT-Permissions.
- Die Console benötigt keinen erfundenen permanenten allgemeinen App-Grant oder eine alle acht Stunden erneuerte Bootstrap-Zuweisung. Nur die konfigurierte Console darf ihren begrenzten Owner-Zugang aus dem neuen privaten `/internal/identity/company-console` ableiten. Dessen Issuer-Workload hat eigenes Purpose/Scope und exakte Client-/User-Bindung. Login, Refresh und Tokenprüfung lesen den aktuellen Source. Andere Clients bleiben zuweisungspflichtig; bestehende explizite App-Zuweisungen behalten ihre bisherigen Regeln.
- Ein Owner hat dadurch keinen Zugriff auf fremde Firmen/Personenlisten, Lizenzvergabe oder Review-Queues. Eigene Verzeichnisrechte sind im [nachfolgenden Slice](company-directory.md) begrenzt beschrieben. Deaktivierung/Pause und fehlende aktuelle Receiving-/Quellenbelege verhindern weitere Autorisierung. Generische Owner-Übertragung, zusätzliche Owner, rollenbasierte OU-Rechte und deren kontrollierter Entzug sind noch nicht implementiert.

## Datenmodell und Commit

Migration 041 ergänzt drei tenantgebundene Tabellen: `identity_company_activations`, `identity_company_activation_events` und `identity_company_activation_outbox`. Root-FKs binden Originalregistrierung, tatsächlichen Freigabeentscheid, Tenant, User, initiales Profil und Profilevent. Das Business-Event trägt eigene Event-ID, `company.activated`, Version 1, Tenant-ID, Correlation-ID des Registrierungs-Requests, Actor, Vorher-/Nachher-Snapshots und Zeitpunkt. Pending-Outbox bedeutet nicht zugestellt.

Die ursprünglichen Pending- und Review-Belege werden nicht überschrieben. Während des Aktivierungscommits sind nur exakt eigene Tenant-/User-Änderungen, das ursprüngliche Profil und tatsächlicher Audit-Fanout zugelassen. Fremde Ressourcen, zusätzliche Rollen und zusätzliche Authority-Checkpoints dürfen nicht mitlaufen. Originalfrist, tatsächliche aktivierte Zustände, aktuelle kanonische Audit-/Outbox-Belege, vollständiger neuer Snapshot und neue Aktivierungsbelege werden bis Commit geprüft. Gleichzeitige eigene Aktivierungsversuche warten auf den tatsächlichen Admission-Lock und erzeugen nur einen Owner.

Für spätere Status-/Source-Prüfungen werden die ursprünglichen unveränderlichen Transitionen und tatsächlich retained Audit-/Outbox-Zeilen geprüft, nicht ein Gleichstand aller aktuellen Unternehmensdaten mit dem Initialsnapshot verlangt. Deshalb invalidiert eine berechtigte spätere Profiländerung nicht die ursprüngliche Aktivierung. Aktuelle Zugangsberechtigung prüft zusätzlich tatsächliche Tenant-/User-Aktivität, Subject-/Home-Bindung und Receiving-Guards. Alle SQL-Funktionen bleiben private, gepinnte tatsächliche Owner-Receivers; dies ist kein fertiggestelltes Least-Privilege-Datenbankrollenmodell oder Off-host-Archiv.

## API

`POST /api/company-registration/activate` und `POST /oauth/company-registration/activate` erwarten exakt `registrationId`, `username`, `password`, `mfaCode`, `confirm:true`. Die native BFF-Route ist statisch, verlangt gleichen Origin, JSON und den vorhandenen Intent-Header und leitet keine Browser-Bearer/Cookies als Credential-Ersatz weiter. Der private Identity-Pfad erwartet dagegen nur `registrationId`, `subject` und den vom Issuer konfigurierten `consoleClientId`, gebunden durch den Workload-Proof.

Schema 1/2 bleiben für ungeprüfte/entschiedene Pending-Anträge kompatibel. Schema 3 gibt `active` oder `suspended`, tatsächliche Aktivitätsflags, `reviewedAt`, `activatedAt`, `consoleClientId`, `profileSaved:true` und `mfaRequired:true` zurück; nie einen Access-Token. `administratorEnabled` ist der aktuell wirksame kanonische Owner-Status inklusive Tenant-/Subject-Bindung, nicht allein das physische `users.enabled`-Bit. Der versionierte Capability-Vertrag kündigt Aktivierung nur bei tatsächlich gesetztem Betreiber-Flag und konfigurierter Console-ID an. [Generierter OpenAPI-3.1-Vertrag](../api/openapi.yaml).

## Offen

[Abnahme dieses Teilprozesses](../testing/test-results.md#business-slice-6-firmenaktivierung-und-owner-erstanmeldung): 2'862 Fälle in sieben abgegrenzten Gates, einschliesslich tatsächlichem frischem Chrome ohne Legacy-Onboarding-Flag und signiertem Produktionsmodus-Gateway. Das ist keine Abnahme des vollständigen WF-001 oder der Plattform.

Account-Self-Signup/föderiertes Erst-Onboarding, externe Firmen-/Domainverifizierung, vollständige eigene Benutzer-/Gruppen-/OU-/Rollenverwaltung, Mehrfach-Owner/Ownership-Transfer, zusammenhängende JML-/Geräte-/Blueprint-/Lizenzprozesse und übrige Business-Domains bleiben erforderlich. Ebenso fehlen vollständige Workflow-/Delivery-/Retry-/DLQ-, Retention-/Datenschutz-Lösch-, Last-/Backup-/Restore-/WCAG- und Produktionsabnahmen. Die 17 bestehenden TypeScript-Diagnosen sind nicht behoben. Keine externen Produktivschreiboperationen, kein Image-Deployment, Commit oder Push wurden ausgeführt.
