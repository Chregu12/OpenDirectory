# Organisationsprofil: implementierter Business-Slice

Stand: 19. Oktober 2026. Unter `/organization` können berechtigte menschliche Administratoren, tatsächliche eigene [Company-Owner](company-activation.md) und begrenzt delegierte Personen das Profil ihres eigenen Unternehmens lesen und versioniert ändern. Die eigene Aktivierung übernimmt den ursprünglichen Registrierungsentwurf bereits als Initialprofil. Das ist ein persistenter Teil von FR-001.04, nicht die vollständige BR-001-Organisation.

## Benutzerweg

1. Mit einer kanonisch gebundenen Identität in einem aktivierten eigenen Tenant anmelden.
2. **Organisation** öffnen. Ohne bisheriges Profil wird ausdrücklich noch kein gespeicherter Datensatz behauptet.
3. Falls erforderlich über den angebotenen Link die vorhandenen **MFA-Einstellungen** öffnen, TOTP regulär einrichten und erneut mit MFA anmelden. Eine zusätzliche fachfremde Administratorrolle ist dafür nicht erforderlich.
4. Firmenname, Adresse, Land, Zeitzone, Standardsprache und Kontaktdaten erfassen; optionale Rechts-/Registerangaben ergänzen.
5. Änderung begründen und speichern. Erst eine bestätigte Receiver-Antwort zeigt Erfolg und die neue Version.
6. Neu laden, um den tatsächlichen gespeicherten Stand abzurufen. Bei Versionskonflikt oder verlorener Bestätigung nicht blind erneut absenden.

Der echte Browser-Test führt diesen Weg mit OIDC, wirklicher TOTP-Einrichtung, PostgreSQL und der Next-Oberfläche aus. Er lädt gespeicherte Daten erneut und beweist, dass ein späterer konkurrierender Stand nicht überschrieben wird.

## Daten und Autorisierung

- Pro Tenant gibt es höchstens ein Profil mit eigener UUID. Bestehende Tenants erhalten keine erfundenen Profile durch einen Backfill; vor dem ersten Save bleibt `organization` null.
- Vierzehn explizite Felder: Name, Rechtsform, Registrierungsnummer, UID/Steuer-ID, zwei Adresszeilen, Postleitzahl, Ort, zweistelliges Land, Zeitzone, Standardsprache (`de`/`en`), Kontakt-E-Mail, Telefon und optionale HTTPS-Website. Die Daten liegen als relationale Textspalten vor, nicht in einem Browser-Array.
- Land, Register- und Steuerangaben sind eingegebene Profildaten, keine Bestätigung durch ein Register. Eine Website wird nicht vom Server abgerufen. Unternehmens-/Domainverifizierung ist ausdrücklich nicht unterstützt.
- Neben dem tatsächlichen kanonischen `admin`-Rollenpfad ist jetzt eine [eng begrenzte eigene Profildelegation](organization-delegations.md) möglich: normale Benutzer können ausschliesslich das eigene Firmenprofil lesen/bearbeiten, ohne globale Adminrolle. Lizenz-, Benutzer- oder Gruppenadministratoren bekommen diese Rechte nicht nebenbei. Allgemeine delegierte Organisationsrollen bleiben offen.
- Der Tenant wird aus ursprünglichem Actor, Subject-Link und kanonischer Eigentümerschaft abgeleitet. Es gibt weder frei wählbare Tenant-Parameter noch einen organisationsübergreifenden Operator-Endpunkt.
- Speichern und delegiertes Lesen erfordern verifizierte MFA mit maximal 300 Sekunden Alter, zusätzlich zur eventuell strengeren gehaltenen Rollen-Assurance. Der ursprüngliche Bearer wird vor und nach DML geprüft; sein ursprüngliches Token-/MFA-Ende und bei Delegation auch das tatsächliche Grant-Ende werden bis zum SQL-Commit eingehalten.
- Eine Profiländerung ändert weder Tenant-Aktivierung/Generation noch Benutzer-, Rollen- oder Lizenzberechtigungen. Der Firmenname ersetzt nicht heimlich die kanonische Tenant-Identität.

Die gemeinsame Live-Rollenquelle bleibt das bestehende Schema 6. Die bekannten [globalen Rollen-/Policy-Grenzen](identity-governance.md#fifty-second-increment-in-progress-tenant-bound-authority-lifecycle) sind nicht durch dieses Formular geschlossen. Auch die Abhängigkeit der Receiver vom tatsächlichen Datenbank-Owner ist keine fertiggestellte Least-Privilege-Datenbankrollenarchitektur. Keine Freigabe für allgemeines Shared-Customer-SaaS-Hosting folgt daraus.

## API und Konflikte

| Methode | Tatsächlich erreichbarer Pfad | Bedeutung |
| --- | --- | --- |
| GET | `/api/identity/organization` | Eigene Metadaten und optional vorhandenes Profil, Actor-/Tenant-Bindung, ETag, aktuelle Schreib-/MFA-Fähigkeit |
| PUT | `/api/identity/organization` | Vollständiges Profil plus Begründung unter exakt passendem `If-Match` erstellen/ersetzen |

Der Zugriffs-Metadatenreceiver meldet `organizationProfileProtocol: 1`. Antworten sind `no-store`; Body und echter ETag-Header müssen übereinstimmen. Die UI prüft vor dem Write erneut Actor, Tenant, Generation, Version und Schreibfähigkeit. Alte Receiver, geänderte Sessions, fremde Antworten oder plausible, aber nicht bestätigte Write-Antworten werden nicht übernommen.

`If-Match` enthält Tenant-UUID, Tenant-Generation/-Version und die eigene Profilversion, vor der ersten Anlage Version 0. Bigints bleiben Strings. Fehlende Vorbedingungen/MFA ergeben 428, Versionskonflikte 412, unzulässige Felder/Query-Selektoren 400, fehlende Berechtigung 403 und fehlende Receiver-/Persistenzbelege 503. Eine ungültige ursprüngliche Sitzung ergibt 401. Es gibt keinen Wildcard-Override und keinen automatischen Retry; ein verlorener Write-Ack erfordert einen erneuten Read. Das ist kein allgemeiner Idempotency-Key-/Workflow-Replay-Dienst.

Der [OpenAPI-3.1-Vertrag](../api/openapi.yaml) wird aus dem gemeinsamen Profilvertrag generiert:

```sh
node services/core/identity-service/scripts/organization-openapi.js > docs/api/openapi.yaml
```

Die Datei verwendet JSON-Syntax, die auch ein gültiges YAML-Dokument ist. Unit-Tests vergleichen sie mit dem Generator. Sie dokumentiert nur diese implementierte API, nicht sämtliche geplanten Plattform-Endpunkte.

## Transaktion und Historie

Migration `037_organization_profiles.sql` legt Profil, unveränderbare Before-/After-Ereignisse und verpflichtende Pending-Outbox an. Der Profileintrag verweist auf sein aktuelles Ereignis über einen deferred FK. Lesen und spätere Updates verlangen auch den tatsächlichen aktuellen Ereignis-/Outbox-Beleg; fehlende Historie wird nicht mit einem späteren Save neu erfunden.

Der Original-Actor, ein gehashter Token-Identifier, Begründung, komplette Before-/After-Zeilen und ursprüngliches Assurance-Ende werden gespeichert. Es wird kein Bearer-Token protokolliert. Die SQL-Admission bindet exakten Owner, Inhalt und Versionsschritt. Deferred Prüfung verlangt den tatsächlichen finalen Authority-Checkpoint derselben Transaktion mit übereinstimmendem Actor/Token und passendem Deadline-Fence. Spätere fremde kanonische Effekte/Truncation oder geleerte Scopes rollen zurück. Der Checkpoint ist keine neue nachträgliche Autorisierungsquelle.

Dies ist lokale, triggergeschützte Audit-Historie, keine manipulationssichere Off-host-Compliance-Ablage. Outbox-Status ist **pending**, nicht zugestellt. Ein administrativer Historienviewer, Retention/Export und zuverlässige Event-Zustellung bleiben eigenständige Arbeit.

## Nachgewiesen und offen

Die [Abnahme](../testing/test-results.md#business-slice-2-organisationsprofil) umfasst echte konkurrierende Row-Lock-Waits, genau einen erfolgreichen alten Versionsstand, zwei echte Tenants, bekannte fremde ETags, Fremdnutzer-Locks, begrenzte/angenommene SQL-Rollen, Rollen-/Workload-Denial, ursprünglichen Bearer-Entzug, reale MFA-Ablaufzeit, fehlende/umgeschriebene Belege, UTC und Generationen oberhalb der JS-Zahlengrenze.

Nicht enthalten: Selbstregistrierung/Erstadministrator, Logos/Uploads, Legal Entities, Unternehmens-/Domainverifizierung, die Zustände Draft/Pending Verification/Active/Suspended/Archived als eigener Business-Workflow, vollständige OU-Governance, allgemeine Custom Roles, englische UI-Übersetzung, Geräteverwaltung, Herstellerpublikation oder ein produktiver Rollout. Die Speichersprache ist wählbar, eine vollständige zweisprachige Plattform ist damit nicht implementiert.
