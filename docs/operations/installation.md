# OpenDirectory lokal verwenden und prüfen

Diese Anleitung ergänzt den vorhandenen Stack für die nachgewiesenen eigenen Company-Slices und den lokalen Frontend-Build. Sie ist keine vollständige produktive SaaS-, Apple-MDM- oder Backup/Restore-Betriebsfreigabe.

## Voraussetzungen

- Vorhandene Identity-/OIDC-/Frontend-Konfiguration und PostgreSQL; keine zusätzliche Datenbank oder neue Server-Dependency wird eingeführt.
- Ein kanonisch gebundener tatsächlicher eigener Company-Owner oder berechtigter menschlicher Administrator in einem enabled eigenen Tenant. Der vorhandene Registrierungs-/Prüfungs-/Aktivierungsweg setzt noch ein echtes Provider-Konto voraus; er ist kein Account-Signup oder externer Unternehmensnachweis.
- Identity-Service mit Migrationen 001–044 und aktuelles Frontend. Der normale Migrationsrunner lädt Profile, Delegation, Registrierung, interne Prüfung, eigene Aktivierung, `042_directory_ou_mutations.sql`, `043_ou_memberships.sql` und die tenantgebundenen Lizenzquellen; bestehende Tenant-/User-Daten werden nicht automatisch als neue Firmenprofile, Grants, Registrierungen, Owner oder Plattformprüfer kopiert. Bestehende OUs erhalten eine Anfangsrevision, keine erfundene rückwirkende Audit-Historie oder aus Department-Text abgeleitete Mitgliedschaft.
- Frische verifizierte MFA zum Speichern. Ohne Faktor führt der Link in der Organisationsseite zum vorhandenen authentifizierten TOTP-Setup; danach regulär mit MFA anmelden.

Öffne `/organization` im laufenden, korrekt angebundenen Portal. Erstelle/ändere das eigene Profil und lade neu. Es gibt keine frei wählbare Tenant-ID, keine versteckte Firmenaktivierung und keine externe Register- oder Apple-Veröffentlichung.

Mit vorhandener eigener Berechtigung kann darunter eine [begrenzte Profilberechtigung](../features/organization-delegations.md) an einen anderen eigenen Benutzer vergeben werden. Dieser meldet sich nach der tatsächlichen Autorisierungsinvalidierung erneut an und braucht verifizierte MFA auch zum Lesen. Es werden keine globale Adminrolle oder zusätzliche Dependency benötigt. Vollständige Company-Rollen, eigenes Account-Signup und Mitarbeitenden-Credentials bleiben offen.

## Öffentliche Vormerkung zur Prüfung

Die [Pending-Registrierung](../features/company-registration.md) braucht den vorhandenen funktionierenden Credential-Provider, Issuer-Signing-/JWKS-Vertrag, `OAUTH_IDENTITY_AUTHORITY_URL` und korrekt konfigurierte native BrowserAuth-BFF-Verbindung mit HTTPS bzw. explizit erlaubtem lokalem Loopback. Ein geeignetes vorhandenes Provider-Konto ist Voraussetzung; kein neues Credential-Konto oder Drittanbieter-Tenant wird erzeugt.

Der neue Flag `COMPANY_REGISTRATION_ENABLED` bleibt standardmässig `false`. Zum bewussten Testen nur beim OAuth-Provider `true` konfigurieren. Beide Compose-Varianten reichen ihn an den Provider weiter; es gibt keine neue Datenbank, neue Dependency oder neue Secret-Art. Keine echte `.env` wurde hier aktiviert und kein produktiver Container neu gebaut/gestartet.

Öffne `/register`, erfasse das Unternehmen und bewahre die Registrierungs-ID auf. Der tatsächliche Erfolg lautet nur **zur Prüfung vorgemerkt**. Tenant und Kandidat sind gesperrt, keine Owner-/Console-/Adminrechte oder erste Anmeldung werden dadurch freigegeben. Passwort/MFA-Code müssen für jede eigene spätere Statusabfrage erneut eingegeben werden. Ein verlorener Ack wird über **Bestehenden Status prüfen**, nicht durch einen automatischen zweiten Create-Auftrag, abgeglichen.

Für die [interne Firmenprüfung](../features/company-registration-reviews.md) muss der Betreiber einen vorhandenen kanonischen Plattformmitarbeiter separat über `company-review-operator.js` bestellen. Der Befehl benötigt eine explizite `IDENTITY_OPERATOR_DATABASE_URL` mit tatsächlichem Owner-Login, Issuer, Benutzer-UUID, erwarteter Version und Begründung. Keine automatische Admin-Übernahme oder zusätzliche Laufzeit-Environment-Allowlist. Danach neu mit frischer MFA anmelden und `/registration-reviews` verwenden. Freigabe und Ablehnung werden tatsächlich gespeichert; auch nach Freigabe bleiben Tenant und Kandidat deaktiviert. Ohne zusätzliche technische Aktivierung ist kein vollständiger Erstadministrator-Login möglich.

Die [anschliessende eigene Aktivierung](../features/company-activation.md) benötigt beim Issuer zusätzlich `COMPANY_ACTIVATION_ENABLED=true` und `COMPANY_CONSOLE_CLIENT_ID` passend zum tatsächlich vorhandenen aktivierten vertraulichen geschützten Browser-Client (gewöhnlich `web-app`). Die Aktivierung bleibt standardmässig ausgeschaltet. Nur der ursprüngliche erneut credentialbestätigte Antragsteller darf nach unabhängiger Freigabe aktivieren. Danach Pflicht-MFA wirklich einrichten und mit MFA anmelden. Der erste Owner erhält ausschliesslich eigene Firmenprofil-/Profildelegationsrechte, keinen globalen Admin oder bereits vollständige Company-Administration. Fehlende Clients, Credentials oder Keyfiles sind Voraussetzungen, keine vorgetäuschten erfolgreichen Vorgänge.

Prüfung, Freigabe und eigene Aktivierung sind getrennte bewusst konfigurierte Schritte, keine Wirkung der blossen Vormerkung. Den Kandidaten nicht durch eine pauschale globale `admin`-Rolle als angeblich fertiges Onboarding freischalten. Neues Credential-Account-Signup, externe Unternehmensverifizierung und vollständige Company-Administration bleiben offen; die tatsächlich vorhandenen eigenen Fähigkeiten stehen im [Implementierungsstand](../implementation-status.md).

## Lokale Prüfungen

Vom Repository-Root:

```sh
npm test --prefix services/core/identity-service -- --runInBand
TMPDIR=/tmp npm run test:groups:integration --prefix services/core/identity-service
npm test --prefix frontend/web-app -- --runInBand
npm run test:browser-auth --prefix frontend/web-app
TMPDIR=/tmp npm run test:gateway:production --prefix services/core/oauth-provider
node services/core/identity-service/scripts/organization-openapi.js
```

Die PostgreSQL-Runner erzeugen ohne explizite Test-DB-URL eigene Wegwerfcluster und räumen sie auf. Eine gesetzte Test-DB-URL muss ausschliesslich auf eine bewusst freigegebene Testdatenbank zeigen. Niemals Produktiv-Zugangsdaten für diese Tests verwenden. Die separaten realen Browser-Tests verwenden tatsächlich OIDC/Next/Chrome und sind kein Mock-Provider-Nachweis für Apple.

## Container-Build-Kontext

Der [eigene Verzeichnis-Slice](../features/company-directory.md) verwendet die vorhandene 041-Grundlage. Der [kanonische OU-Slice](../features/organization-units.md) benötigt Migration 042, der [Membership-Slice](../features/organization-memberships.md) Migration 043 und koordinierten aktuellen Identity-/Web-Code, aber keine neuen Secrets. Nach normaler Pflicht-MFA-Anmeldung kann der tatsächliche Owner eigene Einheiten versioniert bearbeiten/verschieben, Mitglieder ausdrücklich mehrfach zuordnen/entfernen und nur abhängigkeitenfreie Blätter bestätigt löschen. Keine globalen Bootstrap-Rollen vergeben. Alte OU-Clients müssen ETags übernehmen; laufende alte Proof-Transaktionen dürfen beim Upgrade abgewiesen werden. Die neue Tabelle startet leer; kein Department-Backfill. Aktive Mitgliedschaften blockieren auch Benutzerlöschung mit `409`; zuerst kontrolliert unlinken. Historische OU-Events bleiben erhalten. Mitarbeitenden-Zugangsdaten, Rollen-/Blueprint-/Lizenzvererbung werden dadurch nicht provisioniert.

## Reales Geräteinventar

Der [Device-Slice](../features/device-inventory.md) benötigt zusätzlich Migrationen **001–005 in der eigenen Device-PostgreSQL-Datenbank**, aktuelle Identity-/Device-/Gateway-/Web-Images und die originale Pflicht-MFA-Anmeldung. Der normale Device-Start ist `npm start` bzw. `node src/inventoryServer.js`, nicht der bisherige nicht startfähige/simulierende `src/index.js`. Das ist eine koordinierte brechende Receiver-/JSON-Vertragsänderung, kein paralleler Demo-Modus.

Bestehende `DATABASE_URL` oder `DB_HOST`, `DB_PORT`, `DB_NAME=devices`, `DB_USER`, `DB_PASSWORD` verwenden. Weiterhin `OIDC_ISSUER`, `JWKS_URI`, `OIDC_ACCESS_STATE_URL` und `IDENTITY_SERVICE_URL` auf die tatsächlichen internen Authorities konfigurieren. Bestehende gemeinsame Contracts werden mit dem Repository-Root als Docker-Buildkontext kopiert. Beide Compose-Varianten enthalten die entsprechenden Werte; sie wurden nur mit ausdrücklich wegwerfbaren Test-Umgebungswerten und `config --quiet` geprüft, nicht gestartet.

Keine neuen Secrets: der neue Runtime braucht weder Mongo-/Redis-/RabbitMQ-Credentials noch `DEVICE_ENROLLMENT_TOKEN` oder `APPSTORE_AGENT_TOKEN`. Vorhandene historische Driver-/Hardware-Volumes werden nicht gelöscht. Node-Abhängigkeiten wurden aus dem bestehenden Device-Lockfile mit `npm ci --ignore-scripts --no-audit --no-fund` installiert, keine Dependency hinzugefügt oder aktualisiert.

Eine fehlgeschlagene DB-Verbindung/Migration verhindert erfolgreichen Start. `GET /health` prüft explizit den lokalen Storage, nicht externe MDM-Verfügbarkeit. Unter `/devices` eigene Inventargeräte erfassen und Mitarbeitende ausdrücklich zuweisen. Geräte bleiben unenrolled/Compliance unbekannt; nicht implementierte Provider-/Remote-Endpunkte antworten `501`. Unowned historische Geräte werden nicht sichtbar gemacht oder aus heuristischen Benutzerfeldern adoptiert. Niemals alte ungescopte Runtime-Instanzen parallel auf die gemeinsame Datenbank freigeben. Image-Build/Deployment, Legacy-Adoption, vollständiger Lifecycle, JML-Reconciliation, Backup/Restore und Retention bleiben offen.

Frontend und Identity benötigen denselben kleinen `packages/organization-profile-contract`-Ordner. Beide Compose-Dateien bauen das Frontend deshalb vom **Repository-Root** mit `frontend/web-app/Dockerfile`; der Identity-Dockerfile kopiert den Vertrag ebenfalls explizit. Die Root-`.dockerignore` schliesst unter anderem Node-Module, lokale Secrets, Schlüssel und Umgebungsdateien aus. Ein isolierter Build-Kontext nur auf `frontend/web-app` reicht für den gemeinsamen Vertrag nicht.

Beispiel für einen gesondert abzunehmenden Container-Build:

```sh
docker build -f frontend/web-app/Dockerfile .
```

Die Compose-Konfiguration wurde ohne reale Secrets mit `config --quiet` geprüft; es wurde kein Container gestartet oder Image veröffentlicht. Vollständige Deployment-, Secret-Rotation-, Monitoring-, Backup-/Restore- und Rollout-Abnahme bleibt offen. Aktuelle Grenzen und Testresultate: [Organisationsprofil](../features/organization-profile.md), [Testnachweise](../testing/test-results.md).

## Frontend-Typprüfung und Produktionsbuild

Mit den vorhandenen installierten Abhängigkeiten im Repository:

```sh
cd frontend/web-app
npm run type-check -- --incremental false
NEXT_TELEMETRY_DISABLED=1 npm run build
npm start
```

Die 17 zuvor bekannten eigenen TypeScript-Diagnosen sind behoben. `ignoreBuildErrors` ist entfernt: ein fehlerhafter TypeScript-Stand darf nicht mehr als erfolgreicher Produktionsbuild durchgehen. Der reale lokale Build mit Next 14.2.35 besteht und prüft die Typen; die bestehende separate ESLint-Überspringung ist weiterhin offen. Der Build setzt keine produktiven Credentials voraus. Zum tatsächlichen Anmelden braucht `next start` dagegen die korrekt angebundene BrowserAuth-BFF-Konfiguration samt ursprünglichem Issuer/Client, Secrets und HTTPS-Origin; ein gebautes Frontend alleine ist kein funktionierender Identity-Provider.

Die Browser-Regressionsfixture führt nun selbst `next build` und danach `next start` mit `NODE_ENV=production` aus, nicht nur `next dev`. Sie verwendet echte isolierte lokale Datenbanken/Issuer/Chrome und ausschliesslich explizit erlaubtes HTTP-Loopback. Das ersetzt weder öffentliche TLS-/Cookie-/Reverse-Proxy-Abnahme noch ein Container- oder Produktionsdeployment.

Der lokale Build meldet noch nicht fatale Next-SWC-/Workspace-Lockfile- und veraltete Browserslist-Daten-Warnungen. Die installierte Next-Version deklariert SWC 14.2.33; die optionale Darwin-x64-Variante liegt im vorhandenen Root-Lockfile hoisted statt neben dem verschachtelten Next-Eintrag. Der automatische Next-14-Patchversuch scheitert, der echte Build endet dennoch mit Exit 0. Es wurden keine Abhängigkeiten nachinstalliert, Lockdateien umgeschrieben oder Patch-Warnungen per Ignore-Flag ausgeblendet. Ein reproduzierbarer Clean-Install und der Linux-Image-Build bleiben gesondert abzunehmen.

Alte Setup-Einstiege für Templates, kombiniertes Security-, Backup- und Monitoring-Setup behaupten keine erfolgreiche Konfiguration mehr. Sie zeigen die fehlende unterstützte Funktion ausdrücklich an; vorhandene Statusleser und normale berechtigte Editoren bleiben getrennt erhalten. Tokenbasiertes Einzel-Enrollment erzeugt keine lokalen Demo-Tokens mehr. Der bestehende berechtigte Quick-Actions-Bulk-Pfad bleibt bestehen, akzeptiert aber keine erfundenen Erfolgsergebnisse bei fehlender oder falscher Antwort. Diese Korrekturen implementieren keine neuen Provider oder fehlenden Business-Workflows.

## Lizenzquellen: koordinierter Protokollwechsel

Identity benötigt Migrationen **001–044**. Identity und alle Policy-HTTP-Receiver gemeinsam auf `X-OD-License-Snapshot-Protocol: 1` aktualisieren; erfolgreiche Antworten alter Reader ohne diesen Header werden absichtlich nicht mehr angenommen. Keine alten ungescopten Direkt-Reader parallel freigeben. Vor Aktivierung von Eligibility-Workern deren dedizierten Issuer/Client und aktuelle Clientrevision bewusst offline an genau den geprüften Business-Tenant binden. Dafür ist ausschliesslich das explizite `IDENTITY_OPERATOR_DATABASE_URL` mit tatsächlichem Tabellenbesitzer vorgesehen; keine Runtime-URL-Heuristik, keine Caller-Tenant-Auswahl und kein HTTP-Admin-Bypass.

Der [vollständige Quellvertrag mit CLI, Rotation, Widerruf und Rolloutgrenzen](../features/tenant-license-sources.md) beschreibt diese Betriebsänderung. Ungebundene oder nach Clientrotation veraltete Quellen bleiben sicher gesperrt. Eine konfigurierte Quelle ist keine erfolgreiche Client-/Provider-Abnahme und kein Company-App-/Lizenzpool. Migrations-/SQL-Operatorrechte, getrennte Least-Privilege-Logins, echte Deployments und unabhängige Retention sind weiterhin gesondert abzunehmen.

## Eigener Firmen-Lizenzkatalog und lokale Zuweisungen

Der Firmen-Lizenzkatalog benötigt mindestens Policy-Migrationen **001–022** und Identity **001–044**; der verbundene Offboarding-Weg zusätzlich **023/045** wie unten beschrieben. Der normale Firmenweg liegt unter `/applications` und nutzt `/api/licenses/company` sowie den ursprünglichen Identity-Source `/api/identity/company-licenses`. Nur tatsächlicher eigener Company-Owner bzw. kanonisches Home-Admin mit frischer unabhängig gebundener MFA; keine globale Lizenzrolle als Bootstrap. Der eigene Client verlangt `companyLicenseProtocol:1` und aktuelle serverseitige Capabilities, bevor er schreibt.

Identity-/Policy-Dockerfiles kopieren den neuen kleinen `packages/company-license-contract`-Ordner; Policy zusätzlich den bestehenden Tenant-Vertrag. Repository-Root als Buildkontext behalten. Es wurden keine Dependencies oder neuen Secrets hinzugefügt. Bestehendes `IDENTITY_SERVICE_URL` bezeichnet den tatsächlichen internen Identity-Origin; Issuer/JWKS/Access-State müssen weiterhin dieselbe ursprüngliche menschliche Authority prüfen. Alle Images/direkten Consumer koordiniert aktualisieren; alte Instanzen ohne Company-Fences nicht parallel auf derselben Datenbank betreiben. Kein durchgeführtes produktives Deployment wird dadurch behauptet.

NULL-Pools und historische globale Subjects bleiben Legacy. Kein automatisches Übernehmen aus Creator/Graph-Tenant oder Zurücksetzen früherer Sperren/Directory-/Grant-/Providerhistorie. Kontrollierte Migration und getrennte SQL-Runtime-/Operatorrechte bleiben offen. Neue Company-Entitlements sind ausschliesslich lokale finite Per-User-Zuweisungen; kein Lizenzkauf, keine App-Installation und noch keine automatische Lizenzrückgabe bei Kontosperren. [Benutzerweg, Commit-/Betriebsgrenzen und noch offene Funktionen](../features/company-licenses.md).

## Dauerhaftes lokales Mitarbeiter-Offboarding

Der Offboarding-Weg benötigt mindestens **Identity 001–045**, **Policy 001–023**; aktuelle App-/Bestandskorrekturen benötigen zusätzlich Policy **024** wie unten beschrieben. Migrationen sind additiv; 022 bleibt unverändert und bestehende Lizenz-/Directory-Historie wird nicht zurückgesetzt. Runtime, Gatewayvertrag und Frontend koordiniert aktualisieren; alte Instanzen dürfen neue Fences nicht umgehen. Fehlendes Schema/Receiving sperrt statt auf Legacy zurückzufallen. Vor Änderungen Backups und geprüftes Restore-Verfahren verwenden; hier wurde kein Produktivrollout durchgeführt.

Keine neuen Dependencies, Secrets oder externen Schreibcredentials. Bestehende feste interne `IDENTITY_SERVICE_URL` muss den tatsächlichen Identity-Origin bezeichnen. Der Bridge leitet nur den ursprünglichen menschlichen Bearer weiter, ohne Redirect, Service-Credential- oder Fremd-Origin-Fallback. Eigene Company-Authority und frische unabhängig gebundene MFA sind bei jedem Fortsetzen erneut erforderlich. Kurzlebige Quellen werden nicht als gespeicherte Tokens verlängert.

Unter `/applications` Vorgang vorbereiten, Vorschau prüfen und bestätigen. Bis zu 25 erfasste Lizenzen pro Aufruf; weitere Seiten bewusst bestätigen. Bei Timeout/Fehler **zuerst gespeicherten Vorgang und Historie neu laden**, nicht blind neu erstellen. Identischer Create mit gleichem Schlüssel liest nur den Stand. Account-/Lizenz-Commits bleiben bei späterem Journalfehler bestehen; Wiederaufnahme prüft ihre ursprünglichen tatsächlichen Belege. Nach neuer Anmeldung bekannte Vorgangs-ID laden. Weder automatischer Worker noch Cron ist einzurichten.

`completed_local` bestätigt den damaligen lokalen Account-/Lizenzstand. Aktuellen Kontostatus separat beachten; Rollen/Gruppen, Geräte, externe Credentials/Provider und vollständige Sessions sind nicht abgearbeitet. Outbox `pending` ist keine zugestellte Nachricht. Aufbewahrung, SQL-Runtime-/Operator-Trennung und produktive Restore-/Betriebsabnahme bleiben offen. [Benutzer-/Recovery-Vertrag](../features/company-offboarding.md).

Frontend weiterhin mit `npm run type-check -- --incremental false` und `npm run build` prüfen. Next filtert intern Testdiagnosen; nur die unabhängige vollständige Typprüfung deckt diese mit ab. Bestehende nicht fatale SWC-/Workspace-Lockfile-/Browserslist-Warnungen und die ESLint-Build-Ausnahme sind nicht behoben.

## App- und Lizenzbestandskorrekturen

App-/Bestandskorrekturen benötigen mindestens **Identity 001–045**, **Policy 001–024**; der neue Gruppen-Folgeschritt zusätzlich Identity **046**. `024_company_pool_updates.sql` erweitert das vorhandene Company-Katalog-/Audit-/Eventmodell; alte Migrationen und Zuweisungs-/Granthistorie bleiben unverändert. Keine neuen Tabellen, Dependencies, Secrets, Workloads oder externen Schreibcredentials für den Katalogschritt. Bestehenden Migrationslauf im Repository nutzen, nicht einzelne alte Funktionen über die neue Version zurückspielen; ältere und neue Clients wegen des zusätzlichen Historien-Eventtyps koordiniert aktualisieren.

Der Editor unter `/applications` öffnet nur nach dem tatsächlichen eigenen `companyPoolEditProtocol:1`-Check. Bestätigte Korrekturen verändern ausschliesslich lokale Metadaten/Seatbestand. Untergrenze ist die wirkliche Belegung, nicht ein Browserzähler; No-op/alter ETag werden abgelehnt. Bei unbekanntem Abschluss aktuellen Pool und Historie neu laden, keine automatische Wiederholung. Das Aufstocken kauft keine Herstellerlizenz. SQL-Operator-/Runtime-Trennung, Restore, unabhängige Retention und Produktivrollout sind weiterhin separat abzunehmen. [Benutzer-/API-Vertrag](../features/company-licenses.md#app--und-bestandskorrekturen).

## Gruppenentzug beim Austritt

Der Gruppen-Teilprozess benötigt mindestens **Identity 001–046**, **Policy 001–024**. Die additive `046_company_offboarding_groups.sql` verbindet neue Child-Receipts mit dem unveränderten Account-Beleg aus 045 und bestehenden kanonischen Group-Events. Keine Umschreibung alter Migrationen, Gruppenbestände, Rollen oder Lizenzhistorie. Neue Tabellen sind Belege/Commit-Guards, kein zweiter Gruppen-Mutator. Der anschliessende Rollen-/PIM-Teilprozess benötigt zusätzlich Identity 047.

Identity-Runtime und Frontend koordiniert aktualisieren; der Gruppenclient verlangt tatsächliches `companyOffboardingGroupsProtocol:1`. Fehlendes Schema/Receiving bleibt gesperrt, nicht Legacy-Fallback. Vor Produktivänderungen Backups/Restore und getrennte Runtime-/Migrationslogins abnehmen; kein hier ausgeführter Produktivrollout. Keine neue Dependency, Secret, Service-Account-Delegation oder Background-Worker-Konfiguration. Bestehender gemeinsamer Contract-Ordner wird bereits von den Dockerfiles kopiert.

Im gespeicherten lokalen Austrittsprozess „Gruppen beim Austritt entfernen“ öffnen und echte Vorschau laden. Nur die gezeigte Seite mit höchstens 25 Membership-IDs bestätigen. Bei Fehler/Timeout Vorschau und dauerhafte Historie neu lesen; frühere erfolgreiche Child-Commits bleiben bestehen. Ein gespeicherter alter Entzug darf keine später neu angelegte Mitgliedschaft entfernen. Reaktivierung/andere negative Eligibility erfordert einen neuen geprüften Account-Vorgang. Rollen/PIM, OU, Geräte, vollständige Sessions und Provider sind weiterhin separat zu bearbeiten. [Benutzerweg und Grenzen](../features/company-offboarding.md#gruppen-beim-austritt-entfernen).

## Rollen-/PIM-Entzug beim Austritt

Aktueller koordinierter Stand: **Identity 001–047**, **Policy 001–024**. Die additive `047_company_offboarding_access.sql` erweitert nur Belege und Commit-Fences; bestehende Account-, Rollen-/PIM- und Lizenzhoheiten bleiben erhalten. Identity-Runtime und Frontend koordiniert aktualisieren. Fehlendes Schema oder `companyOffboardingAccessProtocol:1` bleibt gesperrt, kein Legacy-Fallback. Keine neue Dependency, externe Credentials, Worker-Delegation oder globale Rollenzuweisung ist erforderlich.

Wirkliche Rollen-/PIM-Bearbeitende können `/offboarding-access` mit kanonischer Benutzer-ID und ursprünglicher Account-Vorgangs-ID verwenden; `users.read` und Company-Ownership sind nicht Voraussetzung. Lesen und Schreiben verlangen trotzdem pro Bereich tatsächliche kanonische Pflichten und eigenständige frische MFA. Company-Owner ohne diese Rechte erhalten keinen Zugriff. Geschützte Rollen behalten die vorhandene kanonische Admin-Grenze. [Bedienung, explizite Bestätigung und Lost-Response-Recovery](../features/company-offboarding-access.md).

Der unabhängige Operator benötigt weiterhin einen tatsächlich autorisierten Console-Anwendungszugang. Ohne bereits verpflichtende MFA-Richtlinie verwendet er die bestehende angemeldete Selbsteinrichtung unter `/mfa` mit aktuellem Passwortnachweis und danach eine neue MFA-Anmeldung. Die öffentliche Ersteinrichtung darf für solche nicht verpflichtenden Konten weiterhin `mfa_enrollment_not_allowed` liefern. Kein automatischer App-Grant, Owner-Bypass oder Absenken der MFA-Anforderungen wird für diesen Slice benötigt.

Vor produktiven Änderungen beide tatsächlichen Datenbanken und retained Audit-/Checkpoint-/Receipt-/Outbox-Ketten sichern und Restore separat abnehmen. SQL-Owner-/Runtime-Trennung, Privacy/Retention und produktiver Rollout sind weiterhin offen. Dieser lokale Slice ist weder ein durchgeführter Produktivrollout noch vollständiger Austritt; keine Geräte-/Provider-/OU-/All-Session-Bereinigung wird behauptet.

## Geräterückgabe beim Austritt

Koordinierter Stand dieses Teilprozesses: **Identity 001–047**, **Device 001–006**, **Policy 001–024**. Keine neue Identity- oder Policy-Migration. Device 006 ergänzt echte Rückgabeaufträge/-Events/-Pending-Outbox und lokale Commit-Guards zum unveränderten Inventar-Kernel aus 005. Bestehende NULL-/Legacy-Geräte werden nicht adoptiert. Identity/Device/Gateway/Frontend gemeinsam aktualisieren; der Gateway verlangt für neue Rückgabewege tatsächlich `deviceReturnsProtocol:1`, nicht nur einen alten Inventory-Receiver.

Die neue private Identity-Quelle liegt unter `POST /api/identity/device-offboarding`. Device verwendet dieselbe konfigurierte tatsächliche Identity-Origin wie die bisherige Inventarquelle; ursprünglicher menschlicher Bearer bleibt erhalten. Bestehende `IDENTITY_SERVICE_URL`, Issuer/JWKS und OIDC-Live-State-Konfiguration gelten weiter. Keine neuen Secrets oder Service-Account-Delegation. Der Gateway kopiert zusätzlich den bestehenden gemeinsamen Device-Contract im Root-Buildkontext; keine neue Dependency.

Im gespeicherten Austritt nach dem echten negativen Checkpoint die Geräteanforderung ausdrücklich öffnen, aktuelle eigene Seite auswählen und bestätigen. Danach unter `/device-returns` die physisch beobachtete Übergabe separat manuell bestätigen oder nur den Auftrag abbrechen. Zuweisungen werden nicht schon bei Anforderung entfernt. Beide Versionen/ETags und ursprüngliche Assignment-UUID sind verbindlich. Unbekanntes Ergebnis verlangt tatsächliches Readback und bewusste Original-Intent-Recovery; kein automatischer Retry. Eine normale Neuzuweisung wird nicht als Rückgabe ausgegeben. [Vollständiger Bedien-/Recovery-Vertrag](../features/device-returns.md).

Vor Deployment die tatsächlichen Identity-/Device-/Policy-Daten sowie alle ursprünglichen Event-/Source-/Outbox-Belege sichern und Restore gesondert prüfen. Kein Cross-DB-FK oder verteilter atomarer Commit; Rücknahme nach späterem Accountwechsel ist eine eigenständige aktuelle Inventarhandlung. Runtime-/Migrationslogins, Datenschutz/Retention, Linux-Image, Monitoring/Last-/Produktivabnahme und echte MDM-/Providerintegration bleiben offen. Es wird kein Produktivrollout oder externer Gerätebefehl ausgeführt.

## Externe OIDC-Anmeldung und SAML

Der zentrale OAuth-Dienst unterstützt den [OIDC-Adapter und authentifizierte SAML-IdP-Starts](../../services/core/oauth-provider/README.md). Dort stehen die geschützten Konfigurationsdateien, exakten Callback-URLs, Zertifikate, Compose-Mounts und Routingvoraussetzungen. Ohne Konfiguration bleiben die bestehenden lokalen Anmeldewege verfügbar. Alte `/api/auth/sso/*`-Callbacks sind mit HTTP 410 stillgelegt. Apple ADE benötigt eine separate, weiterhin nicht abgenommene Anbindung; siehe [Einrichtungsleitfaden](../integrations/apple-automated-device-enrollment.md).

Der [Credential-Service](../../services/core/authentication-service/README.md) auf Port **3002** benötigt seine eigene Auth-Datenbank mit allen zehn SQL-Dateien bis **009**. `AUTH_DATABASE_URL` hat Vorrang vor `DATABASE_URL`, danach gelten die bestehenden `DB_*`-Werte. Fehler einer Migration verhindern den Start; bestehende Passwort-Hashes und Sperren werden nicht durch Demo-Konten ersetzt. `REDIS_URL` gilt für HTTP-Sessions, Token- und Session-Service. Beide Compose-Dateien verwenden den tatsächlichen Servicepfad und einen im Node-Image ausführbaren Healthcheck. OIDC-/JWKS-/Interaction-Endpunkte dieses Dienstes liefern **410**; Clients ausdrücklich beim zentralen OAuth-Issuer registrieren. Bestehende alternative Keys/Clients werden nicht still adoptiert. Ein Verzeichniseintrag allein provisioniert weiterhin keinen Credential-Account, Subject-Link oder MFA.

Im Produktionsmodus einen eigenen starken `JWT_SECRET` mit mindestens 32 Zeichen konfigurieren; fehlende, kurze und frühere Standardschlüssel werden verweigert. Ein optionaler separater `SESSION_SECRET` hat dieselbe Mindestlänge. Ohne diesen wird ein stabiler eigener HTTP-Sitzungsschlüssel aus dem konfigurierten JWT-Schlüssel mit festem HMAC-Zweck abgeleitet. Schlüssel über Neustarts erhalten; alte Sitzungen mit dem früheren Standard-Cookieschlüssel werden nicht übernommen.

## CLI für App-Konten

Node.js 20+ und `node scripts/od.mjs --help` genügen. Es werden keine neuen Server-Abhängigkeiten eingeführt. Die CLI benötigt die tatsächliche HTTPS-Origin des Issuers und gegebenenfalls eine separate API-Origin; Zugangsdaten kommen aus der Secret-Verwaltung des Runners. App-Verwaltung und Automationsläufe verwenden ausdrücklich verschiedene Identitäten. Einrichtung und Grenzen stehen im [App-Konto-Leitfaden](../features/app-accounts-automation.md).

## Lizenzgruppen und Skript-Abgleich

Der [Lizenzgruppenweg](../features/company-license-groups.md) benötigt aktuellen Identity-Code mit Migrationen **001–049**, Policy **001–029** und koordiniertes Gateway/Frontend. Policy 028 ergänzt Links, Events/Pending-Outbox und Gruppeneffekte; 049/029 ergänzen den appgebundenen Abgleich. Bestehende Legacy-Gruppenworker werden nicht für Firmenpools freigeschaltet. Die Dockerfiles kopieren die gemeinsamen Verträge im bestehenden Root-Buildkontext; keine neue Dependency.

Unter Verzeichnisgruppen den Pool ausdrücklich verknüpfen. UI und die CLI-Mitgliedsbefehle starten den manuellen Abgleich mit ursprünglichem menschlichem Bearer/MFA. Für unbeaufsichtigten Betrieb [eine eigene App ausdrücklich freigeben](../features/company-license-automation.md), die Verknüpfung unter Automationen prüfen und einen Zeitplan speichern. Bei Timeout oder Teilfehler tatsächlichen Stand prüfen; frühere Benutzer können bereits gespeichert sein. Kein Produktivrollout oder Herstellerzugriff wird hier ausgeführt.

## Dynamische und verschachtelte Gruppenregeln

Für [dynamische und verschachtelte Gruppenregeln](../features/company-group-rules.md) zusätzlich Identity **050–054** und aktuelles Frontend/CLI ausrollen. Als tatsächlicher Firmeninhaber mit frischer MFA Konfiguration speichern, gespeicherte Vorschau prüfen und den kanonischen Mitgliederabgleich gesondert bestätigen. Konfiguration allein legt keine Mitgliedschaft an. Identity 052 sperrt bereits gespeicherte ungültige Regelquellen beim Lesen und vererbt Review-Fristen; physische Bereinigung bleibt ein eigener Abgleich. Der bereits verfügbare Lizenz-App-Worker verarbeitet danach die tatsächlichen Gruppenquellen; der [Gruppenregel-App-Worker](../features/company-group-rule-automation.md) verwendet die eigene ausdrückliche Aktion `directory.groups.reconcile`. Nach erneutem Anwenden älterer Automations-/Gruppenregelmigrationen 051/052/053 und zuletzt 054 anschliessend erneut anwenden.

## App-Freigaben und dauerhafte Exportjobs

Der [Firmen-Automationsweg](../features/company-automation.md) benötigt Identity **001–054**, Policy **001–029**, aktuellen OAuth-Code mit dem festen Scope `company.automation` und das aktuelle Frontend. Beide Dockerfiles kopieren die gemeinsamen Verträge; bestehender Root-Buildkontext und `/api/identity/*`-Proxy bleiben bestehen. Identity benötigt `POLICY_SERVICE_URL`, Policy `IDENTITY_SERVICE_URL` zum tatsächlichen anderen Service. Beide behalten die gültige Issuer-/JWKS-/Access-State-Konfiguration. Keine neue Runtime-Dependency oder Datenbank.

Ein eigenes dediziertes App-Konto anmelden und vom tatsächlichen Eigentümer mit aktueller MFA ausdrücklich für feste Aktionen freigeben. Auf dem Runner ausschliesslich die App-Zugangsdaten konfigurieren und `node scripts/od.mjs automation worker GRANT_ID` betreiben. Zeitpläne bleiben ohne laufenden Runner gespeichert. [Quellenänderungsbeobachtungen](../features/company-automation-changes.md) über UI oder `automation group-watch`/`license-watch` verwenden denselben Runner; beide neuen privaten Empfänger benötigen die aktuellen Identity-/Policy-Images und gemeinsamen Verträge. Export-, Gruppenregel- und lokale Lizenzgruppenhandler sind ausführbar; Lizenzjobs haben ein festes Ziel, wiederaufnehmbaren Fortschritt und sichtbare Teilresultate. Bei einer Migration-Wiederholung nach 048 auch 049–054 anwenden, damit die erweiterten Empfangsmanifeste konsistent bleiben. Weitere Konten-/Provider-Schreibaktionen und automatischer Artefakt-Retentionprozess bleiben offen; der [Gesamtauftrag](../implementation-worklist.md) ist nicht abgeschlossen.

## Eigene Firmen-App-Konten

[Eigene vertrauliche App-Konten](../features/company-apps.md) benötigen **OAuth 001–014**, **Identity 001–054**, aktuelle OAuth-/Identity-/Gateway-/Web-Images und CLI. Beide gemeinsamen Verträge werden in den bestehenden Docker-Builds kopiert. OAuth verwendet den tatsächlichen Ursprung aus `OAUTH_IDENTITY_AUTHORITY_URL`; Identity behält die gültigen JWKS-/Access-State-/Tenant-State-Einstellungen. Für API-Zugriff über den Gateway `identity-service` aktivieren und `OAUTH_PROVIDER_URL` auf den tatsächlichen OAuth-Ursprung setzen; `/api/clients/company` bleibt ohne Umschreibung und mit ursprünglichem Bearer/If-Match erreichbar. Der Next-Prefix `/api/clients/*` bleibt bestehen. Alte globale Leser nicht neben dem neuen Namespace weiterbetreiben.

Neue Konten als tatsächlicher Owner mit frischer MFA deaktiviert anlegen, das einmalige Secret übernehmen und getrennt aktivieren. Der Originalauftrag ist eine vom Client einmalig erzeugte UUID; bei verlorenem Ergebnis denselben Auftrag prüfen. Keine automatische Secret-Wiederanzeige oder neue UUID für einen unbestätigten Retry. Nach Rotation, Zweck-/Generationswechsel oder Unternehmenspause aktuelle Hoheit und neue ausdrückliche Appfreigabe prüfen. Archivierte Konten und Originalhistorie bleiben über die eigene Registeransicht lesbar. Pending-Outbox ist noch keine externe Zustellung oder vollständige Retention-Abnahme. Kein Produktivrollout wurde hier durchgeführt.
