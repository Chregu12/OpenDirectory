# Mitarbeiteraufnahme: Einladungen, Zugangsdaten und MFA

Stand: 15. November 2026. Der Eintrittsablauf verbindet Originaleinladungen, gesperrte Passwortkonten, kanonische Identity-Aktivierung, Graph-Mail und die erste MFA-Anmeldung. Firmeninhaber können unter `/employee-invitations` Gruppenmitgliedschaften zusammen mit einer Einladung setzen und Einladungen auch über die Owner-CLI verwalten. Eine konfigurierte Microsoft-Graph-App übergibt den Einmal-Link an die verifizierte Zieladresse zum Versand. Mitarbeitende setzen ihr Passwort unter `/employees/accept`; wenn die erste angemeldete App MFA verlangt, richtet die OAuth-Anmeldeseite den appgebundenen Faktor ein und setzt danach den Login fort. Kontrollierte Credential-Namespace-Wiederverwendung, Review geänderter Teilaufnahmen und SCIM bleiben offen. Die internen Empfänger werden ausschliesslich durch eng gebundene Issuer-Workload-Tokens aufgerufen; ein normaler Benutzer- oder App-Token erteilt diese Befugnis nicht.

## Ursprüngliche Einladung

Identity liest unter `POST /api/identity/employee-invitations` den tatsächlichen aktuellen Firmeninhaber. Der ursprüngliche menschliche Bearer und unabhängig gebundene MFA, höchstens fünf Minuten alt, sind auch für Listen, Lesen und Widerruf erforderlich. Eine globale Rolle ersetzt keine Ownership. Ein optional ausgewählter Empfänger muss aus demselben Unternehmen stammen; die Erstellung verlangt einen deaktivierten, unverknüpften gewöhnlichen Verzeichniseintrag in genau der bestätigten Version. Owner, nicht widerrufene privilegierte Rollenzuweisungen und PIM-Eligibility werden nicht als gewöhnliche Einladungsziele übernommen.

Der Create-Auftrag enthält exakt `{id,userId,userRevision,loginName,durationHours,reason,confirm:true}`. UUID und ursprünglicher Auftrag bleiben unveränderlich. `loginName` ist explizit: Verzeichnisnamen, E-Mail-Adressen und bestehende Credential-Subjects werden nicht heuristisch gleichgesetzt. Die Lease beträgt eine bis höchstens 72 Stunden. Eine bestehende Einladung derselben UUID liefert bei unverändertem Inhalt nur Metadaten; sie gibt kein zweites Secret aus. Bei verändertem Originalauftrag wird abgewiesen. Ein verlorenes Secret erfordert bewussten Widerruf und eine neue Einladung.

Die erste Antwort enthält einmalig `UUID.secret`. Gespeichert wird ein SHA-256-Hash des vollständigen zufälligen Tokens mit festem Zweck. Token, Passwort und Passwort-Anfragehash gelangen nicht in Einladungsereignisse oder Outbox. Der Owner-Link zeigt das Token nur nach einer tatsächlich neuen Erstellung. Der öffentliche Empfänger prüft es in einem exakten `no-store` POST und erhält ausschliesslich Organisation, Anmeldename, Ablauf und Status. Owner-Kontext, Tenant-IDs, Witness und private Receipts werden nicht ausgegeben. Der Link verwendet ein URL-Fragment (`/employees/accept#UUID.secret`), das der Browser unmittelbar nach dem Laden aus der Adresszeile entfernt; weder Querystring noch Browser-Storage werden verwendet.

## Öffentliche Einladungsoberfläche

Der Firmeninhaber wählt einen deaktivierten eigenen Verzeichniseintrag aus. Identity liest den aktuellen Zielstand erneut und bestätigt, dass die Person unverknüpft und gewöhnlich ist. Danach speichert Auth mit einer ursprünglichen Owner- und Tenant-Prüfung die Einladung. Jede Verwaltungsanfrage erfordert den aktuellen Owner und unabhängig bestätigte MFA von höchstens fünf Minuten. Die Oberfläche zeigt höchstens 25 Einladungen pro Seite. Ein neu erstelltes Einladungs-Token wird genau einmal angezeigt; ein wiederholter identischer Create-Auftrag liefert Metadaten und kein zweites Token.

Ein Widerruf ist nur für `pending` und `credential_pending` möglich. Nach dem tatsächlichen Auth-Widerruf prüft OAuth den aktuellen negativen Auth-Beleg bei Identity und nimmt eine unveränderte angefangene Teilaufnahme zurück. Ein bereits `accepted` Mitarbeiter wird über das reguläre Offboarding entfernt. Verlorene Antworten werden nicht automatisch wiederholt; dieselbe stabile Create-UUID kann den Originalstatus wiederfinden.

Die öffentliche API ist `GET /oauth/employee-invitations`, `POST /oauth/employee-invitations/inspect` und `POST /oauth/employee-invitations/accept`. Firmeninhaber verwenden `POST /oauth/employee-invitations/owner/{create,list,get,revoke}` mit ihrem normalen menschlichen OAuth-Zugriffstoken. Alternativ bietet das Web-Frontend gleichursprüngliche BFF-Routen unter `/api/employee-invitations`. Die Secret-POSTs sind begrenzt und ohne Cache; die Oberfläche hält Passwort und Bestätigung ausschliesslich im Arbeitsspeicher.

## Owner-CLI

`node scripts/od.mjs employee-invitation` verwendet dieselben öffentlichen Owner-Routen und die bestehenden Auth-/Identity-Prüfungen wie die Oberfläche. Setze `OPENDIRECTORY_ISSUER` auf den tatsächlichen OAuth-Origin und `OPENDIRECTORY_ADMIN_ACCESS_TOKEN` aus deinem Secret-Store auf das ursprüngliche menschliche Zugriffstoken des aktuellen Firmeninhabers. Die MFA darf höchstens fünf Minuten alt sein. App-Zugangsdaten oder eine globale Rolle ersetzen diese Voraussetzung nicht. `OPENDIRECTORY_API_URL` ändert den Empfänger dieser Befehle nicht.

```sh
node scripts/od.mjs employee-invitation list 1
node scripts/od.mjs employee-invitation get INVITATION_UUID
node scripts/od.mjs employee-invitation create invitation.json --result-file new-private-result.json
node scripts/od.mjs employee-invitation revoke revocation.json
```

`invitation.json` enthält den ausdrücklich bestätigten Originalauftrag. Die Beispiel-IDs sind Platzhalter; `userId`, `userRevision` und `loginName` müssen dem ausgewählten eigenen deaktivierten Verzeichniseintrag entsprechen. Lege eine neue stabile Einladungs-UUID fest, bevor du den Auftrag abschickst.

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "userId": "22222222-2222-4222-8222-222222222222",
  "userRevision": "1",
  "loginName": "employee.example",
  "durationHours": 24,
  "reason": "Bestätigter Eintritt dieser Mitarbeiterin",
  "confirm": true
}
```

Die CLI reserviert die neue Ergebnisdatei vor dem HTTP-Auftrag mit exklusivem POSIX-Modus `0600`. Vorhandene Dateien werden nicht überschrieben. Nur diese Datei erhält das einmalige `invitationToken`; stdout zeigt Metadaten, `resultFile`, `mailRequestStatus` und `deliveryConfirmed:false`. Bei `provider_accepted` hat Graph den Versandauftrag angenommen; eine Empfängerzustellung ist damit nicht bestätigt. Ohne Graph-Konfiguration bleibt das Token für den vertraulichen manuellen Versand in der Datei verfügbar. Der Client benötigt dafür ein Dateisystem mit POSIX-Zugriffsrechten.

Nach Timeout oder Verbindungsfehler erfolgt keine automatische Wiederholung. Eine leere private Ergebnisdatei kann zurückbleiben. Prüfe zuerst mit `get` und der ursprünglichen UUID, ob die Einladung gespeichert wurde. Ein identischer Create-Auftrag mit einem neuen Ergebnisdateinamen liefert nur den ursprünglichen Status und kein zweites Token. Ein verlorenes Einmal-Secret verlangt bewussten Widerruf und eine neue Einladungs-UUID. Die CLI ändert weder Auftrag noch Version automatisch.

Für `revocation.json` liest du die tatsächliche Einladungsrevision und bestätigst genau diesen Auftrag:

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "revision": "1",
  "reason": "Eintritt abgesagt und Originaleinladung widerrufen",
  "confirm": true
}
```

Ein erfolgreicher Widerruf bestätigt auch den unabhängigen Identity-Receiver für die Rücknahme einer unveränderten Teilaufnahme. Eine unveränderte Wiederholung desselben Widerrufs erzeugt kein zweites Ereignis. Geänderte Teilaufnahmen und bereits angenommene Mitarbeiter verlangen weiterhin Review beziehungsweise reguläres Offboarding. Gruppenmitgliedschaften werden separat mit `group member add|remove GROUP_ID USER_ID` verwaltet; diese Befehle bilden keine gemeinsame Transaktion mit der Einladung.

## Graph-Mail und Gruppen für den Eintritt

Für automatische Einladung per Mail konfiguriert der OAuth-Provider `OAUTH_EMPLOYEE_INVITATION_GRAPH_TENANT_ID`, `OAUTH_EMPLOYEE_INVITATION_GRAPH_CLIENT_ID`, `OAUTH_EMPLOYEE_INVITATION_GRAPH_CLIENT_SECRET`, `OAUTH_EMPLOYEE_INVITATION_GRAPH_SENDER` und `OAUTH_EMPLOYEE_INVITATION_PUBLIC_URL`. Die App braucht den Microsoft-Graph-Anwendungszugriff `Mail.Send` mit Admin-Consent und ein vorhandenes Absenderpostfach. Beschränke den Mail-Zugriff in Exchange auf das vorgesehene Postfach. Die Zustellung verwendet `POST /users/{sender}/sendMail`; Graph `202 Accepted` bedeutet, dass Graph den Versand angenommen hat, nicht dass der Empfänger die Mail bereits erhalten hat. Bei fehlender oder fehlerhafter Konfiguration bleibt der einmalige Link im Browser zum vertraulichen manuellen Versand verfügbar. Das Passwort wird nie per Mail verschickt.

In der Einladungsansicht können eigene Verzeichnisgruppen ausgewählt werden. Die Gruppenmitgliedschaft wird vor dem Mailversand mit dem normalen, geprüften und auditierten Gruppen-Endpunkt des Firmeninhabers angelegt. Bestehende Gruppenfreigaben bestimmen danach App-Zugriff und Richtlinien. Hat die Gruppe eine unabhängige Mitgliedschaftsprüfung, bleibt sie bis zum Review unwirksam. Ist die Gruppe bereits an einen Firmen-Lizenzpool gebunden, weist der vorhandene Gruppen-Lizenzabgleich nach Aktivierung lokale Poolplätze zu; eine konfigurierte Gruppen-Lizenzautomation kann das erledigen. Die lokale Poolzuteilung selbst bestätigt keine Herstellervergabe oder Mailbox-Erstellung. Gruppenfreigaben, Review und Lizenzabgleich bleiben in ihren jeweiligen bestehenden Protokollen nachvollziehbar.

## Gesperrtes Passwortkonto

Der Empfänger muss das Originalsecret besitzen. Authentication fragt mit einem getrennten kurzlebigen signierten Beobachtungstoken bei Identity nach, ob ursprünglicher Owner, Tenant, Kontext und exakte deaktivierte Personenversion weiterhin gültig sind. Das Passwort wird dabei nicht an Identity weitergegeben. Der damalige menschliche Token wird weder gespeichert noch als spätere Empfängersitzung ausgegeben; ein bloss abgelaufener MFA-Zeitpunkt des Owners ersetzt keinen tatsächlichen Hoheitsentzug.

Authentication prüft die tatsächliche lokale Passwortpolicy, mindestens zwölf Zeichen und höchstens 72 UTF-8-Bytes, und speichert bcrypt-Hash, erste Passwort-Historie und Einladungsbeleg in einer Transaktion. Das neue normale Credential besitzt nur `user`, keine expliziten Berechtigungen und bleibt **gesperrt**. Der Verzeichniseintrag bleibt deaktiviert/unverknüpft. Recovery prüft das ursprüngliche Passwort und legt weder ein zweites Konto an noch ersetzt sie das erste Passwort.

SQL-Guards sperren normale Passwort-/Entsperr-/Löschzugriffe auf unfertige oder widerrufene Credentials. Der Einladungsauftrag darf keine fremden Benutzer oder anderen Auth-Daten verändern. Aufgeschobene Prüfungen verlangen denselben ursprünglichen Credential-, Passwort-History-, Event- und Outbox-Commit; abgelaufene Fristen und fehlende Receiver führen zum Rollback. Die Manifestprüfung prüft auch die tatsächlichen Trigger und Credential-Revisionsfunktion.

## Kanonische Aktivierung und Recovery

Identity nimmt unter `complete` ausschliesslich den ursprünglichen Credential-Witness an. Mit demselben ursprünglichen, Body-/Pfad-gebundenen Workload-Token liest es direkt beim Auth-Service die tatsächliche gespeicherte Einladung und das weiterhin gesperrte Originalcredential. Ein vom Aufrufer behaupteter Credentialstatus genügt nicht. Originalowner, Kontext, Tenant, gewöhnliche Zielperson und deren exakte deaktivierte Version müssen weiterhin gültig sein.

Die Aktivierung verwendet den vorhandenen kanonischen User-Mutation-Kernel, seine Audit-/Outbox-Belege und den expliziten Workload-Actor `oauth-provider` mit `context:null`; keine menschliche MFA oder Administratorrolle wird für eine Maschine erfunden. Eigene SQL-Fences begrenzen die Transaktion auf Statuswechsel, exakten Subject-Link, retained Tenant-Bindung und tatsächliche Audit-Folgeereignisse. Ein unveränderliches Aktivierungszertifikat verbindet ursprünglichen Witness, User-Mutation, vollständigen damaligen Benutzerstand und konkrete Linkrevision. Der vollständige Admission-Fingerprint bindet auch die ursprüngliche Workload-Proof-ID und den damaligen tatsächlichen Rollenstand des Owners bis zum physischen Commit. Fehlende Receiver, fehlende Outbox, Scope-Ersetzung oder abgelaufene Commit-Fristen rollen die Identity-Änderungen zusammen zurück. Das zuvor separat gespeicherte Credential bleibt in diesem Fall gesperrt und wiederaufnehmbar.

Auth entsperrt erst nach einem zweiten direkten Read-only-Check des tatsächlichen Identity-Receipts. Diese Bestätigungsquelle verlangt weiterhin den unveränderten ursprünglichen Aktivierungsstand und dieselbe Linkrevision. Ein später berechtigt bearbeitetes Teilkonto wird bei Recovery nicht erneut aktiviert oder überschrieben. Die historischen Belege bleiben lesbar; ein solcher Fall verlangt Review. Es wird keine atomare Transaktion über beide Datenbanken behauptet.

Die kanonische Rollenquelle verlangt für diese tatsächliche Mitarbeiterbindung MFA, ohne eine globale Rolle hinzuzufügen. Strengere bestehende Rollenregeln behalten ihre Fristen. Die Firmenkonsolenfreigabe gilt nur für den ursprünglich erfassten Console-Client. Die zentrale OAuth-Hoheit liest den tatsächlichen Auth-Credentialstand und vergleicht ihn mit dem Sicherheitsstand aus derselben erfolgreichen Passwortprüfung. Token tragen die aktuelle Credentialrevision; Zugriffsprüfung und Refresh lesen sie erneut. MFA-Einrichtungs- und Recovery-Challenges speichern dieselbe Bindung. Die akzeptierte Mitarbeiter-Einladung muss zusätzlich mit dem originalen `employeeBinding`, der Subject-Verknüpfung und dem Tenant übereinstimmen. Eine spätere normale Profiländerung ersetzt das historische Zertifikat nicht und entzieht allein deshalb nicht die ursprüngliche Konsolenbindung.

Nach Annahme führt die Oberfläche zur normalen `/login`-Anmeldung. Die OAuth-Anmeldeseite erkennt `mfa_enrollment_required`, verwendet die ursprüngliche Client-ID und bietet den bereits vorhandenen kurzlebigen Enrollment-Challenge-Ablauf an. Nach bestätigtem Authenticator-Code kann der Benutzer mit einem neuen aktuellen Code die ursprüngliche Anmeldung fortsetzen. Die Anwendungszuweisung muss weiterhin durch eine eigene Benutzer- oder Gruppenfreigabe gelten; andernfalls zeigt die Login-Seite den fehlenden App-Zugriff an. Der Graph-Mail-, Gruppen-, Pool- und Browserablauf wurde nicht mit einem vollständigen Live-Tenant-E2E bestätigt.

## Zustände

| Zustand | Tatsächliche Wirkung |
| --- | --- |
| `pending` | Originaleinladung gespeichert, noch kein Credential |
| `credential_pending` | Originalcredential und Passwort-Historie gespeichert; Credential gesperrt. Eine bereits bestätigte Identity-Aktivierung kann vor dem separaten Auth-Abschluss bestehen |
| `accepted` | Tatsächlicher Identity-Receiver hat aktiviert; Auth hat dessen Originalreceipt unabhängig bestätigt und genau das ursprüngliche Credential entsperrt |
| `revoked` | Secret unbrauchbar und unfertiges Credential weiterhin gesperrt; ursprünglicher bestätigter Widerrufsauftrag samt Grund bleiben erhalten |

Widerruf verwendet exakt `{id,revision,reason,confirm:true}`. Eine Wiederholung muss denselben Auftrag verwenden. Bereits angenommene Mitarbeiter benötigen den regulären Offboarding-Prozess. Nach tatsächlichem Auth-Widerruf kann `withdraw` eine unveränderte Teilaufnahme kanonisch deaktivieren und genau ihre ursprüngliche Subject-Verknüpfung entfernen. Identity prüft dafür direkt den tatsächlichen negativen Auth-Beleg. Die Tenant-Bindung und alle historischen Ereignisse bleiben erhalten. Spätere berechtigte Änderungen werden nicht automatisch entfernt; ein Konflikt benötigt Review. Bei später gesperrtem Parent werden ausschliesslich dessen exakt belegte automatische User-Generationsänderung und die dazugehörigen kanonischen Audit-/Outbox-Belege toleriert. Eine weitere unabhängige Benutzerversion verlangt Review. Ohne ursprüngliches Aktivierungszertifikat lautet das Ergebnis `changed:false, receipt:null`.

Das widerrufene unfertige Credential bleibt gesperrt und behält Login/E-Mail und Belege. Dessen kontrollierte Namespace-Freigabe/Wiederverwendung und ein Review geänderter Teilaufnahmen sind **noch offen**. Gruppenmitgliedschaften bleiben separate Verzeichnisoperationen; eine Herstellerlizenz oder ein Mailkonto wird durch die Einladung nicht angelegt.

Die eigene `users.security_revision` steigt bei Passwort-, Sperr- oder Credential-MFA-Änderungen, nicht bei gewöhnlichen Loginzählern. Der private `state`-Leser liefert für ein bekanntes Credential nur bei gültigem, entsperrtem Konto eine aktuelle Revision; angenommene Mitarbeiterkonten müssen ausserdem ihr tatsächliches Identity-Zertifikat erfüllen. Ein neuer RS256-Reader ist auf `POST /internal/auth/credential-state` verfügbar. Zentrale Tokens ohne gespeicherte Bindung werden für bekannte lokale Konten nicht nachträglich hochgestuft. Bei unerreichbarem Auth-Reader wird die Prüfung verweigert. Bestehende lokale OAuth-Sitzungen ohne die neue Claim-Bindung müssen sich erneut anmelden.

## Interner Transport und Installation

`POST /internal/auth/employee-invitations/{create,list,get,revoke,inspect,credential,activate,state}` sowie die delegierten Read-only-Callbacks `identity-source` und `revoked-source` sind im Auth-Service montiert. Identity montiert `POST /internal/identity/employee-invitations/{observe,complete,accepted-source,withdraw}`. Der Aktivierungs-Callback bei Identity prüft den ursprünglichen Auth-`activate`-Token; die Auth-Leser prüfen entsprechend den ursprünglichen Identity-`complete`-/`withdraw`-Token. Kein neuer gemeinsamer Signierschlüssel oder statischer interner Bearer wird benötigt.

Private Tokens verwenden RS256, einen tatsächlichen zentralen JWKS-Schlüssel, festes Audience/Purpose/Token-Type, exakte Operation, POST-Pfad, kanonischen Body-Hash, UUID-JTI und höchstens 30 Sekunden Laufzeit. Owner-Operationen binden zusätzlich den unveränderten menschlichen Bearer im separaten Header `X-OpenDirectory-Owner-Authorization`. Andere Operationen lehnen diesen Header ab. Der Identity-Callback validiert den ursprünglichen Operation-/Pfadvertrag auch auf dem expliziten delegierten Auth-Lesepfad. Queryparameter, API-Keys, andere Zwecke/Issuer und zusätzliche JWT-Felder werden abgewiesen. Antworten sind `no-store`.

Auth benötigt alle elf vorhandenen SQL-Dateien bis **010**, einschliesslich beider `005_*`, OAuth zusätzlich Migrationen bis **017**, und den aktuellen Code. Bestehende Accounts und Einladungen bleiben beim Replay unverändert. `OIDC_ISSUER`, `JWKS_URI` und `IDENTITY_SERVICE_URL` müssen auf dieselben tatsächlichen Authorities zeigen. Beide Compose-Dateien reichen diese Werte weiter und bauen Auth jetzt vom Repository-Root; die Dockerfiles kopieren die benötigten gemeinsamen Contracts. Auth deklariert die bereits in Identity eingesetzte JOSE-5-Version explizit. Das aktualisierte Service-Lockfile entfernt auch die verbliebenen Orphans des früher bereits stillgelegten zweiten OIDC-Issuers.

Identity benötigt alle vorhandenen Migrationen in Dateireihenfolge, aktuell bis **060**, einschliesslich **055_employee_enrollments.sql**, und `AUTH_SERVICE_URL` als gepinnten tatsächlichen Auth-Origin. Beide Compose-Dateien setzen ihn. Einzelne ältere Migrationen ersetzen keinen vollständigen Replay der aktuellen Empfänger. Die Migration erweitert die vorhandenen Transaktionsfences auch auf ihre neuen Tabellen und pinnt die tatsächlich beteiligten Routinen/Trigger. Einträge entstehen nur durch den tatsächlichen Aktivierungsvorgang; bestehende Verzeichnisbenutzer werden nicht adoptiert. Keine neue Runtime-Dependency wird in diesem Schritt eingeführt.

OAuth benötigt ausserdem `IDENTITY_SERVICE_URL` als tatsächlichen Identity-Origin für den Abschluss und Widerruf einer Einladung. `OAUTH_IDENTITY_AUTHORITY_URL` allein konfiguriert diese Empfänger nicht. Das Lite-Helm-Chart verwendet deshalb ausdrücklich `http://RELEASE-identity-service:3001`; beide Compose-Dateien setzen den dortigen Dienstnamen. Ein fehlender Kubernetes-Alias `identity-service` wird nicht vorausgesetzt.

Migration **017_credential_binding_validation.sql** repariert die SQL-Prüfung nichtleerer Credential-Bindungen in bestehenden Installationen. Die frische Migration **015** verwendet dieselbe Korrektur. Die vorherige Prüfung verwendete eine nicht vorhandene PostgreSQL-Funktion und wies deshalb gültige Bindungen ab. Das blockierte erste MFA-Einrichtung und Recovery tatsächlicher Passwortkonten. Die Reparatur behält IDs, Originalrevisionen, unveränderliche Tickets und Ablehnung geänderter Credential-Stände bei.

Der generierte [OpenAPI-Vertrag](../api/openapi.yaml) **1.39.0** beschreibt Owner- und Empfänger-OAuth-Routen, öffentliche Minimalantworten, Graph-Versandstatus, interne Originalproofs, separate Owner-Header, Witness-/Receipt-Schemas, kanonische `employeeBinding` und privaten Credential-State-Reader.

## Prüfung

```sh
npm test --prefix services/core/authentication-service -- --runInBand
npm run test:credentials:integration --prefix services/core/authentication-service
npm test --prefix services/core/identity-service -- --runInBand
```

Der Auth-Native-Runner umfasst bestehende Credential-Fälle, tatsächliche gekoppelte PostgreSQL-Transitionsfälle und fünf HTTP-Definitionen mit tatsächlich gestarteten Produktions-Auth-/Redis-Prozessen. Der Identity-HTTP-Teil montiert den ausgelieferten privaten Router, die tatsächlichen Source-/Receiver-Klassen und separat migriertes SQL unter einem lokalen Testserver; die beiden Dienste prüfen die ursprünglichen signierten Proofs über tatsächliche HTTP-Callbacks. Der neue CLI-Fall verwendet zusätzlich den tatsächlichen Invitation-Gateway, signierte Owner-Testtokens, neue private Ergebnisdateien, SQL-Lesekontrollen, identische Wiederholung und Widerruf. Das ist kein vollständig gestarteter produktiver Identity-/OAuth-/Browserablauf und kein echter OTP-Login. Identity führt die vier eigenen ursprünglichen Source-Fälle ausserdem im vorhandenen nativen Runner mit. [Ergebnisse und offene Grenzen](../testing/test-results.md#23-oktober-2026--kanonische-mitarbeiteraktivierung), [vollständiger Auftrag](../implementation-worklist.md).

Am 14. November liefen lokal unter Node.js 20 alle 49 Skriptfälle, alle 56 Credential-/Einladungs-PostgreSQL-/HTTP-Fälle und alle 524 OAuth-Jest-Fälle erfolgreich. Actionlint 1.7.12 und die read-only Workflow-Formatprüfung liefen ebenfalls erfolgreich. Die HTTP-Regression reproduzierte vor der Korrektur eine irreführende `503` bei veralteter Owner-MFA; der Gateway reicht jetzt die tatsächliche `428` weiter. Die CI erhält einen eigenen PostgreSQL-/Redis-Job für diesen bisher fehlenden nativen Runner. Der neue native Credential-Job lief in GitHub auf Linux mit allen 56 Fällen erfolgreich (Run `43650208137`, Commit `3d6cf46`). Die vollständige CI und ein Live-Graph-Tenant-Test stehen weiter aus. Eine Graph-`202`-Antwort bestätigt nur die Annahme des Versandauftrags; lokale Poolzuteilung ist kein Beleg für eine Herstellerlizenz oder Mailbox.

Am 15. November liefen zusätzlich alle **31 MFA-PostgreSQL-Fälle** erfolgreich, einschliesslich tatsächlicher nichtleerer Enrollment-/Recovery-Bindungen, Upgrade der vorherigen SQL-Funktion, Migration mit unverändertem Originalticket und Ablehnung einer späteren Credentialrevision. Der neue Chromium-Fall führt die tatsächliche Next-Produktionsoberfläche, OAuth, den Produktions-Auth-Prozess mit eigenem Redis und getrennte PostgreSQL-Schemas zusammen: eigene Einladung, echtes neues Passwort, kanonische Aktivierung, falsches Passwort abweisen, appgebundene erste OTP-Einrichtung, vertraulicher Callback, Session-Erneuerung und Logout. Das neue Mitarbeiterpasswort wird tatsächlich vom Auth-Service geprüft. Der Owner und ältere Browserakteure verwenden weiterhin ausdrücklich lokale Passwortfixtures; ihr Owner-Login verwendet den tatsächlichen zentralen OTP-Faktor. Der gezielte neue Fall und der bestehende Basislogin liefen erfolgreich. Insgesamt wurden 59 unterschiedliche Browserfälle mit der erweiterten Auth-Testumgebung erfolgreich geprüft: die bisherigen frischen Gruppen, der neue Mitarbeiterablauf und ein gezielter Wiederholungslauf des korrigierten Lizenz-Worker-Falls. Dessen ursprünglicher Versionskonflikt beim Stoppen wird durch bewusstes Beenden des Testworkers und erneutes Laden der tatsächlichen Zeitplanversion vermieden; der separate erfolgreiche CLI-Abschluss wird zusätzlich geprüft. Ein einzelner vollständiger finaler GitHub-Lauf, Live-Graph, physische Authenticator-App und Produktivrollout stehen noch aus. [Prüfnachweis](../testing/employee-onboarding-2026-11-15.json).
