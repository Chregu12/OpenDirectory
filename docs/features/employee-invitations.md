# Mitarbeiteraufnahme: interner Einladungs- und Credential-Empfang

Stand: 23. Oktober 2026. **In Arbeit, noch kein vollständiger Mitarbeiter-Eintritt.** Implementiert sind eigene Originaleinladungen, gesperrte Passwortkonten und die tatsächliche kanonische Identity-Verknüpfung/Aktivierung mit unabhängig bestätigter Credential-Entsperrung. Öffentliche OAuth-Fassade, Oberfläche/CLI und die vollständig verbundene erste Pflicht-MFA-Anmeldung fehlen noch. Die internen Empfänger werden ausschliesslich durch eng gebundene Issuer-Workload-Tokens aufgerufen; ein normaler Benutzer- oder App-Token erteilt diese Befugnis nicht.

## Ursprüngliche Einladung

Identity liest unter `POST /api/identity/employee-invitations` den tatsächlichen aktuellen Firmeninhaber. Der ursprüngliche menschliche Bearer und unabhängig gebundene MFA, höchstens fünf Minuten alt, sind auch für Listen, Lesen und Widerruf erforderlich. Eine globale Rolle ersetzt keine Ownership. Ein optional ausgewählter Empfänger muss aus demselben Unternehmen stammen; die Erstellung verlangt einen deaktivierten, unverknüpften gewöhnlichen Verzeichniseintrag in genau der bestätigten Version. Owner, nicht widerrufene privilegierte Rollenzuweisungen und PIM-Eligibility werden nicht als gewöhnliche Einladungsziele übernommen.

Der Create-Auftrag enthält exakt `{id,userId,userRevision,loginName,durationHours,reason,confirm:true}`. UUID und ursprünglicher Auftrag bleiben unveränderlich. `loginName` ist explizit: Verzeichnisnamen, E-Mail-Adressen und bestehende Credential-Subjects werden nicht heuristisch gleichgesetzt. Die Lease beträgt eine bis höchstens 72 Stunden. Eine bestehende Einladung derselben UUID liefert bei unverändertem Inhalt nur Metadaten; sie gibt kein zweites Secret aus. Bei verändertem Originalauftrag wird abgewiesen. Ein verlorenes Secret erfordert bewussten Widerruf und eine neue Einladung.

Die erste Antwort enthält einmalig `UUID.secret`. Gespeichert wird ein SHA-256-Hash des vollständigen zufälligen Tokens mit festem Zweck. Token, Passwort und Passwort-Anfragehash gelangen nicht in Einladungsereignisse oder Outbox. Die spätere öffentliche Fassade muss interne Witness-/Owner-Metadaten aus ihrer Empfängerantwort entfernen und darf das Secret nicht in Querystrings oder Browser-Storage ablegen; diese Fassade ist noch nicht umgesetzt.

## Gesperrtes Passwortkonto

Der Empfänger muss das Originalsecret besitzen. Authentication fragt mit einem getrennten kurzlebigen signierten Beobachtungstoken bei Identity nach, ob ursprünglicher Owner, Tenant, Kontext und exakte deaktivierte Personenversion weiterhin gültig sind. Das Passwort wird dabei nicht an Identity weitergegeben. Der damalige menschliche Token wird weder gespeichert noch als spätere Empfängersitzung ausgegeben; ein bloss abgelaufener MFA-Zeitpunkt des Owners ersetzt keinen tatsächlichen Hoheitsentzug.

Authentication prüft die tatsächliche lokale Passwortpolicy, mindestens zwölf Zeichen und höchstens 72 UTF-8-Bytes, und speichert bcrypt-Hash, erste Passwort-Historie und Einladungsbeleg in einer Transaktion. Das neue normale Credential besitzt nur `user`, keine expliziten Berechtigungen und bleibt **gesperrt**. Der Verzeichniseintrag bleibt deaktiviert/unverknüpft. Recovery prüft das ursprüngliche Passwort und legt weder ein zweites Konto an noch ersetzt sie das erste Passwort.

SQL-Guards sperren normale Passwort-/Entsperr-/Löschzugriffe auf unfertige oder widerrufene Credentials. Der Einladungsauftrag darf keine fremden Benutzer oder anderen Auth-Daten verändern. Aufgeschobene Prüfungen verlangen denselben ursprünglichen Credential-, Passwort-History-, Event- und Outbox-Commit; abgelaufene Fristen und fehlende Receiver führen zum Rollback. Die Manifestprüfung prüft auch die tatsächlichen Trigger und Credential-Revisionsfunktion.

## Kanonische Aktivierung und Recovery

Identity nimmt unter `complete` ausschliesslich den ursprünglichen Credential-Witness an. Mit demselben ursprünglichen, Body-/Pfad-gebundenen Workload-Token liest es direkt beim Auth-Service die tatsächliche gespeicherte Einladung und das weiterhin gesperrte Originalcredential. Ein vom Aufrufer behaupteter Credentialstatus genügt nicht. Originalowner, Kontext, Tenant, gewöhnliche Zielperson und deren exakte deaktivierte Version müssen weiterhin gültig sein.

Die Aktivierung verwendet den vorhandenen kanonischen User-Mutation-Kernel, seine Audit-/Outbox-Belege und den expliziten Workload-Actor `oauth-provider` mit `context:null`; keine menschliche MFA oder Administratorrolle wird für eine Maschine erfunden. Eigene SQL-Fences begrenzen die Transaktion auf Statuswechsel, exakten Subject-Link, retained Tenant-Bindung und tatsächliche Audit-Folgeereignisse. Ein unveränderliches Aktivierungszertifikat verbindet ursprünglichen Witness, User-Mutation, vollständigen damaligen Benutzerstand und konkrete Linkrevision. Der vollständige Admission-Fingerprint bindet auch die ursprüngliche Workload-Proof-ID und den damaligen tatsächlichen Rollenstand des Owners bis zum physischen Commit. Fehlende Receiver, fehlende Outbox, Scope-Ersetzung oder abgelaufene Commit-Fristen rollen die Identity-Änderungen zusammen zurück. Das zuvor separat gespeicherte Credential bleibt in diesem Fall gesperrt und wiederaufnehmbar.

Auth entsperrt erst nach einem zweiten direkten Read-only-Check des tatsächlichen Identity-Receipts. Diese Bestätigungsquelle verlangt weiterhin den unveränderten ursprünglichen Aktivierungsstand und dieselbe Linkrevision. Ein später berechtigt bearbeitetes Teilkonto wird bei Recovery nicht erneut aktiviert oder überschrieben. Die historischen Belege bleiben lesbar; ein solcher Fall verlangt Review. Es wird keine atomare Transaktion über beide Datenbanken behauptet.

Die kanonische Rollenquelle verlangt für diese tatsächliche Mitarbeiterbindung MFA, ohne eine globale Rolle hinzuzufügen. Strengere bestehende Rollenregeln behalten ihre Fristen. Die Firmenkonsolenfreigabe gilt nur für den ursprünglich erfassten Console-Client. Die zentrale OAuth-Hoheit liest den tatsächlichen Auth-Credentialstand und vergleicht ihn mit dem Sicherheitsstand aus derselben erfolgreichen Passwortprüfung. Token tragen die aktuelle Credentialrevision; Zugriffsprüfung und Refresh lesen sie erneut. MFA-Einrichtungs- und Recovery-Challenges speichern dieselbe Bindung. Die akzeptierte Mitarbeiter-Einladung muss zusätzlich mit dem originalen `employeeBinding`, der Subject-Verknüpfung und dem Tenant übereinstimmen. Eine spätere normale Profiländerung ersetzt das historische Zertifikat nicht und entzieht allein deshalb nicht die ursprüngliche Konsolenbindung.

## Zustände

| Zustand | Tatsächliche Wirkung |
| --- | --- |
| `pending` | Originaleinladung gespeichert, noch kein Credential |
| `credential_pending` | Originalcredential und Passwort-Historie gespeichert; Credential gesperrt. Eine bereits bestätigte Identity-Aktivierung kann vor dem separaten Auth-Abschluss bestehen |
| `accepted` | Tatsächlicher Identity-Receiver hat aktiviert; Auth hat dessen Originalreceipt unabhängig bestätigt und genau das ursprüngliche Credential entsperrt |
| `revoked` | Secret unbrauchbar und unfertiges Credential weiterhin gesperrt; ursprünglicher bestätigter Widerrufsauftrag samt Grund bleiben erhalten |

Widerruf verwendet exakt `{id,revision,reason,confirm:true}`. Eine Wiederholung muss denselben Auftrag verwenden. Bereits angenommene Mitarbeiter benötigen den regulären Offboarding-Prozess. Nach tatsächlichem Auth-Widerruf kann `withdraw` eine unveränderte Teilaufnahme kanonisch deaktivieren und genau ihre ursprüngliche Subject-Verknüpfung entfernen. Identity prüft dafür direkt den tatsächlichen negativen Auth-Beleg. Die Tenant-Bindung und alle historischen Ereignisse bleiben erhalten. Spätere berechtigte Änderungen werden nicht automatisch entfernt; ein Konflikt benötigt Review. Bei später gesperrtem Parent werden ausschliesslich dessen exakt belegte automatische User-Generationsänderung und die dazugehörigen kanonischen Audit-/Outbox-Belege toleriert. Eine weitere unabhängige Benutzerversion verlangt Review. Ohne ursprüngliches Aktivierungszertifikat lautet das Ergebnis `changed:false, receipt:null`.

Das widerrufene unfertige Credential bleibt gesperrt und behält Login/E-Mail und Belege. Dessen kontrollierte Namespace-Freigabe/Wiederverwendung ist **noch offen**. Der öffentliche Ablauf für Aktivierung/Widerruf/Review ist ebenfalls noch zu verbinden; diese internen Schritte laufen noch nicht automatisch über eine Oberfläche.

Die eigene `users.security_revision` steigt bei Passwort-, Sperr- oder Credential-MFA-Änderungen, nicht bei gewöhnlichen Loginzählern. Der private `state`-Leser liefert für ein bekanntes Credential nur bei gültigem, entsperrtem Konto eine aktuelle Revision; angenommene Mitarbeiterkonten müssen ausserdem ihr tatsächliches Identity-Zertifikat erfüllen. Ein neuer RS256-Reader ist auf `POST /internal/auth/credential-state` verfügbar. Zentrale Tokens ohne gespeicherte Bindung werden für bekannte lokale Konten nicht nachträglich hochgestuft. Bei unerreichbarem Auth-Reader wird die Prüfung verweigert. Bestehende lokale OAuth-Sitzungen ohne die neue Claim-Bindung müssen sich erneut anmelden; die komplette erste MFA-/Browseranmeldung und öffentliche Mitarbeiterfassade bleiben offen.

## Interner Transport und Installation

`POST /internal/auth/employee-invitations/{create,list,get,revoke,inspect,credential,activate,state}` sowie die delegierten Read-only-Callbacks `identity-source` und `revoked-source` sind im Auth-Service montiert. Identity montiert `POST /internal/identity/employee-invitations/{observe,complete,accepted-source,withdraw}`. Der Aktivierungs-Callback bei Identity prüft den ursprünglichen Auth-`activate`-Token; die Auth-Leser prüfen entsprechend den ursprünglichen Identity-`complete`-/`withdraw`-Token. Kein neuer gemeinsamer Signierschlüssel oder statischer interner Bearer wird benötigt.

Private Tokens verwenden RS256, einen tatsächlichen zentralen JWKS-Schlüssel, festes Audience/Purpose/Token-Type, exakte Operation, POST-Pfad, kanonischen Body-Hash, UUID-JTI und höchstens 30 Sekunden Laufzeit. Owner-Operationen binden zusätzlich den unveränderten menschlichen Bearer im separaten Header `X-OpenDirectory-Owner-Authorization`. Andere Operationen lehnen diesen Header ab. Der Identity-Callback validiert den ursprünglichen Operation-/Pfadvertrag auch auf dem expliziten delegierten Auth-Lesepfad. Queryparameter, API-Keys, andere Zwecke/Issuer und zusätzliche JWT-Felder werden abgewiesen. Antworten sind `no-store`.

Auth benötigt alle elf vorhandenen SQL-Dateien bis **010**, einschliesslich beider `005_*`, und den aktuellen Code. Bestehende Accounts und Einladungen bleiben beim Replay unverändert. `OIDC_ISSUER`, `JWKS_URI` und `IDENTITY_SERVICE_URL` müssen auf dieselben tatsächlichen Authorities zeigen. Beide Compose-Dateien reichen diese Werte weiter und bauen Auth jetzt vom Repository-Root; der Dockerfile kopiert die vier benötigten gemeinsamen Contracts. Auth deklariert die bereits in Identity eingesetzte JOSE-5-Version explizit. Das aktualisierte Service-Lockfile entfernt auch die verbliebenen Orphans des früher bereits stillgelegten zweiten OIDC-Issuers.

Identity benötigt zusätzlich **055** und `AUTH_SERVICE_URL` als gepinnten tatsächlichen Auth-Origin. Beide Compose-Dateien setzen ihn. Nach Replay älterer Directory-/Gruppen-/Automationsmigrationen zuletzt **055_employee_enrollments.sql** anwenden. Die Migration erweitert die vorhandenen Transaktionsfences auch auf ihre neuen Tabellen und pinnt die tatsächlich beteiligten Routinen/Trigger. Einträge entstehen nur durch den tatsächlichen Aktivierungsvorgang; bestehende Verzeichnisbenutzer werden nicht adoptiert. Keine neue Runtime-Dependency wird in diesem Schritt eingeführt.

Der generierte [OpenAPI-Vertrag](../api/openapi.yaml) **1.29.0** beschreibt die tatsächlich montierten internen Empfänger, Originalproofs, separaten Owner-Header, Witness-/Receipt-Schemas, kanonische `employeeBinding` und privaten Credential-State-Reader. Er erfindet noch keine öffentliche Einladungsroute.

## Prüfung

```sh
npm test --prefix services/core/authentication-service -- --runInBand
npm run test:credentials:integration --prefix services/core/authentication-service
npm test --prefix services/core/identity-service -- --runInBand
```

Der Auth-Native-Runner umfasst bestehende Credential-Fälle, tatsächliche gekoppelte PostgreSQL-Transitionsfälle und vier HTTP-Definitionen mit tatsächlich gestarteten Produktions-Auth-/Redis-Prozessen. Der Identity-HTTP-Teil montiert den ausgelieferten privaten Router, die tatsächlichen Source-/Receiver-Klassen und separat migriertes SQL unter einem lokalen Testserver; die beiden Dienste prüfen die ursprünglichen signierten Proofs über tatsächliche HTTP-Callbacks. Das ist kein vollständig gestarteter produktiver Identity-/OAuth-/Browserablauf. Identity führt die vier eigenen ursprünglichen Source-Fälle ausserdem im vorhandenen nativen Runner mit. [Ergebnisse und offene Grenzen](../testing/test-results.md#23-oktober-2026--kanonische-mitarbeiteraktivierung), [vollständiger Auftrag](../implementation-worklist.md).
