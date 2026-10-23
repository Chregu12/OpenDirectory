# Mitarbeiteraufnahme: interner Einladungs- und Credential-Empfang

Stand: 23. Oktober 2026. **In Arbeit, noch kein vollständiger Mitarbeiter-Eintritt.** Implementiert sind die ursprüngliche eigene Owner-Quelle, persistente Einladungen und das gesperrte Passwortkonto im tatsächlichen Authentication-Service. Öffentliche OAuth-Aufrufe, Oberfläche/CLI, kanonische Identity-Aktivierung und erste Pflicht-MFA fehlen noch. Die internen Empfänger werden ausschliesslich durch eng gebundene Issuer-Workload-Tokens aufgerufen; ein normaler Benutzer- oder App-Token erteilt diese Befugnis nicht.

## Ursprüngliche Einladung

Identity liest unter `POST /api/identity/employee-invitations` den tatsächlichen aktuellen Firmeninhaber. Der ursprüngliche menschliche Bearer und unabhängig gebundene MFA, höchstens fünf Minuten alt, sind auch für Listen, Lesen und Widerruf erforderlich. Eine globale Rolle ersetzt keine Ownership. Ein optional ausgewählter Empfänger muss aus demselben Unternehmen stammen; die Erstellung verlangt einen deaktivierten, unverknüpften gewöhnlichen Verzeichniseintrag in genau der bestätigten Version. Owner, nicht widerrufene privilegierte Rollenzuweisungen und PIM-Eligibility werden nicht als gewöhnliche Einladungsziele übernommen.

Der Create-Auftrag enthält exakt `{id,userId,userRevision,loginName,durationHours,reason,confirm:true}`. UUID und ursprünglicher Auftrag bleiben unveränderlich. `loginName` ist explizit: Verzeichnisnamen, E-Mail-Adressen und bestehende Credential-Subjects werden nicht heuristisch gleichgesetzt. Die Lease beträgt eine bis höchstens 72 Stunden. Eine bestehende Einladung derselben UUID liefert bei unverändertem Inhalt nur Metadaten; sie gibt kein zweites Secret aus. Bei verändertem Originalauftrag wird abgewiesen. Ein verlorenes Secret erfordert bewussten Widerruf und eine neue Einladung.

Die erste Antwort enthält einmalig `UUID.secret`. Gespeichert wird ein SHA-256-Hash des vollständigen zufälligen Tokens mit festem Zweck. Token, Passwort und Passwort-Anfragehash gelangen nicht in Einladungsereignisse oder Outbox. Die spätere öffentliche Fassade muss interne Witness-/Owner-Metadaten aus ihrer Empfängerantwort entfernen und darf das Secret nicht in Querystrings oder Browser-Storage ablegen; diese Fassade ist noch nicht umgesetzt.

## Gesperrtes Passwortkonto

Der Empfänger muss das Originalsecret besitzen. Authentication fragt mit einem getrennten kurzlebigen signierten Beobachtungstoken bei Identity nach, ob ursprünglicher Owner, Tenant, Kontext und exakte deaktivierte Personenversion weiterhin gültig sind. Das Passwort wird dabei nicht an Identity weitergegeben. Der damalige menschliche Token wird weder gespeichert noch als spätere Empfängersitzung ausgegeben; ein bloss abgelaufener MFA-Zeitpunkt des Owners ersetzt keinen tatsächlichen Hoheitsentzug.

Authentication prüft die tatsächliche lokale Passwortpolicy, mindestens zwölf Zeichen und höchstens 72 UTF-8-Bytes, und speichert bcrypt-Hash, erste Passwort-Historie und Einladungsbeleg in einer Transaktion. Das neue normale Credential besitzt nur `user`, keine expliziten Berechtigungen und bleibt **gesperrt**. Der Verzeichniseintrag bleibt deaktiviert/unverknüpft. Recovery prüft das ursprüngliche Passwort und legt weder ein zweites Konto an noch ersetzt sie das erste Passwort.

SQL-Guards sperren normale Passwort-/Entsperr-/Löschzugriffe auf unfertige oder widerrufene Credentials. Der Einladungsauftrag darf keine fremden Benutzer oder anderen Auth-Daten verändern. Aufgeschobene Prüfungen verlangen denselben ursprünglichen Credential-, Passwort-History-, Event- und Outbox-Commit; abgelaufene Fristen und fehlende Receiver führen zum Rollback. Die Manifestprüfung prüft auch die tatsächlichen Trigger und Credential-Revisionsfunktion.

## Zustände und verbleibende Verbindung

| Zustand | Tatsächliche Wirkung |
| --- | --- |
| `pending` | Originaleinladung gespeichert, noch kein Credential |
| `credential_pending` | Originalcredential und Passwort-Historie gespeichert; Credential gesperrt, Identity noch nicht aktiviert |
| `accepted` | Auth-Kernel kann nach unabhängig bestätigtem ursprünglichem Identity-Receipt genau dieses Credential entsperren. Der tatsächliche Identity-Receiver ist noch umzusetzen; die Native-Kernel-Prüfung verwendet dafür eine ausdrücklich ersetzte Bestätigungsquelle |
| `revoked` | Secret unbrauchbar und unfertiges Credential weiterhin gesperrt; ursprünglicher bestätigter Widerrufsauftrag samt Grund bleiben erhalten |

Widerruf verwendet exakt `{id,revision,reason,confirm:true}`. Eine Wiederholung muss denselben Auftrag verwenden. Bereits angenommene Mitarbeiter benötigen den regulären Offboarding-Prozess. Widerruf eines unfertigen Credentials behält dessen Login/E-Mail und Belege; sichere Bereinigung einer teilweise angelegten Identity-Verknüpfung und kontrollierte Wiederverwendung sind **noch offen**.

Die eigene `users.security_revision` steigt bei Passwort-, Sperr- oder Credential-MFA-Änderungen, nicht bei gewöhnlichen Loginzählern. Der private `state`-Leser liefert für dieses Originalcredential nur nach `accepted` und ohne Sperre `ready:true`. Die Bindung dieser Revision an tatsächliche OAuth-Zugriffs-/Refresh-Tokens und MFA-Challenges ist **noch umzusetzen**. Dieser Leser allein belegt keinen vollständigen Sessionwiderruf.

## Interner Transport und Installation

`POST /internal/auth/employee-invitations/{create,list,get,revoke,inspect,credential,activate,state}` sowie der delegierte Read-only-Callback `identity-source` sind im Auth-Service montiert. Identity hat den privaten Beobachter `POST /internal/identity/employee-invitations/observe`. Die vorgesehenen Identity-Receiver `complete`, `accepted-source` und `withdraw` fehlen noch; Auth aktiviert bei fehlender Bestätigungsquelle nichts.

Private Tokens verwenden RS256, einen tatsächlichen zentralen JWKS-Schlüssel, festes Audience/Purpose/Token-Type, exakte Operation, POST-Pfad, kanonischen Body-Hash, UUID-JTI und höchstens 30 Sekunden Laufzeit. Owner-Operationen binden zusätzlich den unveränderten menschlichen Bearer im separaten Header `X-OpenDirectory-Owner-Authorization`. Andere Operationen lehnen diesen Header ab. Der Identity-Callback validiert den ursprünglichen Operation-/Pfadvertrag auch auf dem expliziten delegierten Auth-Lesepfad. Queryparameter, API-Keys, andere Zwecke/Issuer und zusätzliche JWT-Felder werden abgewiesen. Antworten sind `no-store`.

Auth benötigt alle elf vorhandenen SQL-Dateien bis **010**, einschliesslich beider `005_*`, und den aktuellen Code. Bestehende Accounts und Einladungen bleiben beim Replay unverändert. `OIDC_ISSUER`, `JWKS_URI` und `IDENTITY_SERVICE_URL` müssen auf dieselben tatsächlichen Authorities zeigen. Beide Compose-Dateien reichen diese Werte weiter und bauen Auth jetzt vom Repository-Root; der Dockerfile kopiert die vier benötigten gemeinsamen Contracts. Auth deklariert die bereits in Identity eingesetzte JOSE-5-Version explizit. Das aktualisierte Service-Lockfile entfernt auch die verbliebenen Orphans des früher bereits stillgelegten zweiten OIDC-Issuers.

## Prüfung

```sh
npm test --prefix services/core/authentication-service -- --runInBand
npm run test:credentials:integration --prefix services/core/authentication-service
npm test --prefix services/core/identity-service -- --runInBand
```

Der Auth-Native-Runner umfasst bestehende Credential-Fälle, die neuen tatsächlichen PostgreSQL-Transitionsfälle und zwei HTTP-Definitionen mit tatsächlich gestarteten Produktions-Auth-/Redis-Prozessen. Die Identity-HTTP-Quelle ist in diesen zwei Fällen eine lokale Transport-Fixture mit realen Signaturen, tatsächlichen Identity-Klassen und separat migriertem SQL, kein vollständig gestarteter produktiver Identity-/OAuth-/Browserablauf. Identity führt die vier eigenen Source-Fälle ausserdem im vorhandenen nativen Runner mit. [Ergebnisse und offene Grenzen](../testing/test-results.md#23-oktober-2026--interner-employee-einladungsempfang), [vollständiger Auftrag](../implementation-worklist.md).
