# Eng begrenzte Firmenprofil-Delegation

Stand: 19. Oktober 2026. Ein bestehender kanonischer Administrator oder der tatsächlich aktivierte eigene [Company-Owner](company-activation.md) kann einer anderen Person im eigenen Unternehmen zeitlich begrenztes **Lesen und Bearbeiten des Firmenprofils** erlauben. Die Person erhält keine globale Administratorrolle, keine Benutzer-/Gruppen-/Rollenverwaltung und keine Geräte- oder Lizenzrechte. Diese Delegation ist kein vollständiger Erstadministrator-/Registrierungsprozess oder allgemeines Rollenmodell.

## Tatsächlicher Benutzerweg

1. Als vorhandener Administrator `/organization` öffnen und nötigenfalls regulär MFA einrichten/erneut anmelden.
2. Im Bereich **Firmenprofil delegieren** die kanonische Benutzer-UUID aus Personen, Laufzeit von 60 bis 28'800 Sekunden und eine Begründung angeben. Nur eine andere aktivierte Person im selben Tenant kann eine neue Berechtigung erhalten.
3. **Profilberechtigung erteilen** führt den echten Serverbefehl aus. Erst eine passende Befehlsantwort und der anschliessend neu gelesene tatsächliche Bestand bestätigen Erfolg. Es wird kein beliebiger Rollen-/Permission-/Tenant-Parameter akzeptiert.
4. Die betroffene Person meldet sich erneut an. Die alte kanonische Autorisierung wurde invalidiert, auch wenn sie vorher nur gewöhnliche Benutzerrechte hatte. Ohne frische verifizierte MFA erhält sie beim Profilzugriff 428 und kann das vorhandene `/mfa`-Setup verwenden.
5. Danach kann sie ausschliesslich das eigene Firmenprofil lesen und mit den bestehenden Versions-/MFA-/Audit-Regeln bearbeiten. Sie sieht keinen Bereich zum Weiterdelegieren.
6. Für einen Widerruf wählt der Administrator eine tatsächlich vorhandene Zuweisung, begründet den Vorgang und bestätigt ihn separat. Widerruf ist auch für einen inzwischen inaktiven Benutzer möglich; neue Berechtigungen für inaktive Benutzer sind verboten.

Die Seite zeigt höchstens die neuesten 100 Zuweisungen mit tatsächlichem Zustand Aktiv, Abgelaufen, Widerrufen oder Benutzer inaktiv. Eine abgeschnittene ältere Historie wird ausdrücklich angezeigt. Der UUID-Empfänger ist ein bewusst einfacher aktueller Eingabeweg, kein fertiger Benutzer-Picker oder vollständiger Audit-Explorer.

## Vertrauens- und Ablaufgrenzen

- Der Owner stammt aus ursprünglichem menschlichen Actor, Subject-Link und kanonischer Tenant-Eigentümerschaft. Bekannte fremde UUIDs werden vor einem fremden Benutzer-Lock abgewiesen. Es gibt keine mandantenübergreifende Delegation.
- Nur die tatsächlich gehaltene kanonische Administration oder der aktuelle eigene Company-Owner darf delegieren; der neue Empfänger erhält lediglich `organization.read` und `organization.manage`. Selbstvergabe/-widerruf wird nicht zugelassen. Die erste eigene Owner-Profilanmeldung ist inzwischen separat implementiert, vollständige Company-Administration bleibt offen.
- Das bestehende Live-Identity-Protokoll bleibt Schema 6 mit demselben 62-Rollen-Katalog. Die fachliche Profilberechtigung ist **kein zusätzlicher globaler Token-Rollenstring** und kein Cutover auf die versiegelte eigene Rollenquelle. Die Berechtigung wird serverseitig aus eigenen aktuellen SQL-Datensätzen und ihren tatsächlichen Belegen berechnet, nicht aus einem vom Client behaupteten Scope.
- Delegiertes Lesen und jedes Speichern benötigen verifizierte MFA mit höchstens 300 Sekunden Alter. Ein gewöhnlicher Login bleibt für das Einrichten von MFA nutzbar, ist aber keine erfolgreiche privilegierte Profilanmeldung. Es wird keine neue allgemeine Pflicht-MFA-Rolle oder globale Anmeldepolicy behauptet.
- Neue Grants laufen spätestens nach acht Stunden ab. Ein delegierter Profil-Write erhält zusätzlich zum ursprünglichen Token-/MFA-Ende das tatsächliche Grant-Ende als physische SQL-Commit-Frist. Eine beim Lookup noch aktive, beim Commit abgelaufene Berechtigung genügt nicht.
- Grant/Widerruf sperren Actor und eigenes Ziel in kanonischer Reihenfolge, invalidieren die kanonische Zielautorisierung und schreiben unveränderliche Historie/Pending-Outbox gemeinsam mit dem finalen Original-Bearer-Checkpoint. Der Actor kann nicht durch einen internen Ersatz-Token ersetzt werden.
- Profil-Write und Widerruf serialisieren auf demselben tatsächlichen Zielbenutzer. Nach committed Widerruf ist der alte Kontext ungültig; nach Neuanmeldung fehlt die entzogene Profilberechtigung. Reine Zeitabläufe werden bei jedem Zugriff neu berechnet, nicht durch einen angeblich bereits ausgeführten Scheduler simuliert.
- Kein automatischer Write-Retry: doppelte aktive Grants oder bereits widerrufene IDs ergeben 409. Das ist kein allgemeiner Idempotency-Key-/Replay-Dienst. Bei unbestätigter Antwort wird der erfasste Formularbefehl entfernt, bis ausdrücklich neu geladen wird.

## API und Datenmodell

| Methode | Pfad | Tatsächliche Wirkung |
| --- | --- | --- |
| GET | `/api/identity/organization/delegations` | Neueste eigene Grants mit Widerrufs-/Ablaufstatus, `truncated` und aktueller MFA-Schreibfähigkeit |
| POST | `/api/identity/organization/delegations` | `userId`, `durationSeconds`, `reason`; unabhängiger eigener Grant, Autorisierungsinvalidierung, Event/Pending-Outbox |
| POST | `/api/identity/organization/delegations/{id}/revoke` | Explizite immutable Grant-ID plus `reason`; unabhängiger append-only Widerruf mit Autorisierungsinvalidierung |

Alle Antworten sind `no-store`. Der vorhandene Zugriffs-Metadatenreceiver meldet `organizationDelegationProtocol: 1` und berechnet den tatsächlichen zusätzlichen Profilzugriff serverseitig. Query-Selektoren, beliebige Scopes/Rollen und unbekannte Body-Felder sind nicht unterstützt. Der [generierte OpenAPI-Vertrag](../api/openapi.yaml) beschreibt diese tatsächlich implementierten Pfade und Fehlercodes.

Migration `038_organization_delegations.sql` ergänzt vier normalisierte Tabellen: Grants (`identity_organization_delegations`), separate Widerrufe (`identity_organization_delegation_revocations`), ursprüngliche Befehlsereignisse (`identity_organization_delegation_events`) und Pending-Outbox (`identity_organization_delegation_outbox`). UUID-/Tenant-/User-FKs, eindeutiger Widerruf je Grant, eindeutiges Ereignis je Transaktion, begrenzte Zeitwerte und tatsächliche Commit-Prüfungen verhindern einen bloss im Browser gespeicherten Zustand. Grants werden nicht still überschrieben oder als globale Rollen gespiegelt.

Fehlende Receiving-Guards oder positive Grant-Belege machen den Zugriff unverfügbar; plausible IDs allein reichen nicht. Fremde Bearer-Daten werden nicht geloggt, nur der Token-Identifier gehasht. Die neuen Tabellen nehmen an den bestehenden Stage-/Seal-/Checkpoint-/Source-Set-/Profil-No-Effects-Fences teil. Das ist wie der übrige Identity-Stack weiterhin von der tatsächlichen Datenbank-Owner-Rolle abhängig, kein fertiges Least-Privilege-DB-Rollenmodell. Offline-Owner können ausserhalb von Anwendungsbefehlen weiterhin die vorhandenen kontrollierten Test-/Administrations-Resets ausführen; die Trigger sind kein Offhost-Archiv.

## Abnahme und offen

[Testresultate](../testing/test-results.md#business-slice-3-begrenzte-profildelegation) grenzen die echten SQL-, signierten Gateway- und Browser-Nachweise ab. PostgreSQL-Tests beobachten tatsächliche Locks, physische Ablaufzeit und Rollbacks; der reale Browser richtet auch für den normalen Empfänger MFA ein, bearbeitet das Profil ohne Adminrolle und widerruft den tatsächlichen Zugriff.

Nicht enthalten: Unternehmensregistrierung/Erstadministrator, beliebige oder gruppenbasierte Organisationsrollen, OU-Scopes, volle Company-Administration, PIM-/Review-Governance für diese fachliche Delegation, weitere Device-/Lizenzrechte, allgemeiner Policy-/Rollenquellen-Cutover, vollständige History-Pagination/Export, Event-Auslieferung, Offhost-Aufbewahrung, Last-/Backup-/Restore-Abnahme oder Produktivdeployment. `pending` bedeutet weiterhin nicht zugestellt.
