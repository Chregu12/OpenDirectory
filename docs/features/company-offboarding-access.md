# Rollen und PIM beim Austritt bereinigen

Status: **Tested, begrenzter Teilprozess** — Business-Slice 18. Dieser ausdrücklich bestätigte Teilprozess erweitert den gespeicherten [lokalen Austritt](company-offboarding.md), nicht die Rechte eines Company-Owners und nicht den Abschlussumfang von WF-004. [Tatsächliche SQL-/HTTP-/Browserabnahme](../testing/test-results.md#business-slice-18-rollen-und-pim-beim-austritt).

## Benutzerweg und Berechtigungen

Im gespeicherten Austritt nach dem tatsächlichen Account-Checkpoint „Rollen und PIM beim Austritt bereinigen“ ausdrücklich öffnen. Offene oder pausierte lokale Lizenzrückgaben dürfen diesen getrennt autorisierten Schritt nicht blockieren. Alternativ steht `/offboarding-access` für unabhängig berechtigte Rollen-/PIM-Bearbeitende bereit: kanonische Benutzer-ID und ursprüngliche Vorgangs-ID eingeben und bewusst laden. Die UUIDs sind Selektoren, keine Berechtigung.

Der Server verlangt die ursprüngliche aktuelle menschliche Sitzung, denselben Home-Tenant und unabhängig belegte MFA innerhalb von 300 Sekunden. Der Benutzer muss noch vorhanden und in genau derselben ursprünglichen negativen Eligibility-Generation gesperrt sein. Selbstbearbeitung, fremde Tenants, gelöschte oder inzwischen reaktivierte Benutzer sind ausgeschlossen. Eine legitim durch Rollenentzug geänderte Authorization-Revision ist keine neue negative Eligibility.

| Bereich | Lesen | Entziehen |
| --- | --- | --- |
| Rollen | `identities.roles.read` | zusätzlich `identities.roles.manage` |
| PIM-Eligibilities | `pim.eligibilities.read` | zusätzlich `pim.eligibilities.manage` |

`users.read`, `company.apps.*` oder Company-Ownership sind keine Voraussetzung oder Ersatz für diese Rechte. Ein Owner ohne eigenständiges Rollen-/PIM-Recht erhält keinen Zugriff. Geschützte Rollen erfordern weiterhin den tatsächlichen kanonischen `admin` nach den bestehenden Kerneln; aus Ownership, Body-Feldern oder Token-Rollenbehauptungen wird kein Admin erzeugt. Reine Leser sehen echte Daten, aber keinen verfügbaren Schreibweg.

Wie bei jeder Console-Anmeldung bleibt ein tatsächlicher OAuth-Anwendungszugang erforderlich. Diese Funktion weist keine Anwendung zu und erweitert den automatischen Owner-Console-Zugang nicht. Ein separat zugelassener Operator ohne bestehende verbindliche MFA-Richtlinie richtet seinen eigenen Faktor über den vorhandenen angemeldeten Bereich „MFA / 2FA“ (`/mfa`) mit erneutem Passwortnachweis ein und meldet sich danach frisch mit MFA an. Die öffentliche Ersteinrichtung ist bewusst nur bei verpflichtender Client-/Rollenrichtlinie zulässig; dafür werden keine globalen Rechte oder gelockerten Richtlinien vergeben.

## Bestätigung und Wirkung

Die Vorschau zeigt höchstens 25 gespeicherte noch nicht widerrufene Grants pro Seite, einschliesslich abgelaufener Grants. „Noch nicht widerrufen“ bedeutet nicht automatisch „aktuell wirksam“. Gesperrte Zeilen bleiben erkennbar; nur ausdrücklich ausgewählte unterstützte Zeilen gehören zum bestätigten Manifest. Jede Zeile bindet ihre ursprüngliche UUID und einen serverseitig berechneten SHA-256 der kanonischen Grant-Row unter UTC. Es gibt keinen erfundenen numerischen Versionszähler.

1. Aktuelle Vorschau bewusst laden und den passenden Bereich wählen.
2. Die genauen Zeilen auswählen; Begründung und explizite Bestätigung eingeben.
3. Der Server prüft das gesamte Manifest read-only vor der ersten Wirkung. Geänderte Rows, geschützte Grants oder eine geänderte Kontogeneration blockieren die Vorprüfung.
4. Jeder Child verwendet den vorhandenen `DirectoryRoles.revoke` bzw. `PrivilegedActivation.revokeEligibility`, ursprünglichen Bearer und tatsächlichen Authority-Command-Checkpoint. Erfolgreicher Entzug, Audit, zwingende Pending-Outbox und zusätzlicher Parent-Beleg gehören zur jeweiligen Child-Transaktion.
5. Bei unbestätigtem Ergebnis stoppen spätere Children. Frühere echte Commits bleiben bestehen; kein fingierter verteilter Rollback.

Der bestehende PIM-Entzug kann zugehörige offene/angenommene Anträge abbrechen und aktivierte verknüpfte Rollenzuweisungen widerrufen. Diese Wirkung stammt aus der vorhandenen PIM-Hoheit, nicht aus einem zweiten direkten SQL-Schreiber. Eine neue Rollen-Vorschau ist danach erforderlich; eine zuvor angezeigte Row kann durch die echte PIM-Kaskade bereits verändert worden sein. Der alte Rollenauftrag darf solche Änderungen nicht als eigenen Erfolg umdeuten.

Ein verlorener HTTP-Erfolg ist kein Rollback. Vorschau/Historie neu lesen und nur bewusst den ursprünglichen Intent wiederaufnehmen. `already_revoked` setzt einen gültigen eigenen Original-Beleg zur genauen alten ID und Version voraus. Ein neuer Grant bleibt unberührt. Keine automatische POST-Wiederholung, stille Versionsaktualisierung oder unbeaufsichtigte Service-Account-Fortsetzung.

## API und Belege

Die vier [dokumentierten Operationen](../api/openapi.yaml) liegen unter `/api/users/{id}/company-offboarding-access`:

- `GET /capabilities` verlangt genau `workflowId` und mindestens eine tatsächliche Lesepflicht. Antwortprotokoll `companyOffboardingAccessProtocol:1`.
- `GET` verlangt `workflowId`, `kind=role|eligibility`, optional `page` und `limit=25`. Antwort enthält explizite `canRevoke`-/`blockedReason`-Werte.
- `GET /history` verwendet dieselben Selektoren und zeigt retained Originalbelege mit wirklichem Authority-Checkpoint und `deliveryStatus:pending`.
- `POST` akzeptiert nur `{workflowId,eligibilityRevision,kind,reason,confirm:true,items:[{id,version}]}` mit 1–25 eindeutigen IDs. Kein `tenantId`, Actor-, Checkpoint- oder Berechtigungsfeld.

`200` bestätigt ausschliesslich angeforderte alte Grants als `revoked`/`already_revoked`. Bei `207` ist ein Child `unconfirmed`, spätere sind `not_attempted`. Original-Authority-Verlust kann selbst die Teilantwort verhindern; tatsächliche Historie ist massgeblich. Aus Pending-Zustellung folgt kein externer Erfolg.

Identity-Migration **047** ergänzt retained Child-Belege und physische Commit-Prüfung zum unveränderten Parent aus 045. Vorhandene Rollen-/PIM-Tabellen bleiben die Datenhoheit; keine globale Rollenzuweisung, zweite Rollenliste, Änderung des Rollenvertrags oder Lizenzdatenbank entsteht. [Modell](../architecture/domain-model.md), [ADR](../architecture/architecture-decisions.md).

## Grenzen

Dieser Slice entfernt weder OU-Mitgliedschaften noch Geräte-/Provider-Zuweisungen, externe Credentials oder sämtliche Sessions. Allgemeines gruppenbasiertes RBAC, eigene Custom-Rollen/Scopes, vollständige JML-Prozesse und Betriebsabnahmen bleiben offen. Ein leerer Preview ist kein Beweis für vollständigen Rechteentzug. Die historische lokale Account-/Lizenz-Fertigmeldung wird nicht rückwirkend zu einem vollständigen WF-004.

SQL-Besitzer und migrationsberechtigte Betreiber bleiben explizite Vertrauensgrenzen. Gegen einen DDL-kontrollierenden Betreiber wird keine Abwehr behauptet. Runtime-/Operator-Logintrennung, unabhängige Retention, Datenschutzlöschung, Backup/Restore, Last-, WCAG- und produktive Sicherheitsabnahmen bleiben gesondert zu leisten. Es werden keine externen Produktivsysteme verändert.
