# Eigene Personen, Gruppen und Organisationsstruktur

Stand: 19. Oktober 2026. Dieser Slice erweitert den tatsächlich aktivierten [Company-Owner](company-activation.md), nicht eine globale Administratorrolle. Vorhandene kanonische Benutzer-/Gruppendienste werden wiederverwendet: keine zweite Verzeichnisdatenbank, Framework-Migration oder simulierte Provisionierung.

## Nutzbarer Ablauf

1. Eigene Firma registrieren, unabhängig freigeben, ausdrücklich aktivieren und mit Pflicht-MFA anmelden.
2. Unter `/organization` in der **Organisationsstruktur** eine oberste und eine untergeordnete Einheit erstellen. Eltern kommen nur aus tatsächlich geladenen eigenen Einheiten; die API prüft deren Mandantenbindung erneut.
3. Unter `/users` Mitarbeitende als echte gesperrte kanonische Datensätze erstellen. Profiländerungen und ausdrückliche Statusänderungen sind versioniert möglich.
4. Unter `/usergroups` eine leere Gruppe erstellen, ihr Profil bearbeiten und bekannte eigene Benutzer-UUIDs verknüpfen bzw. entfernen. Gruppenlöschung benötigt Bestätigung und die angezeigte Version.
5. Erneut laden: nur tatsächliche eigene Datensätze, keine Beispieldaten oder globale Ausweichsuche.

Ein Mitarbeitendendatensatz ist **kein neu provisioniertes Anmeldekonto**. Passwort, Provider-Subject-Link, MFA, Rolle und App-/Lizenzzuweisung werden nicht automatisch erzeugt. Auch `enabled:true` provisioniert keine Zugangsdaten. Eine Gruppenverknüpfung bestätigt keinen effektiven App-/Lizenzzugriff. Unabhängig regierte Mitgliedschaften behalten separate Review-Bedingungen; Company-Ownership umgeht diese nicht.

## Begrenzte serverseitige Rechte

Der aktive ursprüngliche Owner erhält genau diese zusätzlichen Berechtigungen aus seiner tatsächlichen eigenen Ressource:

- `users.read`, `users.create`, `users.update`, `users.status.manage`.
- `groups.read`, `groups.create`, `groups.update`, `groups.delete`, `groups.members.manage`.
- `ous.read`, `ous.create`; der [kanonische OU-Slice](organization-units.md) ergänzt `ous.update`, `ous.delete`, der [Membership-Slice](organization-memberships.md) zusätzlich `ous.members.manage`, ohne globale Rolle oder automatisches Provisionieren.

Bisherige eigene Profil-/Delegationsrechte bleiben bestehen. Keine globale Rolle, Rollenverwaltung, Benutzerlöschung, Session-Reset-, Geräte-, Lizenz-, Plattformprüfer- oder fremden Anwendungsrechte kommen hinzu. Die 62 Rollennamen und Schema 6 bleiben unverändert; der bestehende OU-Verwalter erhält nur die präzise zusätzliche Membership-Aufgabe, keine Personen-Profilrechte. Profildelegierte erhalten dadurch **keine** Personen-/Gruppenrechte.

Die Route-Grenze lädt die aktuelle tatsächliche Owner-Quelle nur für betroffene Verzeichnisrouten und die Capability-Antwort. Controller bestätigen Berechtigungen nochmals nach ursprünglicher Tenant-/Actor-/MFA-Prüfung im kanonischen Kontext. Behauptete `companyOwner`-/`company_permissions`-Claims ersetzen keinen Datenbanknachweis. Bestehende explizite Verzeichnisrollen behalten ihren bisherigen Weg.

Eigene Verzeichnisrechte erfordern unabhängig gebundene MFA höchstens 300 Sekunden alt. Tenant-Pause, gesperrter Owner, entfernte ursprüngliche Subject-Bindung, veränderte Authority oder fehlende Receiving-/Retained-Belege erlauben keinen positiven Fallback. Ressourcen werden aus dem tatsächlichen Actor-Home bestimmt, nicht aus einem Browser-Tenant-Selektor.

## API und Persistenz

[OpenAPI 3.1](../api/openapi.yaml), aktuell Version 1.6.0, dokumentiert die tatsächlich verwendeten Benutzer-/Gruppen-/OU-Pfade und `/api/identity/access`, nicht sämtliche Legacy-APIs. Der ursprüngliche Slice 7 verwendete Migrationen bis 041 ohne zusätzliche Migration; die anschliessenden [OU-Funktionen](organization-units.md) benötigen 042 und koordinierten aktuellen Identity-/Web-Code. Creation behält die Original-Actor-/Tenant-Proof-Grenze aus 026, Benutzer-/Gruppenänderungen die bestehenden 027/028-Kernels. OU-Erstellung ergänzt einen retained Originalproof vor dem Write. Datensatz, Ownership, tatsächliche Audit-Belege und Pending-Outbox werden nicht durch eine vereinfachte Schreibabkürzung ersetzt. Ursprünglicher Bearer, Tenant-Inkarnation und physische Originalfrist bleiben bis Commit relevant. `If-Match` verhindert veraltete Änderungen.

Benutzerlisten sind serverseitig paginiert. Gruppen-/OU-Listen haben weiterhin eine harte Grenze von 10'000 Datensätzen, keine Pagination; zu grosse Listen schlagen fehl statt als vollständig zu erscheinen. OU-Hierarchien sind auf 256 Ebenen begrenzt. Bereits die Erstellung prüft die tatsächliche eigene Ahnenkette unter Share-Locks und verweigert einen 257. Level sowie zyklische/inkohärente Eltern. Die Oberfläche verwirft doppelte, unvollständige oder zyklische Antworten. Unbestätigtes Speichern erzeugt keinen Erfolg und keine automatische Wiederholung.

## Nachweis und offen

[Slice-7-Abnahme](../testing/test-results.md#business-slice-7-eigene-verzeichnisverwaltung): zwei tatsächliche Firmen, lokale CRUD-/Mitgliedschaftsbelege, verweigerte fremde Zugriffe, erfundene Owner-Claims, später Bearer-Entzug/Rollback und physische Proof-Frist am SQL-Commit. Ein echter frischer Chrome registriert/aktiviert eine Firma und erstellt danach zwei hierarchische Einheiten, zwei gesperrte Mitarbeitende und eine Gruppe mit beiden Verknüpfungen, ohne globale Rolle.

**Fortsetzung:** Die früheren Legacy-OU-PUT/DELETE-Handler sind durch den [kanonischen OU-Slice](organization-units.md) mit tatsächlichen Tenant-/Versions-/Audit-/Commit-Grenzen ersetzt. Der [Membership-Slice](organization-memberships.md) ergänzt echte mehrfache Benutzer-OU-Beziehungen, berechtigte Namenssuche und ausdrücklichen Entzug. Aktive Mitglieder verhindern OU-/Benutzerlöschung. Vollständige Organisations-/Scope-Governance, Rollen-/Blueprint-/Lizenzvererbung und verbundenes JML bleiben offen; das ist keine vollständige SaaS-Isolation.

Weiterhin fehlen vollständige eigene Rollen-/Scope-Governance, zusätzliche Owner/Transfer, Employee-Credential-Onboarding, zusammenhängende JML-/Geräte-/Blueprint-/Lizenzprozesse, übrige Business-Domains und Produktionsabnahme. Die bekannten 17 TypeScript-Diagnosen sind nicht behoben. Keine externe Produktivschreiboperation, kein Deployment, Commit oder Push ist Teil dieses Slice.
