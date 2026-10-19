# Architekturentscheidungen

[ADR 024: eigene Blueprint-Aggregate statt globaler Rollenabkürzung](adr-024-company-blueprints.md) ergänzt tatsächliche eigene Entwürfe, unveränderliche lokale Freigaben und explizite Wiederherstellung ohne neue globale Policy-/Lizenzhoheit.

[ADR 023: konservative Blueprint-Vorschau ohne neue Hoheit](adr-023-blueprint-preview.md) ergänzt den bestehenden versionierten Policy-/Blueprint-Pfad. Kein neues Datenmodell oder stillschweigend aktivierter Company-Rollenvertrag.

## ADR-001: Bestehenden Stack erhalten

Status: beschlossen. Next.js/React/TypeScript und die vorhandenen Node-/Express-/PostgreSQL-Module bleiben die Grundlage. Kein Laravel-/Vite-Zweitprojekt und keine zusätzliche Datenbank für schon kanonisch vorhandene Benutzer, Gruppen oder Lizenzen.

Begründung: Vorhandene Geschäftslogik und reale Integrations-/Security-Tests sind wertvoller als ein paralleler Neubau. Neue Business-Module brauchen klare Datenhoheit und Verträge, aber nicht automatisch einen weiteren Prozess.

## ADR-002: Apple-inspiriertes Produkt, keine vorgetäuschte Apple-Plattform

Status: beschlossen. Eigenes Branding, eigene UI-Komponenten und lokale Geschäftsprozesse. Echte Apple-/MDM-/Marketing-/Payment-Effekte ausschliesslich über dokumentierte, autorisierte und separat getestete Adapter.

Begründung: Inventarisierung, MDM-Zuweisung, Befehlsannahme und tatsächliche Geräteausführung sind unterschiedliche Zustände. Eine lokale Datenbank kann weder eine Apple-Karten-Veröffentlichung noch eine Geräte-Löschung bestätigen.

## ADR-003: Vertikale Prozesse vor weiterer Infrastruktur

Status: beschlossen. Erst Organisationsprofil/Onboarding, dann Mitarbeitende/Geräte/Blueprints/Lizenzen als demonstrierbare Workflows. Vorhandene Identity-Sicherheitslücken bleiben verbindliche Gates, werden aber nicht mit einer fertiggestellten Business Capability verwechselt.

Begründung: Ein zusätzlicher privater SQL-Entwurf oder eine abstrakte Provider-Schicht allein macht die Plattform nicht nutzbar. Der unvollständige, in dieser Entwicklungsarbeit nicht angewendete Entwurf `037_owned_policy_revisions.sql` wurde am 19. Oktober 2026 aus dem automatischen Migrationspfad genommen. Die neue Migration `037_organization_profiles.sql` und der dazugehörige nutzbare Read/Update-Prozess erweitern die Grundlage bis 036, ohne alte Namespace-/Quellenbelege umzuschreiben oder bestehende Datenbankstände zurückzusetzen. Das ist kein aktiver Rollenquellen-Cutover.

## ADR-004: Sichtbare Unverfügbarkeit statt Scheindaten

Status: umgesetzt für die Standortansicht. Ohne Standort-Backend werden weder erfundene Standorte/Gerätezahlen noch Browser-only-Speichern oder funktionslose Export-/Importaktionen angeboten.

Begründung: Der neue Master-Prompt untersagt erfundene Produktivdaten und simulierte Erfolge. Andere Prototype-/Demo-Ansichten benötigen dieselbe Prüfung; diese Entscheidung behauptet nicht deren vollständige Bereinigung.

## ADR-005: Ponytail als Skill, keine automatischen Hooks

Status: installiert. `DietrichGebert/ponytail`, `skills/ponytail`, geprüfter Commit `09c434ab73ca43761c5d8b0c5d341926c2fba710`. Installation in den persönlichen Codex-Skills, keine Änderung fremder Projektinstruktionen und keine Lifecycle-Hooks oder zusätzlichen Agent-Loops.

Anwendung: kleinste vollständige Änderung, vorhandene Komponenten wiederverwenden, keine neue Dependency für wenige Zeilen. Sicherheit, Validierung, Fehlerbehandlung, Barrierearmut und erforderliche Tests werden nicht gestrichen. Der Skill ist eine Arbeitsweise, kein Bestandteil der SaaS-Laufzeit und kein zusätzlicher Integrationsprovider.

## ADR-006: Fachliche Profildelegation statt globaler Adminrolle

Status: umgesetzt für die eng begrenzte Aufgabe Firmenprofil lesen/bearbeiten. Neue Company-Bootstrap-Identitäten dürfen nicht einfach die bestehende globale `admin`-Rolle bekommen. Als erforderlicher erster Baustein kann vorhandene Administration einen eigenen normalen Benutzer für höchstens acht Stunden ausschliesslich zum Firmenprofil berechtigen, mit frischer MFA, tatsächlicher Autorisierungsinvalidierung und append-only Widerruf.

Der vorhandene 62-Rollen-/Schema-6-Vertrag und unveränderliche Owned-Policy-Basen bleiben unberührt; kein neues Token-Rollenwort dient als Abkürzung. Der Identity-Service berechnet diese fachliche Ressourcenberechtigung aus tatsächlichen eigenen Grant-/Event-/Pending-Outbox-Zeilen. Andere Receiver sehen daraus keine Benutzer-, Rollen-, Geräte- oder Lizenzrechte. Bestehende Original-Bearer-/Checkpoint-, Profilversions- und Commit-Frist-Prüfungen werden wiederverwendet; kein neues Framework, Identity-Backend oder Repository-Abstraktionsgerüst ist nötig.

Grenze: Das ist noch kein vollständiger Company-Administrator, keine öffentliche Registrierung, keine allgemeine Custom-Role-/PIM-Engine und kein eigener aktiver Rollenquellen-Cutover. Auch DB-Owner-Abhängigkeit, Event-Auslieferung und vollständige Audit-Retention bleiben offen. Siehe [tatsächlicher Benutzerweg und Datenmodell](../features/organization-delegations.md).

## ADR-007: Ungebundene Registrierung ist ein Pending-Proof, kein Access-Token

Status: umgesetzt für die credentialgebundene Vormerkung. Eine neue Firma hat noch keinen aktiven Tenant-Human-Kontext; ein bestehender Benutzer kann wegen unveränderlicher Home-Bindung nicht einfach in einen neuen Tenant umgehängt werden. Deshalb überprüft der vorhandene Credential-Provider das bestehende Konto, und der vorhandene Issuer signiert einen separaten, methoden-/pfad-/inhalts-/subjectgebundenen Workload mit höchstens 30 Sekunden Laufzeit. Der Browser bekommt ihn nicht. Normale API-Tokens oder Provider-Rollenbehauptungen ersetzen diese Admission nicht.

Der private Owner-Receiver legt nur eine neue gesperrte Komponente und echte Pending-Historie an, ohne die alte Offline-Review-Grenze als angebliche menschliche Freigabe zu missbrauchen. Ein unveränderlicher Request-Key mit kanonischen Belegen und tatsächlichen Locks liefert Idempotenz/Status-Recovery; keine Fake-Aktivierung und keine zweite Passwortdatenbank werden eingeführt. Feature-Flag standardmässig aus, native statische BFF-Routen vor generischen Rewrites, gemeinsame Profilfelder/-Validierung statt einer zweiten Formularlogik.

Grenze: Ein geeignetes Provider-Konto muss schon existieren. Account-Signup, externe Unternehmensprüfung, technische Aktivierung, eigene dauerhafte Company-Owner- und Console-Anwendungsberechtigung, MFA und erste Anmeldung sind weiterhin nötig. Die spätere interne Prüfentscheidung nach ADR-008 ist kein Ersatz für diese Schritte oder den aktiven eigenen Rollenquellen-Cutover. Siehe [implementierter Prozess](../features/company-registration.md).

## ADR-008: Plattformprüfung ist eine explizite Einzelfähigkeit, keine globale Adminrolle

Status: implementiert für interne Anträge. Die feste 62-Rollen-/Schema-6-Quelle wird nicht still erweitert. Ein versioniertes, offline vom tatsächlichen SQL-Owner bestelltes Prüferregister verleiht ausschliesslich `company.registrations.review`. Serverprüfung bei jedem Zugriff, ursprünglicher Human-Context, aktuelle MFA, echte Quellen-/Event-/Outbox-Belege und atomare Autorisierungsinvalidierung bei Bestellung/Widerruf ersetzen eine Token-Rollenbehauptung. Normales `admin` reicht nicht. Es wird kein zweites allgemeines RBAC-Framework eingeführt.

Der fachlich notwendige mandantenübergreifende Zugriff ist auf Registrierungsdaten und die einmalige, immutable interne Entscheidung begrenzt. Der Ziel-Tenant steht im Entscheidungsereignis; die Original-Authority-Command-Prüfung und der finale Checkpoint bleiben im eigenen Management-Tenant des Prüfers. Derselbe kanonische User-Lock serialisiert mit dem Entzug der Prüferbestellung. Die vorhandenen Original-Proof-/Deadline-/No-effects-Grenzen werden nicht global gelockert. Freigabe ändert keine kanonischen Pending-Ressourcen; der öffentliche Status kann den tatsächlichen Entscheidungszustand ohne interne Gründe oder Prüfer-IDs lesen.

Grenze: Keine technische Aktivierung, kein externer Unternehmensnachweis, kein vollständiger Company-Owner, keine Outbox-Auslieferung, kein neues Least-Privilege-DB-Loginmodell. Siehe [Benutzerweg, Offline-Befehl und Commit-Grenzen](../features/company-registration-reviews.md).

## ADR-009: Der freigegebene Antragsteller aktiviert nur seine eigene Firma

Status: implementiert als begrenzter eigener Owner-/MFA-/Console-Prozess. Die unabhängige Review-Entscheidung ist eine Voraussetzung, kein implizites Plattform-Aktivierungsrecht. Der originale Credential-Subject bestätigt erneut seine Identität und ausdrücklich die Aktivierung. Ein eigener kurzlebiger inhaltsgebundener Issuer-Proof autorisiert nur die unveränderte ursprüngliche neue Komponente; der SQL-Commit erzeugt tatsächliche Aktivität, Initialprofil, unveränderlichen eigenen Owner-Nachweis und passende Audit-/Pending-Outbox-Belege. Es wird kein fehlender menschlicher Rollen-Checkpoint vorgetäuscht.

Der bisherige 62-Rollen-/Schema-6-Vertrag bleibt erhalten. Der tatsächliche Owner erzwingt kanonisch MFA für alle Clients/Scopes und erhält serverseitig nur eigene Profil-/Profildelegationsrechte. Die konfigurierte bestehende geschützte vertrauliche Console kann ihren begrenzten Zugang über einen separaten privaten aktuellen Owner-Source ableiten. Keine allgemeine permanente App-Zuweisung oder globale Rolle wird als Bootstrap-Abkürzung erzeugt. Ein neuer Browser braucht dazu keinen erfundenen lokalen Legacy-Onboarding-Abschluss.

Grenze: keine vollständige Company-Administration, keine weiteren App-/Lizenzrechte, kein Account-Self-Signup oder externer Firmenbeweis, keine allgemeine aktive eigene Rollenquelle. [Implementierter Benutzerweg und API-Grenzen](../features/company-activation.md).

## ADR-010: Eigene Verzeichnisadministration aus der tatsächlichen Owner-Ressource

Status: implementiert als begrenzter [Personen-/Gruppen-/OU-Slice](../features/company-directory.md). Die in ADR-009 zunächst nur für Profile benutzte tatsächliche Owner-Quelle gibt nun zusätzlich einen festen eigenen Verzeichnisumfang frei. Der bestehende 62-Rollenvertrag wird nicht um eine globale Company-Admin-Aliasrolle erweitert. Profildelegationen bleiben ausschliesslich Profildelegationen.

Metadaten und Route-ACLs beziehen aktuelle Rechte aus der tatsächlichen eigenen Datenbankressource. Kanonische Controller bestätigen sie nach Original-Actor-/Tenant-/MFA-Prüfung erneut. Creation und Benutzer-/Gruppenänderungen verwenden dieselben bestehenden 026/027/028-Receiving-/Commit-Kernels, statt einen zweiten vereinfachten CRUD-Pfad zu eröffnen. Neue OU-Kinder halten Share-Locks auf der geprüften eigenen Ahnenkette und dürfen die unterstützten 256 Ebenen nicht überschreiten. Foreign-/zyklische oder während des Lockens inkohärent gewordene Ketten erzeugen keinen neuen Namespace.

OU-Änderung/-Löschung erhält der neue Owner nicht: vorhandene Legacy-Handler besitzen noch keinen gleichwertigen Mutation-/ETag-/Audit-Vertrag. Deren Ersatz und Benutzer-OU-Mitgliedschaften sind die nächste notwendige Arbeit, keine als erledigt erklärte Organisations-Governance. Employee-Credentials, eigene Rollen-Scopes, App-/Geräte-/Lizenzverteilung und die allgemeine aktive eigene Rollenquelle bleiben separat offen.

## ADR-011: Ein kanonischer OU-Schreibpfad und eine gemeinsame Tenant-Tree-Grenze

Status: implementiert als [begrenzter OU-Slice](../features/organization-units.md). Die in ADR-010 bewusst nicht freigegebenen Legacy-PUT/DELETE-Handler werden ersetzt, nicht mit einem Owner-Bypass versehen. Es gibt einen serverseitigen Versionsvertrag und einen gemeinsamen Tree-Advisory-Lock für Creation, Update, Move und Retirement. Der resultierende vollständige eigene Baum wird zusätzlich im SQL-Commit geprüft; Parallelität darf keine Zyklen oder stille Kind-Umhängung erzeugen.

Ein unveränderlicher menschlicher Command-Origin wird vor der Mutation gespeichert und mit genauem Effekt, ursprünglicher Frist und Pending-Outbox gebunden. Für OU-Erstellung bleibt der ursprüngliche Proof vor dem Namespace-Write dauerhaft bis Commit referenzierbar; dadurch kann ein gelöschtes lokales GUC keine erfolgreiche bare Creation vortäuschen. UTC-normalisierte Row-/gemeinsame Rollensnapshots vermeiden einen zeitzonenabhängigen Proof-Vergleich ohne Belege zu entfernen.

Die eigentliche Tenant-Owner-Ressource erteilt nur die zwei zusätzlichen eigenen OU-Rechte, nicht eine globale Rolle. Legacy-Caller müssen exakte ETags übernehmen. Mehrfache Benutzer-OU-Mitgliedschaften und ihre abhängigen Entzüge sind ein eigenes relationales Domain-Feature, keine Umdeutung des bisherigen Department-Freitexts. Allgemeine eigene Rollenquelle, DB-Login-/Retention-/Produktionsabnahme bleiben offen.

## ADR-012: Aktive normalisierte OU-Mitgliedschaften, vorhandener OU-Commit-Vertrag

Status: implementiert als [begrenzter Membership-Slice](../features/organization-memberships.md). Eine aktive Beziehung besitzt eine eigene UUID und exklusive Kombination aus OU/User. Tatsächliche Tenant-Hoheit wird unabhängig von den einzelnen FKs geprüft. Kontrolliertes Unlink entfernt nur die aktive Row, erhält aber die exakte ursprüngliche Inkarnation im bestehenden unveränderlichen OU-Event-Proof. Historische IDs werden nicht wiederverwendet. Aktive Abhängigkeiten verhindern Benutzer-/OU-Löschung; keine Kaskade und keine stillschweigende Migration anderer Zuweisungen.

Membership-Änderungen verwenden den vorhandenen Tenant-Tree-Lock, stabil sortierte User-Locks, exakte OU-ETags und denselben Original-Actor-/Frist-/Deferred-Commit-Kernel. Ein zusätzlicher Row-/Commit-Receiver bindet den wirklichen Link; alle älteren No-effects-/Truncate-Grenzen gelten weiter. Dadurch entstehen kein separater vereinfachter Berechtigungsweg und keine zweite Outbox.

`ous.members.manage` erlaubt genau diese Aufgabe. Das separate `users.read` kontrolliert die tatsächliche Profilprojektion und Namenssuche; ein OU-Verwalter erhält es nicht implizit. Keine Department-Uminterpretation, Rollen-, Blueprint-, Geräte- oder Lizenzvererbung. Diese verbundenen Geschäftsprozesse und die vollständige Scope-/Retention-/Produktionsabnahme bleiben offen.

## ADR-013: Ein echter Inventory-only-Receiver statt Legacy-Erfolgen

Status: implementierter [begrenzter Device-Slice](../features/device-inventory.md). Device-Service und dessen vorhandene PostgreSQL-Tabelle behalten die Datenhoheit. Der normale Runtime-Einstieg wird durch eine kleine reale Express-Inventar-API ersetzt, nicht durch eine zweite Datenbank im Identity-Service. Der bisherige Einstieg besitzt eine fehlende Datenbankmanager-Abhängigkeit, In-memory-Fallbacks und unbestätigte Remote-Effekte; diese sind keine Wiederverwendungsgrundlage für positive Business-SaaS-Belege. Alte Dateien/Daten bleiben erhalten, aber der produktive neue Einstieg bietet ausschliesslich nachgewiesene lokale Funktionen an.

Tenant-Hoheit entsteht aus der originalen aktuellen Identity-Quelle, nie aus Requestfeldern oder pauschalen Rollenclaims. Original-Owner bzw. kanonisches eigenes Home-Admin, Pflicht-MFA, exakte Ziel-Snapshots und SQL-Commit-/Deadline-/Audit-/Pending-Outbox-Verträge verbinden die beiden vorhandenen Dienste. Das Gateway muss vor Passthrough den neuen Receiver bestätigen. Zusätzliche globale Rollen oder vermeintliche MDM-/Lizenzrechte sind keine Abkürzung.

Aktuelle exklusive Zuweisungen und retained frühere Beziehungen liegen im Device-Service. Cross-Database-FKs oder sofort atomare verteilte Benutzerlösch-/Revoke-Garantien werden nicht behauptet. Ziel-Snapshots sind keine zukünftige Identitätsgarantie und vergeben keinen Zugang. Weitere Lifecycle-/JML-/Provider- und Datenschutz-/Retention-Verträge bleiben offen; alle beteiligten Images benötigen koordinierten Rollout.

## ADR-014: Kanonische Home-Tenant-Quellen vor eigener Firmen-Lizenzverteilung

Die bisherigen positiven und negativen Lizenz-/Policy-Snapshots brauchen dieselbe tatsächliche Tenant-Grenze; bekannte UUIDs und kanonisches globales `admin` dürfen keine fremde Eligibility oder Rollenbelege projizieren. Eine gemeinsame Boundary vor den vorhandenen Formatierern prüft ursprünglichen Bearer, aktuelle Pflicht und retained Zielhoheit. Self-only-Belege bleiben minimal; kontrollierter Gruppenrefresh ist die einzige schreibende Quelltransaktion. Ein eigener Company-Owner wird nicht zum globalen License-Administrator.

Dedizierte maschinelle Benutzerquellen benötigen zusätzlich eine bewusst vom tatsächlichen SQL-Owner bestellte, versionierte `(issuer,client,tenant,clientRevision)`-Bindung mit unveränderlicher Tenant-Herkunft. Eigene bestätigte negative Zustände bleiben für kontrollierten Entzug lesbar. Keine Umdeutung von Graph-Tenant, Ziel-UUID oder Resource-Lease als Business-Tenant-Hoheit. Bestehende Group-Source-Consents verlangen nun ebenfalls eigene Ersteller-/Gruppenhoheit und stabile beobachtete Ziel-Tenant-Inkarnation.

Ein zwingender Receiver-Header verhindert stille Kommunikation mit alten ungescopten Readers. Das ist ein koordinierter Protokollwechsel, keine Erweiterung von DTO-, Rollen-, Scope-/PIM- oder Allokationsrechten. [Vertrag, CLI, Migration und Grenzen](../features/tenant-license-sources.md). Eigene Firmen-App-/Pool-Verteilung sowie durchgängige JML-/Retention-/DB-Login-/Produktionsabnahme bleiben offen.

## ADR-015: Firmenpools verwenden den bestehenden Allocator und eine explizite eigene Hoheit

Der [begrenzte Firmen-Lizenzkatalog](../features/company-licenses.md) ergänzt nullable unveränderliche Business-Hoheit am vorhandenen Pool und Subject-Spiegel, statt einen zweiten Lizenzbestand aufzubauen oder Company-Owner zu globalen Lizenzmanagern zu machen. Der ursprüngliche Live-Owner-/Home-Admin-Source und dessen eigene Zielprojektion sind von Legacy-Snapshot-Duties getrennt. Der 62-Rollenvertrag bleibt erhalten.

Eigene Pool-/Versionsprüfung muss vor Eligibility und deren möglichen Side Effects stattfinden. Neue Company-Eligibility darf keinen globalen Benutzer-Reconciliation-Pfad ausführen. Legacy-Listen, beliebige Child-ID-Lookups, Governance, Worker und Error-Upserts müssen neue Business-Ressourcen ausdrücklich ausschliessen; eine Filterung nur in der neuen Oberfläche reicht nicht. Shared Subject-Adoption braucht tatsächliche eigene Quelle und vollständig leeren Legacy-Zustand, keinen stillen Reset.

Originale Command-Admission und wirkliche SQL-Effektbelege umschliessen die bestehenden Source-/Grant-/Projektions-/Kapazitäts-/Audit-Regeln. Retained finale Events und Pending-Outbox sowie physische Deadline sind obligatorisch. Ein Company-Kontext ersetzt keinen delegierten Scope. Bereits anders governierte Pools werden kontrolliert abgewiesen, nicht passend umkonfiguriert. Der erste Weg ist endliches Per-User ohne Ablauf, Gruppen, Provider oder automatische Leaver-Wirkung; die vollständige Company-Governance und BR-005 bleiben offen.

Identity und Policy bleiben eigenständige Hoheiten; keine Cross-DB-FKs oder unmögliche distributed Commit-Zusage. SQL-Owner-Vertrauen, Runtime-/Operator-Logintrennung, Off-Host-Retention, Datenschutz-/Idempotenz-/Produktionsabnahmen sind ausdrücklich nicht erledigt. Bestehende NULL-Lizenzdaten werden nicht automatisch nachträglich einem Tenant zugeordnet.

## ADR-016: Kontrollierte Mitarbeiter-Lizenzrückgabe ohne zweiten Allocator

Die [Sammelrückgabe](../features/company-licenses.md#kontrollierte-lizenzrückgabe-beim-austritt) komponiert ausschliesslich den vorhandenen versionierten Einzelentzug. Eine echte paginierte Vorschau erfasst höchstens 25 eigene Pool-/Assignment-Inkarnationen; das gesamte Manifest wird vor dem ersten Schreiben auf Poolhoheit, Version, unterstützte Governance und aktuelle Zuweisung geprüft. Anschliessend muss die ursprüngliche eigene Benutzerquelle tatsächlich gesperrt oder retained gelöscht sein und für jeden Einzelschritt unverändert bleiben.

Keine neue Datenbanktabelle, globale Rolle, automatische Worker-Autorität oder stillschweigende neue Lizenzzuweisung entsteht. Jeder bestehende Allocator-Commit behält Originalproof, Revision, Audit und Pending-Outbox. Die servergenerierte Correlation-ID verbindet die Einzelschritte. Bei spätem Fehler bleiben frühere bestätigte Commits bestehen, der fehlerhafte Schritt ist unbestätigt und spätere Schritte werden ausgelassen. Ein verlorener HTTP-Erfolg ist nicht mit einem Rollback gleichzusetzen; Wiederaufnahme braucht Readback und neue ausdrückliche Bestätigung der aktuellen Seite.

Die gemeinsame Pool-Vorprüfung besitzt jetzt einen eigenen Read-only-Repeatable-Read-Snapshot. Anlass war ein tatsächlich reproduzierter `503` im unveränderten Parallelitätskriterium: eine gerade bestätigte Pool-/Receipt-Version wurde innerhalb der volatilen Validierung inkonsistent gelesen. PostgreSQL dokumentiert die gesonderten Abfragesnapshots [volatiler Funktionen](https://www.postgresql.org/docs/16/xfunc-volatility.html) und die feste Sicht in [Repeatable Read](https://www.postgresql.org/docs/16/transaction-iso.html#XACT-REPEATABLE-READ). Die Quellcode-/Fehlerdiagnose legt diese Kombination als Ursache nahe; die Korrektur verändert weder SQL-Receiving noch Kapazitäts-, Einzelgewinner- oder Versionskriterien. Ein nativer Test prüft die tatsächliche Isolation und Read-only-Einstellung vor der Receipt-Abfrage.

Dieser sichtbare lokale Workflow-Schritt vermeidet eine fingierte atomare Cross-DB-Offboarding-Zusage. Kontosperre, durchgängiger Session-/Rechteentzug, Geräte-Rückgabe und ein dauerhaftes dienstübergreifendes Workflow-Journal bleiben eigene offene Arbeit. Der Browser darf einen erfolgreichen lokalen Lizenzentzug nicht als abgeschlossenes WF-004 ausgeben.

## ADR-017: Ehrlicher Frontend-Build statt unterdrückter Typ- und Capability-Fehler

Die bisher 17 bekannten TypeScript-Diagnosen werden an ihren Ursachen behoben; die bestehende `ignoreBuildErrors`-Ausnahme entfällt. Vorhandenes ES5-Transpilationsziel und Kryptografie bleiben erhalten: Set-/Byte-Iteratoren werden explizit über `Array.from` verarbeitet, SVG-Komponenten erhalten ihren tatsächlich verwendeten SVG-Prop-Vertrag. Ein nicht nullbares arithmetisches Ergebnis wird nicht durch eine syntaktische Nullish-Ausnahme kaschiert; unbekannte oder ungültige Lizenzbestände sind unverfügbar statt erfundene Zahlen.

Fehlende Setup-APIs werden weder als neue Client-Stubs noch durch `any`-/Ignore-Casts erfunden. Alte Template-/Security-/Backup-/Monitoring-Wizards dürfen keine erfolgreiche Produktivkonfiguration in `localStorage` oder Toasts simulieren. Sie zeigen die fehlende unterstützte Funktion; vorhandene tatsächliche Statusleser und der berechtigte Quick-Actions-Bulk-Pfad bleiben getrennt erhalten. Ein Bulk-Ergebnis muss zu den tatsächlichen indizierten Handler-Ergebnissen passen; ein gültiger Workflow-Receipt ist keine unabhängige Provider-/Geräte-Compliance-Abnahme.

Die bestehende isolierte reale Browserfixture verwendet ab jetzt einen tatsächlichen `next build` und `next start` mit Produktionsumgebung. Ein nativer Host-Build, ein Browserlauf mit lokalen Testdiensten, ein reproduzierbarer Clean-Install, ein Linux-Image und der öffentliche Produktivbetrieb sind unterschiedliche Nachweise. Vorhandene ESLint-Ausnahme, nicht fatale Next-Workspace-/SWC- und Browserslist-Warnungen sowie die offenen vollständigen BRs werden nicht durch einen erfolgreichen Compilerlauf erledigt erklärt.

## ADR-018: Dauerhaftes lokales Offboarding aus bestehenden Fachtransaktionen

Der eigene Firmenweg verbindet die vorhandene kanonische Kontosperre mit dem vorhandenen Lizenz-Allocator. Tenantgebundener Auftrag, immutable Identity-Receipt und retained Policy-Fortschrittsjournal ermöglichen ausdrücklich bestätigte Wiederaufnahme nach verlorenem Ergebnis. Weder zweiter Lizenzbestand noch allgemeine Workflow-Plattform. Ursprünglicher menschlicher Bearer und aktuelle Pflicht-MFA bleiben erforderlich; keine gespeicherten Tokens, globalen Rollen oder unbeaufsichtigten Service-Account-Fortsetzungen.

Die Datenbanken besitzen getrennte Commits. Spätere Fehler dürfen reale Account-/Lizenzschritte weder rückgängig behaupten noch als ungeschehen neu ausführen. Ursprüngliche Assignment-/Grant-Inkarnationen, Versionen, Original-Events und Pending-Outbox belegen Fortschritt. Spätere Reaktivierungen und Regrants erlauben keine Umdeutung eines alten Auftrags auf neue Ressourcen. Höchstens 25 Freigaben pro bestätigtem Aufruf; der historische lokale Abschluss verlangt tatsächlich keine verbleibenden eigenen lokalen Zuweisungen.

Rollen/Gruppen, Geräte, vollständige Sessions und externe Provider bleiben offene Schritte von WF-004. [Ausführbarer Umfang und Recovery-Vertrag](../features/company-offboarding.md).

## ADR-019: Katalogkorrekturen im bestehenden Allocator-Commit

App-Metadaten und endlicher eigener Seatbestand werden über den bereits vorhandenen Company-Katalogschreibweg bedingt korrigiert. Keine neue globale Rolle, externe Beschaffung oder zweite Kapazitätshaltung. Neuer spezieller Edit-Receiver/Protokollcheck ist erforderlich; die ursprüngliche feste Authority mit drei Fähigkeiten bleibt unverändert. Die zukünftige getrennte Custom-Role-Delegation wird damit nicht vorweggenommen.

Originalquelle/MFA, kanonischer Pool-Lock, genauer ETag, wirkliche Belegung als Untergrenze, exakt begrenzte Katalog-/Audit-Effekte und retained Event-/Pending-Kette gehören in dieselbe bestehende Allocator-Transaktion. No-op und veralteter Intent werden abgewiesen statt eine neue Version zu fingieren. Vorher/Nachher und Begründung werden in UI und Audit sichtbar; unbekannter Abschluss wird nur gelesen, nicht automatisch neu geschrieben. Lizenzzuweisungen und ihre Inkarnationen bleiben unverändert. [Ausführbarer Vertrag](../features/company-licenses.md#app--und-bestandskorrekturen).

## ADR-020: Gruppenentzug ist ein expliziter kanonischer Offboarding-Child

Der bestehende dauerhafte Account-/Lizenzauftrag wird weder stillschweigend erweitert noch rückwirkend als vollständiger Austritt erklärt. Ein ausdrücklich bestätigter Folgeschritt bindet jede entfernte eigene Gruppenmitgliedschaft an den tatsächlichen ursprünglichen Identity-Account-Beleg und dessen weiterhin unveränderte negative Eligibility.

Es gibt keinen zweiten Gruppen-Mutator und keine implizite globale Rollenverwaltung für Company-Owner. Vor dem ersten Entzug wird das gesamte sichtbare Manifest geprüft; jede Child-Transaktion verbindet den bestehenden `GroupMutator`, dessen Original-Event/Pending-Outbox und einen unveränderlichen Wiederaufnahmebeleg. Späterer Fehler behält frühere echte Commits. Ein verlorenes Ergebnis wird aus der alten Membership-Inkarnation wiedergefunden, nie durch Entfernen eines späteren Regrants repariert. Neue Kontogenerationen erfordern einen neuen geprüften Parent.

Unabhängige Gruppenrechte, aktuelle menschliche Authority und frische MFA bleiben verbindlich. Rollen/PIM und übrige Offboarding-Ressourcen sind eigene offene Hoheitsgrenzen, keine vom Gruppenrecht ableitbaren Fähigkeiten. [Benutzer-/API-Vertrag](../features/company-offboarding.md#gruppen-beim-austritt-entfernen).

## ADR-021: Rollen-/PIM-Entzug verwendet eigenständige tatsächliche Authority

Der Rollen-/PIM-Schritt bindet bestätigte alte Grants an den unveränderten ursprünglichen negativen Account-Checkpoint. Er verwendet die vorhandenen Rollen-/PIM-Entzugskernel und deren reale Authority-Command-Checkpoints. Ownership oder die drei Company-App-Fähigkeiten werden nicht zu globaler Rollenverwaltung erweitert. Tatsächliche kanonische Leserechte und Managementrechte gelten pro Bereich; geschützte Rollen behalten die bestehende zusätzliche Admin-Grenze. Aktuelle menschliche Sitzung, Home-Tenant und eigenständig belegte frische MFA gelten auch für Leser und Recovery.

Die separat erreichbare UI akzeptiert bekannte kanonische Ziel-/Vorgangs-IDs, ohne eine zusätzliche globale Benutzerleseberechtigung zu verlangen. Ein Owner ohne passende Pflichten erhält keinen alternativen Schreibweg. Ein kompletter sichtbarer Intent wird zuerst read-only geprüft; jedes Child besitzt danach seinen eigenen atomaren Original-Kernel-/Checkpoint-/Receipt-/Outbox-Commit. PIM-Kaskaden sind ausschliesslich die echten Wirkungen der bestehenden Hoheit und werden nicht durch einen zweiten SQL-Schreiber nachgebaut.

SHA-256 des kanonischen ursprünglichen Grant-Snapshots unter UTC ersetzt einen erfundenen Versionszähler. Wiederaufnahme verwendet nur die bestätigte alte ID und Version mit gültigem eigenen Receipt, nie einen später neu erteilten Grant. Eine durch den Entzug geänderte Authorization-Revision ist zulässig, eine geänderte negative Account-Eligibility nicht. Keine automatische Wiederholung, kein impliziter vollständiger WF-004 und keine externe Produktivaktion. [Ausführbarer Vertrag und Grenzen](../features/company-offboarding-access.md).

## ADR-022: Rückgabeanforderung ist nicht physische Rückgabe

Der Austritt erzeugt ausdrücklich bestätigte Aufgaben zu tatsächlichen ursprünglichen Gerätezuweisungen. Eine Anforderung verändert weder Inventar noch Benutzerzuweisung. Physische Handback-Erklärung und Abbruch sind eigenständige aktuelle Inventarhandlungen. Der vorhandene `DeviceInventory`-Release bleibt der einzige Schreiber des realen Entzugs; sein Event/Outbox und der Rückgabeabschluss committen lokal zusammen. Ein Abbruch verändert nur Aufgabenmetadaten.

Normale autorisierte Neuzuweisung bleibt möglich. Eine dadurch beendete ursprüngliche Beziehung liefert den abgeleiteten Status `assignment_changed`, keinen erfundenen Rückgabe-Event. Ein Request besitzt exakte alte Assignment-/Device-IDs und -Versionen. Der starke Entscheidungs-ETag bindet zusätzlich die tatsächliche aktuelle Geräteversion. Historische Abschluss-Recovery verwendet ausschliesslich den gültigen alten Intent und Beleg, nie die neue Beziehung.

Nur Erstellen/Erstellungs-Recovery verlangt weiterhin denselben negativen Identity-Account-Checkpoint. Die später manuell beobachtete Übergabe kann auch nach Accountreaktivierung erfolgen; das erlaubt keine neue Kontohandlung oder fremde Zuweisungsbereinigung. Ursprüngliche menschliche Authority, Home-Tenant und frische MFA bleiben bei jeder Phase verbindlich. Die bisherige feste Inventarquelle mit drei Fähigkeiten wird nicht erweitert: eigene neue 13-Feld-Quelle plus getrenntes Return-Receiver-Protokoll statt verstecktem Downgrade oder globaler Rolle. Keine Cross-DB-Atomarität, Providerwirkung oder vollständiger WF-004. [Benutzer-/API-Vertrag](../features/device-returns.md).

## ADR-024: Eigene Blueprint-Entwürfe und immutable Freigaben

[ADR 024](adr-024-company-blueprints.md) beschreibt den getrennten Firmen-Blueprint-Vertrag ohne globale Policy-Rollenabkürzung.

## ADR-025: Gemeinsamer Sitzbestand mit unabhängigen Blueprint-Herkünften

Status: In Progress. [ADR 025](adr-025-company-blueprint-license-origins.md) beschreibt unveränderliche Benutzerbindungen, zusätzliche Herkunftsgrants im bestehenden Allocator, atomare Protokoll-2-Aufträge und vollständiges negatives Offboarding. Keine Abnahme allein durch vorhandene API- oder Source-Tests.
