# Testresultate: Neuausrichtung auf OpenDirectory Business

## 21. Oktober 2026: Direkte App-Konten und Automations-CLI

Erster abgeschlossener Teil: direkter App-Konto-Einstieg ohne Redirect und Standardrechte sowie eine mitgelieferte Node-CLI für Erstellung, getrennte Aktivierung, Introspection, Rotation, Deaktivierung und bedingte API-Aufrufe. Bestehende Register-, Scope-, Versions- und Receiver-Grenzen bleiben erhalten. Kein neuer Mail-Connector, keine Postfach-Provisionierung und kein serverseitiger Skript-Scheduler; die Anbieterfrage ist noch offen.

Acht Node-Client-Regressionen und 23 AppRegistrationsView-Definitionen bestanden; TypeScript-Prüfung ebenfalls Exit 0. Ein zusätzlicher OAuth-Test startet die tatsächlich ausgelieferte CLI als separaten Prozess gegen den tatsächlichen lokalen HTTP-Service und prüft den vollständigen Kontolebenszyklus einschliesslich verweigerter Administration und ungültigem altem Secret. Der OAuth-Gesamtlauf umfasst damit 475 erfolgreiche Definitionen in 19 Suiten. Der Authentifizierungs-Upstream und die Datenbank dieses HTTP-Tests verwenden die bestehenden Demo-/Testgrenzen; dies ist keine produktive Tenant- oder Mailabnahme.

Die acht eigenständigen Client-Fälle sind im Root-Runner und in CI eingebunden. Ein versehentlich gestarteter voller Repository-Runner wurde unmittelbar beendet; die dabei geänderte fremde Lockdatei wurde auf ihren vorherigen Stand zurückgesetzt. Dieser Lauf zählt nicht als bestandene Gesamtsuite. Es wurden keine echten App-Konten, externen Postfächer oder E-Mail-Sendungen angelegt beziehungsweise ausgelöst.


## 21. Oktober 2026: ADE-Korrektur, OIDC-Adapter und SAML-IdP-Start

Die DEP-Endpunkte behaupten ohne Apple-Verbindung keine Geräte oder erfolgreiche Zuweisung mehr. Der zentrale OIDC-Adapter wurde bis zur signierten lokalen Token-Ausgabe mit echtem lokalem Discovery-/Token-/JWKS-Server geprüft. SAML-Response und Assertion besitzen überprüfbare XML-Signaturen und ein echtes X.509-Zertifikat. Authentifizierte IdP-initiierte HTTP-POST-Starts sind implementiert; SP-initiierte Requests, SLO und eine Abnahme gegen externe Kundentenants sind nicht enthalten.

| Prüfung | Erfolgreiche Definitionen | Umfang |
| --- | ---: | --- |
| OAuth Jest | 474 | 19 Suiten; Signatur, Issuer, Audience, Nonce, PKCE, Bindung, Replay, Timeout, zentraler Code-/Token-Flow und MFA |
| Authentication Jest | 314 | 14 Suiten; alte ungeprüfte SSO-Callbacks liefern HTTP 410 |
| Apple MDM | 52 | 5 Suiten; Auth/Admin-Grenzen und ausdrückliche ADE-Nichtverfügbarkeit |
| Identity Jest | 1'152 | 56 Suiten; gemeinsame MFA-Verträge |
| Policy Jest | 1'305 | 37 Suiten; gemeinsame MFA-Verträge |
| Bestehende Frontend-Suite | 2'927 | 112 Suiten |
| Neue Frontend-Regressionen | 2 | ADE-Fehlerzustand und wahrheitsgemässe SAML-Anzeige |
| Browser-Auth Node | 46 | vorhandener serverseitiger Callback und Sitzungsablauf |
| Gezielte native PostgreSQL-Integration | 90 | Clients, MFA und Policy-Gerätewarteschlange; einschliesslich neuem persistentem Föderation-/OTP-/Anti-Replay-Fall |

Diese gezählten Läufe endeten mit Exit 0. TypeScript-Prüfung, `next build` und `git diff --check` ebenfalls erfolgreich. Der Build meldete zusätzlich das bestehende Next.js-/Workspace-Problem bei der automatischen SWC-Lockfile-Reparatur; es verhinderte den Build nicht. Die bereits lokal gelöschte veraltete Callback-Seite wurde in den Auth-Commit übernommen: der bestehende Server-Callback bleibt zuständig, die alte Seite referenzierte entfernte Funktionen und kollidierte mit ihm.

Der anfänglich gestartete breitere PostgreSQL-Runner wurde nach 103 Erfolgen kontrolliert beendet; dieser unterbrochene Lauf gilt ausdrücklich nicht als bestandene Gesamtsuite und wird nicht zusätzlich gezählt. Danach bestanden alle 90 Fälle des oben abgegrenzten Datenbanklaufs. Kein vollständiger Repository-Testlauf, kein produktives Apple-Enrollment und keine externen IdP-/SP-Schreiboperationen wurden ausgeführt.



## Business-Slice 21: Eigene Firmen-Blueprints und immutable Freigaben

Status: **Tested**, begrenzte eigene Entwürfe und immutable lokale Freigaben. Alle unten gezählten finalen Gates enden mit Exit 0. Kein vollständiger BR-004 und keine produktive Deployment-/Provider-Abnahme.

### Implementierung

Neuer tatsächlicher Einstieg `/company-blueprints` mit eigenen SQL-Aggregaten statt neuer Company-Zeilen in global lesbaren Legacy-Tabellen. Ein roleloser wirklicher Firmeninhaber kann strukturierte Entwürfe erstellen, speichern, lokal als immutable Version freigeben, historische Versionen lesen und eine frühere Version ausdrücklich als neuen Entwurf wiederherstellen. Eine getrennte Freigabe erzeugt danach die nächste Versionsnummer. Keine neue globale Rolle, Entsiegelung von Source 036 oder Umdeutung bestehender App-/PIM-/Policy-Governance.

Der neue ursprüngliche Source hat genau elf Felder und drei feste `company.blueprints.*`-Rechte. Aktuelle kanonische Ownership/Home-Administration, unveränderter ursprünglicher Bearer, Tenant und unabhängige MFA <=300 Sekunden bleiben auch beim Lesen erforderlich. Gewünschte App-IDs benötigen bei neuen Schreiboperationen zusätzlich unabhängig bestätigte bestehende Firmen-App-Authority und reale eigene Pool-Evidenz; keine Allocator-/Stock-/Provider-Wirkung.

Drei ausdrücklich sichere lokale Sollschemas verwenden ausschliesslich bekannte Zahlen-/Boolean-Felder: `screen_lock`, `filevault`, `software_update`. Andere Felder, doppelte Schlüssel, Dezimal-/Exponentliterale und geheimnistragende freie Konfigurationen werden abgewiesen. Ein leerer Entwurf ist speicherbar, aber kein freigebbares Artefakt. Unterschiedliche vollständige Profile derselben Art bleiben ein ungelöster Freigabekonflikt.

Private Originaloperation, tatsächlicher Kopf, immutable Version, Metadaten-Event und Pending-Outbox werden atomar gehalten. Deferred Guards begrenzen physische Commit-Fristen. Exakte historische Recovery bestätigt ihre ursprüngliche Revision und verändert keinen späteren Kopf. Aktuelle Pool-Revisionen sind keine dauerhafte Gültigkeitslease historischer Blueprint-Versionen.

### Breite finale Code-Gates

| Tatsächlicher Gate-Umfang | Erfolgreiche Definitionen | Dateien/Suiten |
| --- | ---: | --- |
| Identity Jest | 1'067 | 54 |
| Policy Jest | 1'087 | 31 |
| Gateway Jest | 154 | 7 |
| Frontend Jest | 2'791 | 104 |
| Identity native PostgreSQL | 687 | 20 |
| Policy Integration Runner | 511 | 13; davon 504 PG-Fälle und sieben bestehende Node-Unit-Fälle |

Diese sechs Code-Gruppen umfassen **6'297 unterschiedliche erfolgreiche Definitionen**; hinzu kommen vier unterschiedliche tatsächlich abgeschlossene E2E-Definitionen. Insgesamt **6'301 unterschiedliche erfolgreiche Definitionen / 6'301 gezählte finale Ausführungen** in acht abgegrenzten Gruppen. Vollständiger Typecheck und Standard-`next build` enden beim ersten finalen Lauf ebenfalls mit **Exit 0**.

**457 neue Definitionen:** 71 Identity-Jest und acht Identity-PG; 71 Backend-Jest plus 68 geteilte Vertrags-/API-Fälle; 40 neue Policy-PG; 180 Frontend-Helper-/View-Fälle, neun reale Next-Rewrite-Fälle, acht Gateway-Routing-Fälle und zwei neue ausdrücklich eigenständige E2E-Definitionen. Fokusläufe, R1-Fehlläufe und Wiederholungen werden nicht zusätzlich als Abdeckung gezählt.

### Originale und neue End-to-End-Prozesse

Die ersten beiden R1-Läufe prüften den neuen Blueprint-Prozess vollständig innerhalb des immer weiter gewachsenen alten Company-Megatests. Der neue Workflow selbst bestand: echte Registrierung/Ownership, Apps, Freigaben 1/2/3, Restore, unveränderte historische Daten, stale ETags und ursprüngliche Recovery nach Revision 6. Die Gesamtdefinitionen scheiterten danach dennoch an realen vorhandenen Grenzen: Browser `429` im späteren Gruppenentzug, signiertes HTTP `401` nach abgelaufener ursprünglicher Inventar-MFA. Diese Läufe zählen **nicht** als finale E2E-Erfolge.

Keine Produktions-Rate, MFA-Frist, Source-/PIM-/Commit-Regel oder Test-Zeitgrenze wurde erhöht beziehungsweise übersprungen. Stattdessen sind die fachlich unabhängigen User Journeys jetzt eigenständige Definitionen mit eigener echter Registrierung, unabhängigem Reviewer und Owner-Anmeldung. Die alten Definitionen behalten sämtliche ursprünglichen Assertions; nur die neuen Slice-21-Blöcke wurden herausgelöst. Dedicated Credential-Subjects vermeiden Reihenfolgeabhängigkeiten. Jede finale Definition läuft gegen einen frischen isolierten Cluster unter denselben realen Schutzregeln.

| Finale R2-Definition | Tatsächlicher Nachweis | Status |
| --- | --- | --- |
| Bestehender vollständiger signierter Company-Prozess | Alle bisherigen Assertions unverändert; eigene Rate-/MFA-Grenzen weiterhin wirksam | Passed |
| Neuer signierter Firmen-Blueprint-Prozess | Tatsächlicher roleloser Owner, unabhängige Prüfung/Aktivierung/MFA, sechs atomare Operationen, immutable Versionen und alte Key-/ETag-Recovery nach neuerem Kopf; historische App-Daten auch nach echter normaler Lizenzzuweisung | Passed |
| Bestehender vollständiger Company-Produktionsbrowser | Alle bisherigen Assertions und Grenzen, ohne den neuen unabhängigen Blueprint-Prozess im gleichen Megatest | Passed |
| Neuer Firmen-Blueprint-Produktionsbrowser | Eigene tatsächliche Registrierung/Aktivierung/MFA, realer Firmenkatalog und strukturierter Editor, Freigaben/Restore, echter verlorener ACK und spätere historische Recovery, App-Metadatenänderung ohne Umschreiben von Version 1 | Passed |

Browser bedeutet frisch gebautes `next start`, tatsächlicher Chrome, echter Issuer/BFF/Policy-/Identity-HTTP und PostgreSQL, kein UI-Mock. Vorhandene lokale Geräteaufträge bleiben gespeicherte Aufträge, keine physischen Apple-/MDM-Erfolge.

### Belege

Code-Gates: `/tmp/od-business21-identity-unit-final.log`, `/tmp/od-business21-policy-unit-final.log`, `/tmp/od-business21-gateway-unit-final.log`, `/tmp/od-business21-frontend-unit-final.log`, `/tmp/od-business21-identity-native-full-final.log`, `/tmp/od-business21-policy-native-full-final.log`, `/tmp/od-business21-types-final.log`, `/tmp/od-business21-build-final.log`.

R1-Fehlläufe, Proofs, ursprüngliches Manifest/Wrapper und damalige Screenshots sind getrennt unter `/tmp/od-business21-r1/` erhalten. R2-Handoff `/tmp/od-business21-qa-handoff-r2.json` dokumentiert neue Definitionen und bytegleich erhaltene alte Definitionen.

R2-Runtime-Freeze: `/tmp/od-business21-runtime-freeze-r2.json`, **967 Einträge**, davon 966 Repository-Dateien und ein Wrapper; SHA-256 `0692549f2f5761f7dc1e1ef35edb1a6771bf23cbee90838628d62a8ce9f604f5`. Gegen R1 haben sich ausschliesslich die zwei QA-Dateien und der Wrapper geändert; produktive Quellen, Typprüfung und Default-Build bleiben identisch. Bei allen vier tatsächlichen Starts/Abschlüssen sowie der aktuellen Main-Nachprüfung stimmen sämtliche Quell-, Manifest- und Wrapper-Hashes überein.

Tatsächliche UTC-Abschlüsse: alter signierter Prozess `2026-10-19T17:04:35.003Z`, neuer signierter Prozess `17:05:44.438Z`, alter Produktionsbrowser `17:07:51.033Z`, neuer Produktionsbrowser `17:10:00.480Z`; alle jeweils 1/1 und Exit 0. Logs `/tmp/od-business21-{company-signed,blueprint-signed,company-browser,blueprint-browser}-r2-final.log`, vier gleichnamige `-proof.json` und Handoff `/tmp/od-business21-qa-final-r2.json` halten die einzelnen tatsächlichen Abläufe fest.

Main und QA haben die vier tatsächlichen neuen Browser-PNGs visuell geprüft:

| Lokales Bild unter `/tmp/` | SHA-256 | Nachgewiesener sichtbarer Stand |
| --- | --- | --- |
| `od-business21-blueprint-typed-editor.png` | `8fbae81b56bbe58ee9d279040178358842653dc3423472342014895ceb11e617` | Strukturierter Fünf-Minuten-Entwurf und tatsächlicher gewünschter eigener App-Pool |
| `od-business21-blueprint-immutable-version.png` | `23dee2a0123aed0154b599366cfc24e41a51844520a2aa0e5b283403886baaf4` | Immutable Version 1, ursprüngliche Konfiguration und damalige Pool-Revision 1 |
| `od-business21-blueprint-restored-draft.png` | `d476b34da2d696363e953c09cf428c8bca09e31537bdefc85ba524a5c68aa328` | Revision 5 als geänderter Entwurf bei unverändert aktueller lokaler Version 2 |
| `od-business21-blueprint-history.png` | `06a592b27584af040445b752eb2c8ef3654b9f6066183af34347ad905288016d` | Drei lokale Versionen, sechs tatsächliche Ereignisse und ausstehende Zustellung |

Die ersten zwei Viewport-Aufnahmen beginnen innerhalb des gescrollten App-Bereichs; die relevanten Felder/Versionen sind lesbar, die obere Seitenüberschrift ist teilweise ausserhalb des Ausschnitts. Keine vollständige WCAG-/Responsive-/Layout-Abnahme wird daraus abgeleitet.

OpenAPI **1.18.0**: **106 eindeutige Operationen / 169 auflösbare lokale Referenzen**, bytegleicher Generatoroutput. Elf neue Operationen dokumentieren den privaten Source und den eigenen Blueprint-Lebenszyklus; nicht sämtliche übrigen offenen Plattform-APIs.

Zusammenfassung: `/tmp/od-business21-gates.json`. Das finale `/tmp/od-business21-source-final.sha256` umfasst 999 Repository-Dateien inklusive Dokumentation. Die relative Linkprüfung über 33 Markdown-Dateien und 450 Verweise findet keine neuen fehlenden Ziele; vier bekannte fehlende Services-Wiki-Seiten bleiben unverändert. Die ursprünglichen Benutzeränderungen an lokaler Claude-Konfiguration und gelöschtem Auth-Callback werden nicht zurückgesetzt.

### Grenzen

Kein Blueprint-Ziel-/Gruppen-/Benutzerassignment, keine tatsächliche Blueprint-Lizenzreservierung, unabhängige Company-Deployment-Genehmigung, PIM-Komposition, Secret-Referenzen oder MDM-/Provider-Ausführung. Firmen-Rollen/OU-Scopes/Delegation und vollständiger Onboarding-Prozess bleiben offen.

Bestehende nicht fatale Next-SWC-/Workspace-Lockfile-/Browserslist-/React-act-Warnungen und Lint-Ausnahme bleiben. Keine neue Dependency, kein Docker-/Linux-/Clean-Install-Nachweis, kein Last/WCAG-/Backup-Restore-/Produktivnachweis. Source-/DDL-Owner bleiben dokumentierte Vertrauensgrenzen; keine atomare Identity-/Policy-Transaktion wird behauptet. **Gesamtauftrag weiterhin aktiv.**

Stand: 19. Oktober 2026. Aktuelle begrenzte Abnahme: [Business-Slice 10 – Geräteinventar und Zuweisung](#business-slice-10-geräteinventar-und-zuweisung). Die folgende erste Matrix ist historisch: Ponytail-Installation/Quellenprüfung, dokumentierte Produktausrichtung und Entfernung der bisherigen Standort-Scheindaten. Kein Nachweis einer vollständigen Business Capability oder der gesamten geforderten Enddemo.

| Prüfung | Ergebnis | Nachweis |
| --- | --- | --- |
| Gesamtes Frontend-Jest | **1'106/1'106**, 64 Suites, Exit 0, 68,984 s | `/tmp/od-business1-web2.log` |
| Native Identity/PostgreSQL, vollständige zehn Dateien | **445/445**, Exit 0, 80,89980425 s, keine Fail/Skip/Cancel/Todo | `/tmp/od-business1-identity1.log` |
| Frontend-Typecheck | Exit 2: **17 bekannte Diagnosen**, vollständige Diagnosezeilen identisch zum vorherigen Stand | `/tmp/od-business1-types2.log`, `/tmp/od-business1-types-diagnostics2.log` |
| Ponytail-Quelle | Installierter Skill identisch zu Commit `09c434ab73ca43761c5d8b0c5d341926c2fba710` | SHA-256 `9badd22a32e19cb884e46dfa8d3aae82bb81dfa5484105b8b4f0262df823a509` |

Die beiden neu hinzugefügten Standorttests sind in den 1'106 Frontendfällen enthalten: klare Unverfügbarkeit statt erfundener Standorte/Gerätezahlen sowie keine angeblichen Create-/Save-/Exportaktionen oder API-Aufrufe ohne Backend. Der frühere gezielte Zwei-Fall-Lauf und der erste vollständige Frontendlauf werden nicht zusätzlich gezählt. Der abschliessende Frontendlauf enthält auch die Korrektur des zusätzlichen `main`-Landmarks innerhalb des vorhandenen Layouts.

Die **1'551 erfolgreichen Fälle** dieser beiden unterschiedlichen Suites sind Regression für die damals abgegrenzte Änderung, keine neue Abnahme der historischen Identity-Gates oder des gesamten Apple-Business-Master-Prompts. In diesem ersten Slice wurde das Identity-Backend nicht funktional geändert; die echten Migrationen 001–036 starteten weiterhin. Der unvollständige, in dieser Entwicklungsarbeit nicht angewendete Entwurf `037_owned_policy_revisions.sql` wurde vor diesen damaligen Läufen aus dem automatischen Migrationspfad genommen, ohne bestehende Datenbankstände zurückzusetzen. Der nachfolgende Profil-Slice verwendet eine neue tatsächliche Migration `037_organization_profiles.sql`.

Der Runtime-Quellstand wurde nach der letzten UI-Änderung unter `/tmp/od-business1-runtime-frozen.sha256` erfasst und unter `/tmp/od-business1-runtime-check-final.log` erneut geprüft. Die abgegrenzte Source-/Dokumentationsliste liegt unter `/tmp/od-business1-source-final.sha256`; der maschinenlesbare Gate-Nachweis unter `/tmp/od-business1-gates.json`. Temporäre lokale Logs ersetzen keine dauerhafte CI-/Release-Abnahme.

Nicht ausgeführt bzw. nicht nachgewiesen: neue Business-End-to-End-Demo, Company-Registrierung, Organisation-CRUD, echte Standortverwaltung, vollständige Browser-/Signed-Regression, grüner Produktionsbuild, Lasttests, WCAG-Abnahme, Backup/Restore, Deployment und externe Apple-/MDM-/Marketing-/Billing-Aktionen. Bestehende React-Testwarnungen wurden nicht als neue unabhängige Fehler behoben. Bekannte offene Produkt- und Security-Grenzen bleiben unter [Implementierungsstatus](../implementation-status.md) dokumentiert.

## Business Slice 2: Organisationsprofil

Stand: 19. Oktober 2026. Abnahmegrenze: das [eigene Unternehmensprofil](../features/organization-profile.md) von echter PostgreSQL-Migration 037 über authentifizierte API und Formular bis zu MFA, bedingtem Speichern und Audit/Outbox. Keine Unternehmensregistrierung, kein Erstadministrator-Bootstrap und keine Abnahme der vollständigen Plattform.

| Abschliessende Prüfung | Ergebnis | Nachweis |
| --- | --- | --- |
| Gesamtes Identity-Jest | **577/577**, 29 Suites, Exit 0, 3,081 s | `/tmp/od-business2-unit-final.log` |
| Gesamtes Frontend-Jest | **1'129/1'129**, 67 Suites, Exit 0, 74,148 s | `/tmp/od-business2-web-final.log` |
| Native Identity/PostgreSQL, vollständige elf Dateien | **462/462**, Exit 0, 87,265404833 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business2-identity-final.log` |
| Vollständige Signed-Production-Revocation-Suite | **29/29**, Exit 0, 123,348562375 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business2-production-final.log` |
| Neuer fokussierter echter Chrome-Workflow | **1/1**, Exit 0, 20,933430208 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business2-browser-final.log` |
| Frontend-Typecheck | Exit 2, **17 bekannte Diagnosen**, nach Normalisierung der Quellzeile dieselben Pfade, Codes und Meldungen wie zuvor | `/tmp/od-business2-types-final.log`, Vergleich mit `/tmp/od-business1-types2.log` |
| Compose, beide Varianten | Read-only `config --quiet` mit expliziten Testwerten erfolgreich; keine Container gestartet | `/tmp/od-business2-compose.log` |

Die **2'198 erfolgreichen Fälle** sind die Summe dieser fünf unterschiedlichen finalen Gates, keine Addition überlappender Vorbereitungsläufe oder historischer Abnahmen. **71 neue Falldefinitionen** sind darin enthalten: 28 Identity-Unit-, 17 native PostgreSQL-, 23 Frontend-, zwei Signed-Production- und ein Browserfall. Die historische vollständige Authority-Gate-Matrix und die gesamte bestehende Chrome-Suite wurden nicht erneut vollständig ausgeführt.

### Tatsächliche Nachweise

- Gemeinsame 14-Feld-Validierung, Längen-/Typ-/Fremdfeldgrenzen, Zeitzonen, HTTPS ohne eingebettete Credentials und grosse Versionswerte als Strings; deterministisch generierte OpenAPI-Datei stimmt mit dem Generator überein.
- Zwei echte Tenants, ausschliesslich eigene Firma, Fremd-ETag-Abweisung, normale Benutzer/Workloads ohne Zugriff, fehlende oder veraltete MFA, fehlendes/stales `If-Match`, gesperrte Tenants und fehlende obligatorische Receiving-Guards.
- Echte SQL-Commit-/Rollback-Nachweise: Profil, unveränderliches Ereignis und Pending-Outbox passen exakt zusammen; Original-Actor-/Token-/MFA-Checkpoint im selben Commit. Fehlende Outbox, spätere Manipulation, zusätzliche Canonical Writes oder Truncate nach gelöschtem GUC, Original-Issuer-Widerruf vor Abschluss und Ablauf der physischen MFA-Frist verhindern den Commit.
- Beobachtetes tatsächliches PostgreSQL-Row-Lock-Warten zweier Administratoren: aus demselben erfassten Profilstand bestätigt nur ein Writer; der andere erhält 412. Ein gesperrter fremder Benutzer wird nicht als eigener Schreib-Target behandelt. UTC-Receipts funktionieren auch bei abweichender Session-Zeitzone und grossen Tenant-Generationen.
- Tatsächlich signierte Gateway-Requests überprüfen eigene/fremde Tenants, Berechtigungen, MFA, Versionskonflikte und fehlende Guards auch beim PUT; keine API-Antwort ohne Datensatz-/Audit-/Outbox-Nachweis wird als erfolgreiche Speicherung gezählt.
- Chrome verwendet tatsächliches Next-Frontend, Issuer und PostgreSQL, keinen Organization-API-Mock: Anmeldung zunächst ohne MFA, reales authentifiziertes TOTP-Setup über `/mfa`, erneute Anmeldung, Profil v1 speichern/neuladen, v2 ändern, konkurrierendes autorisiertes API-Update auf v3 und Ablehnung des veralteten Formularstands. Neuladen bestätigt v3 und die tatsächlichen SQL-Belege. Screenshot `/tmp/od-business2-organization.png` visuell geprüft; kein Nachweis umfassender WCAG-Konformität.
- Frontend prüft Original-Session, Actor, Tenant, tatsächlichen HTTP-ETag, Antwortinhalt und exakte Versionsfortschreibung. Unbestätigte Antworten löschen den erfassten Formularstand bis zum Neuladen, statt Erfolg oder automatischen Retry vorzutäuschen. Beide Compose-Varianten und beide Dockerfiles enthalten den gemeinsamen Validierungsvertrag im Root-Build-Kontext.

### Behobene Fehler während der Entwicklung

Die fehlgeschlagenen Vorbereitungsläufe bleiben erhalten und werden nicht als grüne Gates gezählt: `/tmp/od-business2-native1.log` enthielt einen SQL-Syntaxfehler, `/tmp/od-business2-native3.log` deckte nicht kanonische Zeitstempel durch die Session-Zeitzone auf, und `/tmp/od-business2-web-focus1.log` zeigte Server-Metadaten im strikten Formularvertrag. Korrekturen: gültiger SQL-Ausdruck, explizites transaktionales UTC und Projektion der 14 tatsächlichen Profilfelder.

Der erste Browserlauf `/tmp/od-business2-browser1.log` erhielt korrekt 403 beim ungeeigneten purpose-limited MFA-Ersteinrichtungsweg für eine Rolle ohne Pflicht-MFA. Die Produktion wurde nicht abgeschwächt und dem Testakteur keine fremde Zusatzrolle gegeben: Formular und Test verwenden das bestehende authentifizierte `/mfa`-Setup. Spätere fokussierte Vorläufe sind in den abschliessenden Gates enthalten, nicht zusätzlich gezählt.

### Quellstand und verbleibende Grenzen

Der eingefrorene Runtime-Quellstand `/tmp/od-business2-runtime-frozen.sha256` wurde nach den finalen Läufen erfolgreich unter `/tmp/od-business2-runtime-check-final.log` geprüft. Der deterministische API-Vertrag wird zusätzlich durch Unit-Test und abschliessende Source-Liste erfasst. Source/Dokumentation: `/tmp/od-business2-source-final.sha256`; maschinenlesbare Gates: `/tmp/od-business2-gates.json`. Diese temporären lokalen Belege ersetzen keine dauerhafte CI-/Release-Abnahme.

Die 17 TypeScript-Diagnosen bleiben offen; die vorhandene Diagnose in `UnifiLayout.tsx` verschob sich durch zwei neue Zeilen von 473 auf 475, ohne neue Diagnose. Kein grüner Produktionsbuild, kein tatsächlicher Docker-Image-Build oder Deployment wird behauptet. Die Compose-Prüfung validiert ausschliesslich die Konfiguration mit Platzhaltern ohne Produktiv-Credentials.

Weiterhin offen: WF-001 Registrierung/Erstadministrator, vollständige Organisationshierarchie, delegierte Organisationsrollen, eigentliche Audit-Aufbewahrung/Offhost-Sicherung, aktive eigene Rollenquelle statt globalem Source-6-Fallback, allgemeine Least-Privilege-Datenbankrollen, verteilte Commit-/Issuer-Widerrufsserialisierung, ausliefernder Outbox-Worker, Last-/Backup-/Restore-Abnahme und alle externen Apple-/MDM-/Marketing-/Billing-Effekte. `pending` bedeutet nicht zugestellt. Die vorhandenen Identity-Grenzen werden durch das Profil weder aufgehoben noch als vollständige SaaS-Isolation neu zertifiziert.

## Business Slice 3: Begrenzte Profildelegation

Stand: 19. Oktober 2026. Die vorherige Goal-Turn war **Progress**: echter Profile-Slice und überprüfte Dokumentation. Diese Fortsetzung implementiert die [begrenzte eigene Profildelegation](../features/organization-delegations.md) als tatsächlichen Least-Privilege-Baustein. Sie ersetzt keine öffentliche Company-Registrierung und keinen vollständigen Erstadministrator. Die kanonische globale Rollenquelle bleibt Schema 6 mit 62 Rollen.

| Abschliessende Prüfung auf dem aktuellen Quellstand | Ergebnis | Nachweis |
| --- | --- | --- |
| Gesamtes Identity-Jest | **590/590**, 30 Suites, Exit 0, 3,007 s | `/tmp/od-business3-unit-final.log` |
| Gesamtes Frontend-Jest | **1'148/1'148**, 69 Suites, Exit 0, 48,829 s | `/tmp/od-business3-web2.log` |
| Native Identity/PostgreSQL, vollständige elf Dateien | **476/476**, Exit 0, 92,240177708 s; keine Fail/Skip/Cancel/Todo; inklusive erweitertem tatsächlichem Limited-Login-/SET-ROLE-Nachweis für den neuen Delegations-Definer | `/tmp/od-business3-identity-final.log` |
| Vollständige Signed-Production-Revocation-Suite | **30/30**, Exit 0, 124,435251792 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business3-production-final.log` |
| Erweiterter fokussierter echter Chrome-Workflow | **1/1**, Exit 0, 57,472318791 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business3-browser-final.log` |
| Frontend-Typecheck | Exit 2, **17 bekannte Diagnosen**, dieselben Diagnosezeilen wie am Ende von Slice 2; keine neue Diagnose | `/tmp/od-business3-types2.log` |

**2'245 erfolgreiche Fälle** sind die Summe dieser fünf unterschiedlichen abschliessenden Gates. **47 neue Falldefinitionen**: 13 Identity-Unit-, 14 native PostgreSQL-, 19 Frontend- und ein Signed-Production-Fall. Der bestehende Browserfall wurde inhaltlich erweitert, nicht als zusätzliche neue Falldefinition gezählt. Frühere fokussierte/volle Vorbereitungsläufe und historische Abnahmen werden nicht nochmals addiert. Die vollständige historische Authority-Gate-Matrix, sämtliche OAuth-Suites und die gesamte bestehende Browser-Suite wurden hier nicht erneut abgenommen.

### Tatsächliche positive und negative Nachweise

- Gewöhnlicher eigener Benutzer mit unveränderter `user`-Rolle erhält nur Firmenprofil-Lesen/-Bearbeiten. Die tatsächlichen Server-Metadaten enthalten ausschliesslich die beiden Profilrechte. Es entstehen weder globale Rollen noch Benutzer-, Rollen-, Geräte- oder Lizenzverwaltungsrechte; Weiterdelegieren ist verboten.
- Direkter SQL-/API-Prozess bindet ursprünglichen Actor, kanonischen Tenant und tatsächlichen Empfänger. Fremde/fehlende/inaktive neue Ziele, Selbstvergabe, frei gewählte Tenant-/Scope-/Rollenfelder, ungültige Laufzeiten und fehlende MFA werden abgewiesen. Eine inzwischen inaktive eigene Person kann weiterhin kontrolliert widerrufen werden.
- Grant und Widerruf schreiben wirkliche unveränderliche Ereignisse mit Pending-Outbox und finalem Original-Bearer-Checkpoint; die kanonische Zielautorisierungsrevision wird im selben Commit invalidiert. Der tatsächliche signierte alte Bearer wird danach ungültig; nach neuer Anmeldung erlaubt ein widerrufener Grant keinen Profilzugriff mehr.
- Zwei parallele Grants beobachten einen tatsächlichen PostgreSQL-Row-Lock-Wait und ergeben nur einen aktiven Grant. Profil-Write und Widerruf warten auf demselben tatsächlichen Benutzer: ein bereits zugelassener Write linearisiert vor dem Widerruf, kein anschliessender alter oder frisch berechneter widerrufener Zugriff wird akzeptiert.
- Delegiertes Lesen und Speichern brauchen verifizierte MFA mit höchstens 300 Sekunden Alter. Die echte physische Grant-Ablaufzeit wird zusätzlich bis zum Profil-Commit eingehalten. Der schnelle Ablauf-Test verkürzt eine explizite SQL-Fixture vor dem Aufruf unter temporär deaktivierten Owner-Guards; die eigentliche Commit-Ablehnung erfolgt gegen die tatsächliche Uhr, nicht gegen eine simulierte erfolgreiche Provider-Antwort.
- Fehlende Receiving-Guards, verlorene positive Outbox-Belege, tatsächlich unterdrückte Outbox-Inserts, Original-Issuer-Entzug und zusätzliche kanonische Writes nach dem tatsächlichen Final-Checkpoint verhindern positive Ergebnisse. Zielautorisierung und sämtliche neuen Grant-/Event-/Outbox-Zeilen rollen gemeinsam zurück; ein geleerter GUC verbirgt den tatsächlichen Checkpoint nicht.
- Ein tatsächlicher eingeschränkter SQL-Login mit explizitem Definer-Execute-Grant und eine wirkliche `SET ROLE`-Session erreichen weder den Profil- noch den neuen Delegations-Write. Beide werden am tatsächlichen Owner-Check abgewiesen, nicht bloss wegen eines fehlenden Execute-Grants oder eines erfundenen Zielbenutzers.
- Replay der neuen Migration 038 erhält aktuelle Grants und den unveränderten 62-Rollen-Katalog. Die neue fachliche Ressourcenberechtigung aktiviert weder versiegelte Namespaces noch die bisherige nicht abgenommene eigene Rollenquelle.
- Der echte Chrome-Workflow verwendet Next, Issuer, tatsächliches MFA-Setup und PostgreSQL, keine Organization-API-Mocks. Ein Administrator vergibt über die UI den begrenzten Grant; ein normaler Empfänger richtet regulär MFA ein, meldet sich neu an und speichert die eigene Firma als Profilversion 4. Die Delegationsverwaltung ist für ihn nicht vorhanden. Der Administrator bestätigt einen realen Widerruf; der tatsächliche alte signierte Empfänger-Bearer wird mit 401 abgewiesen. Der gespeicherte Ort und die SQL-Belege werden zusätzlich abgefragt. Screenshot: `/tmp/od-business3-organization-delegations.png`.
- Die UI bestätigt erst passende Befehlsantwort **und** tatsächlichen neu gelesenen Bestand, inklusive exakt angeforderter Laufzeit. Fremde Actor-/Tenant-Antworten, unbekannte/revidierte Grants, Sessionwechsel, fehlende MFA und verlorene Bestätigungen ergeben keinen Erfolg und keinen automatischen Write-Retry. Ein Widerruf braucht Auswahl, neue Begründung und separate Bestätigung.
- Der generierte OpenAPI-3.1-Vertrag stimmt mit dem Generator überein und enthält nur die tatsächlich implementierten Profil-/Grant-/Widerrufspfade. Kein öffentlicher Registrierungsendpunkt wird vorgetäuscht.

### Behobene Fehler und erhaltene Grenzen

Die fehlgeschlagenen Vorläufe bleiben als Gegenbelege erhalten, nicht als zusätzliche grüne Gates: `/tmp/od-business3-native1.log` und `/tmp/od-business3-native-debug.log` zeigten eine falsche Receiving-Typprüfung für den neuen INSERT-only Constraint-Trigger; diese wurde auf den tatsächlichen exakten PostgreSQL-Typ 5 korrigiert. `/tmp/od-business3-unit1.log`, `/tmp/od-business3-production1.log` und `/tmp/od-business3-browser1.log` deckten auf, dass der vorhandene Async-Wrapper den Express-`next`-Parameter nicht weitergab. Der Wrapper reicht ihn jetzt korrekt weiter, statt die Fehlerbehandlung oder Auth-Middleware zu umgehen.

Der erste generierte Dokument-Patch landete wegen wiederholter JSON-Kontexte an einer falschen Stelle; der Gleichheitstest erkannte das, und die Datei wurde danach vollständig aus dem Generator ersetzt. Der erste Typecheck enthielt zusätzlich einen nicht zum vorhandenen ES5-Target passenden Unicode-RegExp-Flag; die Control-Character-Prüfung braucht diesen Flag nicht und bleibt erhalten. `/tmp/od-business3-browser2.log` fand zwei legitime gleichnamige MFA-Links; der Browser-Test wählt jetzt den relevanten Profil-Hinweis, statt MFA oder eine Funktion zu entfernen. Abschliessende Gates laufen auf den korrigierten Quellen.

Runtime-Quellen inklusive generiertem API-Dokument: `/tmp/od-business3-runtime-final.sha256`, abschliessend geprüft unter `/tmp/od-business3-runtime-check-final.log`. Gegenüber dem ersten `/tmp/od-business3-runtime-frozen.sha256` wurde ausschliesslich der vorhandene native Limited-Login-/SET-ROLE-Fall um den tatsächlichen Delegations-Definer erweitert und das vollständige native Gate erneut ausgeführt; Laufzeitcode und die anderen Gate-Eingaben bleiben unverändert. Maschinenlesbare Gates: `/tmp/od-business3-gates.json`; abgegrenzte endgültige Source-/Dokumentationsliste: `/tmp/od-business3-source-final.sha256`. Temporäre lokale Belege ersetzen keine dauerhafte CI-/Release-Abnahme. Die vorbereitenden Läufe werden nicht zu diesem Ergebnis addiert.

Nicht ausgeführt oder weiterhin nicht abgenommen: Company-Registrierung/Erstadministrator, allgemeine Custom-/Organisationsrollen, englische Oberfläche, vollständiger Audit-Explorer/History-Pagination, allgemeines Idempotency-Journal, verteilte Issuer-Revocation-/Commit-Serialisierung, Least-Privilege-DB-Rollen, Event-Auslieferung, Lasttests, WCAG-Zertifizierung, Backup/Restore, tatsächlicher Docker-Image-/grüner Produktionsbuild, Deployment und externe Apple-/MDM-/Marketing-/Billing-Aktionen. Die 17 bestehenden TypeScript-Diagnosen bleiben offen. Der neue Grant ist eine begrenzte fachliche Profilaufgabe, keine Fertigstellung des vollständigen Master-Prompts.

## Business Slice 4: Firmenregistrierung

Stand: 19. Oktober 2026. Vorherige Goal-Turn: **Progress**, reale begrenzte Profildelegation. Diese Fortsetzung implementiert den [Pending-only-Registrierungsprozess](../features/company-registration.md) mit tatsächlicher öffentlicher Oberfläche, bestehendem Credential-Provider, signiertem Issuer-Workload und neuem gesperrtem kanonischem Tenant/Kandidaten. Kein vollständiges WF-001, kein Account-Self-Signup, keine Freigabe/Aktivierung oder erste Company-Administrator-Anmeldung.

| Abschliessendes unabhängiges Gate | Ergebnis | Nachweis |
| --- | --- | --- |
| Gesamtes Identity-Jest | **617/617**, 32 Suites, Exit 0, 2,916 s | `/tmp/od-business4-identity-unit-final.log` |
| Gesamtes Issuer-Jest | **450/450**, 17 Suites, Exit 0, 6,67 s | `/tmp/od-business4-issuer-unit-final.log` |
| Gesamtes Frontend-Jest | **1'168/1'168**, 71 Suites, Exit 0, 49,175 s | `/tmp/od-business4-web-final.log` |
| Native Identity/PostgreSQL, vollständige zwölf Dateien | **491/491**, Exit 0, 103,448314625 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business4-identity2.log` |
| Vollständige Signed-Production-Revocation-Suite | **31/31**, Exit 0, 142,557706542 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business4-production-final.log` |
| Zwei fokussierte tatsächliche Chrome-Workflows | **2/2**, Exit 0, 52,896763625 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business4-browser-final.log` |
| Gesamter nativer BrowserAuth/BFF-Test | **44/44**, Exit 0, 0,382943667 s; keine Fail/Skip/Cancel/Todo | `/tmp/od-business4-bff-final.log` |
| Frontend-Typecheck | Exit 2, **17 bekannte Diagnosen**, Diagnosezeilen exakt wie am Ende von Slice 3 | `/tmp/od-business4-types-final.log` |
| Compose-Konfiguration beider Varianten | Read-only `config --quiet` mit expliziten Testwerten erfolgreich; keine Container gestartet | `/tmp/od-business4-compose.log` |

**2'803 erfolgreiche Fälle** sind die Summe dieser sieben unterschiedlichen Gates. **75 neue Falldefinitionen**: 27 Identity-Unit-, sechs Issuer-Unit-, 20 Frontend-, 15 native PostgreSQL-, ein Signed-Production-, ein Browser- und fünf native BFF-Fälle. Issuer-Jest und nativer BFF-Test umfassen hier zusätzlich 444 bzw. 39 bereits bestehende Fälle, die nicht Teil der vorigen Fünf-Gate-Summe waren. Deshalb ist die Differenz zur früheren Gesamtsumme nicht die Zahl neu geschriebener Tests. CJS/PostgreSQL-/Browser-Dateien werden nicht zugleich als Frontend-/Issuer-Jest-Fälle gezählt.

### Tatsächlich nachgewiesen

- Neuer deaktivierter Tenant, deaktivierte kanonische Erstperson, exakte bestätigte Credential-Subject-/Ownership-Bindung und immutable Pending-Registrierung mit tatsächlichen kanonischen Audits sowie einem verpflichtenden Registrierungsereignis/Pending-Outbox. Keine globale Rolle, aktive Profildelegation oder produktives Firmenprofil wird dabei angelegt.
- Exakter Request-Key bindet Inhalt/Issuer/Subject. Replays und ausdrückliche eigene Statusabfragen erzeugen keinen zweiten Tenant; fremde bekannte IDs, abweichende Inhalte, zweite Schlüssel für denselben Subject sowie bereits gebundene oder ungebundene Legacy-Subjects werden nicht als neu adoptierbare Firma behandelt.
- Reale parallele Requests beobachten PostgreSQL-Advisory-Lock-Warten und ergeben eine einzige kanonische Komponente. Die tatsächliche Proof-Ablaufzeit wird bis zum Commit geprüft, auch wenn zuvor bereits ein plausibler Pending-Beleg assembliert wurde. Alle betroffenen Ressourcen rollen gemeinsam zurück.
- Fehlende Receiving-/Deferred-Guards, unterdrückte Registrierungs-/Tenant-/User-Outbox-Inserts, ein später aktivierender User-Trigger, gelöschte Scopes und fremde spätere kanonische Writes/Truncate ergeben keinen Erfolg. Normale immutability-/Owner- und tatsächliche Limited-Login-/SET-ROLE-Grenzen bleiben erhalten; ein Definer-Execute-Grant genügt nicht.
- Tatsächlich signierter RS256-Workload mit eigener Audience/Type/Purpose, festem POST-Pfad, normalisiertem Inhaltsdigest, bestätigtem Subject, Nonce und höchstens 30 Sekunden Laufzeit. Die Gateway-Unit-Suite prüft eine echte RSA-Signatur; Claims-/Body-/Purpose-Negativtests prüfen den Receiving-Vertrag. Die HTTP-/Browser-Suites verwenden den tatsächlichen Issuer/JWKS/Receiver und PostgreSQL, keine simulierte erfolgreiche Registration-API.
- Der tatsächliche normale OAuth-Login des Pending-Kandidaten wird mit `identity_not_eligible` abgewiesen. Ein vorhandener Human/API-Bearer kann den privaten Registrierungs-Receiver nicht ersetzen; eine Registrierungs-ID ist kein Gateway-Zugriffstoken. Provider-Rollen-/Permission-Behauptungen werden nicht als kanonische Administratorrechte übernommen.
- Nativer BFF prüft Origin/Intent/Fetch-Site/JSON/Grösse und leitet keine alten Cookies/Bearer oder Client-Secrets weiter. Passwort/MFA-Code gehen nur zum konfigurierten Issuer/Provider, nicht zum Identity-Receiver oder zurück als Response. Kein automatischer zweiter Submit nach verlorenem Ack.
- Echter Browser: `/register`, bestätigte bestehende Credentials, ausgefüllte gemeinsame Profilfelder, bewusste Vormerkung, tatsächliche Pending-Antwort, geleertes Passwort, Reload mit aufbewahrter Request-ID, echte abgewiesene falsche Credentials, erneute ausdrückliche Statusabfrage und direkte SQL-Prüfung von deaktivierten Ressourcen/fehlenden Rollen. Der bereits bestehende Profile-/Delegations-/MFA-/Konflikt-/Widerrufs-Workflow läuft daneben weiterhin erfolgreich. Screenshot `/tmp/od-business4-company-registration.png` visuell geprüft; keine vollständige WCAG-Abnahme.
- Gemeinsame normale Profileingaben statt duplizierter Formularregeln. Exakte native Submit-/Status-BFF-Routen, Feature-Flag standardmässig `false`, alle drei Docker-Build-Eingaben enthalten die nötigen reellen gemeinsamen Pakete. OpenAPI 3.1 wird tatsächlich generiert und unterscheidet öffentliche Credentials von privatem Workload, ohne Aktivierung oder Access-Token zu behaupten.

### Behobene Entwicklungsfehler

Die Vorläufe bleiben Gegenbelege und werden nicht zu den grünen Gates addiert: `/tmp/od-business4-native1.log` und `/tmp/od-business4-native-debug.log` deckten einen fehlenden erlaubten **tatsächlich ausgelösten eigenen Record-Audit-Fanout** auf. Nur diese konkrete Audit-Tabelle wurde ergänzt, einschliesslich mandatory Snapshot-/aktueller Record-Belege; kein genereller Audit-/SQL-Bypass wurde geschaffen.

`/tmp/od-business4-identity1.log` fand eine Regression im alten Limited-Login-Denial: ein neu eingefügter Registrierungs-Lookup lief vor der tatsächlichen Owner-Prüfung. Die Owner-Prüfung steht jetzt wieder zuerst. Es wurden dem eingeschränkten SQL-Login keine neuen Leserechte gegeben und der frühere Review-Test blieb unverändert.

`/tmp/od-business4-browser1.log` fand, dass eine dynamische BFF-Route von den vorhandenen generischen API-Rewrites abgefangen wurde. Zwei konkrete statische POST-Handler und passende Routing-Regressionsfälle beheben die Ursache. Die fehlgeschlagenen Signed-/Browser-Vorläufe unter `/tmp/od-business4-production1.log`, `/tmp/od-business4-production-focus.log` und `/tmp/od-business4-browser2.log` berührten zudem den bisherigen automatischen **Testfixture**-Adopter. Dieser darf die neue, bereits exakt gebundene Registrierungsoperation nicht in den Fixture-Default-Tenant umhängen; der Fixture-Helper wurde wie bei bereits kanonischer Directory-Creation begrenzt. Die produktive Tenant-Fence blieb streng.

`/tmp/od-business4-web-focus1.log` erkannte einen fehlenden `AbortSignal.timeout`-Support in JSDOM sowie eine zu frühe Assertion auf den noch sichtbaren Loading-State. Die Testumgebung und die erwartete asynchrone Fertigstellung wurden korrigiert; der echte Browser-Timeout wurde nicht entfernt. Spätere fokussierte/grüne Vorläufe sind im finalen Gate enthalten, nicht zusätzliche Fallzahlen.

### Quellstand und verbleibende Grenzen

Runtime-Eingaben inklusive generiertem API-Dokument: `/tmp/od-business4-runtime-frozen.sha256`, abschliessend geprüft unter `/tmp/od-business4-runtime-check-final.log`. Maschinenlesbare Gates: `/tmp/od-business4-gates.json`; endgültige abgegrenzte Source-/Dokumentationsliste: `/tmp/od-business4-source-final.sha256`. Temporäre lokale Belege ersetzen keine CI-/Release-Abnahme.

Die vollständige historische Authority-Gate-Matrix und die gesamte bestehende Chrome-/OAuth-Integrationstestmatrix sind nicht erneut vollständig abgenommen. Unverändert offen: kompletter WF-001 mit Account-Onboarding, Prüfung/Freigabe/Aktivierung, eigenem Company-Owner, Console-Zuweisung und erster MFA-Anmeldung; allgemeine Rollen-/Ressourcen-Governance, DB-Owner-Abhängigkeit, aktiver eigener Rollenquellen-Cutover, Offhost-Retention/Datenschutz-Löschung, Outbox-Auslieferung, Last-/Backup-/Restore-/WCAG-Abnahme und externe Apple-/MDM-/Marketing-/Billing-Effekte. Keine echte `.env` wurde aktiviert, kein tatsächlicher Docker-Image-Build oder Deployment ausgeführt. 17 bestehende TypeScript-Diagnosen verhindern weiterhin eine grüne Produktionsbuild-Abnahme. Der Gesamtauftrag bleibt aktiv, nicht komplett oder blockiert.


## Business Slice 5: Interne Firmenprüfung

Stand: 19. Oktober 2026. Abgenommen ist die interne, explizit berechtigte Firmenprüfung als Teil von WF-001. Freigabe bedeutet `pending-activation`, keine Kontoaktivierung, externe rechtliche Verifizierung oder Company-Owner-/Console-Rechte. Der Gesamtauftrag bleibt offen.

| Gate | Ergebnis | Tatsächlicher lokaler Beleg |
| --- | --- | --- |
| Identity Unit/API | 629 Fälle, 33 Suites, Exit 0 | `/tmp/od-business5-identity-unit-final.log` |
| Issuer Unit/API | 452 Fälle, 17 Suites, Exit 0 | `/tmp/od-business5-issuer-unit-final.log` |
| Frontend | 1'182 Fälle, 73 Suites, Exit 0 | `/tmp/od-business5-web-accepted.log` |
| Native PostgreSQL Identity | 501 Fälle, 12 explizite Dateien, Exit 0 | `/tmp/od-business5-native-final.log` |
| Signierter Produktionsmodus-Gateway | 31 Fälle, Exit 0 | `/tmp/od-business5-production2.log` |
| Fokussiertes tatsächliches Chrome | 2 Fälle, Exit 0 | `/tmp/od-business5-browser-accepted2.log` |
| Native Browser-BFF | 45 Fälle, Exit 0 | `/tmp/od-business5-bff-final.log` |

Gesamt: **2'842** Fälle über sieben abgegrenzte Gates. **39 neue Falldefinitionen**: zwölf Identity-Unit-, zehn native PostgreSQL-, 14 Frontend-, zwei Issuer- und ein BFF-Fall. Bestehende signierte und Browserfälle wurden um die Review-Kette erweitert, nicht zusätzlich gezählt. Fokussierte Vorläufe und historische Gates werden nicht addiert. Die gesamte historische Authority-/OAuth-/Chrome- oder Produktmatrix ist damit nicht abgenommen.

### Tatsächliche Nachweise

- Explizite Offline-Bestellung eines aktiven kanonischen normalen Menschen mit nur `company.registrations.review`. Versionierte Bestellung/Widerruf erzeugen Audit/Pending-Outbox und invalidieren alte Autorisierung; keine neue globale Katalogrolle. Normales `admin`, Workloads und behauptete Token-Scopes erhalten kein Prüfrecht.
- Reale serverseitige Pagination/Filter, Originalantrag und immutable Freigabe/Ablehnung mit frischer MFA, Begründung, Bestätigung und ETag. Zwei tatsächlich konkurrierende Prüfer serialisieren am beobachteten PostgreSQL-Lock; kein Überschreiben des ersten Entscheids.
- Originalbearer vor/nach DML beim Issuer, finaler Original-Checkpoint im eigenen Management-Tenant und physische MFA-Frist bis Commit. Issuer-Widerruf, fehlende Receiving-Trigger/Outbox und unerlaubte zusätzliche Effekte rollen die Entscheidung zurück. Ziel-Tenant und Prüfer-Management-Tenant werden nicht gleichgesetzt.
- Antragsteller lesen nur den credentialbestätigten eigenen Schema-2-Status, ohne interne Gründe/Prüfer-IDs. Auch nach Freigabe sind Tenant/Kandidat gesperrt, kein aktives Firmenprofil angelegt und keine Rolle vergeben; der signierte Login wird weiterhin mit `identity_not_eligible` abgewiesen.
- Der tatsächliche Chrome-Fall verbindet Credentials, BFF, Issuer, Identity-SQL, erlaubte optionale MFA-Einrichtung/Neuanmeldung des normalen Prüfers, UI-Freigabe und erneute Statusabfrage im anonymen Antragstellerbrowser. Review-Antworten sind nicht simuliert. Screenshots `/tmp/od-business5-company-review.png` und `/tmp/od-business5-company-registration.png` wurden visuell geprüft. Die bisherige Profil-/Delegationsdemo besteht ebenfalls.

### Gegenbelege und Korrekturen

Vorläufe bleiben Gegenbelege, nicht zusätzliche grüne Gates. `/tmp/od-business5-native-focus1.log` fand die stille Array-zu-String-Konvertierung bei Pagination; Query-Werte müssen jetzt ausdrücklich Strings sein. `/tmp/od-business5-web-focus1.log` fand einen unpräzisen zugänglichen Buttonnamen; dieser ist jetzt eindeutig.

Die ersten signierten/Browser-Vorläufe verwendeten in der Testbestellung die Transport-URL statt des tatsächlichen konfigurierten Issuers. Korrigiert wurde die Fixture, nicht die Source-Bindung. Eine normale optionale MFA-Person darf den Required-First-Factor-Einstieg nicht verwenden; die echte Browserdemo nutzt stattdessen den erlaubten authentifizierten Einrichtungsweg mit Neuanmeldung. Die bestehende Browser-Fixture musste den neuen Review-Pfad exakt an den echten Receiver durchleiten statt leere Neben-API-Antworten zu liefern. Diese wurden vom Produktclient korrekt zurückgewiesen. Eine Diagnose-Assertion griff zudem auf einen leeren generischen Toast-Alert zu; sie wartet jetzt auf den tatsächlichen MFA-Hinweis.

Der echte Browser erkannte zuletzt einen Unterschied beim impliziten Select-Label: Optionstexte konnten Teil des Namens werden. Die produktive Oberfläche nutzt deshalb ausdrückliche `htmlFor`-/ID-Zuordnungen für Filter, Entscheidung und Grund. Die präzisen Browser-Locators wurden nicht aufgeweicht.

Der erste vollständige Identity-Unit-Lauf scheiterte im bestehenden zustandsbehafteten Gruppen-Fake. Ein isolierter diagnostischer und zwei anschliessende vollständige Läufe bestanden ohne Änderung dieses Fixtures oder des Gruppen-Produktivcodes; keine gesicherte neue Ursache wird behauptet. Ein breiter Dokumentindex-Check fand vier bereits vorhandene fehlende Service-Dokumente. Sie blieben unverändert; der begrenzte Business-Link-Check ist separat dokumentiert.

### Quellstand und offene Grenzen

Runtime: `/tmp/od-business5-runtime-frozen.sha256` (230 ausgewählte Eingaben), geprüft unter `/tmp/od-business5-runtime-check-final.log`. Endgültiger Source-/Dokumentationsstand: `/tmp/od-business5-source-final.sha256`; Gates: `/tmp/od-business5-gates.json`. Der generierte OpenAPI-3.1-Vertrag Version 1.3.0 stimmt mit dem Generator überein; lokale Referenzen und eindeutige Operation-IDs wurden geprüft. Zwei schreibfreie Compose-Konfigurationsprüfungen bestehen; das sind keine laufenden Images oder Deployments.

TypeScript ist **nicht grün**: dieselben 17 bestehenden Diagnosen wie vor diesem Slice, lediglich verschobene Zeilenpositionen; tatsächlicher finaler Compiler-Exit 2 (`/tmp/od-business5-types-result.json`). Kein Produktionsbuild ist abgenommen. Technische Aktivierung, eigener Company-Owner/Console-Zugriff und Erstadministrator-MFA/Login bleiben offen; ebenso aktive eigene Rollenquelle, übrige BRs, Least-Privilege-DB-Loginmodell, allgemeine Workflow-/Delivery-/Retention-/Löschregeln, Last-/Backup-/Restore-/vollständige WCAG-Abnahme und echte externe Providerberechtigungen. Echte `.env` und Betreiberflag bleiben unverändert. Kein Commit, Push, Deployment oder unautorisierter externer Schreibzugriff wurde ausgeführt; der Gesamtauftrag bleibt aktiv.


## Business Slice 6: Firmenaktivierung und Owner-Erstanmeldung

Stand: 19. Oktober 2026. Getestet ist der verbundene Ablauf vom bestehenden Credential-Konto über ursprüngliche Registrierung und unabhängige Freigabe bis zur ausdrücklich eigenen Aktivierung, tatsächlichem Initialprofil, Pflicht-MFA und erster Console-/Profilanmeldung. Der Owner erhält nur eigene Profil-/Profildelegationsrechte, keine globale Rolle oder vollständige Company-Administration. Account-Self-Signup, externe Firmenverifizierung und die übrigen Master-Prompt-Anforderungen bleiben offen.

| Gate | Ergebnis | Tatsächlicher lokaler Beleg |
| --- | --- | --- |
| Identity Unit/API | 635 Fälle, 34 Suites, Exit 0 | `/tmp/od-business6-identity-unit-complete.log` |
| Issuer Unit/API | 454 Fälle, 17 Suites, Exit 0 | `/tmp/od-business6-issuer-unit2.log` |
| Frontend | 1'185 Fälle, 73 Suites, Exit 0 | `/tmp/od-business6-web-final.log` |
| Native PostgreSQL Identity | 509 Fälle, 12 explizite Dateien, Exit 0 | `/tmp/od-business6-native-accepted.log` |
| Signierter Produktionsmodus-Gateway | 31 Fälle, Exit 0 | `/tmp/od-business6-production-final.log` |
| Fokussiertes tatsächliches Chrome | 2 Fälle, Exit 0 | `/tmp/od-business6-browser-accepted.log` |
| Native Browser-BFF | 46 Fälle, Exit 0 | `/tmp/od-business6-bff-final.log` |

Gesamt: **2'862** Fälle in sieben abgegrenzten Gates. **20 neue Falldefinitionen** gegenüber Slice 5: sechs Identity-Unit-, zwei Issuer-, drei Frontend-, acht native PostgreSQL- und ein BFF-Fall. Vorhandene signierte/Browserfälle wurden um echte Aktivierung, MFA und Owner-Anmeldung erweitert; sie werden nicht zusätzlich gezählt. Fokussierte/grüne Vorläufe und historische Gates werden nicht addiert. Die vollständige historische Authority-/OAuth-/Chrome- oder Produktmatrix ist damit nicht abgenommen.

### Nachgewiesener Ablauf und Grenzen

- Nur der ursprüngliche erneut credentialbestätigte Antragsteller kann nach tatsächlicher unabhängiger Freigabe die eigene unveränderte neue Komponente aktivieren. Ungeprüfte/abgelehnte Anträge, fremde Subjects, frei gewählte öffentliche Console-IDs und spätere Console-Umdeutung werden abgewiesen. Die Aktivierung ist separat standardmässig ausgeschaltet.
- Tenant/Kandidat, tatsächliches Initialprofil, dauerhafter eigener Owner und exakte neue Audit-/Pending-Outbox-Belege committen atomar mit originalem Workload-Deadline bis zum physischen Commit. Zwei gleichzeitig laufende Aktivierungen warten am tatsächlich beobachteten SQL-Lock und erzeugen nur einen Owner. Eine neue globale Katalogrolle, ein allgemeiner App-Grant oder ein erfundener menschlicher Authority-Checkpoint wird nicht erzeugt.
- Fehlende aktuelle Receiving-Guards oder tatsächlich ausgelassene Aktivierungs-/Profil-/kanonische Outboxes verhindern Erfolg. Auch das nachträgliche Verändern eines ursprünglichen Profilentwurfs durch ausdrücklich deaktivierte Test-Guards macht Status/Source unverfügbar; Wiederherstellung des exakten Originalbelegs wird geprüft. Spätere legitime Profiländerungen dagegen erhalten die historische Aktivierung.
- Eingeschränkter realer SQL-Login und `SET ROLE` können einen echten aufgenommenen Aktivierungsproof auch bei explizitem Execute-Grant nicht durch einen Definer in Owner-Autorität verwandeln. Unzulässige zusätzliche Effekte bleiben auch nach gelöschtem GUC gesperrt. Der Runtime-DB-Owner bleibt dennoch eine bekannte offene Produktions-/Least-Privilege-DB-Grenze.
- Der private Console-Source hat ein eigenes Purpose/Scope und bindet Client/User/POST/Pfad. State-Read-/Human-Assertions und andere Clients/Benutzer dürfen ihn nicht ersetzen. Die kanonische Owner-Quelle erzwingt MFA unabhängig vom angefragten Client oder Rollen-Scope. Der signierte tatsächliche Login wird vor Ersteinrichtung mit `401 mfa_enrollment_required` abgewiesen; danach funktionieren echte MFA-Anmeldung und eigenes Profil, aber keine Personen- oder Review-Verwaltung.
- Der echte Chrome-Fall verwendet einen frischen Browser ohne vorab gesetztes `od_onboarded`, bestätigt die Null des Flags nach Login, übernimmt Profil Version 1 und ändert das eigene Profil tatsächlich auf Version 2. Kein Legacy-Wizard-Abschluss oder Owner-Bearer wird fingiert. Passwortfelder werden nach Mutation geleert und die Aktivierungsantwort erzeugt keine Session. Die separate bestehende Profil-/Delegationsdemo besteht mit zwei tatsächlichen Firmenprofilen weiterhin.
- Tenant-Pause und das Entfernen des ursprünglichen Subject-Links sperren wirksamen Owner-/Console-Zugang. Ein Test hält bei entferntem Link beide physischen Enabled-Bits auf `true`; öffentliche Anzeige wird trotzdem `suspended` und `administratorEnabled:false`, nicht erfundener aktiver Zugang.

Screenshots `/tmp/od-business6-company-registration.png` und `/tmp/od-business6-company-owner.png` wurden visuell geprüft. Es sind isolierte tatsächliche Testabläufe, keine externe produktive Unternehmens-, Apple-/MDM-, Zahlungs- oder Lizenzanbieter-Abnahme.

### Gegenbelege und Korrekturen

Frühere Läufe bleiben Gegenbelege und werden nicht zu akzeptierten Fällen addiert. Der alte Registrierungstest spielte absichtlich Migration 039 erneut ein und überschrieb dadurch die spätere Tenant-Review-Funktion. Die Replay-Fixture stellt nach der historischen Prüfung wieder die tatsächlich späteren Migrationen her; keine Owner-Prüfung wurde gelockert.

Die erste Aktivierung traf zudem die bestehende Profil-No-effects-Fence, weil sie selbst ein Initialprofil mit eigenem Ereignis erzeugt. Nur exakt die drei neuen Aktivierungsbelege erhalten bei tatsächlicher aktueller Aktivierungs-Admission eine Ausnahme; generische Zusatzwirkungen und Truncation bleiben verboten. Die eigentliche Aktivierungsfence/Deferred-Prüfung kontrolliert weiterhin die gesamte eigene Transition.

Ein entscheidender SQL-Fehler wurde durch den verweigerten Erfolgsbeleg gefunden: `to_jsonb(profile)` löste in der Join-Abfrage den gleichnamigen Registrierungs-JSON-Entwurf statt der tatsächlichen Profilzeile auf. `to_jsonb(profile.*)` bindet jetzt explizit die wirkliche Zeile. Die Validierung wurde nicht abgeschwächt. Der temporäre reine Test-Diagnosepfad wurde nach der Klärung wieder entfernt.

Bestehende Unit-DB-Fixtures bekamen ausdrücklich leere Ergebnisse für den neuen Owner-Lookup statt erfundene positive Owner. Die ältere Browserdemo hatte ungescopte SQL-Assertions auf nur ein Firmenprofil; sie prüft nun exakt den tatsächlichen eigenen Tenant und löscht nicht das neue zweite Firmenprofil, um den Test grün zu machen. Der erste signierte Vorlauf erwartete irrtümlich 403 statt des bereits bestehenden 401-MFA-Ersteinrichtungsvertrags; korrigiert wurde ausschliesslich die Assertion. Das neue Fresh-Browser-Gate prüft den wirklichen Onboarding-Weg ohne den früher allgemeinen Test-Init-Flag.

### Quellstand und offene Abnahme

Runtime-Manifest: `/tmp/od-business6-runtime-frozen.sha256` mit 234 ausgewählten Eingaben, abschliessend geprüft unter `/tmp/od-business6-runtime-check-final.log`. Source-/Dokumentationsmanifest: `/tmp/od-business6-source-final.sha256`; Gates: `/tmp/od-business6-gates.json`. Der generierte OpenAPI-3.1-Vertrag Version 1.4.0 stimmt mit dem Generator überein; alle lokalen Referenzen und 20 eindeutige Operation-IDs wurden geprüft. Die Compose-Konfigurationsprüfungen sind schreibfrei und kein tatsächlicher Image-Build oder Deployment.

TypeScript bleibt nicht grün: 17 bereits bestehende Diagnosen, gegenüber Slice 5 abgesehen von Zeilenpositionen unverändert, letzter Compiler-Exit 2 (`/tmp/od-business6-types-result.json`). Der vollständige Company-Administrator, zusätzliche Owner/Transfer, eigene Personen-/Gruppen-/OU-/Rollen-/Geräte-/Lizenzworkflows, externe Verifizierung, aktive allgemeine eigene Rollenquelle, DB-Rollenmodell, allgemeine Delivery-/Retry-/DLQ-, Retention-/Datenschutz-Lösch-, Last-/Backup-/Restore-/WCAG- und Produktionsabnahmen fehlen weiterhin. Echte `.env` und produktive Systeme wurden nicht verändert. Kein Commit, Push oder Deployment wurde durchgeführt; der Gesamtauftrag bleibt aktiv.

## Business Slice 7: Eigene Verzeichnisverwaltung

Stand: 19. Oktober 2026. Der tatsächliche neue Company-Owner verwendet die vorhandenen tenantgebundenen Personen-/Gruppendienste und eine echte OU-Erstellungsoberfläche, ohne globale Rolle. Geprüft ist der begrenzte [eigene Verzeichnisprozess](../features/company-directory.md), nicht vollständige Company-Administration oder der ganze Master-Prompt.

| Gate | Ergebnis | Tatsächlicher lokaler Beleg |
| --- | --- | --- |
| Identity Unit/API | 652 Fälle, 35 Suites, Exit 0 | `/tmp/od-business7-identity-unit-accepted.log` |
| Issuer Unit/API | 454 Fälle, 17 Suites, Exit 0 | `/tmp/od-business7-issuer-unit.log` |
| Frontend | 1'201 Fälle, 75 Suites, Exit 0 | `/tmp/od-business7-web1.log` |
| Native PostgreSQL Identity | 517 Fälle, 12 explizite Dateien, Exit 0 | `/tmp/od-business7-native-accepted.log` |
| Signierter Produktionsmodus-Gateway | 31 Fälle, Exit 0 | `/tmp/od-business7-production-accepted.log` |
| Fokussiertes tatsächliches Chrome | 2 Fälle, Exit 0 | `/tmp/od-business7-browser-accepted.log` |
| Native Browser-BFF | 46 Fälle, Exit 0 | `/tmp/od-business7-bff.log` |

Gesamt: **2'903** Fälle in sieben abgegrenzten Gates. **41 neue Falldefinitionen** gegenüber Slice 6: 17 Identity-Unit-/Contract-, 16 Frontend- und acht native PostgreSQL-Fälle. Bestehende tatsächliche signierte und Chrome-Abläufe wurden erweitert und nicht zusätzlich gezählt. Grüne Vorläufe, der fokussierte 39-Fall-PG-Lauf und historische Matrizen werden nicht addiert. Die vollständige historische OAuth-/Chrome-/Authority- und Produktmatrix ist damit nicht abgenommen.

### Tatsächlich geprüft

- Ein ursprünglicher Owner mit `roles:[]` legt zwei hierarchische eigene Einheiten, zwei gesperrte Mitarbeitende und eine Gruppe an. Tatsächliche Ownership, Original-Actor, Audit/Pending-Outbox und beide Mitgliedschaftszeilen werden in PostgreSQL geprüft. Profil-/Statusänderung, Gruppenprofil, Mitgliedschaftsentzug und Gruppenretirement behalten echte ETags/Receipts.
- Zwei tatsächliche Firmen können ihre Personen/Gruppen/OUs nicht gegenseitig lesen, überschreiben, als Eltern verwenden oder über Mitgliedschaften verbinden. Ein frischer MFA-Benutzer mit erfundenen Owner-Claims erhält keine solche Authority. Alte explizite Verzeichnisrollen bleiben funktionsfähig.
- Spätes ursprüngliches Bearer-Deny nach tatsächlichem Creation-DML rollt Datensatz, Ownership und Belege zurück. Ablauf des ursprünglichen Tokens während `beforeCommit` wird am physischen deferred SQL-Fence abgelehnt. Tatsächliches Unlink des Owners entzieht den Zugang trotz retained Aktivierungshistorie.
- Eine echte 256-Level-Hierarchie erlaubt ein weiteres Kind auf Level 256, nicht Level 257. Ein bereits zyklischer Parent erzeugt keinen neuen Namespace. Ein tatsächlicher konkurrierender Update der geprüften Grosselternzeile wartet beobachtet in `pg_stat_activity` auf den Share-Lock und wird erst nach Child-Commit wirksam.
- Chrome startet ohne erfundenes `od_onboarded`-Flag. Nach tatsächlicher Registrierung, unabhängiger Prüfung, Aktivierung und MFA werden eigene Organisationseinheiten, Mitarbeitende und Gruppen über echte Next/Issuer/Identity/PostgreSQL-Endpunkte erstellt. Die OU-Pfade werden explizit durchgelassen, nicht vom Browser-Harness mit leeren Demoantworten ersetzt. Screenshots `/tmp/od-business7-company-hierarchy.png` und `/tmp/od-business7-company-group.png` wurden visuell geprüft; keine vollständige WCAG-Abnahme.
- Der signierte Produktionsmodus-Gateway belegt tatsächliche Owner-Capabilities und eigenen Verzeichniszugriff, weiterhin `roles:[]`, fremde Person `404` sowie verweigerte Rollenverwaltung, Plattformreviews, Benutzerlöschung, Session-Reset und OU-PUT/DELETE.

### Gegenbelege und verbleibende Grenzen

Die ersten Browser-Testvorbereitungen hatten zwei Namenskollisionen mit bestehenden Testvariablen (`confirmed`, danach `actual`) und wurden vor Start des Ablaufs abgelehnt. Nur die Testvariablennamen wurden korrigiert; weder produktive Autorisierung noch Assertions wurden abgeschwächt. Danach bestanden beide echten Abläufe, nach Ergänzung der Parent-Depth-/Share-Lock-Prüfung erneut gegen den endgültigen Runtime-Stand. Ein abgeschnittener erster OpenAPI-Patch-Transport führte zu keiner Dateiänderung; das vollständige generierte Artefakt wurde anschliessend über `apply_patch` übernommen und exakt gegen den Generator geprüft.

Runtime-Manifest: `/tmp/od-business7-runtime-frozen.sha256`, 237 ausgewählte Eingaben, abschliessend unter `/tmp/od-business7-runtime-check-final.log` geprüft. Source-/Dokumentationsmanifest: `/tmp/od-business7-source-final.sha256`; Gates: `/tmp/od-business7-gates.json`. Der OpenAPI-3.1-Vertrag Version 1.5.0 besitzt 35 eindeutige Operation-IDs; alle 61 lokalen Referenzen und die Übereinstimmung mit dem Generator sind geprüft. Acht scoped Dokumente enthalten 166 geprüfte lokale Links/Anker ohne Fehler. Keine Compose-/Docker-Konfiguration oder Secrets wurden in diesem Slice verändert; frühere Konfigurationsprüfungen werden nicht als neuer Image-Build gezählt.

Typecheck: weiterhin genau 17 bestehende Diagnosen, gegenüber Slice 6 ausser Zeilenpositionen identisch, Compiler-Exit 2 (`/tmp/od-business7-types-result.json`). Kein erfolgreicher Produktionsbuild wird behauptet. Legacy-OU-Mutationen müssen vor einer Owner-Freigabe kanonisch ersetzt werden; Benutzer-OU-Mitgliedschaften, Credential-Provisionierung, eigene Rollen-/Scope-Governance, verbundene JML-/Geräte-/Blueprint-/Lizenzprozesse und alle verbleibenden Business-/Betriebsanforderungen bleiben offen. Keine externen Produktivschreiboperationen, kein Commit, Push oder Deployment; der Gesamtauftrag bleibt aktiv.

## Business Slice 8: Kanonische OU-Änderungen

Stand: 19. Oktober 2026. Geprüft ist der begrenzte [OU-Schreibvertrag](../features/organization-units.md): tatsächliche eigene versionierte Bearbeitung, Subtree-Verschiebung und bestätigte Blattlöschung statt ungescoptem Legacy-DML. Zusätzlich bleibt der ursprüngliche neue OU-Creation-Proof vor dem Namespace-Write bis zum physischen Commit retained. Benutzer-OU-Mitgliedschaften, weitere Governance und die vollständige Produktabnahme sind nicht daraus abgeleitet.

| Gate | Ergebnis | Tatsächlicher lokaler Beleg |
| --- | --- | --- |
| Identity Unit/API | 674 Fälle, 36 Suites, Exit 0 | `/tmp/od-business8-identity-unit-final.log` |
| Issuer Unit/API | 454 Fälle, 17 Suites, Exit 0 | `/tmp/od-business8-issuer-unit.log` |
| Frontend | 1'212 Fälle, 75 Suites, Exit 0 | `/tmp/od-business8-web-final.log` |
| Native PostgreSQL Identity | 540 Fälle, 13 explizite Dateien, Exit 0 | `/tmp/od-business8-native-final.log` |
| Signierter Produktionsmodus-Gateway | 31 Fälle, Exit 0 | `/tmp/od-business8-production-final.log` |
| Fokussiertes tatsächliches Chrome | 2 Fälle, Exit 0 | `/tmp/od-business8-browser-final.log` |
| Native Browser-BFF | 46 Fälle, Exit 0 | `/tmp/od-business8-bff.log` |

Gesamt: **2'959** Fälle in sieben abgegrenzten Gates. **56 neue Falldefinitionen** gegenüber Slice 7: 22 Identity-Unit-, elf Frontend- und 23 native PostgreSQL-Fälle (22 in der neuen OU-Datei, einer für den tatsächlichen rolelosen Company-Owner). Die beiden bisherigen Owner-OU-Deny-Unitfälle wurden passend zur echten neuen Capability zu positiven Tests mit zwingender aktueller Receiver-Prüfung, nicht zusätzlich gezählt. Vorhandene signierte und Chrome-Fälle wurden erweitert. Fokus-/Vorläufe und historische Gates werden nicht addiert; die vollständige historische OAuth-/Chrome-/Produktmatrix ist nicht abgenommen.

### Tatsächlich belegt

- Originale kanonische Operatoren und der tatsächliche Owner mit `roles:[]` ändern nur eigene OUs. Globales `admin` ersetzt keine Ziel-Tenant-Bindung. Fremde Ziele/Eltern, Leser, erfundene Claims, schwache/fehlende/falsche/veraltete Versionen und nicht unterstützte Legacy-Adapter können keinen positiven Write auslösen.
- Echte Änderungen erzeugen genau gebundene Before-/After-Snapshots, Actor-/Originalproof, Event-Typ/Version, Correlation-ID und Pending-Outbox. Leaf-Retirement behält Namespace, negatives Tenant-Ereignis und alte Creation-Admission. Eltern mit Kindern lassen sich nicht löschen; kein verstecktes `SET NULL` oder kaskadierendes Kind-Delete ist als Erfolg zugelassen.
- Selbst-/Nachfahrenzyklen und zu tiefe Teilbäume werden unabhängig von der Oberfläche abgewiesen. Die Prüfung erfasst den tiefsten tatsächlichen Nachfahren an der 256-Level-Grenze, nicht bloss den verschobenen Root.
- Tatsächliche konkurrierende Updates warten beobachtet am Tree-Advisory-Lock und die zweite alte Version erhält `412`. Gegenläufige Verschiebungen können nicht gemeinsam einen Zyklus committen. Ein Child-Create vor wartendem Parent-Delete erzwingt die erneute tatsächliche Abhängigkeitsprüfung.
- Ursprünglicher Bearer-Entzug nach DML und physischer Ablauf vor Commit rollen tatsächlichen Effekt und Belege zurück. Gelöschte GUCs, unzulässige weitere Writes, Truncation, fehlende Receiver, ausgelassene Events/Outboxes/Creation-Admission und late Row-Trigger-Drift erzeugen keinen erfolgreichen Commit. Ein zweiter an sich gültiger neuer OU-Proof darf nicht auf einem bereits erhaltenen anderen OU-Mutationsauftrag mitreiten; beide Effekte rollen zurück. Echte beschränkt berechtigte SQL-Logins sowie `SET ROLE` können den privaten Definer nicht als Datenbankowner benutzen.
- Der reale Chrome-Weg startet weiterhin ohne erfundenes Legacy-Onboarding-Flag. Nach Registrierung/Freigabe/Aktivierung/MFA werden eigene Einheiten bearbeitet, umbenannt und auf Root/zurück verschoben. Ein tatsächlicher alter ETag erhält `412`; vor der expliziten Löschbestätigung bleibt die echte temporäre Zeile erhalten, danach ist sie retired. Tatsächliche SQL-Events und retained Ownership werden geprüft. `/tmp/od-business8-company-hierarchy.png` wurde visuell geprüft, ohne daraus vollständige WCAG-Konformität abzuleiten.
- Der signierte Produktionsmodus-Gateway belegt dieselben tatsächlichen OU-Aktionen sowie fehlende Version `428`, bestehende Kinder `409`, stale Write `412`, fremde OU `404`, weitere verweigerte Rollen-/Benutzerlösch-/Session-Reset-Rechte und unverändert keine globale Owner-Rolle.

### Gegenbelege und Korrekturen

Die erste erweiterte SQL-Commit-Bedingung hatte eine ungeklammerte `CASE`-Expression und wurde vom tatsächlichen PostgreSQL-Parser abgelehnt. Nach syntaktischer Korrektur zeigte ein nichtleerer Rollen-Snapshot eine echte Zeitzoneninkohärenz: neue gepinnte UTC-Prüfung gegen zuvor im Caller-Zeitraum serialisierte Rollendaten. Der gemeinsame Snapshot wird nun in UTC erzeugt; OU-Row-Snapshots werden innerhalb der gepinnten typisierten Row-Funktion serialisiert. Keine Zeitstempel, Rollenbelege oder Assertions wurden zum Passendmachen entfernt. Ein Trigger-Record mit unterschiedlichen Tabellenfeldern brauchte zudem echtes tabellenspezifisches `IF` statt einer beide Feldformen bindenden `CASE`-Expression.

Die vollständige erste PG-Regression meldete zwei Abweichungen der bestehenden Namespace-/Content-Fehlercodes. Die neuen Receiver wurden auf den vorhandenen `23514`-Konfliktvertrag abgestimmt; unzulässige Ersetzung/Adoption bleibt abgewiesen. Die bestehenden negativen PG-Assertions blieben unverändert. Nach dem grünen 539-Fall-Vorlauf ergänzte die Schlussprüfung noch das Verbot gemischter neuer OU- und vorhandener OU-Mutationsaufträge und einen tatsächlichen gültigen Gegenproof-Test. Das aktuelle 540-Fall-Gate enthält diesen Zusatz. Die zustandsbehaftete API-Testfixture bildet die neue gescopte Actor-Abfrage und gespeicherte OU-Prozedur nach; sie ist kein Ersatz für die tatsächlichen PG-/signierten-/Browser-Gates.

### Quellstand und offene Abnahme

Runtime-Manifest: `/tmp/od-business8-runtime-frozen.sha256`, 239 ausgewählte Eingaben; abschliessender Vergleich `/tmp/od-business8-runtime-check-final.log`. Source-/Dokumentationsmanifest: `/tmp/od-business8-source-final.sha256`; Gates: `/tmp/od-business8-gates.json`. OpenAPI 3.1, Version 1.6.0, stimmt mit dem Generator überein; alle 62 lokalen Referenzen und 37 eindeutigen Operation-IDs sind geprüft. Keine Compose-/Docker-Konfiguration oder Secrets wurden geändert; kein Image-Build oder Deployment wurde ausgeführt.

Der Typecheck bleibt bei genau denselben 17 bestehenden Diagnosen wie Slice 7, abgesehen von Positionen unverändert; Exit 2 (`/tmp/od-business8-types-result.json`). Es wird kein erfolgreicher Produktionsbuild behauptet. Tatsächliche Benutzer-OU-Mitgliedschaften, Rollen-/Scope-Vererbung, Credential-Provisionierung, verbundene JML-/Geräte-/Blueprint-/Lizenzprozesse, übrige Business-Domains, DB-Login-/Retention-/Delivery-/Last-/Backup-/Restore-/WCAG-/Produktionsabnahmen bleiben offen. Echte `.env`, externe Produktivsysteme und fremde lokale Änderungen wurden nicht verändert. Kein Commit oder Push; der Gesamtauftrag bleibt aktiv.

## Business Slice 9: Mehrfache Benutzer-OU-Zuordnungen

Stand: 19. Oktober 2026. Abgenommen ist ausschliesslich der [aktive normalisierte Membership-Vertrag](../features/organization-memberships.md) mit bedingter API, echten berechtigten Mitarbeitendennamen, Mehrfachzuordnung und kontrolliertem Entzug. Nicht das vollständige Organisations-/Rollen-/JML-Modell oder die gesamte 16-Schritte-Demo.

| Abschliessendes Gate | Ergebnis | Tatsächlicher lokaler Beleg |
| --- | --- | --- |
| Identity Unit/API | 690 Fälle, 37 Suites, Exit 0, 2,135 s | `/tmp/od-business9-identity-unit-final.log` |
| Issuer Unit/API | 454 Fälle, 17 Suites, Exit 0, 6,532 s | `/tmp/od-business9-issuer-unit.log` |
| Gesamtes Frontend | 1'234 Fälle, 77 Suites, Exit 0, 44,967 s | `/tmp/od-business9-web-final.log` |
| Native PostgreSQL Identity | 563 Fälle, 14 explizite Dateien, Exit 0, 179,308090125 s | `/tmp/od-business9-native1.log` |
| Signierter Produktionsmodus-Gateway | 31 Fälle, Exit 0, 224,640404708 s | `/tmp/od-business9-production1.log` |
| Fokussierter tatsächlicher Chrome | 2 Fälle, Exit 0, 60,89685875 s | `/tmp/od-business9-browser1.log` |
| Native Browser-BFF | 46 Fälle, Exit 0, 0,429088167 s | `/tmp/od-business9-bff.log` |

**3'020** Fälle in sieben unterschiedlichen Gates. **61 neue Falldefinitionen** gegenüber Slice 8: 16 Identity-Unit-/Validierungs-, 22 Frontend- und 23 native PostgreSQL-Fälle (22 Membership und ein zusätzlicher roleloser Company-Owner-Fall). Die bestehenden signierten und Chrome-Workflows wurden erweitert, nicht als neue Fälle gezählt. Fokussierte 16-/65-Fall-PG-Vorläufe, frühere grüne Unit-Läufe und historische Matrizen werden nicht addiert. Native Gates haben keine Fail/Skip/Cancel/Todo; die vollständige historische Authority-/OAuth-/Chrome-/Produktmatrix wurde nicht nochmals ausgeführt.

### Tatsächliche Gegenprüfungen

- Eine echte eigene deaktivierte Person gehört gleichzeitig zwei eigenen OUs an. Jeder Link besitzt eine neue servergenerierte UUID; doppelte aktive Paare ergeben `409`. Exakte OU-Versionen steigen um eins, Metadaten, Department, Gruppen, Rollen und Lizenzen bleiben unverändert. Unlink betrifft genau eine Inkarnation; erneutes Add erzeugt eine neue ID, alte ID/Remove oder Wiederverwendung der retained UUID darf sie nicht ersetzen.
- Tatsächliches `ous.read` liefert ohne `users.read` keine Profile. Der bestehende OU-Verwalter erhält genau `ous.members.manage`, keine Personen-/Credential-/Lizenzrechte. Ein frischer gewöhnlicher MFA-Benutzer wird vor der Zielexistenz-Prüfung abgewiesen. Fremde eigene User-/OU-/Membership-Kombinationen und ein privilegiert importierter korrupter Cross-Tenant-Link werden nicht als Erfolg bzw. Profil ausgegeben.
- 27 reale Links prüfen Pagination/Count/Revision aus demselben Snapshot. Aktive Beziehungen blockieren OU- und kanonische Benutzerlöschung. Erst kontrolliertes Unlink erlaubt lokales Retirement; genaue historische Membership-Proofs und Ownership bleiben erhalten.
- Konkurrente Adds warten beobachtet mit exakter Backend-PID am echten SQL-Lock; die zweite alte Version erhält `412`. Add vor wartendem OU-Delete erzwingt erst stale Version, dann tatsächliche Abhängigkeit. Wartende Benutzerlöschung kann einen neuen Link nicht umgehen; gewinnt die Benutzerlöschung zuerst, wird das spätere Add `404` statt einer dangling Row.
- Ursprünglicher später Bearer-Entzug, physischer Fristablauf am Commit, fehlende Membership-Row/Events/Outbox/Receiver, gelöschte GUCs, Zusatzwrites/Truncate und späte Trigger-Drift rollen Effekt und Belege zurück. Ein echter beschränkter SQL-Login oder `SET ROLE` kann die private Admission nicht als Datenbankowner benutzen. Replay und fremde Caller-Zeitzone erhalten exakt gebundene UTC-Belege.
- Der signierte Gateway-Workflow benutzt echte ursprüngliche Owner-Capabilities, fresh MFA und `roles:[]`, weist eine deaktivierte Person zwei Einheiten zu, prüft tatsächliche berechtigte Profile und entfernt nur einen Link. Fehlende/stale Versionen, fremde Ziele und weitergehende Rollen-/Session-/Löschrechte bleiben verweigert.
- Frischer Chrome registriert/aktiviert die Firma, führt Pflicht-MFA durch und erstellt eigene OUs, Mitarbeitende und Gruppen. Anschliessend sucht er nach dem tatsächlichen Namen, weist dieselbe Person zwei Einheiten zu und bestätigt genau einen Entzug. SQL prüft beide Links vor der Bestätigung, nur den verbleibenden danach und unveränderte Gruppen-/Rollen-/Statusdaten. `/tmp/od-business9-company-members.png` und `/tmp/od-business9-company-unlinked.png` wurden visuell geprüft; keine vollständige WCAG-Abnahme.
- Frontend-Vertrag und UI prüfen genaue Revisionen auch oberhalb sicherer JSON-Zahlen, Counts, Actor-/Profile-Grenzen, Read-only/Down-level-Verhalten, echte Auswahl, Bestätigung, stale Fehler ohne Schreibretry und verspätete Lese-/Schreibergebnisse nach Sessionverlust.

### Vorläufe und Korrekturen

Der erste Typecheck fand zusätzlich ein neu verwendetes BIGINT-Literal im niedriger zielenden bestehenden TS-Projekt. Es wurde ohne Stack-/Target-Wechsel zu `BigInt(1)` korrigiert; der finale Lauf hat wieder genau die 17 bekannten Diagnosen. UI-Fixtures wurden auf kohärente tatsächliche Counts und separat erlaubte Profile korrigiert, nicht die Runtime-Validierung gelockert. Ein zunächst wirkungsloser positiver Eintrag in einer Invalid-Body-Testtabelle wurde entfernt und nicht als Testnachweis gezählt.

Der ältere Migration-042-Replay-Test stellt nach seiner historischen Prüfung jetzt die tatsächlich späteren Migrationen wieder her. Er darf den aktuellen Membership-Receiver nicht still durch einen alten Funktionskörper ersetzen. Bestehende ursprüngliche Assertions bleiben erhalten; kein Fence wurde für den Replay-Lauf gelockert.

Ein Wiederholungslauf nach ergänzten OpenAPI-Assertions hatte einen einzelnen `socket hang up` im bestehenden Produktionsstart-/Storage-Verweigerungstest, nicht in der neuen Contract-Prüfung (`/tmp/od-business9-identity-unit-post-contract-firstfailure.log`). Der unmittelbar folgende vollständige Identity-Lauf bestand alle 690 Fälle. Keine fachliche Assertion oder Sicherheitsprüfung wurde entfernt, um diesen Vorlauf zu übergehen; eine allgemeine Ursachen-/Flake-Abnahme wird nicht behauptet.

### Quellstand und weiterhin offen

Alle 742 zuvor erfassten Quelldateien waren vor dem Slice unverändert (`/tmp/od-business9-baseline-check.log`). Runtime-Manifest: `/tmp/od-business9-runtime-frozen.sha256`, **242** ausgewählte Eingaben; Schlussvergleich `/tmp/od-business9-runtime-check-final.log`. Source-/Dokumentationsmanifest: `/tmp/od-business9-source-final.sha256`, **750** Eingaben; Gate-Matrix `/tmp/od-business9-gates.json`. OpenAPI 3.1, Version 1.7.0, stimmt exakt mit dem Generator überein; 40 eindeutige Operation-IDs und alle 69 lokalen Referenzen wurden geprüft. Das ist ein begrenzter lokaler Quellbeleg, kein dauerhafter CI-/Release-Nachweis.

Der finale Typecheck bleibt bei denselben **17** Pfad-/Code-/Meldungsdiagnosen wie Slice 8, nach Normalisierung der Positionen unverändert; Compiler-Exit 2 (`/tmp/od-business9-types-result.json`). Kein Produktionsbuild, Image-Build, Deployment oder externe Produktivschreiboperation. Echte `.env`, die vorhandene `.claude/settings.local.json`-Änderung und die benutzerseitige Callback-Löschung bleiben unangetastet; kein Commit oder Push.

Nicht abgeschlossen: primäre Beschäftigung/Legal Entities, Custom Roles/OU-Scopes und Vererbung, zugangsfähiges Employee-Onboarding, Mover/Leaver-Entzüge, Geräte-/Blueprint-/App-/Lizenzprozesse, Standorte/Marketing/Analytics/Billing/Support/Collaboration/Integrationen sowie allgemeine DB-Login-/Retention-/Delivery-/Last-/Backup-/Restore-/WCAG-/Produktionsabnahmen. Pending-Outbox ist kein ausgelieferter Workflow und eine OU-Zuordnung vergibt keine Lizenz. Der volle Master-Prompt bleibt aktiv.

## Business Slice 10: Geräteinventar und Zuweisung

Stand: 19. Oktober 2026. Abgenommen ist der [begrenzte eigene Inventory-only-Weg](../features/device-inventory.md) vom tatsächlichen ursprünglichen Company-Owner und eigenen Mitarbeitendendatensatz bis zur persistenten Gerätezeile, exklusiven Zuweisung/Neuzuweisung/Entzug und retained Historie. Keine vollständige Geräte-/JML-/Provider- oder SaaS-Abnahme.

| Abschliessendes Gate | Ergebnis | Tatsächlicher lokaler Beleg |
| --- | --- | --- |
| Gesamtes Identity Unit/API | 704 Fälle, 38 Suites, Exit 0, 3,710 s | `/tmp/od-business10-identity-unit-final2.log` |
| Gesamtes Issuer Unit/API | 454 Fälle, 17 Suites, Exit 0, 6,556 s | `/tmp/od-business10-issuer-unit-final.log` |
| Gesamtes Frontend | 1'371 Fälle, 79 Suites, Exit 0, 47,164 s | `/tmp/od-business10-web-final.log` |
| Native PostgreSQL Identity | 565 Fälle, 14 explizite Dateien, Exit 0, 180,484853334 s | `/tmp/od-business10-identity-native-final.log` |
| Neues natives PostgreSQL-Inventar | 52 Fälle, Exit 0, 8,102875125 s | `/tmp/od-business10-inventory-bigint-agent.log` |
| Fokussierte Device-Contracts/Source/Startup | 201 Fälle, 3 Suites, Exit 0, 0,827 s | `/tmp/od-business10-device-focused-final.log` |
| Gesamtes Core-Gateway Unit/API | 132 Fälle, 5 Suites, Exit 0, 1,463 s | `/tmp/od-business10-gateway-final2.log` |
| Signierter Produktionsmodus-Gateway | 31 Fälle, Exit 0, 226,547578 s | `/tmp/od-business10-production-final2.log` |
| Fokussierter tatsächlicher Chrome | 2 Fälle, Exit 0, 66,0677305 s | `/tmp/od-business10-browser-final.log` |
| Native Browser-BFF | 46 Fälle, Exit 0, 0,441337583 s | `/tmp/od-business10-bff-final.log` |

**3'558** erfolgreiche Fälle in zehn getrennten begrenzten Gates, **nicht sämtliche Repository-Tests**. **418 neue Falldefinitionen** gegenüber Slice 9: 14 Identity-Unit-, 137 Frontend-, zwei Identity-PG-, 52 Device-PG-, 201 Device-Contract/Authority/DB- und zwölf Gateway-Fälle. Die 120 schon vorhandenen Core-Gateway-Fälle werden erstmals in dieser Business-Matrix mitgeprüft, nicht als neue Definitionen ausgegeben. Bestehende signierte und Chrome-Flows wurden erweitert, nicht zusätzlich gezählt. Vorläufe, historische Matrizen und die separat fehlgeschlagene Legacy-Device-Gesamtsuite werden nicht addiert.

### Tatsächlich geprüft

- Ein real aktivierter Owner mit `roles:[]` registriert ein eigenes Gerät mit unbekannter Compliance, keinem Last Seen/Enrollment/Provider und keinem effektiven App-/Lizenzgrant. Tatsächlicher Tenant, servergenerierte UUIDs, Werte, Actor, ursprünglicher Source, Correlation-ID und Pending-Outbox werden in PostgreSQL kontrolliert.
- Originaler Audience-/RS256-/Purpose-/Issuer-/Tokenstatus, unabhängig gebundene MFA und aktuelle kanonische Rollen/Owner/Home-Quellen. Inventar-Claims und allgemeine Proxy-Rechte ersetzen keine Authority. Fremde bzw. fehlende User-/Device-IDs werden nicht aufgelöst; eigene deaktivierte Mitarbeitende dürfen Inventar erhalten, ohne dadurch aktiv zu werden. Profile bleiben separat durch tatsächliches `users.read` geschützt.
- Eine exklusive aktive Zuweisung, atomarer Wechsel mit erhaltenem vorherigem Link, ausdrücklicher Entzug, genaue ETags/Revisionen und paginierte tatsächliche Historie. Fehlende/stale/fremde ETags, doppelte Zuordnung/Entzüge, case-insensitive Inventar-/Serienkonflikte und callerbestimmte Tenant-/Status-/Providerfelder erzeugen keinen Erfolg.
- Echte SQL-Konkurrenz: der zweite same-ETag-Writer wartet beobachtet auf den tatsächlichen Row-Lock und erhält nach Commit der ersten Änderung `412`. Fehlschläge nach tatsächlichem DML, Originalentzug am letzten Checkpoint und Ablauf der ursprünglichen Frist am physischen Commit rollen Geräte, aktive/alte Beziehungen und Belege vollständig zurück.
- Fehlende Row-/Truncate-/Deferred-Receiver, ausgelassene Geräte/Assignments/Event-/Outbox-Wirkung, spätere Row-/Zielsnapshot-Drift, gelöschte GUCs, Raw-SQL, tatsächlicher beschränkter SQL-Login und `SET ROLE` erzeugen keinen erfolgreichen Originalauftrag. Replay und fremde Caller-Zeitzonen behalten die echten Belege.
- Zwei ausdrücklich privilegierte Fixture-Importe setzen hohe bestehende Revisionen `9007199254740993` und `9223372036854775806`. Echte SQL-Textwerte, Reads, ETags, Before-/After-Proofs und Folgerevisionen bleiben exakt bis `9223372036854775807`. Danach bestätigt `22003` vollständigen Rollback ohne zusätzliche Ereignisse, Outbox oder Zuweisung. Keine erfundene rückwirkende Historie für die importierten Ausgangsversionen.
- Gateway prüft vor jedem eigentlichen Device-Passthrough eine aktuelle echte Receiver-Capability mit demselben menschlichen Bearer. Down-level-/fremde/unbestätigte Receiver und gemeinsame Key-/Workload-Abkürzungen bleiben gesperrt; der frühere Namespace-Rewrite auf `/api` wird nicht mehr verwendet. Erst der bestätigte kanonische Receiver beantwortet nicht unterstützte Wipe-/Provideraktionen mit `501`.
- Der signierte Gateway-Prozess und frischer Chrome nutzen tatsächliche Issuer-/Identity-/Device-/PostgreSQL-Receiver, nicht eine Gerätemock-Antwort. Chrome erfasst ein Gerät, wählt einen tatsächlichen gesperrten eigenen Mitarbeitenden, prüft die noch leere DB-Zuweisung vor Bestätigung und bestätigt Zuweisung/Entzug. SQL prüft unveränderten Benutzerstatus, erhaltene released Beziehung und echte Pending-Historie. Screenshots `/tmp/od-business10-company-device-assigned.png` und `/tmp/od-business10-company-device-released.png` wurden visuell geprüft; keine vollständige WCAG-Abnahme.
- Neue Startup-Tests bestätigen: erst **alle** Migrationen machen Storage verfügbar; Verbindungs-/Migrationsfehler erzeugen keinen Memory-Erfolg. Echte final-source-check-before-COMMIT-Reihenfolge, Rollback und read-only Repeatable Read sind geprüft. UI/Client kontrollieren exakte Antworten, Tenant/Actor/Revisionen, unabhängige Profilrechte, Sitzungswechsel/Abort/verspätete Ergebnisse, Read-only/Down-level-Verhalten und kein automatisches Write-Retry.

### Gegenbelege, Korrekturen und nicht grünes Legacy-Gate

Die vorhandenen Device-Dependencies fehlten zunächst lokal; aus dem bestehenden unveränderten Lockfile wurden 576 Pakete mit `npm ci --ignore-scripts --no-audit --no-fund` installiert. Keine neue Dependency oder Versionsänderung wurde aufgenommen.

Der erste signierte neue Weg scheiterte korrekt an der alten generischen `gateway.proxies.devices.access`-Grenze. Sie wurde nicht durch einen globalen Owner-Claim ersetzt: ein dedizierter Original-Bearer-/Receiver-Handshake plus unabhängige tatsächliche Device-/Identity-Autorisierung schützt den erhaltenen vollständigen Namespace. Die alte generische Proxy-Assertion erwartet nun korrekt eine Verweigerung statt eines Bypasses. Frühere signierte Fehlversuche bleiben unter `/tmp/od-business10-production1.log` erhalten.

Der erste Browserlauf konnte die implizit aus allen Optionsinhalten gebildeten Select-Labels nicht exakt auswählen. Die echten Controls besitzen jetzt eindeutige zugängliche Namen. Zudem hatte der erste Picker gesperrte Datensätze ausgefiltert, obwohl Inventarzuordnung keine Kontoaktivierung ist. Er zeigt nun beide Zustände mit Kennzeichnung; ein zusätzlicher UI-Fall und der reale gesperrte Company-Mitarbeitende prüfen diesen Geschäftsprozess. Die API-Rewrite-Fixture wurde auf den jetzt tatsächlich vorhandenen Receiver aktualisiert, nicht eine alte Catch-all-Antwort beibehalten.

Die Schlussprüfung fand einen echten BIGINT-Verlustpfad: `to_jsonb(devices)` hätte grosse Revisionen als JSON-Zahl nach JavaScript geschickt. Der typisierte UTC-Snapshot und der passende Row-Guard erhalten die Revision nun ausdrücklich als Text. Der anfängliche native Vergleich zeigte entsprechend `1` statt `"1"`; die volle Row-Assertion wird jetzt aus der tatsächlichen Raw-Row plus unabhängigem SQL-`inventory_revision::text` gebildet, nicht durch Entfernen von Feldern oder Vergleich derselben Helperfunktion mit sich selbst. Die zwei hohen nativen Revisionsfälle sind im abschliessenden 52-Fall-Lauf enthalten.

**Separat nicht grün:** Die vollständige alte Device-Jest-Suite hat **6 failed / 505 passed / 511 total**, 1 failed / 17 passed Suites, Exit 1 (`/tmp/od-business10-device-unit-final.log`). Diese Fehler werden nicht als akzeptierte Fälle gezählt. Ein wegwerfbarer Legacy-Vergleich in `/tmp` mit originalem unverändertem `db.js` aus Git und nur Migrationen 001–004 zeigt alle sechs selben Fehlertitel ebenfalls (dort 7 failed / 303 passed / 310 total; `/tmp/od-business10-legacy-full-baseline.log`, `/tmp/od-business10-legacy-baseline-comparison.json`). Ein isolierter 38-Fall-Legacy-Test bestand, liess aber alte MessageBus-Timer offen; dieser abgeschlossene Versuch wurde beendet und nicht als erfolgreiche Gesamtabnahme ausgegeben. Keine fachliche Runtime-Prüfung wurde gelockert, um diese überholten/race-anfälligen Legacy-Fixtures zu übergehen. Deren allgemeine Reparatur und die ganze frühere Geräteplattform sind nicht Bestandteil des akzeptierten neuen Inventargates.

### Quellstand und offene Abnahme

Alle 750 zuvor erfassten Quelldateien waren vor dem Slice unverändert (`/tmp/od-business10-baseline-check.log`). Runtime-Manifest: `/tmp/od-business10-runtime-frozen.sha256`, **261** ausgewählte Eingaben; abschliessend geprüft unter `/tmp/od-business10-runtime-check-final.log`. Source-/Dokumentationsmanifest: `/tmp/od-business10-source-final.sha256`, **845** Eingaben einschliesslich vorhandener Device-Quellen und neuer Tests. Gate-Matrix: `/tmp/od-business10-gates.json`.

Generierter gemeinsamer OpenAPI-3.1-Vertrag **Version 1.8.0**, **48** eindeutige Operation-IDs und **78** aufgelöste lokale Referenzen, exakt gleich dem Generator. Beide Compose-Varianten bestehen read-only `config --quiet` mit explizit wegwerfbaren Env-Werten und ohne echte `.env` (`/tmp/od-business10-compose-full.log`, `/tmp/od-business10-compose-lite.log`); kein Container/Image wurde gebaut oder gestartet.

Der finale Typecheck hat weiterhin genau die **17** bekannten Diagnosen, gegenüber Slice 9 nach Normalisierung der Positionen identisch, Exit 2 (`/tmp/od-business10-types-final.log`). Kein Produktionsbuild oder Deployment. Echte `.env`, die vorhandene `.claude/settings.local.json`-Änderung und die benutzerseitige Callback-Löschung bleiben unverändert; kein Commit/Push oder externer Produktiv-Write.

Vollständiger Lifecycle, Legacy-Geräteadoption, organisatorische Gerätescopes/Delegation, atomare Cross-DB-JML-/Dependenzgarantien, echte Enrollments/Provider-/Compliance-/Remote-Aktionen, verbundene Blueprints/Apps/Lizenzen und sämtliche übrigen Master-Prompt-Domains bleiben offen. Pending-Outbox ist kein ausgelieferter Auftrag. DB-Login-/Retention-/Privacy-/Delivery-/Last-/Backup-/Restore-/WCAG-/Produktionsabnahmen sowie die Legacy- und TypeScript-Probleme sind weiterhin keine erledigten Anforderungen. Der Gesamtauftrag bleibt aktiv.

## Business-Slice 11: Mandantengebundene Lizenzquellen

Stand: 19. Oktober 2026. [Implementierter Vertrag](../features/tenant-license-sources.md). Dieser Slice beseitigt die gefundene mandantenübergreifende menschliche und maschinelle Lizenz-/Policy-Quellprojektion. Er implementiert **nicht** die noch fehlende Business-Tenant-Hoheit der bisherigen globalen App-/Lizenzpools, Company-App-/Lizenz-UI oder vollständige BR-002/005/012.

### Lokale Gates

| Gate | Tatsächlicher Endstatus | Lokaler Beleg |
| --- | --- | --- |
| Identity-Jest | 745/745, 40 Suites, Exit 0, 3,085 s | `/tmp/od-business11-identity-unit-final3.log` |
| Policy-Jest | 661/661, 19 Suites, Exit 0, 2,858 s | `/tmp/od-business11-policy-unit-final.log` |
| Issuer-Jest | 454/454, 17 Suites, Exit 0, 5,668 s | `/tmp/od-business11-issuer-unit-final.log` |
| Frontend-Jest | 1'371/1'371, 79 Suites, Exit 0, 81,261 s | `/tmp/od-business11-web-final.log` |
| Identity/PostgreSQL | 609/609, 17 explizite Dateien, Exit 0, 209,942537709 s | `/tmp/od-business11-identity-native-agent.log` |
| Policy/PostgreSQL | 297/297, 8 explizite Dateien, Exit 0, 34,007663 s | `/tmp/od-business11-policy-native-agent.log` |
| Signierte echte Issuer-/Gateway-/Identity-Quellen | 38/38, Exit 0, 307,561784958 s; 32 Production-Gateway-, zwei Eligibility-/Worker- und vier Group-Source-Fälle | `/tmp/od-business11-signed-agent.log` |
| Frischer echter Chrome | 2/2, Exit 0, 67,120962416 s | `/tmp/od-business11-browser-final.log` |
| Nativer Browser-BFF | 46/46, Exit 0, 0,4308265 s | `/tmp/od-business11-bff-final.log` |

**4'223 erfolgreiche Fälle über neun abgegrenzte Gates**, keine Fail/Skip/Cancel/Todo in den akzeptierten nativen Läufen und keine übersprungenen Unit-Suites. 107 neue Falldefinitionen: 41 Identity-Unit-, 21 Policy-HTTP-Vertrags-, 44 native Identity- und ein signierter Quellfall. Sechs bereits bestehende dedizierte Workload-/Group-Source-Fälle werden zusätzlich erstmals in dieser Business-Matrix mitgezählt, nicht als neu erfundene Tests. Vorbereitende, fokussierte oder wiederholte Läufe werden nicht addiert. Der ursprüngliche Firmen- und Profil-Browserworkflow umfasst weiterhin die tatsächliche eigene Geräteerstellung, exklusive Mitarbeitenden-Zuweisung und Entzug; dafür ist keine neue UI oder simulierte Lizenzvergabe hinzugekommen.

### Nachgewiesene Grenze

- `SnapshotBoundary` benutzt ursprünglichen Live-Bearer, aktuelle tatsächliche kanonische Pflicht und immutable eigene Zielhoheit, nicht behauptete Admin-/Permission-Aliasse. Reine Quellen sind physisch read-only; der kontrollierte eigene Gruppenrefresh ist die explizite Ausnahme. Fremde/unowned UUIDs bleiben verborgen. Aktive, deaktivierte und retained gelöschte Identitäten sind unterscheidbar, ohne fremde historische IDs als inactive/unresolved zu exportieren.
- 22 neue Boundary-Unitfälle, zwei explizite Group-Ownership-Projektionsfehler und 15 reale PostgreSQL-Grenzfälle beweisen eigene/negative/gelöschte Ziele, alle Rollenquellen, gesonderte Self-only-Belege, physische Read-only-Grenzen, einen tatsächlichen Lock-Wait und ursprünglichen Entzug während SQL. Die Native-Fälle verwenden Migrationen 001–044, tatsächliche Canonical Contexts und die echte Offline-Source-Funktion.
- 20 neue native Migration-044-Fälle beweisen unveränderliche Tenant-/Issuer-/Client-Herkunft, optimistic Source-Versionen, bewusste monotone Clientrotation bis exakte BIGINT-Grenzen, tatsächlichen SQL-Owner statt `SET ROLE`, Append-only-/Truncate-/No-effects-/Receiving-/Deferred-Commit-Belege, leere versus konfigurierte Schemata, fehlende Rows/Events/Outbox, Schema-/UTC-Pinning, Replay und explizite CLI-Konfiguration ohne Runtime-DB-Fallback.
- 16 neue Group-Consent-Unitfälle und neun reale native Fälle prüfen tatsächliche menschliche Pflicht, originale Bearer, eigene List/Get/Create/Revoke-Hoheit vor fremden Gruppenlocks, retained Ersteller-/Gruppen-Tenant, eigene gelöschte/pausierte Negativbelege und wirklichen Ziel-Tenant-Generationswechsel zwischen zwei Beobachtungen. Die fünf alten positiven Identity-HTTP-Fixtures bestellen nun tatsächliche kanonische Rollen/Contexts statt signierte Rollen-/Permission-Claims als Autorität zu behandeln.
- Die Policy-Receiver verlangen den exakten Protocol-1-Header. 21 neue HTTP-Vertragsfälle prüfen fehlende/falsche Versionen, Original-Bearer, wiederholte 404 und keine Fallback-/Cache-Antwort. Positive minimale native HTTP-Fixtures bestätigen das Protokoll ausdrücklich; sie sind keine realen Hersteller- oder vollständigen Identity-Server. Die negative Inventory-Fixture liefert bewusst `403`; der tatsächliche Gateway-Gate bleibt ebenfalls `403`, nicht eine abgeschwächte 404-Erwartung.
- Der neue signierte Grenzfall prüft sieben tatsächliche Quellen mit wirklichen aktuellen spezialisierten Rollen, zwei Tenants, fremden/fehlenden UUIDs, normalen Self-only-Personen, exakten minimalen DTOs und kanonischem Admin ohne Fremd-Bypass. Die sechs Lizenzquellen laufen durch den realen Production-Gateway; die private Policy-Publication-Quelle wird direkt am echten Identity-Service geprüft, nicht als bereits öffentliches Gateway-Routing behauptet. Bestehende Workload-/Graph-HTTP-Tests bestellen die echte Source ausdrücklich, prüfen ungebundenes Deny und notwendige erneute Review nach Clientrotation. Keine Cloud-Lizenz wurde vergeben.

Ein separater read-only Review der gemeinsamen Boundary und sieben öffentlichen Identity-Routen ergab keinen konkreten Befund. Das ersetzt keinen vollständigen Security Review oder eine externe Prüfung.

### Nicht akzeptierte Vorbereitung und offene Abnahmen

Der erste Policy-Nativlauf scheiterte an alten Fixtures ohne neuen Pflichtheader und hing anschliessend an einem von der fehlgeschlagenen Voraussetzung abhängigen Testbarrier. Er wurde am konkret identifizierten Parent nach erneutem Poll kontrolliert beendet, **nicht** als Erfolg gezählt. Positive Header-Fixtures und die vorhandene Inventory-Deny-Fixture wurden korrigiert; erst der terminale Gesamtlauf mit 297 Fällen gilt. Ein Identity-Jest-Vorlauf hatte einen einzelnen Socket-Hangup; zwei nachfolgende vollständige Läufe mit je 745 Fällen bestehen. Ein erster signierter Lauf hatte 33 Erfolge und einen neuen frühen MFA-Fixture-Fehler; die tatsächliche erforderliche App-Zuweisung wurde in der Testfixture ergänzt, nicht die Runtime-MFA gelockert. Nach dem fokussierten Nachweis ist der erweiterte vollständige 38-Fall-Lauf grün; beide Vorläufe werden nicht addiert.

### API und Quellenbeleg

Alle 845 zuvor erfassten Source-Eingaben waren vor Beginn unverändert (`/tmp/od-business11-baseline-check.log`). Das begrenzte finale Source-/Dokumentationsmanifest enthält **856** Eingaben (`/tmp/od-business11-source-final.sha256`); die Gate-Matrix liegt unter `/tmp/od-business11-gates.json`. Das Runtime-/Fixture-Manifest umfasst **346** ausgewählte Eingaben (`/tmp/od-business11-runtime-frozen.sha256`), abschliessend unter `/tmp/od-business11-runtime-check-final.log` geprüft. Gegenüber dem ersten Freeze wurde ausschliesslich die neue signierte native Testfixture nach ihrem vorbereitenden MFA-Fehler übernommen, keine Runtime-Authority gelockert; die übrigen 345 Eingaben blieben identisch. Die finalen signierten Tests laufen mit dem übernommenen Quellstand.

Der gemeinsame OpenAPI-3.1-Vertrag **Version 1.9.0** stimmt exakt mit dem Generator überein, enthält **55** eindeutige Operation-IDs und **85** aufgelöste lokale Referenzen. Sieben minimale Quelloperationen, ihre exakten DTOs und der verpflichtende Receiver-Header sind hinzugekommen; kein HTTP-Endpunkt für die ausschliesslich offline bestellte Benutzerquelle wird behauptet. 14 abgegrenzte Business-/Architektur-/Feature-/Operations-/Testdokumente enthalten **116** geprüfte lokale Links/Anker ohne Fehler (`/tmp/od-business11-doc-links.json`). Diese lokalen temporären Belege ersetzen keine dauerhafte CI-/Release-Abnahme.

Der finale direkte Typecheck besitzt weiterhin **17** Diagnosen, Exit **1**, nach Normalisierung der Positionen identisch zu Slice 10 (`/tmp/od-business11-types-direct.log`, `/tmp/od-business11-types-result.json`). Kein erfolgreicher Produktionsbuild. Die sechs bekannten Legacy-Device-Unitfehler wurden in diesem Quellen-Slice nicht erneut als Gesamtsuite geprüft oder als grün gezählt; die tatsächlichen Firmen-/Inventar-Browserwege bestehen. Keine Compose-Konfiguration oder Dependency wurde verändert, kein neues Image gebaut, kein Deployment, Commit/Push oder externer Produktiv-Write ausgeführt. Vorhandene `.claude/settings.local.json`-Änderung und benutzerseitige Callback-Löschung bleiben unangetastet.

Aktualisierung aller Identity-/Policy-Receiver und bewusste Offline-Bestellung der dedizierten Tenant-Quellen sind Voraussetzungen für einen späteren Rollout. Die Migration ist keine automatische Übernahme früher globaler Worker. Ungebundene bzw. nach Rotation veraltete Workloads bleiben gesperrt. Ein Graph-Tenant oder eine Resource-Lease ist keine Business-Tenant-Hoheit. Eigene App-/Pool-Verteilung über den vorhandenen Allocator **vor allen** Eligibility-/Reconciliation-Effekten, vollständige JML-/Blueprint-/Geräteverknüpfung, Scopes, Retention/Privacy/Least-Privilege-DB-Logins und sämtliche übrigen Master-Prompt-Domains sowie Betriebsabnahmen bleiben offen. Der Gesamtauftrag bleibt aktiv.

## Business-Slice 12: Eigenes Firmen-Lizenzinventar

Stand: 19. Oktober 2026. [Tatsächlicher Benutzerweg, SQL-/API-Vertrag und Grenzen](../features/company-licenses.md). Neue eigene endliche Firmenpools und direkte lokale Benutzerzuweisung/Freigabe verwenden den **bestehenden** Allocator mit wirklichen Source-/Grant-/Projektions-/Audit-Effekten. Der ursprüngliche Roleless-Company-Owner erhält keine globale Lizenzrolle. Keine Herstellerbeschaffung, Cloud-Zuteilung, App-Installation oder automatische Company-Leaver-Rückgabe wird aus diesem lokalen Prozess behauptet. Vollständiger BR-005 und Gesamtauftrag bleiben offen.

### Akzeptierte finale Gates

| Gate | Tatsächlicher Endstatus | Lokaler Beleg |
| --- | --- | --- |
| Identity-Jest | 771/771, 41 Suites, Exit 0, 4,407 s | `/tmp/od-business12-identity-unit-final.log` |
| Policy-Jest | 763/763, 22 Suites, Exit 0, 4,103 s | `/tmp/od-business12-policy-unit-final.log` |
| Issuer-Jest | 454/454, 17 Suites, Exit 0, 5,988 s | `/tmp/od-business12-issuer-unit-final.log` |
| Frontend-Jest | 1'510/1'510, 81 Suites, Exit 0, 74,443 s | `/tmp/od-business12-web-final.log` |
| Identity/PostgreSQL | 611/611, 17 explizite Dateien, Exit 0, 219,880918333 s | `/tmp/od-business12-identity-native-final.log` |
| Policy/PostgreSQL inklusive Firmenpools | 355/355, 9 explizite Dateien, Exit 0, 58,986455209 s | `/tmp/od-business12-policy-native-final.log` |
| Echte signierte Production-Gateway-/Source-Regression | 38/38, Exit 0, 335,260756583 s | `/tmp/od-business12-signed-final.log` |
| Frischer echter Chrome | 2/2, Exit 0, 83,265044584 s | `/tmp/od-business12-browser-frozen-final.log` |
| Nativer Browser-BFF | 46/46, Exit 0, 0,55890325 s | `/tmp/od-business12-bff-final.log` |

**4'550 erfolgreiche Fälle in neun abgegrenzten Gates**, keine Fail/Skip/Cancel/Todo in den akzeptierten nativen Läufen. **327 neue Falldefinitionen** gegenüber Slice 11: 26 Identity-Unit-, 102 Policy-Unit-/Vertrags-, 139 Frontend-, zwei native Identity- und 58 native Policy-Fälle. Die bestehenden signierten Firmen- und Browserabläufe wurden um die tatsächliche Lizenzverteilung erweitert, nicht zusätzlich als neue Testdefinitionen gezählt. Vorbereitende/fokussierte/wiederholte Läufe werden nicht addiert.

### Was tatsächlich verbunden ist

- Echter ursprünglicher Company-Owner mit Pflicht-MFA und `roles=[]` → eigene Lizenz-Capabilities → neuer Pool mit einem endlichen Platz → explizit freigegebener eigener Mitarbeiter → bestehender `LicenseAllocator` mit Direct-Source, immutable Grant und effektiver `license_assignments`-Row → bestätigte Freigabe → tatsächlicher freier Platz und Pending-Historie. Dieselben SQL-Tabellen, keine parallele Allokationsdatenbank.
- Signierter echter Gateway prüft fremdes Home-Admin trotz tatsächlichem `admin`, Legacy-Katalog/Kiosk/Detail/Assignments/Audit und Legacy-Write gegen den neuen Pool. Fehlende/alte Version, Duplikat, fremder Empfänger, gesperrter Empfänger und ausgeschöpfte Kapazität erzeugen keine neue Allokation. Das kapazitätsbedingt abgebrochene zweite eigene Ziel hinterlässt auch keine Subject-Adoption. Nach echter kanonischer Kontosperre kann der Owner die bisherige lokale Zuordnung ausdrücklich freigeben; kein Providerprodukt wird angelegt.
- Der neue ursprüngliche Identity-Source besitzt 25 Unit-/Contract-Fälle und zwei tatsächliche native DB-Fälle zusätzlich zur signierten/browsergebundenen Owner-Abnahme: aktueller Home-Actor, eigenes aktives/gesperrtes/retained gelöschtes Ziel, fremde IDs, Role-/Permission-Aliasse und tatsächlicher Actor-Entzug nach SQL. 32 Policy-HTTP-Fälle prüfen den originalen Bearer, exakte elf Source-Felder, positive/negative Inkarnation, Frist, Limits und Fehler ohne Ersatzcredential/Fallback.
- 13 Company-Ordering-Fälle prüfen eigene Pool-/Versions-/Governance-Abnahme **vor** Recipient-Eligibility/Allocator, verweigerte globale Reconciliation und keine bestätigte Oberfläche ohne tatsächlichen Abschluss. Der vorhandene Scope-Kontext ist kein Company-Owner-Ersatz; PIM/Review/Provider/Gruppen-/Request-governierte Pools bleiben kontrolliert gesperrt.
- 55 neue Company/PostgreSQL-Fälle im vollständigen neunten Policy-Nativfile prüfen die wirklichen Allocator-Effekte, Original-/Effect-/Receipt-/Pending-Outbox-Belege, tatsächlichen Row-Lock und konkurrierende endliche Kapazität, physische Frist nach Finalisierung, volle positive BIGINT-Grenze, Read-Receipt-Kette, Raw-DML/Scope-GUC-/`SET ROLE`-Ersatz, fehlende Receiver/unterdrückte Effekte, vorherige/nachherige fremde Lizenzschreibvorgänge, nicht truncatebare Historie, Replay und leere versus historisch belegte Subject-Bindung.
- Die Legacy-Abgrenzung betrifft 14 zusätzliche Governance-/Group-/Provider-/Worker-Runtime-Dateien sowie den Allocator, Eligibility und normale Routen. 57 neue fokussierte Unitfälle und drei native Legacy-Fälle prüfen Null-only-Parent-Lookups, Source-Reihenfolge, globale Subject-/Provider-Fan-out-Grenzen und einen wirklichen Kandidaten-/Adoptions-/Error-Upsert-Race. Die bestehende Lifecycle-Suite bleibt erhalten.
- `/applications` verwendet den echten neuen Katalog. Separat autorisierte Profile liefern freundliche Namen; ohne diese Freigabe bleibt UUID-Fallback. Lokalisierte Datumsanzeige und per Tastatur aufklappbare Originalnachweise ersetzen eine primäre Vier-UUID-Tabelle. Sämtliche Erfolge stammen aus bestätigten Backend-Operationen; kein simulierter SSO-Verbindungstest wird ausgeführt. Writeretry, stale Session/Tenant/Actor, unbekannte DTOs und nicht bestätigte Antworten sind fail-closed getestet.

### Visuelle und betriebliche Prüfung

Die actual Chrome-Abnahme aktiviert den zuvor gesperrten Eintrag über die echte Personenoberfläche, erstellt einen lokalen Ein-Platz-Pool, prüft vor Bestätigung noch fehlende Allokation, weist zu und gibt über die tatsächlichen Dialoge wieder frei. Originale Device-/OU-/Profilabläufe bleiben im selben Workflow erhalten. Aktuelle Screenshots `/tmp/od-business12-company-license-assigned.png` und `/tmp/od-business12-company-license-released.png` wurden visuell geprüft: sichtbare eigene Hauptüberschrift, reale Bestandsänderung, verständliche Local-only-/Offboarding-Grenze. Der Nachweis ist per Enter bedienbar. Dies ist keine vollständige WCAG-2.2-AA-Abnahme.

Beide Compose-Varianten bestehen erneut read-only `config --quiet`, ausdrücklich ohne reale `.env` und mit wegwerfbaren Config-Werten (`/tmp/od-business12-compose-full.log`, `/tmp/od-business12-compose-lite.log`). Die neuen Package-COPY-Pfade beider Dockerfiles existieren. Kein Image-Build, kein Container-Deployment oder Hersteller-Write; keine neue Dependency. Der direkte Frontend-Typecheck hat weiterhin exakt dieselben **17** normalisierten Altfehler, Exit **2** (`/tmp/od-business12-types-final.log`). Die bekannte Legacy-Device-Unit-Gesamtsuite wurde in diesem Lizenz-Slice nicht als neu grün erklärt. Vorhandene Nutzeränderungen, echte `.env` und Callback-Löschung bleiben unverändert; kein Commit/Push.

### Nicht akzeptierte Vorbereitung

Frühe positive Unit-Fixtures hatten noch keine expliziten NULL-only-Pool-/Subject-Metadaten vor dem bestehenden Allocator. Sie wurden um konkrete Legacy-Metadaten ergänzt, ohne Authority-/Kapazitätsprüfungen abzuschwächen. Auch explizites Demo-Fallback benötigt zunächst bestätigte Legacy-Grenzen; eine unbekannte/offline Ownership wird nicht als Firmenrechteersatz verwendet. Native OAuth-/Browser-Fixtures luden zunächst nur bis Policy-Migration 021 und scheiterten korrekt an der fehlenden Company-Receiving-Funktion; beide wurden auf die echte Migration 022 erweitert, nicht mit einem Erfolgs-Mock versehen.

Synthetisch injizierte unbestätigte Company-Rows in Legacy-Negativtests blockierten korrekt anschliessendes Truncate. Ausschliesslich deren kontrollierte privilegierte Testinjektion wird nun in `finally` auf den vorherigen NULL-Zustand zurückgesetzt; reale Company-Commands/Receipts bleiben geschützt. Ein späterer vollständiger Vorlauf hatte 353/355 Erfolge und zwei reale `42P08`-Fehler im neuen Error-Upsert (`text` versus `varchar`); explizite Parameter-Casts beheben den Fehler, die Ownership-/Race-Prädikate bleiben bestehen. Nur die oben stehenden terminalen finalen Gesamtläufe zählen.

### Quellstand, API und verbleibender Umfang

Alle 856 zuvor erfassten Source-Eingaben waren vor diesem Slice unverändert (`/tmp/od-business12-baseline-check.log`). Das finale ausgewählte Source-/Dokumentationsmanifest umfasst **880** Eingaben (`/tmp/od-business12-source-final.sha256`); Runtime-/Fixture-Freeze **854** (`/tmp/od-business12-runtime-frozen.sha256`), nach den finalen Backend-/Signed-/Browsergates identisch geprüft. Die Frontend-Abnahme besitzt zusätzlich eigene Vorher-/Nachher-Manifeste; Schema-022-SHA256 `9a423cfc05b1cd677d9332caf35b364a36fbec2a151ba74e181d2d42737d27e1`. Gate-Matrix: `/tmp/od-business12-gates.json`. Temporäre lokale Belege ersetzen keine CI-/Release-Abnahme.

Der gemeinsame generierte OpenAPI-3.1-Vertrag **Version 1.10.0** ist exakt gleich dem Generator: **65** eindeutige Operation-IDs und **98** aufgelöste lokale Referenzen. Acht eigene Company-Lizenzoperationen und zwei originalgebundene Identity-Quelloperationen sind dokumentiert; keine nicht vorhandene Provider-/Installations-/Edit-/Delete-API. Die geprüften lokalen Dokumentationslinks sind im maschinenlesbaren Gate-Beleg erfasst.

Offen bleiben insbesondere eigene Company-Governance, Metadaten-/Bestandsänderungen, weitere Lizenzmodelle/App-Versionen/Pakete, Gruppen-/Geräte-/Blueprint-Zuweisungen, automatisches Company-JML und Lifecycle-Rückgabe, kontrollierte Legacy-Adoption, Kosten/Exporte und reale Provider. SQL-Owner bleibt eine ausdrückliche Betriebsvertrauensgrenze; keine unabhängige kryptografische SQL-Authentifizierung des Remote-Proofs, keine erledigte Logintrennung, Off-Host-Retention/Privacy, allgemeine Idempotenz oder Produktions-/Last-/Restore-Abnahme. Vollständige BRs und Master-Prompt-Deliverables sind weiterhin nicht abgeschlossen. Der Gesamtauftrag bleibt aktiv.

## Business-Slice 13: Kontrollierte Mitarbeiter-Lizenzrückgabe

Stand: 19. Oktober 2026. Die [bestehende eigene Lizenzverwaltung](../features/company-licenses.md#kontrollierte-lizenzrückgabe-beim-austritt) unterstützt jetzt die tatsächliche paginierte Rückgabe für einen bereits bewusst gesperrten oder retained gelöschten eigenen Mitarbeitenden. Kein zusätzlicher Allocator, neues Tabellenmodell, Secret oder globales Rollenrecht. Dies ist ein ausführbarer lokaler Lizenzschritt von WF-004, kein vollständiger automatischer Leaver-Prozess.

### Finale akzeptierte Gates

| Gate | Terminalstatus | Erfolgreiche Fälle | Beleg |
| --- | --- | --- | --- |
| Identity-Unit einschliesslich erweitertem OpenAPI-Vertrag | Exit 0 | 771 / 41 Suiten | `/tmp/od-business13-identity-unit-final.log` |
| Policy-Unit einschliesslich Manifest-/HTTP-/Quellprüfungen | Exit 0 | 789 / 23 Suiten | `/tmp/od-business13-policy-unit-final.log` |
| Gesamte Frontend-Jest-Suite nach finaler Receipt-Politur | Exit 0 | 1'621 / 81 Suiten | `/tmp/od-business13-web-full-final.log` |
| Gesamter expliziter Policy-PostgreSQL-Runner | Exit 0 | 369 / neun Dateien | `/tmp/od-business13-policy-native-final.log` |
| Tatsächlicher signierter Production-Gateway, Company-Prozess nach Snapshot-Korrektur | Exit 0 | 1 gezielt erweiterter bestehender Ablauf | `/tmp/od-business13-signed-company-final.log` |
| Echter Chrome, Registrierung/Company-Lizenzrückgabe und Organisation | Exit 0 | 2 erweiterte bestehende Abläufe | `/tmp/od-business13-browser-sidecar-final.log` |

Summe dieser sechs abgegrenzten Gates: **3'553** erfolgreiche Fälle. Die **151 zusätzlichen Falldefinitionen** setzen sich aus 26 Policy-Unit-, 111 Frontend- und 14 nativen Policy-Fällen zusammen. Bestehende signierte und Browserabläufe wurden erweitert, nicht als neue Testdefinitionen gezählt. Die Teilmenge von 250 fokussierten Frontend-Fällen und frühere native Teil-/Gesamtläufe sind enthalten oder supersediert, nicht doppelt addiert. Die übrigen 37 signierten Abläufe wurden nach der letzten Snapshot-Korrektur nicht erneut ausgeführt und werden hier ausdrücklich nicht als finale Abnahme behauptet.

### Nachgewiesene Wirkungen und Grenzen

- Vorschau aus tatsächlichem eigenen, konsistentem Read-only-Snapshot mit ursprünglichem Actor/Tenant und minimaler Benutzer-Eligibility; keine automatische Kontosperre oder zusätzliche Profilberechtigung.
- Aktive und fremde Ziele, fremder Pool am späteren Manifestplatz, alte Poolversion und alte Assignment-ID nach Regrant scheitern ohne vorgezogene Teilfreigabe. Körper-/Tenant-/Scope-Selektoren, Duplikate und mehr als 25 Schritte werden abgewiesen.
- Gesperrte und retained gelöschte eigene Ziele werden über die ursprüngliche Live-Quelle bestätigt. Tatsächliche Source-/Grant-/Projektionsentzüge verwenden nur den vorhandenen Allocator und dessen SQL-Receiving, Kapazitäts-/Audit-/Deadline-Regeln. Jeder echte Commit behält seine eigene Revision und Pending-Outbox; die Correlation-ID verbindet die Schritte.
- Ein nativer 25er-Lauf mit 26 wirklichen Ausgangszuweisungen lässt die unsichtbare 26. Zuweisung einschliesslich Version/Grant unverändert. Keine Behauptung einer vollständigen Rückgabe aller Seiten.
- Ein tatsächlicher konkurrierender zweiter Poolwechsel erhält den ersten bestätigten Entzug, kennzeichnet den zweiten als unbestätigt und versucht den dritten nicht. Verlorene Completion nach echtem Commit wird durch aktuelle Vorschau nachvollziehbar; eine physisch unterdrückte Pending-Outbox hinterlässt dagegen keine Freigabe. Reaktivierung während SQL verhindert den laufenden Commit und eine unberechtigte Antwort.
- Browser bestätigt zuerst den aktiven Mitarbeiter als gesperrte Rückgabeaktion, sperrt danach das Konto über den wirklichen Personenweg und gibt zwei bereits zugewiesene lokale Lizenzen erst nach explizitem Dialog frei. SQL bestätigt zwei tatsächliche Release-Receipts derselben Correlation-ID, immutable Pending-Einträge und keine Providerwirkung.
- Namen/Hersteller/Ergebnis sind im UI primär sichtbar; technische IDs liegen in per Enter bedienbaren Nachweisen. Retained Ergebnisse werden nur dem weiterhin passenden Actor und Tenant gezeigt. Alte/gefälschte Client-Snapshots, Sessionwechsel und automatische Wiederholungen werden nicht akzeptiert.

Die drei finalen Screenshots wurden lokal gelesen und visuell geprüft: `/tmp/od-business13-company-license-returns.png`, `/tmp/od-business13-company-license-return-proof.png` und `/tmp/od-business13-company-license-return-confirmation.png`. Sie sind keine umfassende WCAG-/Tablet-/Produktionsabnahme.

### Vorläufe und tatsächlich behobene Ursachen

Ein erster nativer Vorlauf endete mit 61 erfolgreichen von 64 Fällen: zwei neue Fixtures lasen nicht vorhandene Spalten statt der wirklichen Grant-Event-/Directory-Struktur; korrigiert wurde nur die Fixture-Abfrage. Ein bestehendes Parallelitätskriterium meldete ausserdem sporadisch `503: Retained company license pool unavailable`. Ein späterer Lauf reproduzierte diesen Fehler mit zusätzlicher Diagnose. Die Assertion für Versionskonflikt/Einzelgewinner wurde nicht gelockert.

Die originale volatile Receipt-Prüfung konnte bei Read Committed innerhalb ihrer Abfragen unterschiedliche bestätigte Stände sehen. `ownPool` verwendet deshalb ausserhalb eines vorhandenen Clients jetzt einen echten Read-only-Repeatable-Read-Client; die Schreibprüfung nach tatsächlichem Lock bleibt unverändert. Der neue native Test prüft Isolation und Read-only-Einstellung vor dem Katalog-/Receipt-Read. Zusätzlich bestanden **15 von 15** unabhängige Wiederholungen genau dieses Parallelitätsfalls (`/tmp/od-business13-concurrency-repeat.log`, Exit 0); dies ist separate Wiederholungsevidenz, keine zusätzliche fachliche Testabdeckung. Zwei Unit-Fixtures wurden auf den ausdrücklich lesenden Vorprüfungs-Client angepasst, nicht auf erlaubte Schreibwirkungen. Finale 789 Policy-Unit- und 369 PG-Fälle bestehen danach.

Ein 38-Fall-Signed-Vorlauf und der erste Zwei-Fall-Chrome-Lauf vor finaler Snapshot-/UI-Korrektur bleiben Vorbereitung; massgeblich sind nur die oben genannten finalen Logs. Keine laufende Prüfung wurde wegen einer stillen Phase neu gestartet. Der erste falsche npm-Workspace-Aufruf hatte keine Tests ausgeführt und zählt nicht als Gate. Finite bekannte React-Testwarnungen anderer Views wurden nicht als neues Renderloop-Problem umgedeutet oder durch Änderungen an fremden Komponenten überarbeitet.

### Quellenstand und verbleibender Umfang

Alle **880** zuvor erfassten Eingaben waren zu Beginn unverändert (`/tmp/od-business13-baseline-check.log`). Die finale ausgewählte Source-/Dokumentationsliste umfasst **881** Eingaben; Runtime-/Fixture-Freeze **855**. SHA-Manifeste, Hashprüfung und genaue Gate-Matrix liegen unter `/tmp/od-business13-source-final.sha256`, `/tmp/od-business13-runtime-frozen.sha256` und `/tmp/od-business13-gates.json`. Ausgewählte lokale Manifeste ersetzen weder eine vollständige Dependency-Attestation noch CI-/Release-Abnahme. Policy-Migration 022 bleibt unverändert bei SHA256 `9a423cfc05b1cd677d9332caf35b364a36fbec2a151ba74e181d2d42737d27e1`; keine neue Migration oder Abhängigkeit.

Der generierte OpenAPI-3.1-Vertrag **1.11.0** ist exakt gleich der Datei: **67** eindeutige Operation-IDs, **102** aufgelöste lokale Referenzen. Dokumentiert sind die zwei tatsächlichen Preview-/Return-Operationen, exakte Manifest-Revisionen und `200`/`207` mit `released`/`unconfirmed`/`not_attempted`; kein allgemeiner Workflow- oder Provider-Erfolg. Lokale Dokumentationslinks werden im maschinenlesbaren Gate-Beleg geprüft.

Frontend-Typecheck bleibt **Exit 2 mit denselben 17 bestehenden Diagnosen**; Positionen können durch Einfügungen verschoben sein, Fehlertexte und betroffene Dateien sind gleich. Kein Produktionsbuild, Image-Build, Deployment oder echte externe Schreibaktion ist abgenommen. Die alte Device-Unit-Gesamtsuite mit sechs früher nachgewiesenen Legacy-Fehlern und die vollständigen Identity-/Issuer-PG-Suiten wurden hier nicht erneut als grün erklärt.

Weiter offen: automatischer dienstübergreifender JML-/WF-004 mit dauerhaftem Workflow-Journal/Wiederaufnahme, kombinierter Account-/Session-/Rechteentzug und Geräte-Rückgabe; eigene Company-Governance, weitere Lizenz-/App-/Blueprint-Funktionen, sämtliche übrigen BRs/Master-Deliverables sowie Betriebs-/Last-/Restore-/Security-Abnahmen. Eine Kontosperre alleine gibt lokale Lizenzen weiterhin nicht automatisch zurück. BR-005 und Gesamtauftrag bleiben `In Progress`.

## Hardening-Slice 14: Frontend-Produktionsbuild

Stand: 19. Oktober 2026. Der nächste nachgewiesene Schritt ist die Behebung des bis dahin ausdrücklich offenen Frontend-Build-Gates. Die tatsächliche Ausgangsprüfung meldete dieselben **17 TypeScript-Diagnosen** (`/tmp/od-business14-types-baseline.log`, Exit 2). Sie werden nicht länger durch `ignoreBuildErrors` akzeptiert. [Lokale Build-Anleitung und Grenzen](../operations/installation.md#frontend-typprüfung-und-produktionsbuild).

### Finale Gates des eingefrorenen Codes

| Gate | Terminalstatus | Nachweis | Beleg |
| --- | --- | --- | --- |
| Vollständige Standard-TypeScript-Prüfung ohne Incremental-Cache | Exit 0 | **0 Diagnosen**, keine ausgeblendeten eigenen Quellen | `/tmp/od-business14-types-final.log` |
| Gesamte Frontend-Jest-Suite | Exit 0 | **1'767 Fälle, 88 Suiten** | `/tmp/od-business14-web-final.log` |
| Standard-Produktionsbuild mit vorhandenen installierten Abhängigkeiten | Exit 0 | `Compiled successfully`, tatsächliches `Checking validity of types`, `.next/BUILD_ID` und Produktionsrouten | `/tmp/od-business14-build-final.log` |
| Native BrowserAuth-BFF-Prüfung | Exit 0 | **46 Fälle** | `/tmp/od-business14-browser-auth-final.log` |
| Echter Chrome gegen frisches `next build` + `next start`, `NODE_ENV=production` | Exit 0 | **2 erweiterte bestehende Company-/Organisationsabläufe** | `/tmp/od-business14-production-browser-final.log` |

Damit bestehen **1'815 Testfälle über drei Testgates** sowie die beiden separaten Compile-/Build-Gates. **146 neue Unit-Falldefinitionen** gegenüber dem vorherigen Frontend-Stand; die zwei bestehenden Browserfälle werden nicht als neue Definitionen gezählt. Fokussierte Sidecar-Läufe und erfolgreiche Vorläufe sind in der vollständigen Suite enthalten bzw. supersediert, nicht zusätzlich addiert. Keine vollständige Identity-/Policy-/Issuer-/Device-Regression oder neue externe Providerabnahme wird daraus abgeleitet.

### Tatsächlich korrigiert

- SVG-Props der verwendeten Icon-Komponenten entsprechen ihrer realen Verwendung. ES5-Iteratorfehler werden mit `Array.from` behoben, nicht mit einem ungeprüften Wechsel des Compilerziels. PKCE verwendet weiterhin die ursprünglichen kryptografischen Bytes und S256; Referenzvektor, Form/Länge und RNG-/Digest-Fehlerpropagierung sind getestet.
- Alte Policy-Template- und kombinierte Security-Setup-Wizards rufen keine nicht existierenden Methoden mehr auf und speichern keinen angeblichen Erfolg im Browser. Sie erklären die fehlende unterstützte Funktion; der vorhandene bestätigte Richtlinieneditor bleibt separat verfügbar. Backup-/Monitoring-Einstiege erhalten ihre bestehenden Statusleser, aber weder unbekannte Konfigurationsschreibaufrufe noch fingierte Aktivierungsbestätigungen. Fehlende oder ungültige Beobachtungen bleiben unbekannt/unverfügbar, nicht null Bedrohungen oder null Backups.
- Tokenbasiertes Einzel-Enrollment erzeugt keine lokalen Demo-Tokens oder erfolgreichen Gerätezähler mehr. Der tatsächliche bestehende Quick-Actions-Bulk-Endpunkt und seine serverseitige Berechtigung bleiben erhalten. Frontend prüft die wirkliche indizierte Antwortform, Zielnamen/-plattformen, Anzahl, Schrittzustände und Erfolg-/Fehlerzähler. Fehlende, vertauschte, unvollständige oder widersprüchliche Antworten sind unbestätigt; verspätete Antworten nach Unmount dürfen keinen Erfolg nachträglich anzeigen. Kein Apple-/MDM-Provider wurde dadurch neu implementiert.
- Legacy-Apps-&-Books liest nur tatsächliche endliche Bestände mit gültigen IDs und widerspruchsfreien verfügbaren/belegten Plätzen. Arithmetische `NaN`-Werte, erfundene Zufalls-IDs und automatisch eingesetzte Beispielinventare wurden entfernt; explizite Null bleibt Null. Fehlende Daten erzeugen keine Produktiv-KPIs. Der normale eigene Company-Allocator-/Lizenzpfad wurde nicht ersetzt.
- Der gemeinsame Wizard-Schliessen-Button hat einen zugänglichen Namen. Dies ist kein umfassender WCAG-/Screenreader-/Fokustrap-Nachweis.

### Produktionsmodus, nicht nur Development

Die vorhandene reale Browserfixture baut nun zuerst das gesamte Frontend und startet erst nach tatsächlichem Build-Exit 0 `next start`. Die isolierte TypeScript-Konfiguration behält alle `src`-Quellen einschliesslich der dortigen Tests; die unabhängige Standardprüfung/-Build verwendet weiterhin die normale Konfiguration. Die verifizierten Abläufe enthalten echten ursprünglichen Issuer, Credential-/MFA-/Registrierungs-/Owner-/Profilprozess, lokale eigene Geräte-/Lizenzzuweisungen, bestätigte Rückgabe und reale SQL-/Pending-Belege. Sie bleiben lokale isolierte Testdienste, nicht externe Produktivprovider.

Finale Screenshots wurden aus diesem Produktionsbrowserlauf gesichert und visuell gelesen: `/tmp/od-business14-production-license-returns.png`, `/tmp/od-business14-production-license-proof.png`, `/tmp/od-business14-production-license-confirmation.png`. Namens-/Statusanzeige, explizite Bestätigung und per Enter geöffnetes Receipt sind sichtbar. Die geänderten Unsupported-Einstiege besitzen eigenständige DOM-Tests; ihre Prüfung wird nicht aus dem Lizenz-Screenshot behauptet.

### Nicht unterdrückte Warnungen und offene Release-Gates

Der reale Standard- und Fixture-Build endet mit Exit 0, meldet aber weiterhin Next-14-SWC-/Workspace-Lockfile-Warnungen und veraltete Browserslist-Daten. Die vorhandene Next-Version 14.2.35 deklariert SWC 14.2.33. Im vorhandenen Root-Lockfile liegt die optionale Darwin-x64-Variante hoisted, während Next unter `frontend/web-app/node_modules` eingetragen ist; der automatische Patchversuch sucht die Variante im verschachtelten Präfix und scheitert beim Versionsmetadatenzugriff. Das ist kein beseitigter Clean-Install-/Linux-Build-Nachweis. Weder `NEXT_IGNORE_INCORRECT_LOCKFILE` noch ein anderer Patch-Ignore wurde gesetzt; keine Lockdatei oder Dependency wurde zur Schönung umgeschrieben. Die bestehende ESLint-Build-Ausnahme ist unverändert und wird als **nicht abgenommen** ausgewiesen.

Ein lokaler Zwischenlauf enthielt einen neuen Test-Optionsfehler (`getByRole` kennt kein `exact`); die unzulässige Option wurde entfernt, nicht der Test aus der Typprüfung ausgeschlossen. Zwischenstände parallel bearbeiteter Wizard-Quelldateien wurden nicht als finale Fehlerzahl verwendet. Nach dem vollständigen Review wurden Backup-/Monitoring-Antwortgrenzen und unbekannte Nullable-Backups zusätzlich abgesichert; frühere grüne Builds/Browserläufe vor diesen letzten Änderungen zählen nur als Vorbereitung. Die oben genannten finalen Gates gehören zum danach eingefrorenen Runtime-Stand. Stille lebende Prozesse wurden am selben Handle weiter beobachtet, nicht neu gestartet. Ein falscher npm-Aufruf vom Root ohne passenden Script war kein Gate.

### Quellenstand und verbleibender Gesamtumfang

Die **881** zuvor erfassten Source-Eingaben waren vor dieser Arbeit unverändert (`/tmp/od-business14-baseline-check.log`). Die finale ausgewählte Liste umfasst **889** Source-/Dokumentationseingaben; Runtime-/Fixture-Freeze **863**. Der Root-Lock ist nun ebenfalls explizit im Freeze enthalten. Manifest-/Gate-Belege: `/tmp/od-business14-source-final.sha256`, `/tmp/od-business14-runtime-frozen.sha256`, `/tmp/od-business14-gates.json`. Bereits zuvor erfasste Paket-/Lockmanifeste und das originale TypeScript-Config sind unverändert; kein `npm install`, Framework-Upgrade, Datenbankmigrationswechsel oder produktiver Schreibvorgang. Temporäre lokale Belege ersetzen keine vollständige CI-/Dependency-/Release-Attestation.

Dieser Schritt hebt nur die alte Aussage „17 TypeScript-Diagnosen, kein nachgewiesener lokaler Produktionsbuild“ auf. Er schliesst keine der noch unvollständigen BRs, keinen automatischen JML-/WF-004, keine Unternehmens-/Provider-Verifikation und keinen fehlenden Standort-/Marketing-/Billing-/Collaboration-Workflow ab. Reproduzierbarer Clean-Install, Linux-Image, öffentliche TLS-/Cookie-/Proxy-Konfiguration, Lint, vollständige Regression/Security-/Last-/WCAG-/Restore-Abnahme und tatsächlicher SaaS-Betrieb bleiben offen. Der Gesamtauftrag bleibt aktiv.

## Business-Slice 15: Dauerhaftes lokales Mitarbeiter-Offboarding

Stand: 19. Oktober 2026. [Eigene kanonische Kontosperre und erfasste lokale Lizenzrückgabe](../features/company-offboarding.md) sind jetzt ein verbundener ausführbarer Prozess mit dauerhaftem Auftrag, History und ausdrücklich bestätigter Wiederaufnahme. Identity 045 und Policy 023 sind additiv; bestehende Directory-Mutatoren und Allocator bleiben die Fachschreiber. Keine globale Rolle, neue Dependency, gespeicherte Tokens oder unbeaufsichtigter Hintergrundschreiber. **Kein vollständiges WF-004.**

### Finale abgegrenzte Gates

| Gate | Terminalstatus | Erfolgreiche Fälle | Beleg |
| --- | --- | --- | --- |
| Gesamte Identity-Jest-Suite mit Routing-/Bridge-/OpenAPI-Verträgen | Exit 0 | 799 / 43 Suiten | `/tmp/od-business15-identity-unit-final.log` |
| Gesamte Policy-Jest-Suite mit Orchestrierung und echtem Clientvertrag | Exit 0 | 828 / 25 Suiten | `/tmp/od-business15-policy-unit-final.log` |
| Gesamte Frontend-Jest-Suite | Exit 0 | 1'872 / 90 Suiten | `/tmp/od-business15-web-final.log` |
| Vollständiger expliziter Identity-PostgreSQL-Runner | Exit 0 | 632 / 18 Dateien | `/tmp/od-business15-identity-native-final.log` |
| Vollständiger expliziter Policy-Runner mit Journal | Exit 0 | 406 / 11 Dateien: 399 native Fälle und sieben enthaltene Node-Units | `/tmp/od-business15-policy-native-final.log` |
| BrowserAuth/BFF-Vertrag | Exit 0 | 46 | `/tmp/od-business15-browser-auth-final.log` |
| Echter signierter Production-Gateway, erweiterter Company-Ablauf | Exit 0 | 1 gezielt erweiterter bestehender Ablauf | `/tmp/od-business15-signed-final.log` |
| Tatsächlicher Chrome gegen frisch gebautes `next start` | Exit 0 | 2 bestehende erweiterte Abläufe | `/tmp/od-business15-browser-final.log` |
| Unabhängiges vollständiges `tsc --noEmit --incremental false` | Exit 0 | Keine Diagnosen | `/tmp/od-business15-types-final.log` |
| Normaler lokaler `next build` | Exit 0 | Produktionsbuild; bekannte nicht fatale Warnungen bleiben | `/tmp/od-business15-build-final.log` |

Die acht Testgates umfassen **4'586** erfolgreiche Fälle; Typprüfung und Build sind getrennte Gates, keine Testfälle. Fokussierte Vorläufe sind enthalten/supersediert, nicht zusätzlich addiert. Der Policy-Gesamtrunner führt die sieben Journal-Units genau einmal neben 25 nativen Journalfällen und den übrigen nativen Tests aus. Die übrigen 37 signierten Gatewayfälle und vollständige Issuer-/Device-/Gateway-Regression wurden hier nicht erneut abgenommen.

### Nachgewiesener Prozess und Gegenbelege

- Roleless eigener Company-Owner mit Original-Bearer und frischer unabhängig gebundener MFA: tatsächliche aktive Person mit zwei lokalen Lizenzen → ausdrückliche Bestätigung → echte kanonische Sperre samt Directory-Event und Identity-Receipt → zwei tatsächliche bestehende Allocator-Freigaben → sechs retained Journalversionen und Pending-Outbox → nach Neuladen gespeicherter lokaler Abschluss, Liste, Historie und Original-Checkpoint.
- Der kanonische Bridge prüft unabhängig beide Benutzer-Schreibrechte, eigene Tenant-Hoheit, aktuelle Authority und Originalfristen. Bereits gesperrte Konten erzeugen nur `already_disabled`, keine erfundene Mutation. Gleicher Schlüssel/Intent wird aus dem retained Beleg wiedergefunden; anderer Intent, fremder Tenant, Selbstziel, alter ETag oder spätere Reaktivierung werden abgewiesen.
- Tatsächliche SQL-Row-Lock-Waits mit zwischenzeitlichem Source-Entzug, Physical-Commit-Ablauf, fehlende/unterdrückte Belege/Outbox, Raw-DML/Truncate und eingeschränkte Login-/SET-ROLE-Grenzen werden mit realem PostgreSQL geprüft. Journal-Receiving verlangt echte bestehende Lizenz-Release-Events; gefälschte Completion, entfernte erfasste Mitgliedschaft oder fehlende retained Kindbelege werden nicht als Fortschritt ausgegeben.
- Ein wirklich committed Lizenzentzug mit anschliessend fehlgeschlagener Journal-Bestätigung wird durch eine neu erstellte Serviceinstanz aus dem alten Original-Event wiedergefunden, ohne den Child-Entzug erneut auszuführen. Ein Session-Advisory-Lock verhindert parallele Ausführung desselben Vorgangs. Neue Eligibility-/Grant-Inkarnationen werden nicht stillschweigend übernommen.
- Native Policy-Orchestrierung verwendet ausdrücklich einen synthetischen Identity-Bridge und echte Policy-DB/Allocator/Journal. Das ist kein zweiter Cross-Service-Nachweis. Signierter Gateway und Produktionsbrowser verbinden dagegen die beiden realen Dienste, tatsächlichen Issuer/JWKS, Gateway/BFF und PostgreSQL.
- DOM-/Clienttests prüfen echte Capabilities, Vorschau/Bestätigung, Sessionwechsel, kaputte oder fremde DTOs, ETags, ursprüngliche unveränderliche Begründung, pausierte Fortsetzung, gespeicherte Wiederaufnahme und fehlende automatische Schreibwiederholung. Der Produktionsbrowser prüft den wirklichen UI-/HTTP-/SQL-Weg; er beweist keine allgemeine WCAG-Abnahme.

### Vorbereitung, Korrekturen und visuelle Prüfung

Ein Journal-Zwischenstand verglich fälschlich die Autorisierungsrevision mit der Directory-Datensatzrevision. Diese unterschiedlichen Dimensionen sind jetzt getrennt; Native-Regression verwendet ausdrücklich verschiedene Werte. Ein Receipt-Feld `createdAtISO` wurde auf den exakten gemeinsamen `createdAt`-Vertrag korrigiert. Der generische Listenparser lieferte `search:''` an den strengeren Journalparser; der Aufrufer reicht jetzt nur echte Pagination weiter und besitzt zwei Regressionstests. Die beiden frühen 74er-Orchestrierungsläufe waren deshalb nicht grün und zählen nicht als Abnahme.

Ein neuer DOM-Test verwendete unzulässig `{exact:true}` bei `getByRole`; die Option wurde entfernt, nicht die Testdatei ausgeschlossen. Die erste Identity-Jest-Gesamtsuite scheiterte nur am noch nicht aktualisierten generierten YAML-Vertrag; nach tatsächlicher Neugenerierung besteht der volle Lauf. Ein Jest-Fixture-Prototypunterschied wurde im Fixture korrigiert, ohne Runtime-Intent-Gleichheit zu lockern. Next filtert intern Testdiagnosen auch bei umfassendem `tsconfig`; ausschlaggebend für vollständige Typkorrektheit ist deshalb das unabhängige `tsc`-Gate.

Ein signierter Vorlauf konnte wegen eines zu langen lokalen PostgreSQL-Unixsocket-Pfads nicht starten; `TMPDIR=/tmp` behebt nur diese Testumgebung. Danach brach der bisherige Zehn-Sekunden-Requesthelper beim neuen kombinierten Schreibaufruf ab. Ausschliesslich dieser Testaufruf besitzt jetzt 60 Sekunden; Runtime-/SQL-/MFA-Grenzen wurden nicht gelockert. Clienttimeout kann ein unbekanntes Ergebnis bedeuten und benötigt gespeicherten Readback statt Retry. Das ist **keine P95-/Performance-Abnahme**.

Vier reale Screenshots des finalen Produktionsbrowserlaufs wurden visuell gelesen: `/tmp/od-business15-offboarding-confirmation.png`, `/tmp/od-business15-offboarding-completed.png`, `/tmp/od-business15-offboarding-history.png`, `/tmp/od-business15-offboarding-proof.png`. Explizite lokale Umfangsbestätigung, 2/2 tatsächliche Rückgaben, gespeicherter Vorgang, getrennt aktueller Kontostatus, Original-Receipt und ausstehende Ereigniszustellung sind sichtbar. Keine fremden Produktivsysteme wurden dafür beschrieben.

### API, Quellstand und offene Abnahme

OpenAPI **1.12.0** besitzt **75 eindeutige Operationen** und **120 auflösbare lokale Referenzen**; YAML stimmt strukturell mit dem echten Generator und bytegenau mit dessen erzeugtem YAML überein (`/tmp/od-business15-openapi-check.json`). Die acht zusätzlichen Operationen dokumentieren den begrenzten Journal-/Identity-Bridge-Weg, nicht eine vollständige universelle Workflow-API.

Die zuvor erfassten **889** Source-Eingaben waren vor Beginn unverändert. Der finale Freeze umfasst **915** ausgewählte Source-/Dokumentationseingaben und **888** Runtime-/Fixture-/API-Eingaben; er ergänzt auch fünf schon vorhandene bislang nicht erfasste Policy-Scripts. Das ist keine Behauptung, 26 neue Produktdateien entwickelt zu haben. Belege: `/tmp/od-business15-baseline-check.log`, `/tmp/od-business15-runtime-frozen.sha256`, `/tmp/od-business15-runtime-check-final.log`, `/tmp/od-business15-source-final.sha256`, `/tmp/od-business15-gates.json`. Migration 022 bleibt SHA-256 `9a423cfc05b1cd677d9332caf35b364a36fbec2a151ba74e181d2d42737d27e1`. Lokale temporäre Belege ersetzen keine dauerhafte CI-/Release-Attestation.

Rollen-/Gruppenentzug, Geräte-Rückgabe und Remote-Aktionen, vollständiger Session-/Credential-/Provider-Lifecycle, weitere JML-/Blueprint-Verbindungen und übrige BRs bleiben offen. Bestehende Lint-Ausnahme, nicht fatale SWC-/Workspace-Lockfile-/Browserslist-Warnungen, Clean-Install/Linux-Image, Security-/Last-/WCAG-/Restore-/Retention- und produktive Betriebsabnahme sind nicht erledigt. Kein Deployment, Commit/Push oder externer Produktivschreibvorgang. Der Gesamtauftrag bleibt aktiv.

## Business-Slice 16: App- und Bestandskorrekturen

Stand: 19. Oktober 2026. [Eigene App-Metadaten und endlicher lokaler Lizenzbestand](../features/company-licenses.md#app--und-bestandskorrekturen) können jetzt tatsächlich korrigiert werden. Derselbe vorhandene Allocator-/Audit-/Event-/Pending-Vertrag, keine neue Tabelle, globale Rolle, Dependency oder externe Beschaffung. Policy-Migration 024 ist additiv; Identity bleibt bei 045, Policy 022/023 unverändert. BR-005 und der Master-Auftrag bleiben insgesamt unvollständig.

### Finale akzeptierte Gates

| Gate | Terminalstatus | Erfolgreiche Fälle | Beleg |
| --- | --- | --- | --- |
| Gesamte Identity-Jest-Suite einschliesslich erweitertem API-Vertrag | Exit 0 | 799 / 43 Suiten | `/tmp/od-business16-identity-unit-final.log` |
| Gesamte Policy-Jest-Suite mit neuem bedingtem Katalogweg | Exit 0 | 858 / 26 Suiten | `/tmp/od-business16-policy-unit-final.log` |
| Gesamte Frontend-Jest-Suite | Exit 0 | 1'978 / 90 Suiten | `/tmp/od-business16-web-final.log` |
| Vollständiger expliziter Policy-Runner mit allen aktuellen Migrationen | Exit 0 | 437 / 11 Dateien: 430 native Fälle und sieben enthaltene Node-Units | `/tmp/od-business16-policy-native-final.log` |
| BrowserAuth/BFF-Vertrag | Exit 0 | 46 | `/tmp/od-business16-browser-auth-final.log` |
| Echter signierter Production-Gateway, erweiterter Company-Ablauf | Exit 0 | 1 gezielt erweiterter bestehender Ablauf | `/tmp/od-business16-signed-final.log` |
| Tatsächlicher Chrome gegen frischen Produktionsbuild/`next start` | Exit 0 | 2 bestehende erweiterte Abläufe | `/tmp/od-business16-browser-final.log` |
| Unabhängiges vollständiges `tsc --noEmit --incremental false` | Exit 0 | Keine Diagnosen | `/tmp/od-business16-types-final.log` |
| Normaler lokaler `next build` | Exit 0 | Produktionsbuild mit bekannten nicht fatalen Warnungen | `/tmp/od-business16-build-final.log` |

**4'121** erfolgreiche Fälle über sieben abgegrenzte Testgates; zwei weitere Compile-/Build-Gates. **167 neue Falldefinitionen**: 30 Policy-Units, 106 Frontend- und 31 native Policy-Fälle. Die fokussierten 31 bzw. vollständigen 105 Company-Native-Fälle und 461 fokussierten Frontend-Fälle sind in den Gesamtsuiten enthalten, nicht zusätzlich addiert. Signierter und Browserablauf wurden erweitert, nicht als neue Testdefinitionen gezählt. Native Identity-/vollständige Issuer-/Device-/Gateway-Regression und die übrigen 37 signierten Gatewayabläufe wurden hier nicht erneut ausgeführt.

### Tatsächlich belegt

- Ein tatsächlich belegter eigener Pool wird umbenannt, Hersteller/Beschreibung korrigiert und im endlichen Bestand aufgestockt bzw. bis zur wirklichen Belegung reduziert. Alle ursprünglichen Subjects, Assignments, Direct-Sources und Grants bleiben gleich; kein Provider-/Budget-/Finanzeffekt.
- Tatsächlicher editierbarer Protokoll-/SQL-Receiver vor Editoröffnung und erneut unmittelbar vor PATCH, Original-Actor/Tenant und frische unabhängig gebundene MFA, unveränderte feste drei Company-Fähigkeiten, genauer starker Pool-ETag und Vorher/Nachher-Bestätigung. Keine zusätzliche globale Katalogrolle.
- Unterbelegung, unveränderter Intent, falsche/fehlende Version, fremder Pool oder Caller-Tenant und separat geregelte Governance werden ohne wirkliche Katalogänderung oder erfundene Historie abgewiesen. Konkurrierende Korrektur/Allokation verwenden denselben wirklichen Pool-Lock und akzeptieren genau einen der ursprünglichen Versionsstände.
- Zwei konkrete Katalog-UPDATE-Wirkungen (Metadaten und anschliessender einmaliger Revisionsabschluss), genau ein ursprüngliches `pool-updated`-Audit, immutable `app.license.pool.updated`-Event mit null Benutzerziel und zwingende Pending-Outbox sind nachgewiesen. Unterdrückte Effekte/Audit/Outbox/Revision, nachträglich entzogene Originalquelle, Fristablauf nach belegtem Lock-Wait oder am physischen Commit verhindern einen scheinbaren Erfolg.
- Metadatenkorrektur erzeugt/adoptiert keine Benutzer-Subjects und wartet nicht auf deren Row-Locks. Ein danach erstmals zugewiesener Benutzer verwendet weiterhin den bestehenden Allocator. Globale, gefälschte, fremde Audit- und Providerhistorie bleiben kontrollierte Migrationsgrenzen statt aus dem Katalogschreibrecht ableitbare Autorisierung.
- Alte und neue retained Belegketten bleiben nach anschliessendem Assign/Revoke, abgelaufener damaliger Authority und vollständigem Migrationsreplay lesbar. Physische Korruption eines älteren Katalog-Receipts sperrt Liste, Detail, Historie, Edit-Capability und weitere Schreibwege; ein später gültiger Command verdeckt diese nicht.
- Client-/DOM-Tests prüfen nicht bestätigte/alte/fremde Protokolle, gefälschte oder veraltete Snapshots, Sessionverlust, serialisierte Schreiber, Timeout und fehlende/widersprüchliche Antwort-/ETag-Daten ohne automatische Wiederholung. Tatsächlich neu gelesene Suchfilter/Sortierung/Counts und Historie ersetzen die alte Listenposition nach Umbenennung.
- Signierter Gateway und Produktionsbrowser verbinden echten ursprünglichen Issuer/JWKS, Policy/Identity, BFF und PostgreSQL. Nach einer erfolgreichen Korrektur bestehen weiterhin die zuvor vorhandenen tatsächlichen Lizenzrückgaben und der dauerhafte lokale Account-/Lizenz-Offboarding-Prozess. Das beweist weder vollständiges WF-004 noch Apple-/Microsoft-Provideraktionen.

### Nicht akzeptierte Vorbereitung und Korrekturen

Ein erster SQL-Zwischenstand behandelte den eigenen neuen Katalog-Auditactor vor dessen erster Allokation als unübernehmbare Legacy-Historie. Die Ausnahme ist jetzt eng an einen tatsächlich gültigen ursprünglichen eigenen Update-Command/Event/Audit gebunden, nicht an beliebige Actor-Strings. Vier echte negative Historienarten verhindern einen pauschalen Audit-Bypass. Retained Belege prüfen ihre ursprünglichen Zeit-/Fristbeziehungen, verlangen aber keine heute noch lebende damalige MFA.

Der erste Produktionsbrowserlauf scheiterte ausschliesslich am neuen Testoracle: Die Receipt-JTI wurde mit einem früheren Setup-Token verglichen, nicht mit dem inzwischen tatsächlich verwendeten Browser-Bearer. Der Test liest jetzt den Original-JWT des tatsächlichen PATCH und vergleicht dessen JTI/Issuer/Subject/Context, kanonischen Actor und nachgewiesene MFA mit dem gespeicherten Source. Keine Runtime-/SQL-/MFA-Regel wurde abgeschwächt. Der fehlgeschlagene Vorlauf bleibt unter `/tmp/od-business16-browser-provisional-failed.log` erhalten.

Bereits lebende signierte/Browserprozesse wurden bis zu ihrem echten Terminalstatus beobachtet. Grüne Zwischenläufe gegen SQL `32703a3a…` zählen ausdrücklich nur als Vorbereitung: Nach der finalen SQL-Fassung `164e0026…` wurden beide realen Prüfungen frisch und vollständig ausgeführt. Die finalen Logs protokollieren Migration-/Testdatei-Hashes vor dem tatsächlichen Lauf. Kein stiller Prozess wurde nur wegen einer Beobachtungsfrist neu gestartet.

### Visuelle Prüfung, API und Quellenstand

Drei tatsächliche Screenshots aus dem finalen Produktionsbrowserlauf wurden visuell geprüft: `/tmp/od-business16-pool-edit-confirmation.png`, `/tmp/od-business16-pool-edit-completed.png`, `/tmp/od-business16-pool-edit-history.png`. Vorher/Nachher, unveränderte Belegung, geänderter lokaler Bestand und retained Historie mit ausstehender Ereigniszustellung sind sichtbar. Diese Prüfung ist keine allgemeine WCAG-/Screenreader-Abnahme.

OpenAPI **1.13.0**: **77 eindeutige Operationen**, **122 auflösbare lokale Referenzen**; generierter JSON-kompatibler YAML-Vertrag stimmt bytegenau mit dem Generatoroutput überein (`/tmp/od-business16-openapi-check.json`). Die zwei neuen Operationen dokumentieren reale Edit-Capability und bedingtes PATCH, keine externe Beschaffung.

Die vorherigen **915** ausgewählten Source-Eingaben waren vor Beginn unverändert. Final: **917** Source-/Dokumentationseingaben, **890** Runtime-/Fixture-/API-Eingaben. Belege: `/tmp/od-business16-baseline-check.log`, `/tmp/od-business16-runtime-frozen.sha256`, `/tmp/od-business16-runtime-check-final.log`, `/tmp/od-business16-source-final.sha256`, `/tmp/od-business16-gates.json`. SQL024 SHA-256 `164e0026c78fa035080e07b275f250c0b72a04a571829c4094f2f415974ec3a2`; 022/023 unverändert. Lokale temporäre Belege ersetzen keine dauerhafte CI-/Release-Attestation.

Bekannte nicht fatale Next-SWC-/Workspace-Lockfile-/Browserslist-Warnungen, vorhandene ESLint-Ausnahme und bereits bestehende React-act-Testwarnungen bleiben sichtbar. Kein Lockfile-Patch-Ignore, Dependency-/Framework-Upgrade oder TypeScript-Testausschluss. Clean-Install/Linux-Image, öffentliche TLS-/Cookie-Konfiguration, Security-/Last-/WCAG-/Restore-/Retention-/Betriebsabnahme, Custom-Rollen/Scopes, Blueprint-/Geräte-/Gruppenverbindung, vollständiges JML und externe Anbieter fehlen weiterhin. Kein Commit/Push, Deployment oder externer produktiver Schreibvorgang. Gesamtauftrag bleibt aktiv.

## Business-Slice 17: Kontrollierter Gruppenentzug beim Austritt

Stand: 19. Oktober 2026. Der [separat bestätigte Gruppen-Folgeschritt](../features/company-offboarding.md#gruppen-beim-austritt-entfernen) verwendet den bestehenden kanonischen GroupMutator und den unveränderten echten Account-Checkpoint. Identity 046 ergänzt tatsächliche Child-Belege, kein zweites Gruppenverzeichnis oder globale Rollenadministration. Der Schritt ist auch bei offenen/pausierten Lizenzrückgaben verfügbar. **Mitgliedschaften sind nicht allgemeines Gruppen-RBAC oder vollständiges WF-004.**

### Finale akzeptierte Gates

| Gate | Terminalstatus | Erfolgreiche Fälle | Beleg |
| --- | --- | --- | --- |
| Gesamte Identity-Jest-Suite mit neuem Contract/Service/Routing | Exit 0 | 862 / 46 Suiten | `/tmp/od-business17-identity-unit-final.log` |
| Gesamte Policy-Jest-Regression, unveränderte Lizenz-/Parent-Verträge | Exit 0 | 858 / 26 Suiten | `/tmp/od-business17-policy-unit-final.log` |
| Gesamte Frontend-Jest-Suite nach finaler Scope-/Mount-Korrektur | Exit 0 | 2'121 / 92 Suiten | `/tmp/od-business17-web-final.log` |
| Vollständiger Identity-PostgreSQL-Runner mit Migrationen 001–046 | Exit 0 | 652 / 19 Dateien | `/tmp/od-business17-identity-native-final.log` |
| BrowserAuth/BFF-Vertrag | Exit 0 | 46 | `/tmp/od-business17-browser-auth-final.log` |
| Echter signierter Production-Gateway, erweiterter Company-Ablauf | Exit 0 | 1 bestehende erweiterte Definition | `/tmp/od-business17-signed-final.log` |
| Produktions-Chrome: unbekannte Antwort und normale Bestätigung | Zweimal Exit 0 | Dieselbe bestehende Company-Definition zweimal je 1/1 | `/tmp/od-business17-browser-final.log` |
| Unabhängiges vollständiges `tsc --noEmit --incremental false` | Exit 0 | Keine Diagnosen | `/tmp/od-business17-types-final.log` |
| Normaler lokaler `next build` | Exit 0 | Bekannte nicht fatale Warnungen bleiben | `/tmp/od-business17-build-final.log` |

Die sieben abgegrenzten Testgruppen enthalten **4'541 unterschiedliche Falldefinitionen**, mit der zweiten Browserausführung **4'542 erfolgreiche Ausführungen**. Die beiden Chromeprozesse testen unterschiedliche Antwortzweige derselben Definition; weder eine zusätzliche Definition noch eine erneut geprüfte separate Organisationsprofil-UI wird daraus behauptet. **226 neue Falldefinitionen**: 63 Identity-Units, 143 Frontend- und 20 native Identity-Fälle. Fokussierte 20 native bzw. 90 Backend-/247 Frontend-Vorläufe sind enthalten oder supersediert, nicht zusätzlich addiert. Vollständige native Policy-/Issuer-/Device-/Gateway-Regression und die übrigen 37 signierten Gatewaydefinitionen wurden hier nicht erneut abgenommen.

### Tatsächliche Wirkungen und Gegenbelege

- Roleless eigener Company-Owner mit tatsächlicher ursprünglicher Credential-/MFA-/Issuer-Hoheit: echte kanonische Kontosperre und lokale Lizenzrückgabe → zwei aktuelle eigene Gruppenlinks → explizite bestätigte Seite → zwei tatsächliche GroupMutator-Entzüge → ursprüngliche Group-Events/Audit/Outbox und 046-Child-Receipts/Pending. Ein zweiter Mitarbeitender behält seine Mitgliedschaften. Rollen und PIM bleiben unverändert.
- Exakter eigener Parent aus 045, derselbe live vorhandene gesperrte Benutzer und dieselbe negative Eligibility sind zwingend. Kein UUID-/Body-Tenant-/Admin-Alias-/Service-Account-Bypass. Unabhängige aktuelle Gruppenrechte und MFA gelten vor/nach der Arbeit und am physischen Commit.
- Ein wirklicher 26-Gruppen-Fall zeigt 25 aktuelle Links und entfernt genau diese; Gruppe, Version und Link der unsichtbaren 26. bleiben unverändert. Ein später fremder oder veralteter Manifestplatz scheitert vor der ersten Wirkung. Die nachträglich veränderte zweite Gruppenrevision erhält dagegen den ersten echten Child-Commit und stoppt den dritten.
- Verlorener Driver-ACK nach tatsächlichem COMMIT ergibt kein erfundenes positives Ergebnis. Explizite Wiederaufnahme findet den alten Original-Beleg mit derselben Operation-ID wieder; eine später neu erstellte Membership-ID wird nicht entfernt. Historie und Wiederaufnahme bleiben nach tatsächlicher späterer Gruppenlöschung mit ursprünglichem Namen/Version gültig.
- Fehlender/falscher Parent, aktive oder reaktivierte/erneut gesperrte Ziele, importierte fremde Gruppenlinks, fehlende Receiver/Outbox, unterdrückte Group-/Cleanup-Belege, Raw-DML/Truncate, echte eingeschränkte SQL-Logins/`SET ROLE`, frühere/spätere fremde Effekte, Originalquellenverlust und physischer Fristablauf haben tatsächliche PostgreSQL-Gegenbelege. Actor-/Target-Row-Locks werden vor dem eigenen Gruppen-Lock beobachtet; kein Controller-Mock ersetzt diese Prüfungen.
- Native Tests verwenden ausdrücklich synthetische Transport-Revalidation mit echten kanonischen Klassen/Migrationen. Signierter HTTP-Prozess und realer Browser verbinden dagegen ursprünglichen Issuer/JWKS, Gateway/BFF, Identity/Policy und PostgreSQL. Der echte POST-Bearer-Hash wird mit dem 046-Beleg verglichen, nicht ein früherer Setup-Token.
- Der erste finale Chromeprozess manipuliert nach echtem Backend-Commit nur die Rückgabe zu einem ungültigen DTO. UI meldet keinen falschen Erfolg, wiederholt den POST nicht und findet die wirklichen beiden Child-Belege erst durch ausdrücklich angeforderten Readback. Der zweite frische Produktionsprozess bestätigt den normalen Ablauf und liefert die finalen Screens.
- Client-/DOM-Prüfungen decken fehlende/alte/fremde Protokolle, Parent-/Epochbindung, gefälschte Snapshots, Antwortreihenfolge, genaue Partialzustände, unabhängige History-Pagination, Session-/Unmount-Wechsel und doppelte Bestätigung ab. Ein gültiger negativer Account-Checkpoint erlaubt den kollabierten Gruppenschritt auch bei noch offenen oder pausierten Lizenzen; weder Datenladen noch Entzug erfolgt automatisch beim Mount.

### Nicht akzeptierte Vorbereitung und Korrekturen

Ein früher Trigger griff bei unterschiedlichen Relationstypen direkt auf ein nicht vorhandenes OLD-Feld zu; die neue 046-Fence verwendet dafür die passende JSON-Row-Projektion. Eine verschachtelte neue UTC-Einstellung änderte die Timestampdarstellung des bestehenden 028-Group-Proofs; die neue Schicht erhält jetzt die ursprüngliche Child-Kernel-Zeitzone, statt alte Hashprüfungen zu umgehen oder den alten Kernel umzuschreiben.

SQL-Source-Validierung lehnt JSON-null/numerische Reason-/Token-Hash-Werte ausdrücklich ab; das verhindert NULL-Auswertungen in ansonsten vollständigen Proofobjekten. Der physische Deadline-Test musste den bestehenden einsekündigen AuthorizationState-Statement-Timeout für sein absichtliches `pg_sleep` überschreiten können. Nur die Testtransaktion erhält dafür 15 Sekunden. Ausserdem wird der erste reale SQL-Fehler 42501 bewahrt, statt ihn durch die anschliessende absichtlich verweigerte Summary-Revalidation zu überschreiben. Keine Runtime-/MFA-Regel wurde gelockert.

Ein Legacy-Test-Beforehook erwartete noch genau 45 Migrationen und blockierte deshalb 20 bisherige Fälle. Beide expliziten Assertions wurden auf 46 aktualisiert, einschliesslich der vollständigen lückenlosen Nummernfolge; keine Validierung wurde entfernt. Erst der oben genannte gesamte 652er-Lauf gilt als finale Regression.

Die UI behauptet keine unbewiesene allgemeine Gruppenrechte-/Rollenbereinigung mehr, sondern nur kanonische Mitgliedschaftsentfernung. Der dazugehörige alte Textmatcher verursachte einen nicht grünen Frontend-Vorlauf und wurde an den präzisen stärkeren Hinweis angepasst. Die Mount-Bedingung wurde ausserdem von fertiger Lizenzrückgabe auf jeden gültigen negativen Account-Checkpoint erweitert und mit offenen/pausierten Lizenzzuständen geprüft.

Die ersten signierten/Chrome-Vorläufe enthielten ein falsches Testoracle `afterGroupRevision=before+1`. Gruppenrevisionen stammen bereits aus der globalen `identity_group_revision_seq`; korrekt sind `after>before` **und** die exakten tatsächlichen Werte aus kanonischem Event und Datenbank. Nur die beiden QA-Fixtures wurden korrigiert; SQL/Runtime/SDK waren bereits korrekt und unverändert. Vorläufe bleiben als `/tmp/od-business17-signed-prep-revision.log` und `/tmp/od-business17-browser-prep-revision.log` erhalten. Alle laufenden Prozesse wurden bis zu ihren echten Terminalzuständen am selben Handle beobachtet, nicht wegen einer stillen Phase neu gestartet.

### Visuelle Prüfung, API und Source-Freeze

Main und QA haben drei tatsächliche finale Screens visuell gelesen: `/tmp/od-business17-group-cleanup-confirmation.png`, `/tmp/od-business17-group-cleanup-completed.png`, `/tmp/od-business17-group-cleanup-history.png`. Sichtbar sind genau zwei Gruppen/Versionen, explizite Bestätigung, tatsächliche Entzugsresultate, klar als alt markierte History vor Readback und anschliessend beide retained Belege mit globalen Versionssprüngen 15→17 bzw. 16→18 und ausstehender Zustellung. Kein All-Access-/Rollen-/Providererfolg wird daraus abgeleitet.

OpenAPI **1.14.0**: **80 eindeutige Operationen**, **126 auflösbare lokale Referenzen**, bytegleicher Generatoroutput. Drei neue Operationen dokumentieren paginierten Gruppenpreview, bestätigtes Manifest und retained Historie. Neue SQL-/API-Datenhoheit und reale FKs stehen im [Teilmodell](../architecture/domain-model.md#gruppenentzug-beim-austritt-identity-046) und [ERD](../architecture/erd.md#gruppenentzug-beim-austritt-identity-046).

Die vorherigen **917** Source-Eingaben waren vor Beginn unverändert. Final: **929** Source-/Dokumentationseingaben, **902** Runtime-/Fixture-/API-Eingaben. Nur die beiden nachgewiesenen QA-Oracle-Korrekturen änderten nach dem ersten Freeze Testdateien; die übrigen 900 Eingaben blieben identisch. Jeder der drei finalen signierten/Browserprozesse protokolliert 17 tatsächliche Quell-SHA-256 vor Migration und nach Terminal, alle identisch zum aktuellen Stand. Belege: `/tmp/od-business17-baseline-check.log`, `/tmp/od-business17-runtime-frozen.sha256`, `/tmp/od-business17-runtime-check-final.log`, `/tmp/od-business17-source-final.sha256`, `/tmp/od-business17-gates.json`. 046 SHA-256 `ac4782cb3fecd660cc471bcdf2efaace474545716c7eb6ba41fc0b64bdbf0515`; Parent045, bestehender GroupMutator und Policy024 unverändert.

Bekannte nicht fatale SWC-/Workspace-Lockfile-/Browserslist- und React-act-Testwarnungen sowie die vorhandene ESLint-Ausnahme bleiben sichtbar. Unabhängiger voller Typecheck bleibt erforderlich, weil Next intern Testdiagnosen filtert. Keine neue Dependency, kein Lockfile-/Framework-Upgrade, Commit/Push, Deployment oder externer produktiver Schreibvorgang. Vollständige Rollen/PIM-, Session-, OU-, Geräte-/Providerbereinigung, allgemeines Gruppen-RBAC, eigene Custom-Rollen/Scopes und die übrigen BRs sowie Security-/Last-/WCAG-/Restore-/Retention-/Produktivabnahme bleiben offen. Der Gesamtauftrag bleibt aktiv.

## Business-Slice 18: Rollen und PIM beim Austritt

Stand: 19. Oktober 2026. **Tested, begrenzter lokaler Teilprozess**, weder vollständiger WF-004 noch Produktions-/Anbieterabnahme. [Benutzer-/API-Vertrag](../features/company-offboarding-access.md), [Datenhoheit](../architecture/domain-model.md#rollen-pim-entzug-beim-austritt-identity-047), [Mermaid-ERD](../architecture/erd.md#rollen-pim-entzug-beim-austritt-identity-047).

Der unveränderte negative Account-Checkpoint aus Identity 045 trägt nun ausdrücklich bestätigte Rollen-/PIM-Children. Originaler menschlicher Bearer, kanonischer Home-Tenant und unabhängig belegte MFA innerhalb von 300 Sekunden bleiben verbindlich. Rollen und PIM verlangen ihre tatsächlichen separaten Lese-/Managementpflichten; ein Roleless-Owner erhält ausdrücklich keinen Zugriff. Geschützte Grants benötigen den tatsächlichen kanonischen Admin. Ein separat zugelassener Operator verwendet die echte eigene MFA-Selbsteinrichtung und Console-App-Zuweisung; keine Owner-/Tokenrollen-Abkürzung und kein zusätzliches `users.read`.

Vollständiges Read-only-Preflight vor erster Wirkung, genaue alte Grant-UUID/UTC-Row-Hash, vorhandener `DirectoryRoles.revoke` bzw. `PrivilegedActivation.revokeEligibility`, tatsächlicher Command-Checkpoint und atomare Receipt-/Audit-/Pending-Outbox gehören zusammen. Echte PIM-Tests prüfen sowohl offene Anträge als auch aktivierte Rollenzuweisungen. Spätere Fehler behalten frühere Commits; ein unsicherer Child stoppt weitere Arbeit. Recovery bestätigt nur alte gültige ID-/Versionsbelege, nie einen späteren Grant. Native Tests prüfen 25 von 26 echten Grants, veränderte Kontogeneration, fremde importierte Kaskaden, fehlende Receiving-/Outbox-Belege, Unveränderlichkeit und tatsächlichen Fristablauf nach dem Application-Checkpoint.

Die Entwicklungstests fanden und korrigierten insbesondere eine tatsächliche BIGINT-Rundung durch einen JavaScript-JSON-Roundtrip: Grant-Hashes werden jetzt vor dem JSON-Transport in PostgreSQL berechnet. Eine Policyversion `9007199254740993` und nicht-UTC-Sessions sind native Gegenbelege. Die SQL-Receipt belegt zusätzlich die realen Authorization-/Record-Audits der vorhandenen Kernel. Alte PIM-Antragsänderungen sind nicht fälschlich neue Entzugseffekte. Rollen-/PIM-Kernel, Rollenvertrag Schema 6/feste 62 Rollen und Owner-Fähigkeiten bleiben unverändert.

### Finale Gates

| Gate | Tatsächlicher finaler Umfang | Ergebnis / Log |
| --- | --- | --- |
| Identity Jest | 958 Fälle, 50 Suiten | Exit 0; `/tmp/od-business18-access-identity-unit-final.log` |
| Policy Jest | 858 Fälle, 26 Suiten | Exit 0; `/tmp/od-business18-policy-unit-final.log` |
| Frontend Jest | 2'286 Fälle, 95 Suiten | Exit 0; `/tmp/od-business18-web-final.log` |
| Identity PostgreSQL-Gesamtrunner | 674 Fälle, 20 explizite Dateien, `TMPDIR=/tmp` | Exit 0; `/tmp/od-business18-identity-native-final.log` |
| BrowserAuth | 46 Fälle | Exit 0; `/tmp/od-business18-browser-auth-final.log` |
| Signierter Company-Gateway-Prozess | Eine vorhandene tatsächliche Definition erweitert; andere signierte Definitionen nicht erneut ausgeführt | 1/1, Exit 0; `/tmp/od-business18-signed-r3-final.log` |
| Produktionsbrowser | Dieselbe vorhandene Company-Definition in zwei frischen Prozessen: normal sowie fehlerhafte Access-Antwort plus bestehende unsichere Gruppen-Antwort | Je 1/1, Exit 0; `/tmp/od-business18-browser-normal-final.log`, `/tmp/od-business18-browser-malformed-final.log` |

Das sind **4'824 unterschiedliche erfolgreiche Falldefinitionen / 4'825 Ausführungen**. **283 neue Definitionen** gegenüber Slice 17: 36 Shared-/API-Contract-, 60 Backend-/Authority-/Routing-, 165 Frontend- und 22 native Identity-Fälle. Die separat erneut bestandenen fokussierten 22 nativen bzw. 164 Frontend-Fälle sind bereits in den Gesamtläufen enthalten und werden nicht addiert. Die beiden Browservarianten sind keine zwei neuen Definitionen; die separate Profil-Browserdefinition wurde hier nicht erneut ausgeführt.

Unabhängiger vollständiger Typecheck ohne Incremental-Cache: Exit 0, `/tmp/od-business18-types-final.log`. Unveränderter Standard-Produktionsbuild: Exit 0, `/tmp/od-business18-build-final.log`. Beide Browserprozesse bauen zusätzlich ihre eigene Produktionsausgabe und verwenden echtes `next start`, originale Cookies/BFF/Bearer, lokale persistente Dienste und wirklichen Chrome. Der fehlende Docker-`COPY` für den neu importierten bestehenden Rollenkatalog ist um genau diese Datei ergänzt und durch einen zusätzlichen bestehenden Deployment-Suitentest abgesichert; kein neues Paket oder zweiter Katalog.

### Tatsächliche Browser- und Quellbelege

Main und QA haben die drei finalen Screens visuell gelesen: `/tmp/od-business18-access-confirmation.png`, `/tmp/od-business18-access-completed.png`, `/tmp/od-business18-access-history.png`. Sichtbar: genau eine bestätigte alte Rolle, geschützter nicht auswählbarer Grant, reale PIM-Widerrufsmeldung, bewusst noch alte Historie vor Readback und danach der tatsächliche retained Nachweis mit ursprünglichem Hash, Command-Checkpoint, Actor und ausstehender Zustellung. Der unbekannte HTTP-Erfolg wird nicht automatisch wiederholt; der Browser bestätigt ausdrücklich die alte ID/Version, während ein neuer Grant bestehen bleibt. Kein vollständiger Austritt oder externer Erfolg wird angezeigt.

Zwei vorbereitende signierte Prüfungen scheiterten an konkreten Fixture-Annahmen, nicht an diesen finalen Gates: Öffentliche MFA-Ersteinrichtung ist für Konten ohne verpflichtende Richtlinie absichtlich abgelehnt; die Fixture verwendet nun die vorhandene angemeldete Selbsteinrichtung mit echtem Passwortnachweis und danach neue MFA-Anmeldung. Ausserdem überschrieb ein unaliasiertes `checkpoint.valid_until` die gleichnamige Receipt-Spalte im SQL-Ergebnis. Der korrigierte Test prüft getrennt die exakte zusätzliche 300-Sekunden-Receipt-/Source-Frist und die Originaltokenfrist des unveränderten kanonischen Checkpoints; kein Sicherheitskriterium wurde entfernt. Fehlversuche bleiben unter `/tmp/od-business18-signed-prep-r1.log` und `/tmp/od-business18-signed-prep-r2.log` erhalten.

Die 929 vorherigen Source-Eingaben waren vor Beginn unverändert. Final: **946 Source-/Dokumentationseingaben**, **918 Runtime-/Fixture-/API-Eingaben**. Nach dem ersten abgenommenen Runtime-Freeze änderten nur die beiden eben genannten QA-Dateien; die übrigen **916 Eingaben** blieben identisch. Revision 3 ändert gegenüber Revision 2 nur den signierten Test. Alle drei finalen HTTP-/Browserprozesse protokollieren jeweils 32 SHA-256 vor Migration und nach Terminal; diese stimmen mit `/tmp/od-business18-qa-freeze-r3.json` und dem finalen Repository überein. Hauptbelege: `/tmp/od-business18-runtime-frozen.sha256`, `/tmp/od-business18-source-final.sha256`, `/tmp/od-business18-gates.json`. Identity 047 SHA-256: `f208aba393a599b5e3a2162edfbaf62fb87a1ba5529cf3ce0951ab5644032b2a`; Parent045/046, bestehende Rollen-/PIM-Kernel und Policy024 unverändert.

OpenAPI **1.15.0**: **84 eindeutige Operationen**, **131 auflösbare lokale Referenzen**, bytegleicher Generatoroutput; vier neue tatsächlich integrierte Operationen. Keine globale Rollenquelle oder zusätzliche Company-App-Fähigkeit entsteht.

Bestehende nicht fatale SWC-/Workspace-Lockfile-/Browserslist-/React-act-Warnungen und ESLint-Ausnahme bleiben. Docker-Image nicht gebaut: lokaler Daemon nicht erreichbar (`/tmp/od-business18-docker-check.log`), also keine Linux-/Clean-Install-Abnahme. Eine breitere Dokumentations-Linkprüfung findet vier unveränderte fehlende Services-Wiki-Seiten in `docs/README.md`; neue Feature-/Modell-/API-Verweise sind gültig. Keine neue Dependency, Lockfile-/Frameworkmigration, Commit/Push, Deployment oder externer produktiver Schreibvorgang. Eigene Custom-Rollen/Scopes, allgemeines Gruppen-RBAC, sämtliche Sessions, OU-/Geräte-/Provider-Bereinigung, vollständiges WF-004 und übrige BRs sowie Last-/WCAG-/Restore-/Retention-/Produktivabnahme bleiben offen. **Der Gesamtauftrag bleibt aktiv.**
## Business-Slice 19: Geräterückgabe beim Austritt

Stand: 19. Oktober 2026. **Tested, begrenzter lokaler Teilprozess** von BR-003/WF-004. [Benutzer-/API-/Recovery-Vertrag](../features/device-returns.md), [Datenhoheit](../architecture/domain-model.md#geräterückgabe-device-006), [Mermaid-ERD](../architecture/erd.md#geräterückgabe-device-006). Keine vollständige Apple-Business-/Entra-Plattform, kein abgeschlossener gesamter Austritt und keine Produktions- oder MDM-Abnahme.

Die tatsächliche negative Identity-045-Kontosperre trägt nun ausgewählte eigene Geräte-Rückgabeanforderungen. Diese lassen Device und Assignment unverändert. Erst die separat manuell bestätigte Übergabe verwendet den unveränderten kanonischen `DeviceInventory`-Entzug. Dessen 005-Event/-Outbox und 006-Auftrag/-Event/-Outbox committen in derselben Device-Transaktion. Abbrechen verändert nur Aufgabenmetadaten; eine gewöhnliche normale Neuzuweisung ergibt `assignment_changed`, keinen erfundenen Rückgabe-Event. Ein historisch zurückgegebener Auftrag ist keine Aussage über heutige Geräteverfügbarkeit.

Die bisherige 11-Feld-Inventarquelle und exakt drei Rechte bleiben unverändert. Eine neue 13-Feld-Quelle bindet denselben ursprünglichen Bearer, tatsächlichen eigenen Owner/Home-Admin, frische unabhängig belegte MFA und minimalen validierten negativen Parent. Target-Authorization-Revision-Wechsel nach Rollenentzug sind nicht mit einer neuen negativen Eligibility zu verwechseln. Anfordern/Erstellungs-Recovery verlangt weiterhin den ursprünglichen negativen Parent; tatsächliche spätere Inventar-Handback-Entscheidungen können unabhängig davon auch nach Reaktivierung erfolgen. Neue globale Rolle, Company-App-Recht oder Service-Credential entsteht nicht.

### Finale Gates

| Gate | Tatsächlicher finaler Umfang | Ergebnis / Log |
| --- | --- | --- |
| Identity Jest | 996 Fälle, 52 Suiten | Exit 0; `/tmp/od-business19-identity-unit-r2-final.log` |
| Policy Jest | 858 Fälle, 26 Suiten | Exit 0; `/tmp/od-business19-policy-unit-final.log` |
| Frontend Jest | 2'456 Fälle, 99 Suiten | Exit 0; `/tmp/od-business19-frontend-web-r2-final.log` |
| Gateway Jest | 146 Fälle, 6 Suiten | Exit 0; `/tmp/od-business19-gateway-unit-final.log` |
| Device produktionsnaher Jest-Teil | 307 Fälle, 6 gezielte Inventar-/Source-/Return-Suiten; **nicht** die Legacy-Device-Gesamtsuite | Exit 0; `/tmp/od-business19-device-unit-main-r2-final.log` |
| Identity PostgreSQL-Gesamtrunner | 679 Fälle, 20 explizite Dateien | Exit 0; `/tmp/od-business19-identity-native-final.log` |
| Device PostgreSQL-Inventar-/Return-Runner | 97 Fälle: 52 bestehende plus 45 neue | Exit 0; `/tmp/od-business19-device-event-version-native-r2-final.log` |
| BrowserAuth | 46 Fälle | Exit 0; `/tmp/od-business19-browser-auth-final.log` |
| Signierter Company-Gateway-Prozess | Eine bestehende Definition um tatsächliche Device-/Identity-/005-/006-Orakel erweitert; andere signierte Definitionen nicht neu ausgeführt | 1/1, Exit 0; `/tmp/od-business19-signed-r2-final.log` |
| Produktionsbrowser | Dieselbe vorhandene Company-Definition normal und mit beschädigten echten Erfolgsantworten; jeweils neuer PostgreSQL-/Build-/Next-start-/Chrome-Prozess | Je 1/1, Exit 0; `/tmp/od-business19-browser-normal-r2-final.log`, `/tmp/od-business19-browser-malformed-r2-final.log` |

**5'587 unterschiedliche erfolgreiche Falldefinitionen / 5'588 Ausführungen.** Neu sind **378 Definitionen**: 38 Identity-Unit-/Routing-, 31 gemeinsamer Device-Vertrag, 75 Device-Source-/Routing-, 14 Gateway-, 170 Frontend- und 50 native Fälle (5 Identity, 45 Device). Gegenüber Slice 18 kommen ausserdem 385 bereits vorhandene Definitionen aus den zusätzlich geprüften Device-/Gateway-Gates hinzu: 201 Device-Unit-, 52 Device-PG- und 132 Gateway-Fälle. Diese sind zusätzliche ausgeführte Abdeckung, keine neu geschriebenen Tests. Fokussierte Läufe und frühere grüne Revisionen sind in diesen Gesamtläufen enthalten bzw. vorbereitend und werden nicht addiert. Normal/Fehlerantwort sind zwei Ausführungen derselben Browserdefinition; die getrennte Profil-Browserdefinition wurde nicht erneut ausgeführt.

Vollständiger unabhängiger Typecheck ohne Incremental-Cache: Exit 0, `/tmp/od-business19-frontend-types-r2-final.log`. Unveränderter Standard-Produktionsbuild: Exit 0, `/tmp/od-business19-build-r2-final.log`. Beide finalen Browserprozesse bauen zusätzlich eine eigene Produktionsausgabe und verwenden echtes `next start` und Chrome. Kein TypeScript-Ignore, neues Paket, Lockfile-/Framework-Upgrade oder Testausschluss wurde für diese Funktion ergänzt. Die breitere bekannte Legacy-Device-Gesamtsuite ist nicht erneut als grün behauptet.

### Tatsächliche Gegenbelege und korrigierte Integrationslücke

Native Prüfungen belegen echtes Whole-manifest-Preflight, 25 von 26 Assignments, Teilfehler mit erhaltenen früheren Children, ursprüngliche UUID-/ETag-Recovery nach verlorenem ACK und Schutz eines später neu vergebenen Assignments. Eine ausgelassene abschliessende 006-Outbox rollt auch den bereits tatsächlich versuchten kanonischen 005-Release zurück. Die normale spätere Freigabe/Neuzuweisung bleibt möglich, erzeugt aber keinen Rückgabe-Event. Source-Verlust, falscher Home-Tenant, neue Kontogeneration, abgelaufene ursprüngliche Frist nach Application-Checkpoint, gelöschter Scope, Raw-DML und vor Admission eingeschobene Legacy-Device-Effekte sind getrennte reale PostgreSQL-Gegenbelege. Originale 005-Migration, `DeviceInventory` und `InventoryAuthority` bleiben unverändert.

Die erste tatsächliche Browserprüfung fand eine echte Routinglücke: neue verschachtelte Return-/Offboarding-Return-URLs fielen durch die bisherigen Next-Regeln ins falsche API-Backend. Zwei spezifische Regeln vor dem Catch-all beheben die Ursache. **Neun neue Regressionen verwenden den tatsächlichen installierten Next-`getPathMatch`**, einschliesslich des Zero-Segment-`:path*`-Falls; fremde Remote-Command-Familien bleiben unverändert. Kein Fake-Frontend-Receiver oder Test-Bypass ersetzt diese Reparatur.

Vor finaler Abnahme ergänzt der neue Business-Event-Vertrag ausserdem die explizite Ereignisversion `1` in SQL, DTO, Zod und OpenAPI. Das idempotente Backfill auf einer vorherigen unveröffentlichten 006-Tabellenform ist tatsächlich geprüft. Die Datenrevision eines Requests ist nicht deren Ereignisversion. Eine weitere konkrete Direktaufruf-Regression prüft, dass auch ohne übergebene Correlation-ID 005-Release und 006-Entscheidung denselben einmal generierten Correlation-Wert tragen.

Der erste signierte Lauf bestand bereits, der erste Browserlauf scheiterte vor Device-UI-Abnahme an der Weiterleitung; die damalige Fehlerantwort-Variante wurde nicht gestartet. Diese vorbereitenden Resultate und der alte 53-Source-Freeze bleiben erhalten, sind aber keine zusätzlich gezählten finalen Definitionen. Die drei finalen R2-Prozesse verwenden alle denselben neuen Source-Freeze und den korrigierten tatsächlichen Routing-/Event-Vertrag.

### Quell- und Bildbelege

Main und QA lesen die drei tatsächlichen finalen Bilder aus dem letzten Fehlerantwort-Prozess: `/tmp/od-business19-device-return-confirmation.png`, `/tmp/od-business19-device-return-completed.png`, `/tmp/od-business19-device-return-history.png`. Der scrollbare Dialog zeigt die ursprünglich erfassten drei Geräte/Seriennummern, ausdrückliche Bestätigung und den Hinweis, dass Anfordern keine Rückgabe ist. Der erfolgreiche Wiederaufnahmezustand ist ausdrücklich historisch, ohne Behauptung aktueller Verfügbarkeit. Die tatsächliche Historie zeigt Request und manuelle Bestätigung mit Versionswechsel 1→2, realer Inventory-Operation und ausstehender Zustellung. Kein separates vollständig erhaltenes Normal-Bildset wird behauptet.

Die vorherigen **946** Source-Eingaben waren vor Beginn unverändert. Final sind **967 Source-/Dokumentationseingaben** und **938 Runtime-/Fixture-/API-Eingaben** erfasst. Alle drei finalen HTTP-/Browserprozesse protokollieren jeweils **53** tatsächliche SHA-256 vor Migration und nach Terminal; alle stimmen mit `/tmp/od-business19-qa-freeze-r2.json` und dem finalen Stand überein. Hauptbelege: `/tmp/od-business19-runtime-frozen.sha256`, `/tmp/od-business19-source-final.sha256`, `/tmp/od-business19-gates.json`. Änderungen zwischen vorbereitendem und finalem Freeze sind im QA-Handoff erhalten; alte 045/046/047, Policy024 und der bestehende Inventar-Kernel bleiben unverändert. Tests, Quellen und Dokumentation werden nicht durch einen alten grünen Prozess ersetzt.

OpenAPI **1.16.0** hat **94 eindeutige Operationen / 146 auflösbare lokale Referenzen**, bytegleichen Generatoroutput und die tatsächliche Event-Version 1. Zehn neue Operationen trennen private ursprüngliche Herkunft, Request und operative Entscheidung. Das ist nicht die Dokumentation sämtlicher noch offenen Plattform-APIs.

Bestehende nicht fatale Next-SWC-/Workspace-Lockfile-/Browserslist- und React-act-Warnungen sowie vorhandene ESLint-Ausnahme bleiben. Vier bekannte unveränderte fehlende Services-Wiki-Seiten bleiben in der breiteren Dokumentations-Linkprüfung sichtbar, keine neuen Feature-/Modell-/API-Verweise sind gebrochen. Docker-/Linux-Image, reproduzierbarer Clean-Install, getrennte Runtime-/Migrationslogins, unabhängige Retention, Backup/Restore, Last/WCAG und Produktivbetrieb sind nicht abgenommen. Keine produktive Deployment-/Provider-/Geräteaktion, kein Commit/Push und keine neue Dependency. Eigene Geräte-Rollen/OU-Scopes, vollständige Sessions/externen Credentials, übrige JML-/Blueprint-/Lizenzkomposition, echter MDM-Provider und die übrigen BRs bleiben offen. **Der Gesamtauftrag bleibt aktiv.**

## Business-Slice 20: Blueprint-Konfliktvorschau

Status: **Tested**, begrenzter Vergleich vorhandener Platform-Policy-Blueprints, kein vollständiger BR-004 oder Company-Onboarding. Alle unten gezählten finalen Gates enden mit Exit 0.

### Implementierter Umfang

Ein echtes `POST /api/blueprints/preview` liest höchstens 25 explizit ausgewählte aktuelle Elternversionen und deren Konfigurationen gemeinsam in einer Read-only-Repeatable-Read-Transaktion. Bestehendes kanonisches `policies.preview`, ursprüngliche Live-Authority und `no-store` bleiben verbindlich. Firmeninhaberschaft, App-Verwaltung, Body-Scopes oder Service-Accounts erteilen keine neue Policy-Hoheit.

PostgreSQL-JSONB-Gleichheit bestimmt Gruppen gleicher Inhalte. Unterschiedliche Inhalte derselben Konfigurationsart bleiben Konflikte ohne Gewinner. Die Vorschau behält alle ursprünglichen Konfigurations-IDs, zeigt exakten `payloadJson`-Text und behauptet keine Geräte-/Lizenzwirkung. Numerisch gleiche Schreibweisen werden zusammengefasst; unterschiedliche grosse Ganzzahlen bleiben unterschiedlich. Arrays bleiben geordnet. Konservative Ein-Profil-pro-Art-Semantik statt erfundener Apple-/WLAN-/VPN-Komposition.

Der bestehende Single-Blueprint-`/apply`-Pfad prüft Konflikte vor unabhängiger Freigabe und externer Zustellung. Direkte kanonische `deliveryFrame`-Admission prüft den gesamten gesperrten Blueprint ebenfalls. Ein nicht verlustfreier JavaScript-/JSONB-Roundtrip wird mit `503 blueprint_payload_not_lossless` verweigert. Freigabe, MFA, Version, Zielbindung und wiederholte Quellprüfung werden nicht ersetzt.

### Gates

| Tatsächlich abgegrenzte Gruppe | Erfolgreiche Definitionen | Umfang |
| --- | ---: | --- |
| Identity Jest | 996 | 52 Suiten; bestehender Generator-/Vertragsabgleich |
| Policy Jest | 948 | 29 Suiten; vollständiger vorhandener Jest-Lauf |
| Frontend Jest | 2'602 | Vollständiger R4-Lauf aller 101 Suiten |
| Policy native PostgreSQL | 471 | Alle zwölf Dateien des erweiterten vorhandenen Runners |
| Tatsächlicher Produktionsbrowser | 1 | Eine bestehende erweiterte Blueprint-Definition; tatsächlicher R4-Lauf |

**5'018 unterschiedliche erfolgreiche Definitionen / 5'018 gezählte finale Ausführungen.** Vollständiger Typecheck und Standard-`next build` auf R4 enden ebenfalls mit **Exit 0**. Frühere Fokus-/Vorbereitungsläufe werden nicht zusätzlich als Abdeckung gezählt.

**270 neue Falldefinitionen:** 90 Policy-Jest-Fälle (43 Resolver/Request, ein OpenAPI-Vertrag, 45 Routes, ein neuer Eintrag der bestehenden Deny-Matrix), 34 native PostgreSQL-Fälle und 146 Frontend-Fälle (97 Helper, 49 Panel). Die bestehende Browserdefinition wird erweitert, nicht als neue Definition umbenannt. Dieser Gate-Umfang unterscheidet sich von Slice 19; keine Behauptung einer erneuten Ausführung aller damaligen zehn Gruppen.

### Fachliche und Sicherheitsbelege

- Reale gemeinsame SQL-Snapshots, explizite Elternversionen, fehlende/geänderte Eltern, Plattformkonflikte und unveränderte Audit-/Outbox-/Lizenzdaten.
- Tatsächliche SQL-Gleichheit für verschachtelte Objekte und `1`/`1.0`; unterschiedliche `9007199254740992`/`9007199254740993` bleiben Konflikte mit exaktem Text.
- Array-Reihenfolge, keine stillen Deep Merges/Prioritäten, keine mehrfach gezählten ursprünglichen IDs und kein erfolgreicher abgeschnittener Preview bei Grenzen.
- Tatsächlich 1'000 beziehungsweise 1'001 Konfigurationen sowie die exakte 1-MiB-UTF-8-Grenze; keine produktiven Trigger-/Kernel-/Timeout-Lockerungen.
- Rechteverlust vor/nach Abfrage, ungültige Service-/Alias-/Company-Authority und abgebrochene Aufrufe liefern keine bestätigte Vorschau.
- Wirklich unabhängig freigegebene direkte Delivery-Frames verweigern interne Konflikte und Zahlenverlust; gleichwertige verlustfreie Zahlen bleiben zulässig.
- Frontend bindet dieselbe Person und beide bestehenden Rechte; Auswahl-/Plattform-/Katalog-/Sitzungswechsel verwerfen Resultate und verspätete Antworten. Keine automatischen Writes, Aktualisierungen oder Wiederholungen.

### Echte Browserabnahme und Korrekturen

Isolierter Chrome gegen einen frisch gebauten `next start`, echten Issuer, echte signierte BFF-/Policy-HTTP-Aufrufe und native PostgreSQL-Schemata. Der bestehende Geräteauftrag des früheren Einzel-Blueprint-Ablaufs bleibt ein protokollierter lokaler Auftrag, keine physische MDM-Erfolgsbehauptung. Zwei über die tatsächliche UI erstellte Blueprints A3/B2 ergeben ein gemeinsames Profil mit zwei Originalquellen. Ein zusätzliches widersprüchliches Profil in B3 ergibt zwei Varianten mit drei Quellen, keinen Gewinner und keine effektive Konfiguration dieses Typs. Die erfasste alte B2-Version scheitert mit `412`; B3-`/apply` scheitert vor fehlender Freigabe mit `409 blueprint_configuration_conflict`. Policy-Audit-/Outbox-, Lizenz- und Receiver-Evidenz bleiben durch Vorschau und Ablehnung unverändert; genau der vorher vorhandene stornierte Geräteauftrag bleibt erhalten.

Der erste echte R2-Lauf erreichte die Erstellung beider Blueprints, scheiterte aber vor dem ersten Preview-POST am exakten Plattformlabel. Die neue UI-Beschriftung umfasste auch die Select-Optionen. Die Ursache wurde durch getrennte `label[for]`-/`select[id]`-Zuordnung behoben, nicht durch einen weicheren Browserselektor. Ein bestehender Component-Test prüft jetzt den exakten zugänglichen Namen und die tatsächliche Labelzuordnung.

Zwei vorbereitende Typfehler betrafen nur neue Tests: explizite Tupeltypisierung einer Negativfall-Tabelle und ein versehentlich aus Playwright übernommenes, von React Testing Library nicht unterstütztes `exact`-Optionsfeld. Beide sind an der Ursache korrigiert; keine Typunterdrückung oder entfernte Assertion. Der überholte R3-Jest-Vorbereitungslauf wurde gezielt beendet und zählt nicht als bestanden. Ein anfänglicher bestehender Policy-API-Timeout bestand unverändert im fokussierten und vollständigen finalen Wiederholungslauf; kein Timeout wurde erhöht.

### Belege und Grenzen

Finale Logs: `/tmp/od-business20-identity-unit.log`, `/tmp/od-business20-policy-unit-final.log`, `/tmp/od-business20-policy-native-final.log`, `/tmp/od-business20-frontend-unit-r4-final.log`, `/tmp/od-business20-frontend-types-r4-final.log`, `/tmp/od-business20-build-r4-final.log` und `/tmp/od-business20-blueprint-browser-r4-final.log`. Der R2-Fehllauf ist als `/tmp/od-business20-blueprint-browser-r2-failed.log` und `/tmp/od-business20-blueprint-browser-r2-failed-proof.json` erhalten und zählt nicht als finaler Browsererfolg.

R4-Runtime-Freeze: **949 Einträge** inklusive Wrapper, davon 948 Repository-Dateien; Manifest `/tmp/od-business20-runtime-freeze-r4.json`, SHA-256 `b52bf657fbe1c591053bb900908e505eda775d4e30d67328a04dfae7e485a96e`. Tatsächlicher Browserstart `2026-10-19T16:14:24.135Z`, Abschluss `2026-10-19T16:15:07.268Z`, Exit 0. Startup-/Completion-/aktuelle Quellhashes, Freeze-Manifest und Wrapper sind unverändert; Proof `/tmp/od-business20-blueprint-browser-proof.json`.

Main hat beide tatsächlichen R4-Screenshots visuell geprüft: `/tmp/od-business20-blueprint-preview.png` (SHA-256 `71a1549a80e96fd62ae96d2a15561e7f283a929070566fe2816243a930a82795`) zeigt ein gemeinsames Profil mit beiden Quellen; `/tmp/od-business20-blueprint-conflicts.png` (`4c0d1fac31b6be6972a238499a8d5ba5c53ff262b1b9fa0ad877b14c63a797a8`) beide widersprüchlichen Varianten und ihre tatsächlichen Versionen. Das ist keine vollständige WCAG-/Layout-Abnahme.

OpenAPI **1.17.0**: **95 eindeutige Operationen / 148 auflösbare lokale Referenzen**, bytegleicher Generatoroutput. Genau eine neue Preview-Operation; keine Behauptung, sämtliche übrigen Plattform-APIs seien dokumentiert.

Zusammengefasste finale Belege: `/tmp/od-business20-gates.json`. Das abschliessende `/tmp/od-business20-source-final.sha256` umfasst 979 Repository-Dateien inklusive Dokumentation. Die relative Linkprüfung über 31 Markdown-Dateien und 439 Verweise findet keine neuen fehlenden Ziele; vier schon bekannte fehlende Services-Wiki-Seiten bleiben unverändert und werden nicht als behoben gezählt.

Bekannte nicht fatale Next-SWC-/Workspace-Lockfile-/`ENOWORKSPACES`-/Browserslist- sowie React-act-Warnungen und bestehende Lint-Ausnahme bleiben. Neue Abhängigkeiten, DB-Migrationen, Environment-Variablen, produktive Deployments und externe Provider-Schreiboperationen sind nicht hinzugefügt.

Offen: mandanteneigene Blueprint-/Rollen-/Scope-Governance, immutable historische Payload-Versionen, automatische Ziel-/Gruppenauflösung, Komposition mit Apps/Lizenzen, vollständiger Onboarding-Prozess, Provider-Validierung und MDM-Ausführung. Konflikte anderer zugewiesener Blueprints werden nicht automatisch bei einer einzelnen Admission berechnet. Docker/Linux, Clean-Install, Last/WCAG, Backup/Restore und Produktivbetrieb sind nicht abgenommen. **Der Gesamtauftrag bleibt aktiv.**

# Business-Slice 22: Blueprint-Lizenzherkunft und Offboarding

Status: **In Progress**. Die signierte Gateway-End-to-End-Definition besteht nach Korrektur des Historienvergleichs; die Browserabnahme ist offen.

Der Offboarding-Workflow verglich gespeicherte JSON-Zeitstempel mit `to_jsonb`-Werten unter der aktuellen PostgreSQL-Session-Zeitzone. Nach erneuter Aktivierung desselben Benutzers wurden gleichwertige `timestamptz`-Werte (`+00:00` gegenüber `+02:00`) als abweichend bewertet und historische Wiederaufnahme mit 503 abgelehnt. Die Validierung vergleicht jetzt übrige Felder unverändert und prüft `created_at`/`updated_at` als typisierte Zeitstempel.

| Gate | Ergebnis | Umfang |
| --- | --- | --- |
| Signiertes Gateway-/PostgreSQL-E2E | **1/1 bestanden** | Tatsächlicher roleless Owner, mehrere Blueprint-/manuelle Quellen, gemeinsamer Sitz, negatives Offboarding und Wiederaufnahme nach Reaktivierung; isolierte PostgreSQL-Umgebung |
| Browser-/Next-E2E | **Nicht bestanden** | Produktionsbuild gelingt; Browser wartet auf `Blueprint-Mitarbeiter auswählen`, das in diesem least-privilege-Szenario nicht erscheint. Kein grüner Browsernachweis |

Die Browser-E2E-Lücke bleibt offen und wird nicht als Produktivabnahme behauptet. MDM-/Apple-Gerätebefehle, vollständige Business-Plattform, übrige BRs und Betriebsabnahme bleiben ebenfalls offen.

## 22. Oktober 2026 — Lizenzgruppen und Skript-Abgleich

Begrenzter lokaler Ablauf: normale Gruppen mit ausdrücklichen eigenen Pool-Verknüpfungen, Mitgliedsabgleich aus UI/CLI und Erhalt anderer Lizenzherkünfte. Keine neue Hersteller-Provisionierung oder unbeaufsichtigte App-Schreibdelegation.

| Prüfung | Ergebnis |
| --- | --- |
| Identity Jest | 1'162 bestanden, 57 Suites; ein vorübergehender Socket-Abbruch in einer vorhandenen Routingdefinition bestand beim vollständigen Wiederholungslauf |
| Policy Jest | 1'313 bestanden, 38 Suites; einschliesslich generiertem OpenAPI-Readback |
| CLI/Node | 16 bestanden; tatsächlicher CLI-Prozess über HTTP mit ursprünglichem menschlichem Bearer, Operation-Key und Exit 2 bei knappem Pool |
| Frontend, relevante Gruppen-/Blueprint-Definitionen | 48 bestanden; die zuletzt geänderten Lizenzgruppen-Definitionen zusätzlich 11/11 |
| Identity PostgreSQL | 63 bestanden; tatsächlicher rollenloser Owner, fremde Gruppen, retained Löschung und MFA-Grenze |
| Policy PostgreSQL, Lizenzgruppen und Firmenlizenzen | 114 bestanden, davon 9 neue Lizenzgruppenfälle: Poolknappheit, Herkunftsüberlappung, Paginierung, parallele Vergabe, Eligibility-Wechsel, Original-Intent-Recovery und Rollback bei physischem Deadline-Ablauf |
| Policy PostgreSQL, bestehende Blueprint-Zuweisungen | 11 bestanden mit dem abschliessenden Migrationsstand; Mehrquellen-Vergabe, Rollback, negative Eligibility und historische Recovery |
| TypeScript / Next-Produktionsbuild | Bestanden; lokaler Next-Lockfile-Patcher meldete eine bestehende Workspace-Warnung, Build mit bereits installiertem SWC und `NEXT_IGNORE_INCORRECT_LOCKFILE=1` ebenfalls bestanden |

Native Tests verwenden isolierte Wegwerf-PostgreSQL-Cluster. Die bisher offene allgemeine Browser-Offboarding-Abnahme ist durch diese Prüfungen nicht erledigt. Keine Produktivdatenbank, externe Lizenzplattform oder Mailbereitstellung wurde verändert.

## 22. Oktober 2026 — Eigene App-Freigaben und dauerhafte Exportjobs

Begrenzt abgenommen: dedizierter `company.automation`-Scope ohne menschliche Rollen, ausdrückliche zeitlich begrenzte Owner-/MFA-Freigaben für eine konkrete Clientgeneration sowie tatsächliche eigene Benutzer-, Gruppen- und OU-Exporte. Identity 048 ergänzt persistente Jobs, Zeitpläne, Worker-Leases, fünf Versuche mit Backoff, manuelle Wiederaufnahme und unveränderliche Historie. Der bestehende kanonische Identity-/Lizenzschreibweg bleibt separat.

| Prüfung | Ergebnis und Grenze |
| --- | --- |
| Identity Jest | **1'179/1'179**, 59 Suites; vollständiger Lauf mit dem abschliessenden Backendstand |
| OAuth Jest | **477/477**, 19 Suites; einschliesslich tatsächlicher JWT-Ausgabe für den neuen Scope ohne menschliche/mandantenbezogene Rollen und verweigerter globaler Clientverwaltung |
| CLI/Node | **23/23**; tatsächliche Worker-Prozesse über HTTP, durchgehend parsebare JSON-Zeilen, Exit 2 bei bestätigtem fehlgeschlagenem Job und vollständiger Vier-MiB-Download auch bei maximaler JSON-Escapierung |
| Frontend | **11/11** in den zwei neuen Automationssuiten; Kontext-/Antwortprüfung, Freigabe, unbekannte Ergebnisse, Queue und Versionen |
| Gateway | **2/2**; vorhandener kanonischer Identity-Prefix mit ursprünglichem Bearer, keine neue globale Gateway-Berechtigung |
| OpenAPI-Regression | **7/7**; generierter Vertrag **1.21.0**, zwölf neue Pfade und zwölf neue Schemas, vorhandene Pfade/Schemas semantisch unverändert |
| Native PostgreSQL, neuer Automationsweg | **14/14**; tatsächliche kanonische Owner-Aktivierung, eigene/fremde Daten, Widerruf, Rotation, Parallelität, alle Exporttypen, physische Deadline, abgebrochene Worker einschliesslich fünftem Lease, fünf Versuche/manuelle Recovery, beschädigte Originalbelege, inkohärente fremde OU-Parents und begrenzte parallele App-Anmeldungen |
| Native PostgreSQL, vollständige Identity-Suite | **710/710** im abschliessenden vollständigen Lauf; enthält die 14 obigen Automationsfälle. Der gezielte gemeinsame Lauf von 102 Quell-/Registrierungs-/Creation-/Automationsfällen bestand ebenfalls; Wiederholungen sind keine zusätzliche Abdeckung |
| Lokaler Produktionsbrowser | **1/1**, echter Chrome mit frisch gebautem `next start`, realer OAuth-/Identity-/PostgreSQL-Verbindung und tatsächlichem CLI-Prozess; App-Erstellung, Enrollment, roleless Owner mit MFA, explizite Freigabe, eigener CSV-Download, Historie und Widerruf mit wartendem Jobabbruch |
| TypeScript / Next-Produktionsbuild | Bestanden; zusätzlich baut die Browserumgebung ihren eigenen Produktionsserver |

Der Browserlauf entdeckte einen CLI-Formatfehler: Nach JSON-Zeilen gab der Worker seine Abschlussmeldung eingerückt aus. Beide Ausgaben sind jetzt JSON-Zeilen; ein eigenständiger tatsächlicher CLI-Prozess prüft auch den Fehler-Exit. Zwei frühere Browserfehler betrafen die neue Fixture: Ersteinrichtung für ein Konto ohne verpflichtende MFA und die nicht vorhandene Playwright-Response-Methode `clone`. Die endgültige Definition verwendet die tatsächlich vorgesehenen Anmeldewege und prüft echte Antworten. Die visuelle Prüfung korrigierte ausserdem die schlecht lesbaren hellen Formfelder auf die vorhandenen Designvariablen.

Die volle native Regression deckte zusätzlich eine Wechselwirkung des neuen globalen Fences mit eingeschränkten SQL-Logins auf. Der Fence liest seine private Historie jetzt wie die vorhandenen Fences als Definer mit festem Schema/UTC; PUBLIC-Ausführung ist entzogen, ursprüngliche Session-/Owner-Prüfungen bleiben erhalten. Die bestehende Quellen-Fixture erwartet nun 48 Migrationen. Der lokale Wegwerf-Cluster verwendet `max_locks_per_transaction=256`, nachdem paralleler Schema-Cleanup sein zuvor reduziertes Lock-Budget erschöpfte; dies verändert keine externe Datenbankkonfiguration.

Lokale Nachweise: `/tmp/od-automation-identity-final.log`, `/tmp/od-automation-oauth-final.log`, `/tmp/od-automation-cli-final.log`, `/tmp/od-automation-web-tests.log`, `/tmp/od-automation-gateway-tests.log`, `/tmp/od-automation-openapi-final.log`, `/tmp/od-company-automation-pg-final.log`, `/tmp/od-automation-pg-receivers-final.log`, `/tmp/od-automation-identity-pg-all-final.log` und `/tmp/od-company-automation-browser.log`. Browserbilder: `/tmp/od-company-automation-export.png` und `/tmp/od-company-automation-browser.png`; keine Produktivdaten oder Secrets.

Offen bleiben insbesondere unbeaufsichtigter Firmenlizenzabgleich, tenantgebundene eigene App-Registerverwaltung, Mail-/Apple-/andere Provider-Schreibhandler, Artefakt-Retention und vollständige Betriebs-/Last-/Restore-/WCAG-Abnahme. Die allgemeine bestehende Blueprint-Offboarding-Browserlücke wird durch den neuen Automationsbrowser nicht geschlossen. Vollständige BRs und der [Gesamtauftrag](../implementation-worklist.md) bleiben offen; kein produktiver Rollout oder externer Mail-/Lizenzkauf fand statt.

## 23. Oktober 2026 — Automatischer Lizenzgruppenabgleich

Der [neue maschinelle Ablauf](../features/company-license-automation.md) erweitert die bestehende App-Freigabe um `licenses.groups.reconcile`. Der originale aktuelle App-Bearer bleibt durch OAuth → Identity → Policy → kanonische Gruppe/Eligibility erhalten. Es werden weder ein menschlicher Actor noch MFA-Claims hergestellt. Identity 049 und Policy 029 ergänzen feste Lizenzziele, wiederaufnehmbaren Fortschritt, echte Teilresultate und unveränderliche Seiten-/Pending-Belege über dem bestehenden Allocator.

| Gate | Tatsächlich geprüftes Ergebnis |
| --- | --- |
| Identity Jest | 60 Suiten, 1'191 Tests bestanden |
| Policy Jest | 39 Suiten, 1'327 Tests bestanden |
| OAuth Jest | 19 Suiten, 477 Tests bestanden |
| CLI | 25 Tests bestanden; tatsächliche Prozesse für `license-sync`, Teilresultat-Exit 2 und verweigerte falsche Erfolgsmeldungen |
| Betroffene Frontend-Verträge/Views | 7 Suiten, 419 Tests bestanden |
| Frontend TypeScript | `tsc --noEmit` bestanden |
| Vollständige native Identity-Regression | 712 Tests bestanden; zusätzlich neuer tatsächlich verstrichener Minutenintervall-Test für Fortsetzung statt doppelter Zeitplanjobs bestanden |
| Vollständige native Policy-Regression | 550 Tests bestanden; anschliessend 30 gezielte Gruppen-/Lifecycle-Fälle inklusive neuer physischer App-Journaldeadline, fehlendem Receiver und tatsächlicher App-Poolhistorie bestanden |
| Echter Chrome / frischer Produktionsbuild | 2 Tests bestanden: bestehender Export-/Widerrufablauf und neuer regulärer Lizenzzeitplan über die tatsächlichen Services |
| OpenAPI | Version 1.22.0 stimmt exakt mit dem generierten Dokument überein; Referenzen/Operationen sind durch die Vertragsregression geprüft |

Der neue Browserfall erzeugt eine tatsächlich aktivierte Firma samt rollenlosem Owner in Wegwerf-PostgreSQL, meldet eine echte OAuth-App über die ausgelieferte CLI an und genehmigt in der Oberfläche ausschliesslich die Lizenzaktion. Eigene Gruppe, Membership, endlicher Pool und Verknüpfung entstehen über echte HTTP-APIs. Die Oberfläche legt den tatsächlichen 60-Sekunden-Zeitplan an. Der laufende CLI-Prozess weist mit eigenen Client-Credentials den Sitz zu, danach wird die kanonische Membership mit dem ursprünglichen Eigentümertoken entfernt. Nach dem tatsächlich verstrichenen nächsten Intervall bestätigt der zweite Job den Gruppenquellenentzug und `used_seats=0`. Beide SHA-geprüften Berichte nennen die wirkliche App. Anschliessend stoppt die Oberfläche den tatsächlichen Zeitplan. Der Worker protokolliert keine menschliche Principal-ID, kein Client-Secret und keinen Eigentümertoken. Die ergänzenden Bilder wurden visuell geprüft.

Native Fälle beweisen einen 27-Ziele-Lauf über mehrere Worker-Instanzen, einmalige Seat-Belegung trotz verlorener Page-Antwort, volle Pools mit echtem `partial`, erneute Verwendung eines zurückgegebenen Sitzes, erhaltene historische Retry-Epochen, Tenant-/Lease-/Generation-Grenzen, unveränderte menschliche Pfade sowie Ablehnung korrupter Outbox und fehlender Guards. Der abgelaufene Journal-Commit hinterlässt weder Zyklus noch Pending-Receipt. Eigene Poolhistorie zeigt die tatsächliche App mit `actorUserId:null`; der alte direkte Assignment-Pfad bleibt für Source-aware-Pools gesperrt.

Die tatsächliche Servicekette entdeckte zwei Integrationsfehler, die isolierte Allocator-Tests nicht zeigen: Die generelle Policy-Anmeldung blockierte zunächst auch den neuen engen App-Endpunkt; nun akzeptiert nur dessen exakte POST-Route den eigenen festen Workload-Vertrag. Ausserdem verglich ein Gruppenbeleg Zeitstempel als zeitzonenabhängigen JSON-Text. Die unveränderten Originalzeitpunkte werden jetzt typisiert verglichen; keine Historie wird umgeschrieben. Ein weiterer gezielter Test deckte auf, dass die alte reine Direct-Source-Sperre auch die bereits source-aware lesbare Poolhistorie blockierte. Nur der historische Leseweg ist freigegeben; tatsächliche Einzelzuweisung/Entzug behalten ihre getrennten Quellenprüfungen.

Die volle Policy-Regression fand einen bestehenden Test-Fixture-Fehler: Nach temporär verkürzter Authority wurde die Deadline auf die neue Uhrzeit plus 300 gesetzt und konnte damit die originale MFA-Grenze um eine Sekunde überschreiten. Die Fixture stellt jetzt genau die ursprüngliche Grenze `min(exp,auth_time+300)` wieder her; die produktive Prüfung bleibt streng. Ein einmaliger `socket hang up` in einer unveränderten Preview-Routenprüfung trat beim abschliessenden erneuten vollständigen Policy-Lauf nicht mehr auf. Der frische Next-Produktionsbuild beendete sich mit Code 0; die bestehende Next-Lockfile-Patchwarnung bleibt im Log. Rollenlose Owner erhalten durch den Test keine zusätzliche Inventarberechtigung.

Lokale Logs: `/tmp/od-license-automation-identity-all.log`, `/tmp/od-license-automation-policy-all.log`, `/tmp/od-license-automation-oauth-all.log`, `/tmp/od-license-automation-cli.log`, `/tmp/od-license-automation-ui.log`, `/tmp/od-license-automation-types.log`, `/tmp/od-license-automation-identity-pg-all.log`, `/tmp/od-license-automation-coalescing.log`, `/tmp/od-license-automation-policy-pg-all.log`, `/tmp/od-license-automation-policy-history-final.log` und `/tmp/od-license-automation-browser.log`. Visuell geprüfte Browserbilder: `/tmp/od-company-license-automation-assigned.png` und `/tmp/od-company-license-automation-returned.png`.

Dies bestätigt lokale Gruppen-/Poolwirkung, keine Herstellerfreischaltung, Mailbereitstellung, Apple-Verbindung oder produktive Installation. Tenantgebundene App-Registerverwaltung, dynamische/verschachtelte Gruppen, externe Änderungsereignisse und die übrigen BR-/WF-/Betriebsanforderungen bleiben gemäss [vollständigem Auftrag](../implementation-worklist.md) offen. Der bestehende allgemeine Blueprint-Offboarding-Browserfehler wird hierdurch nicht als behoben erklärt.
