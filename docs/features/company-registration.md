# Firmenregistrierung zur Prüfung: implementierter Teilprozess

Stand: 19. Oktober 2026. `/register` ist ein echtes öffentliches Formular mit nativen BFF-Routen, bestehendem Credential-Provider, tatsächlichem Issuer-Workload-Proof und PostgreSQL. Der Teilprozess legt **genau einen neuen gesperrten Tenant und einen neuen gesperrten kanonischen Erstadministrator-Kandidaten** samt Eigentümerschaft, Subject-Link, Registrierungsentwurf und verpflichtender Historie/Pending-Outbox an.

**Kein vollständiger WF-001:** Die [interne Firmenprüfung](company-registration-reviews.md) kann freigeben oder ablehnen, aktiviert selbst aber keine Konten. Der anschliessende [eigene Aktivierungs-/Pflicht-MFA-Prozess](company-activation.md) ermöglicht dem ursprünglichen Antragsteller jetzt den begrenzten Owner-Zugang zum eigenen Profil und dessen Delegationen. Eine globale `admin`-Rolle oder bereits vollständige eigene Company-Administration wird nicht vergeben. Ein vorhandenes Passwortkonto beim konfigurierten Credential-Provider ist weiterhin erforderlich; dieses Formular erstellt kein neues Passwortkonto und bestätigt keine E-Mail oder Firma.

## Einschalten und Benutzerweg

Der Prozess ist standardmässig ausgeschaltet: `COMPANY_REGISTRATION_ENABLED=false`. Nur beim OAuth-Provider auf `true` setzen. Beide Compose-Varianten und `.env.example` erhalten den sicheren Default. Der aktuelle tatsächliche Availability-Receiver steuert die Oberfläche; ohne aktivierten Dienst gibt es keine dekorative Submit-Aktion. Im Revocation-Demo-Modus ist der Prozess auch bei gesetztem Flag nicht verfügbar.

1. Von `/login` **Unternehmen zur Prüfung anmelden** öffnen.
2. Die erzeugte Registrierungs-UUID aufbewahren. Sie ist ein Idempotency-/Recovery-Schlüssel, kein Zugriffstoken. Für einen späteren Browser kann sie auch bewusst wieder eingegeben werden.
3. Bestehenden Benutzernamen, aktuelles Provider-Passwort und nötigenfalls den dort geforderten MFA-Code eingeben. Unternehmensdaten in denselben 14 validierten Feldern wie im bestehenden Firmenprofil erfassen.
4. Die ausdrückliche Vormerkung zur Prüfung bestätigen und absenden.
5. Erst ein tatsächlicher gespeicherter und überprüfter Receiver-Beleg zeigt **Zur Prüfung vorgemerkt** mit Tenant-/Kandidaten-ID. Die Anzeige behauptet weder Aktivierung noch einen Login oder ein gespeichertes produktives Firmenprofil.
6. Bei verlorener Bestätigung oder nach Neuladen Zugangsdaten erneut eingeben und **Bestehenden Status prüfen** wählen. Diese separate Anfrage liest den eigenen Zustand und sendet keinen zweiten Create-Befehl.

Die Anwendung legt nur die Registrierungs-UUID im Tab-Sitzungsspeicher ab, nie Passwort, MFA-Code oder Unternehmensdaten. Nach jedem Submit-/Statusversuch werden Passwort und MFA-Code aus dem Formular entfernt. Es gibt keinen automatischen Write-Retry. Der Entwurf ist unveränderlicher Workflow-Input, nicht ein zweites aktives Organisationsprofil oder ein Browser-only-Objekt.

## Tatsächliche Autorisierungsgrenze

- Der BFF akzeptiert für Schreib-/Credential-Anfragen nur den konfigurierten Origin, JSON, die eigene `X-OD-Company-Registration: 1`-Absicht und zulässigen Fetch-Site-Kontext. Browser-Cookies, bisherige Bearer und OAuth-Client-Secrets werden nicht zum Issuer weitergeleitet. Der vorhandene BrowserAuth-Transport/HTTPS-/URL-Vertrag wird wiederverwendet.
- Nur der konfigurierte Credential-Provider überprüft das eingegebene Passwort. Sein bestätigter Subject-Identifier und seine tatsächlichen Principal-Felder werden verwendet; seine Rollen-/Permission-Behauptungen werden **nicht** als kanonische Verwaltungsrechte übernommen. Fehlen benötigte Principal-Metadaten, gibt es keinen erfundenen Fallback-Account.
- Nach erfolgreicher Credential-Prüfung signiert der vorhandene Issuer einen separaten RS256-Workload mit eigener Audience/Type/Purpose, fester POST-URL, Digest des normalisierten Inhalts, gebundenem Credential-Subject, Nonce und höchstens 30 Sekunden Laufzeit. Der Proof ist kein normaler Access-Token und wird nie an den Browser ausgegeben. Das Passwort erreicht den Identity-Receiver nicht.
- Der private Receiver akzeptiert ausschliesslich diesen tatsächlich verifizierten Workload. Normale Human-/API-Tokens, falscher Zweck/Type/Pfad/Methode/Subject/Digest und zusätzliche Claims können keine Registrierung autorisieren. Öffentliche Anfragen sind zusätzlich begrenzt; 429 ist eine tatsächliche JSON-Denial-Antwort.
- Die kanonische Transaktion erlaubt nur **neue deaktivierte** Ressourcen. Bekannte gebundene oder ungebundene Legacy-Subjects werden nicht adoptiert oder umgehängt. Keine bestehende Organisation, Person oder Rolle kann durch frei gewählte Felder aktiviert werden.
- Die neue Admission ist getrennt von der bisherigen expliziten Offline-Owner-Prüfung. Sie gibt nur den exakten neuen Tenant und Kandidaten frei; sie behauptet keine menschliche Offline-Freigabe. Die alte Review-Grenze für normale Owner-/Limited-Login-/SET-ROLE-Aufrufe bleibt bestehen.
- Der ursprüngliche Proof muss bis zum tatsächlichen SQL-Commit gültig bleiben. Ein abgelaufener Proof, fehlende vorgeschriebene Belege oder spätere fremde kanonische Effekte rollen Tenant, Kandidat und alle neuen Ereignisse gemeinsam zurück. Ein gelöschter GUC verbirgt den tatsächlichen laufenden Registrierungseintrag nicht.

Wie die bestehenden Receiver benötigt auch dieser private SQL-Pfad noch den tatsächlichen Datenbank-Owner. Ein eingeschränkter Login erhält durch einen Definer-Execute-Grant oder `SET ROLE` keine Owner-Autorität. Das ist trotzdem kein fertiggestelltes Least-Privilege-DB-Rollenmodell oder eine Freigabe für allgemeines Shared-Customer-SaaS-Hosting.

## Idempotenz und Belege

Migration `039_company_registrations.sql` ergänzt drei Tabellen:

- `identity_company_registrations`: unveränderlicher Request-Key, neue Tenant-/User-UUIDs mit deferred FKs, bestätigter Credential-Subject, Principal-Spalten, normalisierter Profilentwurf, SQL-Inhaltsdigest, ursprüngliche Proof-Nonce/Zeiten/Digest und Transaktion.
- `identity_company_registration_events`: eigenes Ereignis, Typ `company.registration.requested`, Version 1, Tenant-ID, Zeitpunkt, Correlation-ID und exakte tatsächliche kanonische Snapshots.
- `identity_company_registration_outbox`: verpflichtender übereinstimmender Pending-Beleg im selben Commit; `pending` bedeutet nicht zugestellt.

Kanonische Tenant-/Ownership-/Subject-/User-/Autorisierungs-/Record-Audits werden durch die vorhandenen echten Trigger erzeugt und geprüft. Eine plausible Root-UUID oder ein Snapshot mit fehlender tatsächlicher kanonischer Evidenz genügt nicht. Das produktive `identity_organization_profiles`-Objekt bleibt in dieser Phase ausdrücklich noch ungefüllt; der 14-Feld-Entwurf ist gespeicherter Workflow-Input.

Der Request-Key ist an Issuer, Credential-Subject und exakten normalisierten Inhalt gebunden. Wiederholung desselben Auftrags gibt den retained Zustand zurück. Abweichender Inhalt, ein anderer Subject oder ein zweiter Request-Key für denselben bereits gebundenen Subject ergeben 409 statt eines zweiten Tenants. Tatsächliche Advisory-Locks serialisieren konkurrierende Anfragen. Status kann nur die erneut credentialbestätigte Person lesen; fremde bekannte UUIDs verleihen keinen Zugriff.

Eine später unabhängig geänderte kanonische Tenant-/User-/Ereignis-/Outbox-Zeile wird nicht als noch passender ursprünglicher Pending-Zustand ausgegeben oder durch Retry still repariert. Migration 040 speichert die interne Prüfentscheidung als eigene überprüfbare Transition. Migration 041 führt die anschliessende ausdrücklich eigene Aktivierung mit eigenständigen unveränderlichen Belegen aus; die interne Freigabe aktiviert nicht heimlich einen gespeicherten Antrag. Spätere berechtigte Profiländerungen ersetzen keine historischen Aktivierungsbelege.

## Erreichbare APIs

| Schicht | Methode / Pfad | Tatsächliche Wirkung |
| --- | --- | --- |
| Browser BFF | `GET /api/company-registration` | Tatsächlicher Betreiber-Flag und Pending-only-Protokoll |
| Browser BFF | `POST /api/company-registration/submit` | Eigene Provider-Credentials, Request-Key, Profil und ausdrückliche Vormerkung |
| Browser BFF | `POST /api/company-registration/status` | Separate eigene Statusabfrage nach erneuter Credential-Prüfung |
| Issuer | `GET /oauth/company-registration` | Tatsächliche Capability-Metadaten |
| Issuer | `POST /oauth/company-registration/{submit|status}` | Credential-Prüfung und kurzlebiger gebundener Workload zum Identity-Service |
| Privat | `POST /internal/identity/company-registrations/{submit|status}` | Exakter signierter Issuer-Workload, kein normaler API-Bearer |

Die beiden nativen BFF-POST-Routen sind absichtlich statisch, damit die vorhandenen generischen API-Rewrites sie nicht abfangen. Der generierte [OpenAPI-3.1-Vertrag](../api/openapi.yaml) beschreibt anonyme Credentials und privaten Workload als unterschiedliche Security-Grenzen. Standardantworten sind `no-store`; Password/MFA-Felder sind nur Write-Input, nie Response oder Audit-Inhalt.

## Verifiziert und noch offen

[SQL-, signierte HTTP-, BFF- und Browser-Nachweise](../testing/test-results.md#business-slice-4-firmenregistrierung) prüfen insbesondere reale Konkurrenz, Idempotenz, Proof-Expiry bis Commit, Ursprung/Body/Purpose, alte SQL-Owner-Grenzen, tatsächliche Fehl-/Teilbelege, keine Rollenübernahme, deaktivierte Ressourcen und echte Status-Recovery. Tests nutzen ausdrücklich isolierte Credential-Fixtures; keine fremden produktiven Firmen, Konten oder Apple-Systeme wurden beschrieben.

Noch erforderlich für das volle WF-001: Account-Self-Signup bzw. geeigneter föderierter Credential-Onboarding-Pfad, externe Unternehmens-/Domain-Prüfung und vollständige eigene Company-Administration über Profil-/Delegationsrechte hinaus. Die [technische Aktivierung mit eigener Console und Pflicht-MFA-/Owner-Profilanmeldung](company-activation.md) ist ein separater Teilprozess, keine globale Adminvergabe oder vollständige Plattformabnahme. Weiterhin offen sind Audit-Retention/Datenschutz-Löschprozesse, Outbox-Delivery/Retry/DLQ, Last-/Backup-/Restore- und Produktionsabnahme.
