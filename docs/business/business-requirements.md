# Business Requirements

Quelle: Apple-Business-Master-Prompt des Auftraggebers vom 19. Oktober 2026. Alle folgenden Bereiche bleiben Teil des Auftrags. Die Priorität bestimmt die Umsetzung, nicht den Ausschluss späterer Anforderungen.

| ID | Bereich und Ziel | Priorität | Anforderungsumfang |
| --- | --- | --- | --- |
| BR-001 | Mandanten, Organisationen, Rechtsträger, hierarchische Organisationseinheiten und kontrollierte Unternehmensverifizierung | P0 | FR-001.01–11 |
| BR-002 | Benutzer, Gruppen, granulare und benutzerdefinierte Rollen, OU-Scopes, MFA, OIDC, Entra-/Google-Adapter, SCIM und Joiner-Mover-Leaver | P0 | FR-002.01–15 |
| BR-003 | Geräteinventar, historisierte exklusive Zuweisungen, Enrollment und nur tatsächlich unterstützte Provider-Aktionen | P0 | FR-003.01–15 |
| BR-004 | Versionierte Blueprints mit Apps/Konfigurationen, Mehrfachzuweisungen, Konfliktauflösung, Vorschau, Rollback und Drift | P0 | FR-004.01–12 |
| BR-005 | Anwendungskatalog, Benutzer-/Gruppen-/Gerätezuweisung, Lizenz-Pools, Reservierung, Verbrauch, Freigabe, Kosten und Exporte | P1 | FR-005.01–12 |
| BR-006 | Unternehmensstandorte, Öffnungszeiten/Ausnahmen, Medien, Freigaben und separat bestätigte externe Publikationen | P1 | FR-006.01–10 |
| BR-007 | Standortbezogene Kampagnen, Inhalte, Freigaben, Terminierung, Provider-Veröffentlichung und quellenbezogene Metriken | P1 | FR-007.01–10 |
| BR-008 | Berechtigungsabhängige Dashboards, echte Kennzahlen, Tenant-/OU-/Standort-/Gruppen-/Zeitfilter, CSV-/PDF-Berichte | P1 | FR-008.01–10 |
| BR-009 | Free-/User-/Device-/Organization-/Feature-Pläne, Entitlements, Kosten, Rechnungen, Planwechsel, geprüfte Zahlungsadapter | P2 | FR-009.01–10 |
| BR-010 | Supportfälle mit Benutzern/Geräten/Standorten, Zuständigkeiten, SLA, Eskalation, Anhängen und ITSM-Adaptern | P2 | FR-010.01–10 |
| BR-011 | Domainverifizierung, Mail-/Kalender-/Verzeichnis-/Storage-Zuweisungen, Quotas und Freigaben über Provider | P2 | FR-011.01–10 |
| BR-012 | Versionierte APIs, OpenAPI 3.1, OAuth, Clients/Scopes, Webhooks, Events, Retry/DLQ, Rotation und Synchronisationskonflikte | P0 | FR-012.01–14 |

## Übergreifende Regeln

- Kein Mandantenadministrator liest oder verändert fremde Ressourcen; Platform-Operator-Zugriff ist eine getrennte, explizite Berechtigung.
- Keine OU-Zyklen; keine unkontrollierte Löschung abhängiger Organisationseinheiten.
- Mehrere Blueprint- oder Gruppenquellen erzeugen keine doppelte exklusive Lizenzallokation.
- Produktive Freigaben werden nicht still überschrieben. Änderung, Rollback, Entzug und Fehler behalten ihre Historie.
- Remote-Wipe/Lock und Zahlungen benötigen eigene Berechtigung, tatsächliche Provider-Unterstützung und explizite Bestätigung.
- Kein externer Erfolg aus einer lokalen Datenbankänderung; keine undokumentierten Apple-Endpunkte oder Scopes.
- Secrets/Tokens gehören nicht in Logs, Exporte oder API-Antworten. Uploads, personenbezogene Exporte und Löschungen benötigen eigene Kontrollen.

## Workflows

| ID | Prozess | Verbindlicher Verlauf |
| --- | --- | --- |
| WF-001 | Registrierung | Unternehmen → Tenant/Organisation → überprüfbarer erster Administrator → Profil → optionale Domainverifizierung → Aktivierung → Onboarding |
| WF-002 | Eintritt | Identität → OU/Funktion → Gruppen/Berechtigungen → Blueprints → Lizenzprüfung/-reservierung → Gerätezuweisung → unterstützte Provider-Aktionen → echter Aufgabenstatus |
| WF-003 | Gerätebereitstellung | Erfassen → validieren → zuweisen → Provider bestimmen → effektiven Blueprint berechnen → Bereitstellung → bestätigten Provider-Status speichern |
| WF-004 | Austritt | Anfordern → Benutzer sperren/Sessions widerrufen → Berechtigungen entziehen → Lizenzen freigeben → Geräte-Rückgabe → separat genehmigte Remote-Aktionen → Audit-Report |
| WF-005 | Kampagne | Inhalt/Standorte → Validierung → Freigabe → Terminierung → freigegebener Provider-Auftrag → tatsächliches Ergebnis → quellenspezifische Analytics |

Jeder Workflow braucht validierte Zustände, Verantwortliche, Historie und sichtbare Teilfehler. Wiederholungen dürfen keine zusätzliche Lizenz, Benutzeridentität, Zahlung oder externe Aktion erzeugen. Ein fehlgeschlagener Schritt darf nicht als erfolgreicher Gesamtprozess erscheinen.

Die Story [Rollen/PIM beim Austritt](../features/company-offboarding-access.md) ist ein begrenzter nächster Teil von BR-002/WF-004: Ein eigenständig berechtigter Bearbeiter kann tatsächliche eigene alte Grants nach dem originalen negativen Account-Checkpoint explizit entziehen und die realen kanonischen Belege lesen. Akzeptanz verlangt getrennte echte Lese-/Managementpflichten je Bereich, frische MFA, unveränderte Tenant-/Kontogeneration, geschützte Rollen ohne Owner-Admin-Abkürzung, vollständige Manifest-Vorprüfung, atomaren Child-Checkpoint/Audit/Pending-Beleg und sichtbare Teilfehler. Wiederaufnahme darf nur alte bestätigte IDs/Versionen wiederfinden, keine neuen Grants entfernen. Diese Story schliesst weder eigene Custom-Rollen/Scopes noch den gesamten Austritt ab.

Die Story [Geräterückgabe beim Austritt](../features/device-returns.md) verbindet BR-003/WF-004 mit tatsächlichen Inventarzuweisungen. Akzeptanz: Anforderungen nach echtem negativem Account-Checkpoint lassen die Zuweisung bestehen; nur eine separate manuelle Rückgabeentscheidung gibt genau die ursprüngliche noch aktive Beziehung über den bestehenden Kernel frei. Cancel verändert nur Aufgabenmetadaten. Normale Neuzuweisung wird als `assignment_changed`, nicht als Rückgabe erkannt. Client-Request-UUID, kombinierter Auftrags-/Geräte-ETag, ursprüngliche menschliche Inventarhoheit/MFA und echte atomare Device-Event-/Pending-Belege verhindern stille Wiederholung auf neue Beziehungen. Getrennte Identity- und Device-Hoheit erhalten keine fingierte gemeinsame SQL-Transaktion; keine Remoteaktion oder vollständiger Austritt entsteht daraus.

## Nichtfunktionale Abnahme

Zielwerte, keine gemessenen Zusagen: P95 normaler Lesezugriffe unter 500 ms, mindestens 1'000 Tenants, grosse Tenants mit 10'000 Benutzern, insgesamt 100'000 Geräte und 99,9 % Kernverfügbarkeit. Vor entsprechenden Aussagen sind Last-, Ausfall- und Wiederherstellungstests erforderlich. Server-Pagination, asynchrone Exporte/Jobs, Readiness, Monitoring, strukturierte Logs, Secrets und reproduzierbare Migrationen gehören zum Umfang.

Die UI benötigt deutsche/englische Texte, responsive Desktop-/Tablet-Bedienung, Tastaturzugriff, Dark Mode und WCAG 2.2 AA als Ziel. Navigation: Dashboard, Organisation, Personen/Gruppen, Geräte, Blueprints, Apps, Standorte, Marketing, Analytics, Abonnements, Support, Integrationen, Einstellungen. Keine sichtbare Aktion ohne funktionsfähigen, autorisierten Backend-Prozess.

## Definition of Done

Eine Capability ist erst fertig mit Datenmodell, Business Logic, erreichbarer/dokumentierter REST API, serverseitiger Autorisierung, integrierter Oberfläche, Erfolgs-/Fehlerbehandlung, erforderlichen Audit-Events, erfolgreichen automatisierten Tests, Dokumentation und lokal demonstrierbarem Workflow. Ein getesteter Helper, eine SQL-Basis oder ein Mockup allein erfüllt diese Definition nicht.
