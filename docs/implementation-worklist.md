# Vollständiger Umsetzungsauftrag

Auftrag vom 22. Oktober 2026: sämtliche in der Bestandsaufnahme genannten fehlenden Funktionen umsetzen. Grundlage sind zusätzlich die unveränderten BR-001–012 und WF-001–005 in `business/business-requirements.md`. Die Reihenfolge verkleinert den Auftrag nicht. Der Gesamtauftrag bleibt offen, bis Code, erreichbare APIs, Berechtigung, Oberfläche, Fehler-/Recovery-Verhalten, Tests und Dokumentation für alle Punkte nachgewiesen sind.

| Bereich | Verbindlicher Restumfang | Stand |
| --- | --- | --- |
| App-Automation | Eigene widerrufbare App-Schreibdelegation; persistente Jobs, Zeitplanung, Wiederholungen, Dead Letter und Historie; Lizenzabgleich ohne offene Eigentümersitzung | Teil umgesetzt: eigene explizite App-Freigaben, persistente Export- und Lizenzgruppenjobs/-Zeitpläne, Worker-Leases, Backoff, fünf Versuche, wiederaufnehmbare Seiten, Teilresultate, Historie und UI/CLI. Offen: weitere Schreib-/Providerhandler und tenantgebundene App-Registerverwaltung |
| Gruppen/Lizenzen | Dynamische und verschachtelte Gruppen; externe Änderungsereignisse; automatischer Abgleich bei freiem Bestand; Quellen-/Kapazitäts-/Review-Regeln erhalten | Teil umgesetzt: normale Gruppen-/Pool-Verknüpfungen, manuelle UI-/Skript-Verwaltung und explizit delegierter zeitgesteuerter lokaler App-Abgleich. Dynamische/verschachtelte Gruppen und externe Änderungsereignisse offen |
| Mitarbeiteraufnahme | Einladungen, tatsächliche Zugangsdaten und erste Passwort-/MFA-Anmeldung; SCIM-Synchronisierung | Offen |
| Rollen | Eigene Firmenrollen, OU-Scopes, kontrollierte Delegation und Gruppenvererbung | Offen |
| Mail/Cloud | Ausgewählter Anbieter, Domainprüfung, Postfächer, Aliase, Kalender und Herstellerlizenzen mit tatsächlichem Providerstatus | Offen; Microsoft 365 als erster Adapter vorgesehen, Präferenz angefragt |
| Apple/Geräte | ABM/ASM-Vertrag, Enrollment, App-Verteilung und bestätigte zulässige Gerätebefehle | Offen; Live-Abnahme benötigt tatsächliche Anbieterzugänge/Geräte |
| Blueprints | Gruppen-/Geräte-/OU-Konfigurationsziele, tatsächliches Deployment und Drift | Offen |
| Eintritt/Austritt | Durchgängige dauerhafte Zustände für Identitäten, Sessions, Berechtigungen, Lizenzen, Geräte und externe Dienste | Teilprozesse vorhanden, Gesamtabnahme offen |
| Reporting | Echte Kosten-/Verbrauchs-/OU-Berichte und kontrollierte Exporte | Teil umgesetzt: tatsächliche eigene Benutzer-/Gruppen-/OU-Exporte als JSON/CSV. Kosten-, Verbrauchs- und kombinierte OU-Berichte offen |
| Standorte | Tenantgebundene CRUD-API, Öffnungszeiten/Ausnahmen, Medien, Freigaben und bestätigte Publikation | Offen |
| Marketing | Kampagnen, Inhalte, Prüfung, Zeitplanung, Provider-Aufträge und tatsächliche Ergebnisse/Metriken | Offen |
| Billing | Pläne/Entitlements, Kosten, Rechnungen, Planwechsel und geprüfter Zahlungsadapter | Offen |
| Support | Tickets mit Ressourcenbezug, Zuständigkeit, SLA, Eskalation, Anhängen und ITSM-Verbindung | Offen |
| Betriebsabnahme | Clean Install/Linux-Image, Migration/Restore, Last-/Ausfalltests, Datenschutz/Retention, WCAG und vollständige Browserabläufe | Offen |

Es werden keine globalen Rollen, menschlichen MFA-Nachweise oder fremden Tenant-Bindungen für Maschinen erfunden. Lokaler Commit, ausstehende Zustellung, angenommener Providerauftrag und bestätigte externe Wirkung bleiben unterscheidbar. Anbieterzugänge und physische Geräte ersetzen keine Implementierung; fehlende Live-Abnahmen werden als offen dokumentiert.
