# Geräteübersicht mit tatsächlichem Verbindungsstatus

Version 1.0.45 ergänzt `/devices` um die Betriebsübersicht für das vorhandene [Geräteinventar](device-inventory.md) und die [Rust-Agent-Verbindung](device-agents.md). Erfassen, Stammdaten bearbeiten, Personen zuweisen, Wartung, Archivierung, Wiederbereitstellung, Registrierung und Widerruf verwenden weiterhin die vorhandenen persistenten, protokollierten Befehle.

## Bedienung

- Die Übersicht zeigt Geräte gesamt, Online, Offline und ausstehende Registrierungen. Die Zahlen berücksichtigen die aktuelle Suche sowie Plattform-, Inventarstatus- und Eigentumsfilter. Der zusätzliche **Verbindungsfilter** schränkt die Liste und den Export ein; die Übersicht behält den Vergleich über alle Verbindungszustände bei.
- Alle sechs Zustände sind filterbar: nicht verbunden, Registrierung ausstehend, online, offline, Zugang abgelaufen und Zugang widerrufen.
- In der Liste stehen tatsächlicher Hostname, letzter Kontakt und Agentversion. Fehlende Meldungen werden als **Noch kein Kontakt** angezeigt. Ein Kontakt innerhalb von drei Minuten zählt bei gültigem Gerätecredential als online. Eine abgelaufene oder widerrufene Verbindung wird dadurch nicht wieder aktiv.
- Liste und geöffnete Verbindung aktualisieren sich alle 30 Sekunden. Hintergrundtabs werden nicht abgefragt; offene Änderungen, Bestätigungen und sichtbare Registrierungscodes unterbrechen die jeweilige automatische Aktualisierung. Schreibbefehle werden niemals automatisch wiederholt.
- **CSV exportieren** exportiert die vollständige aktuelle Filterauswahl einschließlich Verbindungsstatus, letztem Kontakt, Hostname und Agentversion. Maximal 5000 Geräte; Tabellenformeln werden entschärft.
- Nach einer erlaubten Plattformkorrektur bleibt der Bericht einer alten, widerrufenen Verbindung als historische Meldung lesbar. Ein aktiver Agent muss weiterhin zur tatsächlichen Inventarplattform passen.

## Quelle und API

`GET /api/devices/fleet` und `GET /api/devices/fleet/export` prüfen denselben ursprünglichen menschlichen Bearer, die tatsächlichen eigenen Inventarrechte und die unveränderte MFA-Frischegrenze wie die vorhandenen Geräteoperationen. Ein Gerätecredential öffnet keine menschliche Inventar-API. Fremde Tenant-Selektoren und zusätzliche Felder sind unzulässig. Antworten sind `no-store`.

Inventar, exklusive aktuelle Benutzerzuweisung, Agent-Verbindung, Seitengrenzen und Counts kommen aus einem PostgreSQL-Repeatable-Read-Snapshot. Eine anschließend gelesene Datenbankzeit bestimmt den gemeinsamen Online-/Ablaufgrenzwert. Dadurch bleibt auch ein unmittelbar vor Snapshot-Erwerb eingegangener Heartbeat gültige Evidenz. Die ursprüngliche Identity-Hoheit wird vor dem Read und nach Abschluss erneut geprüft.

Die JSON-Antwort enthält die bisherigen Inventarzeilen und zusätzlich `fleet: { protocol: 1, tenantId, checkedAt, counts, connections }`. `connections` steht in derselben Reihenfolge wie die Geräte und enthält keine Codes, Credentials oder deren Hashes. `page` und `limit` gelten nur für JSON; beim Export sind sie verboten. `connectionStatus` ergänzt die bestehenden exakt validierten Inventarfilter. Der [generierte OpenAPI-Vertrag](../api/openapi.yaml) dokumentiert beide Endpunkte.

Es werden keine Inventarrevisionen, Zuweisungen oder Compliance-Werte aus Heartbeats abgeleitet. Diese Lieferung benötigt keine Datenbankmigration. Der neue Device-Service kann vor der Oberfläche ausgerollt werden; alte Inventar-Clients bleiben kompatibel.

Version 1.0.45 ergänzt außerdem die fehlenden Web-Weiterleitungen für Flottenexport und Lebenszyklus-Aktionen. Ihre echten HTTP-Wege durch das gebaute Next.js-Image werden mit Methode, Query, Body und Versionsheader geprüft.

## Prüfung und verbleibende Grenzen

Die Abnahme enthält reale PostgreSQL-Operationen, einen tatsächlich kompilierten macOS-Rust-Agenten, signierte Original-OAuth-/MFA-/PIM-Aufrufe durch den Produktions-Gateway-Code sowie Browserprüfungen gegen das gebaute Produktionsimage. Produktive persönliche MFA-/PIM-Vergaben werden dafür nicht erzeugt. Der [Rolloutnachweis](../deployment/device-fleet-2026-11-14.json) hält Artefakte, Datenbestand und öffentliche TLS-/Zugriffsprüfungen fest.

Vollständiges MDM, sichere Remote-Befehle, Compliance-Auswertung, Softwareverteilung, Intune/Apple/Android-Provider, signierte Installer und Windows-/Linux-Hardware-/Autostart-Abnahmen sind weiterhin offen. Eine Gerätezeile allein beweist keine dieser Wirkungen.
