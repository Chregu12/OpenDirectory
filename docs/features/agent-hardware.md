# Tatsächliche System- und Hardwaremeldungen

Version 1.0.46 ergänzt die [Geräteverbindung](device-agents.md) um Systemdaten des Rust-Agenten ab Version 1.2.0. Unter `/devices` ein Gerät öffnen: **System und Hardware** zeigt CPU-Modell und logische Prozessoren, gesamten/verfügbaren Arbeitsspeicher, gesamten/verfügbaren Platz des Systemdatenträgers und die Laufzeit seit dem Start. Fehlende Messungen sind **Unbekannt**. Die manuell gepflegten Inventarwerte und Benutzerzuweisungen bleiben eigenständige Daten.

## Erfassung und Betrieb

Der Agent benötigt Rust ab 1.95 und verwendet [sysinfo 0.40.3](https://docs.rs/sysinfo/latest/sysinfo/) mit den Features `system` und `disk`. Er liest die genannten Werte lokal, ohne Prozesse, Dateien, persönliche Datenträgerpfade oder Zugangsdaten zu übertragen. Der Systemdatenträger wird am tatsächlichen System-Mount ausgewählt; ein fehlender Treffer wird nicht durch einen beliebigen anderen Datenträger ersetzt. Bytezähler werden als exakte Dezimalstrings übertragen und gespeichert. Eine erfolglose Abfrage erzeugt `null`, keinen erfundenen Nullbestand.

```sh
cargo build --locked --release --manifest-path agent-rust/Cargo.toml
od-agent-service inventory
od-agent-service heartbeat
od-agent-service run
```

`inventory` zeigt die lokalen Messwerte. `heartbeat` benötigt die vorhandene geschützte Agent-Konfiguration und sendet genau eine echte Meldung; `run` meldet regelmäßig. Die [Registrierung und CA-Konfiguration](device-agents.md) bleiben unverändert. Agent 1.2 benötigt Server ab 1.0.46; Agent 1.3 mit Sicherheitsmeldung benötigt Server ab 1.0.47. Bisherige Agenten können weiterhin Heartbeats ohne Systemdaten senden. Ein solcher Heartbeat erneuert keine früheren Hardwaremessungen.

## Quelle, Alter und Historie

Jede Hardwaremeldung erhält den tatsächlichen Server-Eingangszeitpunkt, die exakte Agent-Revision, ursprüngliche Registrierungszeit, Plattform und Agent-Version. Die Oberfläche unterscheidet:

- **Keine Systemdaten**: bisher keine Meldung vorhanden.
- **Aktuelle Meldung**: dieselbe aktive registrierte Verbindung, online und höchstens fünf Minuten alte Hardwaremessung.
- **Ältere Meldung**: dieselbe aktive Verbindung, aber offline oder ältere Hardwaremessung.
- **Frühere Geräteverbindung**: Zugang widerrufen/abgelaufen, Registrierung ersetzt oder Plattform geändert. Der alte Bericht bleibt erhalten; eine neue Verbindung übernimmt ihn nicht als eigene Messung.

Der Vergleich der Registrierung erfolgt in PostgreSQL mit voller Zeitpräzision. Die Verbindung wird alle 30 Sekunden geprüft; ihre neue Antwort aktualisiert auch den Hardwareabschnitt. Der sichtbare Prüfzeitpunkt bezeichnet den jeweiligen Server-Snapshot. Die Werte sind Geräteangaben und keine Hardware-Attestierung oder Compliance-Freigabe.

## API, Persistenz und Berechtigung

`POST /api/device-agent/heartbeat` akzeptiert weiterhin genau `deviceId` und `report`, optional ergänzt um `inventory: { schemaVersion:1, cpu, memory, systemDisk, uptimeSeconds }`. Kategorien sind nullable. Eine Kapazität enthält genau `totalBytes` und `availableBytes`, jeweils kanonische Dezimalstrings bis `9223372036854775807`; der Gesamtwert muss positiv und der verfügbare Wert höchstens so groß sein. CPU-Zahlen sind ganze Werte zwischen 1 und 65536. Caller-Zeitstempel, Tenant-/Benutzerfelder und weitere Schlüssel werden abgewiesen.

Migration `009_agent_inventory.sql` ergänzt `device_agent_connections.inventory_report`. Bestehende Verbindungsdaten bleiben erhalten. Dieselben Geräte-Locks, gehashten Gerätecredentials, Ablaufgrenzen, ursprünglichen Proof-/Row-Guards und die erweiterte Deferred-Commit-Prüfung verbinden Heartbeat und Hardwarebericht atomar. Ein verlorener oder ersetzter Bericht darf keinen erfolgreichen Commit vortäuschen. Der strukturierte SQL-Check wird bei Annahme, Lesen und physischem Commit geprüft. Heartbeats erzeugen weiterhin keine Auditzeile je Minute; Ausgabe, Registrierung und Widerruf behalten die bestehende Kontrollhistorie einschließlich geheimnisfreier Zustände.

`GET /api/devices/{id}/agent/inventory` verlangt den ursprünglichen menschlichen Bearer mit aktueller eigener Inventarberechtigung und unveränderter Pflicht-MFA-Frische. Ein Gerätecredential öffnet diesen Leseweg nicht. Der eigene Tenant und Actor kommen aus der tatsächlichen Identity-Hoheit. Zusätzliche Query-Selektoren sind verboten. Quelle und Autorisierung werden vor und nach dem konsistenten Read geprüft; Antworten sind `no-store`. Der [OpenAPI-Vertrag](../api/openapi.yaml) enthält Bericht, Heartbeat und die separate Gerätecredential-Authentifizierung.

## Abnahme und offene Anforderungen

[Liefer- und Prüfnachweis](../deployment/agent-hardware-2026-11-14.json): lokale reale macOS-Messung, tatsächlicher kompilierter Rust-HTTP-Prozess, native PostgreSQL-Prüfungen einschließlich Präzision/Widerruf/Schema-Replay/physischer Drift, ursprünglicher signierter OAuth-/PIM-/Gateway-Weg und Desktop-/Mobil-Browserabläufe. Es werden dafür keine persönlichen produktiven Grants, Geräte oder MFA-Nachweise erzeugt.

Seit 1.0.47 ergänzen [eigene Compliance-Regeln und tatsächliche Sicherheitsmeldungen](device-compliance.md) diesen Hardwareweg. Agent 1.5.0 liefert [fünf native Pakete und tatsächliche VM-Dienst-/Hardwareprüfungen](agent-installation.md). Physische Zielgeräte, Betriebssystemsignierung, sichere weitere Fernbefehle, App-Verteilung und Hersteller-MDM bleiben offen. Der Datenbankbetreiber und der nicht attestierte Geräteagent bleiben bestehende Vertrauensgrenzen. Diese Erweiterung ist eine Grundlage für weitere Geräte-/Compliance-Abläufe; BR-003 und der Gesamtauftrag bleiben offen.
