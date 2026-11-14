# Geräte mit OpenDirectory verbinden

Ab Server 1.0.46 und Rust-Agent 1.2.0 erscheinen [tatsächliche CPU-, Speicher-, Datenträger- und Laufzeitmeldungen](agent-hardware.md) in den Gerätedetails. Ältere Agenten bleiben kompatibel.

Web 1.0.49 bietet [native Downloads und tatsächliche Systemdienst-Installation mit Agent 1.5.0](agent-installation.md). Linux x64/ARM64, macOS Intel/Apple Silicon und Windows x64 sind als Vorschau mit Prüfsummen und GitHub-Herkunftsnachweisen verfügbar; Betriebssystemsignaturen fehlen noch.

Die [Geräteübersicht ab 1.0.45](device-fleet.md) zeigt tatsächlichen Verbindungsstatus und Kontaktzeiten bereits in der Liste, mit Statusfilter, CSV-Export und automatischer Aktualisierung.

Unter `/devices` lassen sich Windows-, macOS- und Linux-Inventargeräte mit dem Rust-Agenten verbinden. Inventar und Agent-Verbindung haben getrennte Versionen: Ein Heartbeat verändert weder Stammdaten noch Benutzerzuweisungen. Dieser Weg liefert Registrierung und tatsächliche Kontaktmeldungen, kein vollständiges MDM.

## In der Oberfläche

1. Engineering in PIM aktivieren oder als tatsächlicher eigener Firmeninhaber/Administrator arbeiten. Die bestehende Inventarprüfung verlangt die ursprüngliche MFA innerhalb von fünf Minuten.
2. Ein verfügbares oder zugewiesenes Gerät öffnen. Plattform und Seriennummer vor Ort prüfen.
3. Unter **Geräteverbindung → Registrierungscode erstellen** eine Begründung eingeben und bestätigen. Der Code gilt zehn Minuten, genau einmal, und nur für dieses Inventargerät. Jeder neue Code sperrt den bisherigen Gerätezugang und alle älteren Codes sofort.
4. Den Agenten auf dem Zielgerät registrieren und starten. **Verbindungsstatus aktualisieren** liest den echten Serverstand. **Online** bedeutet einen erfolgreichen Kontakt innerhalb der letzten drei Minuten; danach wird **Offline** angezeigt. Das ist keine Compliance- oder Hardware-Attestierung.
5. **Gerätezugang widerrufen** sperrt Code und Gerätecredential. Für Plattformänderungen, Wartung oder Archivierung muss die Verbindung zuerst widerrufen werden. Personen können unabhängig davon zugewiesen oder freigegeben werden.

Der Registrierungscode wird ausschließlich in der erfolgreichen Antwort ausgegeben, nach fünf Minuten ausgeblendet und weder im Browser gespeichert noch in der Historie wieder angezeigt. Wird die Antwort verloren, den Status nachlesen und ausdrücklich einen neuen Code erstellen. Keine automatische Schreibwiederholung.

## Agent herunterladen und registrieren

Im Gerät **Agent herunterladen und einrichten** öffnen und das passende Paket des [Vorschaureleases 1.5.0](https://github.com/Chregu12/OpenDirectory/releases/tag/agent-v1.5.0) wählen. Archiv und Herkunft vor der Ausführung wie in der [Installationsanleitung](agent-installation.md) prüfen. Server/Gateway ab 1.0.48 verwenden. Linux-Pakete benötigen glibc ab 2.39 und OpenSSL 3.

Auf der jeweiligen Zielplattform mit installiertem Rust aus diesem Repository bauen:

```sh
cargo build --locked --release --manifest-path agent-rust/Cargo.toml
```

Die selbst gebaute Datei ist `agent-rust/target/release/od-agent-service`, unter Windows `od-agent-service.exe`. Die fünf nativen Release-Pakete werden auf den jeweiligen Plattformen gebaut und mit tatsächlichen VM-Dienststarts geprüft. Betriebssystemsignaturen und die Abnahme auf physischen Zielgeräten bleiben offen.

Auf macOS/Linux in einer Root-Shell den Code ohne Literal in der Shell-Historie eingeben, dann registrieren:

```sh
read -r -s OD_ENROLLMENT_TOKEN
export OD_ENROLLMENT_TOKEN
# Nur bei einer privaten CA, falls sie nicht im Systemvertrauen liegt:
export OD_CA_CERT=/absoluter/pfad/firmen-ca.pem
od-agent-service --server-url https://opendirectory.heusser.local enroll
unset OD_ENROLLMENT_TOKEN
od-agent-service install --dry-run
od-agent-service install
```

Die Standard-Konfiguration liegt unter macOS in `/Library/Application Support/OpenDirectory/agent.json`, unter Linux in `/etc/opendirectory/agent.json`; dafür können Administratorrechte erforderlich sein. Für einen Test als normaler Benutzer zuerst `OD_CONFIG_PATH` auf einen eigenen absoluten Pfad setzen. Unix-Dateien werden atomar mit Modus `0600` gespeichert. Der Bootstrap-Code wird nach erfolgreicher Registrierung aus der Konfiguration entfernt. `OD_CA_CERT` wird als Dateipfad gespeichert; die CA-Datei muss beim späteren Dienstbetrieb weiterhin lesbar sein. TLS-Prüfung und Weiterleitungsverbot bleiben aktiv; `OD_INSECURE` wird abgelehnt.

Windows: in einer administrativen PowerShell den Code über eine verdeckte Eingabe übernehmen:

```powershell
$enrollment = Read-Host 'Einmaliger Registrierungscode' -AsSecureString
$env:OD_ENROLLMENT_TOKEN = [System.Net.NetworkCredential]::new('', $enrollment).Password
$env:OD_CA_CERT = "$env:PROGRAMDATA\OpenDirectory\firmen-ca.pem" # falls erforderlich
.\od-agent-service.exe --server-url https://opendirectory.heusser.local enroll
Remove-Item Env:OD_ENROLLMENT_TOKEN
.\od-agent-service.exe install --dry-run
.\od-agent-service.exe install
```

Windows speichert standardmäßig unter `%PROGRAMDATA%\OpenDirectory\agent.json`; neue Credential-Dateien werden vor dem Schreiben mit `icacls` auf SYSTEM und lokale Administratoren begrenzt. Agent 1.5.0 richtet mit `install` die tatsächliche SYSTEM-Aufgabe beim Systemstart ein. Unter macOS/Linux startet er den tatsächlichen LaunchDaemon-/systemd-Dienst mit der gespeicherten Registrierung. Konfiguration und CA müssen dauerhaft geschützt bleiben; Windows verlangt beide unter `%PROGRAMDATA%\OpenDirectory`. `--config-path` verwendet denselben absoluten Pfad im Vordergrund und als Dienst. Abweichende bestehende Dienstdefinitionen werden ohne ausdrückliches `--replace-existing` abgelehnt. Details, Vorschau, Fehlerverhalten und Entfernung stehen in der [Installationsanleitung](agent-installation.md). `run` bleibt für den bewussten Vordergrundbetrieb verfügbar; `heartbeat` führt genau eine Meldung aus und beendet sich bei HTTP-Fehlern mit Fehlerstatus.

## API und Datenhoheit

- `GET /api/devices/:id/agent?page=1`: eigener Verbindungsstand und echte paginierte Kontrollhistorie, 25 Ereignisse je Seite.
- `POST /api/devices/:id/agent/issue` und `/revoke`: ursprünglicher menschlicher Bearer, Live-Inventarrecht `devices.inventory.create`, frische MFA, exakter `If-Match: "agent-UUID-Revision"`, `{reason, confirm:true}`. Ein noch nie verbundenes Gerät beginnt mit Revision `0`; fehlende Version `428`, überholte Version `412`.
- `POST /api/device-agent/register`: genau `{token, report}`; kein menschlicher Bearer, keine URL-Credentials, keine Tenant- oder Geräteauswahl.
- `POST /api/device-agent/heartbeat`: Geräte-Bearer `odad_…`, genau `{deviceId, report}`, ab Server 1.0.46 optional ergänzt um den [Hardwarebericht `inventory`](agent-hardware.md). `report` enthält ausschließlich `hostname`, `platform`, `architecture`, `osVersion`, `agentVersion`. Plattform muss zum Inventargerät passen. Zeit und Ablauf bestimmt der Server.

Device-Migration `008_device_agents.sql` ergänzt zwei Tabellen. Je Gerät besteht höchstens eine Verbindung. 256-Bit-Geheimnisse werden serverseitig ausschließlich als SHA-256-Hashes gespeichert; Bootstrap zehn Minuten, Gerätecredential 90 Tage. Neu registrieren rotiert den Zugang. Originaler menschlicher Autorisierungsnachweis, Akteur, Begründung, Zeitpunkt, Korrelations-ID und geheimnisfreie Vorher-/Nachher-Stände werden für Ausstellung und Widerruf erhalten; die Registrierung protokolliert den Geräteakteur. Heartbeats aktualisieren den tatsächlichen Kontakt, ohne eine neue Auditzeile je Minute zu erzeugen.

Private ownergebundene SQL-Befehle, Row-/Truncate-Guards, Geräte-Locks, endgültiger Live-Checkpoint und Deferred-Commit-Prüfung schützen den Schreibweg. Ein fehlender Receiver, abgelaufene ursprüngliche Autorisierung oder verschwundene Command-Bindung verhindert den Commit. Der privilegierte Datenbankbetreiber bleibt eine Vertrauensgrenze, wie beim bestehenden Inventar.

Der Gateway leitet ausschließlich die drei exakten POST-Maschinenpfade für Registrierung, Heartbeat und Synchronisierungsabfrage an den unabhängig prüfenden Device-Service. Gerätecredentials gelten nicht für Personen-, Inventar-, PIM- oder andere Verwaltungs-APIs. Unbekannte Pfade, Methoden und Query-Overrides werden nicht durch diesen Proxy freigegeben. Der Service bleibt zusätzlich rate-limitiert; große Flotten benötigen eine gesonderte Lastabnahme.

Die [eigene Compliance-Auswertung](device-compliance.md) und [befristete Synchronisierungsaufträge](device-sync.md) ergänzen das Protokoll. Apple-/Android-MDM, Intune, LAPS-/BitLocker-Verwaltung, Softwareverteilung, Wipe und weitere Fernbefehle bleiben offen. Geräteberichte sind nicht attestiert. Eine Zuweisung oder Registrierung erteilt keinen Benutzerzugang. Es gibt hier keine bestätigte externe Providerwirkung oder ausgelieferte Ereignis-Outbox.


Ab Agent 1.4.0 ergänzt [Gerät synchronisieren](device-sync.md) den tatsächlichen Verbindungsweg um befristete eigene Aufträge. Agent 1.4 benötigt den Server/Gateway ab 1.0.48. Der jeweilige Produktivstand steht im [Liefernachweis](../deployment/device-sync-2026-11-14.json).
