# Agent herunterladen und als Systemdienst einrichten

Web **1.0.49** ergänzt unter `/devices` die Download- und Installationshilfe. Ein Windows-, macOS- oder Linux-Gerät öffnen und **Geräteverbindung → Agent herunterladen und einrichten** aufklappen. Die Links wählen ausdrücklich Plattform und Architektur. Die Pakete des [Vorschaureleases Agent 1.5.0](https://github.com/Chregu12/OpenDirectory/releases/tag/agent-v1.5.0) enthalten das native Programm, `manifest.json` und eine Anleitung. Linux benötigt glibc ab 2.39 und OpenSSL 3; Server und Gateway müssen mindestens **1.0.48** verwenden.

| Plattform | Pakete | Tatsächlicher Autostart |
| --- | --- | --- |
| Linux | x64, ARM64 | systemd: `od-agent.service` |
| macOS | Intel, Apple Silicon | LaunchDaemon: `com.opendirectory.agent` |
| Windows | x64 | Aufgabenplanung: `OpenDirectoryAgent`, SYSTEM, beim Systemstart |

Die fünf Pakete haben SHA-256-Dateien und GitHub-Build-Herkunftsnachweise. Apple Developer ID/Notarisierung und Windows Authenticode sind **nicht eingerichtet**. Ein GitHub-Herkunftsnachweis ersetzt keine Betriebssystemsignatur; die Downloads bleiben eine Vorschau. Die [Anleitung des unveränderten Release-Tags](https://github.com/Chregu12/OpenDirectory/blob/agent-v1.5.0/agent-rust/PACKAGE-README.md) gehört zu genau diesen Paketen.

## Prüfen, registrieren, starten

1. Passendes Archiv und dessen `.sha256` vom Release herunterladen. Den tatsächlichen Archivhash mit der Prüfsummendatei vergleichen und den Herkunftsnachweis vor dem Entpacken/Ausführen prüfen:

   ```sh
   gh attestation verify ARCHIVE --repo Chregu12/OpenDirectory --signer-workflow Chregu12/OpenDirectory/.github/workflows/agent.yml --source-ref refs/tags/agent-v1.5.0 --source-digest 7767146c4fa6e4ccf357c99ef23e154b765f0e53 --deny-self-hosted-runners
   ```

2. In OpenDirectory beim richtigen Inventargerät einen einmaligen Registrierungscode ausstellen. Die bestehenden eigenen Rechte, ursprüngliche MFA-Frische, Begründung und Bestätigung gelten unverändert. Den Code auf dem Zielgerät verdeckt als `OD_ENROLLMENT_TOKEN` einlesen; [Unix- und PowerShell-Beispiele](device-agents.md#agent-herunterladen-und-registrieren). Bei privater CA deren dauerhaften PEM-Pfad über `OD_CA_CERT` setzen. TLS-Prüfung bleibt aktiv.
3. In einem lokalen Administrator-/Root-Terminal mit der echten Serveradresse `od-agent-service --server-url https://opendirectory.heusser.local enroll` ausführen. Unter Windows heißt das Programm `od-agent-service.exe`. Nach Erfolg `OD_ENROLLMENT_TOKEN` entfernen. Der Bootstrap-Code ist einmalig; die geschützte Konfiguration enthält danach das Gerätecredential.
4. `od-agent-service install --dry-run` zeigt ausschließlich Plattform, Programm-, Konfigurations- und Dienstpfad. Die Vorschau liest keine Konfiguration und verändert keinen Dienst; sie ist keine erfolgreiche Installations- oder Berechtigungsprüfung. `--config-path ABSOLUTER-PFAD` wählt ausdrücklich dieselbe Datei für Registrierung und Dienst.
5. `od-agent-service install` ausführen. Der Installer kopiert das Programm in seinen geschützten Systempfad und registriert/startet den tatsächlichen Systemdienst bzw. die Windows-Aufgabe. Danach in OpenDirectory den wirklichen Kontakt, Agentversion, Hardware- und Sicherheitsbericht prüfen. Ein laufender Prozess beweist noch keine erfolgreiche Serveranmeldung.

Unix verlangt eine root-eigene private reguläre Konfiguration (`0600`), geschützte übergeordnete Verzeichnisse und gegebenenfalls einen root-eigenen schreibgeschützten CA-Pfad. Symlinks werden abgelehnt. Standarddateien sind `/etc/opendirectory/agent.json` bzw. `/Library/Application Support/OpenDirectory/agent.json`. Unter Windows müssen Konfiguration und CA innerhalb `%PROGRAMDATA%\OpenDirectory` liegen; der Installer schützt die Pfade für SYSTEM und lokale Administratoren und lehnt abweichende Berechtigungen/Reparse-Pfade ab. CA-Dateien müssen für den späteren Dienstbetrieb erhalten bleiben.

Der Dienst verwendet exakt die gespeicherte Registrierung. Vorübergehende URL-, Credential- oder CA-Overrides werden nicht stillschweigend als Installation übernommen. Gleiches `install` kann den Agenten aktualisieren, ohne das Gerätecredential zu überschreiben. Eine andere bestehende Dienstdefinition wird abgelehnt; erst `install --replace-existing` sichert sie privat und ersetzt sie ausdrücklich. Bei einem Fehler meldet der Installer einen Fehler; den nativen Manager prüfen, bevor erneut installiert wird. Es gibt keine vollständige automatische Rückabwicklung aller bereits ausgeführten Installationsschritte.

## Stoppen und entfernen

Im lokalen Administrator-/Root-Terminal den bekannten Dienst stoppen/deaktivieren:

- Linux: `systemctl disable --now od-agent`, danach `/etc/systemd/system/od-agent.service` entfernen und `systemctl daemon-reload` ausführen.
- macOS: `launchctl bootout system/com.opendirectory.agent`, danach `/Library/LaunchDaemons/com.opendirectory.agent.plist` entfernen.
- Windows PowerShell: `Stop-ScheduledTask -TaskName OpenDirectoryAgent`, danach `Unregister-ScheduledTask -TaskName OpenDirectoryAgent` bestätigen.

Erst nach dem Stoppen das bekannte installierte Programm entfernen: `/usr/local/lib/opendirectory/od-agent-service`, `/Library/Application Support/OpenDirectory/bin/od-agent-service` oder `%PROGRAMFILES%\OpenDirectory\Agent\od-agent-service.exe`. Lokale Dateien zu entfernen widerruft keinen Serverzugang. Das Gerätecredential getrennt über **Gerätezugang widerrufen** sperren; aufbewahrte Konfigurationen und Sicherungen privat halten.

## Nachweise und Grenzen

[Tag-Build mit fünf erfolgreichen nativen Jobs](https://github.com/Chregu12/OpenDirectory/actions/runs/43622676274) und [Liefernachweis](../deployment/agent-installation-2026-11-14.json): Ubuntu 24.04 x64/ARM64, macOS 15 Intel/ARM64 und Windows Server 2025 x64 starten den tatsächlichen jeweiligen Manager auf frischen GitHub-VMs. Je Plattform werden drei echte Hardware-/Sicherheits-Heartbeats empfangen, geschützte Konfiguration, idempotente Neuinstallation, Ablehnung abweichender Dienstdefinitionen und explizite Ersetzung geprüft. Der Test mit Konfigurationspfaden mit Leerzeichen und Prozentzeichen schützt auch die Parameterübergabe. Diese Prüfungen installieren keinen Dienst auf dem Entwickler-Mac oder auf persönlichen Produktivgeräten.

Die veröffentlichten zehn Downloads wurden erneut über ihre öffentlichen URLs geladen und gegen die geprüften Tag-Artefakte verglichen. Der tatsächliche kompilierte Agent 1.5.0 besteht außerdem den PostgreSQL-/HTTP-Gateway-Prozess für Registrierung, Hardware, Compliance, Synchronisierung und Widerruf. Web 1.0.49 besteht 3’223 Unitfälle, Typprüfung und 14 Browserabläufe gegen sein finales Produktionsimage; produktive TLS-, Zugriffsschutz-, Image-Digest- und Quellhash-Prüfungen sind dokumentiert.

Betriebssystemsignierung, Neustartabnahme auf physischen Zielgeräten und Kalibrierung von FileVault/BitLocker/dm-crypt-/Firewall-Befunden bleiben offen. CI bestätigt tatsächliche VM-Dienste und Meldungen, keine physische Geräte- oder Hardware-Attestierung. Weitere Fernbefehle, Softwareverteilung, Hersteller-MDM und der vollständige [Umsetzungsauftrag](../implementation-worklist.md) bleiben offen.
