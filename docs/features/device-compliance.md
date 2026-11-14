# Geräte-Compliance aus tatsächlichen Agentenmeldungen

Version 1.0.47 ergänzt `/devices` um einen Compliance-Abschnitt je Gerät und `/compliance` um eine eigene Geräteübersicht und Firmenrichtlinien. Die frühere Oberfläche eines separat nicht angebundenen Compliance-Engine-Dienstes wird auf diesem Weg ersetzt. Es werden keine Demoquoten, angeblichen Providerbefunde oder automatischen Ausnahmen eingesetzt.

## Einrichten und prüfen

1. Mit Firmeninhaber, Administrator oder tatsächlich aktivierter Rolle **Richtlinienadministrator** und einer höchstens fünf Minuten alten unabhängigen MFA-Anmeldung `/compliance` öffnen.
2. **Firmenrichtlinien**, dann macOS, Windows oder Linux wählen. Die Richtlinie aktivieren und mindestens eine Prüfung auswählen: minimale numerische Betriebssystemversion, Systemdatenträger-Verschlüsselung, Firewall oder mindestens freier Systemdatenträgerspeicher. Berichtsalter: 5–1440 ganze Minuten.
3. Mit Begründung und ausdrücklicher Bestätigung speichern. Bei Versionskonflikt neu laden und die Änderung erneut prüfen. Speichern erstellt eine neue Richtlinienversion mit ursprünglichem Actor, Quelle, Begründung, vorherigem/nachherigem Zustand und ausstehendem Zustellbeleg.
4. Ein vorhandenes eigenes Inventargerät wie unter [Geräteverbindung](device-agents.md) einmalig registrieren und Agent **1.3.0** auf diesem Gerät starten. Erst dessen tatsächliche neue Sicherheitsmeldung bewertet die Richtlinienversion. Bestehende Berichte bestätigen geänderte Regeln nicht.

```sh
cargo build --locked --release --manifest-path agent-rust/Cargo.toml
od-agent-service security
od-agent-service heartbeat
od-agent-service compliance
od-agent-service run
```

`security` zeigt nur lokale Messungen, ohne Registrierung oder Änderung von Systemeinstellungen. `heartbeat` und `run` senden die Sicherheits- und [Hardwaremeldung](agent-hardware.md) mit dem bestehenden Gerätecredential. `compliance` sendet eine echte Meldung und liefert nur bei bestätigtem Serverstatus `compliant` Exitcode 0. Ein erfolgreicher HTTP-Heartbeat alleine bedeutet keine erfüllte Richtlinie. Agent 1.3.0 benötigt Server 1.0.47; Agenten 1.1/1.2 bleiben mit ihren bisherigen Meldungen kompatibel, liefern aber keinen neuen Sicherheitsnachweis.

Die Übersicht bietet eigene Bestandszahlen, Suche, Plattform-/Bewertungsfilter, paginierte Geräte und deren Detail-/Bewertungsverlauf. Zahlen berücksichtigen Suche und Plattform vor dem Bewertungsfilter. Geräte ohne Desktop-Richtlinien, etwa iOS/Android, erscheinen ohne eingerichtete Richtlinie. Details aktualisieren alle 30 Sekunden, die Übersicht über **Neu laden**. Engineering (`device-enrollment-operator`) und `compliance-reader` dürfen lesen; Richtlinienänderungen erhalten nur tatsächlicher eigener Inhaber, `admin` oder `policy-administrator`. Die bestehende PIM-Rollenaktivierung und deren Ablauf bleiben verbindlich. Tokenbehauptungen oder ein Gerätecredential erteilen keine menschlichen Verwaltungsrechte.

## Unterstützte Messungen

| Plattform | Verschlüsselung | Firewall |
| --- | --- | --- |
| macOS | Tatsächlicher `fdesetup status`; nur eindeutiges FileVault On erfüllt | Zustand der macOS-Anwendungsfirewall über `socketfilterfw --getglobalstate` |
| Windows | BitLocker-Systemvolume: `FullyEncrypted` und `ProtectionStatus On` | Alle drei Profile von `Get-NetFirewallProfile -PolicyStore ActiveStore` aktiviert |
| Linux | ext2/ext3/ext4/XFS-Root-Dateisystem über `findmnt` und alle erkennbaren `lsblk --inverse`-Root-Abhängigkeiten mit dm-crypt | Tatsächlich aktives UFW |

Fehlende Programme, unzureichende Leserechte, Zeitüberschreitung oder nicht eindeutig erkennbare Ausgaben bleiben unbekannt. Btrfs-/andere Mehrgeräte-Dateisysteme und andere Linux-Firewallverfahren werden nicht als erfolgreich bestätigt. Die Prozesse haben ein Zeitlimit, begrenzte Ausgabe und erhalten nur festgelegte Leseparameter. Windows-Abfragen übertragen weder Recovery Keys noch Key Protectors. OS-Versionen vergleichen numerische Segmente mit Nullauffüllung (`13.10 > 13.9`); freien Speicher bewertet PostgreSQL mit exakten Dezimal-Bytezählern, ohne JavaScript-Rundung. Eine leere aktive Richtlinie ist unzulässig.

Die zugrunde liegenden Hersteller-/Systemverträge: [BitLocker-Betrieb](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide?tabs=powershell), [ProtectionStatus](https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume), [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile), [lsblk](https://www.man7.org/linux/man-pages/man8/lsblk.8.html), [Ubuntu UFW](https://wiki.ubuntu.com/UFW).

## Status und Nachweis

- **Konform**: jede tatsächliche Pflichtprüfung erfüllt, aktuelle Richtlinienversion und noch gültige Meldung derselben registrierten Verbindung.
- **Abweichung**: mindestens eine Pflichtprüfung nachweislich verletzt.
- **Unbekannt**: keine nachgewiesene Verletzung, aber mindestens eine Pflichtprüfung nicht auswertbar.
- **Keine Richtlinie**: für diese Plattform keine aktivierte Firmenrichtlinie.
- **Neue Meldung ausstehend**: noch keine Sicherheitsmeldung oder geänderte Richtlinienversion.
- **Meldung abgelaufen**: zulässiges Berichtsalter überschritten.
- **Frühere Geräteverbindung**: ursprünglicher Zugang widerrufen, abgelaufen oder Registrierung/Plattform ersetzt. Historie bleibt erhalten, wird aber nicht auf die neue Verbindung übertragen.

Server-Eingangszeit, ursprüngliche Registrierung, Plattform, Agent-Version und exakte Verbindungsrevision binden jede Sicherheitsmeldung. Die Gültigkeit endet spätestens am Richtlinien-Berichtsalter, am Ablauf eines verwendeten Hardwareberichts oder Gerätecredentials. Offline-Kontakt und Berichtsalter sind getrennte Grenzen. Alte Heartbeats ohne `security` erneuern frühere Sicherheitsbefunde nicht. Zustands-/Prüfergebnisänderungen, Richtlinienwechsel und neue Registrierungen erzeugen dauerhafte Bewertungsereignisse; identische Minutentakte erzeugen keine neue Auditzeile.

## Persistenz und API

Migration `010_device_compliance.sql` ergänzt `security_report`/`compliance_report` an der bestehenden Geräteverbindung und vier eigene Tabellen für Plattformrichtlinien, Richtlinienereignisse, deren ausstehende Zustellung und Gerätebewertungen. Existierendes Inventar, Gerätezuordnungen, Credentials und Kontrollhistorie bleiben erhalten. Policy-Locks serialisieren konkurrierende Änderungen und Bewertungen. Guard-/Shape-/Deferred-Commit-Prüfungen verlangen tatsächliche Zustände, Originalfristen, Ereignisse und Zustellbelege; fehlende Empfänger verhindern Erfolg. Richtlinien werden nicht automatisch produktiv aktiviert.

Die [OpenAPI](../api/openapi.yaml), Version 1.37.0, dokumentiert:

- `GET /api/identity/device-compliance`: ursprüngliche aktuelle eigene menschliche Quelle.
- `GET /api/devices/compliance/capabilities`, `/policies`, `/`: Aufgaben, drei Richtlinien und konsistente eigene Geräteseiten.
- `PUT /api/devices/compliance/policies/{platform}`: genau `settings`, `reason`, `confirm:true` und starkes `If-Match: "device-compliance-TENANT-PLATFORM-REVISION"`. Version 0 bezeichnet die noch nicht gespeicherte Standardrichtlinie.
- `GET /api/devices/compliance/policies/{platform}/history` und `/api/devices/{id}/compliance/history`: eigene paginierte Originalereignisse.
- `GET /api/devices/{id}/compliance`: tatsächlicher aktueller Status und letzte gespeicherte Bewertung.
- `POST /api/device-agent/heartbeat`: optionales `security` zusätzlich zu `inventory`; nur bei gesendeter Sicherheitsmeldung zusätzliches bestätigtes `compliance`-Ergebnis.

Menschen lesen mit ursprünglichem, aktuell revalidiertem Bearer und frischer MFA, Antworten sind `no-store`. Fremde Tenant-/Benutzerselektoren, Caller-Zeitstempel und zusätzliche Sicherheitsfelder werden abgewiesen. Gerätecredentials bleiben auf eigene Registrierung/Heartbeat beschränkt. Keine Schreiboperation wird nach Konflikt automatisch wiederholt.

[Liefer- und Prüfnachweis](../deployment/device-compliance-2026-11-14.json): PostgreSQL mit tatsächlichem kompiliertem Rust-Prozess, signierter OAuth-/PIM-/Gateway-Ablauf, Parser- und Berechtigungstests, Produktionsimage-Browser und echte HTTP-Rewrites. Keine produktiven Testbenutzer, Geräte, Richtlinien oder persönlichen Grants werden dafür angelegt.

Windows-/Linux-Messung und Autostart auf realen Zielgeräten, signierte Installer, Hardware-Attestierung, Fernbefehle, MDM und Conditional-Access-Login-Durchsetzung bleiben offen. Die neuen Regeln prüfen die vom Agenten gemeldeten Daten; sie konfigurieren keine Gerätesicherheit. Datenbankbetreiber und Geräteagent bleiben Vertrauensgrenzen. Der [vollständige Umsetzungsauftrag](../implementation-worklist.md) bleibt aktiv.
