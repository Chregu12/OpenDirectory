# Tatsächliche Gerätesynchronisierung

Version 1.0.48 ergänzt unter `/devices` den Abschnitt **Gerät synchronisieren**. Ein eigener Firmeninhaber, Administrator oder aktuell aktivierter Engineering-Bearbeiter kann mit ursprünglicher Inventarberechtigung, frischer MFA, Begründung und Bestätigung eine neue Hardware- und Sicherheitsmeldung anfordern. Der Server speichert einen echten befristeten Auftrag; die Annahme ist noch keine Ausführung. [Prüf- und Lieferstand](../deployment/device-sync-2026-11-14.json).

## Bedienung

Gerät öffnen, **Synchronisierung anfordern** wählen und begründen. Der Agent ab **1.4.0** fragt vor seinem nächsten regulären Heartbeat einen Auftrag ab, liest die Werte neu und sendet beide Meldungen mit dem privaten Zustellnachweis. Der Agent benötigt Server und Gateway ab **1.0.48**. Ältere Agenten melden wie bisher, führen diese Aufträge jedoch nicht aus.

Die Oberfläche zeigt:

- **Wartet auf Agent**: tatsächlich angefordert oder ein weiterer Zustellversuch nach abgelaufener Lease möglich.
- **Vom Agenten abgerufen**: dieser registrierte Agent hat eine gültige Lease erhalten; noch keine neue Meldung bestätigt.
- **Synchronisiert**: neue Hardware-/Sicherheitsberichte und die aktuelle Compliance-Bewertung sind zusammen mit dem ursprünglichen Auftrag atomar gespeichert. Auch eine unbekannte Messung bleibt unbekannt; der Status bestätigt den Eingang, keine erfüllte Sicherheitsrichtlinie.
- **Abgebrochen**: weitere Abrufe und die Bestätigung dieses Auftrags sind gestoppt. Eine bereits begonnene lokale Leseabfrage lässt sich nicht zurückrufen. Ein später normaler Heartbeat ist weiterhin möglich.
- **Auftrag abgelaufen**, **Gerätezugang ersetzt oder ungültig** oder **Zustellung ausgeschöpft**: keine erfolgreiche Bestätigung behauptet. Eine neue Anforderung ist eine eigene ausdrückliche Entscheidung.

Aufträge enden spätestens mit der ursprünglichen fünfminütigen MFA-Frist oder dem Gerätecredential, höchstens fünf Minuten nach Erstellung. Eine Lease gilt höchstens 45 Sekunden, mit insgesamt drei Abrufen. Eine Neuregistrierung übernimmt alte Aufträge nicht. Pro Gerät ist nur ein tatsächlich noch offener Auftrag zulässig. Die Anzeige prüft alle 15 Sekunden, bei sichtbarem Tab, und bietet manuelles Aktualisieren. Auftragsverlauf und Seiten mit je zehn Aufträgen bleiben erhalten.

Der ursprüngliche Erstellungsentscheid autorisiert ausschließlich diese befristete Leseanforderung. Es wird kein menschlicher Bearer gespeichert oder ein wiederverwendbares Recht für den Agenten erzeugt. Spätere Rollenänderungen verlängern den Auftrag nicht. Lesen, Erstellen und Abbrechen prüfen die aktuelle eigene menschliche Quelle und MFA; Erstellen/Abbrechen verlangen die bestehende separate Inventar-Schreibaufgabe. Die maschinelle Abfrage verwendet ausschließlich das tatsächlich registrierte Gerätecredential.

## API und Speicherung

[OpenAPI 1.38.0](../api/openapi.yaml):

| Methode und Route | Wirkung |
| --- | --- |
| `GET /api/devices/{id}/agent/sync?page=1` | Eigene Auftragsseite und aktueller Registrierungs-ETag |
| `POST /api/devices/{id}/agent/sync` | Begründete, bestätigte Anforderung; `If-Match` ist genau der gelesene `connectionEtag` |
| `POST /api/devices/{id}/agent/sync/{requestId}/cancel` | Begründeter Abbruch mit `If-Match: "device-sync-REQUEST-REVISION"` |
| `GET /api/devices/{id}/agent/sync/{requestId}/history` | Originale Actor-, Zeit-, Grund- und Korrelationsbelege |
| `POST /api/device-agent/sync/claim` | Exakt `{deviceId}` und eigenes Gerätecredential; höchstens ein `inventory.refresh`-Auftrag samt privater Lease |
| `POST /api/device-agent/heartbeat` | Optionales `sync:{id,leaseToken}` verlangt beide neuen `inventory`-/`security`-Meldungen; erst der tatsächliche Commit liefert `sync:{id,status:"completed"}` |

Die Generation bindet den eigenen Tenant, das Gerät, die volle PostgreSQL-Präzision der ursprünglichen Registrierung und den Credential-Ablauf. Sie bleibt bei regulären Heartbeats stabil. Alte ETags scheitern nach Neuregistrierung, geänderte Auftragsversionen beim Abbruch; es gibt keine automatische Schreibwiederholung. Gerätecredentials öffnen keine menschlichen Lesewege. Fremde Selektoren und zusätzliche Felder werden abgewiesen, Antworten sind `no-store`. Private Lease-Tokens werden nur bei der maschinellen Annahme ausgegeben und als Hash gespeichert; menschliche Antworten und Ereignisse enthalten keine Lease-Geheimnisse oder ursprünglichen menschlichen Tokens.

Migration `011_device_sync.sql` ergänzt `device_sync_requests` und `device_sync_events`. Dieselbe Reihenfolge aus Geräte-, Verbindungs- und Auftrags-Lock serialisiert Annahme, Abbruch und tatsächliche Datenmeldung. Row-/Truncate-Guards und Deferred-Commit-Prüfungen verlangen genaue Zustände, Originalfristen, unveränderte Registrierung, beide neuen Server-Receipts und den tatsächlichen Ereignisdatensatz. Fehlende Ereignisse oder eine abgelaufene Quelle rollen auch die im selben Heartbeat begonnenen Datenänderungen zurück. Ergebnisse bleiben als eigene Originalkopie erhalten, wenn später neue normale Meldungen eintreffen. Audit ist lokal gespeichert; externe Zustellung wird nicht behauptet.

## Nachweise und Grenzen

Native PostgreSQL-Tests prüfen tatsächliche Zustandswechsel, konkurrierende Abrufe, doppelte offene Aufträge, Abbruch, falsche Leases, fehlende Berichte, Credentials/Widerruf/Neuregistrierung, Ablauf, ausgeschöpfte Versuche, physische Fristen, fehlende Ereignisse und Migration-Replay. Der kompilierte Rust-Prozess und ein unabhängiger signierter OAuth/PIM-/Gateway-Test führen den tatsächlichen Ablauf aus. Browser prüfen Begründung, genaue Versionen, automatische Statusabfrage, Verlauf, mobile Darstellung, Nur-Lesen und Quellenverlust. Produktions-Testgeräte oder persönliche Grants werden dafür nicht angelegt.

`inventory.refresh` liest ausschließlich vorhandene Hardware-/Sicherheitsdaten. Fernsperre, Neustart, Löschung, Shellbefehle, App-Verteilung und Provider-Konfiguration sind weitere offene Anforderungen. Der Agent ist nicht hardwareattestiert; echte Windows-/Linux-Zielgeräte und signierte Installer sind noch abzunehmen. Der vollständige [Umsetzungsauftrag](../implementation-worklist.md) bleibt aktiv.
