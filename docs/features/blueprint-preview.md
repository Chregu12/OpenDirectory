# Blueprint-Vorschau und Konfliktschutz

Status: **Tested**, begrenzter Business-Slice 20. Kein vollständiger BR-004 und keine neue Company-Administrator-Berechtigung.

## Verwendung

Unter `/blueprints` den Bereich **Ausgewählte Blueprint-Versionen vergleichen** öffnen, eine Plattform und höchstens 25 aktuelle Katalogversionen auswählen und **Vorschau berechnen** ausführen. Die tatsächlichen PostgreSQL-Konfigurationen werden verglichen; keine Beispieldaten und keine Schreiboperationen.

Ein Ergebnis zeigt ausgewählte Versionen, ursprüngliche Konfigurations-IDs, nicht widersprüchliche Konfigurationsarten und Konflikte. Änderungen an Auswahl, Plattform, Katalog oder Sitzung verwerfen das alte Ergebnis. Veraltete Versionen müssen ausdrücklich neu geladen und ausgewählt werden. Eine Vorschau genehmigt keine spätere Änderung oder Zustellung.

## Regeln

- Vergleich je `config_type`: genau ein unterschiedlicher JSONB-Inhalt ergibt eine nicht widersprüchliche Konfiguration mit sämtlichen ursprünglichen Quellen. Mehrere Inhalte ergeben einen Konflikt ohne Gewinner, Priorität oder Deep Merge.
- Der Vergleich erfolgt in PostgreSQL. Objekt-Schlüsselreihenfolge ist unerheblich, Array-Reihenfolge bleibt relevant; `1` und `1.0` sind gleich. Unterschiedliche grosse Zahlen werden nicht durch JavaScript-Rundung gleichgesetzt.
- `payloadJson` bleibt der ursprüngliche PostgreSQL-Text. Die Oberfläche zeigt diesen unverändert; sie berechnet daraus keine Geräteaktion. Die tatsächliche Receiver-Admission verweigert eine nicht verlustfrei darstellbare Nutzlast, statt gerundete Werte als exakte Zustellung zu bestätigen.
- Die Prüfung ist bewusst konservativ: ein vollständiges Profil je Art, auch bei WLAN/VPN. Zwei unterschiedliche WLAN-Profile werden als Konflikt gemeldet, nicht anhand erfundener Apple-Semantik zusammengeführt.
- Maximal 25 eindeutige Blueprint-IDs, insgesamt 1'000 ursprüngliche Konfigurationen und 1 MiB ursprünglicher UTF-8-Payloadtext. Überschreitungen scheitern vollständig, ohne abgeschnittenes positives Ergebnis.
- Nur `all` oder zur ausgewählten Plattform passende Blueprints werden akzeptiert. Die Plattform ist eine ausdrückliche Auswahl, kein Nachweis eines angeschlossenen Geräts.

## API und Sicherheit

`POST /api/blueprints/preview`

```json
{"platform":"macos","blueprints":[{"id":"11111111-1111-4111-8111-111111111111","version":3}]}
```

Der bestehende kanonische menschliche `policies.preview`-Zugriff ist erforderlich. Bestehende Policy-Reader besitzen dieses Recht bereits; Company-Ownership oder App-Verwaltung erteilen es nicht. Rollen-/Tenant-Quellverträge, Pflicht-MFA für Schreiboperationen, PIM und unabhängige Publikationsfreigaben werden nicht erweitert oder ersetzt. Die UI benötigt zusätzlich das bestehende Katalog-Leserecht.

Ein gemeinsamer Repeatable-Read-/Read-only-Snapshot prüft sämtliche ausgewählten Elternversionen und Konfigurationen. Die ursprüngliche Autorisierung wird vor und nach der Abfrage geprüft. Erfolgsantworten sind `no-store`; Audit-/Outbox-/Lizenz-/Command-Tabellen bleiben unverändert.

Fehler: `400` ungültige exakte Auswahl; `401/403` fehlende aktuelle Autorisierung; `404` fehlender Blueprint; `409` Plattform oder Grenze; `412` geänderte Version; `503` nicht verfügbare Speicherung oder ungültige gespeicherte Quelle. Es gibt keine automatische Aktualisierung oder Wiederholung.

Interne Konflikte eines einzelnen Blueprints sperren dessen bestehendes `/apply` **vor** Publikationsprüfung und externer Zustellung. Auch die kanonische `deliveryFrame`-Admission prüft den gesamten gesperrten Blueprint, damit ein direkter Receiver-Aufruf diese Konfliktprüfung nicht umgeht. Unabhängige Freigabe, exakte Version, frische MFA, Geräte-Zielbindung und wiederholte Quellprüfungen bleiben obligatorisch. Gleiche Profile werden in der Vorschau zusammengefasst; bestehende Commands und Zertifikatsausstellungen werden dadurch nicht rückwirkend dedupliziert.

## Grenzen

Dies ist eine ausgewählte **Platform-Policy**-Momentaufnahme, kein vollständiger mandanteneigener Blueprint-Prozess. Aktuelle Aggregate-Versionen sind noch keine abrufbaren unveränderlichen historischen Payload-Versionen. Weitere, nicht ausgewählte oder anderen Zielen zugewiesene Blueprints werden nicht automatisch berechnet. Gruppen-/Benutzerauflösung, Prioritäten, App-/Lizenzreservierung, kombinierter Onboarding-Workflow und providerabhängige Validierung bleiben offen.

`previewOnly: true`, `enforcementConfirmed: false` und `licenseReservations: 0` sind feste Tatsachen des Vertrags. Kein Apple-/MDM-Provider, Enrollment oder tatsächlicher Geräteerfolg wird behauptet. Eine fehlende Konfliktmeldung ist keine Bestätigung der fachlichen Gültigkeit eines Profils.

Vertrag: [OpenAPI](../api/openapi.yaml). Entscheidung: [ADR 023](../architecture/adr-023-blueprint-preview.md). Prüfbelege: [Testresultate](../testing/test-results.md).
