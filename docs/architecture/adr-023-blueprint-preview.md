# ADR 023: konservative Blueprint-Vorschau ohne neue Hoheit

Status: Accepted für den begrenzten lokalen Vergleich; Gesamtprodukt weiterhin offen.

## Kontext

Vorhandene Blueprints besitzen versionierte Konfigurations- und Zieländerungen, unabhängige Publikationsfreigaben und kanonische Geräte-Admission. Ein `/apply` prüfte aber keine widersprüchlichen Konfigurationen desselben Typs. Die bestehende Policy-Prioritäts-/Merge-Engine beschreibt keine fachlich dokumentierte Blueprint- oder Apple-Semantik.

## Entscheidung

Bestehenden Stack, Datenbank, `policies.preview` und aktuelle Aggregate-Versionen wiederverwenden. Keine Migration, Rolle, eigene Company-Hoheit, zusätzliche Queue oder neue Abhängigkeit. Ein kleiner Read Service vergleicht ausdrücklich erfasste aktuelle Versionen gemeinsam in einer Read-only-Transaktion.

PostgreSQL-JSONB-Gleichheit entscheidet über gleiche Inhalte. `dense_rank` je `config_type` verhindert insbesondere fehlerhafte Gleichsetzungen grosser Zahlen durch JavaScript. Exakter Payloadtext wird als `payloadJson` ausgegeben und nicht zur Konfliktentscheidung deserialisiert. Bounded Parsing prüft nur die Darstellbarkeit der gespeicherten Struktur. Die tatsächliche Admission prüft zusätzlich einen verlustfreien JSONB-Roundtrip, bevor eine bestehende JavaScript-Payload einen Geräteauftrag speisen kann.

Verschiedene Inhalte derselben Art bleiben ein ungelöster Konflikt. Das ist auch für mehrere legitime WLAN-/VPN-Profile bewusst restriktiver als eine später providerabhängig definierte Komposition. Keine unbestätigte Priorität oder Zusammenführung. Jeder ursprüngliche Eintrag bleibt als Quelle sichtbar.

## Folgen

- Konfliktschutz vor `/apply` und innerhalb direkter kanonischer `deliveryFrame`-Admission; bestehende unabhängige Freigaben und Receiver-Grenzen bleiben erhalten.
- Vergleich ist schreibfrei und keine publizierbare Freigabe, globale Zielauswertung, Lizenzreservierung oder Ausführungsbestätigung.
- Kein Anspruch auf atomare Transaktionen über Identity-, Policy- und Device-Datenbanken. Ein Snapshot darf nach seiner Abfrage bereits historisch sein; spätere Schreib-/Admission-Kernels müssen weiterhin ihre eigenen Originalversionen prüfen.
- Mandanteneigene Blueprint-/App-/Scope-Governance und immutable historische Versionen benötigen einen späteren expliziten Domain-Vertrag. Die versiegelte eigene Rollen-/Policy-Quelle wird nicht beiläufig aktiviert.
- Tests müssen reale SQL-Gleichheit, Präzision, Rechteverlust, Versionswechsel, Grenzen und unveränderte Effekt-Tabellen nachweisen; grüne UI-Mocks allein reichen nicht.
