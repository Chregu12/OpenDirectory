# ADR 025: Blueprint-Zuweisungen als zusätzliche Lizenzherkunft

Status: **In Progress**. Architektur für Slice 22; noch keine abgeschlossene Implementierungs- oder Betriebsabnahme.

## Kontext

Eigene lokale Blueprint-Freigaben enthalten bisher nur gewünschte App-Referenzen. Eine reale Benutzerzuweisung muss deren Lizenzbedarf tatsächlich erfüllen. Dabei können manuelle Zuweisung und mehrere Blueprints dieselbe App verlangen. Ein zweites Lizenzkonto oder eine als manuell ausgegebene Blueprint-Zuweisung würde Bestand, Herkunft und Offboarding verfälschen.

## Entscheidung

- Der vorhandene Allocator bleibt Eigentümer des Sitzbestands. Eine effektive Benutzer-/Pool-Zuweisung verbraucht weiterhin genau einen Sitz; mehrere Herkunftszeilen halten diesen gemeinsam aufrecht.
- Die neue Herkunft ist ausdrücklich `source_type=blueprint`, mit einer unveränderlichen Benutzer-Blueprint-Zuweisung als `source_id`. Jede Pool-Herkunft erhält ihre eigene serverseitige Grant-Inkarnation. `license_grants.kind=direct` bezeichnet dabei einen einzelnen Benutzer als Begünstigten, nicht manuelle Herkunft oder manuelle Widerrufbarkeit.
- Eine Zuweisung bindet eine bestimmte unveränderliche Freigabeversion und die ursprüngliche positive Benutzer-Eligibility. Neue Freigaben ersetzen bestehende Zuweisungen nicht heimlich. Entfernen und erneutes Zuweisen erzeugen eine neue Inkarnation.
- Eine positive Zuweisung mit Apps erfolgt vollständig oder gar nicht in einer Policy-Datenbanktransaktion. Stabile Benutzer-/Pool-Sperren, ursprüngliche Poolversionen und Kapazitätsprüfung sichern auch den Fehler im letzten Pool ab.
- Protokoll 2 besitzt einen unveränderlichen Gesamtauftrag und je betroffenem Pool einen kanonischen Lizenzbeleg mit tatsächlichen Herkunfts-, Projektions-, Audit-, Revisions- und Pending-Outbox-Effekten. Die Ein-Auftrag-pro-Transaktion-Regel des bisherigen Protokolls 1 bleibt getrennt erhalten.
- Die neue ursprüngliche Assignment-Authority hat genau zwölf Felder und die zwei eigenen Aufgaben `company.blueprints.assignments.read` und `company.blueprints.assign`. Blueprint-Autoren erhalten dadurch keine globale Policy- oder Lizenzrolle. Tatsächlicher App-Zugriff benötigt unabhängig die bestehende Firmen-App-Authority desselben ursprünglichen Actors und Tenants. Quellenfristen begrenzen die Admission, nicht die Lebensdauer einer zugewiesenen Lizenz.
- Manuelles Entfernen widerruft nur die manuelle Herkunft. Blueprint-Entzug entfernt nur die erfassten Grants dieser Blueprint-Inkarnation. Der Sitz wird erst nach der letzten Herkunft frei; Belege unterscheiden Herkunftsentzug und Sitzfreigabe.
- Das neue negative Offboarding erfasst sämtliche ursprünglichen Quellen/Grants und Blueprint-Bindungen, einschliesslich Bindungen ohne Apps. Der bestehende tatsächliche Identity-045-Nachweis bleibt der unveränderte negative Lifecycle-Checkpoint. Eine spätere Reaktivierung darf keinen alten Auftrag zum Entzug neuer Grants berechtigen.
- Alte Aufträge behalten ihre ursprüngliche Belegform. Ungeeignete aktuelle Protokoll-1-Operationen müssen `upgrade_required` melden statt Blueprint-Herkunft auszublenden oder Erfolg vorzutäuschen.

## Grenzen

Aktivierung erst nach vollständiger negativer Lifecycle-Unterstützung und deren Tests. Konservative Konflikterkennung statt eines erfundenen Prioritätsgewinners. Benutzer-Sollkonfigurationen sind keine bestätigten Geräte-Konfigurationen oder Apple-MDM-Befehle.

Account-Sperre in Identity und lokale Bereinigung in Policy besitzen getrennte Commits; das Journal macht Teilfehler sichtbar, bietet aber keine verteilte Atomarität. Geänderte negative Benutzerinkarnationen, insbesondere nach Reaktivierung oder späterer Löschung, benötigen einen ausdrücklich unterstützten Nachweis statt eines aktualisierten alten Checkpoints.

SQL-/DDL-Owner, unveränderte Receiver und produktive Rollentrennung bleiben die bisherige ausdrückliche Vertrauensgrenze. Keine zusätzliche Runtime, Dependency, Datenbank oder produktive Provider-Schreiboperation.
