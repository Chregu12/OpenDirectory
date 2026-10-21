# Firmen-Blueprint-Zuweisungen und Lizenzherkunft

Status: **In Progress**. Der implementierte Teil ist noch nicht vollständig durch die geplanten signierten und Browser-Abläufe abgenommen.

## Verhalten

Ein berechtigter Firmenadministrator weist einem aktivierten eigenen Benutzer eine konkrete unveränderliche Blueprint-Version zu. Die Zuweisung speichert die Eligibility-Inkarnation des Benutzers. Eine spätere Blueprint-Veröffentlichung oder Benutzer-Reaktivierung erneuert diese Bindung nicht automatisch.

Lokale App-Pools aus der Freigabe werden über den vorhandenen Policy-Allocator reserviert. Manuelle und mehrere Blueprint-Herkünfte besitzen jeweils eigene tatsächliche Grants, teilen aber pro Benutzer und Pool dieselbe effektive Lizenzzuweisung und damit genau einen Sitz. Der Herkunftstyp `blueprint` bleibt von der manuellen Herkunft `direct` unterscheidbar. Eine manuelle Rücknahme löscht keine Blueprint-Herkunft; der Sitz wird erst nach der letzten Quelle freigegeben.

Die Blueprint-Ansicht zeigt gebundene Benutzer, Versionen, aktuelle wirksame Konfigurationen und Konflikte. Die App-Verwaltung zeigt tatsächliche Zuweisungsquellen und Grant-IDs. Eine Konfliktvorschau benennt konkurrierende Konfigurationen, ohne eine erfundene Priorität anzuwenden.

## Berechtigung und Belege

Die Assignment-Quelle gewährt ausschliesslich `company.blueprints.assignments.read` und `company.blueprints.assign`. Eine Blueprint- oder App-Berechtigung ersetzt keine der jeweils anderen Quellen. Für Poolwirkungen sind zusätzlich die vorhandene Firmen-App-Authority desselben ursprünglichen Actors und Tenants sowie aktuelle MFA erforderlich. API-Schreibvorgänge benötigen Idempotency-Key und die passende aktuelle ETag.

Migrationen 026/027 halten Blueprint-Bindungen, Operations, Pool-Children, tatsächliche Allocator-Effekte, Ereignisse und Pending-Outbox in Policy. Positive Mehrpool-Zuweisungen sowie das negative vollständige Quellenmanifest sind jeweils atomar innerhalb der Policy-Datenbank. Identitätssperre und Policy-Rückgabe sind getrennte Commits; das dauerhafte Workflow-Journal zeigt Teilfehler und Recovery.

V2-Offboarding erfasst alle lokalen Quellen und aktiven Blueprint-Bindungen einschliesslich Blueprints ohne Apps. Es verlangt den ursprünglichen negativen Identity-045-Checkpoint. Gesperrte oder gelöschte Generationen werden nicht durch einen alten Auftrag aufgefrischt. Bestehende V1-Belege bleiben historisch lesbar; für quellenabhängige nicht unterstützte V1-Wege kommt `upgrade_required` zurück.

## Grenzen

- Eine lokale Blueprint-Freigabe bestätigt keine Installation, Gerätekonfiguration oder Apple-MDM-Ausführung.
- Allgemeine Konfigurationszuweisungen an Gruppen, Geräte, Standorte und OUs bleiben offen. Für lokale Lizenzen existiert jetzt der gesonderte [Lizenzgruppen-Abgleich](company-license-groups.md) mit lizenzreinen Blueprints und ausdrücklicher Pool-Verknüpfung.
- Externe App-Käufe, Herstellerbestände und Providerzustellung sind nicht Teil dieser Funktion.
- Outbox-Belege sind tatsächlich `pending`; ein Worker oder zugestelltes Ereignis wird damit nicht behauptet.
- Die getrennten Identity-/Policy-Commits bilden keine verteilte Transaktion.
- SQL-/DDL-Owner, vollständige Rollen- und Deployment-Governance, Retention und Produktionsbetrieb bleiben explizite offene Voraussetzungen.

Siehe [ADR 025](../architecture/adr-025-company-blueprint-license-origins.md), [Datenmodell](../architecture/domain-model.md), [ERD](../architecture/erd.md#firmen-blueprint-zuweisungen-und-lizenzquellen-migration-026) und [Implementierungsstatus](../implementation-status.md).
