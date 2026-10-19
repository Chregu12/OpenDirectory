# ADR 024: eigene Blueprint-Aggregate statt globaler Rollenabkürzung

Status: Accepted für lokale Entwürfe, immutable Freigaben und kontrollierte Wiederherstellung; kein vollständiger BR-004.

## Kontext

Slice 20 konnte vorhandene globale Policy-Blueprints vergleichen. Das erteilte einem tatsächlichen Firmeninhaber keine mandanteneigene Blueprint-Verwaltung. Neue Tenant-Zeilen in die bestehenden global gelesenen Tabellen einzufügen oder `policies.manage` aus Ownership abzuleiten würde die vorhandene Berechtigungsgrenze verletzen.

## Entscheidung

Ein eigener begrenzter Domain-Einstieg `/api/company-blueprints` mit separaten `company_blueprint_*`-Relationen und elf Feldern ursprünglicher eigener Authority. Die drei neuen Company-Rechte werden nur durch tatsächliche Ownership beziehungsweise aktuelle kanonische Home-Administration mit frischer MFA bestätigt. Globale Rollen, bestehende feste Rechte und Source 036 bleiben unverändert.

Das vorhandene Policy-Backend, PostgreSQL, Original-Bearer-Source-Muster und konservative SQL-Konfliktberechnung werden wiederverwendet. Keine neue Runtime, Datenbank, Queue, Dependency oder freie Workload-Authority. Der Einstieg wird nach OIDC-Prüfung, aber vor dem sachlich anderen globalen Policy-Guard montiert; der Guard selbst erhält keine breite Ausnahme.

Mutable Aggregate-Revision und immutable Freigabenummer sind getrennt. Wiederherstellen erzeugt nur einen neuen Entwurf; eine anschliessende ausdrückliche Freigabe erzeugt eine weitere immutable Version. Aktuelle Source-/App-Fristen werden am physischen Commit geprüft. Exakte idempotente historische Recovery liest ihren ursprünglichen Beleg, überschreibt keinen neueren Kopf und erneuert keine alte Berechtigung.

Die drei strukturierten lokalen Konfigurationen erlauben nur bekannte Zahlen-/Boolean-Felder. Nicht unterstützte Geheimnisträger bleiben bis zu einem Secret-Referenzvertrag ausgeschlossen. Gewünschte Apps referenzieren tatsächliche eigene Pools unter unabhängiger bestehender App-Authority. Freigaben speichern nur deren damalige Metadaten; laufende Lizenzrevisionen sind kein dauerhafter Blueprint-Gültigkeitsnachweis. Keine Allocator- oder Gerätewirkung.

## Folgen

- Firmeninhaber können reale, isolierte lokale Blueprints ohne globale Policy-Administratorrolle verwenden.
- Vorhandene globale Publikations-/Device-Admission-Grenzen bleiben unabhängig und akzeptieren diese neuen IDs nicht als vorhandene globale Ressourcen.
- Begrenzte Konfigurationsdokumente sind Aggregate, keine beliebige neue Entitätstabelle pro Providerfeld. Relationale Tenant-/Parent-/Version-/Event-Verknüpfungen sichern den Lebenszyklus; tatsächliche App-Pool-Referenzen werden am Domain-Grenzübergang geprüft.
- Lokale Freigabe ist ein unveränderliches Artefakt, keine unabhängige Vier-Augen-Deployment-Genehmigung oder erfolgreiche MDM-Ausführung.
- Organisationsscopes, delegierte Company-Rollen, tatsächliche Blueprint-Lizenzallokation und Provider-Prozesse müssen anschliessend explizit auf diesem eigenen Domain-Vertrag aufbauen.
- Ein Angreifer mit SQL-/DDL-Owner-Rechten ist nicht durch dieselbe Anwendung autorisiert. Produktive DB-Rollentrennung, unabhängige Retention und Cross-Service-Revocation-Garantien bleiben separat nachzuweisen.
