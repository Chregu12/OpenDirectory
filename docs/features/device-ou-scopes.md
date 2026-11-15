# Geräte-OU-Scopes (in Arbeit)

Dieser Zweig ergänzt den eigenen Rollen-/PIM-Kern um den ausdrücklich getrennten Scope `device-ou`. Die Erweiterung ist noch nicht produktiv und erfüllt die Geräte-Capability noch nicht vollständig. Bestehende Device-Empfänger akzeptieren ausschließlich tenantweite Quellen und lehnen die neuen begrenzten Quellen ab. Die Oberfläche bietet noch keine Geräte-OU-Vergabe an.

`tenant` behält die bisherige Wirkung. `ou` bleibt auf die drei bisherigen Benutzeraktionen begrenzt. `device-ou` bindet die ursprüngliche eigene OU samt Eigentümergeneration und darf ausschließlich `devices.inventory.read`, `devices.inventory.create`, `devices.inventory.assign` und `devices.compliance.read` enthalten. Benutzeraktionen, gemischte Verzeichnisrollen und die tenantweite Compliance-Richtlinienverwaltung sind ausgeschlossen. Bestehende tenantweite Pflichten bleiben unabhängig wirksam; eine zusätzliche begrenzte Quelle darf sie weder erweitern noch entziehen.

Migration `062_device_ou_scopes.sql` erweitert die bestehenden Grant-/Eligibility-Constraints und sechs versionierte Quell-/Änderungsroutinen. Direkte Vergaben, geschützte statische Empfängergruppen, eigene PIM-Aktivierung, unabhängige Genehmigung, einmaliger Freigabeverbrauch, ursprüngliche Mitgliedschaft, Rolle/Revision, Ablauf und historische Belege verwenden weiterhin den vorhandenen Kernel. Die ursprüngliche OU-Generation wird in der privaten Quelle ausdrücklich als `ouGeneration` erhalten. Eine aktuelle Abfrage für `kind: device-ou` muss die ausgewählte eigene OU innerhalb der aktuellen eigenen Hierarchie bestätigen. Benutzer-OU-Mitgliedschaften sind dafür keine Gerätezuweisung.

Eine neue Mitgliedschaft oder ersetzte OU-Generation rettet keine alte Aktivierung oder Vergabe. Verschobene Unter-OUs folgen der aktuellen Hierarchie. Die Migration aktualisiert nur die tatsächlich geänderten, bereits versiegelten Funktionsnachweise und überprüft den vollständigen Rollenempfänger am Ende. Sie vergibt selbst keine Rollen und ändert keine vorhandenen Grants oder PIM-Anträge. Der additive vollständige Migrationslauf muss die vorhandenen Belege erhalten.

Der API-Vertrag 1.42.0 unterscheidet den neuen Scope in direkter Vergabe, Eligibility und Genehmigungsantrag. Ein gültiger Grant oder eine PIM-Aktivierung allein ist noch kein gerätebezogener Berechtigungsnachweis.

Vor einer Freigabe müssen folgende Teile zusammen fertig sein:

- Ursprüngliche menschliche Identity-Quelle mit aktueller OU-Generation, Hierarchie, Deadline und einer explizit versionierten Device-Empfangsgrenze.
- Tatsächliche lokale Geräte-/OU-Zuordnung und Version bei Listen, Zählungen, Filtern, CSV, Einzelgeräten und sämtlichen erhaltenen Gerätehistorien.
- Dieselbe Begrenzung bei Agent-, Hardware-, Compliance-, Synchronisierungs- und Rückgabeansichten.
- Gerätebezogene ursprüngliche Schreibbelege und physische SQL-Commit-Prüfungen für Änderungen, Zuweisung/Freigabe, Agent-/Sync-Verwaltung und Rückgabeentscheidungen; tenantweite Neuerfassung und Richtlinienänderung benötigen weiterhin eine entsprechende tenantweite Pflicht.
- Unabhängige Begrenzung von Änderungen der Geräte-OU selbst und überprüfte dienstübergreifende Verschiebungs-/Löschabhängigkeiten.
- Firmenrollen-/PIM-Oberfläche mit verständlicher Scope-Auswahl, tatsächlichen gerätebezogenen Rechten, Ablauf/Sitzungsverlust und ehrlichen Teilfehlern.
- Native PostgreSQL-, vollständige Linux-CI- und tatsächliche Browserabläufe sowie geprüfter separater Image-/Migrations-Rollout.

Die fünfminütige ursprüngliche Geräte-MFA-Frische bleibt verbindlich. Getrennte Identity-/Device-Datenbanken liefern weiterhin keine augenblickliche verteilte Widerrufsgarantie. Gerätegruppenscopes und die weiteren Anforderungen des [Gesamtauftrags](../implementation-worklist.md) bleiben offen.

Der [lokale Kern-Prüfbericht](../testing/device-ou-scope-kernel-2026-11-15.json) belegt 62 tatsächliche PostgreSQL-Fälle, 1’288 Identity-Unit-Fälle und sieben Policy-API-Prüfungen. Diese Nachweise ersetzen die oben noch offenen Device-/UI-/Rollout-Prüfungen nicht.
