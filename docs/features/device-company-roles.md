# Geräteaufgaben über eigene Firmenrollen und PIM

Ab Version **1.0.50** können Rollenverwalter unter **Administration → Firmenrollen** getrennte Geräteaufgaben an eigene Personen oder geschützte statische Rollengruppen vergeben. Die vorhandenen direkten Vergaben, PIM-Berechtigungen, Selbstaktivierung, unabhängige Genehmigung und Kontrollhistorie werden weiterverwendet. Es werden keine globalen Tokenrollen erzeugt.

| Auswählbare Aktion | Tatsächlicher Zugriff |
| --- | --- |
| `devices.inventory.read` | Inventar, Gerätehistorie, Filter/CSV, Agent-Status, Hardware, Synchronisierungsverlauf und Rückgabehistorie lesen |
| `devices.inventory.create` | Geräte erfassen, Stammdaten/Lebenszyklus ändern, Agent-Zugang ausstellen/widerrufen, Synchronisierung anfordern/abbrechen |
| `devices.inventory.assign` | Personen zuweisen/freigeben, bestehende Rückgaben bestätigen/abbrechen; Rückgabeanforderungen benötigen zusätzlich den echten ursprünglichen Offboarding-Beleg |
| `devices.compliance.read` | Eigene Gerätebewertungen, Compliance-Übersicht, Richtlinien und Historie lesen |
| `devices.compliance.manage` | Eigene Plattformrichtlinien begründet und versioniert ändern |

Inventar-Schreibrechte benötigen ausdrücklich zusätzlich **Geräte und Hardware lesen**; Compliance-Verwaltung benötigt **Geräte-Compliance lesen**. Der Editor zeigt diese Voraussetzung und verhindert eine unvollständige Auswahl. API und SQL-Constraint prüfen sie unabhängig. Inventarleser erhalten keine Profil-, Zuweisungs-, Stock- oder Compliance-Verwaltung. Ein Compliance-Recht erteilt keinen allgemeinen Inventarzugriff. Fehlendes Compliance-Recht entfernt ausschließlich diesen getrennten Detailabschnitt, ohne erlaubte Inventardaten zu verbergen.

## Einrichten und aktivieren

1. Als tatsächlicher eigener Firmeninhaber/Rollenadministrator eine eigene Definition mit den gewünschten Aktionen und maximaler Dauer erstellen, beispielsweise **Geräterückgaben** mit Lesen und Zuweisen. Begründung und Bestätigung bleiben erforderlich.
2. **Rolle vergeben** öffnen. Eine andere aktive eigene Person oder eine geschützte Rollengruppe auswählen. Standard ist **Berechtigt · eigene PIM-Aktivierung erforderlich**. Geräteaktionen unterstützen ausschließlich **Eigene Firma**; ein Benutzer-OU-Scope kann keine tenantweiten Geräterechte erzeugen.
3. Die berechtigte Person aktiviert unter **PIM → Firmenrollen** ihre Aufgabe ausdrücklich. Eine gegebenenfalls konfigurierte unabhängige Genehmigung bleibt verbindlich. Zuweisung allein erteilt keine aktiven Rechte.
4. Navigation und Geräteansichten verwenden die tatsächlichen aktuellen Pflichten. Reine Leser sehen keine Schreibaktionen. Die Benutzerwahl benötigt weiterhin separat `users.read`; ohne Profilrecht bleibt die bekannte kanonische Benutzer-ID verwendbar.
5. **Beenden**, administrative Rücknahme, Eligibility-Entzug, geänderte Definition oder entfernte ursprüngliche Gruppenmitgliedschaft beenden die entsprechende Quelle. Historische Belege bleiben erhalten. Eine spätere neue Mitgliedschaft übernimmt keine alte Aktivierung.

Eine eigene PIM-Aktivierung kann bis zu zehn Stunden gelten. **Für Gerätezugriffe bleibt die ursprüngliche fünfminütige MFA-Frische verbindlich**, ebenso eine strengere aktuelle Anmelderichtlinie und der ursprüngliche Tokenablauf. Die neue Gerätequelle verlängert dieses Fenster nicht. Neue eigene Rollen verändern die bestehenden Engineering-/Admin-/Owner-Rechte nicht.

## Quelle und Protokollierung

Identity-Migration `060_device_company_roles.sql` erweitert denselben bisherigen Rollenkatalog von vierzehn Verzeichnisaktionen um die fünf Geräteaktionen. OU-Scopes bleiben auf die bisherigen drei Benutzeraktionen begrenzt. Es gibt keine automatische Rechtevergabe, Gruppenübernahme oder Änderung bestehender Definitionen.

Die originale Identity-Hoheit löst direkte oder tatsächlich aktivierte Rollen live auf: eigene Definition/Revision, eigener Tenant, Empfänger-Generation, Ablauf, Widerruf, geschützte Gruppenmitgliedschaft und Review sowie beim PIM die ursprüngliche Aktivierung/MFA-/Actor-Bindung. Pro ausgegebener Pflicht wird genau eine deterministisch ausgewählte tenantweite Quelle erfasst. Die Antwort enthält zusätzlich `delegation.grants`, einschließlich Grant-/Eligibility-ID, Rollen-ID/-Revision und gegebenenfalls Aktivierungs-ID und ursprünglicher Mitgliedschaft. `validUntil` wird durch sämtliche ausgewählten Quellen zusätzlich begrenzt.

Der Device-Empfänger prüft die Antwort unabhängig gegen den ursprünglichen menschlichen Bearer, Kontext, Zweck, Deadline und exakte Quellenstruktur. Teilrechte ohne Delegationsbeleg werden nicht als alte Vollberechtigung angenommen. Der Gateway bestätigt weiterhin den tatsächlichen Receiver. Jede API prüft die konkret erforderliche Pflicht; eine lesende Rückgabe-Capability autorisiert keine Entscheidung.

Bestehende atomare Inventar-, Agent-, Policy-, Synchronisierungs- und Rückgabebelege erhalten die verwendete Quelle. PIM-Aktivierung/Beendigung behalten ihre eigene sichtbare Historie. Device-Migration `012_delegated_device_returns.sql` ergänzt die tatsächliche Rückgabevalidierung um Teilrechte und ursprüngliche Quellen; manuelle Bestätigung verwendet weiterhin denselben kanonischen Inventar-Entzug. Bekannte ursprüngliche Deadlines, Versionsschutz und physische Commit-Guards bleiben erhalten.

Identity und Device verwenden getrennte Datenbanken. Live-Checkpoints verhindern die Nutzung einer zwischen den Prüfungen erkennbar entzogenen Quelle; eine augenblickliche verteilte Commit-/Widerrufsgarantie wird nicht behauptet. SQL-Betreiber bleiben Vertrauensgrenze. Lokale Pending-Outbox ist keine bestätigte externe Zustellung.

## Abnahme und offene Punkte

[Prüf- und Liefernachweis](../deployment/device-company-roles-2026-11-14.json) für Version 1.0.50 und Helm-Revision 85.

Echte getrennte PostgreSQL-Schemas prüfen Lesen/Zuweisen ohne Profilausweitung, PIM-basierte Geräteänderungen, Rücknahme während einer gehaltenen Schreibtransaktion mit vollständigem Rollback, abgelehnte Geräte-OU-Vergaben, Migration-Replay, unabhängige Compliance-Verwaltung sowie echte Offboarding-Rückgabe und atomaren Inventarentzug. Ein zusätzlicher signierter OAuth-/Gateway-/PostgreSQL-Prozess prüft die Geräte-PIM-Aktivierung ohne globale Engineering-/Adminrolle. Browser prüfen Definition/Eligibility, Leserechte und Beenden auf Desktop/Mobil sowie die bisherigen Geräteprozesse gegen das gebaute Produktionsimage. Die Tests verwenden isolierte Konten und Datenbanken.

Geräte-OU-/Gerätegruppenscopes, weitere Geräte-/Lizenzaktionen, vollständiges MDM, Betriebssystemsignierung und physische Agent-Abnahmen bleiben Teil des [offenen Gesamtauftrags](../implementation-worklist.md).
