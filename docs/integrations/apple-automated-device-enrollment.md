# Apple Business / Apple School Manager: Automated Device Enrollment

Stand: 21. Oktober 2026. Das frühere Device Enrollment Program (DEP) heisst heute Automated Device Enrollment (ADE). Der bestehende API-Pfad mit `/dep/` bleibt aus Kompatibilitätsgründen erhalten.

## Einrichtung und Beschaffung

1. Organisation bei Apple registrieren und die Administrationsrechte einrichten.
2. Vor dem Kauf mit einem teilnehmenden Händler die Zuordnungsfähigkeit der konkreten Geräte klären und die Organisations-/Händler-IDs austauschen.
3. Bei Apple einen Managementdienst verknüpfen und die Geräte zuweisen. Beim MDM Enrollment-Einstellungen und die gewünschte Konfiguration vorbereiten.
4. Das zugewiesene Gerät mit Internetverbindung einrichten. Die Registrierung erfolgt beim MDM; dieser stellt unterstützte Einstellungen und Apps bereit.

Die Verfügbarkeit eines Geräts im Handel garantiert keine automatische Apple-Zuordnung. Die konkrete Lieferkette und Zuordnung vor der Beschaffung mit dem Lieferanten klären. Händlerbezogene Aussagen aus einem fremden Angebot sind keine Zusage von OpenDirectory. Grundlagen: [Apple für Unternehmen](https://www.apple.com/chde/business/enterprise/) und Apples Handbuch zu [Gerätelieferanten](https://support.apple.com/guide/business/axmef1c47493/web).

## Apple Configurator

Unterstützte Geräte lassen sich auch ausserhalb der üblichen Beschaffung über Apple Configurator hinzufügen. Anschliessend müssen sie einem Managementdienst zugewiesen werden. Dabei gilt eine **vorläufige Frist von 30 Tagen**, in der der Benutzer die Bindung und Verwaltung entfernen kann. Modell-/OS-Voraussetzungen und ein allenfalls notwendiges Löschen vorab anhand von [Apples Anleitung](https://support.apple.com/en-gb/guide/business/axm200a54d59/web) prüfen.

## Grenze in OpenDirectory

Der bisherige DEP-Pfad enthielt fünf erfundene Seriennummern und änderte nur einen lokalen Speicher. Diese Simulation wurde entfernt. Beide Endpunkte melden jetzt `503 apple_ade_not_configured`; sie bestätigen keine Registrierung und keine Zuweisung. Die Anzeige unterscheidet einen fehlgeschlagenen Abruf von einem leeren Inventar.

Ein echter Connector mit autorisiertem Organisationszugriff, Geräteabgleich, geprüften Zuweisungsbelegen und Test-Tenant-Abnahme bleibt offen. Fernlöschen, Sperren und Neustarten benötigen eine tatsächlich funktionierende, geeignete MDM-Anbindung. Apple-Zuweisung, lokaler Blueprint, MDM-Registrierung und bestätigter Gerätebefehl sind eigene Ergebnisse. Siehe [Capability-Matrix](apple-capability-matrix.md).

[SAML und OIDC](../../services/core/oauth-provider/README.md) betreffen die Anmeldung an Anwendungen. Sie ersetzen weder ADE noch APNs und belegen keine Apple-Account-Föderation.
