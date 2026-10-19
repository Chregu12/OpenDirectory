# OpenDirectory Business: Produktvision

Stand: 19. Oktober 2026. Verbindliche neue Produktausrichtung aus dem Apple-Business-Master-Prompt. Der bisherige Entra-Ausbau ist ein Teil des Identity-Moduls, nicht mehr die gesamte Produktvision.

## Ziel

Eine eigenständige, einfach bedienbare Business-Management-Plattform für Unternehmen: Organisation, Mitarbeitende, Geräte, Blueprints, Anwendungen und Lizenzen in einem Portal. Später folgen Standorte, Marketing, Abrechnung, Support und Collaboration. Produktname, Komponenten und Gestaltung bleiben eigenständig; Apple-Marken und Logos werden nicht übernommen.

Ein einfacher Ablauf steht vor technischer Funktionsfülle:

1. Unternehmen registrieren und den ersten Administrator sicher einrichten.
2. Organisationseinheiten und Mitarbeitende anlegen.
3. Gruppen und passende, möglichst kleine Berechtigungen zuweisen.
4. Geräte erfassen und Mitarbeitenden zuordnen.
5. Apps und Konfigurationen über freigegebene Blueprints zuweisen.
6. Tatsächlichen Lizenzbedarf, Fortschritt und Fehler nachvollziehen.

Standorte, Kampagnen und externe Veröffentlichungen gehören weiterhin zum vollständigen Ziel, nicht zur ersten Core-Demo. Die 16 Schritte der geforderten Enddemo werden in der [Statusübersicht](../implementation-status.md) getrennt nachgewiesen.

## Produktprinzipien

- Bestehende Next.js-/TypeScript-, Node-/Express- und PostgreSQL-Komponenten wiederverwenden. Kein paralleler Laravel-/Vite-Neubau.
- Die Standardoberfläche konzentriert sich auf Geschäftsaufgaben. Fortgeschrittene Infrastruktur gehört nicht in jeden Onboarding-Schritt.
- Least Privilege, strikte serverseitige Mandantentrennung und MFA bei privilegierten Aktionen sind kein optionaler Expertenmodus.
- Eine gespeicherte lokale Zuweisung ist weder eine ausgeführte Geräteaktion noch eine beim Hersteller bereitgestellte Lizenz.
- Kein Erfolg ohne tatsächliche Bestätigung. Keine erfundenen Standortdaten, Kennzahlen oder unsichtbar simulierten Speichervorgänge.
- Fehlende Integrationen werden als nicht verfügbar angezeigt. `External Dependency` ersetzt keine fehlende eigene Implementierung.
- Vorhandene technische Teiltests machen eine gesamte Business Capability nicht fertig. Dafür gelten alle zehn DoD-Punkte des Master-Prompts.

## Erste Lieferreihenfolge

1. Ist-Zustand und Grenzen festhalten, Scheinfunktionen aus der Produktdarstellung entfernen.
2. Eigenes Organisationsprofil vollständig durch Datenbank, API, Berechtigungen, Oberfläche und Tests führen.
3. Registrierungs-/Erstadministrator-Workflow mit überprüfbarem Bootstrap implementieren; keine erfundene oder dauerhafte globale Administratorberechtigung.
4. Mitarbeitenden-/Gruppen-/OU-Prozess und Geräteinventar zu einem ausführbaren Core-Workflow verbinden.
5. Blueprints, effektive Konfigurationen, App-Zuweisungen und Lizenzallokation integrieren.
6. Erst danach zusätzliche Business-Domains und freigegebene externe Provider anschliessen.

Diese Reihenfolge ist kein Verzicht auf spätere Anforderungen. Eine vollständige SaaS-Plattform oder produktionsfähige Apple-Integration wird durch diesen Plan noch nicht behauptet.

## Referenzen

- [Apple Business: Benutzerhandbuch](https://support.apple.com/de-ch/guide/business/welcome/web): fachliche Orientierung, nicht unsere Implementierungsdokumentation.
- [Ponytail](https://github.com/DietrichGebert/ponytail): vorhandene Bausteine zuerst, kleinste vollständige Lösung, keine Kürzungen bei Sicherheit, Validierung oder Tests.
- [Integrationsgrenzen](../integrations/apple-capability-matrix.md) und [konkrete Lücken](../implementation-status.md).
