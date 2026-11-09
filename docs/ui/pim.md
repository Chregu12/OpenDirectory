# PIM im Admin Center

Die Oberfläche orientiert sich am kompakten Aufbau von Microsoft Entra: Navigation links, Rollen als Tabelle und ein seitliches Formular für die Aktivierung. OpenDirectory bleibt als eigenes Produkt erkennbar; die bestehenden Rechteprüfungen gelten unverändert.

## Eigene Rollen aktivieren

Auf der Übersicht und unter `/pim` stehen dieselben Bereiche zur Verfügung:

- **Berechtigt:** eigene zugewiesene Gruppen und persönliche Rollen, die aktiviert werden können.
- **Aktiv:** laufende Aktivierungen sowie bereits direkt zugewiesene Rollen. Direkte Adminrechte werden ausdrücklich gekennzeichnet und durch PIM nicht eingeschränkt.
- **Meine Anträge:** Antragsstatus, Freigabe, Dauer und gegebenenfalls gespeichertes Ende.
- **Gruppen:** vorhandene Aufgabengruppen und die jeweils zulässigen Verwaltungsaktionen.
- **Genehmigungen:** nur für berechtigte PIM-Prüfer; eigene Anträge können nicht selbst genehmigt werden.

Bei einer berechtigten Zuweisung öffnet **Aktivieren** das Formular rechts. Dauer über Schieberegler oder Stundenfeld auswählen, eine Begründung eingeben und **Aktivieren** wählen. Dieser ausdrückliche Formularabschluss sendet den Antrag ohne zusätzlichen Bestätigungsdialog. Die zulässige Dauer berücksichtigt Rollen- und Gruppenlimit, Benutzerberechtigung und deren verbleibende Frist.

Die Oberfläche meldet einen Antrag als **ausstehend**, bis eine unabhängige Freigabe vorliegt. Eine Freigabe ist noch keine aktive Rolle. Der Benutzer aktiviert die freigegebene Rolle mit einem Klick und frischer MFA; anschließend startet eine neue Anmeldung für den geänderten Rollenstand. Es gibt keine automatische Genehmigung, Aktivierung oder Wiederholung unbestätigter Schreibvorgänge.

**Abbrechen**, das Schließen-Symbol und Escape schließen das Formular ohne Antrag. Dialogfokus und Tab-Tastenbedienung funktionieren auch auf kleinen Bildschirmen. Nach Ablauf einer Aktivierung wird die alte private Anzeige entfernt und eine neue Anmeldung angeboten.

## Gruppen verwalten und Vorgänge prüfen

Unter **Gruppen** können berechtigte Verwalter über **Zuweisen** einen Benutzer auswählen. Eine Zuweisung macht die Person nur berechtigt. Die eigene Eligibility muss ein anderer berechtigter Verwalter vergeben. Aus einem Benutzerprofil führt **PIM-Gruppen zuweisen** direkt zur Gruppenansicht mit vorausgewählter Verzeichnis-ID.

Das Menü **Weitere Aktionen** enthält **Protokoll**, **Zuweisungen anzeigen** und gegebenenfalls **Gruppe deaktivieren**. Das Protokoll zeigt echte paginierte PIM-Ereignisse mit Person, Begründung, Zeitpunkt und gespeichertem geplantem Ende. Verwaltungsänderungen und der Entzug von Rechten behalten ihre ausdrückliche Bestätigung.

Seltenere Einzelrollen- und Richtlinienwerkzeuge sind über **Weitere Rollen und Richtlinien** erreichbar. Ihre Daten werden erst beim Öffnen geladen. Die vollständigen verfügbaren Funktionen und Prüfungen bleiben erhalten.

Die gemeinsame Navigation liegt links. Ein ruhiger Kopfbereich, dezente Überschriften, Tabellen und flache Flächen ersetzen große Farbkacheln. Die Infrastrukturübersicht zeigt Kennzahlen und Anmeldungen jeweils einmal; Schnellaktionen bilden eine Befehlsleiste. Die Plattformverteilung ist bei Bedarf aufklappbar.

## Vorlagen

- [Microsoft: Gruppenmitgliedschaft mit PIM aktivieren](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/groups-activate-roles)
- [Microsoft: Gruppen in PIM verwalten](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/groups-discover-groups)
- [Ali Tajran: Entra PIM und Aktivierungsformular](https://www.alitajran.com/microsoft-entra-privileged-identity-management/)
- [cloudkaffee.ch: PIM-Grundkonfiguration](https://www.cloudkaffee.ch/microsoft-azure/privileged-identity-management-pim-konfiguration-onbaording/)
- [Apporetum: PIM-Rollen verwalten](https://docs.apporetum.com/docs/managing-apps/Configure-PIM-roles/)

[Rechte, Ablauf, API und Audit](../features/pim.md)
