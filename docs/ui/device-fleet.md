# Geräteverwaltung unter /devices

Die produktive Route verwendet `DeviceInventoryView.tsx`. Sie verwaltet das persistente Firmeninventar im Device-Service. `/fleet` öffnet dieselbe Ansicht.

1. Als Firmeninhaber, Administrator oder mit aktivierter PIM-Aufgabe Engineering anmelden. Die ursprüngliche MFA muss für Inventarzugriffe höchstens fünf Minuten zurückliegen. Bei Ablauf führt **Erneut anmelden** direkt zur Geräteansicht zurück.
2. **Gerät erfassen** öffnet das Formular für Inventarnummer, Seriennummer, Hersteller, Modell, Klasse, Plattform, Eigentum, Betriebssystemversion, Kaufdatum, Garantieende und Beschreibung.
3. Über Suche, Plattform, Status, Eigentum und Sortierung den serverseitigen Bestand eingrenzen. Seiten und Gesamtzahl stammen aus derselben Datenbanksicht. **CSV exportieren** lädt den vollständigen gefilterten eigenen Bestand mit höchstens 5000 Geräten; bei mehr Geräten muss der Filter eingeschränkt werden.
4. Eine Inventarnummer öffnet Details, Benutzerzuweisung und Historie. Die separat berechtigte Personen-API liefert den Benutzerpicker. Ohne Profilrecht kann eine bekannte kanonische Benutzer-ID eingegeben werden.
5. **Stammdaten bearbeiten** erhält die bestehende Benutzerzuweisung und verlangt eine Begründung. Die gespeicherte Revision muss weiterhin aktuell sein; Konflikte überschreiben keine parallelen Änderungen.
6. **In Wartung nehmen**, **Archivieren** und **Wieder bereitstellen** verlangen eine ausdrückliche Bestätigung und Begründung. Ein zugewiesenes Gerät muss zuerst freigegeben werden. Wartende und archivierte Geräte können erst nach Wiederbereitstellung neu zugewiesen werden. Archivieren löscht weder Gerät noch Historie.
7. Die Historie zeigt Akteur, Zeit, Version, ursprüngliche Zuweisungen, tatsächliche geänderte Felder und Begründung. Die lokale Outbox-Zustellung bleibt als ausstehend gekennzeichnet.

**Geräterückgaben öffnen** führt zum gesonderten bestätigten Rückgabeprozess. Eine einfache Freigabe einer Inventarzuweisung ist keine Bestätigung der physischen Rückgabe.

Eine Inventarzeile registriert keinen Agenten und kein MDM. Enrollment, Online-Status, Compliance, LAPS, BitLocker, App-Installation und Fernaktionen benötigen eine echte geprüfte Anbindung. Die Ansicht erfindet diese Daten oder Aktionen nicht. Die früheren `DevicesView`-/`DeviceFleetView`-Prototypen beschreiben keinen produktiven Funktionsumfang.
