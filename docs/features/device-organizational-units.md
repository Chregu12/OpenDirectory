# Geräte einer Organisationseinheit zuordnen

Im Detailbereich von `/devices` lässt sich ein eigenes Inventargerät einer bestehenden eigenen Organisationseinheit zuordnen, umordnen oder aus ihr entfernen. Die Benutzerzuweisung bleibt unabhängig. Eine Änderung benötigt eine Begründung und eine ausdrückliche Bestätigung. Die Oberfläche zeigt erst nach dem bestätigten SQL-Commit einen Erfolg und bietet den erhaltenen Änderungsverlauf an.

Dies ist eine organisatorische Inventarzuordnung. Geräte-OU-/Gerätegruppenscopes für Rollen und PIM sind weiterhin offen; diese Zuordnung erweitert keine Berechtigung. Name, Eltern-ID, Eigentümergeneration und Version der OU werden als Stand der bestätigten Änderung gespeichert. Eine spätere Umbenennung, Verschiebung oder Löschung in Identity aktualisiert diese historische Angabe nicht. Eine getrennte aktuelle Auskunft zeigt, ob die ursprüngliche OU noch bestätigt ist oder sich geändert hat. Gerätebezogene Berechtigungsnachweise, Hierarchiescopes und dienstübergreifende Löschabhängigkeiten bleiben vor einer Nutzung als Berechtigungsscope erforderlich.

## Rechte und Änderungen

- Lesen von Zuordnung und Verlauf: aktuelles `devices.inventory.read` im eigenen Tenant.
- Zuordnen, Umordnen und Entfernen: aktuelles tenantweites `devices.inventory.create` mit frischer menschlicher MFA.
- Auswahl einer OU: zusätzlich aktuelles `ous.read`; es werden ausschließlich eigene OUs mit serverseitiger Suche und 25 Einträgen pro Seite angeboten. Eine fehlende OU-Leseberechtigung sperrt die Auswahl, ohne die erlaubte Inventaranzeige zu entziehen.
- Entfernen benötigt keinen neuen OU-Lesezugriff; der vorhandene Stand bleibt im Verlauf erhalten.

Der öffentliche Schreibaufruf enthält ausschließlich `ou` (UUID, Eigentümergeneration und Version oder `null`), `reason` und `confirm: true`. Der starke `If-Match`-Wert bindet die Geräteversion und die unabhängige OU-Zuordnungsversion. Eine inzwischen geänderte Auswahl oder Zuordnung führt zu `412`; es gibt keinen automatischen Schreibwiederholungsversuch. Ein unveränderter Stand führt zu `409`. Ein älterer Geräteempfänger mit `501` bietet keine OU-Aktion an.

## Aktueller OU-Stand

Bei einer gespeicherten Zuordnung fragt die Oberfläche zusätzlich den aktuellen OU-Stand ab. Die Auskunft unterscheidet:

- `current`: eigener UUID-/Generationsbezug, Name, Eltern-ID und Version stimmen mit dem gespeicherten Stand überein.
- `changed`: die ursprüngliche eigene OU besteht noch, wurde aber geändert. Aktueller Name und Version werden getrennt angezeigt. Ein bewusster neuer Zuordnungsvorgang kann den aktuellen Stand mit neuem Protokolleintrag übernehmen.
- `not-current`: die ursprüngliche eigene OU mit genau dieser Eigentümergeneration wird nicht mehr bestätigt. Es werden keine aktuellen Metadaten einer fremden oder ersetzten Ressource zurückgegeben.
- `unassigned`: es besteht keine gespeicherte OU-Zuordnung.

Die Abfrage benötigt ausschließlich `devices.inventory.read` und bei zugeordneter OU zusätzlich `ous.read`. Sie benötigt weder Inventar-Schreibrecht noch Benutzerprofile. Fehlt nur das zusätzliche OU-Leserecht, bleibt die erlaubte Inventaranzeige mit ihrem gespeicherten Zuordnungsstand nutzbar. Ein tatsächlicher Inventar-/Sitzungsentzug bleibt ein Sicherheitsfehler. Netzwerk-, Protokoll- und Empfangsfehler werden als unbestätigte Auskunft angezeigt, niemals als erfolgreiche aktuelle Zuordnung. Bei einem älteren Status-Empfänger mit `501` erscheint keine Status-Aktion.

`GET .../organizational-unit/status` verlangt den ursprünglichen starken `If-Match`-Wert der gespeicherten Zuordnung. Das öffentliche Ziel enthält keine freie OU-Auswahl: Device löst UUID und Eigentümergeneration aus der tatsächlich eigenen Gerätezuordnung auf. Identity prüft die ursprüngliche Leseberechtigung, aktuelle eigene Ressource und gegebenenfalls ursprüngliche OU-Lesevergabe mehrfach. Device vergleicht die lokale Zuordnung erneut, auch nach der letzten Identity-Antwort. Eine neue Vergabe rettet keine alte Antwort; veraltete Zuordnungsstände oder erkannte Änderungen führen zu `412`.

Die Auskunft schreibt keine Geräte-, Zuordnungs-, Ereignis- oder Outbox-Zeilen. Sie enthält einen Prüfzeitpunkt und die ursprüngliche Frist `validUntil`; die Anzeige wird bei Fristablauf und Sitzungsverlust verworfen. Sie ist eine zeitgebundene lesende Auskunft und kein Berechtigungsbeleg für Geräteaktionen. Separate Identity-/Device-Datenbanken liefern damit weiterhin keine augenblickliche verteilte Widerrufsgarantie.

## Empfang und Protokollierung

Identity löst den ursprünglichen menschlichen Bearer, die aktive Firmenbindung, die Inventarberechtigung und gegebenenfalls die ursprüngliche OU-Lesevergabe auf. Device übernimmt keine vom Browser gelieferten Quellen. Es fragt die Quelle vor der Änderung und nochmals vor dem Commit ab. Ersatzvergaben retten einen bereits begonnenen Vorgang nicht; die ursprüngliche Quelle und Auswahl müssen unverändert bleiben. Token-, MFA- und Vergabefristen begrenzen den Nachweis.

Migration `013_device_organizational_units.sql` ergänzt vier Tabellen. Zuordnung, unveränderliches Ereignis und lokaler Outbox-Beleg werden zusammen geschrieben und beim physischen Commit überprüft. Der Verlauf enthält Akteur, Begründung, Zeitpunkt, Korrelation und Vorher-/Nachherstand; private Token-/Vergabenachweise werden nicht an den Browser ausgegeben. `deliveryStatus: pending` bedeutet ausschließlich einen lokalen Beleg, keine bestätigte Zustellung an einen externen Dienst. Die Geräteversion und die bisherige Benutzerzuweisung werden durch eine OU-Änderung nicht verändert.

Die fünf privaten SQL-Routinen haben einen festgelegten Suchpfad, gesperrte öffentliche Ausführung und ein überprüftes Manifest. Empfangs-, Lösch-, Truncate- und verzögerte Commit-Sicherungen müssen vollständig vorhanden sein. Die additive Migration kann erneut ausgeführt werden und erhält vorhandene Zuordnungen und Historien.

Identity und Device verwenden getrennte Datenbanken. Die erneute Quellenprüfung unmittelbar vor dem Device-Commit stellt keine verteilte Transaktion oder augenblickliche dienstübergreifende Widerrufssperre her.

## APIs und Prüfung

| Route | Zweck |
| --- | --- |
| `GET /api/devices/organizational-units` | Eigene OU-Auswahl mit Suche und Seiten |
| `GET /api/devices/{id}/organizational-unit` | Erhaltener Zuordnungsstand und ETag |
| `PUT /api/devices/{id}/organizational-unit` | Bestätigte Änderung mit ursprünglicher Auswahl und ETag |
| `GET /api/devices/{id}/organizational-unit/history` | Eigener erhaltener Verlauf mit Seiten |
| `GET /api/devices/{id}/organizational-unit/status` | Aktueller eigener OU-Stand für den ursprünglichen Zuordnungs-ETag |
| `GET/POST /api/identity/device-organizational-units` | Ursprüngliche Auswahl beziehungsweise privater Berechtigungsnachweis |
| `POST /api/identity/device-organizational-units/status` | Getrennter ursprünglicher Lesenachweis und aktuelle eigene OU-Metadaten |

Die Verträge sind Bestandteil der kanonisch erzeugten OpenAPI-Datei. Native PostgreSQL-Fälle prüfen eigene/fremde Ressourcen, getrennte Rechte, Seiten, unveränderte Gerätezuweisung, veraltete Auswahl, Quellenersatz, Fristablauf, fehlende Belege, späte Zustandsänderung und Migration-Replay. Die Web-Tests prüfen Bestätigung, Sitzungsverlust und veraltete Antworten. Playwright prüft die Darstellung und Bedienung bei 390 und 1440 Pixeln; der tatsächliche Firmenregistrierungsablauf verwendet zusätzlich echte OAuth-, Identity-, Device- und PostgreSQL-Dienste. Der konkrete Abnahmestand steht im [Prüfbericht](../testing/device-organizational-units-2026-11-15.json); ein produktiver Rollout dieses Bausteins ist separat erforderlich.

Die zusätzliche Live-Auskunft ist im [Status-Prüfbericht](../testing/device-ou-current-status-2026-11-15.json) getrennt belegt. Geräte-OU-/Gruppenrechte bleiben Teil des offenen Gesamtauftrags.
