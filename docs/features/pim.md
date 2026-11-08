# PIM-Aufgabengruppen

Die kanonische PIM-Verwaltung liegt im Identity-Service unter `/api/identity/pim`. Die Übersicht (`/dashboard`) zeigt die tatsächlich eingerichteten Aufgabengruppen und eigene Berechtigungen, Anträge und Aktivierungen. `/pim` ergänzt die Gruppen-, Benutzerzuweisungs- und Rollenrichtlinienverwaltung.

## Getrennte Aufgaben

Migration **056** legt für bestehende Firmen sechs Gruppendefinitionen an. Dabei entstehen keine Benutzerberechtigungen und keine aktiven Rollen.

| Gruppe | Kanonische Rolle | Aufgabe |
| --- | --- | --- |
| Engineering | `device-enrollment-operator` | Geräteaufnahme vorbereiten und ausführen |
| Lizenzen | `license-administrator` | Lizenzbestand und Zuweisungen verwalten |
| Benutzerverwaltung | `user-administrator` | Verzeichnisbenutzer verwalten |
| Apps & SSO | `application-administrator` | Registrierte Anwendungen verwalten |
| Richtlinien-Rollout | `policy-deployment-operator` | Richtlinienbereitstellung ausführen |
| Global Security | `admin` | Vollständige kanonische Administration |

Eine Gruppe umfasst genau eine bestehende Katalogrolle mit deren tatsächlich durchgesetzten Rechten. Weitere Gruppen können mit Namen, Beschreibung, Rolle und Laufzeitlimit angelegt werden. Rolle und Limit einer angelegten Gruppe sind unveränderbar; eine andere Berechtigung wird als neue Gruppe eingerichtet und ausdrücklich neu zugewiesen.

Verzeichnisgruppen und diese PIM-Aufgabengruppen sind getrennte Datenbestände. Die Aktivierung vergibt eine kanonische OpenDirectory-Rolle. Sie verändert keine AD-, LDAP-, Rancher- oder SaaS-Gruppenmitgliedschaft.

## Benutzer berechtigen und aktivieren

1. Unter **Benutzer** einen Eintrag öffnen und **PIM-Gruppen zuweisen** wählen, oder unter `/pim` bei der Gruppe **Benutzer zuweisen** öffnen.
2. Benutzer, maximale Aktivierungsdauer, Berechtigungsfrist und Begründung auswählen und bestätigen. Eine Zuweisung macht den Benutzer nur berechtigt. Eine Selbstvergabe von Eligibility bleibt verboten.
3. Der berechtigte Benutzer beantragt auf der Übersicht genau diese Aufgabe mit Laufzeit und Begründung.
4. Ein unabhängiger berechtigter Prüfer genehmigt den Antrag. Eigene Anträge können nicht selbst genehmigt werden. Für Global Security sind die vorhandenen Schutzregeln für `admin` maßgeblich: ein anderer Administrator oder ausdrücklich konfigurierte zulässige PIM-Prüfer.
5. Der Benutzer aktiviert den genehmigten Antrag mit einer höchstens fünf Minuten alten, nachweislich gebundenen OpenDirectory-MFA. Die Freigabe selbst gilt fünf Minuten. Nach Aktivierung startet eine neue Anmeldung, damit der Token den geänderten kanonischen Rollenstand erhält.

Die Obergrenze beträgt **zehn Stunden**. Maßgeblich ist das Minimum aus Gruppenlimit, aktueller Rollenrichtlinie, Benutzer-Eligibility und deren verbleibender Frist. Bestehende Rollenrichtlinien behalten ihre Werte; viele bestehende Rollen sind weiterhin auf acht Stunden begrenzt, bis ein berechtigter Richtlinienverwalter die Rolle ausdrücklich anders konfiguriert. Die gesperrte Basisrolle `user` behält ihre feste Richtlinie. Strengere MFA-, App-, Mandanten- und Governance-Regeln gelten weiter.

Ein aktiver Benutzer kann die Aktivierung vorzeitig beenden. Berechtigte Verwalter können die Zuweisung entziehen oder die gesamte Gruppe deaktivieren. Der Entzug verwendet die bestehenden PIM-Revocations und beendet zugehörige tatsächliche Rollenleases. Am gespeicherten Ablauf entfallen die Rollen bei der kanonischen Rechteberechnung auch ohne geöffneten Browser. Alte Token und Refresh-Grants passen dann nicht mehr zum Rollenstand.

## Global Security und dauerhafte Rechte

Global Security aktiviert die bestehende vollständige `admin`-Rolle. Eine Gruppenzuweisung allein erteilt diese Rolle nicht. Schutz, unabhängige Freigabe, MFA, Laufzeit und Audit gelten auch hier.

Bereits dauerhaft vergebene Rollen werden nicht automatisch entfernt. Die Übersicht kennzeichnet bestehende dauerhafte Adminrechte ausdrücklich. Für einen Betrieb ausschließlich über PIM muss die verpflichtende Rollenrichtlinie einschließlich unabhängigem Freigabe- und Wiederherstellungsweg eingerichtet werden. Bestehende Sicherungen gegen Aussperren des letzten Administrators bleiben erhalten.

## Protokollierung und Vertrauensgrenzen

Das Gruppenprotokoll zeigt Konfigurationsanlage und Deaktivierung, Benutzerberechtigung und Entzug, Antrag, Genehmigung oder Ablehnung sowie Aktivierung und Beendigung. Es enthält handelnde und betroffene Person, Rolle, Begründung, Zeitpunkt, Dauer und gespeichertes geplantes Ende. Eigene Vorgänge bleiben für den betroffenen Benutzer lesbar; fremde Vorgänge erfordern die vorhandene PIM-Leseberechtigung innerhalb derselben Firma.

`identity_pim_group_audit`, `identity_pim_audit` und die Rollenbelege sind gegen normale Änderung und Löschung geschützt. Gruppen- und Eligibility-Bindung sind unveränderbar. Fachänderungen behalten zusätzlich die Auditprotokolle des jeweiligen Dienstes; das PIM-Protokoll erfasst den PIM-Lebenszyklus.

Schreibaktionen verwenden den originalen authentifizierten menschlichen Bearer, aktuelle kanonische Rollen, Home-Tenant-Prüfung und die bestehenden Authority-Checkpoints. Gruppe, Zielbenutzer und Rolle werden auf dem Server gebunden. Ein Auditfehler oder entzogenes Originalrecht rollt Wirkung und Belege gemeinsam zurück. Alle bestehenden Empfänger-Fences für eingeschränkte Automationen, Offboarding und Employee-Enrollments sind auch auf den neuen Tabellen aktiv. Physische Datenbankbesitzer bleiben die bestehende explizite Vertrauensgrenze.

Neue Firmen ohne Gruppen können diese über **Standardgruppen einrichten** durch einen berechtigten Administrator anlegen lassen. Unbestätigte Schreibantworten führen zum Readback; sie werden nicht automatisch erneut geschrieben.
