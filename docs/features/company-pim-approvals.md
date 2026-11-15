# Unabhängige Genehmigung eigener PIM-Rollen

Eigene Firmen-Verzeichnisrollen können jetzt eine unabhängige Genehmigung vor der persönlichen Aktivierung verlangen. [Microsoft Entra beschreibt denselben grundsätzlichen Ablauf](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/groups-approval-workflow): Antrag, unabhängige Entscheidung und tatsächliche Aktivierung bleiben getrennte Schritte. OpenDirectory verwendet dafür seine bestehenden ursprünglichen Benutzer-, Tenant-, MFA- und Verzeichnisquellen.

## Richtlinie konfigurieren

Unter **Firmenrollen → Rolle öffnen → PIM-Genehmigung**:

1. **Unabhängige Genehmigung erforderlich** aktivieren. Unter **Genehmigung durch** eine eigene geschützte Rollengruppe auswählen oder die bisherigen zentralen Prüfer verwenden. Die Gruppe benötigt mindestens ein aktiviertes Mitglied mit wirksamer Mitgliedschaft. Das Zeitfenster nach einer Freigabe wählen: eine bis 60 Minuten, Vorgabe fünf Minuten.
2. **Genehmigungsrichtlinie speichern** und die Begründung bestätigen. Eine tatsächliche eigene Firmeninhaberschaft oder aktuelle kanonische Rollenverwaltung sowie frische MFA sind erforderlich.
3. Die Änderung erzeugt eine neue Richtlinienversion. Sie macht bisherige Aktivierungen und offene Anträge/Freigaben dieser Rolle unwirksam; dies steht ausdrücklich im Bestätigungsdialog.

Ohne gespeicherte Richtlinie gilt die virtuelle Revision `0` mit eigener Aktivierung ohne zusätzliche Genehmigung. Bereits bestehende aktive Vergaben bleiben beim rein additiven Rollout erhalten. Die neue Richtlinie betrifft die berechtigten PIM-Zuweisungen; direkte aktive Firmenrollenvergaben behalten ihren eigenen ursprünglichen Verwaltungs- und MFA-Vertrag.

## Antrag und Entscheidung

- Die berechtigte Person wählt unter **Home/PIM → Firmenrollen → Berechtigt → Aktivieren** die konkrete Dauer und begründet den Zugriff. Bei erforderlicher Genehmigung erstellt die Bestätigung einen Antrag. Ein Antrag oder eine Freigabe erteilt noch keine Rechte.
- Unter **Meine Anträge** stehen tatsächlicher Zustand, Rolle, Bereich, ursprüngliche Aktionen und Dauer, Entscheidung und Begründung. Ungeprüfte Anträge laufen spätestens nach 24 Stunden ab, früher bei Ablauf der ursprünglichen Quelle oder unzureichender Restlaufzeit.
- **Genehmigungen** zeigt ausschließlich Anträge, für deren Rolle die aktuelle Person tatsächlich prüfen darf. Bei einer ausgewählten Genehmigergruppe erhalten ihre wirksamen Mitglieder diese rollenbezogene Queue ohne zusätzliche globale Rolle. Firmeninhaber, Rollenverwalter und kanonische **PIM Approver** können eine ausgewählte Gruppe nicht umgehen; ohne ausgewählte Gruppe gelten die bisherigen zentralen Prüfer. Diese Prüfbefugnis erteilt keine zusätzliche Verwaltung der Firmendefinitionen oder Genehmigungsrichtlinien. Selbstgenehmigung und Selbstablehnung sind ausgeschlossen; mindestens eine weitere berechtigte Identität ist daher erforderlich.
- **Genehmigen/Ablehnen** verlangt eine eigene Begründung, Bestätigung und ursprüngliche frische MFA. Die erste Entscheidung auf der exakten aktuellen Antragsversion gewinnt. Konkurrierende oder überholte Entscheidungen werden nicht still überschrieben oder automatisch wiederholt.
- Nach einer Freigabe wählt die ursprüngliche berechtigte Person innerhalb des konfigurierten Fensters **Jetzt aktivieren**. Die Dauer und der Bereich stammen unverändert aus dem Antrag. Die Aktivierung benötigt erneut frische MFA und verbraucht genau diese Freigabe einmal.
- **Zurückziehen** beendet einen eigenen noch nicht verbrauchten Antrag, auch nach Freigabe oder Quellenänderung. Dafür gilt die normale aktuelle Anmelderichtlinie, ohne zusätzliche fünfminütige Aktivierungsprüfung. Tatsächlich aktive Rechte werden weiterhin über **Beenden** zurückgegeben oder durch ihre bestehende Eligibility-/Aktivierungsverwaltung entzogen.

Die vorhandenen Grenzen bleiben verbindlich: maximal zehn Stunden und höchstens die Rolle und die ursprüngliche Restlaufzeit. Bestehende strengere Issuer-/Owner-/globale Rollen-MFA-Richtlinien werden nicht gelockert. Die einfache direkte Aktivierungsroute kann eine vorgeschriebene Genehmigung nicht umgehen.

## Tatsächliche Bindungen und Protokoll

Identity-Migration `059_company_pim_approvals.sql` ergänzt Richtlinien, unveränderlich gebundene Anträge, Aktivierungsverknüpfungen und sechs versiegelte private SQL-Helfer. Migration `061_company_pim_approver_groups.sql` ergänzt die ausgewählte Gruppe mit ihrer ursprünglichen Tenant-Inkarnation, zwei weitere private Helfer und die unabhängige Gruppenprüfung beim tatsächlichen Commit. Jeder Antrag hält die tatsächlich gelesene Rollendefinition als Snapshot und bindet Definitions-/Eligibility-/Richtlinienversion, ursprüngliche Mitgliedschafts-Inkarnation, Benutzer-/Subject-/Link-Kontext, MFA-Revision, Bereich und ursprüngliche Quellenfrist. Entfernen und erneutes Hinzufügen der Mitgliedschaft, aus der die PIM-Berechtigung stammt, Rollen-/Richtlinienänderungen, Widerruf, Kontosperre oder geänderte MFA-/Identitätsbindung beleben keine alte Freigabe wieder. Ein erneuerter Review verlängert keine ursprünglich erfasste Antragsfrist.

Die vorhandenen kanonischen Rollen- und Issuerverträge bleiben unverändert. Als Prüfer gelten nur tatsächliche aktuelle kanonische Rechte oder die ausdrücklich konfigurierte eigene geschützte Genehmigergruppe; Caller-Flags, API-Keys und Workload-Bearer ersetzen sie nicht. Bei Gruppenentscheidungen speichert der ursprüngliche Akteur zusätzlich Gruppen-ID, Generation, konkrete Mitgliedschafts-ID und Quellenfrist. Entfernen oder Ersetzen dieser Mitgliedschaft während einer Entscheidung verhindert den Commit. Auch Queue-Seiten und Zähler werden auf die erlaubten Rollen begrenzt und ihre ursprünglichen Quellen nach der externen Akteurprüfung erneut gelesen. Die zugelassene Queue behält auch die Historie deaktivierter Rollen bei; eine weitere Entscheidung auf deren überholten Anträgen bleibt gesperrt. Eine abgeschlossene unabhängige Entscheidung bleibt ein historischer tatsächlicher Entscheidungsbeleg. Der spätere Austritt eines Genehmigers aus der Gruppe entzieht dessen künftige Prüfbefugnis; eine bereits abgeschlossene Entscheidung bleibt historisch erhalten. Eine Rollen-/Richtlinienänderung oder ein Eligibility-/Aktivierungsentzug beendet dagegen wie bisher die Wirkung der ursprünglichen Aktivierung. Die aktuelle Rollen-/Eligibility-/Richtlinienquelle muss bei der Aktivierung und jeder anschließenden Nutzung weiterhin wirksam sein.

Richtlinienänderung, Antragsanlage, Entscheidung, Rücknahme und Freigabeverbrauch binden ihre tatsächlichen Vorher-/Nachher-Daten, ursprünglichen Akteur und Begründung an eine verpflichtende lokale Pending-Outbox. Die persönliche Historie zeigt auch die eigenen Anträge und die Entscheidung anderer berechtigter Personen. Die globale Rollen-Historie bleibt separat lesbar. Ausstehende Outbox bedeutet keine ausgelieferte E-Mail oder externe Wirkung.

Gemeinsame Tenant-Schreiblocks, starke ETags, Row-/Truncate-Guards und Deferred-Commit-Prüfungen schützen die tatsächlichen Effekte. Richtlinien- und Antragsquellen werden am physischen Commit erneut geprüft. Läuft die Genehmigung während der Aktivierung ab, werden Aktivierung und Verbrauch gemeinsam zurückgerollt. Eine erfundene positive Admission-Antwort, ein fehlender Receiver oder ein unterdrückter Beleg ergibt keinen bestätigten Erfolg. Der privilegierte Datenbankbetreiber und die bestehende dienstübergreifende Issuer-Revalidierung bleiben Vertrauensgrenzen.

## Schnittstellen

Die [OpenAPI-Datei](../api/openapi.yaml) dokumentiert `companyPimApprovalProtocol: 1` und die tatsächlichen DTOs:

- `GET/PUT /api/identity/company-roles/:id/approval-policy`: eigene Richtlinie lesen oder bedingt versionieren; starker ETag `"company-pim-policy-UUID-revision"`, für den unkonfigurierten Zustand `0`. `reviewerGroupId` ist die ausdrücklich ausgewählte Gruppen-UUID oder `null` für zentrale Prüfer. Bei bereits ausgewählter Gruppe muss eine Änderung diesen Wert ausdrücklich angeben; alte Clients können die Gruppe nicht durch Weglassen entfernen.
- `GET /api/identity/company-pim-approvals/eligibilities/:id`: eigene aktuelle Aktivierungsoptionen und gegebenenfalls bestehenden unverbrauchten Antrag lesen.
- `POST /api/identity/company-pim-approvals/eligibilities/:id/requests`: eigenen ursprünglichen Antrag mit Eligibility-ETag und exakter positiver Richtlinienrevision anlegen.
- `GET /api/identity/company-pim-approvals/self`: ausschließlich eigene Anträge, serverseitige Suche und Seiten zu 25 Einträgen.
- `GET /api/identity/company-pim-approvals/requests`: tatsächliche eigene Tenant-Queue, Statusfilter `pending`, `approved`, `all`, Suche und Seiten.
- `POST /api/identity/company-pim-approvals/requests/:id/approve|deny|cancel`: exakte aktuelle Antragsversion entscheiden bzw. selbst zurückziehen.
- `POST /api/identity/company-pim-approvals/requests/:id/activate`: die konkrete Freigabe mit aktuellem Antrags-ETag verbrauchen; die Rückgabe bestätigt tatsächliche Aktivierung und verbrauchte Antragsrevision.

Antrags-ETags sind `"company-request-UUID-revision"`. Fremde Tenant-/Benutzer-Overrides werden nicht übernommen. Verlorene oder widersprüchliche Antworten verlangen aktuelles Nachlesen und eine neue ausdrückliche Entscheidung, ohne automatische Schreibwiederholung.

## Noch offen

Weitere delegierte Genehmigerverwaltung, periodische Reviews, Benachrichtigungszustellung, terminierte Aktivierungen, weitere delegierbare Lizenz-/Geräte-/Provideraktionen und vollständige Last-/Betriebsabnahmen bleiben offen. Pro Firmenrolle ist eine geschützte Genehmigergruppe auswählbar; deren Mitgliederverwaltung verwendet die bestehende unabhängige Rollenverwaltung mit frischer MFA. Die Gruppenauswahl zeigt höchstens 1’000 geschützte Gruppen und behält eine gespeicherte Gruppe bei unvollständiger Liste bei. Die Queue lehnt mehr als 1’000 gleichzeitig wirksame Rollenquellen ab. Die bestehende Rolle PIM Approver kann über die bereits vorhandene Rollen-/PIM-Verwaltung vergeben werden. Es werden keine persönlichen Produktions-MFA-Nachweise oder Rollen für die Tests erfunden; positive menschliche Abläufe verwenden isolierte Konten und Datenbanken.

[Lokale Abnahme der Genehmigergruppen](../testing/pim-approver-groups-2026-11-15.json) dokumentiert die tatsächlichen PostgreSQL-, HTTP-/OAuth-/MFA- und Oberflächenprüfungen mit ihren Grenzen. Der vollständige CI-Lauf und die produktive Freigabe dieses Bausteins bleiben getrennte Schritte.
