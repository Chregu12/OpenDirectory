# Aktuelle Wirksamkeit von Gruppenregeln

Stand: 23. Oktober 2026. Identity 052 prüft die gespeicherte Regelquelle beim Lesen der zentralen Anwendungsberechtigung und der Gruppen-Lizenzquelle. Eine bereits materialisierte Regelmitgliedschaft vermittelt keinen Gruppenzugriff mehr, wenn die aktuelle Regel deaktiviert/geändert wurde, die Benutzer-Eligibility gewechselt hat, Attribute nicht mehr passen oder kein gültiger Untergruppenzeuge mehr besteht. Dazu muss kein Worker gelaufen sein. Direkte manuelle Mitgliedschaften behalten ihre eigene Herkunft. Der separate Konfliktindikator `actorIsMember` bleibt absichtlich an gespeicherte physische Links gebunden: Auch eine ausstehende oder vorläufig unwirksame eigene Quelle darf keine App-Selbstadministration ermöglichen.

## Bedienung und Grenzen

Unter **Gruppen → gespeicherte Regelvorschau** werden bestehende Links mit tatsächlicher Membership-ID, Herkunft und `effective` angezeigt. `validUntil` benennt die endliche aktuelle Quellenfrist, sonst NULL. Die Oberfläche zeigt maximal 25 Links pro Seite. Die Prüfung ist eine Beobachtung; für einen späteren Stand neu laden.

Der gespeicherte Link wird erst beim expliziten [Owner-Abgleich](company-group-rules.md) oder dem genehmigten [App-Job](company-group-rule-automation.md) physisch entfernt. Neue Mitglieder werden ebenfalls über diesen kanonischen Abgleich angelegt und bleiben bei unabhängiger Gruppenprüfung zunächst ausstehend. Regeländerungen benötigen eine neue Link-Inkarnation; ein Abgleich verlängert keine alte Review-Frist stillschweigend.

Passen lediglich die Attribute vor der Bereinigung wieder, kann dieselbe unveränderte Regel-/Eligibility-Inkarnation mit ihrer ursprünglichen noch gültigen Review-Frist wieder wirksam sein. Es wird kein neuer Freigabezyklus erfunden. Manuelle Quellen werden durch die Regel nicht adoptiert oder gelöscht.

## Untergruppen und Fristen

Dynamische Bedingungen und gültige Untergruppen sind alternative Zeugen. Die gültige Quelle mit der spätesten Frist reicht aus. Eine unabhängig passende dynamische Bedingung benötigt keinen Untergruppenzeugen. Die eigene Review-Frist begrenzt das Gesamtergebnis zusätzlich: `min(eigene Frist, max(gültige alternative Zeugen))`. Fehlende Anfangsfreigaben und abgelaufene Kinder sind keine positiven Zeugen. Gültige unabhängige Alternativen bleiben erhalten.

Die Auflösung ist auf 16 Verschachtelungslinks und insgesamt 1'024 besuchte Mitgliedschaften je Wurzel begrenzt. Unvollständige Auflösung, fehlende Original-/Pending-Belege, Zyklen und beschädigte Empfangsroutinen werden abgelehnt. Es gibt keine erfolgreiche abgeschnittene Mitgliederliste.

## Quellenrevision und Auslieferung

Der Gruppen-Snapshot bleibt Schema 3 mit der vorhandenen 300-Sekunden-Beobachtungslease. `revision` ist für regelverwaltete Gruppen eine monotone Quellenbeobachtungsrevision, getrennt vom physischen Gruppen-ETag. Sie berücksichtigt retained eigene Benutzer-/Gruppenrevisionen, Regelkonfigurationen, Tenantversion und bereits erreichte historische Review-Fristen. Änderungen anderer Tenants verändern sie nicht. Alle Werte bleiben exakte BIGINT-Zeichenfolgen; Überlauf wird abgelehnt. Start- und Endrevision müssen gleich sein, andernfalls liefert die Quelle 409 statt einer gemischten Beobachtung. Bestehende Empfänger behalten ihren Schutz gegen gleichen Revisionsstand mit widersprüchlichem Hash.

Jedes ausgegebene effektive Mitglied trägt zusätzlich die geerbte `reviewDeadlineAt`. Der bestehende Policy-Lease-Empfänger begrenzt die Lease bereits durch diese Frist. Damit wird keine sofortige Invalidierung bereits ausgegebener dienstübergreifender Caches behauptet. Physisch belegte lokale Sitze werden weiterhin über den vorhandenen Lizenzabgleich zurückgegeben. Der [quellenabhängige App-Abgleich](company-automation-changes.md) kann diese Bereinigung und neue Materialisierung auslösen. Ereigniszustellung, unmittelbare dienstübergreifende Invalidierung und externe Provider bleiben im [Gesamtauftrag](../implementation-worklist.md) offen.

## Installation

Identity 001–053 mit aktuellem Code und Frontend koordiniert ausrollen; Policy verwendet weiterhin 001–029. 052 und anschliessend 053 anwenden, auch nach erneutem Anwenden älterer Gruppen-/Automationsmigrationen. Die Migration ergänzt Funktionen und die vorhandenen geschützten Manifeste, keine zweite Mitgliedertabelle oder neue Runtime-Dependency. Fehlt der aktuelle Receiver, wird keine positive Quelle ausgeliefert. Aufrufer können eine 409-Beobachtung erneut lesen; unbestätigte Schreibwirkungen weiterhin zuerst anhand aktueller Daten und Historie prüfen.
