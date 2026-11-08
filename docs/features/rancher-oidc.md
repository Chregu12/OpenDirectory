# Rancher-Anmeldung über OpenDirectory

Rancher ist hier die Anwendung, OpenDirectory der OIDC-Identitätsanbieter.
Die Lizenz-Konnektoren werden dafür nicht benötigt. Diese Anleitung richtet sich
an Rancher 2.15.2 mit dem Anbieter **Generic OIDC**. Das Bereitstellen von
Metadaten oder einer Vorlage bestätigt noch keinen erfolgreichen SSO-Login.

## Verbindung vorbereiten

1. In OpenDirectory unter **Administration → Identitätsanbieter → Anwendungen**
   eine vertrauliche Anwendung registrieren. Name: `Rancher`, Callback exakt
   `https://rancher.heusser.local/verify-auth`, Scopes `openid profile email groups`.
   Die Registrierung startet deaktiviert. Die tatsächlich erzeugte Client-ID
   verwenden, keine angenommene ID `rancher`.
2. Das einmal angezeigte Client-Secret direkt im geschützten Rancher-Dialog
   übernehmen. Nicht ins Repository, in URLs, Protokolle oder Chat kopieren.
3. Der Anwendung passende kanonische Benutzer oder Gruppen ausdrücklich und
   zeitlich begrenzt zuweisen. Selbstverwaltung und unabhängige Prüfungen bleiben
   wirksam. Der vorhandene Operator-Bootstrap erlaubt bei der Ersteinrichtung
   ausschließlich eine einzelne Benutzerzuweisung für höchstens acht Stunden;
   er ist keine dauerhafte Gruppenzuweisung. Die gewünschte MFA-Richtlinie unter
   **Anmeldeanforderung** separat konfigurieren.
4. Die Anwendung erst nach Prüfung der Zuweisung aktivieren.

## Zertifikatsvertrauen

Rancher muss Discovery, Token-Endpunkt, JWKS und UserInfo über geprüftes HTTPS
erreichen. Für die interne CA unterstützt Rancher
[`additionalTrustedCAs`](https://documentation.suse.com/cloudnative/rancher-manager/latest/en/installation-and-upgrade/references/helm-chart-options.html).
Das Secret `cattle-system/tls-ca-additional` enthält unter `ca-additional.pem`
ausschließlich die geprüften öffentlichen CA-Zertifikate. Bei einem vorhandenen
Bundle bleiben dessen Zertifikate erhalten. Den privaten CA- oder Server-Schlüssel
nicht übernehmen.

Die [Helm-Ergänzung](../../deploy/helm/rancher/opendirectory-oidc.values.yaml)
mit den bisherigen privaten Werten und derselben installierten Rancher-Chartversion
verwenden. Vorher den gerenderten Unterschied prüfen. Ein anschließender Abruf
aus jedem Rancher-Pod muss ohne Abschalten der Zertifikatsprüfung funktionieren:

```sh
curl --fail --silent --show-error \
  https://opendirectory.heusser.local/.well-known/openid-configuration
```

## Rancher konfigurieren

Unter **Users & Authentication → Auth Provider → Generic OIDC**:

| Feld | Wert |
| --- | --- |
| Client ID / Client Secret | Tatsächliche Registrierung aus OpenDirectory |
| Issuer | `https://opendirectory.heusser.local` |
| Rancher callback | `https://rancher.heusser.local/verify-auth` |
| Scopes | `openid profile email groups` |
| PKCE | `S256` |
| Custom claims | Nicht erforderlich |

Die [Rancher-Anleitung](https://documentation.suse.com/cloudnative/rancher-manager/latest/en/rancher-admin/users/authn-and-authz/configure-generic-oidc.html)
beschreibt den interaktiven Test beim Aktivieren. Der Rancher-OAuth-Client kann
bei der Token-Anmeldung automatisch auf `client_secret_post` wechseln; diese
Methode ist in OpenDirectory-Discovery veröffentlicht. Der Regressionstest
prüft denselben Code nach einer abgewiesenen Basic-Anmeldung, den exakten
Callback, S256, State, Nonce, UserInfo und die Einmaligkeit des Codes.

## Benutzer und Gruppen berechtigen

Rancher bildet Benutzer aus dem unveränderlichen OIDC-`sub`. Gruppen kommen aus
bestätigten OpenDirectory-Mitgliedschaften als UUID-Liste im Claim `groups`.
Gruppennamen aus dem Passwortanbieter, SCIM-Labels und lokale Rollen werden
nicht als Rancher-Gruppenrechte übernommen. Keine künstlichen Gruppenpfade
oder pauschalen Administratorzuweisungen konfigurieren.

Den Standortzugriff auf die vorgesehenen Benutzer/Gruppen beschränken und die
benötigten Rancher-Rollen ausdrücklich vergeben. Gruppen-Principals haben die
Form `genericoidc_group://KANONISCHE-GRUPPEN-UUID`. Die Suche/Anzeige ist keine
Verzeichnissynchronisierung; die gewünschte UUID gegen OpenDirectory prüfen.

UserInfo liest aktuelle Mitgliedschaften, Refresh berechnet Gruppen neu und
eine Scope-Reduktion entfernt sie. **Bereits bestehende Rancher-Sitzungen und
Kubernetes-Zugangsdaten werden dadurch nicht unmittelbar widerrufen.** Rancher
2.15.2 implementiert für Generic OIDC keinen eigenständigen Gruppen-Refetch.
Änderungen deshalb zusätzlich mit Ranchers eigenen Sitzungs-/Zugriffsregeln
prüfen; keine sofortige externe Sperrung behaupten.

## Abnahme

Mit einem ausdrücklich zugewiesenen Konto anmelden und `sub`, Gruppen sowie
die tatsächlich erlaubten Rancher-Aktionen prüfen. Danach ein nicht zugewiesenes
Konto ablehnen lassen, eine Mitgliedschaft entziehen und die Wirkung auf neue
Anmeldungen sowie bestehende Rancher-Sitzungen getrennt prüfen. Ein erneutes
Abspielen des OAuth-Codes oder ein fremder Callback darf keine Tokens erzeugen.
Lokale Rancher-Anmeldung für Wiederherstellung verfügbar halten.

Die automatischen HTTP-Tests verwenden synthetische Konten und ersetzen diesen
interaktiven Test mit den tatsächlichen Konten nicht.
