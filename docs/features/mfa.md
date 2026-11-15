# MFA und Zwei-Faktor-Anmeldung

OpenDirectory unterstützt Passwort plus einen eigenen zeitbasierten Einmalcode (TOTP). Der Faktor gilt nach bestätigter Einrichtung für jede neue Benutzeranmeldung. Ein optionaler Faktor des Passwortanbieters ist davon getrennt. Anwendungen und Rollen können MFA verpflichtend verlangen; PIM prüft einen tatsächlichen, höchstens fünf Minuten alten MFA-Nachweis.

## Eigenes Konto einrichten

1. Unter **`/mfa` → TOTP einrichten** den eigenen Benutzernamen und das aktuelle Passwort bestätigen. Einen beim Passwortanbieter aktivierten Einmalcode zusätzlich eingeben.
2. Den angezeigten geheimen Schlüssel privat in einem TOTP-Authenticator erfassen: SHA-1, sechs Stellen, 30 Sekunden. Die Einrichtung innerhalb von zehn Minuten mit einem aktuellen Code bestätigen.
3. Einen neuen Einmalcode abwarten und erneut anmelden. Die Einrichtung macht bisherige Tokens ungültig; ein bereits benutzter Code wird nicht nochmals angenommen.
4. Unter `/mfa` eigene Notfallcodes mit Passwort und einem unbenutzten Einmalcode erzeugen und privat getrennt aufbewahren. Codes und Schlüssel weder ins Repository noch in Chats oder Tickets kopieren.

Ein unbestätigter Start aktiviert keinen Faktor. Für eine PIM-Aktivierung nach Ablauf der fünf Minuten erneut mit Passwort und einem frischen Code anmelden; eine Sitzungsverlängerung erzeugt keinen neuen MFA-Nachweis.

## Verlust und Deaktivierung

Notfallcodes sind einmalig nutzbar und werden nur gehasht gespeichert. Die Wiederherstellung verlangt das eigene Passwort und einen unbenutzten Notfallcode; sie ersetzt den verlorenen Faktor, verwirft alte Sitzungen und erteilt selbst keine normale Anmeldung. Danach regulär anmelden. Ohne vorbereitete Notfallcodes besteht keine Selbstwiederherstellung.

Eine bewusste Deaktivierung unter `/mfa` verlangt erneut Passwort und einen unbenutzten OpenDirectory-Code. PIM bleibt ohne den geforderten Faktor gesperrt.

## Geprüfter Umfang

Die Prüfung vom 15. November 2026 bestand aus 199 gezielten Unit-Tests, 31 tatsächlichen PostgreSQL-Fällen und sechs Browserabläufen mit echten temporären Diensten. Abgedeckt sind Einrichtung, zeitliche Codegrenzen, Wiederverwendungsschutz, Wiederherstellung, App-/Rollenpflicht, Mitarbeiter-Erstanmeldung und PIM. Geheimnisse werden mit AES-256-GCM verschlüsselt; Faktoränderungen entwerten frühere Nachweise und Fehlversuche werden dauerhaft begrenzt.

Bei der rein lesenden Produktivprüfung war noch kein OpenDirectory-Faktor eingerichtet. Die Einrichtung im persönlichen Authenticator und die persönliche Produktivanmeldung sind deshalb separat abzunehmen. SMS, Push und WebAuthn/Passkeys gehören nicht zu diesem Stand.
